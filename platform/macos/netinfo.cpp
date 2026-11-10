// macOS network information through the BSD routing table: a routing socket for the
// default route, sysctl for the ARP table, getifaddrs for addresses (DESIGN §10).
#include "frego/platform/netinfo.hpp"

#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <format>

namespace frego::platform {
namespace {

// Routing messages pad each sockaddr to a 4-byte boundary on Darwin.
constexpr std::size_t sa_roundup(std::size_t len) {
    return len > 0 ? (1 + ((len - 1) | (sizeof(std::uint32_t) - 1))) : sizeof(std::uint32_t);
}

struct Fd {
    int fd;
    ~Fd() {
        if (fd >= 0) ::close(fd);
    }
};

struct DefaultRoute {
    std::string iface;
    std::optional<net::Ipv4> gateway;
};

std::expected<DefaultRoute, std::string> query_default_route() {
    Fd sock{::socket(PF_ROUTE, SOCK_RAW, AF_INET)};
    if (sock.fd < 0) return std::unexpected(std::format("routing socket: {}", std::strerror(errno)));

    struct {
        rt_msghdr hdr;
        std::uint8_t space[512];
    } msg{};
    auto* cp = reinterpret_cast<std::uint8_t*>(&msg.hdr + 1);
    auto append = [&](const void* sa, std::size_t len) {
        std::memcpy(cp, sa, len);
        cp += sa_roundup(len);
    };
    sockaddr_in dst{};  // 0.0.0.0
    dst.sin_len = sizeof dst;
    dst.sin_family = AF_INET;
    sockaddr_in mask = dst;  // /0
    sockaddr_dl ifp{};       // ask the kernel to fill in the interface
    ifp.sdl_len = sizeof ifp;
    ifp.sdl_family = AF_LINK;
    append(&dst, sizeof dst);    // RTAX_DST
    append(&mask, sizeof mask);  // RTAX_NETMASK
    append(&ifp, sizeof ifp);    // RTAX_IFP

    static std::atomic<int> next_seq{1};
    const int seq = next_seq++;
    const auto len = static_cast<std::size_t>(cp - reinterpret_cast<std::uint8_t*>(&msg));
    msg.hdr.rtm_msglen = static_cast<u_short>(len);
    msg.hdr.rtm_version = RTM_VERSION;
    msg.hdr.rtm_type = RTM_GET;
    msg.hdr.rtm_flags = RTF_UP | RTF_GATEWAY;
    msg.hdr.rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;
    msg.hdr.rtm_pid = ::getpid();
    msg.hdr.rtm_seq = seq;

    if (::write(sock.fd, &msg, len) < 0) {
        if (errno == ESRCH) return std::unexpected("no IPv4 default route (offline?)");
        return std::unexpected(std::format("route query: {}", std::strerror(errno)));
    }
    ssize_t n = 0;
    do {
        n = ::read(sock.fd, &msg, sizeof msg);
    } while (n > 0 && (msg.hdr.rtm_seq != seq || msg.hdr.rtm_pid != ::getpid()));
    if (n <= 0) return std::unexpected("route query: no reply");
    if (msg.hdr.rtm_errno != 0)
        return std::unexpected(std::format("route query: {}", std::strerror(msg.hdr.rtm_errno)));

    DefaultRoute out;
    const auto* p = reinterpret_cast<const std::uint8_t*>(&msg.hdr + 1);
    const auto* end = reinterpret_cast<const std::uint8_t*>(&msg) + n;
    for (int i = 0; i < RTAX_MAX && p < end; ++i) {
        if (!(msg.hdr.rtm_addrs & (1 << i))) continue;
        const auto* sa = reinterpret_cast<const sockaddr*>(p);
        if (i == RTAX_GATEWAY && sa->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(sa);
            out.gateway = net::Ipv4{ntohl(sin->sin_addr.s_addr)};
        } else if (i == RTAX_IFP && sa->sa_family == AF_LINK) {
            const auto* sdl = reinterpret_cast<const sockaddr_dl*>(sa);
            out.iface.assign(sdl->sdl_data, sdl->sdl_nlen);
        }
        p += sa_roundup(sa->sa_len);
    }
    if (out.iface.empty()) return std::unexpected("default route has no interface");
    return out;
}

}  // namespace

std::expected<Interface, std::string> default_interface(std::string_view preferred) {
    Interface out;
    std::optional<net::Ipv4> gateway;
    if (preferred.empty() || preferred == "auto") {
        auto route = query_default_route();
        if (!route) return std::unexpected(route.error());
        out.name = route->iface;
        gateway = route->gateway;
    } else {
        out.name = std::string(preferred);
        if (auto route = query_default_route(); route && route->iface == out.name)
            gateway = route->gateway;
    }
    out.gateway = gateway;

    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0)
        return std::unexpected(std::format("getifaddrs: {}", std::strerror(errno)));
    bool have_ip = false;
    for (ifaddrs* ifa = list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || out.name != ifa->ifa_name) continue;
        if (ifa->ifa_flags & IFF_POINTOPOINT) out.point_to_point = true;
        if (ifa->ifa_addr->sa_family == AF_INET && !have_ip && ifa->ifa_netmask) {
            out.addr = {ntohl(reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr.s_addr)};
            out.netmask = {ntohl(reinterpret_cast<sockaddr_in*>(ifa->ifa_netmask)->sin_addr.s_addr)};
            have_ip = true;
        } else if (ifa->ifa_addr->sa_family == AF_LINK) {
            const auto* sdl = reinterpret_cast<const sockaddr_dl*>(ifa->ifa_addr);
            if (sdl->sdl_alen == 6) {
                std::span<const std::uint8_t, 6> raw(
                    reinterpret_cast<const std::uint8_t*>(LLADDR(sdl)), 6);
                out.mac = net::Mac::from(raw);
            }
        }
    }
    ::freeifaddrs(list);
    if (!have_ip) return std::unexpected(std::format("interface {} has no IPv4 address", out.name));
    return out;
}

std::expected<std::vector<ArpEntry>, std::string> arp_table(std::string_view iface) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
    std::vector<std::uint8_t> buf;
    std::size_t needed = 0;
    // The table can grow between the size query and the read; retry a few times.
    for (int attempt = 0;; ++attempt) {
        if (::sysctl(mib, 6, nullptr, &needed, nullptr, 0) != 0)
            return std::unexpected(std::format("sysctl size: {}", std::strerror(errno)));
        buf.resize(needed + needed / 4 + 256);
        needed = buf.size();
        if (::sysctl(mib, 6, buf.data(), &needed, nullptr, 0) == 0) break;
        if (errno != ENOMEM || attempt == 3)
            return std::unexpected(std::format("sysctl read: {}", std::strerror(errno)));
    }

    std::vector<ArpEntry> entries;
    for (std::size_t off = 0; off + sizeof(rt_msghdr) <= needed;) {
        const auto* rtm = reinterpret_cast<const rt_msghdr*>(buf.data() + off);
        if (rtm->rtm_msglen == 0) break;
        const std::size_t msg_end = off + rtm->rtm_msglen;
        off = msg_end;
        if (msg_end > needed) break;

        const auto* sin = reinterpret_cast<const sockaddr_inarp*>(rtm + 1);
        const auto* sdl = reinterpret_cast<const sockaddr_dl*>(
            reinterpret_cast<const std::uint8_t*>(sin) + sa_roundup(sin->sin_len));
        if (reinterpret_cast<const std::uint8_t*>(sdl) + sizeof(sockaddr_dl) > buf.data() + msg_end)
            continue;
        if (sdl->sdl_family != AF_LINK || sdl->sdl_alen != 6) continue;  // incomplete entry

        char name[IF_NAMESIZE] = {};
        if (!::if_indextoname(sdl->sdl_index, name)) continue;
        if (!iface.empty() && iface != name) continue;

        std::span<const std::uint8_t, 6> raw(reinterpret_cast<const std::uint8_t*>(LLADDR(sdl)), 6);
        entries.push_back({net::Ipv4{ntohl(sin->sin_addr.s_addr)}, net::Mac::from(raw), name,
                           rtm->rtm_rmx.rmx_expire == 0});
    }
    return entries;
}

}  // namespace frego::platform
