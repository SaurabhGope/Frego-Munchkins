#include "frego/platform/probe.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <thread>

namespace frego::platform {
namespace {

sockaddr_in to_sockaddr(net::Ipv4 ip, std::uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(ip.value);
    return a;
}

}  // namespace

std::size_t udp_nudge(std::span<const net::Ipv4> hosts, std::stop_token stop) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    ::fcntl(fd, F_SETFL, O_NONBLOCK);
    std::size_t sent = 0;
    for (auto host : hosts) {
        if (stop.stop_requested()) break;
        auto a = to_sockaddr(host, 9);  // discard port
        // Errors (EHOSTDOWN, EHOSTUNREACH, ENOBUFS) are expected for absent hosts.
        ::sendto(fd, nullptr, 0, 0, reinterpret_cast<sockaddr*>(&a), sizeof a);
        // Pace the sweep so the ARP queue and Wi-Fi aren't flooded.
        if (++sent % 32 == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    ::close(fd);
    return sent;
}

ProbeOutcome tcp_probe(net::Ipv4 ip, std::uint16_t port, std::chrono::milliseconds timeout) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return {ProbeResult::Error, errno};
    ::fcntl(fd, F_SETFL, O_NONBLOCK);
    auto a = to_sockaddr(ip, port);
    int err = 0;
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
        err = errno;
        if (err == EINPROGRESS) {
            pollfd p{fd, POLLOUT, 0};
            if (::poll(&p, 1, static_cast<int>(timeout.count())) == 1) {
                socklen_t len = sizeof err;
                ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
            } else {
                err = ETIMEDOUT;
            }
        }
    }
    ::close(fd);
    if (err == 0 || err == ECONNREFUSED) return {ProbeResult::Reached, err};
    if (err == ETIMEDOUT) return {ProbeResult::Timeout, err};
    if (err == EHOSTUNREACH || err == ENETUNREACH) return {ProbeResult::Unreachable, err};
    return {ProbeResult::Error, err};
}

}  // namespace frego::platform
