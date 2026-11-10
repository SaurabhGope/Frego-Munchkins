#include "frego/platform/route_monitor.hpp"

#include <net/route.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>

namespace frego::platform {

RouteMonitor::RouteMonitor() : fd_(::socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)) {}

RouteMonitor::~RouteMonitor() {
    if (fd_ >= 0) ::close(fd_);
}

bool RouteMonitor::wait_for_change(std::chrono::milliseconds timeout) {
    if (fd_ < 0) return false;
    pollfd p{fd_, POLLIN, 0};
    if (::poll(&p, 1, static_cast<int>(timeout.count())) != 1) return false;

    // Drain everything queued; report whether any message was relevant.
    bool relevant = false;
    alignas(rt_msghdr) std::uint8_t buf[2048];
    while (true) {
        ssize_t n = ::recv(fd_, buf, sizeof buf, MSG_DONTWAIT);
        if (n < static_cast<ssize_t>(sizeof(rt_msghdr))) break;
        const auto* hdr = reinterpret_cast<const rt_msghdr*>(buf);
        switch (hdr->rtm_type) {
            case RTM_ADD: case RTM_DELETE: case RTM_CHANGE:
            case RTM_IFINFO: case RTM_NEWADDR: case RTM_DELADDR:
                relevant = true;
                break;
            default:
                break;
        }
    }
    return relevant;
}

}  // namespace frego::platform
