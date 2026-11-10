// Linux support arrives in M5 (netlink); until then these report "unsupported".
#include <thread>

#include "frego/platform/netinfo.hpp"
#include "frego/platform/route_monitor.hpp"

namespace frego::platform {

std::expected<Interface, std::string> default_interface(std::string_view) {
    return std::unexpected("Linux support arrives in M5");
}

std::expected<std::vector<ArpEntry>, std::string> arp_table(std::string_view) {
    return std::unexpected("Linux support arrives in M5");
}

RouteMonitor::RouteMonitor() = default;
RouteMonitor::~RouteMonitor() = default;

bool RouteMonitor::wait_for_change(std::chrono::milliseconds timeout) {
    std::this_thread::sleep_for(timeout);
    return false;
}

}  // namespace frego::platform
