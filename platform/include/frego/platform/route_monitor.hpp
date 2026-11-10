#pragma once

#include <chrono>

namespace frego::platform {

// Watches the kernel routing table for changes (macOS: a PF_ROUTE socket), so
// network-guard can re-check the network within about a second of leaving home.
class RouteMonitor {
public:
    RouteMonitor();
    ~RouteMonitor();
    RouteMonitor(const RouteMonitor&) = delete;
    RouteMonitor& operator=(const RouteMonitor&) = delete;

    bool ok() const { return fd_ >= 0; }
    // Waits up to `timeout`; true if a route, interface or address change arrived.
    bool wait_for_change(std::chrono::milliseconds timeout);

private:
    int fd_ = -1;
};

}  // namespace frego::platform
