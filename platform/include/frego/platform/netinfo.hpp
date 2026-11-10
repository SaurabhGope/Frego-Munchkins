#pragma once

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "frego/net/ipv4.hpp"
#include "frego/net/mac.hpp"

namespace frego::platform {

struct Interface {
    std::string name;
    net::Ipv4 addr;
    net::Ipv4 netmask;
    std::optional<net::Mac> mac;        // none for tunnels (utun) and loopback
    std::optional<net::Ipv4> gateway;   // only when this interface carries the default route
    bool point_to_point = false;

    net::Subnet subnet() const { return net::Subnet::of(addr, netmask); }
};

// The interface carrying the IPv4 default route ("auto"), or a named interface.
// macOS: routing socket RTM_GET for 0.0.0.0/0 + getifaddrs (DESIGN §10).
std::expected<Interface, std::string> default_interface(std::string_view preferred = "auto");

struct ArpEntry {
    net::Ipv4 ip;
    net::Mac mac;
    std::string iface;
    bool permanent = false;
};

// Complete IPv4 neighbour (ARP) entries; incomplete ones are skipped. Empty iface = all.
// macOS: sysctl {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO}.
std::expected<std::vector<ArpEntry>, std::string> arp_table(std::string_view iface = {});

}  // namespace frego::platform
