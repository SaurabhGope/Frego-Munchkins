#pragma once

#include <bit>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace frego::net {

// An IPv4 address, stored in host byte order so subnet arithmetic is plain integer math.
struct Ipv4 {
    std::uint32_t value = 0;

    static std::optional<Ipv4> parse(std::string_view text);  // dotted quad only
    std::string str() const;

    bool multicast() const { return (value >> 28) == 0xE; }  // 224.0.0.0/4
    auto operator<=>(const Ipv4&) const = default;
};

struct Subnet {
    Ipv4 network;
    int prefix = 0;  // 0..32

    static Subnet of(Ipv4 addr, Ipv4 netmask);
    std::uint32_t mask() const { return prefix == 0 ? 0 : ~std::uint32_t{0} << (32 - prefix); }
    Ipv4 broadcast() const { return {network.value | ~mask()}; }
    bool contains(Ipv4 a) const { return (a.value & mask()) == network.value; }
    // Usable host addresses (excludes network and broadcast for prefixes < 31).
    std::uint32_t host_count() const;
    std::string str() const;  // "192.168.1.0/24"
};

}  // namespace frego::net
