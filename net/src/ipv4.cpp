#include "frego/net/ipv4.hpp"

#include <charconv>
#include <format>

namespace frego::net {

std::optional<Ipv4> Ipv4::parse(std::string_view text) {
    std::uint32_t value = 0;
    const char* p = text.data();
    const char* end = text.data() + text.size();
    for (int octet = 0; octet < 4; ++octet) {
        if (octet > 0) {
            if (p >= end || *p != '.') return std::nullopt;
            ++p;
        }
        if (p >= end || *p < '0' || *p > '9') return std::nullopt;
        if (*p == '0' && p + 1 < end && p[1] >= '0' && p[1] <= '9') return std::nullopt;  // no leading zeros
        unsigned part = 0;
        auto [next, ec] = std::from_chars(p, end, part);
        if (ec != std::errc{} || part > 255) return std::nullopt;
        value = (value << 8) | part;
        p = next;
    }
    if (p != end) return std::nullopt;
    return Ipv4{value};
}

std::string Ipv4::str() const {
    return std::format("{}.{}.{}.{}", value >> 24, (value >> 16) & 0xFF, (value >> 8) & 0xFF,
                       value & 0xFF);
}

Subnet Subnet::of(Ipv4 addr, Ipv4 netmask) {
    int prefix = std::popcount(netmask.value);
    Subnet s{{}, prefix};
    s.network = {addr.value & s.mask()};
    return s;
}

std::uint32_t Subnet::host_count() const {
    if (prefix >= 31) return prefix == 31 ? 2 : 1;
    return (~mask()) - 1;
}

std::string Subnet::str() const { return std::format("{}/{}", network.str(), prefix); }

}  // namespace frego::net
