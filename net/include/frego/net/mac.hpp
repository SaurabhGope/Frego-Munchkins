#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace frego::net {

// A 48-bit IEEE 802 MAC address.
struct Mac {
    std::array<std::uint8_t, 6> bytes{};

    // Accepts "b4:3d:08:02:98:e8", the unpadded "b4:3d:8:2:98:e8" that macOS `arp`
    // prints, and '-' separators. Case-insensitive.
    static std::optional<Mac> parse(std::string_view text);
    static Mac from(std::span<const std::uint8_t, 6> raw);

    std::string str() const;  // lower-case, zero-padded, ':'-separated

    // First three bytes: the Organizationally Unique Identifier.
    std::uint32_t oui() const {
        return (std::uint32_t{bytes[0]} << 16) | (std::uint32_t{bytes[1]} << 8) | bytes[2];
    }
    // U/L bit set: not from a vendor block. Phones and laptops use these as per-network
    // "private" addresses, and extenders use them when rewriting MACs.
    bool locally_administered() const { return (bytes[0] & 0x02) != 0; }
    // I/G bit set: a group address (multicast or broadcast), never a single host.
    bool multicast() const { return (bytes[0] & 0x01) != 0; }
    bool is_zero() const;

    auto operator<=>(const Mac&) const = default;
};

}  // namespace frego::net
