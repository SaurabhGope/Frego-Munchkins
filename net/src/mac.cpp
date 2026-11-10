#include "frego/net/mac.hpp"

#include <algorithm>
#include <format>

namespace frego::net {
namespace {

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

std::optional<Mac> Mac::parse(std::string_view text) {
    Mac mac;
    std::size_t i = 0;
    for (std::size_t group = 0; group < 6; ++group) {
        if (group > 0) {
            if (i >= text.size() || (text[i] != ':' && text[i] != '-')) return std::nullopt;
            ++i;
        }
        int value = 0;
        std::size_t digits = 0;
        while (i < text.size() && hex_value(text[i]) >= 0) {
            if (++digits > 2) return std::nullopt;
            value = value * 16 + hex_value(text[i++]);
        }
        if (digits == 0) return std::nullopt;
        mac.bytes[group] = static_cast<std::uint8_t>(value);
    }
    if (i != text.size()) return std::nullopt;
    return mac;
}

Mac Mac::from(std::span<const std::uint8_t, 6> raw) {
    Mac mac;
    std::copy(raw.begin(), raw.end(), mac.bytes.begin());
    return mac;
}

std::string Mac::str() const {
    return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", bytes[0], bytes[1], bytes[2],
                       bytes[3], bytes[4], bytes[5]);
}

bool Mac::is_zero() const {
    return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
}

}  // namespace frego::net
