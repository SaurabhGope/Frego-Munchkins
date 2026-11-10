#include "frego/events/text.hpp"

#include <cstdint>

namespace frego::catalog {
namespace {

constexpr std::string_view kReplacement = "\xEF\xBF\xBD";  // U+FFFD

// Length of a valid UTF-8 sequence starting at s[i], or 0 if it's invalid
// (RFC 3629: no overlongs, no surrogates, nothing above U+10FFFF).
std::size_t valid_sequence(std::string_view s, std::size_t i, std::uint32_t& cp) {
    auto at = [&](std::size_t k) { return static_cast<std::uint8_t>(s[i + k]); };
    auto cont = [&](std::size_t k) { return i + k < s.size() && (at(k) & 0xC0) == 0x80; };
    std::uint8_t b0 = at(0);
    if (b0 < 0x80) {
        cp = b0;
        return 1;
    }
    if (b0 >= 0xC2 && b0 <= 0xDF && cont(1)) {
        cp = ((b0 & 0x1Fu) << 6) | (at(1) & 0x3Fu);
        return 2;
    }
    if (b0 >= 0xE0 && b0 <= 0xEF && cont(1) && cont(2)) {
        cp = ((b0 & 0x0Fu) << 12) | ((at(1) & 0x3Fu) << 6) | (at(2) & 0x3Fu);
        if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
        return 3;
    }
    if (b0 >= 0xF0 && b0 <= 0xF4 && cont(1) && cont(2) && cont(3)) {
        cp = ((b0 & 0x07u) << 18) | ((at(1) & 0x3Fu) << 12) | ((at(2) & 0x3Fu) << 6) |
             (at(3) & 0x3Fu);
        if (cp < 0x10000 || cp > 0x10FFFF) return 0;
        return 4;
    }
    return 0;
}

bool is_control(std::uint32_t cp) {
    return (cp < 0x20 && cp != '\t') || cp == 0x7F || (cp >= 0x80 && cp <= 0x9F);
}

}  // namespace

std::string text(std::string_view bytes, std::size_t max_len) {
    std::string out;
    out.reserve(bytes.size() < max_len ? bytes.size() : max_len);
    std::size_t i = 0;
    while (i < bytes.size()) {
        std::uint32_t cp = 0;
        std::size_t n = valid_sequence(bytes, i, cp);
        std::string_view piece;
        if (n == 0) {
            piece = kReplacement;
            n = 1;  // skip one byte and resynchronise
        } else if (is_control(cp)) {
            i += n;
            continue;
        } else {
            piece = bytes.substr(i, n);
        }
        if (out.size() + piece.size() > max_len) break;  // never split a code point
        out += piece;
        i += n;
    }
    return out;
}

}  // namespace frego::catalog
