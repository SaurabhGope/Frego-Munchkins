#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace frego::net {

// Bounds-checked cursor over untrusted bytes (DESIGN §5.1). An out-of-range read returns
// zero (or an empty span) and latches failed(), so parsers can read a whole structure and
// check once at the end instead of after every field.
class ByteReader {
public:
    explicit ByteReader(std::span<const std::uint8_t> buf) : buf_(buf) {}

    std::uint8_t u8() {
        if (!need(1)) return 0;
        return buf_[pos_++];
    }

    std::uint16_t u16be() {
        if (!need(2)) return 0;
        auto v = static_cast<std::uint16_t>((buf_[pos_] << 8) | buf_[pos_ + 1]);
        pos_ += 2;
        return v;
    }

    std::uint32_t u32be() {
        if (!need(4)) return 0;
        auto v = (std::uint32_t{buf_[pos_]} << 24) | (std::uint32_t{buf_[pos_ + 1]} << 16) |
                 (std::uint32_t{buf_[pos_ + 2]} << 8) | std::uint32_t{buf_[pos_ + 3]};
        pos_ += 4;
        return v;
    }

    std::span<const std::uint8_t> bytes(std::size_t n) {
        if (!need(n)) return {};
        auto s = buf_.subspan(pos_, n);
        pos_ += n;
        return s;
    }

    std::string_view str(std::size_t n) {
        auto b = bytes(n);
        return {reinterpret_cast<const char*>(b.data()), b.size()};
    }

    // Child reader over the next n bytes, for length-prefixed fields. A child of a
    // failed read starts out failed.
    ByteReader sub(std::size_t n) {
        bool ok = need(n);
        ByteReader child(ok ? bytes(n) : std::span<const std::uint8_t>{});
        child.failed_ = !ok;
        return child;
    }

    void skip(std::size_t n) {
        if (need(n)) pos_ += n;
    }

    std::size_t remaining() const { return failed_ ? 0 : buf_.size() - pos_; }
    std::size_t offset() const { return pos_; }
    bool failed() const { return failed_; }

private:
    bool need(std::size_t n) {
        if (failed_ || n > buf_.size() - pos_) {
            failed_ = true;
            return false;
        }
        return true;
    }

    std::span<const std::uint8_t> buf_;
    std::size_t pos_ = 0;
    bool failed_ = false;
};

}  // namespace frego::net
