#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace frego::net {

// Self-contained SHA-256 (FIPS 180-4), so `net` needs no crypto dependency. Used for
// network fingerprints now and JA4 hashes later; not for anything security-critical.
class Sha256 {
public:
    Sha256();
    void update(std::span<const std::uint8_t> data);
    void update(std::string_view data);
    std::array<std::uint8_t, 32> finish();

    static std::string hex(std::string_view data);  // lower-case hex digest

private:
    void block(const std::uint8_t* p);

    std::array<std::uint32_t, 8> h_;
    std::array<std::uint8_t, 64> buf_{};
    std::size_t buf_len_ = 0;
    std::uint64_t total_ = 0;
};

}  // namespace frego::net
