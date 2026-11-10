#include <chrono>
#include <format>
#include <mutex>
#include <random>

#include "frego/domain/store.hpp"

namespace frego::domain {

std::string new_device_id() {
    static std::mutex mu;
    static std::mt19937_64 rng{std::random_device{}()};
    std::uint64_t r1, r2;
    {
        std::lock_guard lk(mu);
        r1 = rng();
        r2 = rng();
    }
    // RFC 9562 UUIDv7: 48-bit unix ms, version 7, 12 random bits, variant 10, 62 random bits.
    const auto ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                   std::chrono::system_clock::now().time_since_epoch())
                                                   .count());
    const std::uint64_t hi = (ms << 16) | 0x7000 | (r1 & 0x0FFF);
    const std::uint64_t lo = (r2 & 0x3FFFFFFFFFFFFFFFull) | 0x8000000000000000ull;
    return std::format("dev_{:08x}-{:04x}-{:04x}-{:04x}-{:012x}", hi >> 32, (hi >> 16) & 0xFFFF, hi & 0xFFFF,
                       lo >> 48, lo & 0xFFFFFFFFFFFFull);
}

}  // namespace frego::domain
