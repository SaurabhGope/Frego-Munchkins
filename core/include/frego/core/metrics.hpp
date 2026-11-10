#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace frego {

// Named atomic counters and gauges, served at /api/v1/metrics (DESIGN §4.6).
class Metrics {
public:
    // The returned reference stays valid for the registry's lifetime; cache it on hot paths.
    std::atomic<std::int64_t>& counter(std::string_view name);
    void add(std::string_view name, std::int64_t delta = 1) { counter(name).fetch_add(delta, std::memory_order_relaxed); }
    void set(std::string_view name, std::int64_t value) { counter(name).store(value, std::memory_order_relaxed); }
    std::int64_t get(std::string_view name) const;
    nlohmann::json snapshot() const;

private:
    mutable std::mutex mu_;
    std::map<std::string, std::unique_ptr<std::atomic<std::int64_t>>, std::less<>> values_;
};

}  // namespace frego
