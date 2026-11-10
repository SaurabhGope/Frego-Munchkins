#include "frego/core/metrics.hpp"

namespace frego {

std::atomic<std::int64_t>& Metrics::counter(std::string_view name) {
    std::lock_guard lk(mu_);
    auto it = values_.find(name);
    if (it == values_.end())
        it = values_.emplace(std::string(name), std::make_unique<std::atomic<std::int64_t>>(0)).first;
    return *it->second;
}

std::int64_t Metrics::get(std::string_view name) const {
    std::lock_guard lk(mu_);
    auto it = values_.find(name);
    return it == values_.end() ? 0 : it->second->load(std::memory_order_relaxed);
}

nlohmann::json Metrics::snapshot() const {
    std::lock_guard lk(mu_);
    nlohmann::json out = nlohmann::json::object();
    for (const auto& [name, value] : values_) out[name] = value->load(std::memory_order_relaxed);
    return out;
}

}  // namespace frego
