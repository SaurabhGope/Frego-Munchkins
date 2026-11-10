#include "frego/core/plugin.hpp"

#include <condition_variable>
#include <mutex>

namespace frego {

bool PluginRegistry::contains(std::string_view name) const {
    for (const auto& [n, _] : entries_)
        if (n == name) return true;
    return false;
}

std::unique_ptr<Plugin> PluginRegistry::create(std::string_view name) const {
    for (const auto& [n, factory] : entries_)
        if (n == name) return factory();
    return nullptr;
}

std::vector<std::string> PluginRegistry::names() const {
    std::vector<std::string> out;
    for (const auto& [n, _] : entries_) out.push_back(n);
    return out;
}

bool interruptible_sleep(std::stop_token stop, std::chrono::milliseconds d) {
    std::mutex m;
    std::condition_variable_any cv;
    std::unique_lock lk(m);
    cv.wait_for(lk, stop, d, [] { return false; });
    return !stop.stop_requested();
}

}  // namespace frego
