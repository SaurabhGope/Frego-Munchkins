#pragma once

#include <atomic>
#include <filesystem>
#include <memory>
#include <vector>

#include <nlohmann/json.hpp>

#include "frego/core/bus.hpp"
#include "frego/core/config.hpp"
#include "frego/core/http.hpp"
#include "frego/core/plugin.hpp"

namespace frego {

// Owns plugins, gives each a Context, and enforces the collection gate and fault
// isolation (DESIGN §4.3).
class PluginHost {
public:
    struct Deps {
        Bus& bus;
        Logger& log;
        Metrics& metrics;
        const Config& config;
        const TimeSource& clock;
        Scheduler& scheduler;
        const Services& services;
        ApiServer* api;  // null in tests: routes are accepted and ignored
        std::filesystem::path data_dir;
    };

    explicit PluginHost(Deps deps);
    ~PluginHost();
    PluginHost(const PluginHost&) = delete;
    PluginHost& operator=(const PluginHost&) = delete;

    void add(std::unique_ptr<Plugin> plugin);  // before bus.start()
    void start_all();
    void stop_jobs();  // shutdown phase 1: no new publishes from jobs
    void stop_all();   // shutdown phase 3, after the bus drained: plugin->stop() in reverse

    bool gate_open() const { return gate_open_.load(); }
    nlohmann::json status() const;

private:
    class Slot;
    void on_gate_event(const Event& e);

    Deps deps_;
    std::vector<std::unique_ptr<Slot>> slots_;
    std::atomic<bool> gate_open_{false};  // closed until network-guard says otherwise
};

}  // namespace frego
