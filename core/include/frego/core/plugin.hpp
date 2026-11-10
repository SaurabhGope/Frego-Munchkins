#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "frego/core/http.hpp"
#include "frego/core/log.hpp"
#include "frego/core/metrics.hpp"
#include "frego/core/scheduler.hpp"
#include "frego/core/services.hpp"
#include "frego/core/time.hpp"
#include "frego/events/catalog.hpp"

namespace frego {

inline constexpr std::uint32_t kPluginApiVersion = 1;

struct PluginInfo {
    std::string_view name;  // static storage, e.g. "neighbor-scan"
    std::string_view version;
    std::string_view description;
    bool collects = false;  // touches the network / produces live observations → gated (§4.3)
};

// Handed to plugins by the host (DESIGN §4.3).
class Context {
public:
    virtual ~Context() = default;

    virtual std::string_view name() const = 0;
    // observed_at defaults to clock().now(). Collecting plugins' live-session events are
    // refused (returns false) while the collection gate is closed.
    virtual bool publish(Payload payload, std::optional<Clock::time_point> observed_at = std::nullopt,
                         SessionId session = kLiveSession) = 0;
    virtual const TimeSource& clock() const = 0;
    virtual Logger& log() = 0;
    virtual Metrics& metrics() = 0;
    virtual const nlohmann::json& config() const = 0;  // this plugin's config section
    virtual const std::filesystem::path& data_dir() const = 0;
    virtual const Services& services() const = 0;
    virtual HttpRoutes& http() = 0;  // domain endpoints; guards applied by the host
    virtual void subscribe_custom(std::string type) = 0;
    // Runs job now, then every interval (skipped while disabled or, for collecting plugins,
    // while the gate is closed). Call from start().
    virtual Scheduler::JobId every(std::chrono::milliseconds interval, Scheduler::Job job) = 0;
    virtual void kick(Scheduler::JobId id) = 0;
    virtual bool gate_open() const = 0;

    template <class T>
    T& service() const {
        return services().template get<T>();
    }
};

// One interface for every role: sources publish from start(), analyzers subscribe and
// publish, sinks subscribe and write.
class Plugin {
public:
    virtual ~Plugin() = default;
    virtual PluginInfo info() const = 0;
    virtual std::vector<EventKind> subscriptions() const { return {}; }
    virtual void start(Context&) {}
    // Called on the plugin's own bus worker; jobs run on scheduler threads, so plugins
    // that share state between the two must synchronise it.
    virtual void on_event(const Event&, Context&) {}
    // Collecting plugins only; delivered on the plugin's own bus worker.
    virtual void on_gate(bool /*open*/, Context&) {}
    virtual void stop() {}  // must be idempotent
};

class PluginRegistry {
public:
    using Factory = std::unique_ptr<Plugin> (*)();
    void add(std::string name, Factory factory) { entries_.emplace_back(std::move(name), factory); }
    bool contains(std::string_view name) const;
    std::unique_ptr<Plugin> create(std::string_view name) const;
    std::vector<std::string> names() const;

private:
    std::vector<std::pair<std::string, Factory>> entries_;
};

// Sleeps up to d; returns false as soon as stop is requested.
bool interruptible_sleep(std::stop_token stop, std::chrono::milliseconds d);

}  // namespace frego
