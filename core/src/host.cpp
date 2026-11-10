#include "frego/core/host.hpp"

#include <algorithm>
#include <deque>
#include <format>
#include <mutex>
#include <set>

namespace frego {
namespace {

constexpr int kMaxFailures = 5;
constexpr auto kFailureWindow = std::chrono::seconds(60);

class NullRoutes final : public HttpRoutes {
public:
    void get(const std::string&, HttpHandler) override {}
    void post(const std::string&, HttpHandler) override {}
    void patch(const std::string&, HttpHandler) override {}
};

}  // namespace

class PluginHost::Slot final : public Context {
public:
    Slot(PluginHost& host, std::unique_ptr<Plugin> plugin)
        : host_(host),
          plugin_(std::move(plugin)),
          info_(plugin_->info()),
          config_(host.deps_.config.plugin(info_.name)) {
        if (host.deps_.api)
            routes_ = host.deps_.api->routes(std::string(info_.name), [this] { return !disabled_.load(); });
        else
            routes_ = std::make_unique<NullRoutes>();
    }

    // --- Context ---
    std::string_view name() const override { return info_.name; }

    bool publish(Payload payload, std::optional<Clock::time_point> observed_at, SessionId session) override {
        if (info_.collects && session == kLiveSession && !host_.gate_open()) {
            host_.deps_.metrics.add("gate.refused");
            return false;
        }
        return host_.deps_.bus.publish(info_.name, std::move(payload), observed_at.value_or(clock().now()), session);
    }

    const TimeSource& clock() const override { return host_.deps_.clock; }
    Logger& log() override { return host_.deps_.log; }
    Metrics& metrics() override { return host_.deps_.metrics; }
    const nlohmann::json& config() const override { return config_; }
    const std::filesystem::path& data_dir() const override { return host_.deps_.data_dir; }
    const Services& services() const override { return host_.deps_.services; }
    HttpRoutes& http() override { return *routes_; }
    bool gate_open() const override { return host_.gate_open(); }

    void subscribe_custom(std::string type) override {
        std::lock_guard lk(custom_mu_);
        custom_types_.insert(std::move(type));
    }

    Scheduler::JobId every(std::chrono::milliseconds interval, Scheduler::Job job) override {
        auto id = host_.deps_.scheduler.every(
            std::string(info_.name), interval, [this, job = std::move(job)](std::stop_token st) {
                if (disabled_.load()) return;
                if (info_.collects && !host_.gate_open()) return;
                guarded("job", [&] { job(st); });
            });
        jobs_.push_back(id);
        return id;
    }

    void kick(Scheduler::JobId id) override { host_.deps_.scheduler.kick(id); }

    // --- host side ---
    std::vector<EventKind> kinds() {
        auto kinds = plugin_->subscriptions();
        wants_gate_events_ = std::ranges::find(kinds, EventKind::CollectionGate) != kinds.end();
        if (info_.collects && !wants_gate_events_) kinds.push_back(EventKind::CollectionGate);
        return kinds;
    }

    bool accepts(const Event& e) const {
        if (e.kind() != EventKind::Custom) return true;
        std::lock_guard lk(custom_mu_);
        return custom_types_.contains(std::get<Custom>(e.payload).type);
    }

    void deliver(const Event& e) {
        if (disabled_.load()) return;
        guarded("event", [&] {
            if (e.kind() == EventKind::CollectionGate && info_.collects) {
                plugin_->on_gate(std::get<CollectionGate>(e.payload).open, *this);
                if (!wants_gate_events_) return;
            }
            plugin_->on_event(e, *this);
        });
    }

    void start() {
        try {
            plugin_->start(*this);
            started_ = true;
        } catch (const std::exception& ex) {
            disable(std::format("start() failed: {}", ex.what()));
        }
    }

    void stop() {
        try {
            plugin_->stop();
        } catch (const std::exception& ex) {
            log().error(info_.name, "stop() threw: {}", ex.what());
        }
    }

    void kick_jobs() {
        for (auto id : jobs_) host_.deps_.scheduler.kick(id);
    }

    bool collects() const { return info_.collects; }

    nlohmann::json status() const {
        std::lock_guard lk(fail_mu_);
        return {{"name", info_.name},
                {"version", info_.version},
                {"description", info_.description},
                {"collects", info_.collects},
                {"state", disabled_ ? "disabled" : started_ ? "running" : "not_started"},
                {"failures", total_failures_},
                {"last_error", last_error_}};
    }

private:
    template <class F>
    void guarded(std::string_view what, F&& f) {
        try {
            f();
        } catch (const std::exception& ex) {
            failure(std::format("{}: {}", what, ex.what()));
        } catch (...) {
            failure(std::format("{}: unknown exception", what));
        }
    }

    void failure(std::string what) {
        const auto now = clock().now();
        bool trip = false;
        {
            std::lock_guard lk(fail_mu_);
            failures_.push_back(now);
            while (!failures_.empty() && now - failures_.front() > kFailureWindow) failures_.pop_front();
            ++total_failures_;
            last_error_ = what;
            trip = failures_.size() >= static_cast<std::size_t>(kMaxFailures);
        }
        log().error(info_.name, "{}", what);
        if (trip) disable(std::format("{} failures in {} s; last error: {}", kMaxFailures, kFailureWindow.count(), what));
    }

    void disable(std::string reason) {
        if (disabled_.exchange(true)) return;
        {
            std::lock_guard lk(fail_mu_);
            last_error_ = reason;
        }
        log().error(info_.name, "plugin disabled: {}", reason);
        host_.deps_.bus.publish("host",
                                Alert{std::format("plugin:{}", info_.name), "plugin_failed", Severity::Medium, "",
                                      std::format("Plugin {} was disabled", info_.name), reason},
                                clock().now());
    }

    PluginHost& host_;
    std::unique_ptr<Plugin> plugin_;
    PluginInfo info_;
    nlohmann::json config_;
    std::unique_ptr<HttpRoutes> routes_;
    std::vector<Scheduler::JobId> jobs_;
    bool wants_gate_events_ = false;
    bool started_ = false;
    std::atomic<bool> disabled_{false};

    mutable std::mutex custom_mu_;
    std::set<std::string, std::less<>> custom_types_;

    mutable std::mutex fail_mu_;
    std::deque<Clock::time_point> failures_;
    std::int64_t total_failures_ = 0;
    std::string last_error_;
};

PluginHost::PluginHost(Deps deps) : deps_(std::move(deps)) {
    // The host's own subscription comes first, so in synchronous mode the gate state is
    // updated before any plugin sees the same CollectionGate event.
    deps_.bus.subscribe({"host", {EventKind::CollectionGate}, [this](const Event& e) { on_gate_event(e); }, {}, 0});
}

PluginHost::~PluginHost() = default;

void PluginHost::add(std::unique_ptr<Plugin> plugin) {
    auto slot = std::make_unique<Slot>(*this, std::move(plugin));
    Slot* raw = slot.get();
    auto kinds = raw->kinds();
    if (!kinds.empty()) {
        deps_.bus.subscribe({std::string(raw->name()), kinds, [raw](const Event& e) { raw->deliver(e); },
                             [raw](const Event& e) { return raw->accepts(e); }, 0});
    }
    slots_.push_back(std::move(slot));
}

void PluginHost::on_gate_event(const Event& e) {
    const auto& gate = std::get<CollectionGate>(e.payload);
    const bool was_open = gate_open_.exchange(gate.open);
    if (gate.open == was_open) return;
    deps_.log.info("host", "collection gate {}: {}", gate.open ? "OPEN" : "closed", gate.reason);
    deps_.metrics.set("gate.open", gate.open ? 1 : 0);
    if (gate.open)  // jobs run again, the first one immediately
        for (auto& s : slots_)
            if (s->collects()) s->kick_jobs();
}

void PluginHost::start_all() {
    for (auto& s : slots_) s->start();
}

void PluginHost::stop_jobs() { deps_.scheduler.stop_all(); }

void PluginHost::stop_all() {
    for (auto it = slots_.rbegin(); it != slots_.rend(); ++it) (*it)->stop();
}

nlohmann::json PluginHost::status() const {
    nlohmann::json out = nlohmann::json::array();
    for (const auto& s : slots_) out.push_back(s->status());
    return out;
}

}  // namespace frego
