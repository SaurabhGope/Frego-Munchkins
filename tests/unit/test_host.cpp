#include <stdexcept>

#include <catch2/catch_test_macros.hpp>

#include "frego/core/host.hpp"

using namespace frego;
using namespace std::chrono_literals;

namespace {

struct Collector final : Plugin {
    Context* ctx = nullptr;
    int runs = 0;
    std::vector<bool> gates;
    PluginInfo info() const override { return {"collector", "0", "test", true}; }
    void start(Context& c) override {
        ctx = &c;
        c.every(1min, [this](std::stop_token) {
            ++runs;
            ctx->publish(Heartbeat{static_cast<std::uint64_t>(runs)});
        });
    }
    void on_gate(bool open, Context&) override { gates.push_back(open); }
};

struct Thrower final : Plugin {
    PluginInfo info() const override { return {"thrower", "0", "test", false}; }
    std::vector<EventKind> subscriptions() const override { return {EventKind::Heartbeat}; }
    void on_event(const Event&, Context&) override { throw std::runtime_error("boom"); }
};

struct CustomListener final : Plugin {
    std::vector<std::string> seen;
    PluginInfo info() const override { return {"listener", "0", "test", false}; }
    std::vector<EventKind> subscriptions() const override { return {EventKind::Custom}; }
    void start(Context& c) override { c.subscribe_custom("org.mine"); }
    void on_event(const Event& e, Context&) override { seen.push_back(std::get<Custom>(e.payload).type); }
};

struct Fixture {
    Metrics metrics;
    Logger log{LogLevel::Error, false};
    ManualTimeSource clock;
    ManualScheduler scheduler{clock};
    Services services;
    Config config = Config::from_json({});
    Bus bus{Bus::Mode::Synchronous, metrics, log, clock};
    PluginHost host{{bus, log, metrics, config, clock, scheduler, services, nullptr, "/tmp"}};
    std::vector<Alert> alerts;

    void watch_alerts() {
        bus.subscribe({"alerts", {EventKind::Alert}, [this](const Event& e) { alerts.push_back(std::get<Alert>(e.payload)); }, {}, 0});
    }
    void gate(bool open) {
        bus.publish("network-guard", CollectionGate{open, open ? "home" : "away"}, clock.now());
        bus.pump();
    }
};

}  // namespace

TEST_CASE("collecting plugins are gated until the gate opens", "[host]") {
    Fixture f;
    auto owned = std::make_unique<Collector>();
    auto* c = owned.get();
    f.host.add(std::move(owned));
    f.bus.start();
    f.host.start_all();

    f.scheduler.run_due();
    CHECK(c->runs == 0);  // the gate starts closed
    CHECK_FALSE(c->ctx->publish(Heartbeat{99}));
    CHECK(f.metrics.get("gate.refused") == 1);

    f.gate(true);
    CHECK(f.host.gate_open());
    CHECK(c->gates == std::vector<bool>{true});
    f.scheduler.run_due();  // opening kicks the job: it runs immediately
    CHECK(c->runs == 1);
    CHECK(c->ctx->publish(Heartbeat{100}));

    f.gate(false);
    CHECK(c->gates == std::vector<bool>{true, false});
    CHECK_FALSE(c->ctx->publish(Heartbeat{101}));
    // Investigation sessions aren't gated: they never touch the network.
    CHECK(c->ctx->publish(Heartbeat{102}, std::nullopt, 7));
}

TEST_CASE("a plugin failing 5 times in 60 s is disabled and raises an alert", "[host]") {
    Fixture f;
    f.host.add(std::make_unique<Thrower>());
    f.watch_alerts();
    f.bus.start();
    f.host.start_all();
    for (std::uint64_t i = 0; i < 7; ++i) f.bus.publish("t", Heartbeat{i}, f.clock.now());
    f.bus.pump();

    REQUIRE(f.alerts.size() == 1);
    CHECK(f.alerts[0].kind == "plugin_failed");
    CHECK(f.alerts[0].key == "plugin:thrower");
    auto status = f.host.status();
    CHECK(status[0]["state"] == "disabled");
    CHECK(status[0]["failures"] == 5);  // nothing delivered after it was disabled
}

TEST_CASE("failures spread over more than 60 s don't disable a plugin", "[host]") {
    Fixture f;
    f.host.add(std::make_unique<Thrower>());
    f.bus.start();
    f.host.start_all();
    for (std::uint64_t i = 0; i < 8; ++i) {
        f.bus.publish("t", Heartbeat{i}, f.clock.now());
        f.bus.pump();
        f.clock.advance(20s);
    }
    CHECK(f.host.status()[0]["state"] == "running");
}

TEST_CASE("custom events reach only plugins that asked for that type", "[host]") {
    Fixture f;
    auto owned = std::make_unique<CustomListener>();
    auto* l = owned.get();
    f.host.add(std::move(owned));
    f.bus.start();
    f.host.start_all();
    f.bus.publish("t", Custom{"org.mine", 1, {}}, f.clock.now());
    f.bus.publish("t", Custom{"org.other", 1, {}}, f.clock.now());
    f.bus.pump();
    CHECK(l->seen == std::vector<std::string>{"org.mine"});
}
