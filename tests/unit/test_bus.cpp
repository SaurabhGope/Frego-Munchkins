#include <atomic>
#include <thread>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "frego/core/bus.hpp"

using namespace frego;
using namespace std::chrono_literals;

namespace {

struct Fixture {
    Metrics metrics;
    Logger log{LogLevel::Error, false};
    ManualTimeSource clock;
};

Clock::time_point t0() { return from_unix_ms(1'000); }

}  // namespace

TEST_CASE("synchronous bus delivers in publish order to matching subscribers only", "[bus]") {
    Fixture f;
    Bus bus(Bus::Mode::Synchronous, f.metrics, f.log, f.clock);
    std::vector<std::uint64_t> beats;
    int alerts = 0;
    bus.subscribe({"a", {EventKind::Heartbeat}, [&](const Event& e) { beats.push_back(std::get<Heartbeat>(e.payload).seq); }, {}, 0});
    bus.subscribe({"b", {EventKind::Alert}, [&](const Event&) { ++alerts; }, {}, 0});
    bus.start();
    for (std::uint64_t i = 1; i <= 5; ++i) REQUIRE(bus.publish("test", Heartbeat{i}, t0()));
    CHECK(bus.pump() == 5);
    CHECK(beats == std::vector<std::uint64_t>{1, 2, 3, 4, 5});
    CHECK(alerts == 0);
}

TEST_CASE("bus stamps ids and published_at but keeps observed_at and session", "[bus]") {
    Fixture f;
    Bus bus(Bus::Mode::Synchronous, f.metrics, f.log, f.clock);
    std::vector<Event> seen;
    bus.subscribe({"a", {EventKind::Heartbeat}, [&](const Event& e) { seen.push_back(e); }, {}, 0});
    bus.start();
    bus.publish("src", Heartbeat{1}, from_unix_ms(5), 9);
    bus.publish("src", Heartbeat{2}, from_unix_ms(6));
    bus.pump();
    REQUIRE(seen.size() == 2);
    CHECK(seen[0].id < seen[1].id);
    CHECK(seen[0].observed_at == from_unix_ms(5));
    CHECK(seen[0].published_at == f.clock.now());
    CHECK(seen[0].session == 9);
    CHECK(seen[1].session == kLiveSession);
    CHECK(seen[0].source == "src");
}

TEST_CASE("critical events overtake earlier bulk events", "[bus]") {
    Fixture f;
    Bus bus(Bus::Mode::Synchronous, f.metrics, f.log, f.clock);
    std::vector<EventKind> order;
    bus.subscribe({"a", {EventKind::Heartbeat, EventKind::Alert}, [&](const Event& e) { order.push_back(e.kind()); }, {}, 0});
    bus.start();
    bus.publish("t", Heartbeat{1}, t0());
    bus.publish("t", Alert{"k", "x", Severity::High, "", "t", "r"}, t0());
    bus.pump();
    CHECK(order == std::vector<EventKind>{EventKind::Alert, EventKind::Heartbeat});
}

TEST_CASE("bulk lanes are bounded in bytes; critical lanes never drop", "[bus]") {
    Fixture f;
    const std::size_t one = approx_size(Event{0, {}, {}, 0, "t", Heartbeat{}});
    Bus bus(Bus::Mode::Synchronous, f.metrics, f.log, f.clock, {one * 2, one * 64});
    int beats = 0, alerts = 0;
    bus.subscribe({"a", {EventKind::Heartbeat, EventKind::Alert}, [&](const Event& e) {
                       (e.kind() == EventKind::Alert ? alerts : beats)++;
                   }, {}, 0});
    bus.start();
    CHECK(bus.publish("t", Heartbeat{1}, t0()));
    CHECK(bus.publish("t", Heartbeat{2}, t0()));
    CHECK_FALSE(bus.publish("t", Heartbeat{3}, t0()));  // ingress full
    for (int i = 0; i < 100; ++i) CHECK(bus.publish("t", Alert{std::to_string(i), "x", Severity::Low, "", "t", "r"}, t0()));
    bus.pump();
    CHECK(beats == 2);
    CHECK(alerts == 100);
    CHECK(f.metrics.get("bus.dropped.ingress.Heartbeat") == 1);
}

TEST_CASE("subscribers may publish; events queue instead of recursing", "[bus]") {
    Fixture f;
    Bus bus(Bus::Mode::Synchronous, f.metrics, f.log, f.clock);
    std::vector<std::uint64_t> seen;
    int depth = 0, max_depth = 0;
    bus.subscribe({"a", {EventKind::Heartbeat}, [&](const Event& e) {
                       max_depth = std::max(max_depth, ++depth);
                       auto seq = std::get<Heartbeat>(e.payload).seq;
                       seen.push_back(seq);
                       if (seq < 3) bus.publish("a", Heartbeat{seq + 1}, t0());
                       --depth;
                   }, {}, 0});
    bus.start();
    bus.publish("t", Heartbeat{1}, t0());
    bus.pump();
    CHECK(seen == std::vector<std::uint64_t>{1, 2, 3});
    CHECK(max_depth == 1);
}

TEST_CASE("subscriber filters run before delivery", "[bus]") {
    Fixture f;
    Bus bus(Bus::Mode::Synchronous, f.metrics, f.log, f.clock);
    int got = 0;
    bus.subscribe({"a", {EventKind::Custom}, [&](const Event&) { ++got; },
                   [](const Event& e) { return std::get<Custom>(e.payload).type == "org.mine"; }, 0});
    bus.start();
    bus.publish("t", Custom{"org.mine", 1, {}}, t0());
    bus.publish("t", Custom{"org.other", 1, {}}, t0());
    bus.pump();
    CHECK(got == 1);
}

TEST_CASE("threaded bus: a slow subscriber doesn't delay others", "[bus]") {
    Fixture f;
    SystemTimeSource clock;
    Bus bus(Bus::Mode::Threaded, f.metrics, f.log, clock);
    std::atomic<int> fast{0};
    std::atomic<bool> release{false};
    bus.subscribe({"slow", {EventKind::Heartbeat}, [&](const Event&) {
                       while (!release) std::this_thread::sleep_for(1ms);
                   }, {}, 0});
    bus.subscribe({"fast", {EventKind::Heartbeat}, [&](const Event&) { ++fast; }, {}, 0});
    bus.start();
    for (std::uint64_t i = 0; i < 50; ++i) bus.publish("t", Heartbeat{i}, clock.now());
    for (int i = 0; i < 200 && fast < 50; ++i) std::this_thread::sleep_for(5ms);
    CHECK(fast == 50);  // all delivered while "slow" is still stuck on the first one
    release = true;
    CHECK(bus.wait_idle(2s));
    bus.stop(1s);
}

TEST_CASE("threaded bus stop drains, then refuses new events", "[bus]") {
    Fixture f;
    SystemTimeSource clock;
    Bus bus(Bus::Mode::Threaded, f.metrics, f.log, clock);
    std::atomic<int> got{0};
    bus.subscribe({"a", {EventKind::Heartbeat, EventKind::Alert}, [&](const Event&) { ++got; }, {}, 0});
    bus.start();
    for (std::uint64_t i = 0; i < 100; ++i) bus.publish("t", Heartbeat{i}, clock.now());
    bus.publish("t", Alert{"k", "x", Severity::High, "", "t", "r"}, clock.now());
    bus.stop(2s);
    CHECK(got == 101);
    CHECK_FALSE(bus.publish("t", Heartbeat{1}, clock.now()));
}
