#pragma once

#include <atomic>
#include <chrono>

#include "frego/events/catalog.hpp"

namespace frego {

// Injected time (DESIGN §4.1 time rules). Plugins never call system_clock::now() directly,
// so replay tests can drive everything from a manual clock.
class TimeSource {
public:
    virtual Clock::time_point now() const = 0;
    virtual ~TimeSource() = default;
};

class SystemTimeSource final : public TimeSource {
public:
    Clock::time_point now() const override { return Clock::now(); }
};

class ManualTimeSource final : public TimeSource {
public:
    explicit ManualTimeSource(Clock::time_point start = from_unix_ms(1'767'225'600'000))  // 2026-01-01
        : rep_(start.time_since_epoch().count()) {}

    Clock::time_point now() const override { return Clock::time_point(Clock::duration(rep_.load())); }
    void set(Clock::time_point t) { rep_.store(t.time_since_epoch().count()); }
    void advance(Clock::duration d) { rep_.fetch_add(d.count()); }

private:
    std::atomic<Clock::rep> rep_;
};

}  // namespace frego
