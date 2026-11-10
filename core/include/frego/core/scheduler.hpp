#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>

#include "frego/core/time.hpp"

namespace frego {

// Periodic jobs for plugins (ctx.every()). Each job runs immediately, then every
// `interval`; kick() runs it again as soon as possible (e.g. when the gate opens).
class Scheduler {
public:
    using JobId = std::uint64_t;
    using Job = std::function<void(std::stop_token)>;

    virtual ~Scheduler() = default;
    virtual JobId every(std::string name, std::chrono::milliseconds interval, Job job) = 0;
    virtual void kick(JobId id) = 0;
    virtual void stop_all() = 0;
};

// Production: one thread per job, sleeping on a condition variable.
class ThreadedScheduler final : public Scheduler {
public:
    ~ThreadedScheduler() override;
    JobId every(std::string name, std::chrono::milliseconds interval, Job job) override;
    void kick(JobId id) override;
    void stop_all() override;

private:
    struct State {
        std::mutex mu;
        std::condition_variable_any cv;
        bool kicked = false;
        std::jthread thread;
    };
    std::mutex mu_;
    std::map<JobId, std::shared_ptr<State>> jobs_;
    JobId next_ = 1;
};

// Tests and replay: jobs run only when run_due() is called, against a manual clock.
class ManualScheduler final : public Scheduler {
public:
    explicit ManualScheduler(const TimeSource& clock) : clock_(clock) {}
    JobId every(std::string name, std::chrono::milliseconds interval, Job job) override;
    void kick(JobId id) override;
    void stop_all() override;
    std::size_t run_due();  // runs every job whose time has come; returns how many ran

private:
    struct Entry {
        std::chrono::milliseconds interval;
        Job job;
        Clock::time_point due;
    };
    const TimeSource& clock_;
    std::stop_source stop_;
    std::map<JobId, Entry> jobs_;
    JobId next_ = 1;
};

}  // namespace frego
