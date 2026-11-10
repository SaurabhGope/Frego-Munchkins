#include "frego/core/scheduler.hpp"

namespace frego {

ThreadedScheduler::~ThreadedScheduler() { stop_all(); }

Scheduler::JobId ThreadedScheduler::every(std::string, std::chrono::milliseconds interval, Job job) {
    auto state = std::make_shared<State>();
    std::lock_guard lk(mu_);
    JobId id = next_++;
    state->thread = std::jthread([state_ptr = state.get(), interval, job = std::move(job)](std::stop_token st) {
        while (!st.stop_requested()) {
            job(st);
            std::unique_lock lk2(state_ptr->mu);
            state_ptr->cv.wait_for(lk2, st, interval, [&] { return state_ptr->kicked; });
            state_ptr->kicked = false;
        }
    });
    jobs_.emplace(id, std::move(state));
    return id;
}

void ThreadedScheduler::kick(JobId id) {
    std::shared_ptr<State> state;
    {
        std::lock_guard lk(mu_);
        auto it = jobs_.find(id);
        if (it == jobs_.end()) return;
        state = it->second;
    }
    {
        std::lock_guard lk(state->mu);
        state->kicked = true;
    }
    state->cv.notify_all();
}

void ThreadedScheduler::stop_all() {
    std::map<JobId, std::shared_ptr<State>> jobs;
    {
        std::lock_guard lk(mu_);
        jobs.swap(jobs_);
    }
    for (auto& [_, state] : jobs) state->thread.request_stop();
    for (auto& [_, state] : jobs)
        if (state->thread.joinable()) state->thread.join();
}

Scheduler::JobId ManualScheduler::every(std::string, std::chrono::milliseconds interval, Job job) {
    JobId id = next_++;
    jobs_.emplace(id, Entry{interval, std::move(job), clock_.now()});
    return id;
}

void ManualScheduler::kick(JobId id) {
    if (auto it = jobs_.find(id); it != jobs_.end()) it->second.due = clock_.now();
}

void ManualScheduler::stop_all() {
    stop_.request_stop();
    jobs_.clear();
}

std::size_t ManualScheduler::run_due() {
    std::size_t ran = 0;
    const auto now = clock_.now();
    for (auto& [_, entry] : jobs_) {
        if (entry.due > now) continue;
        entry.job(stop_.get_token());
        entry.due = now + entry.interval;
        ++ran;
    }
    return ran;
}

}  // namespace frego
