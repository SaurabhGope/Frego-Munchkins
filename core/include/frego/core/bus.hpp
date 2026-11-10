#pragma once

#include <atomic>
#include <bitset>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "frego/core/log.hpp"
#include "frego/core/metrics.hpp"
#include "frego/core/time.hpp"
#include "frego/events/catalog.hpp"

namespace frego {

struct BusLimits {
    std::size_t ingress_bytes = 32u << 20;
    std::size_t mailbox_bytes = 8u << 20;
};

// Event bus (DESIGN §4.2). A router copies each event into the mailbox of every
// subscriber of its kind; each subscriber drains its own mailbox on its own worker, so
// a slow plugin can't stall the others. Two lanes everywhere: critical events are never
// dropped and are dequeued first; bulk lanes are bounded in bytes and drop when full.
// Publishing never blocks.
class Bus {
public:
    enum class Mode { Threaded, Synchronous };

    using Limits = BusLimits;

    using Handler = std::function<void(const Event&)>;
    using Filter = std::function<bool(const Event&)>;  // runs on the router thread

    struct Subscription {
        std::string name;
        std::vector<EventKind> kinds;
        Handler handler;
        Filter filter;                  // optional
        std::size_t mailbox_bytes = 0;  // 0 = Limits::mailbox_bytes
    };

    Bus(Mode mode, Metrics& metrics, Logger& log, const TimeSource& clock, Limits limits = {});
    ~Bus();
    Bus(const Bus&) = delete;
    Bus& operator=(const Bus&) = delete;

    // Subscribers are fixed before start(); in synchronous mode they run in this order.
    void subscribe(Subscription subscription);

    // Assigns id and published_at. Returns false if the event was dropped (bulk lane full)
    // or the bus has stopped.
    bool publish(std::string_view source, Payload payload, Clock::time_point observed_at,
                 SessionId session = kLiveSession);

    void start();
    // Waits for quiet (up to `drain_budget`), then stops all threads. Leftover critical
    // events are still delivered; leftover bulk events are counted as dropped.
    void stop(std::chrono::milliseconds drain_budget = std::chrono::seconds(2));

    // Synchronous mode: route and deliver everything, including events published by
    // handlers, until quiet. Returns the number of handler calls.
    std::size_t pump();
    // Threaded mode: true once every published event has been handled.
    bool wait_idle(std::chrono::milliseconds timeout);

    Mode mode() const { return mode_; }

private:
    struct Item {
        Event event;
        std::size_t size;
    };

    struct Queue {
        std::mutex mu;
        std::condition_variable_any cv;
        std::deque<Item> critical;
        std::deque<Item> bulk;
        std::size_t bulk_bytes = 0;
        std::size_t capacity = 0;

        bool empty_locked() const { return critical.empty() && bulk.empty(); }
        bool push_locked(Item&& item);
        Item pop_locked();
    };

    struct Subscriber {
        std::string name;
        std::bitset<kKindCount> kinds;
        Handler handler;
        Filter filter;
        Queue queue;
        std::jthread worker;
    };

    void route(const Event& e);
    void deliver(Subscriber& s, const Event& e);
    void router_loop(std::stop_token st);
    void worker_loop(Subscriber& s, std::stop_token st);
    void done_one();

    Mode mode_;
    Metrics& metrics_;
    Logger& log_;
    const TimeSource& clock_;
    Limits limits_;

    Queue ingress_;
    std::vector<std::unique_ptr<Subscriber>> subs_;
    std::uint64_t next_id_ = 1;  // guarded by ingress_.mu
    std::atomic<bool> accepting_{true};
    bool started_ = false;
    bool stopped_ = false;
    std::jthread router_;

    // Events in ingress + deliveries waiting in mailboxes or running; 0 means quiet.
    std::atomic<std::int64_t> pending_{0};
    std::mutex idle_mu_;
    std::condition_variable idle_cv_;

    std::atomic<std::int64_t>& published_;
    std::atomic<std::int64_t>& delivered_;
};

}  // namespace frego
