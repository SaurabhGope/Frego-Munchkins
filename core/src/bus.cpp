#include "frego/core/bus.hpp"

#include <format>

namespace frego {

bool Bus::Queue::push_locked(Item&& item) {
    if (is_critical(item.event.kind())) {
        critical.push_back(std::move(item));
        return true;
    }
    if (bulk_bytes + item.size > capacity) return false;
    bulk_bytes += item.size;
    bulk.push_back(std::move(item));
    return true;
}

Bus::Item Bus::Queue::pop_locked() {
    if (!critical.empty()) {
        Item item = std::move(critical.front());
        critical.pop_front();
        return item;
    }
    Item item = std::move(bulk.front());
    bulk.pop_front();
    bulk_bytes -= item.size;
    return item;
}

Bus::Bus(Mode mode, Metrics& metrics, Logger& log, const TimeSource& clock, Limits limits)
    : mode_(mode),
      metrics_(metrics),
      log_(log),
      clock_(clock),
      limits_(limits),
      published_(metrics.counter("bus.published")),
      delivered_(metrics.counter("bus.delivered")) {
    ingress_.capacity = limits_.ingress_bytes;
}

Bus::~Bus() { stop(std::chrono::milliseconds(0)); }

void Bus::subscribe(Subscription subscription) {
    if (started_) throw std::logic_error("Bus::subscribe after start()");
    auto s = std::make_unique<Subscriber>();
    s->name = std::move(subscription.name);
    for (auto k : subscription.kinds) s->kinds.set(static_cast<std::size_t>(k));
    s->handler = std::move(subscription.handler);
    s->filter = std::move(subscription.filter);
    s->queue.capacity = subscription.mailbox_bytes ? subscription.mailbox_bytes : limits_.mailbox_bytes;
    subs_.push_back(std::move(s));
}

bool Bus::publish(std::string_view source, Payload payload, Clock::time_point observed_at,
                  SessionId session) {
    if (!accepting_) return false;
    const EventKind kind = kind_of(payload);
    {
        std::lock_guard lk(ingress_.mu);
        Event e{next_id_, observed_at, clock_.now(), session, source, std::move(payload)};
        Item item{std::move(e), 0};
        item.size = approx_size(item.event);
        ++pending_;
        if (!ingress_.push_locked(std::move(item))) {
            metrics_.add(std::format("bus.dropped.ingress.{}", kind_name(kind)));
            done_one();
            return false;
        }
        ++next_id_;
        if (ingress_.critical.size() > 10'000) metrics_.set("bus.critical_backlog", static_cast<std::int64_t>(ingress_.critical.size()));
    }
    ingress_.cv.notify_one();
    published_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void Bus::route(const Event& e) {
    const auto idx = static_cast<std::size_t>(e.kind());
    for (auto& s : subs_) {
        if (!s->kinds.test(idx)) continue;
        if (s->filter && !s->filter(e)) continue;
        Item copy{e, approx_size(e)};
        bool ok;
        {
            std::lock_guard lk(s->queue.mu);
            ++pending_;
            ok = s->queue.push_locked(std::move(copy));
        }
        if (ok) {
            s->queue.cv.notify_one();
        } else {
            metrics_.add(std::format("bus.dropped.{}.{}", s->name, kind_name(e.kind())));
            done_one();
        }
    }
}

void Bus::deliver(Subscriber& s, const Event& e) {
    try {
        s.handler(e);
    } catch (const std::exception& ex) {
        log_.error("bus", "subscriber {} threw on {}: {}", s.name, kind_name(e.kind()), ex.what());
    } catch (...) {
        log_.error("bus", "subscriber {} threw on {}", s.name, kind_name(e.kind()));
    }
    delivered_.fetch_add(1, std::memory_order_relaxed);
}

void Bus::done_one() {
    if (--pending_ == 0) {
        std::lock_guard lk(idle_mu_);
        idle_cv_.notify_all();
    }
}

void Bus::router_loop(std::stop_token st) {
    while (true) {
        Item item;
        {
            std::unique_lock lk(ingress_.mu);
            ingress_.cv.wait(lk, st, [&] { return !ingress_.empty_locked(); });
            if (ingress_.empty_locked()) return;  // stop requested and nothing left
            item = ingress_.pop_locked();
        }
        route(item.event);
        done_one();
    }
}

void Bus::worker_loop(Subscriber& s, std::stop_token st) {
    while (true) {
        Item item;
        {
            std::unique_lock lk(s.queue.mu);
            s.queue.cv.wait(lk, st, [&] { return !s.queue.empty_locked(); });
            if (st.stop_requested()) return;  // stop() handles leftovers
            item = s.queue.pop_locked();
        }
        deliver(s, item.event);
        done_one();
    }
}

void Bus::start() {
    if (started_) return;
    started_ = true;
    if (mode_ != Mode::Threaded) return;
    router_ = std::jthread([this](std::stop_token st) { router_loop(st); });
    for (auto& s : subs_) {
        Subscriber* raw = s.get();
        s->worker = std::jthread([this, raw](std::stop_token st) { worker_loop(*raw, st); });
    }
}

bool Bus::wait_idle(std::chrono::milliseconds timeout) {
    std::unique_lock lk(idle_mu_);
    return idle_cv_.wait_for(lk, timeout, [&] { return pending_.load() == 0; });
}

std::size_t Bus::pump() {
    if (mode_ != Mode::Synchronous) throw std::logic_error("Bus::pump needs Mode::Synchronous");
    std::size_t handled = 0;
    bool progress = true;
    while (progress) {
        progress = false;
        while (true) {
            Item item;
            {
                std::lock_guard lk(ingress_.mu);
                if (ingress_.empty_locked()) break;
                item = ingress_.pop_locked();
            }
            route(item.event);
            done_one();
            progress = true;
        }
        for (auto& s : subs_) {
            while (true) {
                Item item;
                {
                    std::lock_guard lk(s->queue.mu);
                    if (s->queue.empty_locked()) break;
                    item = s->queue.pop_locked();
                }
                deliver(*s, item.event);
                done_one();
                ++handled;
                progress = true;
            }
        }
    }
    return handled;
}

void Bus::stop(std::chrono::milliseconds drain_budget) {
    if (stopped_) return;
    stopped_ = true;
    if (mode_ == Mode::Synchronous) {
        pump();
        accepting_ = false;
        return;
    }
    if (!started_) {
        accepting_ = false;
        return;
    }
    // Let handlers finish what's queued; they may still publish while we wait.
    wait_idle(drain_budget);
    accepting_ = false;

    router_.request_stop();
    if (router_.joinable()) router_.join();
    for (auto& s : subs_) {
        s->worker.request_stop();
        if (s->worker.joinable()) s->worker.join();
    }

    // Leftovers: critical events are always delivered (on this thread); bulk is dropped.
    std::size_t dropped = 0;
    {
        std::lock_guard lk(ingress_.mu);
        while (!ingress_.empty_locked()) {
            Item item = ingress_.pop_locked();
            if (is_critical(item.event.kind())) route(item.event);
            else ++dropped;
            done_one();
        }
    }
    for (auto& s : subs_) {
        std::deque<Item> critical;
        {
            std::lock_guard lk(s->queue.mu);
            critical.swap(s->queue.critical);
            dropped += s->queue.bulk.size();
            for (std::size_t i = 0; i < s->queue.bulk.size(); ++i) done_one();
            s->queue.bulk.clear();
            s->queue.bulk_bytes = 0;
        }
        for (auto& item : critical) {
            deliver(*s, item.event);
            done_one();
        }
    }
    if (dropped) {
        metrics_.add("bus.dropped.shutdown", static_cast<std::int64_t>(dropped));
        log_.warn("bus", "dropped {} bulk event(s) still queued at shutdown", dropped);
    }
}

}  // namespace frego
