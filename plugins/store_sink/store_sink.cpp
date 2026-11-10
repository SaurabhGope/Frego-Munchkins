#include "frego/plugins/store_sink.hpp"

#include <mutex>
#include <vector>

#include "frego/domain/store.hpp"

namespace frego::plugins {
namespace {

constexpr std::size_t kMaxBatch = 1000;

class StoreSinkPlugin final : public Plugin {
public:
    PluginInfo info() const override {
        return {"store-sink", "0.1.0", "Writes events to the local SQLite database", false};
    }

    std::vector<EventKind> subscriptions() const override {
        return {EventKind::Heartbeat, EventKind::DeviceIdentified, EventKind::Alert};
    }

    void start(Context& ctx) override {
        store_ = &ctx.service<domain::DomainStore>();
        ctx_ = &ctx;
        auto interval = std::chrono::milliseconds(ctx.config().value("flush_ms", 250));
        ctx.every(interval, [this](std::stop_token) { flush(); });
    }

    void on_event(const Event& e, Context&) override {
        if (is_critical(e.kind())) {
            // Committed before we return, so it can't be lost to a crash (DESIGN §6.2).
            store_->write(std::span(&e, 1));
            return;
        }
        bool full;
        {
            std::lock_guard lk(mu_);
            buffer_.push_back(e);
            full = buffer_.size() >= kMaxBatch;
        }
        if (full) flush();
    }

    void stop() override {
        if (store_) flush();
    }

private:
    void flush() {
        std::vector<Event> batch;
        {
            std::lock_guard lk(mu_);
            batch.swap(buffer_);
        }
        if (batch.empty()) return;
        store_->write(batch);
        ctx_->metrics().add("store.rows", static_cast<std::int64_t>(batch.size()));
    }

    domain::DomainStore* store_ = nullptr;
    Context* ctx_ = nullptr;
    std::mutex mu_;
    std::vector<Event> buffer_;
};

}  // namespace

std::unique_ptr<Plugin> make_store_sink() { return std::make_unique<StoreSinkPlugin>(); }

}  // namespace frego::plugins
