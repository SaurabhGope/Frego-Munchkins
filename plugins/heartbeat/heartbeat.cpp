#include "frego/plugins/heartbeat.hpp"

#include <atomic>

namespace frego::plugins {
namespace {

class HeartbeatPlugin final : public Plugin {
public:
    PluginInfo info() const override {
        return {"heartbeat", "0.1.0", "Emits a heartbeat to prove the bus, store and API path", false};
    }

    void start(Context& ctx) override {
        auto interval = std::chrono::seconds(ctx.config().value("interval_s", 5));
        ctx.every(interval, [this, &ctx](std::stop_token) { ctx.publish(Heartbeat{++seq_}); });
    }

private:
    std::atomic<std::uint64_t> seq_{0};
};

}  // namespace

std::unique_ptr<Plugin> make_heartbeat() { return std::make_unique<HeartbeatPlugin>(); }

}  // namespace frego::plugins
