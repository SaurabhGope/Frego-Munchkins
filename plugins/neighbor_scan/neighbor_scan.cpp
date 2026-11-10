#include "frego/plugins/neighbor_scan.hpp"

#include <vector>

#include "frego/platform/netinfo.hpp"
#include "frego/platform/probe.hpp"

namespace frego::plugins {
namespace {

class NeighborScanPlugin final : public Plugin {
public:
    PluginInfo info() const override {
        return {"neighbor-scan", "0.1.0", "Finds hosts on the home subnet from the ARP table (no root)", true};
    }

    void start(Context& ctx) override {
        interface_ = ctx.config().value("interface", std::string{"auto"});
        settle_ = std::chrono::milliseconds(ctx.config().value("settle_ms", 2000));
        auto interval = std::chrono::seconds(ctx.config().value("interval_s", 300));
        ctx.every(interval, [this, &ctx](std::stop_token st) { scan(ctx, st); });
    }

private:
    void scan(Context& ctx, std::stop_token st) {
        auto itf = platform::default_interface(interface_);
        if (!itf) {
            ctx.log().warn("neighbor-scan", "no usable interface: {}", itf.error());
            return;
        }
        const auto subnet = itf->subnet();
        // Sweeping more than a /22 (1022 hosts) is slow and rude; smaller than /30 is pointless.
        if (subnet.prefix >= 22 && subnet.prefix <= 30) {
            std::vector<net::Ipv4> hosts;
            for (auto v = subnet.network.value + 1; v < subnet.broadcast().value; ++v)
                if (v != itf->addr.value) hosts.push_back({v});
            platform::udp_nudge(hosts, st);
        } else {
            ctx.log().warn("neighbor-scan", "{} is outside /22–/30; reading the ARP table without a sweep", subnet.str());
        }
        if (!interruptible_sleep(st, settle_)) return;

        auto table = platform::arp_table(itf->name);
        if (!table) {
            ctx.log().warn("neighbor-scan", "ARP table: {}", table.error());
            return;
        }
        NeighborSnapshot snap{itf->name, subnet.str(), {}, {itf->addr.str(), 4, itf->mac ? itf->mac->str() : ""}};
        for (const auto& e : *table) {
            if (e.mac.multicast() || e.mac.is_zero() || e.ip.multicast()) continue;
            if (!subnet.contains(e.ip) || e.ip == subnet.broadcast() || e.ip == itf->addr) continue;
            snap.entries.push_back({e.ip.str(), 4, e.mac.str()});
        }
        const auto count = snap.entries.size();
        ctx.metrics().set("neighbor_scan.entries", static_cast<std::int64_t>(count));
        if (ctx.publish(std::move(snap)))
            ctx.log().info("neighbor-scan", "{}: {} neighbour(s) on {}", itf->name, count, subnet.str());
    }

    std::string interface_;
    std::chrono::milliseconds settle_{2000};
};

}  // namespace

std::unique_ptr<Plugin> make_neighbor_scan() { return std::make_unique<NeighborScanPlugin>(); }

}  // namespace frego::plugins
