#include <algorithm>
#include <cstdint>
#include <mutex>

#include "frego/net/ipv4.hpp"
#include "frego/plugins/identity.hpp"

namespace frego::plugins {
namespace {

class IdentityPlugin final : public Plugin {
public:
    PluginInfo info() const override {
        return {"identity", "0.1.0", "Assigns stable device identities and serves the device list", false};
    }

    std::vector<EventKind> subscriptions() const override { return {EventKind::NeighborSnapshot}; }

    void start(Context& ctx) override {
        store_ = &ctx.service<domain::DomainStore>();

        const auto oui_path = ctx.data_dir() / "oui.csv";
        if (auto db = net::OuiDb::load_file(oui_path)) {
            oui_ = std::move(*db);
            ctx.log().info("identity", "loaded {} vendor prefixes", oui_.size());
        } else {
            ctx.log().warn("identity", "no vendor database at {}; run scripts/fetch-data.sh to add vendor names",
                           oui_path.string());
        }
        resolver_ = std::make_unique<IdentityResolver>(&oui_);
        for (const auto& mac : store_->shared_macs()) resolver_->remember_shared(mac);
        for (const auto& known : store_->known_identities()) resolver_->remember(known);

        ctx.http().get("/api/v1/devices", [this](const HttpRequest&) {
            auto rows = store_->devices();
            auto ip_key = [](const domain::DeviceRow& d) {
                auto ip = d.ip ? net::Ipv4::parse(*d.ip) : std::nullopt;
                return ip ? ip->value : UINT32_MAX;
            };
            std::ranges::sort(rows, {}, ip_key);
            nlohmann::json list = nlohmann::json::array();
            for (const auto& d : rows) list.push_back(domain::to_json(d));
            return HttpResponse{200, {{"count", rows.size()}, {"devices", list}}};
        });
    }

    void on_event(const Event& e, Context& ctx) override {
        if (!is_live(e)) return;  // investigation sessions never touch the live inventory
        const auto& snap = std::get<NeighborSnapshot>(e.payload);
        auto identified = resolver_->resolve(snap);
        for (const auto& mac : resolver_->take_new_shared())
            ctx.log().info("identity",
                           "{} answers for several IPs: probably a Wi-Fi extender or mesh node. Tracking each IP "
                           "behind it as its own device until you confirm (M1).",
                           mac);
        int created = 0;
        for (auto& d : identified) {
            created += d.created ? 1 : 0;
            ctx.publish(std::move(d), e.observed_at);
        }
        if (created) ctx.log().info("identity", "{} new device(s)", created);
    }

private:
    domain::DomainStore* store_ = nullptr;
    net::OuiDb oui_;
    std::unique_ptr<IdentityResolver> resolver_;
};

}  // namespace

std::unique_ptr<Plugin> make_identity() { return std::make_unique<IdentityPlugin>(); }

}  // namespace frego::plugins
