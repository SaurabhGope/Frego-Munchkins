#include "frego/plugins/network_guard.hpp"

#include <array>
#include <format>
#include <mutex>
#include <thread>

#include "frego/net/sha256.hpp"
#include "frego/platform/netinfo.hpp"
#include "frego/platform/probe.hpp"
#include "frego/platform/route_monitor.hpp"

namespace frego::plugins {
namespace guard {

std::string fingerprint(std::string_view gateway_mac, std::string_view subnet) {
    return net::Sha256::hex(std::format("{}|{}", gateway_mac, subnet)).substr(0, 16);
}

NetworkStatus classify(bool have_network, const std::optional<domain::NetworkRow>& row) {
    if (!have_network) return NetworkStatus::None;
    if (!row) return NetworkStatus::Unknown;
    if (row->state == "home" || row->state == "alias") return NetworkStatus::Home;
    if (row->state == "declined") return NetworkStatus::Declined;
    return NetworkStatus::Unknown;  // retired: a former home must be approved again
}

}  // namespace guard

namespace {

enum class LanAccess { Unknown, Checking, Ok, Blocked, Inconclusive, NoHosts };

std::string_view lan_access_name(LanAccess a) {
    switch (a) {
        case LanAccess::Unknown: return "unknown";
        case LanAccess::Checking: return "checking";
        case LanAccess::Ok: return "ok";
        case LanAccess::Blocked: return "blocked";
        case LanAccess::Inconclusive: return "inconclusive";
        case LanAccess::NoHosts: return "no_other_hosts";
    }
    return "unknown";
}

struct Observed {
    std::optional<domain::NetworkObservation> network;
    std::string iface;
    std::string self_ip;
    std::string reason;  // why there's no usable network
};

std::optional<net::Mac> arp_lookup(const std::string& iface, net::Ipv4 ip) {
    auto table = platform::arp_table(iface);
    if (!table) return std::nullopt;
    for (const auto& e : *table)
        if (e.ip == ip) return e.mac;
    return std::nullopt;
}

class NetworkGuardPlugin final : public Plugin {
public:
    PluginInfo info() const override {
        return {"network-guard", "0.1.0", "Only collects on the approved home network; drives the collection gate", false};
    }

    void start(Context& ctx) override {
        ctx_ = &ctx;
        store_ = &ctx.service<domain::DomainStore>();
        interface_ = ctx.config().value("interface", std::string{"auto"});
        register_routes(ctx.http());

        auto interval = std::chrono::seconds(ctx.config().value("interval_s", 30));
        job_ = ctx.every(interval, [this](std::stop_token st) { evaluate(st); });

        // React to route changes within about a second instead of waiting for the next tick.
        monitor_ = std::jthread([this](std::stop_token st) {
            platform::RouteMonitor monitor;
            if (!monitor.ok()) {
                ctx_->log().warn("network-guard", "route monitor unavailable; relying on the {} s check", 30);
                return;
            }
            while (!st.stop_requested()) {
                if (!monitor.wait_for_change(std::chrono::milliseconds(500))) continue;
                if (!interruptible_sleep(st, std::chrono::milliseconds(500))) return;  // debounce bursts
                ctx_->kick(job_);
            }
        });
    }

    void stop() override {
        monitor_ = {};
        probe_ = {};
    }

private:
    Observed observe(std::stop_token st) {
        auto itf = platform::default_interface(interface_);
        if (!itf) return {std::nullopt, "", "", itf.error()};
        Observed o{std::nullopt, itf->name, itf->addr.str(), ""};
        if (itf->point_to_point || !itf->mac) {
            o.reason = std::format("default route goes through {} (VPN or tunnel)", itf->name);
            return o;
        }
        if (!itf->gateway) {
            o.reason = "no default gateway";
            return o;
        }
        auto gw = *itf->gateway;
        auto mac = arp_lookup(itf->name, gw);
        if (!mac) {  // make the kernel resolve the gateway, then look again
            std::array hosts{gw};
            platform::udp_nudge(hosts, st);
            interruptible_sleep(st, std::chrono::milliseconds(300));
            mac = arp_lookup(itf->name, gw);
        }
        if (!mac) {
            o.reason = std::format("can't resolve the gateway's MAC ({})", gw.str());
            return o;
        }
        auto subnet = itf->subnet().str();
        o.network = domain::NetworkObservation{guard::fingerprint(mac->str(), subnet), gw.str(), mac->str(), subnet};
        return o;
    }

    void evaluate(std::stop_token st) {
        Observed o = observe(st);
        std::optional<domain::NetworkRow> row;
        if (o.network) row = store_->network(o.network->fingerprint);
        const NetworkStatus status = guard::classify(o.network.has_value(), row);
        std::string reason = o.reason;
        switch (status) {
            case NetworkStatus::Home: reason = row->state == "alias" ? "home network (via another access point)" : "home network"; break;
            case NetworkStatus::Unknown: reason = "not approved as your home network yet; run `fregoctl network approve`"; break;
            case NetworkStatus::Declined: reason = "you said this isn't your home network"; break;
            case NetworkStatus::None: break;
        }

        bool changed;
        {
            std::lock_guard lk(mu_);
            const std::string fp = o.network ? o.network->fingerprint : "";
            const std::string old_fp = current_.network ? current_.network->fingerprint : "";
            changed = first_ || status != status_ || fp != old_fp || reason != reason_;
            first_ = false;
            current_ = o;
            status_ = status;
            reason_ = reason;
        }
        if (!changed) return;

        NetworkChanged ev{o.network ? o.network->fingerprint : "", o.iface,
                          o.network ? o.network->subnet : "", o.network ? o.network->gateway_ip : "",
                          o.network ? std::optional(o.network->gateway_mac) : std::nullopt, status, reason};
        ctx_->log().info("network-guard", "network {} ({}){}", network_status_name(status), reason,
                         o.network ? std::format(" fingerprint={} gateway={} subnet={}", o.network->fingerprint,
                                                 o.network->gateway_ip, o.network->subnet)
                                   : "");
        ctx_->publish(std::move(ev));
        ctx_->publish(CollectionGate{status == NetworkStatus::Home, reason});
        if (status == NetworkStatus::Home) start_probe(o);
    }

    // lan_access_probe (DESIGN §10.1): a TCP connect to a non-router LAN host, retried with
    // backoff because a never-seen binary's first launchd run can fail transiently.
    void start_probe(const Observed& o) {
        probe_ = std::jthread([this, iface = o.iface, self = o.self_ip,
                               gateway = o.network->gateway_ip](std::stop_token st) {
            set_lan(LanAccess::Checking);
            constexpr std::array<int, 6> delays{0, 1, 2, 4, 8, 16};
            bool unreachable = false;
            for (int delay : delays) {
                if (!interruptible_sleep(st, std::chrono::seconds(delay))) return;
                auto table = platform::arp_table(iface);
                if (!table) continue;
                // Any answer proves reachability, including "connection refused". Many devices
                // silently drop unused ports, so try common ones first; a timeout proves nothing.
                constexpr std::array<std::uint16_t, 3> ports{80, 443, 9};
                int tried = 0;
                for (const auto& e : *table) {
                    const auto ip = e.ip.str();
                    if (e.permanent || ip == gateway || ip == self || e.mac.multicast()) continue;
                    if (++tried > 4) break;
                    for (auto port : ports) {
                        if (st.stop_requested()) return;
                        auto r = platform::tcp_probe(e.ip, port, std::chrono::milliseconds(700));
                        if (r.result == platform::ProbeResult::Reached) {
                            set_lan(LanAccess::Ok);
                            ctx_->log().info("network-guard", "LAN access ok (reached {}:{})", ip, port);
                            return;
                        }
                        if (r.result == platform::ProbeResult::Unreachable) {
                            unreachable = true;
                            break;  // the OS refused to route to this host; other ports won't differ
                        }
                    }
                }
                if (tried == 0) {
                    set_lan(LanAccess::NoHosts);
                    return;
                }
            }
            if (unreachable) {
                set_lan(LanAccess::Blocked);
                ctx_->log().error("network-guard",
                                  "macOS is blocking LAN access for fregod (Local Network Privacy). Allow it in "
                                  "System Settings > Privacy & Security > Local Network, or run fregod from a terminal.");
            } else {
                set_lan(LanAccess::Inconclusive);
            }
        });
    }

    void set_lan(LanAccess a) {
        std::lock_guard lk(mu_);
        lan_ = a;
    }

    nlohmann::json state_json() {
        std::lock_guard lk(mu_);
        nlohmann::json j = {{"status", network_status_name(status_)},
                            {"reason", reason_},
                            {"iface", current_.iface},
                            {"gate_open", ctx_->gate_open()},
                            {"lan_access", lan_access_name(lan_)}};
        if (current_.network)
            j.update({{"fingerprint", current_.network->fingerprint},
                      {"gateway_ip", current_.network->gateway_ip},
                      {"gateway_mac", current_.network->gateway_mac},
                      {"subnet", current_.network->subnet}});
        return j;
    }

    std::optional<domain::NetworkObservation> current_network() {
        std::lock_guard lk(mu_);
        return current_.network;
    }

    void register_routes(HttpRoutes& http) {
        http.get("/api/v1/network", [this](const HttpRequest&) {
            auto j = state_json();
            auto home = store_->home_network();
            j["home"] = home ? domain::to_json(*home) : nlohmann::json(nullptr);
            return HttpResponse{200, j};
        });
        http.post("/api/v1/network/approve", [this](const HttpRequest& req) {
            auto network = current_network();
            if (!network) throw HttpError(409, "no usable network to approve", {{"reason", state_json()["reason"]}});
            const bool replace = req.json_body().value("replace", false);
            auto result = store_->approve_network(*network, replace, ctx_->clock().now());
            if (result == domain::ApproveResult::ReplaceRequired) {
                auto home = store_->home_network();
                throw HttpError(409, "replace_required",
                                {{"home", home ? domain::to_json(*home) : nlohmann::json(nullptr)}});
            }
            ctx_->kick(job_);
            static constexpr std::array<std::string_view, 4> names{"approved", "already_home", "added_alias", "replace_required"};
            return HttpResponse{200, {{"result", names[static_cast<std::size_t>(result)]}, {"fingerprint", network->fingerprint}}};
        });
        http.post("/api/v1/network/decline", [this](const HttpRequest&) {
            auto network = current_network();
            if (!network) throw HttpError(409, "no usable network to decline");
            store_->decline_network(*network, ctx_->clock().now());
            ctx_->kick(job_);
            return HttpResponse{200, {{"result", "declined"}, {"fingerprint", network->fingerprint}}};
        });
    }

    Context* ctx_ = nullptr;
    domain::DomainStore* store_ = nullptr;
    std::string interface_;
    Scheduler::JobId job_ = 0;
    std::jthread monitor_;
    std::jthread probe_;

    std::mutex mu_;
    bool first_ = true;
    Observed current_;
    NetworkStatus status_ = NetworkStatus::None;
    std::string reason_;
    LanAccess lan_ = LanAccess::Unknown;
};

}  // namespace

std::unique_ptr<Plugin> make_network_guard() { return std::make_unique<NetworkGuardPlugin>(); }

}  // namespace frego::plugins
