#include <algorithm>
#include <format>
#include <variant>

#include "frego/domain/store.hpp"
#include "frego/events/json.hpp"

namespace frego::domain {
namespace {

using nlohmann::json;

template <class... Ts>
struct Overloaded : Ts... {
    using Ts::operator()...;
};

json opt(const std::optional<std::string>& v) { return v ? json(*v) : json(nullptr); }

constexpr std::string_view kNetworkColumns =
    "id, fingerprint, gateway_ip, gateway_mac, subnet, ssid, state, first_seen, approved_at";

NetworkRow read_network(const Stmt& s) {
    return {s.col_int(0), s.col_text(1), s.col_text(2), s.col_text(3), s.col_text(4),
            s.col_opt(5), s.col_text(6), s.col_int(7), s.col_opt_int(8)};
}

std::optional<NetworkRow> select_network(Connection& c, std::string_view where, std::string_view arg = {}) {
    auto s = c.prepare(std::format("SELECT {} FROM networks WHERE {}", kNetworkColumns, where));
    if (!arg.empty()) s.bind_text(1, arg);
    if (!s.step()) return std::nullopt;
    return read_network(s);
}

std::optional<std::int64_t> home_id(Connection& c) {
    auto s = c.prepare("SELECT id FROM networks WHERE state = 'home'");
    if (!s.step()) return std::nullopt;
    return s.col_int(0);
}

void upsert_network(Connection& c, const NetworkObservation& n, std::string_view state, std::int64_t now,
                    std::optional<std::int64_t> approved_at) {
    c.prepare(
         "INSERT INTO networks (fingerprint, gateway_ip, gateway_mac, subnet, state, first_seen, approved_at) "
         "VALUES (?, ?, ?, ?, ?, ?, ?) "
         "ON CONFLICT(fingerprint) DO UPDATE SET gateway_ip = excluded.gateway_ip, "
         "gateway_mac = excluded.gateway_mac, subnet = excluded.subnet, state = excluded.state, "
         "approved_at = excluded.approved_at")
        .bind_text(1, n.fingerprint)
        .bind_text(2, n.gateway_ip)
        .bind_text(3, n.gateway_mac)
        .bind_text(4, n.subnet)
        .bind_text(5, state)
        .bind_int(6, now)
        .bind_opt(7, approved_at)
        .step();
}

void set_meta_on(Connection& c, std::string_view key, std::string_view value) {
    c.prepare("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v")
        .bind_text(1, key)
        .bind_text(2, value)
        .step();
}

void observe(Connection& c, const std::string& device, std::string_view key, std::string_view value,
             std::string_view via, std::int64_t ts) {
    c.prepare(
         "INSERT INTO device_observations (device_id, key, value, via, first_seen, last_seen) "
         "VALUES (?, ?, ?, ?, ?, ?) "
         "ON CONFLICT(device_id, key, value) DO UPDATE SET "
         "first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)")
        .bind_text(1, device)
        .bind_text(2, key)
        .bind_text(3, value)
        .bind_text(4, via)
        .bind_int(5, ts)
        .bind_int(6, ts)
        .step();
}

// Closes another device's open binding on this IP and opens ours (DESIGN §7.6).
void bind_ip(Connection& c, const std::string& ip, const std::string& device, std::optional<std::int64_t> network,
             std::int64_t ts) {
    auto open = c.prepare("SELECT device_id FROM ip_bindings WHERE ip = ? AND valid_to IS NULL");
    open.bind_text(1, ip);
    bool have_ours = false;
    std::vector<std::string> others;
    while (open.step()) {
        auto holder = open.col_text(0);
        if (holder == device) have_ours = true;
        else others.push_back(std::move(holder));
    }
    for (const auto& other : others)
        c.prepare("UPDATE ip_bindings SET valid_to = ? WHERE ip = ? AND device_id = ? AND valid_to IS NULL")
            .bind_int(1, ts)
            .bind_text(2, ip)
            .bind_text(3, other)
            .step();
    if (!have_ours)
        c.prepare("INSERT OR IGNORE INTO ip_bindings (ip, device_id, network_id, valid_from) VALUES (?, ?, ?, ?)")
            .bind_text(1, ip)
            .bind_text(2, device)
            .bind_opt(3, network)
            .bind_int(4, ts)
            .step();
}

void remember_shared_mac(Connection& c, const std::string& mac, const std::string& ip, std::int64_t ts) {
    auto s = c.prepare("SELECT ips FROM shared_macs WHERE mac = ?");
    s.bind_text(1, mac);
    json ips = json::array();
    if (s.step()) {
        auto parsed = json::parse(s.col_text(0), nullptr, false);
        if (parsed.is_array()) ips = std::move(parsed);
    }
    if (std::find(ips.begin(), ips.end(), json(ip)) == ips.end()) ips.push_back(ip);
    c.prepare(
         "INSERT INTO shared_macs (mac, ips, first_seen) VALUES (?, ?, ?) "
         "ON CONFLICT(mac) DO UPDATE SET ips = excluded.ips")
        .bind_text(1, mac)
        .bind_text(2, json_out(ips))
        .bind_int(3, ts)
        .step();
}

void write_device(Connection& c, const DeviceIdentified& d, std::int64_t ts, std::optional<std::int64_t> network) {
    c.prepare(
         "INSERT INTO devices (id, network_id, identity, mac, ip, vendor, randomized, is_self, first_seen, last_seen) "
         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
         "ON CONFLICT(id) DO UPDATE SET network_id = excluded.network_id, identity = excluded.identity, "
         "mac = coalesce(excluded.mac, mac), ip = excluded.ip, vendor = coalesce(excluded.vendor, vendor), "
         "randomized = excluded.randomized, is_self = excluded.is_self, "
         "first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)")
        .bind_text(1, d.id)
        .bind_opt(2, network)
        .bind_text(3, d.identity)
        .bind_opt(4, d.mac)
        .bind_text(5, d.ip)
        .bind_opt(6, d.vendor)
        .bind_int(7, d.randomized ? 1 : 0)
        .bind_int(8, d.is_self ? 1 : 0)
        .bind_int(9, ts)
        .bind_int(10, ts)
        .step();
    if (d.mac) observe(c, d.id, "mac", *d.mac, d.via, ts);
    observe(c, d.id, "ip", d.ip, d.via, ts);
    if (d.vendor) observe(c, d.id, "vendor", *d.vendor, d.via, ts);
    bind_ip(c, d.ip, d.id, network, ts);
    if (d.identity == "weak" && d.mac) remember_shared_mac(c, *d.mac, d.ip, ts);
}

void write_alert(Connection& c, const Alert& a, std::int64_t ts, std::optional<std::int64_t> network) {
    c.prepare(
         "INSERT INTO alerts (key, network_id, ts, updated, device_id, kind, severity, title, reason) "
         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
         "ON CONFLICT(key) DO UPDATE SET updated = excluded.updated, severity = excluded.severity, "
         "title = excluded.title, reason = excluded.reason")
        .bind_text(1, a.key)
        .bind_opt(2, network)
        .bind_int(3, ts)
        .bind_int(4, ts)
        .bind_opt(5, a.device.empty() ? std::nullopt : std::optional<std::string>(a.device))
        .bind_text(6, a.kind)
        .bind_int(7, static_cast<std::int64_t>(a.severity))
        .bind_text(8, a.title)
        .bind_text(9, a.reason)
        .step();
}

}  // namespace

json to_json(const DeviceRow& d) {
    return {{"id", d.id},
            {"network_id", d.network_id ? json(*d.network_id) : json(nullptr)},
            {"label", opt(d.label)},
            {"kind", d.kind},
            {"identity", d.identity},
            {"mac", opt(d.mac)},
            {"ip", opt(d.ip)},
            {"vendor", opt(d.vendor)},
            {"hostname", opt(d.hostname)},
            {"model", opt(d.model)},
            {"randomized", d.randomized},
            {"is_self", d.is_self},
            {"first_seen", d.first_seen},
            {"last_seen", d.last_seen}};
}

json to_json(const NetworkRow& n) {
    return {{"id", n.id},
            {"fingerprint", n.fingerprint},
            {"gateway_ip", n.gateway_ip},
            {"gateway_mac", n.gateway_mac},
            {"subnet", n.subnet},
            {"ssid", opt(n.ssid)},
            {"state", n.state},
            {"first_seen", n.first_seen},
            {"approved_at", n.approved_at ? json(*n.approved_at) : json(nullptr)}};
}

void SqliteDomainStore::write(std::span<const Event> events) {
    if (events.empty()) return;
    db_.write([&](Connection& c) {
        const auto network = home_id(c);
        for (const auto& e : events) {
            if (!is_live(e)) continue;  // investigation sessions arrive in M3
            const auto ts = to_unix_ms(e.observed_at);
            std::visit(Overloaded{
                           [&](const Heartbeat& h) {
                               set_meta_on(c, "last_heartbeat", json_out({{"seq", h.seq}, {"observed_at", ts}}));
                           },
                           [&](const DeviceIdentified& d) { write_device(c, d, ts, network); },
                           [&](const Alert& a) { write_alert(c, a, ts, network); },
                           [](const auto&) {},
                       },
                       e.payload);
        }
    });
}

std::vector<DeviceRow> SqliteDomainStore::devices() {
    return db_.read([](Connection& c) {
        auto s = c.prepare(
            "SELECT id, network_id, label, kind, identity, mac, ip, vendor, hostname, model, randomized, is_self, "
            "first_seen, last_seen FROM devices d "
            "WHERE network_id = (SELECT id FROM networks WHERE state = 'home') "
            "AND NOT EXISTS (SELECT 1 FROM device_redirects r WHERE r.from_id = d.id)");
        std::vector<DeviceRow> out;
        while (s.step())
            out.push_back({s.col_text(0), s.col_opt_int(1), s.col_opt(2), s.col_text(3), s.col_text(4), s.col_opt(5),
                           s.col_opt(6), s.col_opt(7), s.col_opt(8), s.col_opt(9), s.col_int(10) != 0,
                           s.col_int(11) != 0, s.col_int(12), s.col_int(13)});
        return out;
    });
}

std::vector<KnownIdentity> SqliteDomainStore::known_identities() {
    return db_.read([](Connection& c) {
        auto s = c.prepare(
            "SELECT id, mac, ip, identity FROM devices "
            "WHERE mac IS NOT NULL AND ip IS NOT NULL "
            "AND network_id = (SELECT id FROM networks WHERE state = 'home')");
        std::vector<KnownIdentity> out;
        while (s.step()) out.push_back({s.col_text(0), s.col_text(1), s.col_text(2), s.col_text(3)});
        return out;
    });
}

std::vector<std::string> SqliteDomainStore::shared_macs() {
    return db_.read([](Connection& c) {
        auto s = c.prepare("SELECT mac FROM shared_macs");
        std::vector<std::string> out;
        while (s.step()) out.push_back(s.col_text(0));
        return out;
    });
}

std::optional<NetworkRow> SqliteDomainStore::network(std::string_view fingerprint) {
    return db_.read([&](Connection& c) { return select_network(c, "fingerprint = ?", fingerprint); });
}

std::optional<NetworkRow> SqliteDomainStore::home_network() {
    return db_.read([](Connection& c) { return select_network(c, "state = 'home'"); });
}

ApproveResult SqliteDomainStore::approve_network(const NetworkObservation& n, bool replace, Clock::time_point now) {
    const auto t = to_unix_ms(now);
    return db_.write([&](Connection& c) {
        auto home = select_network(c, "state = 'home'");
        if (home && home->fingerprint == n.fingerprint) return ApproveResult::AlreadyHome;
        if (home && home->subnet == n.subnet && home->gateway_ip == n.gateway_ip) {
            upsert_network(c, n, "alias", t, t);
            return ApproveResult::AddedAlias;
        }
        if (home && !replace) return ApproveResult::ReplaceRequired;
        if (home) c.exec("UPDATE networks SET state = 'retired' WHERE state IN ('home', 'alias')");
        upsert_network(c, n, "home", t, t);
        return ApproveResult::Approved;
    });
}

void SqliteDomainStore::decline_network(const NetworkObservation& n, Clock::time_point now) {
    db_.write([&](Connection& c) { upsert_network(c, n, "declined", to_unix_ms(now), std::nullopt); });
}

std::optional<std::string> SqliteDomainStore::meta(std::string_view key) {
    return db_.read([&](Connection& c) -> std::optional<std::string> {
        auto s = c.prepare("SELECT v FROM meta WHERE k = ?");
        s.bind_text(1, key);
        if (!s.step()) return std::nullopt;
        return s.col_text(0);
    });
}

void SqliteDomainStore::set_meta(std::string_view key, std::string_view value) {
    db_.write([&](Connection& c) { set_meta_on(c, key, value); });
}

}  // namespace frego::domain
