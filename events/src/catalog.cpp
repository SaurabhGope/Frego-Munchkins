#include "frego/events/catalog.hpp"

#include <array>

namespace frego {
namespace {

using nlohmann::json;

template <class... Ts>
struct Overloaded : Ts... {
    using Ts::operator()...;
};

constexpr std::array<std::string_view, kKindCount> kKindNames{
    "Heartbeat", "NetworkChanged", "CollectionGate", "NeighborSnapshot",
    "DeviceIdentified", "Alert", "Custom"};

json opt(const std::optional<std::string>& v) { return v ? json(*v) : json(nullptr); }

std::optional<std::string> opt_from(const json& j, const char* key) {
    auto it = j.find(key);
    if (it == j.end() || it->is_null()) return std::nullopt;
    return it->get<std::string>();
}

json neighbor_json(const NeighborEntry& n) {
    return {{"ip", n.ip}, {"family", n.family}, {"mac", n.mac}};
}

NeighborEntry neighbor_from(const json& j) {
    return {j.at("ip").get<std::string>(), j.value("family", std::uint8_t{4}),
            j.at("mac").get<std::string>()};
}

std::size_t str_size(const std::string& s) { return s.size(); }
std::size_t str_size(const std::optional<std::string>& s) { return s ? str_size(*s) : 0; }

}  // namespace

bool is_critical(EventKind k) noexcept {
    return k == EventKind::Alert || k == EventKind::NetworkChanged ||
           k == EventKind::CollectionGate;
}

std::string_view kind_name(EventKind k) noexcept {
    auto i = static_cast<std::size_t>(k);
    return i < kKindNames.size() ? kKindNames[i] : "Unknown";
}

std::optional<EventKind> kind_from_name(std::string_view name) noexcept {
    for (std::size_t i = 0; i < kKindNames.size(); ++i)
        if (kKindNames[i] == name) return static_cast<EventKind>(i);
    return std::nullopt;
}

std::string_view severity_name(Severity s) noexcept {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
    }
    return "info";
}

std::string_view network_status_name(NetworkStatus s) noexcept {
    switch (s) {
        case NetworkStatus::None: return "none";
        case NetworkStatus::Unknown: return "unknown";
        case NetworkStatus::Declined: return "declined";
        case NetworkStatus::Home: return "home";
    }
    return "none";
}

std::size_t approx_size(const Event& e) noexcept {
    std::size_t extra = std::visit(
        Overloaded{
            [](const Heartbeat&) -> std::size_t { return 0; },
            [](const NetworkChanged& n) {
                return str_size(n.fingerprint) + str_size(n.iface) + str_size(n.subnet) +
                       str_size(n.gateway_ip) + str_size(n.gateway_mac) + str_size(n.reason);
            },
            [](const CollectionGate& g) { return str_size(g.reason); },
            [](const NeighborSnapshot& s) {
                return str_size(s.iface) + str_size(s.subnet) +
                       s.entries.size() * (sizeof(NeighborEntry) + 32);
            },
            [](const DeviceIdentified& d) {
                return str_size(d.id) + str_size(d.ip) + str_size(d.mac) + str_size(d.vendor);
            },
            [](const Alert& a) {
                return str_size(a.key) + str_size(a.title) + str_size(a.reason) + str_size(a.device);
            },
            [](const Custom& c) { return str_size(c.type) + 64 * (c.data.size() + 1); },
        },
        e.payload);
    return sizeof(Event) + extra;
}

std::int64_t to_unix_ms(Clock::time_point t) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

Clock::time_point from_unix_ms(std::int64_t ms) noexcept {
    return Clock::time_point(std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(ms)));
}

json payload_to_json(const Payload& p) {
    return std::visit(
        Overloaded{
            [](const Heartbeat& h) -> json { return {{"seq", h.seq}}; },
            [](const NetworkChanged& n) -> json {
                return {{"fingerprint", n.fingerprint}, {"iface", n.iface}, {"subnet", n.subnet},
                        {"gateway_ip", n.gateway_ip}, {"gateway_mac", opt(n.gateway_mac)},
                        {"status", network_status_name(n.status)}, {"reason", n.reason}};
            },
            [](const CollectionGate& g) -> json { return {{"open", g.open}, {"reason", g.reason}}; },
            [](const NeighborSnapshot& s) -> json {
                json entries = json::array();
                for (const auto& n : s.entries) entries.push_back(neighbor_json(n));
                return {{"iface", s.iface}, {"subnet", s.subnet}, {"entries", entries},
                        {"self", neighbor_json(s.self)}};
            },
            [](const DeviceIdentified& d) -> json {
                return {{"id", d.id}, {"ip", d.ip}, {"mac", opt(d.mac)}, {"vendor", opt(d.vendor)},
                        {"identity", d.identity}, {"randomized", d.randomized},
                        {"is_self", d.is_self}, {"created", d.created}, {"via", d.via}};
            },
            [](const Alert& a) -> json {
                return {{"key", a.key}, {"kind", a.kind}, {"severity", severity_name(a.severity)},
                        {"device", a.device}, {"title", a.title}, {"reason", a.reason}};
            },
            [](const Custom& c) -> json {
                return {{"type", c.type}, {"schema_version", c.schema_version}, {"data", c.data}};
            },
        },
        p);
}

Payload payload_from_json(EventKind kind, const json& j) {
    switch (kind) {
        case EventKind::Heartbeat:
            return Heartbeat{j.at("seq").get<std::uint64_t>()};
        case EventKind::NetworkChanged: {
            NetworkChanged n{j.at("fingerprint").get<std::string>(), j.at("iface").get<std::string>(),
                             j.at("subnet").get<std::string>(), j.at("gateway_ip").get<std::string>(),
                             opt_from(j, "gateway_mac"), NetworkStatus::None,
                             j.value("reason", std::string{})};
            auto status = j.at("status").get<std::string>();
            for (auto s : {NetworkStatus::None, NetworkStatus::Unknown, NetworkStatus::Declined,
                           NetworkStatus::Home})
                if (network_status_name(s) == status) n.status = s;
            return n;
        }
        case EventKind::CollectionGate:
            return CollectionGate{j.at("open").get<bool>(), j.value("reason", std::string{})};
        case EventKind::NeighborSnapshot: {
            NeighborSnapshot s{j.at("iface").get<std::string>(), j.value("subnet", std::string{}),
                               {}, neighbor_from(j.at("self"))};
            for (const auto& e : j.at("entries")) s.entries.push_back(neighbor_from(e));
            return s;
        }
        case EventKind::DeviceIdentified:
            return DeviceIdentified{j.at("id").get<std::string>(), j.at("ip").get<std::string>(),
                                    opt_from(j, "mac"), opt_from(j, "vendor"),
                                    j.value("identity", std::string{"strong"}),
                                    j.value("randomized", false), j.value("is_self", false),
                                    j.value("created", false), j.value("via", std::string{})};
        case EventKind::Alert: {
            Alert a{j.at("key").get<std::string>(), j.at("kind").get<std::string>(), Severity::Info,
                    j.value("device", std::string{}), j.at("title").get<std::string>(),
                    j.at("reason").get<std::string>()};
            auto sev = j.value("severity", std::string{"info"});
            for (auto s : {Severity::Info, Severity::Low, Severity::Medium, Severity::High})
                if (severity_name(s) == sev) a.severity = s;
            return a;
        }
        case EventKind::Custom:
            return Custom{j.at("type").get<std::string>(), j.value("schema_version", std::uint16_t{1}),
                          j.value("data", json::object())};
        case EventKind::Count:
            break;
    }
    throw json::other_error::create(501, "unknown event kind", nullptr);
}

json to_json(const Event& e) {
    return {{"id", e.id},
            {"catalog", kCatalogVersion},
            {"schema", Event::kSchemaVersion},
            {"observed_at", to_unix_ms(e.observed_at)},
            {"published_at", to_unix_ms(e.published_at)},
            {"session", e.session},
            {"kind", kind_name(e.kind())},
            {"source", e.source},
            {"data", payload_to_json(e.payload)}};
}

}  // namespace frego
