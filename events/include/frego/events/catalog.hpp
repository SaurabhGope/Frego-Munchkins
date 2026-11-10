#pragma once

// The event catalog (DESIGN §4.1): a versioned, data-only contract shared by the core
// engine and every plugin. The engine routes by kind_of() and serializes with to_json();
// it never looks inside a payload.
//
// Ordering contract (DESIGN §4.2): within a lane, events arrive in publish order. Critical
// events (is_critical) can overtake bulk events published earlier. Don't assume otherwise.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace frego {

// Adding a kind or an optional field: minor bump. Removing or renaming: major bump.
inline constexpr std::string_view kCatalogVersion = "1.0.0";

using Clock = std::chrono::system_clock;
using DeviceId = std::string;  // opaque "dev_<uuidv7>"; never derived from or parsed for MAC/IP
using SessionId = std::uint32_t;
inline constexpr SessionId kLiveSession = 0;  // pcap investigations get their own ids (§6.4)

enum class Severity : std::uint8_t { Info, Low, Medium, High };
enum class NetworkStatus : std::uint8_t { None, Unknown, Declined, Home };

struct Heartbeat {
    std::uint64_t seq = 0;
};

// Published by network-guard whenever the network or its status changes.
struct NetworkChanged {
    std::string fingerprint;  // empty when status == None
    std::string iface;
    std::string subnet;
    std::string gateway_ip;
    std::optional<std::string> gateway_mac;
    NetworkStatus status = NetworkStatus::None;
    std::string reason;
};

// The generic collection switch (§4.3). The core acts on it; only network-guard publishes it.
struct CollectionGate {
    bool open = false;
    std::string reason;
};

struct NeighborEntry {
    std::string ip;
    std::uint8_t family = 4;  // 4 | 6
    std::string mac;          // canonical lower-case, zero-padded
};

// One full ARP/NDP table read. Published as one event so identity can see a MAC
// answering for several IPs (§7.3, §7.6).
struct NeighborSnapshot {
    std::string iface;
    std::string subnet;
    std::vector<NeighborEntry> entries;
    NeighborEntry self;
};

// identity's verdict on one observation: which device it belongs to.
struct DeviceIdentified {
    DeviceId id;
    std::string ip;
    std::optional<std::string> mac;
    std::optional<std::string> vendor;
    std::string identity = "strong";  // strong | weak | provisional (§7.6)
    bool randomized = false;
    bool is_self = false;
    bool created = false;  // first time identity has seen this device
    std::string via;
};

struct Alert {
    std::string key;  // dedupe key
    std::string kind;
    Severity severity = Severity::Info;
    DeviceId device;
    std::string title;
    std::string reason;
};

// Escape hatch for plugin-defined events. The "frego." namespace is reserved.
struct Custom {
    std::string type;
    std::uint16_t schema_version = 1;
    nlohmann::json data;
};

using Payload = std::variant<Heartbeat, NetworkChanged, CollectionGate, NeighborSnapshot,
                             DeviceIdentified, Alert, Custom>;

enum class EventKind : std::uint8_t {
    Heartbeat,
    NetworkChanged,
    CollectionGate,
    NeighborSnapshot,
    DeviceIdentified,
    Alert,
    Custom,
    Count
};
inline constexpr std::size_t kKindCount = static_cast<std::size_t>(EventKind::Count);
static_assert(kKindCount == std::variant_size_v<Payload>, "EventKind must mirror Payload");

constexpr EventKind kind_of(const Payload& p) noexcept {
    return static_cast<EventKind>(p.index());
}

struct Event {
    static constexpr std::uint16_t kSchemaVersion = 1;
    std::uint64_t id = 0;            // monotonic, assigned by the bus
    Clock::time_point observed_at{};  // when it happened; set by the source
    Clock::time_point published_at{}; // when it entered the bus; metrics only
    SessionId session = kLiveSession;
    std::string_view source;          // plugin name, static storage
    Payload payload;

    EventKind kind() const noexcept { return kind_of(payload); }
};

inline bool is_live(const Event& e) noexcept { return e.session == kLiveSession; }

// Critical-lane kinds are never dropped (§4.2).
bool is_critical(EventKind k) noexcept;
std::string_view kind_name(EventKind k) noexcept;
std::optional<EventKind> kind_from_name(std::string_view name) noexcept;
std::string_view severity_name(Severity s) noexcept;
std::string_view network_status_name(NetworkStatus s) noexcept;

// Rough heap + inline size, used for byte-bounded bulk lanes.
std::size_t approx_size(const Event& e) noexcept;

std::int64_t to_unix_ms(Clock::time_point t) noexcept;
Clock::time_point from_unix_ms(std::int64_t ms) noexcept;

nlohmann::json payload_to_json(const Payload& p);
// Throws nlohmann::json::exception on missing or mistyped required fields.
// Unknown fields are ignored so newer files still replay on older builds.
Payload payload_from_json(EventKind kind, const nlohmann::json& j);
nlohmann::json to_json(const Event& e);

}  // namespace frego
