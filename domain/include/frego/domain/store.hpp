#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "frego/core/database.hpp"
#include "frego/events/catalog.hpp"

namespace frego::domain {

struct DeviceRow {
    std::string id;
    std::optional<std::int64_t> network_id;
    std::optional<std::string> label;
    std::string kind;
    std::string identity;
    std::optional<std::string> mac, ip, vendor, hostname, model;
    bool randomized = false;
    bool is_self = false;
    std::int64_t first_seen = 0;
    std::int64_t last_seen = 0;
};
nlohmann::json to_json(const DeviceRow& d);

// What identity needs to resume after a restart: which key maps to which device.
struct KnownIdentity {
    std::string device_id;
    std::string mac;
    std::string ip;
    std::string identity;  // strong (keyed by MAC) | weak (keyed by MAC + IP)
};

struct NetworkObservation {
    std::string fingerprint;
    std::string gateway_ip;
    std::string gateway_mac;
    std::string subnet;
};

struct NetworkRow {
    std::int64_t id = 0;
    std::string fingerprint, gateway_ip, gateway_mac, subnet;
    std::optional<std::string> ssid;
    std::string state;  // home | alias | declined | retired
    std::int64_t first_seen = 0;
    std::optional<std::int64_t> approved_at;
};
nlohmann::json to_json(const NetworkRow& n);

enum class ApproveResult { Approved, AlreadyHome, AddedAlias, ReplaceRequired };

// The home-network schema and its queries (DESIGN §6.1). Thread-safe: writes are
// serialised by core::Database, reads use its reader pool.
class DomainStore {
public:
    virtual ~DomainStore() = default;

    // Persists a batch in one transaction. Live-session events only in M0.
    virtual void write(std::span<const Event> events) = 0;

    virtual std::vector<DeviceRow> devices() = 0;
    virtual std::vector<KnownIdentity> known_identities() = 0;
    virtual std::vector<std::string> shared_macs() = 0;

    virtual std::optional<NetworkRow> network(std::string_view fingerprint) = 0;
    virtual std::optional<NetworkRow> home_network() = 0;
    // An observation with the home network's subnet and gateway IP but a different
    // gateway MAC (e.g. seen through a MAC-rewriting extender) is added as an alias of
    // home instead of replacing it.
    virtual ApproveResult approve_network(const NetworkObservation& n, bool replace, Clock::time_point now) = 0;
    virtual void decline_network(const NetworkObservation& n, Clock::time_point now) = 0;

    virtual std::optional<std::string> meta(std::string_view key) = 0;
    virtual void set_meta(std::string_view key, std::string_view value) = 0;
};

class SqliteDomainStore final : public DomainStore {
public:
    explicit SqliteDomainStore(Database& db) : db_(db) {}

    void write(std::span<const Event> events) override;
    std::vector<DeviceRow> devices() override;
    std::vector<KnownIdentity> known_identities() override;
    std::vector<std::string> shared_macs() override;
    std::optional<NetworkRow> network(std::string_view fingerprint) override;
    std::optional<NetworkRow> home_network() override;
    ApproveResult approve_network(const NetworkObservation& n, bool replace, Clock::time_point now) override;
    void decline_network(const NetworkObservation& n, Clock::time_point now) override;
    std::optional<std::string> meta(std::string_view key) override;
    void set_meta(std::string_view key, std::string_view value) override;

private:
    Database& db_;
};

// "dev_" + a UUIDv7 (time-ordered, random tail). Never derived from MAC or IP.
std::string new_device_id();

}  // namespace frego::domain
