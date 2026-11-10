#pragma once

#include <functional>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "frego/core/plugin.hpp"
#include "frego/domain/store.hpp"
#include "frego/net/mac.hpp"
#include "frego/net/oui.hpp"

namespace frego::plugins {

// Decides which device each neighbour entry belongs to and serves /api/v1/devices
// (DESIGN §7.6). M0 is the basic slice: opaque IDs, OUI vendors, randomized-MAC flags and
// shared-MAC detection. Merges, questions and DHCP/EUI-64 evidence arrive in M1.
std::unique_ptr<Plugin> make_identity();

// Pure resolution logic, separated from the plugin for tests.
class IdentityResolver {
public:
    using IdFactory = std::function<std::string()>;
    explicit IdentityResolver(const net::OuiDb* oui = nullptr, IdFactory new_id = domain::new_device_id);

    void remember(const domain::KnownIdentity& known);
    void remember_shared(const std::string& mac);

    // One DeviceIdentified per entry plus one for the host itself. A MAC seen on two or
    // more IPs in the snapshot becomes "shared": until the user says otherwise (M1), each
    // IP behind it is tracked as its own weak device, with no vendor (it's the
    // extender's, not the device's).
    std::vector<DeviceIdentified> resolve(const NeighborSnapshot& snapshot);
    std::vector<std::string> take_new_shared();  // shared MACs first detected since last call

private:
    DeviceIdentified identify(const net::Mac& mac, const std::string& ip, bool shared, bool is_self);

    const net::OuiDb* oui_;
    IdFactory new_id_;
    std::unordered_map<std::string, std::string> strong_;  // mac → device id
    std::unordered_map<std::string, std::string> weak_;    // mac@ip → device id
    std::set<std::string> shared_;
    std::vector<std::string> new_shared_;
};

}  // namespace frego::plugins
