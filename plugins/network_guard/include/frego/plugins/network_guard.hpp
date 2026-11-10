#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "frego/core/plugin.hpp"
#include "frego/domain/store.hpp"

namespace frego::plugins {

// Only collect on the approved home network (DESIGN §7.0, B3). Fingerprints the network,
// publishes NetworkChanged + CollectionGate, serves /api/v1/network*, and checks that
// macOS Local Network Privacy isn't blocking LAN access (§10.1).
std::unique_ptr<Plugin> make_network_guard();

namespace guard {

// First 16 hex chars of SHA-256("<gateway_mac>|<subnet>").
std::string fingerprint(std::string_view gateway_mac, std::string_view subnet);

// Status of an observed network given the stored row for its fingerprint, if any.
NetworkStatus classify(bool have_network, const std::optional<domain::NetworkRow>& row);

}  // namespace guard
}  // namespace frego::plugins
