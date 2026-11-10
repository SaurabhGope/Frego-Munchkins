#pragma once

#include <memory>

#include "frego/core/plugin.hpp"

namespace frego::plugins {

// Publishes Heartbeat{seq} every interval_s, proving the bus → store → API → SSE path
// before any networking code runs (DESIGN §7.1).
std::unique_ptr<Plugin> make_heartbeat();

}  // namespace frego::plugins
