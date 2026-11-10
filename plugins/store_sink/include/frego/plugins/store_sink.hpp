#pragma once

#include <memory>

#include "frego/core/plugin.hpp"

namespace frego::plugins {

// Persists events through domain::DomainStore (DESIGN §7.2). Bulk events are batched
// every flush_ms (or 1,000 events); critical events are committed immediately.
std::unique_ptr<Plugin> make_store_sink();

}  // namespace frego::plugins
