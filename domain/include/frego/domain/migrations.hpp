#pragma once

#include <span>

#include "frego/core/database.hpp"

namespace frego::domain {

// The home-network schema (DESIGN §6.3–6.4), applied by core::Database::migrate().
std::span<const Migration> migrations();

}  // namespace frego::domain
