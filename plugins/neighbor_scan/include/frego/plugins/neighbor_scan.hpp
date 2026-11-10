#pragma once

#include <memory>

#include "frego/core/plugin.hpp"

namespace frego::plugins {

// Finds hosts on the home subnet without root (DESIGN §7.3): a UDP nudge to every host
// fills the kernel ARP cache, then one NeighborSnapshot of the table is published.
// M0 covers IPv4/ARP; IPv6/NDP arrives in M1.
std::unique_ptr<Plugin> make_neighbor_scan();

}  // namespace frego::plugins
