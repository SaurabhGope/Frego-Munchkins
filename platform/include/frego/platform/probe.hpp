#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stop_token>

#include "frego/net/ipv4.hpp"

namespace frego::platform {

// Sends an empty UDP datagram to port 9 of each host. The kernel has to ARP for the
// destination before it can send, which fills the ARP cache without root (DESIGN §7.3).
// Returns how many sends were attempted; stops early when stop is requested.
std::size_t udp_nudge(std::span<const net::Ipv4> hosts, std::stop_token stop);

enum class ProbeResult { Reached, Unreachable, Timeout, Error };

struct ProbeOutcome {
    ProbeResult result = ProbeResult::Error;
    int error = 0;  // errno for Unreachable/Error
};

// TCP connect with a timeout. "Connection refused" counts as Reached: the packet got to
// the host. Unreachable means the OS refused to route it (e.g. Local Network Privacy).
ProbeOutcome tcp_probe(net::Ipv4 ip, std::uint16_t port, std::chrono::milliseconds timeout);

}  // namespace frego::platform
