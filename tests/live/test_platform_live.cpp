// Touches the real network; hidden by the [.live] tag. Run with:
//   ./build/debug/tests/frego_tests "[.live]"
// Must run outside network sandboxes (DESIGN §10.1, finding 4).
#include <catch2/catch_test_macros.hpp>

#include "frego/platform/netinfo.hpp"

using namespace frego;

TEST_CASE("default interface and ARP table are readable", "[.live]") {
    auto itf = platform::default_interface();
    REQUIRE(itf.has_value());
    INFO("interface " << itf->name << " addr " << itf->addr.str() << "/" << itf->subnet().prefix);
    CHECK(itf->subnet().prefix > 0);
    CHECK(itf->gateway.has_value());

    auto table = platform::arp_table(itf->name);
    REQUIRE(table.has_value());
    bool gateway_seen = false;
    for (const auto& e : *table) gateway_seen |= itf->gateway && e.ip == *itf->gateway;
    CHECK(gateway_seen);
}
