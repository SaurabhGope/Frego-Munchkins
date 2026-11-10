#include <catch2/catch_test_macros.hpp>

#include "frego/plugins/network_guard.hpp"

using namespace frego;
using namespace frego::plugins;

TEST_CASE("network fingerprint is stable and depends on gateway MAC and subnet", "[network-guard]") {
    auto a = guard::fingerprint("b4:3d:08:02:98:e8", "192.168.1.0/24");
    CHECK(a.size() == 16);
    CHECK(a == guard::fingerprint("b4:3d:08:02:98:e8", "192.168.1.0/24"));
    CHECK(a != guard::fingerprint("22:23:51:01:2a:2b", "192.168.1.0/24"));
    CHECK(a != guard::fingerprint("b4:3d:08:02:98:e8", "192.168.0.0/24"));
}

TEST_CASE("network classification follows the B3 state machine", "[network-guard]") {
    auto row = [](std::string state) {
        domain::NetworkRow r;
        r.state = std::move(state);
        return std::optional(r);
    };
    CHECK(guard::classify(false, std::nullopt) == NetworkStatus::None);
    CHECK(guard::classify(true, std::nullopt) == NetworkStatus::Unknown);
    CHECK(guard::classify(true, row("home")) == NetworkStatus::Home);
    CHECK(guard::classify(true, row("alias")) == NetworkStatus::Home);
    CHECK(guard::classify(true, row("declined")) == NetworkStatus::Declined);
    CHECK(guard::classify(true, row("retired")) == NetworkStatus::Unknown);
}
