#include <catch2/catch_test_macros.hpp>

#include "frego/plugins/identity.hpp"

using namespace frego;
using namespace frego::plugins;

namespace {

IdentityResolver::IdFactory counter_ids() {
    auto n = std::make_shared<int>(0);
    return [n] { return "dev_" + std::to_string(++*n); };
}

const net::OuiDb kOui = net::OuiDb::parse_csv(
    "MA-L,808ABD,Samsung Electronics Co.,x\n"
    "MA-L,B43D08,Router Corp,x\n");

const DeviceIdentified* by_ip(const std::vector<DeviceIdentified>& v, const std::string& ip) {
    for (const auto& d : v)
        if (d.ip == ip) return &d;
    return nullptr;
}

// The builder's home network on 2026-11-10 (DESIGN §7.6): router, TV, and an extender
// (22:23:51:01:2a:2b) answering ARP for several devices behind it.
NeighborSnapshot home_snapshot() {
    return {"en0",
            "192.168.1.0/24",
            {{"192.168.1.1", 4, "b4:3d:08:02:98:e8"},
             {"192.168.1.3", 4, "80:8a:bd:f1:db:d2"},
             {"192.168.1.5", 4, "22:23:51:01:2a:2b"},
             {"192.168.1.10", 4, "22:23:51:01:2a:2b"},
             {"192.168.1.28", 4, "22:23:51:01:2a:2b"}},
            {"192.168.1.27", 4, "7a:73:de:ac:29:de"}};
}

}  // namespace

TEST_CASE("devices with their own MAC get a strong identity and vendor", "[identity]") {
    IdentityResolver r(&kOui, counter_ids());
    auto out = r.resolve(home_snapshot());
    REQUIRE(out.size() == 6);
    auto tv = by_ip(out, "192.168.1.3");
    REQUIRE(tv);
    CHECK(tv->identity == "strong");
    CHECK(tv->vendor == "Samsung Electronics Co.");
    CHECK_FALSE(tv->randomized);
    CHECK(tv->created);
    CHECK(by_ip(out, "192.168.1.1")->vendor == "Router Corp");
}

TEST_CASE("a MAC on several IPs is shared: one weak device per IP, no vendor", "[identity]") {
    IdentityResolver r(&kOui, counter_ids());
    auto out = r.resolve(home_snapshot());
    CHECK(r.take_new_shared() == std::vector<std::string>{"22:23:51:01:2a:2b"});
    CHECK(r.take_new_shared().empty());
    auto a = by_ip(out, "192.168.1.5");
    auto b = by_ip(out, "192.168.1.10");
    REQUIRE(a);
    REQUIRE(b);
    CHECK(a->identity == "weak");
    CHECK(a->id != b->id);
    CHECK_FALSE(a->vendor);
    CHECK(a->randomized);  // the extender's rewritten MAC is locally administered
}

TEST_CASE("the host itself is identified and flagged", "[identity]") {
    IdentityResolver r(&kOui, counter_ids());
    auto out = r.resolve(home_snapshot());
    auto self = by_ip(out, "192.168.1.27");
    REQUIRE(self);
    CHECK(self->is_self);
    CHECK(self->via == "self");
    CHECK(self->randomized);  // macOS private Wi-Fi address
}

TEST_CASE("identities are stable across scans, IP changes and restarts", "[identity]") {
    IdentityResolver r(&kOui, counter_ids());
    auto first = r.resolve(home_snapshot());
    const auto tv_id = by_ip(first, "192.168.1.3")->id;

    auto moved = home_snapshot();
    moved.entries[1].ip = "192.168.1.30";  // TV got a new DHCP lease
    auto second = r.resolve(moved);
    CHECK(by_ip(second, "192.168.1.30")->id == tv_id);
    CHECK_FALSE(by_ip(second, "192.168.1.30")->created);

    // A fresh resolver primed from the store resolves to the same ids.
    IdentityResolver restarted(&kOui, counter_ids());
    restarted.remember({tv_id, "80:8a:bd:f1:db:d2", "192.168.1.30", "strong"});
    restarted.remember_shared("22:23:51:01:2a:2b");
    const auto weak_id = by_ip(second, "192.168.1.5")->id;
    restarted.remember({weak_id, "22:23:51:01:2a:2b", "192.168.1.5", "weak"});
    auto third = restarted.resolve(moved);
    CHECK(by_ip(third, "192.168.1.30")->id == tv_id);
    CHECK(by_ip(third, "192.168.1.5")->id == weak_id);
    CHECK(restarted.take_new_shared().empty());  // already known
}

TEST_CASE("malformed MACs are skipped", "[identity]") {
    IdentityResolver r(nullptr, counter_ids());
    NeighborSnapshot s{"en0", "", {{"192.168.1.9", 4, "not-a-mac"}}, {"192.168.1.27", 4, ""}};
    CHECK(r.resolve(s).empty());
}
