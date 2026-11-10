#include <catch2/catch_test_macros.hpp>

#include "frego/events/catalog.hpp"
#include "frego/events/json.hpp"
#include "frego/events/text.hpp"

using namespace frego;

TEST_CASE("catalog::text keeps valid UTF-8 and strips control characters", "[events]") {
    CHECK(catalog::text("Living Room TV") == "Living Room TV");
    CHECK(catalog::text("Saurabh\xE2\x80\x99s iPhone") == "Saurabh\xE2\x80\x99s iPhone");  // U+2019
    CHECK(catalog::text("a\tb\nc\x01" "d\x7F") == "a\tbcd");
    CHECK(catalog::text("x\xC2\x85y") == "xy");  // C1 control U+0085
}

TEST_CASE("catalog::text replaces invalid sequences with U+FFFD", "[events]") {
    const std::string fffd = "\xEF\xBF\xBD";
    CHECK(catalog::text("a\xFFz") == "a" + fffd + "z");
    CHECK(catalog::text("\xC0\xAF") == fffd + fffd);              // overlong
    CHECK(catalog::text("\xED\xA0\x80") == fffd + fffd + fffd);  // surrogate
    CHECK(catalog::text("\xE2\x82") == fffd + fffd);              // truncated
}

TEST_CASE("catalog::text truncates on a code-point boundary", "[events]") {
    CHECK(catalog::text("abcdef", 4) == "abcd");
    CHECK(catalog::text("ab\xE2\x80\x99", 4) == "ab");  // a 3-byte char won't fit in 2
    CHECK(catalog::text(std::string(1000, 'x')).size() == 255);
}

TEST_CASE("json_out never throws on invalid UTF-8", "[events]") {
    nlohmann::json j = {{"name", std::string("bad\xFF\xFE")}};
    std::string out;
    REQUIRE_NOTHROW(out = json_out(j));
    const bool replaced = out.find("\\ufffd") != std::string::npos || out.find("\xEF\xBF\xBD") != std::string::npos;
    CHECK(replaced);
}

TEST_CASE("every payload round-trips through JSON", "[events]") {
    std::vector<Payload> payloads{
        Heartbeat{42},
        NetworkChanged{"abcd", "en0", "192.168.1.0/24", "192.168.1.1", "b4:3d:08:02:98:e8", NetworkStatus::Home, "home"},
        CollectionGate{true, "home network"},
        NeighborSnapshot{"en0", "192.168.1.0/24", {{"192.168.1.3", 4, "80:8a:bd:f1:db:d2"}}, {"192.168.1.27", 4, "7a:73:de:ac:29:de"}},
        DeviceIdentified{"dev_x", "192.168.1.3", "80:8a:bd:f1:db:d2", "Samsung", "strong", false, false, true, "arp"},
        Alert{"k", "plugin_failed", Severity::Medium, "", "t", "r"},
        Custom{"org.example.test", 2, {{"a", 1}}},
    };
    REQUIRE(payloads.size() == kKindCount);
    for (const auto& p : payloads) {
        auto j = payload_to_json(p);
        auto back = payload_from_json(kind_of(p), j);
        CHECK(kind_of(back) == kind_of(p));
        CHECK(payload_to_json(back) == j);
    }
}

TEST_CASE("from_json ignores unknown fields and rejects missing required ones", "[events]") {
    auto p = payload_from_json(EventKind::Heartbeat, {{"seq", 1}, {"added_in_v2", true}});
    CHECK(std::get<Heartbeat>(p).seq == 1);
    CHECK_THROWS(payload_from_json(EventKind::Heartbeat, nlohmann::json::object()));
}

TEST_CASE("kind names, critical lanes and envelope JSON", "[events]") {
    for (std::size_t i = 0; i < kKindCount; ++i) {
        auto k = static_cast<EventKind>(i);
        CHECK(kind_from_name(kind_name(k)) == k);
    }
    CHECK(is_critical(EventKind::Alert));
    CHECK(is_critical(EventKind::CollectionGate));
    CHECK(is_critical(EventKind::NetworkChanged));
    CHECK_FALSE(is_critical(EventKind::Heartbeat));
    CHECK_FALSE(is_critical(EventKind::NeighborSnapshot));

    Event e{7, from_unix_ms(1000), from_unix_ms(2000), 3, "test", Heartbeat{1}};
    auto j = to_json(e);
    CHECK(j["observed_at"] == 1000);
    CHECK(j["published_at"] == 2000);
    CHECK(j["session"] == 3);
    CHECK(j["kind"] == "Heartbeat");
    CHECK(j["catalog"] == std::string(kCatalogVersion));
    CHECK(approx_size(e) >= sizeof(Event));
}
