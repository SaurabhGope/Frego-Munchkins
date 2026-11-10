#include <catch2/catch_test_macros.hpp>

#include "frego/domain/migrations.hpp"
#include "frego/domain/store.hpp"
#include "test_util.hpp"

using namespace frego;
using namespace frego::domain;

namespace {

struct Fixture {
    test::TempDir dir;
    Logger log{LogLevel::Error, false};
    std::unique_ptr<Database> db = Database::open(dir.path / "frego.db");
    std::unique_ptr<SqliteDomainStore> store;

    Fixture() {
        db->migrate(migrations(), dir.path / "backups", log);
        store = std::make_unique<SqliteDomainStore>(*db);
    }

    void write(Payload p, std::int64_t ms, SessionId session = kLiveSession) {
        Event e{1, from_unix_ms(ms), from_unix_ms(ms), session, "test", std::move(p)};
        store->write(std::span(&e, 1));
    }
};

const NetworkObservation kHome{"aaaa", "192.168.1.1", "b4:3d:08:02:98:e8", "192.168.1.0/24"};
const NetworkObservation kViaExtender{"bbbb", "192.168.1.1", "22:23:51:01:2a:2b", "192.168.1.0/24"};
const NetworkObservation kCafe{"cccc", "10.0.0.1", "00:11:22:33:44:55", "10.0.0.0/24"};

DeviceIdentified tv(std::string ip = "192.168.1.3") {
    return {"dev_tv", std::move(ip), "80:8a:bd:f1:db:d2", "Samsung", "strong", false, false, true, "arp"};
}

}  // namespace

TEST_CASE("schema migrates and creates the live session", "[domain]") {
    Fixture f;
    CHECK(f.db->user_version() == 1);
    auto live = f.db->read([](Connection& c) {
        auto s = c.prepare("SELECT kind FROM sessions WHERE id = 0");
        s.step();
        return s.col_text(0);
    });
    CHECK(live == "live");
}

TEST_CASE("network approval: home, alias via extender, replace, decline", "[domain]") {
    Fixture f;
    auto now = from_unix_ms(1000);
    CHECK_FALSE(f.store->home_network());
    CHECK(f.store->approve_network(kHome, false, now) == ApproveResult::Approved);
    CHECK(f.store->approve_network(kHome, false, now) == ApproveResult::AlreadyHome);
    // Same router seen through a MAC-rewriting extender: an alias, not a new home.
    CHECK(f.store->approve_network(kViaExtender, false, now) == ApproveResult::AddedAlias);
    CHECK(f.store->network("bbbb")->state == "alias");
    // A genuinely different network needs explicit replacement.
    CHECK(f.store->approve_network(kCafe, false, now) == ApproveResult::ReplaceRequired);
    CHECK(f.store->home_network()->fingerprint == "aaaa");
    CHECK(f.store->approve_network(kCafe, true, now) == ApproveResult::Approved);
    CHECK(f.store->home_network()->fingerprint == "cccc");
    CHECK(f.store->network("aaaa")->state == "retired");
    CHECK(f.store->network("bbbb")->state == "retired");

    f.store->decline_network(kHome, now);
    CHECK(f.store->network("aaaa")->state == "declined");
}

TEST_CASE("devices upsert, keep first_seen, and tag the home network", "[domain]") {
    Fixture f;
    f.store->approve_network(kHome, false, from_unix_ms(1));
    f.write(tv(), 1000);
    auto later = tv("192.168.1.30");
    later.vendor.reset();  // a missing vendor never erases a known one
    f.write(later, 5000);

    auto devices = f.store->devices();
    REQUIRE(devices.size() == 1);
    const auto& d = devices[0];
    CHECK(d.id == "dev_tv");
    CHECK(d.ip == "192.168.1.30");
    CHECK(d.vendor == "Samsung");
    CHECK(d.first_seen == 1000);
    CHECK(d.last_seen == 5000);
    CHECK(d.network_id == f.store->home_network()->id);

    auto known = f.store->known_identities();
    REQUIRE(known.size() == 1);
    CHECK(known[0].mac == "80:8a:bd:f1:db:d2");
}

TEST_CASE("an IP binding moves to whoever holds the IP now", "[domain]") {
    Fixture f;
    f.store->approve_network(kHome, false, from_unix_ms(1));
    f.write(tv("192.168.1.2"), 1000);
    DeviceIdentified phone{"dev_phone", "192.168.1.2", "d6:3f:25:96:09:da", std::nullopt, "strong", true, false, true, "arp"};
    f.write(phone, 2000);
    auto rows = f.db->read([](Connection& c) {
        auto s = c.prepare("SELECT device_id, valid_from, valid_to FROM ip_bindings WHERE ip = '192.168.1.2' ORDER BY valid_from");
        std::vector<std::tuple<std::string, std::int64_t, std::optional<std::int64_t>>> out;
        while (s.step()) out.emplace_back(s.col_text(0), s.col_int(1), s.col_opt_int(2));
        return out;
    });
    REQUIRE(rows.size() == 2);
    CHECK(std::get<0>(rows[0]) == "dev_tv");
    CHECK(std::get<2>(rows[0]) == 2000);
    CHECK(std::get<0>(rows[1]) == "dev_phone");
    CHECK_FALSE(std::get<2>(rows[1]));
}

TEST_CASE("weak devices record their shared MAC", "[domain]") {
    Fixture f;
    f.store->approve_network(kHome, false, from_unix_ms(1));
    f.write(DeviceIdentified{"dev_a", "192.168.1.5", "22:23:51:01:2a:2b", std::nullopt, "weak", true, false, true, "arp"}, 10);
    f.write(DeviceIdentified{"dev_b", "192.168.1.10", "22:23:51:01:2a:2b", std::nullopt, "weak", true, false, true, "arp"}, 10);
    CHECK(f.store->shared_macs() == std::vector<std::string>{"22:23:51:01:2a:2b"});
    auto ips = f.db->read([](Connection& c) {
        auto s = c.prepare("SELECT ips FROM shared_macs");
        s.step();
        return nlohmann::json::parse(s.col_text(0));
    });
    CHECK(ips.size() == 2);
}

TEST_CASE("devices from another network or session are not listed", "[domain]") {
    Fixture f;
    f.write(tv(), 1000);  // no home yet → network_id NULL
    CHECK(f.store->devices().empty());
    f.store->approve_network(kHome, false, from_unix_ms(1));
    f.write(DeviceIdentified{"dev_x", "192.168.1.9", "00:11:22:33:44:55", std::nullopt, "strong", false, false, true, "arp"}, 2000, 5);
    CHECK(f.store->devices().empty());  // investigation sessions never touch the live inventory
}

TEST_CASE("heartbeat and alerts are persisted", "[domain]") {
    Fixture f;
    f.write(Heartbeat{3}, 1234);
    auto hb = nlohmann::json::parse(*f.store->meta("last_heartbeat"));
    CHECK(hb["seq"] == 3);
    CHECK(hb["observed_at"] == 1234);

    f.write(Alert{"plugin:x", "plugin_failed", Severity::Medium, "", "Plugin x was disabled", "boom"}, 10);
    f.write(Alert{"plugin:x", "plugin_failed", Severity::Medium, "", "Plugin x was disabled", "boom again"}, 20);
    auto [count, reason, updated] = f.db->read([](Connection& c) {
        auto s = c.prepare("SELECT count(*), max(reason), max(updated) FROM alerts");
        s.step();
        return std::tuple{s.col_int(0), s.col_text(1), s.col_int(2)};
    });
    CHECK(count == 1);  // deduplicated by key
    CHECK(reason == "boom again");
    CHECK(updated == 20);
}

TEST_CASE("device ids are opaque uuidv7", "[domain]") {
    auto a = new_device_id();
    auto b = new_device_id();
    CHECK(a != b);
    CHECK(a.starts_with("dev_"));
    CHECK(a.size() == 4 + 36);
    CHECK(a[4 + 14] == '7');  // version nibble
}
