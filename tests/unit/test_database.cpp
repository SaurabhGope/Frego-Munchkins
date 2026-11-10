#include <array>
#include <filesystem>
#include <random>

#include <catch2/catch_test_macros.hpp>

#include "frego/core/database.hpp"
#include "test_util.hpp"

using namespace frego;

namespace {

constexpr std::array<Migration, 1> kV1{{{1, "create t", "CREATE TABLE t (x INTEGER);"}}};
constexpr std::array<Migration, 2> kV2{{{1, "create t", "CREATE TABLE t (x INTEGER);"},
                                        {2, "add u", "CREATE TABLE u (y INTEGER);"}}};
constexpr std::array<Migration, 2> kBroken{{{1, "create t", "CREATE TABLE t (x INTEGER);"},
                                            {2, "broken", "CREATE TABLE v (z INTEGER); SELECT nonsense FROM nowhere;"}}};

}  // namespace

TEST_CASE("migrations apply in order and set user_version", "[database]") {
    test::TempDir dir;
    Logger log(LogLevel::Error, false);
    auto db = Database::open(dir.path / "t.db");
    db->migrate(kV1, dir.path / "backups", log);
    CHECK(db->user_version() == 1);
    db->write([](Connection& c) { c.exec("INSERT INTO t VALUES (7)"); });
    auto x = db->read([](Connection& c) {
        auto s = c.prepare("SELECT x FROM t");
        s.step();
        return s.col_int(0);
    });
    CHECK(x == 7);
    CHECK_FALSE(std::filesystem::exists(dir.path / "backups"));  // a new database isn't backed up
}

TEST_CASE("upgrading backs up first; newer schemas are refused", "[database]") {
    test::TempDir dir;
    Logger log(LogLevel::Error, false);
    {
        auto db = Database::open(dir.path / "t.db");
        db->migrate(kV1, dir.path / "backups", log);
        db->migrate(kV2, dir.path / "backups", log);
        CHECK(db->user_version() == 2);
    }
    int backups = 0;
    for (const auto& e : std::filesystem::directory_iterator(dir.path / "backups"))
        backups += e.path().filename().string().starts_with("frego-v1-") ? 1 : 0;
    CHECK(backups == 1);

    auto db = Database::open(dir.path / "t.db");
    CHECK_THROWS_AS(db->migrate(kV1, dir.path / "backups", log), MigrationError);  // DB is v2, build knows v1
}

TEST_CASE("a failing migration rolls back and leaves the previous version", "[database]") {
    test::TempDir dir;
    Logger log(LogLevel::Error, false);
    auto db = Database::open(dir.path / "t.db");
    db->migrate(kV1, dir.path / "backups", log);
    CHECK_THROWS_AS(db->migrate(kBroken, dir.path / "backups", log), MigrationError);
    CHECK(db->user_version() == 1);
    auto has_v = db->read([](Connection& c) {
        auto s = c.prepare("SELECT count(*) FROM sqlite_master WHERE name = 'v'");
        s.step();
        return s.col_int(0);
    });
    CHECK(has_v == 0);
}
