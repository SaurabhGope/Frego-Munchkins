#include <catch2/catch_test_macros.hpp>

#include "frego/core/config.hpp"

using namespace frego;

TEST_CASE("config overrides merge over defaults", "[config]") {
    auto c = Config::from_json({{"plugins", {{"heartbeat", {{"enabled", false}}}}}, {"api", {{"port", 9000}}}});
    CHECK_FALSE(c.plugin_enabled("heartbeat"));
    CHECK(c.plugin("heartbeat").value("interval_s", 0) == 5);  // untouched default survives
    CHECK(c.plugin_enabled("neighbor-scan"));
    CHECK(c.api_port() == 9000);
    CHECK(c.api_listen() == "127.0.0.1");
}

TEST_CASE("unknown plugins are disabled and unknown keys are reported", "[config]") {
    auto c = Config::from_json({{"surprise", 1}, {"api", {{"tls", true}}}});
    CHECK_FALSE(c.plugin_enabled("does-not-exist"));
    CHECK(c.plugin("does-not-exist").is_object());
    auto unknown = c.unknown_keys();
    CHECK(std::ranges::find(unknown, "surprise") != unknown.end());
    CHECK(std::ranges::find(unknown, "api.tls") != unknown.end());
}

TEST_CASE("data_dir expands ~ and defaults to the platform path", "[config]") {
    CHECK_FALSE(Config::from_json({}).data_dir());
    auto c = Config::from_json({{"data_dir", "~/frego-test"}});
    REQUIRE(c.data_dir());
    CHECK(c.data_dir()->filename() == "frego-test");
    CHECK(c.data_dir()->string().find('~') == std::string::npos);
}
