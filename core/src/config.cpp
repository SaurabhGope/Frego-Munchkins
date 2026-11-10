#include "frego/core/config.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace frego {

nlohmann::json Config::defaults() {
    return nlohmann::json::parse(R"({
      "data_dir": "",
      "log_level": "info",
      "api": { "listen": "127.0.0.1", "port": 8737 },
      "plugins": {
        "store-sink":    { "enabled": true,  "flush_ms": 250 },
        "network-guard": { "enabled": true,  "interval_s": 30 },
        "heartbeat":     { "enabled": true,  "interval_s": 5 },
        "neighbor-scan": { "enabled": true,  "interval_s": 300, "interface": "auto", "settle_ms": 2000 },
        "identity":      { "enabled": true }
      }
    })");
}

Config Config::from_json(const nlohmann::json& overrides) {
    Config c;
    c.root_ = defaults();
    c.patch(overrides);
    return c;
}

std::expected<Config, std::string> Config::load_file(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) return std::unexpected("cannot open " + path.string());
    std::stringstream buf;
    buf << in.rdbuf();
    auto parsed = nlohmann::json::parse(buf.str(), nullptr, /*allow_exceptions=*/false,
                                        /*ignore_comments=*/true);
    if (parsed.is_discarded() || !parsed.is_object())
        return std::unexpected(path.string() + " is not a valid JSON object");
    return from_json(parsed);
}

void Config::patch(const nlohmann::json& overrides) {
    if (overrides.is_object()) root_.merge_patch(overrides);
}

const nlohmann::json& Config::plugin(std::string_view name) const {
    static const nlohmann::json empty = nlohmann::json::object();
    auto plugins = root_.find("plugins");
    if (plugins == root_.end() || !plugins->is_object()) return empty;
    auto it = plugins->find(std::string(name));
    return (it == plugins->end() || !it->is_object()) ? empty : *it;
}

bool Config::plugin_enabled(std::string_view name) const {
    return plugin(name).value("enabled", false);
}

std::string Config::api_listen() const {
    return root_.value("/api/listen"_json_pointer, std::string{"127.0.0.1"});
}

int Config::api_port() const { return root_.value("/api/port"_json_pointer, 8737); }

std::string Config::log_level() const { return root_.value("log_level", std::string{"info"}); }

std::optional<std::filesystem::path> Config::data_dir() const {
    auto dir = root_.value("data_dir", std::string{});
    if (dir.empty()) return std::nullopt;
    if (dir.starts_with("~/")) {
        const char* home = std::getenv("HOME");
        return std::filesystem::path(home ? home : ".") / dir.substr(2);
    }
    return std::filesystem::path(dir);
}

std::vector<std::string> Config::unknown_keys() const {
    std::vector<std::string> unknown;
    auto known = defaults();
    for (auto& [key, value] : root_.items()) {
        if (!known.contains(key)) unknown.push_back(key);
        else if (key == "api" && value.is_object())
            for (auto& [sub, _] : value.items())
                if (!known["api"].contains(sub)) unknown.push_back("api." + sub);
    }
    return unknown;
}

}  // namespace frego
