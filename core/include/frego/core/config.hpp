#pragma once

#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace frego {

// <data_dir>/config.json merged over built-in defaults (DESIGN §4.5). Unknown keys are
// warnings, not errors.
class Config {
public:
    static nlohmann::json defaults();
    static Config from_json(const nlohmann::json& overrides);
    static std::expected<Config, std::string> load_file(const std::filesystem::path& path);

    void patch(const nlohmann::json& overrides);

    const nlohmann::json& root() const { return root_; }
    const nlohmann::json& plugin(std::string_view name) const;  // {} when absent
    bool plugin_enabled(std::string_view name) const;
    std::string api_listen() const;
    int api_port() const;
    std::string log_level() const;
    std::optional<std::filesystem::path> data_dir() const;  // "~/" expanded; nullopt = platform default
    std::vector<std::string> unknown_keys() const;

private:
    nlohmann::json root_;
};

}  // namespace frego
