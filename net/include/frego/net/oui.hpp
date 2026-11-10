#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "frego/net/mac.hpp"

namespace frego::net {

// MAC vendor lookup from the IEEE MA-L registry (oui.csv from standards-oui.ieee.org).
class OuiDb {
public:
    // Columns: Registry,Assignment,Organization Name,Organization Address.
    // Malformed rows are skipped.
    static OuiDb parse_csv(std::string_view csv);
    static std::expected<OuiDb, std::string> load_file(const std::filesystem::path& path);

    // nullopt for unknown prefixes and for locally administered (randomized) MACs.
    std::optional<std::string_view> lookup(const Mac& mac) const;
    std::size_t size() const { return vendors_.size(); }

private:
    std::unordered_map<std::uint32_t, std::string> vendors_;
};

}  // namespace frego::net
