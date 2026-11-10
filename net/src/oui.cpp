#include "frego/net/oui.hpp"

#include <charconv>
#include <fstream>
#include <sstream>
#include <vector>

namespace frego::net {
namespace {

// Splits RFC 4180 CSV into records: quoted fields may contain commas, newlines and ""
// escapes.
class CsvReader {
public:
    explicit CsvReader(std::string_view text) : text_(text) {}

    bool next(std::vector<std::string>& fields) {
        fields.clear();
        if (pos_ >= text_.size()) return false;
        std::string field;
        bool quoted = false;
        while (pos_ < text_.size()) {
            char c = text_[pos_++];
            if (quoted) {
                if (c != '"') {
                    field += c;
                } else if (pos_ < text_.size() && text_[pos_] == '"') {
                    field += '"';
                    ++pos_;
                } else {
                    quoted = false;
                }
            } else if (c == '"') {
                quoted = true;
            } else if (c == ',') {
                fields.push_back(std::move(field));
                field.clear();
            } else if (c == '\n') {
                break;
            } else if (c != '\r') {
                field += c;
            }
        }
        fields.push_back(std::move(field));
        return true;
    }

private:
    std::string_view text_;
    std::size_t pos_ = 0;
};

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

}  // namespace

OuiDb OuiDb::parse_csv(std::string_view csv) {
    OuiDb db;
    CsvReader reader(csv);
    std::vector<std::string> fields;
    while (reader.next(fields)) {
        if (fields.size() < 3 || fields[0] != "MA-L" || fields[1].size() != 6) continue;
        std::uint32_t prefix = 0;
        const char* begin = fields[1].data();
        const char* end = begin + fields[1].size();
        auto [ptr, ec] = std::from_chars(begin, end, prefix, 16);
        if (ec != std::errc{} || ptr != end) continue;
        auto name = trim(fields[2]);
        if (!name.empty()) db.vendors_.emplace(prefix, std::string(name));
    }
    return db;
}

std::expected<OuiDb, std::string> OuiDb::load_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::unexpected("cannot open " + path.string());
    std::ostringstream buf;
    buf << in.rdbuf();
    return parse_csv(buf.str());
}

std::optional<std::string_view> OuiDb::lookup(const Mac& mac) const {
    if (mac.locally_administered() || mac.multicast()) return std::nullopt;
    auto it = vendors_.find(mac.oui());
    if (it == vendors_.end()) return std::nullopt;
    return it->second;
}

}  // namespace frego::net
