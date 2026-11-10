#include "frego/platform/paths.hpp"

#include <cstdlib>

namespace frego::platform {

std::filesystem::path default_data_dir() {
    if (const char* home = std::getenv("FREGO_HOME"); home && *home) return home;
    const char* user_home = std::getenv("HOME");
    std::filesystem::path base = user_home ? user_home : ".";
#if defined(__APPLE__)
    return base / "Library" / "Application Support" / "FregoMunchkin";
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg)
        return std::filesystem::path(xdg) / "fregomunchkin";
    return base / ".local" / "share" / "fregomunchkin";
#endif
}

}  // namespace frego::platform
