#pragma once

#include <filesystem>

namespace frego::platform {

// $FREGO_HOME, else ~/Library/Application Support/FregoMunchkin (macOS) or
// $XDG_DATA_HOME/fregomunchkin (Linux).
std::filesystem::path default_data_dir();

}  // namespace frego::platform
