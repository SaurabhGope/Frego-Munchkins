#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace frego {

// The only place JSON is serialized (DESIGN §8, M7). Invalid UTF-8 is replaced instead
// of throwing. A CTest check (tools/check-json-dump.sh) fails if nlohmann's dump() is
// called anywhere else.
std::string json_out(const nlohmann::json& j);

}  // namespace frego
