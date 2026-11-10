#include "frego/events/json.hpp"

namespace frego {

std::string json_out(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

}  // namespace frego
