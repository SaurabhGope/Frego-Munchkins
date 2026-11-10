add_library(frego_core
  src/bus.cpp
  src/config.cpp
  src/database.cpp
  src/host.cpp
  src/http.cpp
  src/log.cpp
  src/metrics.cpp
  src/plugin.cpp
  src/scheduler.cpp)
target_include_directories(frego_core PUBLIC include)
# The core depends only on the event contract, never on net/platform/domain (DESIGN §2).
target_link_libraries(frego_core
  PUBLIC frego_events nlohmann_json::nlohmann_json
  PRIVATE httplib::httplib SQLite::SQLite3)
frego_warnings(frego_core)
frego_version(frego_core)
