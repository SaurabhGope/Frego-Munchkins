add_executable(frego_tests
  unit/test_net.cpp
  unit/test_events.cpp
  unit/test_bus.cpp
  unit/test_config.cpp
  unit/test_database.cpp
  unit/test_domain.cpp
  unit/test_host.cpp
  unit/test_http.cpp
  unit/test_identity.cpp
  unit/test_network_guard.cpp
  live/test_platform_live.cpp)
target_link_libraries(frego_tests PRIVATE
  Catch2::Catch2WithMain httplib::httplib
  frego_core frego_domain frego_net frego_platform
  frego_plugin_identity frego_plugin_network_guard)
frego_warnings(frego_tests)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
# Tests tagged [.live] touch the real network and only run when asked for.
catch_discover_tests(frego_tests)

add_test(NAME json_dump_only_in_json_out COMMAND sh ${PROJECT_SOURCE_DIR}/tools/check-json-dump.sh ${PROJECT_SOURCE_DIR})
