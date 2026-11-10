add_executable(fregoctl main.cpp)
target_link_libraries(fregoctl PRIVATE frego_events httplib::httplib nlohmann_json::nlohmann_json)
frego_warnings(fregoctl)
frego_version(fregoctl)
