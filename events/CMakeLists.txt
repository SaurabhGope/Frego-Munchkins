add_library(frego_events src/catalog.cpp src/text.cpp src/json.cpp)
target_include_directories(frego_events PUBLIC include)
target_link_libraries(frego_events PUBLIC nlohmann_json::nlohmann_json)
frego_warnings(frego_events)
