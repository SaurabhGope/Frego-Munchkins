add_library(frego_domain src/migrations.cpp src/sqlite_store.cpp src/ids.cpp)
target_include_directories(frego_domain PUBLIC include)
target_link_libraries(frego_domain PUBLIC frego_core frego_events)
frego_warnings(frego_domain)
