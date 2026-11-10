add_library(frego_net src/mac.cpp src/oui.cpp src/ipv4.cpp src/sha256.cpp)
target_include_directories(frego_net PUBLIC include)
frego_warnings(frego_net)
