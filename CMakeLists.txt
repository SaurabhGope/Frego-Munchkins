cmake_minimum_required(VERSION 3.28)
project(FregoMunchkin VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(FREGO_BUILD_TESTS "Build unit tests" ON)
option(FREGO_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(FREGO_WERROR "Treat warnings as errors" OFF)
set(FREGO_CHANNEL "test" CACHE STRING "Release channel compiled into every binary: test | stable")
set_property(CACHE FREGO_CHANNEL PROPERTY STRINGS test stable)

if(NOT FREGO_CHANNEL MATCHES "^(test|stable)$")
  message(FATAL_ERROR "FREGO_CHANNEL must be 'test' or 'stable', got '${FREGO_CHANNEL}'")
endif()
# DESIGN §3 / ADR-021: stable builds require API authentication, which doesn't exist yet.
if(FREGO_CHANNEL STREQUAL "stable")
  message(FATAL_ERROR "stable builds require API authentication (DESIGN §8, ADR-021); only 'test' builds are possible today")
endif()

set(FREGO_VERSION_STRING "${PROJECT_VERSION}-${FREGO_CHANNEL}")

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(Warnings)
include(Sanitizers)
include(Dependencies)

find_package(SQLite3 REQUIRED)

# Plugins compiled into fregod. Directory `foo_bar` registers as plugin "foo-bar" and must
# provide frego/plugins/foo_bar.hpp declaring frego::plugins::make_foo_bar().
set(FREGO_PLUGINS heartbeat store_sink network_guard neighbor_scan identity)

add_subdirectory(events)
add_subdirectory(net)
add_subdirectory(platform)
add_subdirectory(core)
add_subdirectory(domain)
add_subdirectory(plugins)
add_subdirectory(apps)

if(FREGO_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
