#pragma once

#include <filesystem>
#include <format>
#include <random>

namespace frego::test {

// A fresh directory under the system temp dir, removed on destruction.
struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::random_device rd;
        path = std::filesystem::temp_directory_path() / std::format("frego-test-{:08x}{:08x}", rd(), rd());
        std::filesystem::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

}  // namespace frego::test
