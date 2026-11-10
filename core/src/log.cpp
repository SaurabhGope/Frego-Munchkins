#include "frego/core/log.hpp"

#include <chrono>

namespace frego {
namespace {

std::string_view level_name(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warn: return "WARN";
        case LogLevel::Error: return "ERROR";
    }
    return "INFO";
}

}  // namespace

Logger::Logger(LogLevel min, bool to_stderr) : min_(min), to_stderr_(to_stderr) {}

Logger::~Logger() {
    if (file_) std::fclose(file_);
}

bool Logger::open_file(const std::filesystem::path& path, std::size_t max_bytes, int keep) {
    std::lock_guard lk(mu_);
    if (file_) std::fclose(file_);
    file_ = std::fopen(path.c_str(), "a");
    path_ = path;
    max_bytes_ = max_bytes;
    keep_ = keep;
    std::error_code ec;
    written_ = file_ ? static_cast<std::size_t>(std::filesystem::file_size(path, ec)) : 0;
    return file_ != nullptr;
}

void Logger::rotate_locked() {
    std::fclose(file_);
    std::error_code ec;
    for (int i = keep_ - 1; i >= 1; --i) {
        auto from = path_.string() + "." + std::to_string(i);
        auto to = path_.string() + "." + std::to_string(i + 1);
        std::filesystem::rename(from, to, ec);
    }
    std::filesystem::rename(path_, path_.string() + ".1", ec);
    file_ = std::fopen(path_.c_str(), "a");
    written_ = 0;
}

void Logger::write(LogLevel level, std::string_view component, std::string_view message) {
    auto now = std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
    std::string line = std::format("{:%Y-%m-%dT%H:%M:%S}Z {:<5} {:<14} {}\n", now, level_name(level),
                                   component, message);
    std::lock_guard lk(mu_);
    if (to_stderr_) std::fputs(line.c_str(), stderr);
    if (file_) {
        std::fputs(line.c_str(), file_);
        std::fflush(file_);
        written_ += line.size();
        if (max_bytes_ > 0 && written_ > max_bytes_) rotate_locked();
    }
}

std::optional<LogLevel> Logger::parse_level(std::string_view name) {
    if (name == "trace") return LogLevel::Trace;
    if (name == "debug") return LogLevel::Debug;
    if (name == "info") return LogLevel::Info;
    if (name == "warn") return LogLevel::Warn;
    if (name == "error") return LogLevel::Error;
    return std::nullopt;
}

}  // namespace frego
