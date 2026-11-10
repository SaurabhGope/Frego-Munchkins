#pragma once

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <format>
#include <mutex>
#include <optional>
#include <string_view>

namespace frego {

enum class LogLevel { Trace, Debug, Info, Warn, Error };

// Small lock-protected logger: stderr plus an optional rotating file (DESIGN §4.6).
class Logger {
public:
    explicit Logger(LogLevel min = LogLevel::Info, bool to_stderr = true);
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void set_level(LogLevel level) { min_.store(level); }
    bool enabled(LogLevel level) const { return level >= min_.load(); }

    // Appends to `path`; rolls to path.1 … path.<keep> once it exceeds max_bytes.
    bool open_file(const std::filesystem::path& path, std::size_t max_bytes = 5u << 20, int keep = 5);
    void write(LogLevel level, std::string_view component, std::string_view message);

    template <class... A>
    void trace(std::string_view c, std::format_string<A...> f, A&&... a) { log(LogLevel::Trace, c, f, std::forward<A>(a)...); }
    template <class... A>
    void debug(std::string_view c, std::format_string<A...> f, A&&... a) { log(LogLevel::Debug, c, f, std::forward<A>(a)...); }
    template <class... A>
    void info(std::string_view c, std::format_string<A...> f, A&&... a) { log(LogLevel::Info, c, f, std::forward<A>(a)...); }
    template <class... A>
    void warn(std::string_view c, std::format_string<A...> f, A&&... a) { log(LogLevel::Warn, c, f, std::forward<A>(a)...); }
    template <class... A>
    void error(std::string_view c, std::format_string<A...> f, A&&... a) { log(LogLevel::Error, c, f, std::forward<A>(a)...); }

    static std::optional<LogLevel> parse_level(std::string_view name);

private:
    template <class... A>
    void log(LogLevel level, std::string_view c, std::format_string<A...> f, A&&... a) {
        if (enabled(level)) write(level, c, std::format(f, std::forward<A>(a)...));
    }
    void rotate_locked();

    std::atomic<LogLevel> min_;
    bool to_stderr_;
    std::mutex mu_;
    std::FILE* file_ = nullptr;
    std::filesystem::path path_;
    std::size_t max_bytes_ = 0;
    std::size_t written_ = 0;
    int keep_ = 0;
};

}  // namespace frego
