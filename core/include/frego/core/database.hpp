#pragma once

// Generic SQLite plumbing (DESIGN §6.1–6.2): one writer connection, a small reader pool,
// WAL, and a migration runner that backs up first. The schema itself lives in `domain`.

#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "frego/core/log.hpp"

struct sqlite3;
struct sqlite3_stmt;

namespace frego {

class SqliteError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class MigrationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Stmt {
public:
    Stmt(sqlite3* db, std::string_view sql);
    ~Stmt();
    Stmt(Stmt&& other) noexcept;
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;
    Stmt& operator=(Stmt&&) = delete;

    // 1-based parameter indexes, as in SQLite.
    Stmt& bind_int(int idx, std::int64_t value);
    Stmt& bind_text(int idx, std::string_view value);
    Stmt& bind_null(int idx);
    Stmt& bind_opt(int idx, const std::optional<std::string>& value);
    Stmt& bind_opt(int idx, const std::optional<std::int64_t>& value);

    bool step();  // true while a row is available
    void reset();

    // 0-based column indexes, as in SQLite.
    bool col_null(int col) const;
    std::int64_t col_int(int col) const;
    std::string col_text(int col) const;
    std::optional<std::string> col_opt(int col) const;
    std::optional<std::int64_t> col_opt_int(int col) const;

private:
    sqlite3* db_;
    sqlite3_stmt* stmt_ = nullptr;
};

class Connection {
public:
    explicit Connection(sqlite3* db) : db_(db) {}
    void exec(std::string_view sql);
    Stmt prepare(std::string_view sql) { return Stmt(db_, sql); }
    std::int64_t last_insert_id() const;
    int changes() const;
    sqlite3* raw() const { return db_; }

private:
    sqlite3* db_;
};

struct Migration {
    int version;
    std::string_view name;
    std::string_view sql;
};

class Database {
public:
    static std::unique_ptr<Database> open(const std::filesystem::path& file, int max_readers = 4);
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    int user_version();
    const std::filesystem::path& file() const { return file_; }

    // Applies pending migrations in version order, each in its own transaction. Backs up
    // first (keeping the last 3) unless the database is new. Refuses a schema newer than
    // the newest migration this build knows. Throws MigrationError.
    void migrate(std::span<const Migration> migrations, const std::filesystem::path& backup_dir,
                 Logger& log);

    // BEGIN IMMEDIATE … COMMIT around f(Connection&); ROLLBACK if f throws.
    template <class F>
    decltype(auto) write(F&& f) {
        std::lock_guard lk(write_mu_);
        writer_.exec("BEGIN IMMEDIATE");
        try {
            if constexpr (std::is_void_v<std::invoke_result_t<F, Connection&>>) {
                f(writer_);
                writer_.exec("COMMIT");
            } else {
                auto result = f(writer_);
                writer_.exec("COMMIT");
                return result;
            }
        } catch (...) {
            try {
                writer_.exec("ROLLBACK");
            } catch (...) {
            }
            throw;
        }
    }

    // Runs f(Connection&) on a pooled read-only connection.
    template <class F>
    decltype(auto) read(F&& f) {
        Lease lease(*this);
        return f(lease.conn);
    }

private:
    explicit Database(std::filesystem::path file, sqlite3* writer, int max_readers);

    struct Lease {
        explicit Lease(Database& db);
        ~Lease();
        Database& db;
        Connection conn;
    };
    sqlite3* acquire_reader();
    void release_reader(sqlite3* db);
    std::filesystem::path backup(const std::filesystem::path& dir, int from_version, Logger& log);

    std::filesystem::path file_;
    sqlite3* writer_db_;
    Connection writer_;
    std::mutex write_mu_;

    std::mutex read_mu_;
    std::condition_variable read_cv_;
    std::vector<sqlite3*> idle_readers_;
    int open_readers_ = 0;
    int max_readers_;
};

}  // namespace frego
