#include "frego/core/database.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <format>

namespace frego {
namespace {

[[noreturn]] void fail(sqlite3* db, std::string_view what) {
    throw SqliteError(std::format("sqlite {}: {}", what, db ? sqlite3_errmsg(db) : "out of memory"));
}

sqlite3* open_connection(const std::filesystem::path& file, int flags) {
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(file.c_str(), &db, flags | SQLITE_OPEN_NOMUTEX, nullptr) != SQLITE_OK) {
        std::string msg = db ? sqlite3_errmsg(db) : "out of memory";
        sqlite3_close(db);
        throw SqliteError(std::format("cannot open {}: {}", file.string(), msg));
    }
    sqlite3_busy_timeout(db, 5000);
    return db;
}

std::vector<std::filesystem::path> list_backups(const std::filesystem::path& dir) {
    std::vector<std::filesystem::path> out;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        auto name = entry.path().filename().string();
        if (name.starts_with("frego-v") && name.ends_with(".db")) out.push_back(entry.path());
    }
    // Names embed a sortable UTC timestamp, so lexical order is chronological per version;
    // sort by modification time to compare across versions.
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        std::error_code e1, e2;
        return std::filesystem::last_write_time(a, e1) < std::filesystem::last_write_time(b, e2);
    });
    return out;
}

}  // namespace

// --- Stmt -------------------------------------------------------------------------------

Stmt::Stmt(sqlite3* db, std::string_view sql) : db_(db) {
    if (sqlite3_prepare_v2(db, sql.data(), static_cast<int>(sql.size()), &stmt_, nullptr) != SQLITE_OK)
        fail(db, std::format("prepare `{}`", sql.substr(0, 60)));
}

Stmt::~Stmt() { sqlite3_finalize(stmt_); }

Stmt::Stmt(Stmt&& other) noexcept : db_(other.db_), stmt_(other.stmt_) { other.stmt_ = nullptr; }

Stmt& Stmt::bind_int(int idx, std::int64_t value) {
    if (sqlite3_bind_int64(stmt_, idx, value) != SQLITE_OK) fail(db_, "bind");
    return *this;
}

Stmt& Stmt::bind_text(int idx, std::string_view value) {
    if (sqlite3_bind_text(stmt_, idx, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK)
        fail(db_, "bind");
    return *this;
}

Stmt& Stmt::bind_null(int idx) {
    if (sqlite3_bind_null(stmt_, idx) != SQLITE_OK) fail(db_, "bind");
    return *this;
}

Stmt& Stmt::bind_opt(int idx, const std::optional<std::string>& value) {
    return value ? bind_text(idx, *value) : bind_null(idx);
}

Stmt& Stmt::bind_opt(int idx, const std::optional<std::int64_t>& value) {
    return value ? bind_int(idx, *value) : bind_null(idx);
}

bool Stmt::step() {
    int rc = sqlite3_step(stmt_);
    if (rc == SQLITE_ROW) return true;
    if (rc == SQLITE_DONE) return false;
    fail(db_, "step");
}

void Stmt::reset() {
    sqlite3_reset(stmt_);
    sqlite3_clear_bindings(stmt_);
}

bool Stmt::col_null(int col) const { return sqlite3_column_type(stmt_, col) == SQLITE_NULL; }

std::int64_t Stmt::col_int(int col) const { return sqlite3_column_int64(stmt_, col); }

std::string Stmt::col_text(int col) const {
    const auto* p = sqlite3_column_text(stmt_, col);
    return p ? std::string(reinterpret_cast<const char*>(p), static_cast<std::size_t>(sqlite3_column_bytes(stmt_, col)))
             : std::string{};
}

std::optional<std::string> Stmt::col_opt(int col) const {
    if (col_null(col)) return std::nullopt;
    return col_text(col);
}

std::optional<std::int64_t> Stmt::col_opt_int(int col) const {
    if (col_null(col)) return std::nullopt;
    return col_int(col);
}

// --- Connection ---------------------------------------------------------------------------

void Connection::exec(std::string_view sql) {
    std::string owned(sql);  // sqlite3_exec needs a NUL-terminated string
    char* err = nullptr;
    if (sqlite3_exec(db_, owned.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw SqliteError(std::format("sqlite exec: {}", msg));
    }
}

std::int64_t Connection::last_insert_id() const { return sqlite3_last_insert_rowid(db_); }

int Connection::changes() const { return sqlite3_changes(db_); }

// --- Database -----------------------------------------------------------------------------

std::unique_ptr<Database> Database::open(const std::filesystem::path& file, int max_readers) {
    sqlite3* writer = open_connection(file, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    auto db = std::unique_ptr<Database>(new Database(file, writer, max_readers));
    db->writer_.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;");
    return db;
}

Database::Database(std::filesystem::path file, sqlite3* writer, int max_readers)
    : file_(std::move(file)), writer_db_(writer), writer_(writer), max_readers_(max_readers) {}

Database::~Database() {
    for (auto* r : idle_readers_) sqlite3_close(r);
    sqlite3_close(writer_db_);
}

int Database::user_version() {
    std::lock_guard lk(write_mu_);
    auto stmt = writer_.prepare("PRAGMA user_version");
    stmt.step();
    return static_cast<int>(stmt.col_int(0));
}

sqlite3* Database::acquire_reader() {
    std::unique_lock lk(read_mu_);
    read_cv_.wait(lk, [&] { return !idle_readers_.empty() || open_readers_ < max_readers_; });
    if (!idle_readers_.empty()) {
        sqlite3* db = idle_readers_.back();
        idle_readers_.pop_back();
        return db;
    }
    ++open_readers_;
    lk.unlock();
    try {
        return open_connection(file_, SQLITE_OPEN_READONLY);
    } catch (...) {
        std::lock_guard lk2(read_mu_);
        --open_readers_;
        read_cv_.notify_one();
        throw;
    }
}

void Database::release_reader(sqlite3* db) {
    {
        std::lock_guard lk(read_mu_);
        idle_readers_.push_back(db);
    }
    read_cv_.notify_one();
}

Database::Lease::Lease(Database& d) : db(d), conn(d.acquire_reader()) {}

Database::Lease::~Lease() { db.release_reader(conn.raw()); }

std::filesystem::path Database::backup(const std::filesystem::path& dir, int from_version, Logger& log) {
    std::filesystem::create_directories(dir);
    auto stamp = std::format("{:%Y%m%dT%H%M%S}Z",
                             std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
    auto target = dir / std::format("frego-v{}-{}.db", from_version, stamp);

    sqlite3* dest = open_connection(target, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    {
        std::lock_guard lk(write_mu_);
        sqlite3_backup* b = sqlite3_backup_init(dest, "main", writer_db_, "main");
        if (!b) {
            std::string msg = sqlite3_errmsg(dest);
            sqlite3_close(dest);
            throw SqliteError(std::format("backup init {}: {}", target.string(), msg));
        }
        sqlite3_backup_step(b, -1);
        int rc = sqlite3_backup_finish(b);
        sqlite3_close(dest);
        if (rc != SQLITE_OK) throw SqliteError(std::format("backup to {} failed ({})", target.string(), rc));
    }
    log.info("database", "backed up schema v{} to {}", from_version, target.string());

    auto backups = list_backups(dir);
    while (backups.size() > 3) {
        std::error_code ec;
        std::filesystem::remove(backups.front(), ec);
        backups.erase(backups.begin());
    }
    return target;
}

void Database::migrate(std::span<const Migration> migrations, const std::filesystem::path& backup_dir,
                       Logger& log) {
    std::vector<Migration> ordered(migrations.begin(), migrations.end());
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) { return a.version < b.version; });
    const int latest = ordered.empty() ? 0 : ordered.back().version;
    const int current = user_version();

    if (current > latest) {
        auto backups = list_backups(backup_dir);
        throw MigrationError(std::format(
            "database {} has schema v{}, newer than this build understands (v{}); refusing to start. {}",
            file_.string(), current, latest,
            backups.empty() ? std::string("No backup found.")
                            : "Most recent backup: " + backups.back().string()));
    }
    if (current == latest) return;

    std::optional<std::filesystem::path> backup_path;
    if (current > 0) backup_path = backup(backup_dir, current, log);

    for (const auto& m : ordered) {
        if (m.version <= current) continue;
        try {
            write([&](Connection& c) {
                c.exec(m.sql);
                c.exec(std::format("PRAGMA user_version = {}", m.version));
            });
        } catch (const std::exception& e) {
            throw MigrationError(std::format("migration {} ({}) failed: {}{}", m.version, m.name, e.what(),
                                             backup_path ? "; backup: " + backup_path->string() : ""));
        }
        log.info("database", "applied migration {} ({})", m.version, m.name);
    }
}

}  // namespace frego
