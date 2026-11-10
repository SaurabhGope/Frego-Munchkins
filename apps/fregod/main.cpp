// fregod: the FregoMunchkin daemon. Wires the core engine, the domain store and the
// built-in plugins together, then waits for SIGINT/SIGTERM.
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <print>
#include <string>
#include <string_view>

#include "frego/core/bus.hpp"
#include "frego/core/config.hpp"
#include "frego/core/database.hpp"
#include "frego/core/host.hpp"
#include "frego/core/http.hpp"
#include "frego/core/scheduler.hpp"
#include "frego/domain/migrations.hpp"
#include "frego/domain/store.hpp"
#include "frego/platform/paths.hpp"

namespace frego {
void register_builtin_plugins(PluginRegistry& registry);
}

namespace {

constexpr std::string_view kUsage = R"(usage: fregod [options]

  --config PATH      config file (default: <data dir>/config.json if it exists)
  --data-dir PATH    data directory (default: ~/Library/Application Support/FregoMunchkin)
  --port N           API port (default 8737)
  --log-level LEVEL  trace | debug | info | warn | error
  --allow-root       run even as root (not recommended)
  --version          print the version and exit
)";

struct Options {
    std::optional<std::filesystem::path> config;
    std::optional<std::filesystem::path> data_dir;
    std::optional<int> port;
    std::optional<std::string> log_level;
    bool allow_root = false;
};

std::optional<Options> parse_args(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        auto value = [&]() -> std::optional<std::string> {
            if (i + 1 >= argc) return std::nullopt;
            return std::string(argv[++i]);
        };
        if (a == "--config") {
            auto v = value();
            if (!v) return std::nullopt;
            o.config = *v;
        } else if (a == "--data-dir") {
            auto v = value();
            if (!v) return std::nullopt;
            o.data_dir = *v;
        } else if (a == "--port") {
            auto v = value();
            if (!v) return std::nullopt;
            o.port = std::atoi(v->c_str());
        } else if (a == "--log-level") {
            o.log_level = value();
            if (!o.log_level) return std::nullopt;
        } else if (a == "--allow-root") {
            o.allow_root = true;
        } else if (a == "--version") {
            std::println("fregod {}", FREGO_VERSION);
            std::exit(0);
        } else {
            return std::nullopt;
        }
    }
    return o;
}

bool is_loopback(std::string_view addr) {
    return addr == "127.0.0.1" || addr == "localhost" || addr == "::1" || addr.starts_with("127.");
}

}  // namespace

int main(int argc, char** argv) {
    using namespace frego;

    auto opts = parse_args(argc, argv);
    if (!opts) {
        std::fputs(kUsage.data(), stderr);
        return 2;
    }
    if (::geteuid() == 0 && !opts->allow_root) {
        std::println(stderr, "fregod refuses to run as root; only frego-capture needs root (use --allow-root to override)");
        return 2;
    }
    ::umask(077);  // database, logs and backups are readable by this user only (DESIGN §13)

    // Signals are handled by sigwait on the main thread; block them before any thread starts.
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &signals, nullptr);
    ::signal(SIGPIPE, SIG_IGN);

    // --- configuration ---
    std::filesystem::path data_dir = opts->data_dir.value_or(platform::default_data_dir());
    auto config_path = opts->config.value_or(data_dir / "config.json");
    Config config = Config::from_json({});
    if (std::filesystem::exists(config_path)) {
        auto loaded = Config::load_file(config_path);
        if (!loaded) {
            std::println(stderr, "fregod: {}", loaded.error());
            return 2;
        }
        config = std::move(*loaded);
        if (!opts->data_dir)
            if (auto dir = config.data_dir()) data_dir = *dir;
    } else if (opts->config) {
        std::println(stderr, "fregod: config file {} not found", config_path.string());
        return 2;
    }
    if (opts->port) config.patch({{"api", {{"port", *opts->port}}}});
    if (opts->log_level) config.patch({{"log_level", *opts->log_level}});

    // Test builds have no API authentication, so the API must stay on loopback (ADR-021).
    if (std::string_view(FREGO_CHANNEL) == "test" && !is_loopback(config.api_listen())) {
        std::println(stderr, "fregod: api.listen must be a loopback address in test builds (got {}); the API has no "
                             "authentication yet", config.api_listen());
        return 2;
    }

    std::error_code ec;
    std::filesystem::create_directories(data_dir, ec);
    if (ec) {
        std::println(stderr, "fregod: cannot create {}: {}", data_dir.string(), ec.message());
        return 2;
    }
    std::filesystem::permissions(data_dir, std::filesystem::perms::owner_all, ec);

    auto level = Logger::parse_level(config.log_level()).value_or(LogLevel::Info);
    Logger log(level);
    log.open_file(data_dir / "fregod.log");
    for (const auto& key : config.unknown_keys()) log.warn("config", "unknown key '{}' ignored", key);

    log.warn("fregod", "FregoMunchkin {} is a TEST build (proof of concept). Don't make it the only DNS server for "
                       "a household. The API is unauthenticated and bound to {}.", FREGO_VERSION, config.api_listen());

    try {
        // --- storage ---
        auto db = Database::open(data_dir / "frego.db");
        db->migrate(domain::migrations(), data_dir / "backups", log);
        domain::SqliteDomainStore store(*db);

        // --- engine ---
        Metrics metrics;
        SystemTimeSource clock;
        ThreadedScheduler scheduler;
        Bus bus(Bus::Mode::Threaded, metrics, log, clock);
        Services services;
        services.provide<domain::DomainStore>(store);

        ApiServer api({config.api_listen(), config.api_port()}, bus, metrics, log);
        PluginHost host({bus, log, metrics, config, clock, scheduler, services, &api, data_dir});

        PluginRegistry registry;
        register_builtin_plugins(registry);
        for (const auto& name : registry.names()) {
            if (config.plugin_enabled(name)) host.add(registry.create(name));
            else log.info("fregod", "plugin {} disabled in config", name);
        }
        if (auto plugins = config.root().find("plugins"); plugins != config.root().end() && plugins->is_object())
            for (const auto& [name, _] : plugins->items())
                if (!registry.contains(name)) log.warn("config", "unknown plugin '{}' ignored", name);

        api.set_status_provider([&] {
            return nlohmann::json{{"name", "FregoMunchkin"},
                                  {"version", FREGO_VERSION},
                                  {"channel", FREGO_CHANNEL},
                                  {"authenticated", false},
                                  {"warning", "API is unauthenticated (test build)"},
                                  {"data_dir", data_dir.string()},
                                  {"gate_open", host.gate_open()},
                                  {"last_heartbeat", store.meta("last_heartbeat").value_or("")},
                                  {"plugins", host.status()}};
        });

        // Shutdown order (DESIGN §4.2): API first (closes streams), then sources, then drain
        // the bus, then stop plugins so sinks flush last. Runs on every exit path, so a
        // failed start never leaves threads pointing at destroyed objects.
        struct Shutdown {
            ApiServer& api;
            PluginHost& host;
            Bus& bus;
            ~Shutdown() {
                api.stop();
                host.stop_jobs();
                bus.stop(std::chrono::seconds(2));
                host.stop_all();
            }
        } shutdown{api, host, bus};

        bus.start();
        host.start_all();
        api.start();
        log.info("fregod", "listening on http://{}:{} (data: {})", config.api_listen(), api.port(), data_dir.string());

        int sig = 0;
        sigwait(&signals, &sig);
        log.info("fregod", "received {}; shutting down", sig == SIGINT ? "SIGINT" : "SIGTERM");
    } catch (const std::exception& e) {
        log.error("fregod", "fatal: {}", e.what());
        return 1;
    }
    log.info("fregod", "bye");
    return 0;
}
