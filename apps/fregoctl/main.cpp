// fregoctl: a thin client over fregod's HTTP API (DESIGN §8), so the CLI and the UI can
// never disagree.
#include <httplib.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "frego/events/json.hpp"

namespace {

using nlohmann::json;

constexpr std::string_view kUsage = R"(usage: fregoctl [--port N] <command>

commands:
  status                       daemon, plugins, collection gate
  devices [--json]             devices on the home network
  network [status]             current network and whether it's home
  network approve [--replace]  mark the current network as home
  network decline              mark the current network as not home
  tail [--kinds A,B] [--json]  stream live events

The port defaults to $FREGO_PORT, else 8737.
)";

struct Client {
    httplib::Client http;
    int port;
    Client(int p) : http("127.0.0.1", p), port(p) {
        http.set_connection_timeout(2);
        http.set_read_timeout(10);
    }
};

[[noreturn]] void die(const std::string& msg) {
    std::println(stderr, "fregoctl: {}", msg);
    std::exit(1);
}

json parse_or_die(const httplib::Result& r, int port) {
    if (!r) die(std::format("can't reach fregod on 127.0.0.1:{} ({}). Is it running?", port, httplib::to_string(r.error())));
    auto j = json::parse(r->body, nullptr, false);
    if (j.is_discarded()) die(std::format("unexpected response (HTTP {})", r->status));
    return j;
}

json get(Client& c, const std::string& path) {
    auto j = parse_or_die(c.http.Get(path), c.port);
    if (j.is_object() && j.contains("error")) die(j.value("error", std::string{"error"}));
    return j;
}

std::pair<int, json> post(Client& c, const std::string& path, const json& body) {
    httplib::Headers headers{{"X-Frego-Client", "fregoctl"}};
    auto r = c.http.Post(path, headers, frego::json_out(body), "application/json");
    auto j = parse_or_die(r, c.port);
    return {r->status, j};
}

std::string str(const json& j, const char* key, std::string fallback = "-") {
    auto it = j.find(key);
    if (it == j.end() || it->is_null()) return fallback;
    return it->is_string() ? it->get<std::string>() : frego::json_out(*it);
}

std::string ago(std::int64_t unix_ms) {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto s = std::max<std::int64_t>(0, (now - unix_ms) / 1000);
    if (s < 60) return std::format("{}s ago", s);
    if (s < 3600) return std::format("{}m ago", s / 60);
    if (s < 86400) return std::format("{}h ago", s / 3600);
    return std::format("{}d ago", s / 86400);
}

std::string clock_time(std::int64_t unix_ms) {
    std::time_t t = static_cast<std::time_t>(unix_ms / 1000);
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[16];
    std::strftime(buf, sizeof buf, "%H:%M:%S", &tm);
    return buf;
}

int cmd_status(Client& c) {
    auto s = get(c, "/api/v1/status");
    std::println("{} {} ({} channel)", str(s, "name"), str(s, "version"), str(s, "channel"));
    if (!s.value("authenticated", true)) std::println("warning: {}", str(s, "warning"));
    std::println("uptime      {} s", s.value("uptime_s", 0));
    std::println("data dir    {}", str(s, "data_dir"));
    std::println("gate        {}", s.value("gate_open", false) ? "OPEN (collecting)" : "closed (not collecting)");
    if (auto hb = json::parse(str(s, "last_heartbeat", ""), nullptr, false); hb.is_object())
        std::println("heartbeat   #{} {}", hb.value("seq", 0), ago(hb.value("observed_at", std::int64_t{0})));

    auto n = parse_or_die(c.http.Get("/api/v1/network"), c.port);
    if (!n.contains("error"))
        std::println("network     {} on {}: {} (LAN access: {})", str(n, "status"), str(n, "iface"), str(n, "reason"),
                     str(n, "lan_access"));

    std::println("\n{:<15} {:<12} {:<8} {}", "PLUGIN", "STATE", "FAILURES", "DESCRIPTION");
    for (const auto& p : s.value("plugins", json::array()))
        std::println("{:<15} {:<12} {:<8} {}", str(p, "name"), str(p, "state"), p.value("failures", 0),
                     str(p, "description"));
    return 0;
}

int cmd_devices(Client& c, bool as_json) {
    auto d = get(c, "/api/v1/devices");
    if (as_json) {
        std::println("{}", frego::json_out(d));
        return 0;
    }
    std::println("{:<16} {:<18} {:<28} {:<9} {:<30} {}", "IP", "MAC", "VENDOR", "IDENTITY", "FLAGS", "LAST SEEN");
    for (const auto& dev : d.value("devices", json::array())) {
        std::vector<std::string> flags;
        if (dev.value("is_self", false)) flags.push_back("this-mac");
        if (dev.value("randomized", false)) flags.push_back("private-mac");
        if (dev.value("identity", std::string{}) == "weak") flags.push_back("behind-shared-mac");
        std::string joined;
        for (const auto& f : flags) joined += (joined.empty() ? "" : ",") + f;
        auto vendor = str(dev, "vendor");
        if (vendor.size() > 27) vendor = vendor.substr(0, 26) + "~";
        std::println("{:<16} {:<18} {:<28} {:<9} {:<30} {}", str(dev, "ip"), str(dev, "mac"), vendor,
                     str(dev, "identity"), joined.empty() ? "-" : joined, ago(dev.value("last_seen", std::int64_t{0})));
    }
    std::println("\n{} device(s)", d.value("count", 0));
    return 0;
}

int cmd_network(Client& c, const std::vector<std::string_view>& args) {
    std::string_view sub = args.empty() ? "status" : args[0];
    if (sub == "status") {
        auto n = get(c, "/api/v1/network");
        std::println("status       {}", str(n, "status"));
        std::println("reason       {}", str(n, "reason"));
        std::println("interface    {}", str(n, "iface"));
        std::println("subnet       {}", str(n, "subnet"));
        std::println("gateway      {} ({})", str(n, "gateway_ip"), str(n, "gateway_mac"));
        std::println("fingerprint  {}", str(n, "fingerprint"));
        std::println("gate         {}", n.value("gate_open", false) ? "open" : "closed");
        std::println("LAN access   {}", str(n, "lan_access"));
        if (n.contains("home") && n["home"].is_object())
            std::println("home         {} (gateway {}, subnet {})", str(n["home"], "fingerprint"),
                         str(n["home"], "gateway_ip"), str(n["home"], "subnet"));
        else
            std::println("home         none yet; run `fregoctl network approve` on your home network");
        return 0;
    }
    if (sub == "approve") {
        bool replace = std::ranges::find(args, std::string_view("--replace")) != args.end();
        auto [status, body] = post(c, "/api/v1/network/approve", {{"replace", replace}});
        if (status == 409 && str(body, "error") == "replace_required") {
            std::println(stderr, "A different home network is already approved ({}). If you replaced your router, run:\n"
                                 "  fregoctl network approve --replace",
                         body.contains("home") ? str(body["home"], "fingerprint") : "?");
            return 1;
        }
        if (status != 200) die(str(body, "error"));
        std::println("{}: {}", str(body, "result"), str(body, "fingerprint"));
        return 0;
    }
    if (sub == "decline") {
        auto [status, body] = post(c, "/api/v1/network/decline", json::object());
        if (status != 200) die(str(body, "error"));
        std::println("declined: {}", str(body, "fingerprint"));
        return 0;
    }
    std::fputs(kUsage.data(), stderr);
    return 2;
}

std::string summarize(const json& e) {
    const auto kind = str(e, "kind");
    const auto& d = e.contains("data") ? e["data"] : json::object();
    if (kind == "Heartbeat") return std::format("#{}", d.value("seq", 0));
    if (kind == "NetworkChanged") return std::format("{}: {}", str(d, "status"), str(d, "reason"));
    if (kind == "CollectionGate") return std::format("{}: {}", d.value("open", false) ? "OPEN" : "closed", str(d, "reason"));
    if (kind == "NeighborSnapshot")
        return std::format("{} neighbour(s) on {} ({})", d.value("entries", json::array()).size(), str(d, "subnet"), str(d, "iface"));
    if (kind == "DeviceIdentified")
        return std::format("{} {} {}{}", str(d, "ip"), str(d, "mac"), str(d, "vendor", ""),
                           d.value("created", false) ? " [new]" : "");
    if (kind == "Alert") return std::format("[{}] {}", str(d, "severity"), str(d, "title"));
    if (kind == "Custom") return str(d, "type");
    return frego::json_out(d);
}

int cmd_tail(Client& c, const std::vector<std::string_view>& args) {
    std::string path = "/api/v1/events/stream";
    bool raw = false;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--kinds" && i + 1 < args.size()) path += "?kinds=" + std::string(args[++i]);
        else if (args[i] == "--json") raw = true;
    }
    c.http.set_read_timeout(60);  // the server pings every 15 s
    std::string buffer;
    int status = 0;
    auto r = c.http.Get(
        path,
        [&](const httplib::Response& res) {
            status = res.status;
            return true;
        },
        [&](const char* data, std::size_t len) {
            if (status != 200) {
                buffer.append(data, len);
                return true;
            }
            buffer.append(data, len);
            std::size_t end;
            while ((end = buffer.find("\n\n")) != std::string::npos) {
                std::string frame = buffer.substr(0, end);
                buffer.erase(0, end + 2);
                if (!frame.starts_with("data: ")) continue;  // ": ping" keep-alives
                auto e = json::parse(frame.substr(6), nullptr, false);
                if (e.is_discarded()) continue;
                if (raw) std::println("{}", frego::json_out(e));
                else
                    std::println("{}  {:<17} {:<14} {}", clock_time(e.value("observed_at", std::int64_t{0})), str(e, "kind"),
                                 str(e, "source"), summarize(e));
                std::fflush(stdout);
            }
            return true;
        });
    if (status != 200 && status != 0) {
        auto j = json::parse(buffer, nullptr, false);
        die(j.is_object() ? str(j, "error") : std::format("HTTP {}", status));
    }
    if (!r) die(std::format("stream ended: {}", httplib::to_string(r.error())));
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string_view> args(argv + 1, argv + argc);
    int port = 8737;
    if (const char* env = std::getenv("FREGO_PORT")) port = std::atoi(env);
    if (args.size() >= 2 && args[0] == "--port") {
        port = std::atoi(std::string(args[1]).c_str());
        args.erase(args.begin(), args.begin() + 2);
    }
    if (args.empty() || args[0] == "help" || args[0] == "--help") {
        std::fputs(kUsage.data(), args.empty() ? stderr : stdout);
        return args.empty() ? 2 : 0;
    }
    if (args[0] == "--version") {
        std::println("fregoctl {}", FREGO_VERSION);
        return 0;
    }

    Client client(port);
    const auto cmd = args[0];
    const std::vector<std::string_view> rest(args.begin() + 1, args.end());
    if (cmd == "status") return cmd_status(client);
    if (cmd == "devices") return cmd_devices(client, std::ranges::find(rest, std::string_view("--json")) != rest.end());
    if (cmd == "network") return cmd_network(client, rest);
    if (cmd == "tail") return cmd_tail(client, rest);
    std::fputs(kUsage.data(), stderr);
    return 2;
}
