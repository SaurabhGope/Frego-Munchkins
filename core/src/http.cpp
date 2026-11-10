#include "frego/core/http.hpp"

#include <httplib.h>

#include <algorithm>
#include <atomic>
#include <bitset>
#include <cctype>
#include <condition_variable>
#include <deque>
#include <format>
#include <mutex>
#include <ranges>
#include <thread>
#include <vector>

#include "frego/events/json.hpp"

namespace frego {
namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

void send_json(httplib::Response& res, int status, const nlohmann::json& body) {
    res.status = status;
    res.set_content(json_out(body), "application/json");
}

}  // namespace

bool host_allowed(std::string_view host_header, int port) {
    const std::string host = lower(host_header);
    for (std::string_view name : {"127.0.0.1", "localhost", "[::1]"})
        if (host == std::format("{}:{}", name, port)) return true;
    return false;
}

bool mutation_allowed(std::string_view method, bool has_client_header, std::string_view origin, int port) {
    if (method == "GET" || method == "HEAD" || method == "OPTIONS") return true;
    if (!has_client_header) return false;
    if (origin.empty()) return true;  // non-browser clients (fregoctl) don't send Origin
    const std::string o = lower(origin);
    return o == std::format("http://127.0.0.1:{}", port) || o == std::format("http://localhost:{}", port);
}

std::string HttpRequest::param(const std::string& name, const std::string& fallback) const {
    auto it = params.find(name);
    return it == params.end() ? fallback : it->second;
}

nlohmann::json HttpRequest::json_body() const {
    if (body.empty()) return nlohmann::json::object();
    auto j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded()) throw HttpError(400, "request body is not valid JSON");
    return j;
}

// --- SSE fan-out --------------------------------------------------------------------------

namespace {

struct StreamClient {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<std::string> queue;
    std::bitset<kKindCount> kinds;
    bool closed = false;
};

class SseHub {
public:
    SseHub(std::size_t queue_limit, Metrics& metrics) : limit_(queue_limit), metrics_(metrics) {}

    std::shared_ptr<StreamClient> join(std::bitset<kKindCount> kinds) {
        auto c = std::make_shared<StreamClient>();
        c->kinds = kinds;
        std::lock_guard lk(mu_);
        c->closed = closed_;
        clients_.push_back(c);
        return c;
    }

    void leave(const std::shared_ptr<StreamClient>& c) {
        std::lock_guard lk(mu_);
        std::erase(clients_, c);
    }

    // Runs on the hub's own bus worker, never on the router (DESIGN §4.2).
    void publish(const Event& e) {
        std::vector<std::shared_ptr<StreamClient>> targets;
        {
            std::lock_guard lk(mu_);
            for (auto& c : clients_)
                if (c->kinds.test(static_cast<std::size_t>(e.kind()))) targets.push_back(c);
        }
        if (targets.empty()) return;
        const std::string data = json_out(to_json(e));
        for (auto& c : targets) {
            {
                std::lock_guard lk(c->mu);
                if (c->queue.size() >= limit_) {
                    c->queue.pop_front();
                    metrics_.add("sse.dropped");
                }
                c->queue.push_back(data);
            }
            c->cv.notify_one();
        }
    }

    void close_all() {
        std::lock_guard lk(mu_);
        closed_ = true;
        for (auto& c : clients_) {
            {
                std::lock_guard lk2(c->mu);
                c->closed = true;
            }
            c->cv.notify_all();
        }
    }

private:
    std::size_t limit_;
    Metrics& metrics_;
    std::mutex mu_;
    std::vector<std::shared_ptr<StreamClient>> clients_;
    bool closed_ = false;
};

}  // namespace

// --- ApiServer ----------------------------------------------------------------------------

struct ApiServer::Impl {
    Impl(ApiOptions o, Metrics& m, Logger& l) : options(std::move(o)), metrics(m), log(l), hub(options.stream_queue, m) {}

    ApiOptions options;
    Metrics& metrics;
    Logger& log;
    SseHub hub;
    httplib::Server server;
    std::thread thread;
    int port = 0;
    std::atomic<int> streams{0};
    std::function<nlohmann::json()> status_provider;
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();

    HttpRequest convert(const httplib::Request& req) {
        HttpRequest out{req.method, req.path, {}, req.body};
        for (const auto& [k, v] : req.params) out.params.emplace(k, v);
        for (const auto& [k, v] : req.path_params) out.params[k] = v;
        return out;
    }

    httplib::Server::Handler wrap(std::string owner, std::function<bool()> enabled, HttpHandler handler) {
        return [this, owner = std::move(owner), enabled = std::move(enabled), handler = std::move(handler)](
                   const httplib::Request& req, httplib::Response& res) {
            if (enabled && !enabled()) {
                send_json(res, 503, {{"error", "plugin_disabled"}, {"plugin", owner}});
                return;
            }
            try {
                HttpResponse out = handler(convert(req));
                send_json(res, out.status, out.body);
            } catch (const HttpError& e) {
                nlohmann::json body = {{"error", e.what()}};
                if (e.extra.is_object()) body.update(e.extra);
                send_json(res, e.status, body);
            }
        };
    }

    void stream(const httplib::Request& req, httplib::Response& res) {
        std::bitset<kKindCount> kinds;
        if (auto list = req.get_param_value("kinds"); !list.empty()) {
            for (auto part : std::views::split(list, ',')) {
                std::string_view name(part.begin(), part.end());
                auto kind = kind_from_name(name);
                if (!kind) {
                    send_json(res, 400, {{"error", std::format("unknown event kind '{}'", name)}});
                    return;
                }
                kinds.set(static_cast<std::size_t>(*kind));
            }
        } else {
            kinds.set();
        }
        // Each stream holds a worker for its lifetime; cap them (DESIGN §8, M7).
        if (streams.fetch_add(1) >= options.max_streams) {
            streams.fetch_sub(1);
            res.set_header("Retry-After", "5");
            send_json(res, 503, {{"error", "too_many_streams"}, {"max", options.max_streams}});
            return;
        }
        auto client = hub.join(kinds);
        res.set_header("Cache-Control", "no-cache");
        res.set_chunked_content_provider(
            "text/event-stream",
            [this, client](std::size_t, httplib::DataSink& sink) {
                std::deque<std::string> batch;
                {
                    std::unique_lock lk(client->mu);
                    client->cv.wait_for(lk, options.ping_interval,
                                        [&] { return client->closed || !client->queue.empty(); });
                    if (client->closed) return false;
                    batch.swap(client->queue);
                }
                if (batch.empty()) {
                    static constexpr std::string_view ping = ": ping\n\n";
                    return sink.write(ping.data(), ping.size());
                }
                for (const auto& data : batch) {
                    std::string frame = "data: " + data + "\n\n";
                    if (!sink.write(frame.data(), frame.size())) return false;
                }
                return true;
            },
            [this, client](bool) {
                hub.leave(client);
                streams.fetch_sub(1);
            });
    }
};

namespace {

class OwnedRoutes final : public HttpRoutes {
public:
    using Wrap = std::function<httplib::Server::Handler(HttpHandler)>;
    OwnedRoutes(httplib::Server& server, Wrap wrap) : server_(server), wrap_(std::move(wrap)) {}
    void get(const std::string& p, HttpHandler h) override { server_.Get(p, wrap_(std::move(h))); }
    void post(const std::string& p, HttpHandler h) override { server_.Post(p, wrap_(std::move(h))); }
    void patch(const std::string& p, HttpHandler h) override { server_.Patch(p, wrap_(std::move(h))); }

private:
    httplib::Server& server_;
    Wrap wrap_;
};

}  // namespace

ApiServer::ApiServer(ApiOptions options, Bus& bus, Metrics& metrics, Logger& log)
    : impl_(std::make_unique<Impl>(std::move(options), metrics, log)) {
    auto& im = *impl_;
    std::vector<EventKind> all;
    for (std::size_t i = 0; i < kKindCount; ++i) all.push_back(static_cast<EventKind>(i));
    bus.subscribe({"sse-hub", all, [&im](const Event& e) { im.hub.publish(e); }, {}, 0});

    auto& svr = im.server;
    const int workers = im.options.workers;
    svr.new_task_queue = [workers] { return new httplib::ThreadPool(static_cast<std::size_t>(workers)); };
    svr.set_default_headers({{"X-Content-Type-Options", "nosniff"},
                             {"Content-Security-Policy", "default-src 'self'"},
                             {"Cache-Control", "no-store"}});

    svr.set_pre_routing_handler([&im](const httplib::Request& req, httplib::Response& res) {
        if (!host_allowed(req.get_header_value("Host"), im.port)) {
            send_json(res, 403, {{"error", "forbidden_host"}});
            return httplib::Server::HandlerResponse::Handled;
        }
        if (!mutation_allowed(req.method, req.has_header("X-Frego-Client"), req.get_header_value("Origin"), im.port)) {
            send_json(res, 403, {{"error", "csrf_check_failed"}});
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
    svr.set_exception_handler([&im](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
        std::string what = "unknown error";
        try {
            if (ep) std::rethrow_exception(ep);
        } catch (const std::exception& e) {
            what = e.what();
        } catch (...) {
        }
        im.log.error("api", "{} {} failed: {}", req.method, req.path, what);
        send_json(res, 500, {{"error", "internal_error"}});
    });

    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("FregoMunchkin " FREGO_VERSION " - test build. The web UI arrives in M1; try `fregoctl status`.\n",
                        "text/plain");
    });
    svr.Get("/api/v1/status", im.wrap("core", {}, [&im](const HttpRequest&) {
        nlohmann::json s = im.status_provider ? im.status_provider() : nlohmann::json::object();
        s["uptime_s"] = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - im.started).count();
        s["streams"] = {{"open", im.streams.load()}, {"max", im.options.max_streams}};
        return HttpResponse{200, s};
    }));
    svr.Get("/api/v1/metrics", im.wrap("core", {}, [&im](const HttpRequest&) {
        return HttpResponse{200, im.metrics.snapshot()};
    }));
    svr.Get("/api/v1/events/stream", [&im](const httplib::Request& req, httplib::Response& res) { im.stream(req, res); });
}

ApiServer::~ApiServer() { stop(); }

std::unique_ptr<HttpRoutes> ApiServer::routes(std::string owner, std::function<bool()> enabled) {
    return std::make_unique<OwnedRoutes>(impl_->server, [this, owner = std::move(owner), enabled = std::move(enabled)](HttpHandler h) {
        return impl_->wrap(owner, enabled, std::move(h));
    });
}

void ApiServer::set_status_provider(std::function<nlohmann::json()> provider) {
    impl_->status_provider = std::move(provider);
}

void ApiServer::start() {
    auto& im = *impl_;
    if (im.options.port == 0) {
        im.port = im.server.bind_to_any_port(im.options.listen);
        if (im.port <= 0) throw std::runtime_error(std::format("cannot bind {}", im.options.listen));
    } else {
        im.port = im.options.port;
        if (!im.server.bind_to_port(im.options.listen, im.port))
            throw std::runtime_error(std::format("cannot bind {}:{} (is fregod already running?)", im.options.listen, im.port));
    }
    im.thread = std::thread([&im] { im.server.listen_after_bind(); });
}

void ApiServer::stop() {
    auto& im = *impl_;
    im.hub.close_all();
    if (im.server.is_running()) im.server.stop();
    if (im.thread.joinable()) im.thread.join();
}

int ApiServer::port() const { return impl_->port; }

}  // namespace frego
