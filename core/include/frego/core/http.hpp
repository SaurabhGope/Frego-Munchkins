#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "frego/core/bus.hpp"
#include "frego/core/log.hpp"
#include "frego/core/metrics.hpp"

namespace frego {

struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> params;  // query string + path params (":id")
    std::string body;

    std::string param(const std::string& name, const std::string& fallback = {}) const;
    nlohmann::json json_body() const;  // {} for an empty body; HttpError 400 when invalid
};

struct HttpResponse {
    int status = 200;
    nlohmann::json body = nlohmann::json::object();
};

// Throw from a handler to answer with a specific status and {"error": message}.
struct HttpError : std::runtime_error {
    HttpError(int status_code, const std::string& message, nlohmann::json detail = {})
        : std::runtime_error(message), status(status_code), extra(std::move(detail)) {}
    int status;
    nlohmann::json extra;
};

using HttpHandler = std::function<HttpResponse(const HttpRequest&)>;

// What a plugin gets from ctx.http(): register domain endpoints (DESIGN §8). The host
// applies guards and JSON error handling to every route.
class HttpRoutes {
public:
    virtual ~HttpRoutes() = default;
    virtual void get(const std::string& pattern, HttpHandler handler) = 0;
    virtual void post(const std::string& pattern, HttpHandler handler) = 0;
    virtual void patch(const std::string& pattern, HttpHandler handler) = 0;
};

struct ApiOptions {
    std::string listen = "127.0.0.1";
    int port = 8737;  // 0 = pick a free port (tests)
    int workers = 16;
    int max_streams = 4;
    std::chrono::milliseconds ping_interval = std::chrono::seconds(15);
    std::size_t stream_queue = 1000;
};

// Security guards (DESIGN §8), exposed for tests.
bool host_allowed(std::string_view host_header, int port);
bool mutation_allowed(std::string_view method, bool has_client_header, std::string_view origin, int port);

class ApiServer {
public:
    // Subscribes the SSE hub to the bus, so construct it before bus.start().
    ApiServer(ApiOptions options, Bus& bus, Metrics& metrics, Logger& log);
    ~ApiServer();
    ApiServer(const ApiServer&) = delete;
    ApiServer& operator=(const ApiServer&) = delete;

    // Routes registered through the returned object answer 503 while enabled() is false.
    std::unique_ptr<HttpRoutes> routes(std::string owner, std::function<bool()> enabled);
    void set_status_provider(std::function<nlohmann::json()> provider);

    void start();  // throws std::runtime_error if the address can't be bound
    void stop();   // closes SSE streams first, then the server
    int port() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace frego
