#include <httplib.h>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "frego/core/http.hpp"

using namespace frego;
using namespace std::chrono_literals;

TEST_CASE("Host header guard blocks DNS rebinding", "[http]") {
    CHECK(host_allowed("127.0.0.1:8737", 8737));
    CHECK(host_allowed("localhost:8737", 8737));
    CHECK(host_allowed("LOCALHOST:8737", 8737));
    CHECK(host_allowed("[::1]:8737", 8737));
    CHECK_FALSE(host_allowed("evil.example:8737", 8737));
    CHECK_FALSE(host_allowed("127.0.0.1:9999", 8737));
    CHECK_FALSE(host_allowed("127.0.0.1", 8737));
    CHECK_FALSE(host_allowed("", 8737));
}

TEST_CASE("CSRF guard requires the client header on mutations", "[http]") {
    CHECK(mutation_allowed("GET", false, "", 8737));
    CHECK_FALSE(mutation_allowed("POST", false, "", 8737));
    CHECK(mutation_allowed("POST", true, "", 8737));
    CHECK(mutation_allowed("POST", true, "http://127.0.0.1:8737", 8737));
    CHECK_FALSE(mutation_allowed("POST", true, "https://evil.example", 8737));
}

namespace {

struct Server {
    Metrics metrics;
    Logger log{LogLevel::Error, false};
    SystemTimeSource clock;
    Bus bus{Bus::Mode::Threaded, metrics, log, clock};
    ApiServer api{{"127.0.0.1", 0, 16, 4, 200ms, 1000}, bus, metrics, log};
    std::atomic<bool> enabled{true};
    std::unique_ptr<HttpRoutes> routes = api.routes("demo", [this] { return enabled.load(); });

    Server() {
        routes->get("/api/v1/demo", [](const HttpRequest& r) {
            return HttpResponse{200, {{"ok", true}, {"q", r.param("q")}}};
        });
        routes->post("/api/v1/demo/:id", [](const HttpRequest& r) {
            if (r.param("id") == "bad") throw HttpError(409, "nope", {{"hint", "x"}});
            return HttpResponse{200, {{"id", r.param("id")}, {"body", r.json_body()}}};
        });
        bus.start();
        api.start();
    }
    ~Server() {
        api.stop();
        bus.stop(1s);
    }
    httplib::Client client() const { return httplib::Client("127.0.0.1", api.port()); }
};

}  // namespace

TEST_CASE("API routes, guards and plugin-disabled answers", "[http]") {
    Server s;
    auto c = s.client();

    auto r = c.Get("/api/v1/demo?q=hi");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(nlohmann::json::parse(r->body)["q"] == "hi");
    CHECK(r->get_header_value("X-Content-Type-Options") == "nosniff");

    CHECK(c.Get("/api/v1/status")->status == 200);
    CHECK(c.Get("/api/v1/demo", {{"Host", "evil.example"}})->status == 403);

    CHECK(c.Post("/api/v1/demo/1", "{}", "application/json")->status == 403);  // no X-Frego-Client
    httplib::Headers h{{"X-Frego-Client", "test"}};
    auto ok = c.Post("/api/v1/demo/1", h, R"({"a":1})", "application/json");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(nlohmann::json::parse(ok->body)["body"]["a"] == 1);
    auto conflict = c.Post("/api/v1/demo/bad", h, "{}", "application/json");
    CHECK(conflict->status == 409);
    CHECK(nlohmann::json::parse(conflict->body)["hint"] == "x");
    CHECK(c.Post("/api/v1/demo/1", h, "{not json", "application/json")->status == 400);

    s.enabled = false;
    auto off = c.Get("/api/v1/demo");
    CHECK(off->status == 503);
    CHECK(nlohmann::json::parse(off->body)["error"] == "plugin_disabled");
}

TEST_CASE("a 5th SSE stream gets 503 while the API keeps answering", "[http]") {
    Server s;
    std::atomic<int> open{0};
    std::vector<std::thread> streams;
    for (int i = 0; i < 4; ++i)
        streams.emplace_back([&] {
            auto c = s.client();
            c.Get("/api/v1/events/stream", [&](const httplib::Response& res) {
                if (res.status == 200) ++open;
                return true;
            }, [](const char*, std::size_t) { return true; });
        });
    for (int i = 0; i < 200 && open < 4; ++i) std::this_thread::sleep_for(10ms);
    REQUIRE(open == 4);

    auto c = s.client();
    auto fifth = c.Get("/api/v1/events/stream");
    REQUIRE(fifth);
    CHECK(fifth->status == 503);
    CHECK(fifth->get_header_value("Retry-After") == "5");
    CHECK(c.Get("/api/v1/status")->status == 200);

    s.api.stop();  // closes streams, so the readers return
    for (auto& t : streams) t.join();
}

TEST_CASE("events with invalid UTF-8 stream without breaking the API", "[http]") {
    Server s;
    std::string received;
    std::atomic<bool> done{false};
    std::thread reader([&] {
        auto c = s.client();
        c.Get("/api/v1/events/stream?kinds=Alert", [&](const char* d, std::size_t n) {
            received.append(d, n);
            if (received.find("\n\n") != std::string::npos) done = true;
            return !done.load();
        });
    });
    // Wait until the stream is registered, then publish a hostile device-supplied string.
    for (int i = 0; i < 200 && s.client().Get("/api/v1/status") &&
                    nlohmann::json::parse(s.client().Get("/api/v1/status")->body)["streams"]["open"] == 0;
         ++i)
        std::this_thread::sleep_for(10ms);
    s.bus.publish("t", Alert{"k", "x", Severity::Low, "", std::string("TV\xFF\xFE name"), "r"}, s.clock.now());
    for (int i = 0; i < 200 && !done; ++i) std::this_thread::sleep_for(10ms);
    s.api.stop();
    reader.join();
    REQUIRE(done);
    CHECK(received.starts_with("data: "));
    CHECK(received.find("\"kind\":\"Alert\"") != std::string::npos);
    CHECK(received.find("\xEF\xBF\xBD") != std::string::npos);  // replaced, not thrown
}

TEST_CASE("unknown event kinds are rejected on the stream", "[http]") {
    Server s;
    auto r = s.client().Get("/api/v1/events/stream?kinds=Bogus");
    REQUIRE(r);
    CHECK(r->status == 400);
}
