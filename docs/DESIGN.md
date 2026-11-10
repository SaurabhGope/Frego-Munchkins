# FregoMunchkin — Technical Design

**v1.0** · Owner: Saurabh Gope · Date: 2026-11-10 · Status: **Approved** · Implements: [PRD v0.3](PRD.md)

| Version | Change |
|---|---|
| 0.1 | First draft |
| 0.2 | Resolving the senior-engineer review, one finding at a time (see §17). B1 resolved: event time vs. publish time, injectable clock, pcap ingest as separate investigation sessions. B2 resolved: Mac-hosted POC with test-channel builds, per-device DNS opt-in, hardened forwarder, IPv6 listener + bypass detection. B3 resolved: network fingerprint, collection gate, one approved home network. B4 resolved: opaque device IDs, observations, redirect-based merges (suggest + confirm), shared-MAC question. B5 resolved: sighting cache + enforced bus budget for packet-derived sources. B6 resolved by spike on macOS 26.6.2: plain binaries keep LAN access; an embedded Info.plist triggers the block; startup self-check; repeated multicast queries. M1 resolved: event catalog library + `Custom` escape hatch; domain store and domain API moved out of the core. M2 resolved: mailbox per plugin, critical lane, byte-bounded bulk lanes, non-blocking publish, synchronous test mode. M3 resolved: packet decoding moved into the unprivileged helper. M4 resolved: `dhcp-listen` in M1 (pending spike S-LAN), visibility-based level ladder, Mac capture as a side quest. M5 resolved: device classes, ledger digest, enforced noise budget, per-device learning, baselines table. M6 resolved: actionable-only gold, separate magpie counter, XP only for understanding. M7 resolved: SSE stream cap and pool sizing, one stream per browser, UTF-8 invariant, non-throwing JSON. M8 resolved: no API auth in the POC (accepted risk; loopback-only; required before stable), SSDP fetch rules. M9 resolved: `neighbor-scan` (ARP + NDP + all-nodes ping), dual-stack attribution; spike S-DHCP widened to S-LAN. All 10 minor points resolved. Spike S-LAN done: DHCP and IPv6 discovery verified without root; new real-MAC evidence; ARP-spoofing outcome for shared MACs. |
| 1.0 | **Approved** by the owner after the review round (B1–B6, M1–M9, m1–m10) and spikes B6 + S-LAN. The builder's home extender is confirmed. |
| 1.1 | M0 implemented and verified on the home network; §14 records the scope and seven intentional departures from this doc. |

## 1. Scope

This document describes how FregoMunchkin is built: the code layout, the core shell, the plugin model, the event model, threading, storage, the API, the capture path, protocol parsers, each v1 plugin, the game engine, the UI, and how we test it. It covers milestones M0–M5 from the PRD and marks the seams where v2+ ("something big") plugs in.

**Design summary:** a small C++23 daemon (`fregod`) hosts plugins that talk only through a typed event bus. Pure, I/O-free protocol parsers live in their own library so they can be unit-tested and fuzzed in isolation. A tiny root helper (`frego-capture`) is the only privileged code. A TypeScript web UI renders "Frego's Glen" from a localhost REST + SSE API.

---

## 2. Repository layout and layering

```
Frego-Munchkins/
├── CMakeLists.txt            # top-level; options, FetchContent deps
├── CMakePresets.json         # debug, asan, release, fuzz
├── cmake/                    # Warnings.cmake, Sanitizers.cmake, EmbedFiles.cmake
├── net/                      # libfrego_net: pure protocol parsing, NO I/O, NO deps
│   ├── include/frego/net/    # bytes.hpp mac.hpp ethernet.hpp arp.hpp ip.hpp tcp.hpp udp.hpp
│   │                         # dns.hpp tls.hpp ja4.hpp ssdp.hpp oui.hpp psl.hpp
│   └── src/
├── platform/                 # libfrego_platform: OS-specific I/O
│   ├── include/frego/platform/  # netinfo.hpp arp_table.hpp route.hpp poller.hpp paths.hpp
│   ├── macos/                # sysctl / getifaddrs / routing sockets
│   └── linux/                # netlink / /proc (M5)
├── events/                   # libfrego_events: the event catalog (typed structs + JSON); data only
│   └── include/frego/events/
├── core/                     # libfrego_core: the engine (bus, plugin host, scheduler, config, log,
│   ├── include/frego/core/   #   metrics, HTTP server, SQLite database + migration runner)
│   └── src/
├── domain/                   # libfrego_domain: home-network schema, migrations, queries (DomainStore)
│   ├── include/frego/domain/
│   └── src/
├── plugins/                  # one directory per plugin, each a static lib
│   ├── heartbeat/  store_sink/  neighbor_scan/  mdns/  ssdp/  identity/
│   ├── dns_fwd/  capture_ingest/  trackers/  alerts/  game/
├── apps/
│   ├── fregod/               # daemon main()
│   ├── fregoctl/             # CLI client over the HTTP API
│   └── frego-capture/        # root helper
├── ui/                       # TypeScript + Vite web app ("Frego's Glen")
├── data/                     # trackers.json orgs.json quests.json lore/*.md (+ fetched oui.csv, psl.dat)
├── scripts/fetch-data.sh     # downloads IEEE OUI + Public Suffix List
├── tests/                    # unit/ replay/ fuzz/ fixtures/
└── docs/                     # PRD.md DESIGN.md adr/
```

**Dependency rule (enforced by CMake target links):**

```
net  ←  platform ─────────────────────────┐
(pure)   (OS I/O)                          ▼
events  ←  core  ←  domain  ←────────  plugins  ←  apps
(contract) (engine)  (schema+queries)   (features)  (binaries)
```

- `net` depends on nothing but the standard library. Every byte-parsing function lives here, which makes it fully testable and fuzzable.
- `events` depends only on nlohmann/json. It holds the event catalog: plain structs, `kind_of`, and JSON conversion. No logic, no I/O.
- `core` depends only on `events`, and uses only the envelope (`Event`), `kind_of()` and `to_json()`. It routes, stores generically and serves HTTP, but **never inspects a payload**. It doesn't depend on `net`, `platform` or `domain`. This is what makes "the core knows nothing about networking" true (PRD §6.1; M1).
- `domain` holds everything specific to a home network that is persistent: the SQLite schema, its migrations and its queries.
- Plugins never include each other's headers. They share only the `events` catalog and the `domain` store.

---

## 3. Toolchain and dependencies

| Item | Choice | Notes |
|---|---|---|
| Language | **C++23** | Needed for `std::expected`. Supported by Apple clang 21 (installed) and GCC ≥ 12 (Raspberry Pi OS bookworm). *This raises the PRD's C++20 to C++23. See ADR-001.* |
| Build | CMake ≥ 3.28 + Ninja | Both installed via Homebrew |
| Capture | libpcap | Ships in the macOS SDK; `libpcap-dev` on Linux |
| Storage | SQLite 3 | Ships in the macOS SDK; `libsqlite3-dev` on Linux |
| HTTP server | cpp-httplib (header-only) | FetchContent, pinned tag |
| JSON | nlohmann/json (header-only) | Used for both config and the API |
| Tests | Catch2 v3 | FetchContent |
| Fuzzing | libFuzzer | **Apple clang doesn't ship libFuzzer**, so fuzz builds use Homebrew `llvm` or Linux CI |
| UI | TypeScript + Vite | Node is installed; build output is embedded in `fregod` |

Compiler flags: `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror` in CI. Debug preset uses `-fsanitize=address,undefined`.

**Build channel (B2).** CMake option `FREGO_CHANNEL` (`test` | `stable`, default **`test`**) is compiled into every binary. While FregoMunchkin is a POC, every build is a test build:
- the version reads `0.1.0-test`;
- `fregod` logs a startup banner saying it's a test build that must not be the only DNS server for a household;
- `/api/v1/status` returns `"channel": "test"`, `fregoctl status` prints it, and the UI shows a permanent "Test build · POC" ribbon.

Switching to `stable` is a deliberate later decision, gated on:
- an always-on host (Pi) and the B2 failure modes being re-reviewed;
- **API authentication (M8, §8).** A `stable` build without authentication fails to configure (CMake error).

Data files that aren't in the repo (`oui.csv` from IEEE, `public_suffix_list.dat` from publicsuffix.org) are downloaded by `scripts/fetch-data.sh`. The daemon itself makes **no** outbound requests except DNS forwarding.

---

## 4. Core shell (`libfrego_core`)

### 4.1 Events

Events are plain structs collected in a `std::variant`. A variant (rather than a class hierarchy) gives exhaustive `std::visit`, value semantics, no heap allocation per event, and cheap copies across threads.

**Ownership (M1).** The structs below live in **`libfrego_events`**, the *event catalog*: a versioned, data-only contract shared by everyone. The core engine treats a payload as opaque. It routes by `kind_of(payload)`, serializes with `to_json`, and never looks inside.

- **Text invariant (M7): every string in a catalog event is valid UTF-8.** Names, hostnames, SNIs, TXT values and SSDP fields arrive as attacker-controlled bytes. The `net` parsers hand them out as raw views; the conversion into an event string goes through `catalog::text(bytes, max_len)`, which replaces invalid sequences with U+FFFD, strips control characters except tab, and truncates at a code-point boundary (default 255 bytes). Events are therefore always safe to serialize and to display.
- **Versioning.** `kCatalogVersion` (semver) is written into every JSON event and replay file.
  - Adding an event type, or an optional field, is a minor bump.
  - Removing or renaming anything is a major bump.
  - `from_json` ignores unknown fields, so newer files still replay on older builds where possible.
- **Escape hatch for plugin-defined events:**
  ```cpp
  struct Custom { std::string type;        // namespaced, e.g. "org.example.wifi_survey"
                  uint16_t schema_version;
                  nlohmann::json data; };  // part of Payload like any other event
  ```
  - Plugins subscribe to specific custom types with `ctx.subscribe_custom("org.example.wifi_survey")`; the host filters by `type`, so a plugin never sees other custom types.
  - The `frego.` namespace is reserved.
  - A custom type that proves useful is promoted into the catalog as a real struct, with a minor version bump.
- **Across a plugin ABI (v2).** Dynamically loaded plugins exchange events as catalog JSON (`to_json`/`from_json`). Only in-process, first-party plugins use the typed structs directly. The variant never crosses a C ABI.

```cpp
// core/include/frego/core/event.hpp
namespace frego {

using Clock = std::chrono::system_clock;
using DeviceId = std::string;               // opaque "dev_<uuidv7>"; never derived from or parsed for MAC/IP (§7.6)

struct NeighborEntry   { std::string ip; uint8_t family; std::string mac; };   // family: 4 | 6
struct NeighborSnapshot{ std::string iface; std::vector<NeighborEntry> entries; NeighborEntry self; };
struct DeviceSeen      { std::string ip; std::optional<std::string> mac; std::string via; };
struct DeviceHint      { DeviceId device; std::string key; std::string value; std::string via; };
                         // key ∈ hostname | vendor | model | service | mdns_name | upnp_server
struct DnsQuery        { DeviceId device; std::string client_ip; std::string qname; uint16_t qtype;
                         uint8_t rcode; std::vector<std::string> answers; std::string via; };
struct FlowRecord      { DeviceId device; uint8_t proto; std::string src, dst; uint16_t sport, dport;
                         uint64_t packets, bytes_out, bytes_in; Clock::time_point start, end; bool final; };
struct TlsHello        { DeviceId device; std::string dst; uint16_t dport; std::string sni;
                         std::vector<std::string> alpn; std::string ja4; };
struct Alert           { std::string key; std::string kind; Severity severity; DeviceId device;
                         std::string title; std::string reason; };
struct GameEvent       { std::string kind; int xp; std::string detail; };   // xp | achievement | level | mood
struct Heartbeat       { uint64_t seq; };
struct NetworkChanged  { std::string fingerprint; std::string iface; std::string subnet;
                         std::string gateway_ip; std::optional<std::string> gateway_mac;
                         NetworkStatus status; std::string reason; };
                         // status ∈ Home | Unknown | Declined | None (offline, VPN, no gateway MAC)
struct CollectionGate  { bool open; std::string reason; };   // generic; the core acts on it (§4.3)

struct DeviceMerged     { DeviceId from, to; std::string reason; };     // reason ∈ user | promoted | shared_mac_single
struct IdentityQuestion { int64_t id; std::string kind; nlohmann::json detail; };  // kind ∈ merge | shared_mac

using Payload = std::variant<Heartbeat, NetworkChanged, CollectionGate, NeighborSnapshot, DeviceSeen, DeviceHint,
                             DeviceMerged, IdentityQuestion, DnsQuery, FlowRecord, TlsHello,
                             Alert, GameEvent>;

using SessionId = uint32_t;
inline constexpr SessionId kLiveSession = 0;   // live network; pcap ingests get their own ids (§6.4)

struct Event {
    static constexpr uint16_t kSchemaVersion = 1;
    uint64_t id;                       // monotonic, assigned by the bus
    Clock::time_point observed_at;     // when it happened: set by the SOURCE (packet time for pcaps)
    Clock::time_point published_at;    // when it entered the bus: set by the BUS; metrics only
    SessionId session = kLiveSession;  // which dataset this belongs to
    std::string_view source;           // plugin name (static storage)
    Payload payload;
};

enum class EventKind : uint8_t { Heartbeat, DeviceSeen, DeviceHint, DnsQuery,
                                 FlowRecord, TlsHello, Alert, GameEvent, Count };
constexpr EventKind kind_of(const Payload& p) { return static_cast<EventKind>(p.index()); }
}
```

**Packets are not events.** At 10k+ packets/s, putting raw packets on the bus would dominate CPU. The capture plugin decodes and aggregates packets in its own thread and publishes only derived events (`FlowRecord`, `TlsHello`, `DnsQuery`, `DeviceSeen`). That keeps the bus at roughly 10–1000 events/s on a home network.

Every event type has `to_json`/`from_json`, used by the API, SSE, and replay files (§12.3).

**Time rules (review finding B1).**
- **Event time** (`observed_at`) is the only time used for storage, analytics, alerts, baselines, the game and the UI. Sources must set it. For pcap data it's the packet timestamp; for live sources it's `ctx.clock().now()` at the moment of observation.
- **Publish time** (`published_at`) is stamped by the bus and used only for the `bus.latency_ms` metric.
- No plugin calls `std::chrono::system_clock::now()` directly. Time comes from the injected `TimeSource` (§4.3), so replay tests can run on a fake clock.

### 4.2 Event bus

**Model: a mailbox per plugin (M2).** The dispatcher never runs plugin code. It only copies each event into the mailbox of every plugin subscribed to its kind. Each plugin drains its own mailbox on its own worker thread.

```
publishers (any thread)        router thread                 per-plugin workers
───────────────────────        ─────────────                 ──────────────────
ctx.publish(e) ──► ingress ──► for each subscriber of kind ──► [mailbox: identity] ──► identity.on_event
                   (2 lanes)     copy e into its mailbox  ──► [mailbox: store-sink] ──► store_sink.on_event
                                                         ──► [mailbox: sse-hub]   ──► SSE fan-out
                                                         ──► ...
```

**Two lanes, everywhere (ingress and every mailbox)**

| Lane | Kinds | Limit | When full |
|---|---|---|---|
| **Critical** | `Alert`, `NetworkChanged`, `CollectionGate`, `DeviceMerged`, `IdentityQuestion` | Unbounded (these are naturally rare; a metric warns above 10k queued) | Never dropped |
| **Bulk** | everything else | **Bytes**, not events: ingress 32 MB, each mailbox 8 MB by default (configurable per plugin), using `approx_size(event)` from the catalog | Dropped and counted |

- **Order:** critical events are dequeued before bulk ones. Within a lane, events stay in publish order. Each plugin therefore sees bulk events in order, and critical events in order, but a critical event can overtake bulk events that were published earlier. The catalog documents this, and analyzers must not assume otherwise.
- **Publishing never blocks**, from any thread, including a plugin worker publishing while handling an event. When a bulk lane is full, the event is dropped and counted.
- **Isolation:** a slow plugin fills only its own mailbox. Its drops are counted against it (`bus.dropped.<plugin>.<kind>`), the UI's plugin health shows them, and every other plugin is unaffected.
- **Fault isolation (§4.3)** still applies: exceptions are caught on the plugin's worker, and repeated failures disable the plugin.
- **Re-entrancy:** a plugin publishing from `on_event` goes through ingress like everyone else. There's no recursive delivery.
- **Timestamps:** the bus assigns `id` and `published_at` only. It never touches `observed_at` or `session`; `publish()` takes them from the caller (the `Context` fills in the plugin's session).
- **Shutdown:** stop sources → drain ingress → drain each mailbox (2 s budget overall; what's left in bulk lanes is counted as dropped; critical lanes are always drained) → `stop()` plugins in reverse order.

**Deterministic mode (tests and replay).** `Bus(Mode::Synchronous)` has no threads. `pump()` routes every queued event and runs each subscriber's handler inline, in subscription order, until everything is quiet. Replay and unit tests use this mode, so results are reproducible. The threaded mode is covered by separate stress tests (slow subscriber isolation, drop accounting, shutdown drain).

**Implementation (v1).** Every queue is a mutex + condition variable + two `std::deque`s with a byte counter. That's simple and plenty fast at home rates. The `Mailbox` interface allows a lock-free MPSC ring later without API changes.

### 4.3 Plugin API

```cpp
// core/include/frego/core/plugin.hpp
namespace frego {

inline constexpr uint32_t kPluginApiVersion = 1;

struct PluginInfo {
    std::string_view name;          // "neighbor-scan"
    std::string_view version;       // "0.1.0"
    std::string_view description;
    bool collects = false;          // touches the network or produces live observations → gated (below)
};

class TimeSource {                  // injected; never call system_clock::now() in plugins
public:
    virtual Clock::time_point now() const = 0;
    virtual ~TimeSource() = default;
};
// Production: SystemTimeSource. Tests and replay: ManualTimeSource { void advance(duration); }.
// Jobs scheduled with every()/after() run off the same TimeSource, so a manual clock drives them too.

class Context {                     // handed to plugins by the host
public:
    // observed_at: when the thing happened (packet time for pcaps). Defaults to clock().now().
    virtual void publish(Payload p, std::optional<Clock::time_point> observed_at = {},
                         SessionId session = kLiveSession) = 0;
    virtual const TimeSource& clock() const = 0;
    virtual HttpRoutes& http() = 0;                    // register domain endpoints (§8); guards applied by the host
    virtual void subscribe_custom(std::string type) = 0;  // receive Custom events of this type only
    virtual Store& store() = 0;                       // read-mostly access (§6)
    virtual Logger& log() = 0;
    virtual const nlohmann::json& config() const = 0; // this plugin's config section
    virtual Scheduler& scheduler() = 0;               // every(), after()
    virtual const std::stop_token& stop_token() const = 0;
    virtual ~Context() = default;
};

class Plugin {
public:
    virtual PluginInfo info() const = 0;
    virtual std::span<const EventKind> subscriptions() const { return {}; }
    virtual void start(Context& ctx) {}               // spawn threads / schedule jobs here
    virtual void on_event(const Event& e, Context& ctx) {}
    virtual void stop() {}                            // must be idempotent
    virtual void on_gate(bool open, Context& ctx) {}  // collecting plugins: open/close sockets here
    virtual ~Plugin() = default;
};
}
```

There are no separate Source, Analyzer and Sink base classes. The roles are conventions: a source publishes from `start()`, an analyzer subscribes and publishes, and a sink subscribes and writes. One interface keeps the host simple, and a plugin can play several roles (e.g. `game`).

**Registration (v1, static).** Each plugin is a static library that exports a factory. CMake generates `apps/fregod/plugins.gen.cpp` from the `FREGO_PLUGINS` list:

```cpp
void register_builtin_plugins(PluginRegistry& r) {
    r.add("heartbeat", [] { return std::make_unique<HeartbeatPlugin>(); });
    r.add("neighbor-scan",  [] { return std::make_unique<NeighborScanPlugin>(); });
    // ...
}
```

The registration list is generated on purpose, instead of using self-registering static objects: linkers drop unreferenced object files from static libraries, so self-registering plugins silently disappear.

**Dynamic loading (v2 path).** The same factory can be exposed as `extern "C" const frego_plugin_v1* frego_plugin_entry()` from a `.dylib`/`.so` loaded with `dlopen`. The C ABI struct carries `api_version` and function pointers that wrap the C++ object, so plugins built with a different compiler stay compatible. Out-of-process plugins over a unix socket (for crash isolation) are the step after that.

**Collection gate (B3).** The core has one generic switch, the *collection gate*, and doesn't know why it opens or closes. The `network-guard` plugin (§7.0) is the only plugin that drives it, by publishing `CollectionGate`. For every plugin whose `PluginInfo::collects` is true:
- **Closed (the default at startup):** `every()` jobs skip their runs; `ctx.publish()` refuses live-session events and counts them (`gate.refused`), so a scan that started at home and finishes after the laptop moved can't leak foreign data; and `on_gate(false)` is called so I/O plugins (`dns-fwd`, live capture) close their sockets.
- **Open:** `on_gate(true)` is called and jobs run again, the first one immediately.
- Investigation sessions (pcap files, §6.4) aren't gated: they don't touch the network.

**Lifecycle and fault isolation.**

```
load config → construct enabled plugins → start() each (in config order)
→ run → SIGINT/SIGTERM → stop sources → drain bus (≤ 2 s) → stop sinks → flush store → exit
```

- Exceptions thrown by `start`/`on_event` are caught by the host and logged. After 5 failures in 60 s the plugin is disabled, and an `Alert{kind="plugin_failed"}` is raised.
- A crash (segfault) inside a plugin can't be caught in-process. That's accepted for v1, where all plugins are first-party; out-of-process plugins solve it later.

### 4.4 Threading model

| Thread | Owner | Work |
|---|---|---|
| main | `fregod` | Signal handling (`sigwait`), lifecycle |
| bus router | core | Copies ingress events into subscriber mailboxes; never runs plugin code |
| plugin workers | core (one per plugin with subscriptions) | Drain the plugin's mailbox and call `on_event` (~12 threads in v1) |
| scheduler | core | Timer wheel for `every()`/`after()` jobs; runs jobs on a small pool (2 threads) |
| store writer | `store_sink` | Batches writes into SQLite transactions |
| HTTP pool | core API | cpp-httplib workers: 16, of which at most 4 may be held by SSE streams (M7) |
| per-source I/O | plugins | `mdns`, `ssdp`, `dns-fwd`, `capture-ingest` each own a `std::jthread` |

All threads use `std::jthread` + `std::stop_token`. Blocking socket loops use `poll()` with a 250 ms timeout so they notice stop requests promptly.

### 4.5 Config

The config file is `<data_dir>/config.json`. JSON is used to avoid a third dependency (ADR-004). Unknown keys are warnings, not errors.

```json
{
  "data_dir": "~/Library/Application Support/FregoMunchkin",
  "api": { "listen": "127.0.0.1", "port": 8737 },
  "plugins": {
    "heartbeat":      { "enabled": false, "interval_s": 5 },
    "neighbor-scan":       { "enabled": true, "interval_s": 300, "interface": "auto" },
    "mdns":           { "enabled": true, "interval_s": 900 },
    "ssdp":           { "enabled": true, "interval_s": 900 },
    "dns-fwd":        { "enabled": false, "listen": "0.0.0.0", "port": 53, "upstream": "gateway" },
    "capture-ingest": { "enabled": false, "socket": "capture.sock" },
    "alerts":         { "learning_hours": 24, "night": ["00:00", "05:00"] }
  }
}
```

Data directory: `~/Library/Application Support/FregoMunchkin` on macOS and `$XDG_DATA_HOME/fregomunchkin` on Linux; `$FREGO_HOME` overrides both.

### 4.6 Logging and metrics

- A small in-house logger: levels (trace…error), a structured `key=value` tail, and output to stderr plus a rotating file (`fregod.log`, 5 × 5 MB). It's lock-protected, which is fine at our rates.
- Metrics registry: atomic counters and gauges, named `plugin.event` (e.g. `bus.queue_depth`, `capture.pps`, `bus.dropped.FlowRecord`), served as JSON at `/api/v1/metrics`.

### 4.7 Error handling convention

- `net` and `platform` code returns `std::expected<T, Error>` and never throws. Parsers run on untrusted bytes in hot loops.
- Plugin and core code may throw for programmer or configuration errors; the host catches them (§4.3).
- `Error` is `{ ErrorCode code; std::string_view what; }`, with no allocation on the hot path.

---

## 5. Protocol library (`libfrego_net`)

### 5.1 Safe byte reading

Every parser is built on one bounds-checked cursor. Out-of-range reads never touch memory; they latch a failure flag that the parser checks once at the end of a structure, which keeps parser code readable.

```cpp
class ByteReader {
public:
    explicit ByteReader(std::span<const std::byte> buf);
    uint8_t  u8();              // returns 0 and sets failed() if out of range
    uint16_t u16be();
    uint32_t u32be();
    std::span<const std::byte> bytes(size_t n);   // empty span + failed() if short
    ByteReader sub(size_t n);   // child reader over the next n bytes (for length-prefixed fields)
    void skip(size_t n);
    size_t remaining() const;  size_t offset() const;  bool failed() const;
};
```

Parsed results hold **views** (`std::span`, `std::string_view`) into the packet buffer, so nothing is copied while parsing. The rule: views never outlive the packet buffer. Anything published on the bus is copied into owning `std::string`s first.

### 5.2 Parsers (all in `net`, all fuzzed)

| Module | Parses | Key details |
|---|---|---|
| `ethernet` | Ethernet II, 802.1Q VLAN (stacked) | Also BSD loopback (DLT_NULL) and raw IP link types |
| `arp` | ARP request/reply | Sender IP/MAC feed `DeviceSeen` |
| `ip` | IPv4, IPv6 | IPv4 IHL/options and fragments (L4 parsed only for offset 0); IPv6 extension header chain (0, 43, 44, 60), capped at 8 |
| `tcp` / `udp` | Headers, ports, flags, seq, payload | TCP data offset validated |
| `dns` | Full message: header, questions, RRs | Name compression with loop guard (≤ 64 jumps, ≤ 255 bytes); A, AAAA, CNAME, PTR, TXT, SRV, HTTPS decoded; builder for queries |
| `tls` | TLS record + ClientHello | Cipher suites, extensions, SNI, ALPN, supported_versions, signature_algorithms, GREASE detection |
| `ja4` | JA4 fingerprint from a ClientHello | See §5.3 |
| `ssdp` | HTTP-over-UDP headers | `SERVER`, `ST`, `USN`, `LOCATION`; minimal XML tag extractor for `friendlyName`, `manufacturer`, `modelName` (size-capped at 64 KB) |
| `mac` | Text ↔ bytes, U/L and I/G bits | `is_randomized()` = locally administered bit (`0x02`) |
| `oui` | IEEE CSV → `flat_map<uint32_t, string>` | Loaded once (~35k entries) |
| `psl` | Public Suffix List | `registrable_domain("a.b.example.co.uk") → "example.co.uk"` |

### 5.3 JA4 (TLS client fingerprint)

We implement JA4 (the client fingerprint is BSD-3 licensed; the rest of the JA4+ suite has a different licence and is out of scope). Format: `JA4 = a_b_c`.

- **a** = `t` (TCP; `q` for QUIC, M3.5) + version (highest non-GREASE `supported_versions`, else the hello's version: `13`/`12`/`11`/`10`) + `d` if SNI is present, else `i` + 2-digit cipher count (non-GREASE, max 99) + 2-digit extension count (non-GREASE, max 99) + first and last character of the first ALPN value (`00` if none; hex fallback if a character is non-alphanumeric).
- **b** = first 12 hex characters of SHA-256 over the sorted, comma-joined 4-hex cipher list (non-GREASE).
- **c** = first 12 hex characters of SHA-256 over the sorted extension list, excluding GREASE, SNI (`0000`) and ALPN (`0010`), then `_` and the signature algorithms in original order.

SHA-256 is a small self-contained implementation in `net` (no OpenSSL dependency), tested against the NIST vectors. **Test fixtures are our own captures (minor review point).** We don't copy third-party pcaps into the repo, which avoids licence questions about files whose terms we haven't checked. Instead, `tests/fixtures/tls/` holds ClientHellos captured on the builder's Mac against a local TLS server (`openssl s_server` on 127.0.0.1): `curl`, Safari, Chrome and Firefox, including a post-quantum two-segment hello (§5.4). Expected JA4 strings are generated **once** with the upstream reference implementation (the JA4 client fingerprint is BSD-3 licensed; we run the tool, we don't vendor it) and committed next to each fixture with the tool version recorded. If upstream vectors are ever wanted, their licence gets checked and noted in `tests/fixtures/LICENSES.md` first.

### 5.4 TLS ClientHello reassembly

ClientHellos with post-quantum key shares (X25519MLKEM768, now the default in Chrome, Firefox and Apple's stacks) are about 1.8 KB, which spans **two** TCP segments. Single-packet parsing would miss most modern hellos. So:

- When a client→server payload begins `16 03 0x` (TLS handshake record) but the record length is longer than the payload, a per-flow `HelloBuffer` (cap 16 KB) is opened, with `next_seq`.
- Subsequent segments are appended only if `seq == next_seq`. Out-of-order or retransmitted segments are ignored, which is good enough because hellos are early in a flow and rarely reordered.
- The buffer is parsed when complete, then freed. It's also freed after 3 s or 8 segments.

---

## 6. Storage

### 6.1 Interface

```cpp
// M1: the split between engine and domain.
//  - core/database.hpp: generic SQLite plumbing (connections, WAL, writer thread, reader pool,
//    a migration runner that applies migrations registered by any library in order).
//  - domain/store.hpp: DomainStore below, i.e. the home-network schema and queries.
//    The core never includes it.
class Store {                          // domain/include/frego/domain/store.hpp (DomainStore)
public:
    virtual void write_batch(std::span<const Event> events) = 0;     // used by store_sink only
    virtual std::vector<DeviceRow> devices(const DeviceQuery&) = 0;
    virtual std::optional<DeviceRow> device(std::string_view id) = 0;
    virtual std::vector<DomainStat> top_domains(std::string_view device, Clock::duration window, int limit) = 0;
    virtual std::vector<DnsRow> dns(const DnsQueryFilter&) = 0;
    virtual std::vector<AlertRow> alerts(const AlertFilter&) = 0;
    virtual void set_label(std::string_view device, std::string_view label) = 0;
    virtual void ack_alert(int64_t id) = 0;
    virtual GameState game_state() = 0;
    virtual void save_game_state(const GameState&) = 0;
    virtual ~Store() = default;
};
```

`SqliteDomainStore` (in `domain`, built on `core::Database`) is the v1 implementation. A `DuckDbStore` or `ClickHouseStore` for long-term analytics can be added later behind the same interface.

### 6.2 SQLite setup

- Database file: `<data_dir>/frego.db`, with `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`.
- **One writer connection** owned by the `store_sink` thread. Events are buffered and committed in one transaction every 250 ms or every 1,000 events, whichever comes first.
- **A reader connection pool** (4) for API threads. WAL lets reads proceed during writes.
- Migrations: `PRAGMA user_version` plus ordered SQL files embedded in the binary and applied at startup.
  - **Backup first (minor review point).** Before applying any migration, fregod copies the database with SQLite's online backup API to `backups/frego-v<from>-<timestamp>.db` and keeps the last 3. Each migration runs in its own transaction, so a failure rolls back that step, leaves the database at the previous version, and fregod exits with the backup path in the error.
  - **Forward-only, but downgrade-safe.** A binary that finds a newer `user_version` than it knows refuses to start (no silent damage) and points to the most recent backup made before that upgrade.
- **Crash-loss window (minor review point).** Bulk events are committed every 250 ms, so a crash can lose up to 250 ms of bulk data (DNS rows, flows, sightings). That's accepted: sources re-observe within minutes. **Critical-lane events (M2), i.e. alerts, merges, network changes and identity questions, are committed immediately**, in their own transaction, before `store_sink` acknowledges them. They can't be lost to a crash after being accepted.

### 6.3 Schema (migration 001)

```sql
CREATE TABLE devices (
  id           TEXT PRIMARY KEY,          -- opaque "dev_<uuidv7>" (§7.6); never MAC/IP-derived
  label        TEXT,                      -- user-owned; survives every identifier change
  kind         TEXT NOT NULL DEFAULT 'unknown',  -- phone|tv|speaker|camera|plug|computer|router|unknown
  identity     TEXT NOT NULL,             -- strong (own MAC) | weak (IP behind a shared MAC) | provisional (IP only)
  -- "current best" view, recomputed from device_observations; never the source of truth
  mac TEXT, ip TEXT, vendor TEXT, hostname TEXT, model TEXT,
  randomized   INTEGER NOT NULL DEFAULT 0,
  first_seen   INTEGER NOT NULL, last_seen INTEGER NOT NULL   -- unix ms, event time
);
CREATE TABLE device_observations (         -- every identifier ever seen for a device
  device_id TEXT NOT NULL,
  key   TEXT NOT NULL,                     -- mac | ip | hostname | mdns_name | model | vendor | service | upnp_server
                                           -- | dhcp_chaddr | dhcp_client_id | dhcp_fp | dhcp_vendor_class | eui64_mac
  value TEXT NOT NULL, via TEXT NOT NULL,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (device_id, key, value)
);
CREATE INDEX obs_lookup ON device_observations(key, value);
CREATE TABLE device_redirects (            -- merges: rows are never rewritten, so merges are undoable
  from_id TEXT PRIMARY KEY, to_id TEXT NOT NULL,
  reason TEXT NOT NULL, merged_at INTEGER NOT NULL
);
CREATE TABLE identity_questions (          -- merge suggestions + shared-MAC questions for the user
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL,          -- merge | shared_mac
  subject TEXT NOT NULL UNIQUE,                         -- "merge:<a>|<b>" (sorted) or "shared_mac:<mac>"
  evidence TEXT NOT NULL,                               -- JSON shown to the user
  state TEXT NOT NULL DEFAULT 'open',                   -- open | accepted | rejected
  created INTEGER NOT NULL, answered INTEGER
);
CREATE TABLE shared_macs (
  mac TEXT PRIMARY KEY, ips TEXT NOT NULL,              -- JSON array of IPs seen behind it
  verdict TEXT NOT NULL DEFAULT 'unknown',              -- unknown | extender | single_device
  first_seen INTEGER NOT NULL, decided_at INTEGER
);
CREATE TABLE ip_bindings (                 -- which device held which IP (v4 or v6), when
  ip TEXT NOT NULL, device_id TEXT NOT NULL, valid_from INTEGER NOT NULL, valid_to INTEGER,
  PRIMARY KEY (ip, valid_from)
);
-- Readers resolve every device_id through device_redirects (view `device_canonical`,
-- one hop: chains are collapsed when a merge happens).
CREATE TABLE dns (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, device_id TEXT, client_ip TEXT NOT NULL,
  qname TEXT NOT NULL, domain TEXT NOT NULL,   -- registrable domain (PSL)
  qtype INTEGER NOT NULL, rcode INTEGER NOT NULL, answers TEXT, via TEXT NOT NULL
);
CREATE INDEX dns_device_ts ON dns(device_id, ts);
CREATE INDEX dns_domain    ON dns(device_id, domain);
CREATE TABLE flows (
  id INTEGER PRIMARY KEY, start INTEGER NOT NULL, end INTEGER NOT NULL, device_id TEXT,
  proto INTEGER NOT NULL, src TEXT, sport INTEGER, dst TEXT, dport INTEGER,
  packets INTEGER, bytes_out INTEGER, bytes_in INTEGER, sni TEXT, ja4 TEXT
);
CREATE INDEX flows_device_start ON flows(device_id, start);
CREATE TABLE alerts (
  id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE,   -- dedupe key
  ts INTEGER NOT NULL, updated INTEGER NOT NULL, device_id TEXT,
  kind TEXT NOT NULL, severity INTEGER NOT NULL, title TEXT NOT NULL, reason TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'open'                   -- open|acked|resolved
);
CREATE TABLE game (k TEXT PRIMARY KEY, v TEXT NOT NULL);   -- JSON blobs: xp, level, quests, achievements
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);   -- installed_at, schema info
CREATE TABLE networks (                    -- B3: which network is "home"
  id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE,
  gateway_ip TEXT NOT NULL, gateway_mac TEXT NOT NULL, subnet TEXT NOT NULL, ssid TEXT,
  state TEXT NOT NULL,                    -- home | declined | retired (a former home)
  first_seen INTEGER NOT NULL, approved_at INTEGER
);
CREATE UNIQUE INDEX one_home ON networks(state) WHERE state = 'home';   -- at most one home
-- devices, ip_bindings, dns, flows and alerts carry `network_id INTEGER` = the home network
-- at the time of observation; baselines are keyed by network_id too.
```

**Time columns** (`ts`, `start`, `end`, `first_seen`, `last_seen`) always hold event time (`observed_at`), never publish or insert time.

**Retention (v1):** raw `dns` and `flows` rows are kept for 30 days and rolled up into `dns_daily(device_id, domain, day, count)`. The window is configurable; PRD open question #4 is resolved this way.

**Rollups catch up instead of running on a clock (minor review point).** A laptop is often asleep at "nightly" times. The rollup job therefore runs at startup, after every wake (`NSWorkspaceDidWakeNotification`; on Linux, an hourly check), and once an hour.
- Each run processes **every complete day not yet rolled up**, tracked by `meta.rollup_done_through`, oldest first, one day per transaction.
- It's idempotent: re-running a day replaces its rollup rows.
- Raw rows are deleted only after their day's rollup has committed, so a sleep in the middle never loses data.

### 6.4 Sessions: live network vs. pcap investigations

Ingesting a pcap file creates an **investigation session**, a separate dataset you can browse. It never touches the live network's state.

```sql
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,               -- 0 = live (created by migration 001)
  kind TEXT NOT NULL,                   -- live | pcap
  name TEXT NOT NULL,                   -- e.g. file name
  created INTEGER NOT NULL,             -- wall-clock time of ingest
  first_ts INTEGER, last_ts INTEGER,    -- event-time range covered by the data
  packets INTEGER, status TEXT          -- ingesting | done | failed
);
-- dns, flows and the new session_devices carry `session_id INTEGER NOT NULL DEFAULT 0`.
CREATE TABLE session_devices (          -- devices as seen inside one pcap
  session_id INTEGER NOT NULL, mac TEXT, ip TEXT NOT NULL, vendor TEXT,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (session_id, ip, mac)
);
```

| State | Live session (0) | Investigation session (pcap) |
|---|---|---|
| `dns`, `flows` rows | Yes | Yes, tagged with its `session_id` |
| Device inventory (`devices`, `ip_bindings`) | Yes | No; uses `session_devices` instead |
| Alerts, baselines, game state | Yes | **Never** |
| UI | The Glen | An "Investigations" list; each opens a read-only view of that capture |

**Enforcement:** the bus delivers every event, but analyzers (`identity`, `alerts`, `trackers`, `game`) skip any event whose `session != kLiveSession`. `store_sink` writes investigation events only to session-tagged tables. One shared helper, `is_live(e)`, keeps the check consistent; a replay test covers each analyzer.

---

## 7. Plugins (v1)

### 7.0 `network-guard` (M0): only collect on the approved home network (B3)

**Fingerprint.** Fingerprint = SHA-256 of `gateway_mac | subnet` (first 16 hex characters), plus the gateway IP for display.
- The gateway MAC comes from the ARP entry for the default gateway. The guard sends one UDP nudge to the gateway to make sure that entry exists.
- **SSID is optional.** Since macOS 14, reading the Wi‑Fi name needs Location Services permission, which a CLI daemon rarely has. If available, the SSID is shown for display only and never used for matching.
- **No usable fingerprint** (offline, a full-tunnel VPN as default route, a point-to-point interface, or no gateway MAC after the nudge) → status `None` with a reason, e.g. "default route goes through VPN utun3", and the gate stays closed.

**Detection.** Re-evaluated on startup, on every routing-socket change notification (`RTM_ADD`/`RTM_DELETE`/`RTM_IFINFO`; netlink on Linux), and every 30 s as a fallback. Leaving home closes the gate within about 1 s of the route change.

**State machine**

| Fingerprint matches | Status | Gate |
|---|---|---|
| The `home` row | Home | **open** |
| A `declined` row | Declined | closed, no prompt |
| A `retired` row or nothing | Unknown | closed, and the UI and CLI ask "Is this your home network?" |
| No fingerprint | None | closed |

**Approval rules (one home only)**
- `fregoctl network approve` or the UI's "Yes, this is home" sets the current network as `home`.
- If a different home already exists, the user must confirm a replacement ("Your home network looks different: new router? Replace home?"). The old row becomes `retired`. Its data is kept, tagged with its `network_id`, and the new home starts fresh baselines.
- "No" marks the network `declined`.
- Nothing is ever collected, stored or forwarded on a network that isn't `home`. Investigation sessions (pcap files) are the only exception, because they never touch the network.

### 7.1 `heartbeat` (M0)
Publishes `Heartbeat{seq}` every `interval_s`. It exists to prove the full path (bus → store → API → SSE → UI) before any networking code exists. It's disabled by default after M0.

### 7.2 `store_sink` (M0)
Subscribes to all persistent kinds. Bulk events are copied into a local buffer (lock, push, unlock) that its writer thread drains into `Store::write_batch` every 250 ms; critical-lane events are written immediately in their own transaction (§6.2). Upserts merge device fields: non-empty new values win, hints are unioned, and `last_seen = max`.

### 7.3 `neighbor-scan` (M1): ARP + IPv6 NDP (M9)

```
every interval_s:
  netinfo = platform::default_interface()        // getifaddrs + routing socket: iface, IPv4 addr/mask,
                                                 // IPv6 prefixes (link-local, global, ULA), mac, gateway
  # IPv4: make the kernel ARP every host
  hosts = netinfo.ipv4_subnet().hosts()          // refuse subnets larger than /22 (1022 hosts)
  for h in hosts: sendto(udp_sock, "", h:9)       // "UDP nudge": the kernel must ARP to send → fills the ARP cache
  # IPv6: can't sweep a /64, so ask everyone at once
  ping ff02::1%iface (ICMPv6 echo, unprivileged SOCK_DGRAM)   // all-nodes multicast: every IPv6 host replies
                                                 // → their link-local (and often global) addresses enter the NDP cache
  sleep 2 s
  arp = platform::arp_table(iface)               // macOS: sysctl {CTL_NET, PF_ROUTE, 0, AF_INET,  NET_RT_FLAGS, RTF_LLINFO}
  ndp = platform::ndp_table(iface)               // macOS: sysctl {CTL_NET, PF_ROUTE, 0, AF_INET6, NET_RT_FLAGS, RTF_LLINFO}
  publish NeighborSnapshot{iface, entries = arp ∪ ndp  (each: ip, family, mac), self}
```

- **One snapshot event, not one event per entry.** `identity` needs a whole snapshot to spot a MAC answering for several IPs (B4), and to link a device's IPv4 and IPv6 addresses through its MAC.
- **IPv6 addresses are linked through the MAC.** Phones and laptops rotate *temporary* IPv6 addresses daily (RFC 8981), so `ip_bindings` will see many short-lived v6 addresses per device. That's expected: each one links back to the device through its MAC. A DNS query or flow from any of them is attributed correctly, as long as the binding was seen near the time of the event (§7.6 step 3 falls back to a fresh `ndp_table` lookup).
- **Dual-stack throughout:** `ip_bindings` stores v4 and v6; subnet checks (DNS client allowlist B2, SSDP fetch rules M8, `SightingCache` "inside local subnet" B5) use the interface's IPv4 subnet *and* its IPv6 prefixes; link-local addresses are scoped to the home interface.
- **No root is required: verified by spike S-LAN.** The kernel does the ARPing, and an unprivileged ICMPv6 echo over `SOCK_DGRAM` to `ff02::1%en0` worked from a terminal and as a launchd agent:
  - **4 responders:** the router (`fe80::1`), the Samsung TV, the Mac itself, and one host behind the shared MAC;
  - the NDP table grew from 10 to 12 entries on `en0`, and already held the household's global IPv6 addresses (the ISP hands out a `2401:4900::/32`-range prefix, so the home network is dual-stack).
  - **First-launch caveat:** the *first ever* launchd run of the new binary failed with `EHOSTUNREACH` on 2 of 3 sends and got no replies. Every later run worked (4/4 responders, twice). This looks like macOS evaluating a never-seen executable. `lan_access_probe` therefore retries (§10.1).
- **EUI-64 link-locals leak real MACs (new identity evidence).** Some devices form their IPv6 link-local address from their hardware MAC (modified EUI-64: flip bit 0x02 of the first byte, remove `ff:fe` from the middle). `fe80::828a:bdff:fef1:dbd2` decodes to the TV's real MAC `80:8a:bd:f1:db:d2`. `fe80::86e6:57ff:fedf:6848`, answering at L2 with the shared MAC `22:23:51:01:2a:2b`, decodes to **`84:e6:57:df:68:48`**, a different, globally unique MAC behind the shared one. `neighbor-scan` decodes EUI-64 link-locals into an `eui64_mac` observation (§7.6). Privacy-address schemes (RFC 7217/8981) don't leak this; plenty of IoT stacks still do.
- A raw ARP/NDP sweep via BPF (root, through `frego-capture`) remains an optional M3 improvement for hosts that drop UDP or ignore multicast pings. A raw ARP/NDP sweep via BPF (root, through `frego-capture`) is an optional M3 improvement for hosts that drop UDP or ignore multicast pings.
- **Limits:** the network fingerprint (B3) stays IPv4-based (gateway MAC + IPv4 subnet). IPv6-only home networks are out of scope for the POC. Devices that never answer the all-nodes ping and never talk over IPv6 are still found through ARP.
- Reading both tables through `sysctl` instead of parsing `arp -an`/`ndp -an` output is deliberate: it's faster and more robust, and it teaches how the BSD routing table stores link-layer entries (`rt_msghdr` + `sockaddr_inarp`/`sockaddr_in6` + `sockaddr_dl`).

### 7.4 `mdns` (M1)
- Sends DNS-SD queries to `224.0.0.251:5353` **from an ephemeral port**. Per RFC 6762 §6.7, responders then reply by unicast to that port ("legacy unicast"). This avoids fighting macOS `mDNSResponder` for port 5353.
- **Every multicast query is sent 3 times, 1 s apart, and the answers are combined** (RFC 6762 §5.2 style). The B6 spike showed the same query getting 0 answers on one run and 3 on the next. The same applies to SSDP M-SEARCH (§7.5).
- Round 1 asks for `_services._dns-sd._udp.local PTR` to get service types. Round 2 sends PTR queries per type (batched in up to 10 questions per packet) to get instances, with SRV/TXT/A records in the additional section.
- Hints extracted: `mdns_name` (A-record owner, e.g. `Living-Room.local`), `service` (`_googlecast._tcp`, `_airplay._tcp`, `_hap._tcp`, `_ipp._tcp`…), `model` from TXT keys `md`, `model`, `am`, `ty`, and `hostname` from TXT `fn`.
- **Passive listening is part of M1 (decision).** A second socket binds `0.0.0.0:5353` with `SO_REUSEADDR` + `SO_REUSEPORT` (sharing the port with macOS `mDNSResponder`) and joins `224.0.0.251` on the home interface (and `ff02::fb` for IPv6, M9).
  - It hears devices' own announcements and goodbyes, and other hosts' query responses, so it catches devices that never answer legacy-unicast queries and keeps names fresh at almost no cost.
  - The B6 spike verified that the group join and its responses work from a terminal and as a launchd agent (plain binary).
  - Received packets go through the same parser and size caps as active responses.
  - The listener is gated like every collector (B3).

### 7.5 `ssdp` (M1)
- Sends `M-SEARCH * HTTP/1.1` with `ST: ssdp:all` and `MX: 2` to `239.255.255.250:1900`, then collects responses for 4 s.
- For each unique `LOCATION`, it fetches the device description and extracts `friendlyName`, `manufacturer` and `modelName`. **Fetch rules (M8)**, so a device can't make Frego request arbitrary URLs:
  - the URL's host must be a **literal IP** (no hostnames, so no DNS lookups), **equal to the source IP of the SSDP response**, and inside the home subnet;
  - scheme `http` only;
  - **redirects are disabled**;
  - 2 s timeout and 64 KB cap; at most one fetch per device per hour;
  - URLs that break a rule are skipped and counted (`ssdp.location_rejected`).
- Hints: `upnp_server`, `model`, `hostname`, `vendor`.

### 7.5a `dhcp-listen` (M1): the best identification signal, without root (M4)

When a device joins the network or renews its lease, it **broadcasts** a DHCP DISCOVER/REQUEST to `255.255.255.255:67`. Those broadcasts reach every host on the LAN, including the Mac. They carry the strongest identification signals available from a laptop's vantage point:

| DHCP option | Gives | Used as |
|---|---|---|
| 12 Host Name | e.g. `Saurabhs-iPhone`, `android-5f3a…`, `LGwebOSTV` | `hostname` observation (strong merge evidence) |
| 60 Vendor Class | e.g. `android-dhcp-14`, `MSFT 5.0`, `udhcp 1.36.1` | `dhcp_vendor_class` observation; feeds device kind |
| 55 Parameter Request List | ordered option list, an OS fingerprint | `dhcp_fp` observation (hash of the list); feeds kind/OS |
| 61 Client Identifier | often the real hardware MAC, even when the frame uses a randomized one | supporting merge evidence |
| 50 Requested IP | the IP the device is about to hold | opens an `ip_binding` early |

**How it listens.** A plain UDP socket bound to `0.0.0.0:67` with `SO_REUSEADDR`/`SO_REUSEPORT`, receiving broadcasts. **No root is needed:** macOS allows unprivileged binds below 1024, as verified for port 53 in B6. The plugin parses BOOTP + options with a `net::dhcp` parser (bounds-checked, fuzzed; low volume, so in-process per M3).

**Passive only.** The plugin never sends DHCP, never answers, and never changes leases. It is gated like every collector (B3).

**Spike S-LAN: verified on the builder's Mac (macOS 26.6.2, home Wi‑Fi, 2026-11-10).** Two listeners ran at the same time on `:67` for 5 minutes, one from a terminal and one as a launchd user agent. The builder toggled Wi‑Fi on their iPhone.

| Question | Result |
|---|---|
| 1. Does a non-root `:67` socket hear *other* devices' DHCP broadcasts? | **Yes.** Bound without root. Heard the iPhone's REQUEST → DECLINE → DISCOVER → REQUEST ×2 (5 packets). |
| 2. Same under launchd (Local Network Privacy)? | **Yes**, identical 5 packets. Two `SO_REUSEPORT` listeners both receive every broadcast. |
| 3. Anything else holding `:67`/`:68`? | **No** (nothing listed by `netstat`). Internet Sharing's `bootpd` would hold `:67` if enabled; the plugin reports that as a clear error. |
| 4. IPv6 all-nodes ping? | See §7.3: works from a terminal and as a launchd agent. |

**What an iPhone with a private Wi‑Fi address sends** (one device type; others still to be observed): no hostname (option 12), no vendor class (option 60). It does send:
- parameter list `1,121,3,6,15,108,114,119,162,252`. Options 108 (IPv6-only preferred, RFC 8925) and 114 (captive portal, RFC 8910) mark a recent Apple OS. This is useful for `kind`/OS, but not for a name.
- `chaddr` and client identifier (61) = the private MAC `d6:3f:25:96:09:da`.

So DHCP gives Apple devices an OS fingerprint and a **true MAC**, not a name. Names for them still come from mDNS (§7.4) and from the user. IoT devices, Android and Windows typically do send options 12 and 60; that's to be confirmed as more devices check in.

**DHCP reveals the real MAC behind a MAC-rewriting extender (new identity evidence).** After the iPhone reconnected, the ARP table showed its new address .28 behind the shared MAC `22:23:51:01:2a:2b`, while its own DHCP packets carried `chaddr d6:3f:25:96:09:da`. A DHCP `chaddr`/client-id together with the requested IP (option 50) is therefore the strongest available link between an IP and the device's real hardware address. It feeds `identity` (§7.6).

**The fallback isn't needed for the POC.** Capture-based DHCP (`frego-capture`, `udp port 67 or 68`, root) stays documented in case an access point is found that filters client broadcasts.

**Cadence.** Devices broadcast on joining, waking and renewing, typically every few hours, so identification fills in over a day rather than instantly. The UI says so ("Frego learns names as devices check in").

### 7.6 `identity` (M1): who is a device?

This is the hardest part of discovery. It's an analyzer that consumes `DeviceSeen` and `DeviceHint` and decides which device each observation belongs to.

**Principle (B4): identifiers are evidence, not identity.** A device gets an opaque ID (`dev_<uuidv7>`) once, when it's first created. MACs, IPs, hostnames, mDNS names and models are *observations* attached to it (`device_observations`). They can change, rotate or be shared without the device, its label or its history changing.

**Resolving an observation `(ip, mac?, hints, observed_at)`**

1. **Own MAC.** The MAC isn't shared (or the user said its shared MAC is a single device) → find the device that has observation `mac = <mac>`. Found → that device. Not found → go to step 4.
2. **Shared MAC** (verdict `unknown` or `extender`) → the MAC can't identify the device. Use, in order:
   - the device with an active `ip_binding` for this IP that is behind the same MAC;
   - a device behind the same MAC with a matching `hostname`/`mdns_name` observation;
   - otherwise step 4, with `identity = weak`.
3. **No MAC** (e.g. a DNS query from an IP) → the device holding the IP in `ip_bindings` at `observed_at`; else the platform ARP/NDP table → step 1; else step 4 with `identity = provisional`.
4. **New device** → a new opaque ID is created and `DeviceIdentified` is published. A merge-candidate search runs (below).

**Provisional promotion (automatic).** When a provisional (IP-only) device's IP is later seen with a MAC *at the same time*, it's merged into the MAC's device with `reason = promoted`. This is the only automatic merge. It isn't a guess: it's the same address at the same moment.

**Merge suggestions: the user confirms (decision).** Nothing else merges automatically.
- **Candidates:** a new device with a **randomized MAC**, compared against existing devices that weren't online at the same time (the old device's `last_seen` is before the new one's `first_seen`, give or take 5 minutes).
- **Evidence:**
  - strong: same `mdns_name`, same `hostname` (from mDNS or DHCP option 12), same DHCP client identifier (option 61);
  - supporting: same `model`, same `vendor`/services set, same `dhcp_fp` + `dhcp_vendor_class`.
- **When to ask:** at least one strong match → an `identity_questions` row of kind `merge`. The UI shows "Possibly the same as *Saurabh's iPhone*" with the evidence, plus Merge / Not the same buttons.
- **Merge** writes `device_redirects(from → to, reason = user)`. Existing rows are never rewritten: readers resolve through the redirect, so labels and history appear under the surviving device. **Undo** deletes the redirect. A rejected pair is never suggested again.
- **Alerts:** a new device with a randomized MAC raises `new_device` at **info** severity, since it's probably a rotation, and links to the suggestion if there is one. Devices with globally unique MACs keep medium.

**Shared MACs: ask the user (decision), now with evidence (updated by spike S-LAN).**
- **Detection:** one MAC is seen on two or more IPs in the same ARP/NDP snapshot, or within 5 minutes across sightings.
- **Evidence collected before asking:**
  - `dhcp_chaddr`: a DHCP request for one of those IPs carried a different MAC (§7.5a);
  - `eui64_mac`: an EUI-64 link-local behind the shared MAC decodes to a different MAC (§7.3);
  - `arp_history`: the IP previously answered with its own MAC, e.g. the TV at .3 was `80:8a:bd:f1:db:d2` and later appeared behind the shared MAC.

  Each kind of evidence that a real, different MAC sits behind the shared one is shown with the question. The device behind it is keyed to that real MAC (identity `strong`) rather than tracked as a weak IP-only device.
- **What the builder's network showed:** `22:23:51:01:2a:2b` (a locally administered MAC) answered ARP for six IPs at once: .3 (the TV, earlier seen with its own MAC), .5, .10, .28 (the iPhone, whose DHCP carried `d6:3f:25:96:09:da`), .101 and .102. Meanwhile `d6:3f:25:96:09:da`, flagged as "shared" in the first ARP table (.2/.8/.18), turned out to be **one iPhone holding different IPs over time**. Both cases from the original design were wrong guesses, which is why the user decides.
- **Confirmed by the builder (2026-11-10): the house has a Wi‑Fi extender.** So `22:23:51:01:2a:2b` is the extender in MAC-rewriting repeater mode, and the verdict for it is `extender`. The EUI-64 MAC `84:e6:57:df:68:48`, decoded from the link-local address that answers with the shared MAC, is most likely the extender's own hardware MAC. The network also shows the usual side effects of MAC-rewriting repeaters: the Mac's own IP changed three times in a day (.6 → .26 → .27), and the iPhone declined its previous lease. This exact layout becomes a **replay fixture** (`tests/replay/extender_mac_nat.jsonl`): shared MAC + DHCP `chaddr` mismatch + EUI-64 evidence + verdict `extender` → TV and iPhone keyed to their real MACs, no spoofing alert.
- **The question:** "`22:23:51:01:2a:2b` answers for 6 addresses, and at least 2 of them belong to devices with their own MACs. Do you have a mesh node or Wi‑Fi extender?"
  - **Yes → `extender`:** devices behind it are keyed by their real MAC where evidence exists, else by IP (weak). The UI groups them under "Behind *extender X*".
  - **"It's one device" → `single_device`:** only offered when there's *no* evidence of different real MACs (as with the iPhone). The weak devices are merged (`reason = shared_mac_single`); undoable.
  - **No, I have no extender → `unexplained`:** one MAC answering ARP for other devices' addresses, with no extender in the house, is the signature of **ARP spoofing** (someone intercepting LAN traffic). This raises a **high-severity** alert: *"A device (22:23:51:01:2a:2b) is answering for 6 other devices' addresses. If you don't have a Wi‑Fi extender or mesh node, someone on your network may be intercepting traffic."* The alert links to a lore card on ARP spoofing.
- **Re-checking:** the answer is remembered, but if a shared MAC with verdict `extender` or `single_device` starts answering for the **router's IP**, a high-severity alert is raised anyway. Extenders never need to impersonate the gateway; ARP spoofers do.

**Other rules**
- `ip_bindings` records which device held each IPv4/IPv6 address over time (a binding closes when a different device appears on that IP), so a DNS query at time *t* is attributed to whoever held the IP at *t*.
- **Device kind** (TV, phone, plug…) is a scored guess from vendor + services + model (e.g. `_googlecast` → tv/streamer, `_hap` → smart-home, `_ipp` → printer). The rules live in `data/kinds.json`. A user's choice of kind always wins.
- **Required tests:** rotation → suggestion → merge → undo; IP-only DNS → promotion; shared MAC unknown → weak devices → `single_device` merge; a label survives a rotation + merge; a rejected pair is never re-suggested.

### 7.7 `dns-fwd` (M2)

**Deployment model for the POC (B2).** The forwarder runs on the Mac in test builds. Devices are opted in **one at a time**, by setting that device's DNS server to the Mac by hand (start with the builder's own phone). Pointing the router's DHCP at the Mac for the whole house is possible but unsupported in test builds, because whenever the Mac sleeps or leaves home, every opted-in device loses name resolution. The setup guide covers this explicitly:
- how to opt a device in, and how to undo it (per OS: iOS, Android, macOS, Windows, smart TVs where possible);
- that a sleeping Mac breaks DNS for opted-in devices. While testing, run `caffeinate -s` or keep the Mac on power with sleep disabled;
- `fregoctl dns clients` lists every device currently routed through Frego, so you always know what to undo.

Moving to an always-on box (Pi) is deferred until the POC shows it's needed; the M5 platform layer keeps that path open.

**Listening**
- UDP **and TCP** (clients retry over TCP when the UDP response sets the TC bit), on **IPv4 and IPv6** (`listen: ["0.0.0.0", "::"]`), so a device can be pointed at the Mac over either family.
- **Not an open resolver.** A query is answered only if the client address is inside the home network's IPv4 subnet or IPv6 prefixes (link-local and the global/ULA prefixes on the home interface). Anything else is dropped silently and counted (`dns.refused_foreign`). The forwarder runs only while the Mac is on an approved home network (B3); on any other network it stops listening.

**Forwarding**
- **UDP path:** each client query goes out on a **fresh ephemeral socket** (random source port chosen by the kernel) with a fresh random transaction ID, so an off-path spoofer has to guess about 32 bits instead of 16. A reply is accepted only if it arrives on that socket from the upstream's address and port, and its ID and question section match the query. In-flight queries are capped at 256; past the cap, new queries get SERVFAIL. Sockets close on reply or after a 3 s timeout.
- **TCP path:** one thread per connection (cap 64), forwarding to the upstream over TCP.
- After relaying, both the query and the response are parsed, and a `DnsQuery` event is published with the answers.
- **Loop guard:** refuses to start if the upstream resolves to one of our own addresses. `"upstream": "gateway"` resolves to the default gateway at startup.
- Binding UDP port 53 without root on `0.0.0.0` and `[::]` was **verified** on macOS 26.6.2 (B6 spike), both from Terminal and as a launchd agent. On Linux it needs `CAP_NET_BIND_SERVICE`. The port is configurable.
- Not in scope: caching, DNSSEC validation, DoH/DoT serving (blocking and serving DoH are v2 plugins).

**Bypass detection (IPv6 and DoH).** Devices commonly skip Frego by using the router's IPv6 DNS (handed out via router advertisements) or a hard-coded DoH/DoT resolver. Frego doesn't interfere with either: no rogue router advertisements, no traffic redirection. Instead it makes the gap visible:
- A device becomes **routed** when Frego receives DNS from it, and is shown with a "routed through Frego" badge.
- If a routed device is still seen on the network (ARP/mDNS) but Frego has had no DNS from it for 60 minutes, the device is marked **possibly bypassing**. The UI hint says: "Likely using IPv6 or encrypted DNS: see setup guide §IPv6."
- This is a device status, not an alert, so it doesn't count toward Mischief or the alert-noise budget.
- The setup guide explains the IPv6 bypass and the per-device fixes (point the device's IPv6 DNS at the Mac's address, or turn off IPv6 DNS on the test device). Changing router-wide IPv6 settings is out of scope.

### 7.8 `frego-capture` + `capture-ingest` (M3)

**Privilege separation and parser isolation (M3).** Two rules:
- Only opening the BPF device needs root.
- **Raw packets are parsed only in `frego-capture`, after it has dropped root.** `fregod` holds the household database and serves the API, so it never sees a raw packet.

```
sudo frego-capture -i en0 --to ~/…/capture.sock          (live)
     frego-capture --file x.pcap --session 7 --to …       (pcap file / stdin; no root needed)
  1. live only: pcap_create / snaplen 262144 / immediate mode / pcap_activate   (needs root)
  2. drop privileges: setgid/setuid to SUDO_UID/SUDO_GID (or --user); verify that regaining root fails
  3. confine itself: RLIMIT_AS 512 MB, RLIMIT_NOFILE 16, RLIMIT_CORE 0, no new files
     (a macOS sandbox profile / Linux seccomp filter is planned for v1.1)
  4. connect to fregod's unix socket; decode frames; send finished records
```

The BPF file descriptor stays usable after dropping root. Everything from step 2 onward, including all packet parsing, runs as the user, in a process holding nothing but the capture handle and one socket. A crash or memory-safety bug caused by a crafted packet stays inside that process.

**What runs where**

| `frego-capture` (unprivileged after step 2) | `fregod` |
|---|---|
| libpcap read loop; Ethernet/ARP/IP/TCP/UDP decoding; `FlowTable`; `HelloBuffer` + TLS/JA4; DNS-in-capture parsing; `SightingCache`; the packet-time watermark (§7.8 B1); the 50 events/s budget (B5) | The `capture-ingest` plugin: receives records, validates them, publishes them as catalog events |

**Wire protocol (helper → fregod).** Length-prefixed catalog JSON (M1), all lengths little-endian u32:

```
Hello  : {"hello":{"proto":1,"catalog":"1.x","mode":"live|file","iface":"en0","session":0|n}}
Record : {"kind":"FlowRecord","observed_at":…,"data":{…}}   (any catalog kind the helper is allowed to send)
Stats  : {"stats":{"packets":…,"drops_kernel":…,"ts_regressions":…}}  every 10 s
Bye    : {"bye":{"reason":"eof|signal|error","detail":"…"}}
```

**fregod treats the helper's output as untrusted too.** A compromised helper must not be able to compromise fregod. Parsing small JSON records is a far smaller attack surface than parsing raw packets, but `capture-ingest` still enforces:
- frames ≤ 64 KB;
- only the allowed kinds: `FlowRecord`, `TlsHello`, `DnsQuery`, `DeviceSeen`;
- `from_json` strict on types and string lengths;
- rate ≤ the B5 budget, with a burst allowance;
- the session must be the one assigned for this connection.

Any violation drops the connection and flags the plugin `degraded`.

**Control (fregod → helper):** `{"pause":true}` / `{"pause":false}` mirrors the collection gate (B3). While paused, the helper keeps reading (so the kernel buffer doesn't overflow) but discards frames. The B3 publish gate in fregod remains the real enforcement.

**Crashes.** fregod notices the disconnect and marks capture `degraded` with the reason. Counter `capture.helper_exits{reason}` goes up. A live helper started via `sudo` is restarted by the user, or by its launchd/systemd unit when running as a service.

**Pcap files and stdin** (`fregoctl ingest file.pcap`, `tcpdump -w - | fregoctl ingest -`) go through the same path: `fregoctl` asks fregod for a new investigation session (§6.4), then runs `frego-capture --file … --session <id>` as the user. pcapng is detected and rejected with a clear message in v1. A live capture publishes into the live session.

**Decode pipeline** (all inside `frego-capture`, one thread, no locks):

```
frame → ethernet → (arp → SightingCache → DeviceSeen)
                 → ip → tcp/udp → FlowTable.update()
                                 → udp:53 response  → dns::parse → DnsQuery (via="capture")
                                 → tcp:443 c→s first bytes → HelloBuffer → tls::parse → ja4 → TlsHello
                 → src MAC + src IP inside local subnet → SightingCache → DeviceSeen (via="capture")
→ records → socket → fregod/capture-ingest (validate) → bus
```

**Low-volume parsers stay in fregod.** The DNS forwarder (§7.7), mDNS (§7.4) and SSDP (§7.5) handle much lower volumes and need fregod's sockets. Their parsers run in-process. Mitigations:
- the same `net` parsers, each with a libFuzzer target and ASan/UBSan in CI;
- strict size caps per message;
- SSDP XML capped at 64 KB.

Moving them into a sandboxed decoder process is the documented next step if fuzzing or field data shows they need it.

**Sighting cache (B5).** Seeing a local device in a packet is a per-packet fact, so it must not become a per-packet event. `SightingCache` sits between the decoders and `publish()`:
- Key `(ip, mac)` → last emitted time (packet time, §7.8 watermark).
- Emit `DeviceSeen` only when:
  - the pair is new;
  - the IP shows up with a different MAC (a possible new device, or ARP spoofing on the LAN, both worth knowing immediately);
  - or 60 s of packet time have passed since the last emission for that pair (keeps `last_seen` fresh).
- Bounded at 4,096 pairs, evicting least-recently-seen. An evicted pair is simply re-emitted the next time it's seen, which costs one event.
- The same cache sits in front of ARP-packet sightings.

**Bus budget for packet-derived sources (ADR-003, enforced).** A plugin that decodes packets may publish at most **50 events/s sustained**, whatever the packet rate. Everything else must be aggregated (flows) or de-duplicated (sightings). Enforcement:
- metric `bus.published.<plugin>` with a `capture.events_per_packet` ratio;
- a debug-build warning when the 10 s average exceeds the budget;
- required tests: (a) 100k packets from one host over 5 minutes of packet time → exactly 1 + 5 `DeviceSeen` events; (b) the same IP with a new MAC → an immediate extra event; (c) a 4,097th pair evicts the oldest.

**Flow table:**
- `unordered_map<FlowKey, FlowState>` where `FlowKey` = (proto, client ip:port, server ip:port). The client is the sender of the SYN, or of the first packet if no SYN was seen.
- Flows are emitted as `FlowRecord`:
  - with `final=true` on FIN/RST (+2 s grace) or on idle timeout (TCP 120 s, UDP 60 s);
  - with `final=false` as interim records every 5 min for long flows, so long downloads show up live.
- Capped at 100k entries; past the cap, the oldest-idle flows are evicted (and emitted).
- **All flow timers run on packet time, not wall-clock time** (B1). The table keeps a *watermark*: the newest packet timestamp seen. Idle timeouts, the FIN/RST grace period, interim records and the `HelloBuffer` expiry are all measured against the watermark. A one-hour pcap ingested in two seconds therefore produces exactly the flows it would have produced live.
  - **Live capture:** the watermark is `max(last packet ts, clock().now())`, advanced by a 1 s tick, so flows still expire on a quiet network.
  - **File ingest:** the watermark moves only with packets. At EOF every remaining flow is flushed with `final=true`.
- Packet timestamps going backwards (common in merged captures) don't move the watermark back. Those packets are still counted, and the `capture.ts_regressions` counter goes up.
- Bytes are counted from IP total length (`wire_len`), not captured length.
- QUIC (UDP/443) is recorded as a flow with proto 17 and labelled `quic` in the UI. Decrypting QUIC Initial packets to get the SNI (keys derived from the DCID via HKDF-SHA256 + AES-128-GCM) is planned for M3.5 and would need AES, so it's deferred.

### 7.9 `trackers` (M2)
- `data/trackers.json` maps domain suffixes to `{category: ads|telemetry|analytics, org}`. It's a small curated list in v1 (e.g. `doubleclick.net`, `samsungacr.com`, `device-metrics-us.amazon.com`, `app-measurement.com`).
- `data/orgs.json` maps domain suffixes to "kingdoms" (Google, Apple, Amazon, Meta, Microsoft, Netflix, Samsung, Xiaomi, Tuya, …). The UI uses these for rainbows.
- On each `DnsQuery`, the plugin matches suffixes against a reversed-label trie (O(labels)) and publishes the Magpie alert (§7.10).

### 7.10 `alerts` (M4)

The rules are pure functions over live-session events (§6.4) plus small in-memory state, rebuilt from the Store at startup. **Design goal (M5): an alert is something worth interrupting you for.** Everything merely interesting goes to the ledger instead.

**Device classes** (from `kind`, §7.6; the user can override per device):

| Class | Kinds | Why |
|---|---|---|
| **Predictable** | tv, streamer, speaker, camera, plug, smart-home, printer, router, appliance | A small, stable set of destinations. Something new is genuinely interesting. |
| **People-devices** | phone, tablet, computer, and `unknown` until classified | They follow what people do. Something new is normal. |

Each device has a **"Watch closely"** toggle that treats it as predictable. The UI suggests it for unknown-kind devices that look like IoT.

**Learning periods**
- install: 1 h (for `new_device`);
- `new_domain`: 72 h from the device's first DNS event;
- baseline rules (`night_owl`, `traffic_spike`): ≥ 7 days of history for that device.

Until then, a rule simply doesn't fire for that device, and the UI shows "Frego is still learning *Living Room TV* (day 3 of 7)".

| Rule | Trigger | Applies to | Severity | Dedupe key |
|---|---|---|---|---|
| `new_device` | `identity` creates a device (not a merge or promotion), after the install learning window | all | medium; **info** if the MAC is randomized (probably a rotation, see §7.6) | `new_device:<id>` |
| `new_domain` | First query for a registrable domain after the 72 h learning period | **predictable only** | low | `new_domain:<id>:<domain>` |
| `magpie` | Tracker match | all | info, one daily summary updated in place | `magpie:<id>:<yyyy-mm-dd>` |
| `night_owl` | Night-window DNS count > max(20, the device's own night mean + 4σ over ≥ 7 nights) | all with a baseline | low | `night:<id>:<date>` |
| `traffic_spike` | Hourly bytes > max(10 MB, 5 × p50 of the same hour-of-week over ≥ 7 days). **Only for devices whose traffic Frego can actually see** (M4): in the Mac POC that's the Mac itself | visible devices | medium | `spike:<id>:<yyyy-mm-ddThh>` |
| `nxdomain_burst` | > 30 distinct NXDOMAIN names in 10 min (DGA-like), **excluding single-label names** (browsers probe random single-label names to detect DNS hijacking) | all | high | `nx:<id>:<window>` |
| `plugin_failed` | Host disabled a plugin | — | medium | `plugin:<name>` |

**Frego's ledger (the digest).** Not an alert. A daily, browsable card per device listing new registrable domains (people-devices, and predictable devices still in their learning period), magpies, and anything suppressed by the noise budget. It doesn't count toward Mischief, mood, gold or the alert budget.

```sql
CREATE TABLE ledger (device_id TEXT NOT NULL, day TEXT NOT NULL, kind TEXT NOT NULL,   -- new_domain | suppressed | magpie
                     item TEXT NOT NULL, count INTEGER NOT NULL, first_ts INTEGER NOT NULL,
                     PRIMARY KEY (device_id, day, kind, item));
```

**Noise budget (enforced, not just a target).**
- **Medium and high alerts are never suppressed.**
- Low and info alerts are capped at **3 per device per day**. The rest go to the ledger as `suppressed`, with a single "…and 7 more in the ledger" note on the last alert.
- Metrics `alerts.raised{severity}` and `alerts.suppressed` let us check the PRD target from real data. A replay test over a recorded day of the builder's home network must stay within it.

**Baselines** get their own table (instead of JSON blobs in `meta`):

```sql
CREATE TABLE baselines (device_id TEXT NOT NULL, network_id INTEGER NOT NULL, metric TEXT NOT NULL,  -- dns_count | bytes
                        hour_of_week INTEGER NOT NULL,         -- 0..167
                        mean REAL NOT NULL, m2 REAL NOT NULL,  -- Welford running variance, for σ
                        samples INTEGER NOT NULL,
                        PRIMARY KEY (device_id, network_id, metric, hour_of_week));
```

Every alert gets a templated plain-English `reason`, e.g. *"Living Room TV looked up 63 domains between 00:00 and 05:00; over the last 2 weeks it averaged 4."*

### 7.11 `game` (M4)

The game plugin is an analyzer + sink that turns network facts into game state. **Game logic never sits on the alert path:** alerts are published and stored before the game plugin sees them.

- **Level (capability-based, PRD §7.3; M4).** A level measures how much of the *household* Frego can see. It's computed from which data sources produced events about **other devices** in the last 24 h:
  - neighbor-scan → 1 Hedge Watcher;
  - mdns/ssdp → 2 Mound Keeper;
  - dhcp-listen with ≥ 1 identified device → 3 Name Keeper;
  - dns-fwd with ≥ 1 opted-in, non-self client → 4 Rainbow Seer;
  - gateway or mirror-port capture (v2) → 5 Glen Guardian.
- **Capturing the Mac's own traffic is not a level.** It completes the side quest **"Look in the mirror"** (XP + a lore card on TCP/UDP, flows, TLS, SNI, JA4) and lights up `traffic_spike` for the Mac only. The UI labels capture views "this Mac only".
- **XP (M6): rewards understanding, never dismissing.**
  - +5 per device labelled;
  - +5 per identity question answered (merge or shared MAC);
  - +3 per lore card read through;
  - +100 per quest.

  **Acknowledging or resolving an alert earns nothing**, so there's no incentive to click alerts away. Passive events (a new device appearing, Frego finding a vendor) earn nothing either: XP comes from what *you* did.
- **Gold (0–1000) measures only what you can act on (M6):** `1000 − 150·open_high − 75·open_medium − 10·open_low − 15·open_identity_questions`, clamped to 0.
  - The pot refills as you handle things.
  - It never penalizes what you can't fix: unidentifiable devices, randomized MACs, devices that bypass Frego's DNS. Info alerts and the ledger cost nothing.
  - **Magpies** appear as a separate **"coins carried off today"** counter beside the pot (distinct tracker domains contacted in 24 h, per device on hover). It doesn't drain the pot, because nothing in v1 can stop them. When v2 adds DNS blocking, blocked magpies become "coins saved", and the counter may start counting against the pot.
- **Mood:** calm (no open low+ alerts) → wary (open low) → alarmed (open medium/high).
- **Quests:** declared in `data/quests.json` as conditions over a metrics snapshot, so new quests need no C++:
  ```json
  { "id": "know_thy_folk", "title": "Know Thy Folk", "xp": 100,
    "when": { "metric": "identified_ratio", "op": ">=", "value": 0.9 },
    "lore": "lore/arp.md" }
  ```
  The supported metrics are: `devices_total`, `identified_ratio`, `labelled_ratio`, `magpies_seen`, `dns_clients`, `uptime_hours`, `labelled_randomized`.
- Game changes publish `GameEvent`s, which the SSE stream forwards so the UI can animate them.

---

## 8. API (`fregod`, localhost)

Base path `/api/v1`. All endpoints return JSON. cpp-httplib serves the API and the embedded UI.

**Route ownership (M1).**
- The core serves only the generic endpoints: `/status`, `/metrics`, `/events/stream`, and the UI assets.
- Every domain endpoint (`/devices`, `/dns`, `/alerts`, `/network`, `/identity`, `/game`…) is registered by the plugin that owns that data, through `ctx.http().get/post(path, handler)`. For example, `identity` registers `/devices` and `/identity/*`, and `network-guard` registers `/network*`.
- The host applies the Host/Origin/CSRF guards and JSON error handling to every route, so plugins can't bypass them.
- A route registered by a disabled plugin answers `503 {"error":"plugin_disabled"}`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/status` | Version, uptime, enabled plugins + health, level |
| GET | `/metrics` | Counters/gauges (§4.6) |
| GET | `/devices` | List with kind, names, last_seen, dns_24h, top kingdom |
| GET | `/devices/{id}` | Detail + hints |
| PATCH | `/devices/{id}` | `{label}` |
| GET | `/devices/{id}/domains?window=24h` | Top registrable domains + org + tracker flag |
| GET | `/dns?device=&since=&limit=` | Raw DNS log |
| GET | `/flows?device=&since=&limit=` | Flows |
| GET | `/alerts?state=open` | Mischief list |
| POST | `/alerts/{id}/ack` | Acknowledge |
| GET | `/identity/questions?state=open` | Merge suggestions and shared-MAC questions |
| POST | `/identity/questions/{id}/answer` | `{accept: bool}` (merge) or `{verdict: "extender"\|"single_device"}` |
| POST | `/devices/{id}/unmerge` | Remove the redirect that merged `{id}` into another device |
| GET | `/network` | Current fingerprint, status, reason, gate state, and the home network |
| POST | `/network/approve` | `{replace: bool}` → make the current network home |
| POST | `/network/decline` | Mark the current network declined |
| GET | `/game` | Level, XP, gold, mood, quests, achievements |
| GET | `/events/stream` | **SSE** live feed of `Event` JSON (filter `?kinds=Alert,GameEvent`); at most 4 concurrent streams (M7) |
| GET | `/*` | Embedded UI assets |

**Threading and live streams (M7).** cpp-httplib serves each request on a pool worker, and an SSE stream occupies its worker for as long as it's open. Without limits, a few browser tabs and a `fregoctl tail` would leave no workers for ordinary API calls. So:
- **The pool has 16 workers**, and **SSE may hold at most 4** (atomic counter). A 5th stream gets `503` with `Retry-After: 5`, so 12 or more workers always remain for regular requests.
- **The UI opens one stream per browser, not per tab.** The first tab holds the SSE connection and relays events to other tabs over a `BroadcastChannel`. When it closes, another tab takes over (leader election via the Web Locks API). `fregoctl tail` uses one stream.
- **Streams can't idle forever.** A `: ping` comment every 15 s detects dead clients (write failure frees the worker). Each stream has a per-client queue of at most 1,000 events, dropping the oldest and counting the drops, so a slow reader can't build up memory.
- **Shutdown** closes all streams first, so `stop()` never waits on a 15 s ping.
- Moving SSE onto its own event loop (or WebSockets) is the documented next step if 4 streams become limiting. The `ApiServer` interface hides the choice.

**JSON output can't throw on bad text (M7).** Serialization goes through one helper, `json_out(j)` = `dump(-1, ' ', false, error_handler_t::replace)`. It's used by API responses, SSE, the helper wire protocol, replay files and logs. CI fails if `.dump(` appears anywhere else (a grep check). Required tests:
- an mDNS name containing invalid UTF-8 and control bytes is stored, served by `/devices`, streamed over SSE, and shown in the UI without error;
- a 5th SSE client gets 503 while `/status` still answers.

**Security** (the API exposes your household's browsing metadata, so it's treated seriously):
- It binds to `127.0.0.1`. **In `test` builds, `api.listen` must be a loopback address:** fregod refuses to start otherwise, because the POC has no authentication.
- **No authentication in the POC (M8, accepted risk).** The Host/Origin/CSRF guards stop web pages, but any process on this Mac, under any user account, can read the API: device inventory, DNS history, alerts.
  - Accepted for the POC: it runs on the builder's single-user Mac, on test builds only.
  - `fregoctl status` and the UI's test-build ribbon say "API is unauthenticated (test build)".
  - Authentication is a **hard requirement before a `stable` build** (§3). The planned design: `fregoctl` over a unix socket in the 0700 data dir; the UI behind an HttpOnly, SameSite=Strict session cookie issued through a one-time login link from `fregoctl open`.
- **DNS-rebinding guard:** requests whose `Host` isn't `127.0.0.1:<port>` or `localhost:<port>` are rejected.
- **CSRF guard:** mutating requests need an `X-Frego-Client` header (which browsers can't send cross-origin without a CORS preflight, and we answer no CORS) plus a matching `Origin`.
- Remote access (v2) means a token, TLS, and an explicit opt-in.

`fregoctl` is a thin client over the same API (`status`, `devices`, `alerts`, `label`, `ingest`, `tail`), so the CLI and UI can never disagree.

---

## 9. UI: "Frego's Glen"

### 9.1 Stack and build
- `ui/` is TypeScript + Vite. There's no framework in v1 (ADR-005): a small hand-rolled component helper over the DOM. All untrusted strings (mDNS names, SSDP friendly names, SNIs) are rendered with `textContent`, never `innerHTML`, because device-supplied strings are attacker-controllable.
- In development, run `vite dev` with a proxy to `fregod`. For release, `vite build` produces assets that CMake embeds into `fregod` (generated `ui_assets.cpp`: path → bytes + content-type + ETag).

### 9.2 Screens

| Screen | Content |
|---|---|
| **The Glen** (home) | When the gate is closed: Frego asleep under his hat, with the reason ("Not your home network" / "No network" / "VPN in the way") and, for an unknown network, the "Is this your home network?" prompt. When open: Frego (animated SVG, mood state), pot-of-gold gauge, level badge + XP bar, ring of Folk avatars around the pot, the latest Mischief, "what Frego can see" visibility meter (levels 1–5 with how to unlock the next) |
| **The Folk** | Device cards: avatar by kind, name/label, vendor, Changeling and Stranger badges, last seen, DNS today; inline rename |
| **Folk detail** | Rainbows: SVG arcs from the device to kingdoms, sized by query count; Magpie list; domain table; raw DNS tail |
| **Mischief** | Alerts by severity with plain reason, ack button |
| **Quests & Lore** | Quest progress; unlocked lore cards (ARP, multicast, DNS, TLS/JA4…) rendered from `data/lore/*.md` |
| **Plain mode** | Same data as tables; no character, no animation (toggle persisted in `localStorage`) |

### 9.3 Frego asset
- One layered SVG with named groups (`#body`, `#eyes`, `#mouth-calm`, `#mouth-wary`, `#mouth-alarmed`, `#pot`, `#coins`). Mood switches CSS classes on the root; animations (blink, coin sparkle, hop on level-up) are CSS keyframes, disabled under `prefers-reduced-motion`.
- v1 ships a placeholder drawn in-house. Final art is PRD open question #2; the layered-group contract lets the art be swapped without code changes.
- Theme: green and gold design tokens on `:root`, light/dark via `prefers-color-scheme`, and colour is never the only signal (icons + text on every state).

---

## 10. Platform layer

| Function | macOS (v1) | Linux (M5) |
|---|---|---|
| `default_interface()` | Routing socket `RTM_GET` for 0.0.0.0 → iface + gateway; `getifaddrs` for IP/mask; `AF_LINK` `sockaddr_dl` for MAC | Netlink `RTM_GETROUTE` / `RTM_GETADDR` |
| `arp_table(iface)` | `sysctl NET_RT_FLAGS RTF_LLINFO` (AF_INET) | Netlink `RTM_GETNEIGH` (or `/proc/net/arp`) |
| `ndp_table(iface)` (M9) | `sysctl NET_RT_FLAGS RTF_LLINFO` (AF_INET6) | Netlink `RTM_GETNEIGH` with `AF_INET6` |
| `ping_all_nodes_v6(iface)` (M9) | ICMPv6 echo on `SOCK_DGRAM`/`IPPROTO_ICMPV6` to `ff02::1` | Same (needs `net.ipv4.ping_group_range` to include the user) |
| `paths()` | `~/Library/Application Support/FregoMunchkin` | XDG |
| Service | launchd **user agent** for `fregod` (see §10.2); capture stays a manual `sudo` session | systemd units (`fregod.service`, `frego-capture.service` with `AmbientCapabilities=CAP_NET_RAW`) |

Each function is behind a header in `platform/include`, with one `.cpp` per OS selected by CMake.

### 10.1 macOS Local Network Privacy (B6, verified by spike)

Since macOS 15, macOS can block a process from reaching LAN devices. A throwaway spike tested this on the builder's Mac (**macOS 26.6.2**, home Wi‑Fi `en0`, 2026-11-10). It ran a TCP connect to the router and to a non-router LAN device (a Samsung TV), mDNS (legacy-unicast and multicast-group styles), SSDP, and a port-53 bind.

| How the process was launched | Router (unicast) | Other LAN device (unicast) | mDNS / SSDP (multicast) | Bind :53 v4/v6 |
|---|---|---|---|---|
| From a terminal (Ghostty), plain binary | ✅ | ✅ | ✅ | ✅ |
| launchd user agent, plain binary | ✅ | ✅ | ✅ | ✅ |
| launchd user agent, binary **with an embedded `Info.plist`** (bundle id + `NSLocalNetworkUsageDescription`), ad-hoc signed | ✅ | ❌ "No route to host" | ❌ silently dropped (3/3 runs) | ✅ |
| Inside Claude Code's sandboxed shell | ✅ UDP / ❌ TCP "Network is unreachable" | — | ❌ | ✅ |

**Findings**
1. A plain command-line binary, with no bundle identity, has full LAN access on this macOS version, whether started from a terminal or by launchd.
2. **The commonly suggested fix makes things worse.** Embedding an `Info.plist` gives the binary an app identity, and Local Network Privacy then blocks it: unicast to non-router hosts fails with `EHOSTUNREACH`, and multicast is dropped without any error. The builder confirmed that no prompt appeared for the spike binaries. The only prompt was for Ghostty, the terminal hosting the session, which confirms that processes launched from a terminal run under the terminal's permission. The router stays reachable, so a check against the gateway alone would miss the block.
3. Multicast answers are flaky from one query to the next. One run got 0 mDNS answers; the next got 3 from the same process type.
4. Development tools that sandbox network access (such as Claude Code's shell) block LAN traffic. Live tests must run outside such sandboxes.

**Design rules**
- **Ship plain executables.** `fregod` and `frego-capture` are bare Mach-O binaries: no embedded `Info.plist`, no app bundle (ADR-015). Revisit if the product ever becomes a signed `.app` with a proper permission flow.
- **Startup self-check (`lan_access_probe`, in `network-guard`).** After the gate opens, run two probes:
  - a TCP connect to a non-router LAN host taken from the ARP table, using any port, where *connection refused* counts as success;
  - one mDNS query.

  **Retry before concluding** (spike S-LAN): a never-seen executable's first launchd run can fail transiently. The probe retries with backoff (1, 2, 4, 8, 16 s; about 30 s in total) and reports `lan_blocked` only if every attempt fails.

  If the router is reachable but the other host gives `EHOSTUNREACH`/`ENETUNREACH`, or every multicast probe over 3 tries gets nothing while the ARP table shows other hosts, the status becomes **`lan_blocked`**:
  - `fregod` logs it clearly;
  - `/api/v1/status` and `fregoctl status` report it, with the fix: System Settings › Privacy & Security › Local Network, or run from a terminal;
  - the UI shows Frego "stuck behind the hedge".

  Collection continues, but discovery results are marked as possibly incomplete.
- **Repeat multicast queries** (§7.4, §7.5).
- **Keep the spike.** Before each new macOS major version, re-run it (`tools/lnp-check/`, to be added to the repo when coding starts) and update this table.


### 10.2 Running persistently on the Mac (minor review point; decision)

`fregod` runs as a **launchd user agent**: per user, unprivileged, no LaunchDaemon and no root.
- **`fregoctl service install`** writes `~/Library/LaunchAgents/dev.fregomunchkin.fregod.plist` with:
  - `RunAtLoad`;
  - `KeepAlive` = restart on crash (with `ThrottleInterval` 30 s);
  - `ProcessType` = `Background`;
  - logs into the data dir.

  It then loads the agent with `launchctl bootstrap gui/<uid>`. **`fregoctl service uninstall`** unloads it and removes the plist. `fregoctl service status` shows its state.
- **Behaviour:** fregod starts at login and stops at logout. While the Mac sleeps, nothing runs: the collection gate stays as it was, flows pause, and the rollup catches up after wake (§6.3). On wake, `network-guard` re-checks the network before collecting.
- **Local Network Privacy:** the B6 spike verified that a plain binary running as a launchd user agent keeps full LAN access (§10.1). The `lan_access_probe` re-checks this on every start.
- **Capture isn't persistent in the POC.** It needs root, so it stays a manual `sudo frego-capture …` session. That's fine, because capture no longer unlocks a level (M4).
- **"Night Watch" (24 h) quest:** counts fregod uptime on the home network with the gate open. Sleep pauses the count rather than resetting it, so the quest is reachable on a laptop that's left plugged in, with sleep disabled on power, or with `caffeinate`.

---

## 11. Performance and scaling plan

| Concern | v1 (home, Mac/Pi) | Scale-up seam |
|---|---|---|
| Capture | libpcap, immediate mode, 1 thread | `CaptureBackend` interface → AF_XDP / eBPF (Linux), PF_RING; RSS-style sharding by flow hash across N decoder threads |
| Bus | Mutex queue, 1 dispatcher | Lock-free MPSC ring; per-kind queues |
| Storage | SQLite, batched | `Store` interface → DuckDB / ClickHouse; rollups |
| Plugins | Static, in-process | `dlopen` C ABI → out-of-process over unix socket |
| Deployment | Single host | Gateway mode; multi-site aggregator consuming the same event JSON |

**Budget (Pi 4): estimates, not measurements (minor review point).** Decode + flow update ≤ 5 µs/packet → 10k pps ≈ 5% of one core. Target RSS < 50 MB (the flow table at 100k entries × ~200 B ≈ 20 MB is the main consumer). None of these numbers has been measured yet. They become real once we have:
- **micro-benchmarks** (`tests/bench/`, Catch2 benchmarks): `ByteReader`, each parser, `FlowTable.update`, `SightingCache`, JA4, run on the builder's Mac and on a Pi when one exists;
- **a replay throughput test** (`frego-capture --file` on a recorded 10-minute capture, measuring packets/s and peak RSS).

Results are recorded in `docs/perf.md` with hardware, OS, compiler and commit. Until then, every performance figure in this doc and the PRD is labelled as an estimate.

---

## 12. Testing strategy

1. **Unit (Catch2), `tests/unit/`:** every `net` parser with hand-built byte arrays (including malformed cases: truncated, compression loops, oversized lengths, GREASE-only lists); `ByteReader`; SHA-256 against NIST vectors; JA4 against upstream fixture pcaps; event bus ordering/backpressure/re-entrancy; `SqliteStore` against an in-memory DB; identity rules (including the proxy-ARP case recorded from this network); each alert rule; game formulas.
2. **Fuzz (libFuzzer), `tests/fuzz/`:** one target per parser (`fuzz_dns`, `fuzz_tls_hello`, `fuzz_frame`, `fuzz_ssdp`), run with ASan + UBSan, seeded from `tests/fixtures/`. This needs Homebrew LLVM on macOS. CI runs each target for 60 s per PR.
3. **Replay, `tests/replay/`:** `.jsonl` event streams (each line carries its `observed_at` and `session`) → run through the real plugin graph with a `ManualTimeSource` that the harness advances to each event's time → assert on emitted alerts and game events. This is also how bugs found on the home network become regression tests. Required cases for B1:
   - A pcap with a 10-minute gap produces two separate flows: the first expires on packet time.
   - An investigation session never produces alerts, baseline updates or game events.
   - A night-time event replayed during the day still triggers `night_owl`, because rules use `observed_at`.
4. **Live (manual, per milestone):** follows the PRD §11 checklist on the builder's network.
5. **CI (GitHub Actions):** a macOS + Ubuntu matrix running debug-asan (tests), release (tests + size check), and a fuzz job (Ubuntu, clang).

Commands (established in M0):

```sh
cmake --preset debug && cmake --build --preset debug
ctest --preset debug                         # all tests
ctest --preset debug -R dns                  # single test / pattern
./build/debug/apps/fregod/fregod --config ./dev.json
```

---

## 13. Security and privacy checklist
- Parsers: bounds-checked reader, fuzzed, no `memcpy` from untrusted lengths without a check, compression-loop and recursion caps.
- Privilege: only `frego-capture` touches root, and it drops privileges right after `pcap_activate`. `fregod` refuses to run as root unless `--allow-root` is passed.
- Parser isolation (M3): raw packets are decoded only in the unprivileged, resource-limited `frego-capture`. `fregod` receives validated, rate-limited catalog records and never parses a raw packet.
- API: localhost-only, Host and Origin checks, no CORS.
- UI: `textContent` only for device-supplied strings; strict CSP (`default-src 'self'`).
- Data: no payloads stored; database file mode 0600; data dir 0700.
- Network egress: only DNS upstream (dns-fwd) and the SSDP `LOCATION` fetches (LAN only, private-IP check enforced).

---

## 14. Milestone breakdown

### M0: Core shell + first slice of discovery (**done**, 2026-11-10)

**Built:**
- Libraries `events` (catalog 1.0.0, `catalog::text`, `json_out`), `net` (`ByteReader`, MAC, OUI, IPv4/subnet, SHA-256), `platform/macos` (default route via routing socket, ARP table via sysctl, UDP nudge, TCP probe, route monitor), `core` (two-lane mailbox bus with synchronous test mode, plugin host with collection gate and fault isolation, schedulers, config, logger, metrics, SQLite database with backup-first migrations, HTTP API with guards and capped SSE), `domain` (migration 001 = full v1 schema, `SqliteDomainStore`).
- Plugins `heartbeat`, `store-sink`, `network-guard`, `neighbor-scan` (IPv4/ARP), `identity` (basic).
- Apps `fregod` and `fregoctl` (`status`, `devices`, `network status|approve|decline`, `tail`).
- Tests: 53 Catch2 unit tests + the `json_out` grep check, all passing under ASan/UBSan, plus a `[.live]` platform test.

**Exit criteria, verified live on the builder's network (macOS 26.6.2):**
- Heartbeats reach SQLite and the SSE stream (`fregoctl tail`).
- On an unapproved network the gate stays closed and nothing is collected. After `fregoctl network approve` the gate opens, `neighbor-scan` runs at once, and `fregoctl devices` lists 9 devices with OUI vendors.
- After a restart, home is recognised and every device keeps its ID.
- `lan_access_probe` reports `ok`. The Host and CSRF guards return 403. Database files are 0600. SIGINT shuts down cleanly. No sanitizer reports.

**Where the implementation departs from this doc (all intentional):**
1. **`ctx.service<T>()` replaces `ctx.store()` (§4.3).** A typed service lookup that `fregod` fills, so the core never names `DomainStore` (§2 layering).
2. **`DeviceIdentified` is in the catalog.** It was used in §7.6 but missing from §4.1. Catalog 1.0.0 holds only the kinds M0 needs. The rest of §4.1 are added as minor bumps when their milestones land.
3. **`networks.state` gains `alias` (§7.0).** It's the same router (same subnet and gateway IP) seen with a different gateway MAC, as through a MAC-rewriting extender. Approving it adds an alias of home instead of asking to replace home.
4. **`lan_access_probe` tries TCP ports 80, 443, then 9 on up to 4 hosts (§10.1).** In the live run, hosts behind the extender silently dropped port 9, which only gave `inconclusive`. A timeout proves nothing; any answer, even "connection refused", proves access.
5. **Scheduler:** one thread per job (`ThreadedScheduler`) instead of a timer wheel and a 2-thread pool (§4.4). `ManualScheduler` runs jobs on a manual clock for tests.
6. **`heartbeat` is enabled by default during M0.** It gets disabled at the start of M1.
7. **Basic identity:** a MAC on two or more IPs in one snapshot becomes shared, and each IP behind it becomes a weak device without a vendor. The question, evidence and merges arrive in M1.

**Observed during the live run:** the Mac's own private Wi‑Fi MAC rotated (`7a:73:de:ac:29:de` at .27 → `ce:10:28:8a:16:79` at .18) within the same day. This is a real rotation for the M1 merge suggestions to handle (§7.6).

### M1: Discovery
Spike S-LAN done (§7.5a). Scope: `net`: bytes, mac, dns, dhcp, ssdp, oui · `platform/macos`: netinfo, arp_table, ndp_table · plugins: neighbor-scan, mdns, ssdp, dhcp-listen, identity · API: devices · UI v0 (Glen + Folk, placeholder Frego).

### M2: DNS
`dns-fwd` (UDP + TCP), psl, trackers, orgs, rainbows UI, Magpie alerts.

### M3: Capture
`frego-capture`, wire protocol, `net`: ethernet/arp/ip/tcp/udp/tls/ja4/sha256, flow table, hello reassembly, pcap file ingest, fuzzers.

### M4: Analytics + game
Baselines, the remaining alert rules, game plugin, quests/lore, Mischief and Quests screens, Plain mode.

### M5: Linux/Pi
`platform/linux`, systemd units, ARM64 cross-build, 24 h soak.

---

## 15. Architecture decision records (summary)

| ADR | Decision | Why | Revisit when |
|---|---|---|---|
| 001 | C++23 (not C++20) | `std::expected` for no-throw parsers; supported by Apple clang 21 and GCC 12+ | Never needed below GCC 12 |
| 002 | Events as `std::variant`; router + mailbox per plugin; critical lane never drops; bulk lanes bounded in bytes; synchronous mode for tests | Value semantics and exhaustive handling; a slow plugin can't stall others; alerts can't be lost; tests stay deterministic | Thread count matters (e.g. on very small devices) |
| 003 | Packets never on the bus; packet-derived sources publish ≤ 50 events/s, via aggregation (flows) or de-duplication (`SightingCache`) | Keeps the bus at ~1000 events/s; capture aggregates locally | — |
| 004 | JSON config (no TOML) | One fewer dependency; nlohmann/json is already in | Users find JSON painful |
| 005 | No UI framework in v1 | Small surface; learn the DOM; easy to migrate later | UI exceeds ~5 screens or state gets hairy |
| 006 | Compiled-in plugins, generated registry | Avoids static-init dead-stripping; simplest correct start | Third-party plugins (v2) |
| 007 | Root helper drops privileges and then does **all** packet decoding; sends validated catalog-JSON records to fregod; DNS/mDNS/SSDP parsers stay in fregod with fuzzing | Least privilege, and the process that holds household data never parses raw packets | Fuzzing finds bugs in the in-process parsers, or Linux capabilities make the helper unnecessary |
| 008 | Hand-written parsers, libraries only for plumbing | Learning goal + full control over untrusted input | — |
| 009 | Data files fetched by script, not by the daemon | Daemon stays offline-by-default | Auto-update becomes a feature |
| 010 | Event time (`observed_at`, source-set) separate from publish time; injectable `TimeSource`; flow timers on packet time | Correct pcap ingest; deterministic replay tests | — |
| 011 | Pcap ingests are isolated investigation sessions; never feed live alerts, baselines or the game | Old data must not raise today's alerts or skew baselines | Users ask to import history from a router capture |
| 012 | POC runs on the Mac as `test`-channel builds; DNS opt-in is per device; forwarder answers home-network clients only, uses a random source port per upstream query, listens on IPv4 + IPv6, and detects (but never blocks or redirects) bypass | A sleeping laptop must not take down a household; no open resolver; no interception | POC proves the need for an always-on host (Pi) |
| 013 | Generic collection gate in the core, driven only by `network-guard`; fingerprint = gateway MAC + subnet; exactly one approved home; idle elsewhere | No scanning or data collection on networks the user doesn't own; no foreign data in the DB; the core stays network-agnostic | Users need more than one site |
| 014 | Opaque device IDs; identifiers are observations; merges via redirects (never rewriting rows); only provisional→MAC promotion is automatic; other merges and shared-MAC verdicts are confirmed by the user | DHCP renewals and MAC rotation must not create "new" devices or lose labels; wrong merges must be undoable | Strong signals (e.g. DHCP fingerprints) are reliable enough to auto-merge |
| 015 | Ship `fregod`/`frego-capture` as plain executables (no embedded `Info.plist`/bundle identity); `lan_access_probe` self-check at startup; multicast queries repeated 3× | Verified on macOS 26.6.2: plain binaries keep LAN access from a terminal and from launchd; an embedded `Info.plist` triggers Local Network Privacy blocking without a prompt | A future macOS version enforces LNP on plain binaries, or Frego ships as a signed `.app` |
| 016 | Core engine depends only on the event *contract* (`libfrego_events`) and never inspects payloads; domain schema/queries live in `libfrego_domain`; domain API routes are registered by plugins; `Custom{type, version, json}` for plugin-defined events; catalog JSON is the cross-ABI format | Makes "core knows nothing about networking" and "grows by plugins" true, while first-party plugins stay typed and fast | Custom events become common enough to need a schema registry |
| 017 | Passive, non-root `dhcp-listen` in M1 (verified by spike S-LAN first; capture fallback); levels measure household visibility; capturing only the Mac's own traffic is a side quest, not a level | DHCP gives the best identification from a laptop's vantage point; the game must not reward visibility that doesn't exist | The spike shows non-root listening fails |
| 018 | Alerts only for what's worth an interruption: device classes, ledger digest for the rest, an enforced low/info budget (3/device/day; medium/high never suppressed), 7-day baselines | A noisy alert feed teaches people to ignore Frego | Field data shows predictable devices are noisier than expected |
| 019 | Scores reward understanding and actionable fixes only: no XP for acknowledging alerts, no gold penalty for things the user can't fix; magpies shown separately until blocking exists | Avoids dark patterns and "number go up" behaviour that empties alerts of meaning | v2 blocking makes magpies actionable |
| 020 | Cap SSE streams (4 of 16 workers), share one stream per browser; all event strings valid UTF-8 at creation; one non-throwing JSON serializer | Device-supplied text is hostile; a thread-per-stream server must protect its API workers | SSE limits bite, at which point move streaming to an event loop |
| 021 | No API authentication in POC test builds (loopback-only enforced, shown in status/UI); authentication required before any `stable` build; SSDP fetches limited to the responder's literal LAN IP with no redirects | POC on a single-user Mac; keep scope small without letting the risk outlive the POC | Any non-test build, multi-user Mac, or remote access |
| 022 | IPv6 in the POC: NDP table + all-nodes ping alongside ARP, one neighbor snapshot per scan, v6 addresses tied to devices through the MAC, dual-stack checks; fingerprint stays IPv4 | Dual-stack devices and the v6 DNS listener (B2) must be attributable | IPv6-only home networks |
| 023 | fregod runs as a launchd user agent (installed by `fregoctl service install`); capture stays a manual `sudo` session in the POC | Persistent without root; verified LAN access for plain binaries under launchd (B6) | Always-on host (Pi) or a need for persistent capture |

## 16. Decisions from the first review round
1. C++23 approved (ADR-001); the PRD is updated.
2. Retention approved: 30 days raw, then daily rollups.
3. ARP scan + OUI vendor lookup + basic identity move into M0.

## 17. Senior-engineer review: resolution tracker

| ID | Finding | Status | Resolution |
|---|---|---|---|
| B1 | Bus-assigned timestamps corrupt pcap ingest; no fake clock | **Resolved** | `observed_at` vs. `published_at` (§4.1, §4.2); `TimeSource` (§4.3); flow timers on packet time (§7.8); investigation sessions (§6.4); ADR-010/011; replay cases (§12) |
| B2 | Laptop as household DNS: sleep, IPv6 bypass, open resolver, fixed upstream port | **Resolved** | Test-channel builds (§3); per-device opt-in + setup guide + `fregoctl dns clients` (§7.7); home-network-only clients; per-query random source port; IPv4+IPv6 listener; bypass detection as a device status; Pi deferred until needed; ADR-012 |
| B3 | No notion of which network; scans foreign networks | **Resolved** | `network-guard` plugin + fingerprint (§7.0); collection gate in the core, closed by default, which refuses late publishes (§4.3); one home, replace with confirmation, decline (§7.0); `networks` table and `network_id` tagging (§6.3); approve/decline API (§8); sleeping Frego in the UI (§9.2); ADR-013 |
| B4 | Device IDs embed MAC/IP; no merge path | **Resolved** | Opaque IDs + `device_observations` (§6.3); resolution algorithm, user-confirmed merge suggestions, undoable redirects, automatic provisional promotion, shared-MAC question (§7.6); new events (§4.1); identity API (§8); info-level alert for randomized new devices; ADR-014 |
| B5 | Capture publishes `DeviceSeen` per packet | **Resolved** | `SightingCache` (§7.8): emit on new pair, MAC change, or every 60 s of packet time; 4,096-pair LRU; 50 events/s budget with metric, debug warning and tests; ADR-003 amended |
| B6 | macOS Local Network Privacy unverified | **Resolved (verified by spike)** | Spike on macOS 26.6.2 (§10.1): plain binaries have full LAN access from a terminal and from launchd; an embedded `Info.plist` causes blocking. Plain executables, `lan_access_probe` self-check, repeated multicast queries, port-53 bind verified (§7.7); ADR-015 |
| M1 | Core isn't really network-agnostic; variant can't cross a plugin ABI | **Resolved** | `libfrego_events` catalog + versioning + `Custom` escape hatch (§4.1); new layering with `domain` (§2); `core::Database` vs. `DomainStore` (§6.1); plugin-registered routes (§8); `ctx.http()`, `ctx.subscribe_custom()` (§4.3); ADR-016 |
| M2 | Single synchronous dispatcher; alerts droppable; publisher blocking; count-based capacity | **Resolved** | Router + per-plugin mailboxes and workers; critical lane never drops; bulk lanes bounded in bytes; publishing never blocks; per-plugin drop metrics; synchronous mode for tests and replay (§4.2, §4.4); ADR-002 amended |
| M3 | Fault isolation is mostly for show; untrusted packet parsing runs in the process holding the household data | **Resolved** | All packet decoding (flows, TLS/JA4, DNS-in-capture, sightings) runs in `frego-capture` after privilege drop, with resource limits; length-prefixed catalog-JSON records; fregod validates kinds, sizes, rate and session; pause control mirrors the gate; crash handling; pcap files use the same path; low-volume parsers stay in-process with fuzzing (§7.8, §13); ADR-007 amended |
| M4 | Mac capture adds little but unlocks a level; DHCP missing | **Resolved** (spike S-LAN pending) | `dhcp-listen` plugin in M1, no root, passive, with capture-based fallback (§7.5a); DHCP evidence in identity merges (§7.6); level ladder based on household visibility, Mac capture as the "Look in the mirror" side quest (§7.11); `traffic_spike` limited to devices whose traffic is visible (§7.10); ADR-017 |
| M5 | Alert noise targets unrealistic | **Resolved** | Predictable vs. people-device classes + "Watch closely"; `new_domain` alerts only for predictable devices, people-devices go to the daily ledger; per-device learning periods (1 h / 72 h / 7 days); baseline-relative `night_owl`; NXDOMAIN excludes single-label probes; enforced noise budget; `baselines` and `ledger` tables (§7.10); ADR-018 |
| M6 | Game mechanics fight the design rules | **Resolved** | Gold counts only actionable items (open alerts by severity, open identity questions); magpies in a separate "coins carried off today" counter until v2 blocking; no XP for acknowledging alerts or passive events; XP for labelling, answering identity questions, lore, quests (§7.11); ADR-019 |
| M7 | SSE streams starve the HTTP pool; JSON `dump()` throws on invalid UTF-8 | **Resolved** | 16 workers, ≤ 4 SSE streams (503 + Retry-After beyond), one stream per browser via BroadcastChannel + Web Locks, pings + bounded per-client queues, streams closed first at shutdown (§8, §4.4); catalog UTF-8 invariant via `catalog::text()` (§4.1); single `json_out()` helper enforced by CI, plus tests (§8); ADR-020 |
| M8 | Localhost API has no auth; SSDP fetch can be abused | **Resolved: risk accepted for the POC** | No auth in test builds, documented and shown in status/UI; loopback-only listen enforced in test builds; auth (unix socket + one-time login cookie) is a hard gate for `stable` (§3, §8); SSDP fetch rules: literal IP equal to responder, home subnet, no redirects, rate-limited (§7.5); ADR-021 |
| M9 | IPv6 missing | **Resolved** (spike S-LAN pending) | `arp-scan` → `neighbor-scan`: ARP + NDP tables, unprivileged ICMPv6 all-nodes ping, one `NeighborSnapshot` event (§7.3, §4.1); v6 addresses (incl. temporary) linked through the MAC; dual-stack bindings and subnet checks; `ndp_table` + v6 ping in the platform layer (§10); IPv6-only networks out of scope; ADR-022 |
| m1 | Two sources of truth for proxy state | **Resolved** (by B4) | `shared_macs` table is the only source (§6.3, §7.6) |
| m2 | Baselines as JSON blobs | **Resolved** (by M5) | `baselines` table (§7.10) |
| m3 | Nightly rollup assumes the Mac is awake | **Resolved** | Catch-up rollups: at startup, on wake, hourly; per-day, idempotent, delete only after commit (§6.3) |
| m4 | Forward-only migrations, no backup | **Resolved** | Online backup before migrating (keep 3), per-migration transactions, refuse newer schemas (§6.2) |
| m5 | `store_sink` can lose up to 250 ms on crash | **Resolved** | Documented for bulk events; critical-lane events committed immediately (§6.2, §7.2) |
| m6 | JA4 fixture licences | **Resolved** | Own captures against a local TLS server; expected values from the reference tool, with its version recorded (§5.3) |
| m7 | No persistent-run story on the Mac | **Resolved** | launchd user agent via `fregoctl service install`; capture stays manual; Night Watch pauses on sleep (§10.2) |
| m8 | VPN as default route breaks discovery | **Resolved** (by B3) | `network-guard` status `None` with "VPN in the way" (§7.0) |
| m9 | Embedded mDNS responders ignore legacy unicast | **Resolved** | Passive mDNS listener moved into M1 (§7.4); spike showed group join works |
| m10 | Unmeasured performance numbers | **Resolved** | Labelled as estimates; micro-benchmarks + replay throughput test; results in `docs/perf.md` (§11) |
| S-LAN | Spike: DHCP without root, IPv6 all-nodes ping, Local Network Privacy | **Done** | Non-root `:67` hears other devices' DHCP from a terminal and under launchd; ICMPv6 all-nodes ping works (first-launch transient → probe retries); DHCP `chaddr` and EUI-64 link-locals reveal real MACs behind a MAC-rewriting device; shared-MAC question gains evidence and an ARP-spoofing outcome (§7.3, §7.5a, §7.6, §10.1) |
