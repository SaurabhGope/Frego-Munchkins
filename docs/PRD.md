# FregoMunchkin — Home/IoT Network Observer

**PRD v0.3** · Owner: Saurabh Gope · Date: 2026-11-10 · Status: Approved · Stage: proof of concept (test builds, Mac-hosted)

| Version | Change |
|---|---|
| 0.1 | First draft (Python, plain dashboard) |
| 0.2 | Renamed to **FregoMunchkin**. Gamified UI built around Frego the leprechaun. Core in **C++**. Architecture is now a minimal core shell that grows through plugins. |
| 0.3 | C++23 (for `std::expected`). Retention: 30 days raw, then daily rollups. ARP scan + OUI vendor lookup pulled into M0. |

## 1. Problem

A typical home network has 15–40 connected devices: phones, laptops, TVs, speakers, cameras, plugs, bulbs, consoles. The owner usually cannot answer basic questions:

- What devices are on my network right now, and what are they?
- Who does each device talk to (which companies, which domains)?
- Is any device doing something new or unusual (new destinations, 3 a.m. activity, traffic spikes)?
- Which devices are chatty with ads/telemetry endpoints?

Router admin pages show a DHCP list at best. Enterprise tools (Zeek, Suricata, NDR products) answer these questions, but they're heavy, intimidating, and no fun.

## 2. Vision

**Frego, a leprechaun, guards your home network the way a leprechaun guards his pot of gold.** Your devices are his folk, your data is the gold, and trackers are thieves trying to carry it off. Network monitoring becomes something you *want* to open: a living character whose mood reflects your network's health, plus quests that teach you how networks actually work.

The product starts as a **bare-bones core shell** and grows into a platform through plugins: Mac laptop → Raspberry Pi → home gateway/router → (optionally) multi-site.

## 3. Users

1. **v1: the builder.** A technically curious user testing on their own home network from a Mac, who wants to learn networking deeply (and C++) while building it.
2. **Later:** privacy-conscious households, homelab owners, and families who want a friendly window into their network.
3. **Much later:** developers who write plugins (new collectors, analyzers, quests).

## 4. Goals and non-goals

**Goals (v1)**
1. A tiny, solid **core shell** (event bus, plugin host, storage, API) that every feature plugs into.
2. Accurate device inventory with no root required.
3. Per-device DNS visibility for devices pointed at Frego as their DNS server.
4. Packet analysis (live or `.pcap`): flows, TLS SNI, JA4 fingerprints, using a small privileged capture helper.
5. Explainable alerts based on per-device baselines.
6. A **gamified web UI** with Frego as the guide.
7. **Learning by building:** every protocol parser (Ethernet, ARP, IPv4/6, TCP, UDP, DNS, mDNS, SSDP, TLS) is hand-written. Libraries are used only for plumbing (capture, storage, HTTP, JSON).

**Non-goals (v1)**
- Reading payload content (it's almost all TLS; we work with metadata).
- Blocking or filtering traffic (v2 plugin).
- ARP spoofing or other man-in-the-middle tricks to intercept other devices' traffic.
- Cloud sync, accounts, multi-site.
- LLM explanations (v2 plugin).

## 5. The visibility constraint (key design input)

On a switched or Wi‑Fi home network, a laptop **cannot see other devices' unicast traffic**. The table below lists what each vantage point can see. It also drives Frego's levels (§7.3), so the game literally teaches it.

| Vantage point | Sees | Needs | Phase |
|---|---|---|---|
| Active probe + ARP table | Every live IP/MAC on the subnet | Nothing | M1 |
| Multicast (mDNS, SSDP) | Device names, models, service types | Nothing | M1 |
| DHCP broadcasts (passive) | Hostnames, vendor class, OS fingerprint as devices join or renew | Nothing (to be verified by spike S-LAN) | M1 |
| DNS forwarder | Every DNS query from devices using it as resolver | Point a device's (or router DHCP's) DNS at Frego | M2 |
| Packet capture on host | Host's own traffic + broadcast/multicast | Root (privileged helper) | M3 |
| Offline pcap ingest | Whatever the capture contains | A `.pcap` file | M3 |
| Gateway / mirror port | All traffic, all devices | Pi or router hardware | v2 |

Devices that hard-code DoH/DoT (some Android, Chromecast, browsers) bypass the forwarder. That's a known gap, and later we can detect it ("traffic but no DNS").

## 6. Architecture: a minimal core shell that grows by plugins

### 6.1 Principles
- **The core knows nothing about networking.** It only routes events, hosts plugins, and provides generic storage, config, scheduling and the HTTP server. The event types are a shared, versioned catalog, and plugins can define their own custom events. Every feature, even device discovery and its API endpoints, is a plugin.
- **Everything is an event.** Plugins communicate only through typed, versioned events on the bus. That keeps them decoupled, testable, and replayable (you can feed recorded events back in to test analyzers).
- **Interfaces at every seam.** Capture backend, storage engine, and transport are abstract interfaces, so we can scale up later without rewrites.
- **Least privilege.** Only a tiny capture helper ever runs as root. The core runs as the user.

### 6.2 Components

```
                 ┌──────────────── fregod (core daemon, unprivileged) ─────────────────┐
                 │                                                                      │
 frego-capture ──┼─► Sources ──┐                                     ┌─► Sinks          │
 (root helper,   │  nbr-scan    │        ┌────────────────────┐       │   sqlite store   │
  libpcap) ──────┼─ mdns, ssdp  ├──────► │  Event Bus (typed) │ ─────►│   game engine    │
  pcap stream    │  dns-fwd     │        └────────┬───────────┘       │   notifier (v2)  │
  over unix sock │  pcap-ingest ┘                 │      ▲            └──────────────────│
                 │                                ▼      │                              │
                 │                        Analyzers ─────┘ (derive events + alerts)     │
                 │                        flows · baseline · trackers · nxdomain        │
                 │                                                                      │
                 │  Core services: plugin registry · config · scheduler · logging       │
                 │                 storage interface · HTTP/JSON API + SSE live stream  │
                 └───────────────────────────────┬──────────────────────────────────────┘
                                                 │ HTTP / SSE (localhost)
                                 ┌───────────────┴────────────────┐
                           Web UI (Frego's Glen)              fregoctl (CLI)
```

| Component | Role | v1 implementation | Scale-up path |
|---|---|---|---|
| `fregod` | Core daemon: bus, plugin host, API | C++23, single process, thread per source | Sharded workers, lock-free queues |
| Plugin API | `Source`, `Analyzer`, `Sink` interfaces | Compiled-in plugins, static registry | Shared libs (`dlopen`) behind a versioned C ABI; out-of-process plugins over IPC |
| Event bus | Typed pub/sub | In-process, bounded MPSC queue | Persist to a log for replay; zero-copy ring buffers |
| `frego-capture` | Root helper: libpcap → unix socket | libpcap | AF_XDP / eBPF on Linux, PF_RING |
| Storage | `Store` interface | SQLite (WAL) | DuckDB/ClickHouse for analytics, retention tiers |
| API | REST + Server-Sent Events | cpp-httplib + nlohmann/json | Auth, remote access, multi-site aggregator |
| `fregoctl` | CLI over the API | C++ | Same |
| Web UI | Gamified dashboard | TypeScript + Vite, SVG/CSS animation, served by `fregod` | Mobile app / PWA |

### 6.3 Core event types (v1)
`DeviceSeen` (ip, mac, source, hints) · `DeviceIdentified` (vendor, hostname, model, services) · `DnsQuery` (client, qname, qtype, rcode, answers) · `Flow` (5-tuple, bytes, packets, timing) · `TlsHello` (SNI, ALPN, JA4) · `Alert` (kind, severity, device, reason) · `GameEvent` (xp, achievement, mood change).

Every event carries `schema_version`, `ts`, `source_plugin`.

### 6.4 Tech choices
- **C++23**, CMake + Ninja, clang (macOS) and gcc (Linux/Pi).
- System libraries: **libpcap**, **SQLite3** (both ship with macOS).
- Fetched with CMake `FetchContent`: **cpp-httplib**, **nlohmann/json**, **Catch2** (tests). There are no other runtime dependencies.
- Platform layer isolates OS specifics: on macOS, the ARP table is read via `sysctl(NET_RT_FLAGS)` and the default route via routing sockets; on Linux, via netlink and `/proc/net/arp`. Both are good learning territory.
- Sanitizers (ASan/UBSan) on in debug builds, plus fuzz targets for every parser, because parsers that read untrusted bytes off the wire are where C++ bites.

## 7. Gamified experience: "Frego's Glen"

### 7.1 Character
**Frego** is an original leprechaun (our own design, not modelled on any branded mascot): a small, sharp-eyed cobbler with a green coat, a buckled hat, and a pot of gold. He's witty and a bit grumpy about thieves, but always on your side. He speaks in short, plain-English lines with a light Irish flavour, and **never at the expense of clarity**.

### 7.2 Metaphor map
| Network concept | In the Glen |
|---|---|
| Home network | The Glen |
| Your data / privacy | The pot of gold |
| Devices | The Folk (each a card with a creature/portrait by device type) |
| Unknown/new device | A Stranger at the Gate |
| Randomized MAC | A Changeling (looks different every visit) |
| Tracker/telemetry domain | A Magpie (gold thief) |
| Alert | Mischief |
| Network health | Gold in the pot (0–1000, drops only for things you can act on: open alerts and identity questions) + Frego's mood |
| Trackers contacted today | "Coins carried off" counter beside the pot (doesn't drain it until v2 blocking) |
| Connections to companies | Rainbows from a device to the "kingdoms" (Google, Apple, Amazon…) |

### 7.3 Progression is tied to real visibility
Frego **levels up as he can see more of the network**, so progress means actual capability, not points for opening the app:

| Level | Title | Unlocked by | Lore card teaches |
|---|---|---|---|
| 1 | Hedge Watcher | First ARP scan | ARP, MAC addresses, subnets |
| 2 | Mound Keeper | mDNS/SSDP discovery | Multicast, service discovery |
| 3 | Name Keeper | First device identified from its DHCP broadcast | DHCP, leases, OS fingerprints |
| 4 | Rainbow Seer | First device using the DNS forwarder | DNS, resolvers, DoH and IPv6 bypass |
| 5 | Glen Guardian | Gateway or mirror-port capture: sees all traffic (v2) | Routing, NAT, why vantage points matter |

Capturing only the Mac's own traffic is **not** a level, because it adds no household visibility. It's the side quest **"Look in the mirror"**, with a lore card on TCP/UDP, flows, TLS, SNI and JA4.

### 7.4 Quests and achievements (v1 set)
- **Know Thy Folk:** identify (name/vendor) 90% of devices.
- **Name Them All:** give every device a label.
- **Spot the Magpie:** first tracker detected.
- **Seal the Leak:** route a device's DNS through Frego.
- **Night Watch:** Frego keeps watch for 24 hours straight.
- **Changeling Hunter:** label a device that uses a randomized MAC.

### 7.5 Moods
Calm (no open mischief) → Wary (low severity) → Alarmed (medium or high). Mood comes from open alerts. The underlying alert and its plain reason are **always one click away**.

### 7.6 Design rules
- The game layer sits *on top of* the data; it never hides or delays a real alert.
- No guilt mechanics, streak shaming or dark patterns.
- A "Plain mode" toggle shows the same data as a standard dashboard.
- Accessible: colour is never the only signal; light/dark themes; reduced-motion support.

## 8. Features by milestone

| Milestone | Scope | Exit criteria |
|---|---|---|
| **M0: Core shell** | CMake project, `fregod` with event bus, plugin registry, config, logging, SQLite store, HTTP API + SSE, `fregoctl status`, one demo "heartbeat" plugin, **ARP scan + OUI vendor lookup + basic device identity**, `fregoctl devices`, unit tests, sanitizer build | `fregod` runs; heartbeat and ARP events reach the DB and the API; `fregoctl devices` lists the home network; tests pass |
| **M1: Discovery** | `neighbor-scan` source (ARP via UDP nudge + IPv6 NDP via all-nodes ping; sysctl table reads), OUI vendor lookup, `mdns` + `ssdp` sources, `dhcp-listen` (passive DHCP fingerprinting, after spike S-LAN), device-identity analyzer (handles randomized MACs and mesh/extender proxy-ARP), UI v0: Glen with Frego + Folk cards | ≥ 90% of router DHCP list found; ≥ 50% of devices named or vendored |
| **M2: DNS** | `dns-fwd` source (UDP forwarder), domain → organisation grouping, tracker analyzer (Magpies), rainbows in the UI | A phone using Frego as DNS shows its domains within 5 s |
| **M3: Capture** | `frego-capture` root helper, pcap stream + file ingest, hand-written decoders (Eth/ARP/IPv4/IPv6/TCP/UDP), flow table, TLS ClientHello → SNI + JA4 (with multi-segment reassembly for post-quantum-sized hellos) | Parses a real 10-minute capture from this Mac with no crashes under ASan; fuzzers run clean |
| **M4: Analytics + game** | Baselines, alerts (new device, new domain after learning period, magpie, night activity, traffic spike, NXDOMAIN burst), XP/levels/quests/moods, lore cards, Plain mode | ≤ 10 low/info alerts/day after learning (medium/high never suppressed); everything else in the daily ledger |
| **M5: Linux/Pi port** *(only if the POC shows it's needed)* | Linux platform layer, systemd units, cross-compile for ARM64 | Runs 24 h on a Pi |

**v2+ (the "something big" path):** gateway mode on a Pi/OpenWrt, DNS blocking plugin, LLM "ask Frego" explanations, push notifications, dynamic plugin SDK + community quests/plugins, multi-site aggregator, mobile PWA.

## 9. Non-functional requirements
- **Performance (v1, estimated targets, not yet measured):** 10k packets/s on a Raspberry Pi 4; < 50 MB RSS; < 5% CPU idle. Benchmarks will replace these estimates (DESIGN §11).
- **Design headroom:** the bus and capture interfaces must allow 1 Gbps line rate later without API changes.
- **Reliability:** a misbehaving plugin can't crash the core; plugin exceptions are caught and the plugin is disabled.
- **Security:** parsers are bounds-checked and fuzzed; the API binds to localhost with a Host-header check (DNS-rebinding guard); the UI escapes all device-supplied strings (mDNS names are attacker-controllable); the root helper does one thing.
- **Privacy:** everything local; no payloads stored; only the user-triggered OUI download and DNS upstream queries leave the machine.
- **Ethics:** monitor only networks you own or are authorised to monitor; no interception.

## 10. Success metrics (on the builder's home network)
- Inventory finds ≥ 90% of DHCP-listed devices; ≥ 50% get a vendor or name.
- DNS events appear in the UI within 5 s.
- ≤ 10 low/info alerts/day after learning, enforced by a per-device budget; medium/high alerts are never suppressed; every alert has a plain-English reason. New domains on phones and laptops go to the daily ledger, not alerts.
- Frego reaches Level 4 (Rainbow Seer) on the Mac setup.
- The builder can explain every protocol Frego parses (the learning goal).

## 11. Test plan
1. **Unit tests (Catch2):** every parser with hand-built byte vectors; event bus; store; each alert rule with recorded events.
2. **Fuzzing (libFuzzer):** DNS, mDNS, SSDP, Ethernet/IP/TCP/UDP, TLS ClientHello parsers.
3. **Replay tests:** recorded event streams → expected alerts and game events.
4. **Live, on the home network:** scan vs. router DHCP list → one phone on the DNS forwarder → 10-minute capture → 24 h soak.

## 12. Open questions
1. Can the router's DHCP-advertised DNS be changed (whole-house test), or is testing per device?
2. Frego's art: hand-drawn SVG by us, commissioned, or AI-assisted with a human pass? (v1 can ship a simple SVG placeholder.)
3. UI stack: plain TypeScript + Vite (proposed) or a framework (Svelte/React) once the UI grows?
4. ~~Retention~~ Decided: 30 days raw DNS/flow rows, then daily rollups.
5. Tracker list source: small built-in list for v1; later a public blocklist?
