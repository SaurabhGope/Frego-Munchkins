#include "frego/domain/migrations.hpp"

#include <array>

namespace frego::domain {
namespace {

// Migration 001: the full v1 schema from DESIGN §6.3, §6.4, §7.10. Later milestones fill
// tables that M0 leaves empty. Times are unix milliseconds of event time (observed_at).
constexpr std::string_view k001 = R"sql(
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);

CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,               -- 0 = live
  kind TEXT NOT NULL,                   -- live | pcap
  name TEXT NOT NULL,
  created INTEGER NOT NULL,
  first_ts INTEGER, last_ts INTEGER,
  packets INTEGER, status TEXT
);
INSERT INTO sessions (id, kind, name, created) VALUES (0, 'live', 'live network', CAST(strftime('%s','now') AS INTEGER) * 1000);

CREATE TABLE networks (
  id INTEGER PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  gateway_ip TEXT NOT NULL, gateway_mac TEXT NOT NULL, subnet TEXT NOT NULL, ssid TEXT,
  state TEXT NOT NULL,                  -- home | alias | declined | retired
  first_seen INTEGER NOT NULL, approved_at INTEGER
);
CREATE UNIQUE INDEX one_home ON networks(state) WHERE state = 'home';

CREATE TABLE devices (
  id TEXT PRIMARY KEY,                  -- opaque dev_<uuidv7>
  network_id INTEGER,
  label TEXT,
  kind TEXT NOT NULL DEFAULT 'unknown',
  identity TEXT NOT NULL,               -- strong | weak | provisional
  mac TEXT, ip TEXT, vendor TEXT, hostname TEXT, model TEXT,
  randomized INTEGER NOT NULL DEFAULT 0,
  is_self INTEGER NOT NULL DEFAULT 0,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL
);
CREATE TABLE device_observations (
  device_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL, via TEXT NOT NULL,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (device_id, key, value)
);
CREATE INDEX obs_lookup ON device_observations(key, value);
CREATE TABLE device_redirects (
  from_id TEXT PRIMARY KEY, to_id TEXT NOT NULL,
  reason TEXT NOT NULL, merged_at INTEGER NOT NULL
);
CREATE VIEW device_canonical AS
  SELECT d.id AS id, COALESCE(r.to_id, d.id) AS canonical_id
  FROM devices d LEFT JOIN device_redirects r ON r.from_id = d.id;
CREATE TABLE identity_questions (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL,
  subject TEXT NOT NULL UNIQUE,
  evidence TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'open',
  created INTEGER NOT NULL, answered INTEGER
);
CREATE TABLE shared_macs (
  mac TEXT PRIMARY KEY, ips TEXT NOT NULL,
  verdict TEXT NOT NULL DEFAULT 'unknown',  -- unknown | extender | single_device | unexplained
  first_seen INTEGER NOT NULL, decided_at INTEGER
);
CREATE TABLE ip_bindings (
  ip TEXT NOT NULL, device_id TEXT NOT NULL, network_id INTEGER,
  valid_from INTEGER NOT NULL, valid_to INTEGER,
  PRIMARY KEY (ip, valid_from)
);
CREATE INDEX ip_bindings_open ON ip_bindings(ip) WHERE valid_to IS NULL;

CREATE TABLE dns (
  id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL DEFAULT 0, network_id INTEGER,
  ts INTEGER NOT NULL, device_id TEXT, client_ip TEXT NOT NULL,
  qname TEXT NOT NULL, domain TEXT NOT NULL,
  qtype INTEGER NOT NULL, rcode INTEGER NOT NULL, answers TEXT, via TEXT NOT NULL
);
CREATE INDEX dns_device_ts ON dns(device_id, ts);
CREATE INDEX dns_domain ON dns(device_id, domain);
CREATE TABLE dns_daily (
  device_id TEXT NOT NULL, domain TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (device_id, domain, day)
);
CREATE TABLE flows (
  id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL DEFAULT 0, network_id INTEGER,
  start INTEGER NOT NULL, end INTEGER NOT NULL, device_id TEXT,
  proto INTEGER NOT NULL, src TEXT, sport INTEGER, dst TEXT, dport INTEGER,
  packets INTEGER, bytes_out INTEGER, bytes_in INTEGER, sni TEXT, ja4 TEXT
);
CREATE INDEX flows_device_start ON flows(device_id, start);
CREATE TABLE session_devices (
  session_id INTEGER NOT NULL, mac TEXT, ip TEXT NOT NULL, vendor TEXT,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (session_id, ip, mac)
);

CREATE TABLE alerts (
  id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE, network_id INTEGER,
  ts INTEGER NOT NULL, updated INTEGER NOT NULL, device_id TEXT,
  kind TEXT NOT NULL, severity INTEGER NOT NULL, title TEXT NOT NULL, reason TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE ledger (
  device_id TEXT NOT NULL, day TEXT NOT NULL, kind TEXT NOT NULL,
  item TEXT NOT NULL, count INTEGER NOT NULL, first_ts INTEGER NOT NULL,
  PRIMARY KEY (device_id, day, kind, item)
);
CREATE TABLE baselines (
  device_id TEXT NOT NULL, network_id INTEGER NOT NULL, metric TEXT NOT NULL,
  hour_of_week INTEGER NOT NULL, mean REAL NOT NULL, m2 REAL NOT NULL, samples INTEGER NOT NULL,
  PRIMARY KEY (device_id, network_id, metric, hour_of_week)
);
CREATE TABLE game (k TEXT PRIMARY KEY, v TEXT NOT NULL);
)sql";

constexpr std::array<Migration, 1> kMigrations{{
    {1, "initial schema", k001},
}};

}  // namespace

std::span<const Migration> migrations() { return kMigrations; }

}  // namespace frego::domain
