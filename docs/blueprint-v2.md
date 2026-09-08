# PROJECT BLUEPRINT v2: DecoyOps — Desktop Deception & Threat Intelligence Engine

*All components below are free / open-source or free-tier. No paid service is required to build or run this end to end.*

---

## 1. PROJECT OBJECTIVE & DESIGN MOTIVE

- **Objective:** A native, secure desktop application that automates deployment, lifecycle management, and telemetry monitoring of Docker-based network honeypots (Cowrie, Dionaea).
- **Motive:** Replace manual container orchestration and fragmented log analysis with a centralized, zero-trust control panel for observing adversary behavior safely.
- **Tone & Naming:** Professional, enterprise-grade ("DecoyOps"), no exaggerated marketing language.

---

## 2. ARCHITECTURE & TECH STACK (100% free)

| Layer | Choice | Cost |
|---|---|---|
| Desktop shell | Tauri 2.0 (Rust core + OS webview) | Free, open-source |
| Frontend | React + TypeScript, TailwindCSS, Shadcn/UI, Deck.gl | Free, open-source |
| Backend | Rust (Docker API client, fs watcher, proxying) | Free |
| Container engine | Docker Community Edition | Free |
| Database | SQLite (WAL mode) | Free |
| Geolocation | MaxMind GeoLite2 (free license, offline `.mmdb`) | Free tier, requires free account |
| Threat intel | AbuseIPDB (free tier, 1,000 checks/day), VirusTotal (free tier, 4 req/min) | Free tier |
| Tunneling | **Self-hosted** FRP (`frps`/`frpc`) on your own VPS or home server | Free (you supply the host) |
| Secrets | OS keyring via Rust `keyring` crate (Windows Credential Manager / macOS Keychain / Linux Secret Service) | Free, built into OS |

No component requires a paid license. The only thing you must supply yourself is a small VPS or public IP to run `frps` — a free-tier cloud instance (e.g., Oracle Cloud's always-free tier) works fine for this.

---

## 3. USER INTERFACE

### 3.1 Standard Mode (Operator View)
- Fleet sidebar: live status per decoy (`ssh-decoy-01`, `smb-trap-02`, etc.)
- Command Center dashboard: 3D threat map (Deck.gl), live counters (active sessions, unique actors, payload interceptions), incident feed table (timestamp, source IP, geo, attack vector)
- 3-step deployment wizard: template → network binding → initialize

### 3.2 Advanced Mode (Analyst View)
- Network topology tuning: custom CIDR blocks, `macvlan` attachments
- Honeywall rules engine: outbound throttling, packet filtering sliders
- Forensic inspector: hex viewer for PCAPs, SHA-256 panel (hash-only by default — see §5.3)

---

## 4. BACKEND SPECIFICATIONS (Rust IPC)

### 4.1 Container Lifecycle (`src-tauri/src/docker.rs`)
- `deploy_decoy(template_type, port_mapping)` — pulls images, builds isolated bridge networks, mounts persistent volumes
- `terminate_decoy(container_id)` — graceful stop + removal
- `get_fleet_telemetry()` — **event-driven, not polled** (see §5.2)

### 4.2 Threat Intel Pipeline (`src-tauri/src/pipeline.rs`)
- `watch_target_logs(path)` — uses `notify` crate to parse `cowrie.json` / `dionaea.sqlite` on write
- `enrich_threat_data(ip_address, file_hash)`:
  1. Resolve geolocation locally via MaxMind DB (no external call, no rate limit)
  2. Query AbuseIPDB for IP reputation
  3. Query VirusTotal by **hash only** by default (see §5.3)

### 4.3 Data Layer (`src-tauri/src/db.rs`)
- SQLite opened in **WAL mode** (`PRAGMA journal_mode=WAL;`) to avoid writer lock contention as session volume grows
- Indexes on `(timestamp)`, `(source_ip)`, `(container_id)` from day one — added retroactively is painful once tables are large
- Retention policy (configurable, default 90 days): a scheduled job prunes raw session rows past the window but keeps aggregated daily stats indefinitely

---

## 5. GAPS CLOSED FROM v1

### 5.1 Tunneling — self-hosted only, hardened
The original "free cloud relay" language was vague and risky. Fixed spec:
- Run `frps` on infrastructure **you control** — never the public frp demo server.
- `frpc` ↔ `frps` connection uses TLS (`transport.tls.enable = true`) and a shared auth token (`auth.method = token`).
- Rate-limit and bandwidth-cap each proxied port at the `frps` config level so a compromised or misbehaving decoy cannot be leveraged as a DDoS reflector or pivot back toward your real infrastructure.
- Decoy containers have **no outbound route** except through the air-gapped bridge network in §5.4 — they cannot reach `frps` directly, only inbound traffic is relayed to them.

### 5.2 Telemetry — event-driven, not polled
`get_fleet_telemetry()` now subscribes to the Docker Events API (`/events` endpoint) instead of polling on an interval. This scales cleanly to dozens of decoys without a growing background poll loop, and surfaces state changes (OOM kill, crash, restart) immediately instead of on the next poll tick.

### 5.3 Malware handling — never touches the host filesystem in executable form
- Quarantine step retained: captured binaries are `chmod 000`'d and suffixed `.isolated` immediately on capture.
- **New rule:** VirusTotal lookups default to **hash-only** submission (SHA-256), never full-file upload, unless the operator explicitly opts in per-file via the Forensic Inspector. This avoids silently uploading captured malware samples to a third party and avoids any local execution path.
- The hex viewer opens files as read-only byte streams; the UI never calls an OS "open with" or execute action on a captured sample.

### 5.4 Network isolation, made explicit
1. **Socket proxying:** `/var/run/docker.sock` is never exposed to the frontend or to decoy containers; all commands route through a restricted local proxy.
2. **Air-gapped bridge networks:** each decoy gets its own isolated Docker bridge network with no route to the host's LAN or to other decoys.
3. **Egress denial by default:** decoy containers have outbound traffic blocked at the bridge/firewall level unless a rule explicitly allows it (useful for observing C2 callback attempts safely, but off by default).

### 5.5 Lifecycle policy on abnormal exit
- Default: on unexpected container exit, DecoyOps logs the event, alerts in the Command Center feed, and does **not** auto-restart (prevents restart-loop noise if a decoy is being actively exploited into a crash state).
- Operator-configurable per-decoy: "auto-restart with backoff" is available as an opt-in toggle in Advanced Mode.

---

## 6. SECURITY & ISOLATION SUMMARY

1. Socket proxying — no direct Docker socket exposure
2. Automated quarantine — permission-stripped, non-executable, hash-only external lookups
3. Air-gapped per-decoy networks — no lateral traversal
4. Self-hosted, TLS-authenticated FRP tunnel with rate limiting
5. Secrets in OS keyring, never in source or plaintext config
6. Event-driven telemetry (no unbounded polling growth)
7. Configurable retention + no silent auto-restart on crash

---

## 7. WHAT YOU STILL NEED TO DECIDE (not a flaw, just open design choices)

- Retention window default (90 days suggested above) — adjust to your storage budget.
- Whether to enable egress-allow rules for C2 observation (off by default; a deliberate research choice, not something to flip on casually).
- Which decoy templates ship by default vs. are pulled on demand (affects first-run disk footprint).
