# DecoyOps Blueprint v3 — Implementation-Level Hardening Addendum

*Extends v2. Each item below is the specific fix for a gap flagged as "design decision, not yet implementation-proof." Still free/open-source throughout.*

---

## 1. Telemetry: event-driven + reconciliation safety net

Pure event-streaming can silently miss events (dropped connection, daemon restart mid-stream). Fix: keep the Docker Events subscription as the primary path, add a cheap reconciliation poll as a backstop.

```rust
// src-tauri/src/docker.rs

// Primary: live event stream
async fn watch_events(docker: Docker, tx: Sender<FleetEvent>) {
    let mut stream = docker.events(Some(EventsOptions {
        filters: hashmap!{"type" => vec!["container"]},
        ..Default::default()
    }));
    while let Some(event) = stream.next().await {
        if let Ok(ev) = event {
            tx.send(FleetEvent::from_docker(ev)).await.ok();
        }
        // on stream error/close, fall through to reconnect loop below
    }
}

// Backstop: reconcile actual state every 60s regardless of event stream health
async fn reconcile_loop(docker: Docker, tx: Sender<FleetEvent>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        if let Ok(containers) = docker.list_containers::<String>(None).await {
            tx.send(FleetEvent::Reconcile(containers)).await.ok();
        }
    }
}
```

The UI merges both: event stream gives near-real-time updates, reconciliation corrects any drift within 60s worst case. If the event stream disconnects, wrap it in a reconnect-with-backoff loop (1s, 2s, 4s... capped at 30s) so it self-heals without crashing the backend.

---

## 2. FRP host hardening checklist (concrete, not just "harden it")

Applies to whatever free-tier VPS runs `frps` (e.g., Oracle Cloud Free Tier, a spare home server, etc.):

- [ ] SSH: key-only auth, `PasswordAuthentication no`, non-standard port, `fail2ban` installed
- [ ] Firewall (`ufw` or `nftables`): default deny inbound; allow only the `frps` bind port + SSH port
- [ ] `frps.toml`: `auth.method = "token"` with a token generated via `openssl rand -hex 32`, rotated quarterly
- [ ] `frps.toml`: `transport.tls.enable = true`, TLS cert from Let's Encrypt (free) via `certbot`
- [ ] Per-proxy `bandwidthLimit` set in `frps.toml` (e.g., `1MB` per decoy proxy) so no single decoy can saturate the link
- [ ] Unattended security updates enabled (`unattended-upgrades` on Debian/Ubuntu — free, built-in)
- [ ] `frps` runs as an unprivileged user, not root, via systemd `User=` directive

This turns "harden the box" from a vague instruction into a checklist someone can actually tick off in an afternoon.

---

## 3. MaxMind GeoLite2 auto-refresh

MaxMind requires a free account and periodic re-download (license key, not a one-time file). Automate it instead of relying on manual memory:

```bash
# /etc/cron.weekly/update-geolite2 (or a Tauri background job on app launch if offline-first)
#!/bin/bash
GEOIPUPDATE_ACCOUNT_ID="<free account id>" \
GEOIPUPDATE_LICENSE_KEY="<free license key>" \
geoipupdate -f /etc/GeoIP.conf -d /var/lib/GeoIP
```

Use MaxMind's own `geoipupdate` tool (free, open-source) rather than a hand-rolled downloader — it handles the checksum verification and versioning correctly. DecoyOps's Rust backend just reads whatever `.mmdb` is currently on disk; it doesn't need to know a refresh happened.

---

## 4. Rate-limit handling for AbuseIPDB / VirusTotal (free tiers)

Free tiers: AbuseIPDB ~1,000 checks/day, VirusTotal ~4 requests/min. A busy honeypot will exceed both fast. Fix: a bounded queue with dedup + backoff instead of firing a request per event.

```rust
// src-tauri/src/pipeline.rs

struct EnrichmentQueue {
    seen: LruCache<String, Instant>,   // dedup: don't re-check same IP/hash within 24h
    queue: VecDeque<EnrichRequest>,
}

async fn enrichment_worker(mut q: EnrichmentQueue, vt_limiter: RateLimiter, abuse_limiter: RateLimiter) {
    loop {
        if let Some(req) = q.queue.pop_front() {
            if q.seen.contains(&req.key()) { continue; } // skip duplicate lookups
            match req.kind {
                Kind::Ip => { abuse_limiter.wait().await; /* call AbuseIPDB */ }
                Kind::Hash => { vt_limiter.wait().await; /* call VirusTotal, hash only */ }
            }
            q.seen.put(req.key(), Instant::now());
        } else {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}
```

- `RateLimiter` = a simple token-bucket (the `governor` crate, free, does this in a few lines).
- Dedup means a repeat scanner IP hitting the honeypot 500 times in an hour only triggers one AbuseIPDB call, not 500 — this alone solves most of the quota pressure.
- When the daily AbuseIPDB quota is exhausted, the UI shows "reputation lookup pending" instead of blocking or dropping the event — enrichment just catches up next day.

---

## 5. SQLite concurrency under load

WAL mode alone isn't enough once write volume is high — you also need a busy timeout and a single-writer pattern so concurrent inserts don't throw `SQLITE_BUSY`.

```rust
// src-tauri/src/db.rs
let conn = Connection::open("decoyops.db")?;
conn.pragma_update(None, "journal_mode", "WAL")?;
conn.pragma_update(None, "synchronous", "NORMAL")?;   // safe with WAL, much faster than FULL
conn.pragma_update(None, "busy_timeout", 5000)?;      // wait up to 5s instead of erroring immediately
```

- **Single writer thread pattern:** route all inserts through one dedicated tokio task with an `mpsc` channel, rather than letting every log-watcher fire its own write. SQLite handles one writer cleanly; many concurrent writers is where contention actually comes from, WAL mode doesn't remove that constraint entirely.
- Reads (for the UI dashboard) can happen on separate connections concurrently — WAL mode's real benefit is readers not blocking on the writer.

---

## 6. Egress-deny firewall rules (concrete nftables, not just "block it")

Each decoy's bridge network gets an explicit deny-by-default egress rule rather than relying on Docker's default network behavior:

```bash
# Applied per decoy bridge network at deploy_decoy() time
nft add table inet decoyops
nft add chain inet decoyops decoy_egress { type filter hook forward priority 0 \; policy drop \; }

# Default: drop all egress from decoy subnet
nft add rule inet decoyops decoy_egress ip saddr 172.20.0.0/24 drop

# Opt-in rule, only added if operator enables "C2 observation mode" for that decoy
nft add rule inet decoyops decoy_egress ip saddr 172.20.0.5 tcp dport {80,443} accept
```

`deploy_decoy()` writes the base drop rule automatically for every new decoy's subnet. The opt-in accept rule is only inserted if the operator flips the toggle mentioned in v2 §7, and it's scoped to that one container's IP, not the whole subnet.

---

## 7. Tauri IPC permission scoping

Left implicit in v1/v2. Fix: an explicit capability allowlist so the webview can only invoke the specific commands it needs, nothing else.

```json
// src-tauri/capabilities/main.json
{
  "identifier": "main-window",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "shell:allow-open",
    { "identifier": "fs:allow-read", "allow": [{ "path": "$APPDATA/decoyops/logs/*" }] }
  ]
}
```

- No `shell:allow-execute`, no unscoped `fs:allow-write` — the frontend can never ask the OS to run an arbitrary binary or write outside the app's own data directory.
- Docker/DB/network operations are exposed as narrow, named Tauri commands (`deploy_decoy`, `terminate_decoy`, etc.) — the webview never gets a generic "run this shell command" bridge, even for convenience.

---

## Status after this pass

| Area | v2 state | v3 fix |
|---|---|---|
| Telemetry drift | Assumed pure event stream | Event stream + 60s reconciliation backstop |
| VPS security | "Harden it" | Concrete checklist, all free tools |
| GeoLite2 staleness | Not addressed | Automated weekly refresh via `geoipupdate` |
| API quota exhaustion | Not addressed | Dedup + token-bucket queue |
| SQLite contention | WAL only | WAL + busy_timeout + single-writer pattern |
| Egress control | "Denied by default" (vague) | Explicit nftables rules, opt-in scoped to single IP |
| IPC surface | Not addressed | Explicit Tauri capability allowlist, no shell exec |

This is still a design document, not a tested binary — the remaining honest gap is that none of this has been run under real load. But every item you'd hit first in implementation now has a concrete answer instead of a hand-wave.
