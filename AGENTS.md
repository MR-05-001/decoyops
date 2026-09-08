# AGENTS.md — DecoyOps

Standing instructions for any agent working in this workspace. Read this before planning or writing code. Treat every constraint below as non-negotiable unless the operator explicitly overrides it in a direct instruction.

## What we're building
A native desktop app (Tauri 2.0 + Rust core, React/TS frontend) that deploys, manages, and monitors Docker-based network honeypots (Cowrie, Dionaea) with a zero-trust, air-gapped security posture. Full spec: see `docs/blueprint-v2.md` and `docs/blueprint-v3-hardening.md` in this repo.

## Stack (do not substitute without asking)
- Desktop shell: Tauri 2.0
- Frontend: React + TypeScript, TailwindCSS, Shadcn/UI, Deck.gl
- Backend: Rust (docker.rs, pipeline.rs, db.rs, quarantine.rs)
- DB: SQLite, WAL mode, `busy_timeout=5000`, single-writer-thread pattern
- Container engine: Docker CE
- Geolocation: MaxMind GeoLite2, refreshed via `geoipupdate`, never a hand-rolled downloader
- Threat intel: AbuseIPDB + VirusTotal, free tier — see rate-limit rule below
- Tunneling: self-hosted FRP only. Never point `frpc` at a public/demo `frps` server.
- Secrets: OS keyring via the `keyring` crate. Never in source, config files, or logs.

## Hard constraints (violating these is a bug, not a style choice)

1. **No direct Docker socket exposure.** All container operations route through the restricted proxy in `docker.rs`. Never let the frontend or a decoy container touch `/var/run/docker.sock` directly.
2. **Captured binaries are never executed, ever, on the host.** On capture: `chmod 000` + `.isolated` suffix immediately. VirusTotal submissions are hash-only (SHA-256) by default; full-file upload requires an explicit per-file operator opt-in in the UI, never a default code path.
3. **Egress-deny by default per decoy.** Every new decoy's bridge subnet gets an explicit `nftables` drop rule at deploy time (see blueprint v3 §6). Any accept rule must be scoped to a single container IP and only exists if the operator has enabled "C2 observation mode" for that specific decoy — never subnet-wide, never default-on.
4. **Tauri IPC surface is an explicit allowlist.** No `shell:allow-execute`. No unscoped `fs:allow-write`. Every Docker/DB/network action is a narrow named command (`deploy_decoy`, `terminate_decoy`, etc.) defined in `src-tauri/capabilities/`, not a generic exec bridge.
5. **Telemetry is event-driven + reconciled**, not polled on a tight loop. Subscribe to the Docker Events API; also run a 60s reconciliation pass as a drift backstop (blueprint v3 §1).
6. **Rate-limit third-party lookups.** AbuseIPDB/VirusTotal calls go through a dedup + token-bucket queue (`governor` crate), never a direct call per event. Repeat IPs/hashes within 24h are served from cache, not re-queried.
7. **No auto-restart on abnormal container exit by default.** Log + alert only, unless the operator has opted in per-decoy to auto-restart-with-backoff.

## Architecture decision records

### ADR-001: Docker socket access model (decided 2026-09-06)

**Context:** Hard constraint #1 requires "no direct Docker socket exposure." Blueprint v2 §5.4 references a "restricted local proxy." The question is whether this proxy is an in-process Rust module boundary or a separate container/process (e.g., Tecnativa/docker-socket-proxy) that filters Docker API calls at the network level.

**Decision — v1: in-process encapsulation via `DockerProxy` struct in `docker.rs`.**

- `docker.rs` is the **only** module that imports `bollard` or holds a Docker client handle.
- `bollard::Docker` lives as a **private field** on `pub struct DockerProxy` — no other module can extract or borrow it.
- Bollard connects directly to the Docker daemon (Unix socket on Linux/macOS, named pipe on Windows). There is no separate proxy process.
- `commands.rs` is a thin relay that calls `DockerProxy` methods by name; it never constructs bollard types.
- Container creates will never bind-mount `/var/run/docker.sock`; enforced with a `debug_assert!`.

**Scope of protection:**

- ✅ **Webview-origin attacks** (XSS, malicious frontend code): blocked by the Tauri IPC allowlist + in-process module boundary. The webview can only reach Docker through named Tauri commands.
- ❌ **Full process compromise** (RCE in the Rust backend, dependency supply chain attack): the attacker is in the same PID and can access the socket directly despite the `private` field. On a desktop app, this attacker also has the user's OS permissions and could bypass or kill any local socket proxy anyway.

**Future hardening (v2+):** Add a Tecnativa/docker-socket-proxy-style container as a second, independent layer. The upgrade path is a one-line transport swap: `Docker::connect_with_local_defaults()` → `Docker::connect_with_http("http://127.0.0.1:2375")` in `DockerProxy::connect()`. The rest of the codebase doesn't change because all Docker access is already funneled through `docker.rs`.

### ADR-002: Egress-Deny Firewall Abstraction (decided 2026-09-06)

**Context:** Hard constraint #3 requires explicit egress-deny rules for each decoy's bridge network (blueprint v3 §6 specifies `nftables`). Since the app runs natively on Windows as well as Linux, we cannot rely solely on `nftables`.

**Decision:**
- Firewall logic is abstracted behind a `FirewallBackend` trait.
- **Linux:** Uses the `nftables` backend per the blueprint.
- **Windows:** Egress-deny is a documented, known gap until a WFP (Windows Filtering Platform) backend is implemented.
- **Enforcement:** Until the WFP backend lands, `deploy_decoy()` on Windows must return a loud, explicit error (or deploy with a persistent UI warning) stating that HC#3 is not enforced. It cannot deploy silently as if the network is fully air-gapped.

---

## Coding standards
- Rust: `cargo fmt` + `cargo clippy -- -D warnings` must pass before any commit.
- All async I/O (Docker API, DB, HTTP) uses `tokio`.
- No `unwrap()` in code paths that touch network input, container state, or captured file contents — use proper `Result` propagation. `unwrap()` is acceptable only in tests or on values proven infallible by prior checks.
- Frontend: functional React components, Tailwind utility classes only (no arbitrary inline styles unless justified in a comment).

## Working mode
- Use **Plan mode** for anything touching `docker.rs`, `pipeline.rs`, the Tauri capabilities file, or the nftables rule generation — these are the security-critical paths. Produce a plan artifact and wait for review before executing.
- Fast mode is fine for UI-only changes (Shadcn components, dashboard layout, Deck.gl map styling) that don't touch permissions, sockets, or network rules.
- When a task would require relaxing any constraint in the "Hard constraints" section above, stop and ask rather than proceeding — don't silently loosen a security control to make a feature easier to ship.

## Free-tier awareness
Everything in this stack is free or free-tier by design (see blueprint v2 §2). If an agent's implementation approach would require a paid API, paid cloud service, or paid library license, flag it instead of adding it — there's almost certainly a free alternative already specified in the blueprint docs.
