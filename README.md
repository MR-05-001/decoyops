# DecoyOps

[![Build Status](https://github.com/MR-05-001/decoyops/actions/workflows/release.yml/badge.svg)](https://github.com/MR-05-001/decoyops/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tauri](https://img.shields.io/badge/Tauri-2.0-F24E1E?logo=tauri&logoColor=white)](https://tauri.app/)

> **DecoyOps** is a zero-trust, air-gapped desktop application designed to deploy, manage, and monitor network honeypots (decoys) using Docker. Built on a Tauri 2.0 (Rust) backend and a React (TypeScript) frontend, it provides enterprise-grade threat intelligence and deception technology from a standalone desktop environment.

---

## 1. Architecture Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend** | React, TypeScript, TailwindCSS, Deck.gl | UI rendering, state management, and real-time threat mapping |
| **Backend Core** | Rust (Tauri 2.0) | High-performance IPC bridge, OS-level execution, and system tray |
| **Containerization** | Docker CE | Honeypot orchestration via the Rust `bollard` client proxy |
| **Database** | SQLite | `busy_timeout=5000` WAL mode for concurrent, async data storage |
| **Telemetry** | `tokio` (Async Rust) | Event-driven architecture utilizing MPSC channels for log parsing |

---

## 2. Key Features

**1-Click Honeypot Deployment**
Deploy industry-standard honeypots (such as Cowrie SSH/Telnet and Dionaea Malware Capture) securely via an intuitive UI without writing complex compose files.

**Zero-Trust Docker Architecture**
Containers are restricted with `cap-drop ALL`, strictly whitelisted capabilities, and isolated IPC bridging. Direct Docker socket exposure (`/var/run/docker.sock`) is strictly prohibited by the architecture.

**Encrypted Tunneling (FRP)**
Native support for Fast Reverse Proxy (FRP) with TLS encryption. Route external attacker traffic through a cloud VPS directly into your local decoys without exposing your internal local network.

**Real-time Threat Intelligence**
Automated IP geolocation via MaxMind GeoLite2 and threat scoring through integrated AbuseIPDB and VirusTotal lookup pipelines.

---

## 3. Security Hardening Constraints

DecoyOps is built around strict security mandates to ensure the host machine is never compromised by the deception environment:

1. **Never Execute Captures:** Malware captures are immediately assigned `chmod 000` and suffixed with `.isolated` upon entering the host filesystem.
2. **Egress-Deny by Default:** Decoy bridge subnets drop all outbound traffic (enforced via `nftables` on Linux environments).
3. **Restricted Shell Execution:** The Tauri IPC exclusively utilizes a pre-defined allowlist of commands. No generic `shell:allow-execute` or `fs:allow-write` privileges exist.
4. **Token Bucket Rate Limiting:** Third-party API calls (AbuseIPDB/VirusTotal) are tightly rate-limited and cached to prevent API abuse and respect free-tier provider limits.

---

## 4. Installation & Setup

### Prerequisites
Before compiling DecoyOps from source, ensure the following dependencies are installed in your environment:
* **Node.js** (v20 or newer)
* **Rust** (Stable toolchain via `rustup`)
* **Docker CE** (Running and accessible to your user context)

**Linux Only:** OS-specific build tools are required. For Ubuntu/Debian distributions, run:
```bash
sudo apt update
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

### Build Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MR-05-001/decoyops.git
   cd decoyops
   ```

2. **Install frontend dependencies:**
   ```bash
   npm install
   ```

3. **Run in Development Mode:**
   ```bash
   npm run tauri dev
   ```

4. **Build for Production (Release):**
   ```bash
   npm run tauri build
   ```
   *The compiled installer (e.g., `.msi` / `.exe` on Windows, `.deb` / `.AppImage` on Linux) will be output to the `src-tauri/target/release/bundle/` directory.*

---

## 5. Automated CI/CD (GitHub Actions)

This repository includes a `.github/workflows/release.yml` pipeline. When a new git tag (e.g., `v1.0.0`) is pushed to the repository, GitHub Actions will automatically provision Windows, macOS, and Linux runners, build the application natively for each platform, and attach the resulting cross-platform installers to a new GitHub Release.

---

## 6. Documentation

For deeper architectural insights, system diagrams, and design decisions, please review the documentation in the `docs/` directory:
* `docs/blueprint-v2.md`: Core application specification and data models.
* `docs/blueprint-v3-hardening.md`: Egress firewall, tunneling, and capability-drop specifications.

## 7. License

This project is licensed under the MIT License.
