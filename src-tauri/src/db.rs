//! SQLite data layer — blueprint v2 §4.3, v3 §5.
//!
//! Hardening pragmas applied at connection time:
//! - WAL journal mode (readers don't block on the writer)
//! - `synchronous = NORMAL` (safe with WAL, much faster than FULL)
//! - `busy_timeout = 5000` (wait up to 5s instead of erroring immediately)
//!
//! Write concurrency is managed via the **single-writer-task pattern**:
//! all inserts are routed through one dedicated tokio task with an `mpsc`
//! channel, so SQLite only ever sees one writer. Reads (for the UI dashboard)
//! can happen on separate connections concurrently.

#![allow(dead_code)]

use rusqlite::{params, Connection};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

// ---------------------------------------------------------------------------
// Schema SQL
// ---------------------------------------------------------------------------

const SCHEMA_V1: &str = r#"
-- Registered decoy containers
CREATE TABLE IF NOT EXISTS decoys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id    TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    template_type   TEXT NOT NULL,
    port_mapping    TEXT NOT NULL,
    bridge_network  TEXT,
    subnet_cidr     TEXT,
    state           TEXT NOT NULL DEFAULT 'created',
    auto_restart    INTEGER NOT NULL DEFAULT 0,
    c2_observe_mode INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Honeypot sessions (one per attacker connection)
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    decoy_id        INTEGER NOT NULL REFERENCES decoys(id),
    container_id    TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    source_port     INTEGER,
    protocol        TEXT,
    geo_country     TEXT,
    geo_city        TEXT,
    geo_lat         REAL,
    geo_lon         REAL,
    started_at      TEXT NOT NULL DEFAULT (datetime('now')),
    ended_at        TEXT
);

-- Individual events within a session
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id),
    container_id    TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    source_ip       TEXT,
    attack_vector   TEXT,
    raw_data        TEXT,
    timestamp       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Quarantined captured files (HC#2: never executed, hash-only VT by default)
CREATE TABLE IF NOT EXISTS captured_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER REFERENCES sessions(id),
    container_id    TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    original_name   TEXT,
    file_size       INTEGER,
    isolated_path   TEXT NOT NULL,
    vt_status       TEXT DEFAULT 'pending',
    vt_result_json  TEXT,
    operator_upload_consent INTEGER NOT NULL DEFAULT 0,
    captured_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Threat intel lookup cache (24h dedup — blueprint v3 §4)
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    key             TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    result_json     TEXT NOT NULL,
    queried_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Aggregated daily stats (survive retention pruning — blueprint v2 §4.3)
CREATE TABLE IF NOT EXISTS daily_stats (
    date            TEXT PRIMARY KEY,
    total_sessions  INTEGER NOT NULL DEFAULT 0,
    unique_ips      INTEGER NOT NULL DEFAULT 0,
    payloads_captured INTEGER NOT NULL DEFAULT 0,
    events_count    INTEGER NOT NULL DEFAULT 0
);

-- App settings (retention window, etc.)
CREATE TABLE IF NOT EXISTS settings (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);
INSERT OR IGNORE INTO settings (key, value) VALUES ('retention_days', '90');

-- Indexes: blueprint v2 §4.3 says "from day one"
CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_container_id ON sessions(container_id);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_container_id ON events(container_id);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);

CREATE INDEX IF NOT EXISTS idx_captured_files_sha256 ON captured_files(sha256);
CREATE INDEX IF NOT EXISTS idx_captured_files_container_id ON captured_files(container_id);

CREATE INDEX IF NOT EXISTS idx_threat_cache_queried_at ON threat_intel_cache(queried_at);
"#;

const SCHEMA_V2: &str = r#"
ALTER TABLE sessions ADD COLUMN ssh_client_version TEXT;
ALTER TABLE sessions ADD COLUMN ja3_fingerprint TEXT;
ALTER TABLE sessions ADD COLUMN tty_log_path TEXT;
ALTER TABLE events ADD COLUMN mitre_ttp TEXT;
ALTER TABLE decoys ADD COLUMN realism_score INTEGER;
ALTER TABLE decoys ADD COLUMN tunnel_public_url TEXT;
ALTER TABLE decoys ADD COLUMN tunnel_provider TEXT;
ALTER TABLE decoys ADD COLUMN tunnel_remote_port INTEGER;
ALTER TABLE decoys ADD COLUMN tunnel_pid INTEGER;

INSERT OR IGNORE INTO settings (key, value) VALUES ('webhook_url', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('webhook_vt_threshold', '5');
"#;

const SCHEMA_V3: &str = r#"
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    container_id TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    extracted_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_iocs_container ON iocs(container_id);
"#;

// ---------------------------------------------------------------------------
// Connection setup
// ---------------------------------------------------------------------------

/// Opens the SQLite database with the hardening pragmas from blueprint v3 §5,
/// then runs any pending schema migrations.
///
/// # Errors
///
/// Returns an error if the database file cannot be opened, if any
/// pragma fails to apply, or if migrations fail.
pub fn open_database(path: &str) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    run_migrations(&conn)?;
    Ok(conn)
}

/// Applies schema migrations using the `user_version` pragma for versioning.
/// This avoids a heavy migration framework (free-tier constraint) while
/// being safe for schema evolution.
fn run_migrations(conn: &Connection) -> Result<(), rusqlite::Error> {
    let version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if version < 1 {
        conn.execute_batch(SCHEMA_V1)?;
        conn.pragma_update(None, "user_version", 1)?;
    }
    if version < 2 {
        conn.execute_batch(SCHEMA_V2)?;
        conn.pragma_update(None, "user_version", 2)?;
    }
    if version < 3 {
        conn.execute_batch(SCHEMA_V3)?;
        conn.pragma_update(None, "user_version", 3)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Row structs (returned to frontend via Tauri IPC)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DecoyRow {
    pub id: i64,
    pub container_id: String,
    pub name: String,
    pub template_type: String,
    pub port_mapping: String,
    pub bridge_network: Option<String>,
    pub subnet_cidr: Option<String>,
    pub state: String,
    pub auto_restart: bool,
    pub c2_observe_mode: bool,
    pub created_at: String,
    pub updated_at: String,
    pub realism_score: Option<i32>,
    pub tunnel_public_url: Option<String>,
    pub tunnel_provider: Option<String>,
    pub tunnel_remote_port: Option<u16>,
    pub tunnel_pid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SessionRow {
    pub id: i64,
    pub decoy_id: i64,
    pub container_id: String,
    pub source_ip: String,
    pub source_port: Option<i32>,
    pub protocol: Option<String>,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_lat: Option<f64>,
    pub geo_lon: Option<f64>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub ssh_client_version: Option<String>,
    pub ja3_fingerprint: Option<String>,
    pub tty_log_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EventRow {
    pub id: i64,
    pub session_id: i64,
    pub container_id: String,
    pub event_type: String,
    pub source_ip: Option<String>,
    pub attack_vector: Option<String>,
    pub raw_data: Option<String>,
    pub timestamp: String,
    pub geo_lat: Option<f64>,
    pub geo_lon: Option<f64>,
    pub mitre_ttp: Option<String>,
    pub tty_log_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IocRow {
    pub id: i64,
    pub session_id: Option<i64>,
    pub container_id: String,
    pub ioc_type: String,
    pub ioc_value: String,
    pub extracted_at: String,
}

#[derive(Debug, Serialize)]
pub struct CapturedFileRow {
    pub id: i64,
    pub session_id: Option<i64>,
    pub container_id: String,
    pub sha256: String,
    pub original_name: Option<String>,
    pub file_size: Option<i64>,
    pub isolated_path: String,
    pub vt_status: Option<String>,
    pub vt_result_json: Option<String>,
    pub operator_upload_consent: bool,
    pub captured_at: String,
}

#[derive(Debug, Serialize)]
pub struct DailyStatRow {
    pub date: String,
    pub total_sessions: i64,
    pub unique_ips: i64,
    pub payloads_captured: i64,
    pub events_count: i64,
}

#[derive(Debug, Serialize)]
pub struct DashboardCounters {
    pub active_decoys: i64,
    pub active_sessions: i64,
    pub unique_actors: i64,
    pub payloads_captured: i64,
    pub total_events: i64,
}

// ---------------------------------------------------------------------------
// Single-writer task (blueprint v3 §5)
// ---------------------------------------------------------------------------

/// Message type for the single-writer channel.
pub enum DbCommand {
    /// Register a new decoy in the database.
    InsertDecoy {
        container_id: String,
        name: String,
        template_type: String,
        port_mapping: String,
        bridge_network: Option<String>,
        subnet_cidr: Option<String>,
        realism_score: Option<i32>,
        tunnel_public_url: Option<String>,
        tunnel_provider: Option<String>,
        tunnel_remote_port: Option<u16>,
        tunnel_pid: Option<u32>,
    },
    /// Update a decoy's state (running, stopped, exited, error).
    UpdateDecoyState { container_id: String, state: String },
    /// Remove a decoy record (after terminate_decoy).
    DeleteDecoy { container_id: String },
    /// Insert a new honeypot session. Returns the inserted row ID via oneshot.
    InsertSession {
        container_id: String,
        source_ip: String,
        source_port: Option<i32>,
        protocol: Option<String>,
        geo_country: Option<String>,
        geo_city: Option<String>,
        geo_lat: Option<f64>,
        geo_lon: Option<f64>,
        reply: oneshot::Sender<Result<i64, String>>,
    },
    /// Insert an event within a session.
    InsertEvent {
        session_id: i64,
        container_id: String,
        event_type: String,
        source_ip: Option<String>,
        attack_vector: Option<String>,
        raw_data: Option<String>,
        mitre_ttp: Option<String>,
    },
    /// Update a session with fingerprinting and TTY info.
    UpdateSessionFingerprint {
        session_id: i64,
        ssh_client_version: Option<String>,
        ja3_fingerprint: Option<String>,
        tty_log_path: Option<String>,
    },
    /// Record a captured file (HC#2: operator_upload_consent defaults to 0).
    InsertCapturedFile {
        session_id: Option<i64>,
        container_id: String,
        sha256: String,
        original_name: Option<String>,
        file_size: Option<i64>,
        isolated_path: String,
    },
    /// Cache a threat intel lookup result (24h dedup).
    CacheThreatIntel {
        key: String,
        kind: String,
        result_json: String,
    },
    /// Update a global setting.
    UpdateSetting { key: String, value: String },
    /// Prune old data past the retention window.
    Prune { retention_days: u32 },
    /// Record an extracted Indicator of Compromise (IoC).
    InsertIoc {
        session_id: Option<i64>,
        container_id: String,
        ioc_type: String,
        ioc_value: String,
    },
}

/// Spawns the single-writer task (blueprint v3 §5).
///
/// All inserts are routed through this task via an `mpsc` channel,
/// so SQLite only ever sees one writer — concurrent reads use separate
/// connections via [`open_database`].
///
/// Returns the sender half of the channel.
///
/// # Panics
///
/// Panics if the database cannot be opened. This is called once at app
/// startup, so a missing/corrupt DB file is a fatal error.
pub fn spawn_writer_task(db_path: String) -> mpsc::Sender<DbCommand> {
    let (tx, mut rx) = mpsc::channel::<DbCommand>(256);

    tauri::async_runtime::spawn(async move {
        let conn = open_database(&db_path).expect("failed to open database for writer task");

        while let Some(cmd) = rx.recv().await {
            if let Err(e) = handle_db_command(&conn, cmd) {
                eprintln!("db writer error: {e}");
            }
        }
    });

    tx
}

/// Process a single write command against the database.
fn handle_db_command(conn: &Connection, cmd: DbCommand) -> Result<(), rusqlite::Error> {
    match cmd {
        DbCommand::InsertDecoy {
            container_id,
            name,
            template_type,
            port_mapping,
            bridge_network,
            subnet_cidr,
            realism_score,
            tunnel_public_url,
            tunnel_provider,
            tunnel_remote_port,
            tunnel_pid,
        } => {
            conn.execute(
                "INSERT INTO decoys (container_id, name, template_type, port_mapping, bridge_network, subnet_cidr, realism_score, tunnel_public_url, tunnel_provider, tunnel_remote_port, tunnel_pid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![container_id, name, template_type, port_mapping, bridge_network, subnet_cidr, realism_score, tunnel_public_url, tunnel_provider, tunnel_remote_port, tunnel_pid],
            )?;
        }
        DbCommand::UpdateDecoyState {
            container_id,
            state,
        } => {
            conn.execute(
                "UPDATE decoys SET state = ?1, updated_at = datetime('now') WHERE container_id = ?2",
                params![state, container_id],
            )?;
        }
        DbCommand::DeleteDecoy { container_id } => {
            conn.execute(
                "UPDATE decoys SET state = 'deleted', updated_at = datetime('now') WHERE container_id = ?1",
                params![container_id],
            )?;
        }
        DbCommand::InsertSession {
            container_id,
            source_ip,
            source_port,
            protocol,
            geo_country,
            geo_city,
            geo_lat,
            geo_lon,
            reply,
        } => {
            let result = conn.execute(
                "INSERT INTO sessions (decoy_id, container_id, source_ip, source_port, protocol, geo_country, geo_city, geo_lat, geo_lon)
                 VALUES ((SELECT id FROM decoys WHERE container_id = ?1), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![container_id, source_ip, source_port, protocol, geo_country, geo_city, geo_lat, geo_lon],
            );
            let response = match result {
                Ok(_) => Ok(conn.last_insert_rowid()),
                Err(e) => Err(e.to_string()),
            };
            // Increment daily stats
            let _ = conn.execute(
                "INSERT INTO daily_stats (date, total_sessions, unique_ips, events_count)
                 VALUES (date('now'), 1, 1, 0)
                 ON CONFLICT(date) DO UPDATE SET
                     total_sessions = total_sessions + 1,
                     unique_ips = (SELECT COUNT(DISTINCT source_ip) FROM sessions WHERE date(started_at) = date('now'))",
                [],
            );
            let _ = reply.send(response);
        }
        DbCommand::InsertEvent {
            session_id,
            container_id,
            event_type,
            source_ip,
            attack_vector,
            raw_data,
            mitre_ttp,
        } => {
            conn.execute(
                "INSERT INTO events (session_id, container_id, event_type, source_ip, attack_vector, raw_data, mitre_ttp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![session_id, container_id, event_type, source_ip, attack_vector, raw_data, mitre_ttp],
            )?;
            // Increment daily event count
            let _ = conn.execute(
                "INSERT INTO daily_stats (date, total_sessions, unique_ips, events_count)
                 VALUES (date('now'), 0, 0, 1)
                 ON CONFLICT(date) DO UPDATE SET events_count = events_count + 1",
                [],
            );
        }
        DbCommand::UpdateSessionFingerprint {
            session_id,
            ssh_client_version,
            ja3_fingerprint,
            tty_log_path,
        } => {
            conn.execute(
                "UPDATE sessions SET ssh_client_version = COALESCE(?1, ssh_client_version),
                                     ja3_fingerprint = COALESCE(?2, ja3_fingerprint),
                                     tty_log_path = COALESCE(?3, tty_log_path)
                 WHERE id = ?4",
                params![ssh_client_version, ja3_fingerprint, tty_log_path, session_id],
            )?;
        }
        DbCommand::InsertCapturedFile {
            session_id,
            container_id,
            sha256,
            original_name,
            file_size,
            isolated_path,
        } => {
            conn.execute(
                "INSERT INTO captured_files (session_id, container_id, sha256, original_name, file_size, isolated_path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![session_id, container_id, sha256, original_name, file_size, isolated_path],
            )?;
            // Increment daily payload count
            let _ = conn.execute(
                "INSERT INTO daily_stats (date, total_sessions, unique_ips, payloads_captured, events_count)
                 VALUES (date('now'), 0, 0, 1, 0)
                 ON CONFLICT(date) DO UPDATE SET payloads_captured = payloads_captured + 1",
                [],
            );
        }
        DbCommand::CacheThreatIntel {
            key,
            kind,
            result_json,
        } => {
            conn.execute(
                "INSERT OR REPLACE INTO threat_intel_cache (key, kind, result_json, queried_at)
                 VALUES (?1, ?2, ?3, datetime('now'))",
                params![key, kind, result_json],
            )?;
        }
        DbCommand::UpdateSetting { key, value } => {
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
                params![key, value],
            )?;
        }
        DbCommand::Prune { retention_days } => {
            let cutoff = format!("-{retention_days} days");
            // Delete old events
            conn.execute(
                "DELETE FROM events WHERE timestamp < datetime('now', ?1)",
                params![cutoff],
            )?;
            // Delete old sessions
            conn.execute(
                "DELETE FROM sessions WHERE started_at < datetime('now', ?1)",
                params![cutoff],
            )?;
            // Delete old captured files records (the .isolated files on disk
            // must be cleaned up separately by the quarantine module)
            conn.execute(
                "DELETE FROM captured_files WHERE captured_at < datetime('now', ?1)",
                params![cutoff],
            )?;
            // Clear stale threat intel cache (24h)
            conn.execute(
                "DELETE FROM threat_intel_cache WHERE queried_at < datetime('now', '-1 day')",
                [],
            )?;
            // Delete old iocs
            conn.execute(
                "DELETE FROM iocs WHERE extracted_at < datetime('now', ?1)",
                params![cutoff],
            )?;
            // daily_stats are NOT pruned — they survive indefinitely (blueprint v2 §4.3)
        }
        DbCommand::InsertIoc {
            session_id,
            container_id,
            ioc_type,
            ioc_value,
        } => {
            conn.execute(
                "INSERT INTO iocs (session_id, container_id, ioc_type, ioc_value)
                 VALUES (?1, ?2, ?3, ?4)",
                params![session_id, container_id, ioc_type, ioc_value],
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Read helpers (open separate connections — WAL allows concurrent readers)
// ---------------------------------------------------------------------------

/// Get a global setting value.
pub fn get_setting(conn: &Connection, key: &str) -> Result<Option<String>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

/// Get the next available remote port for a tunnel within a given range.
pub fn get_next_available_remote_port(
    conn: &Connection,
    start_port: u16,
    end_port: u16,
) -> Result<Option<u16>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT tunnel_remote_port FROM decoys WHERE tunnel_remote_port IS NOT NULL ORDER BY tunnel_remote_port ASC")?;
    
    let used_ports: Result<Vec<u16>, _> = stmt
        .query_map([], |row| {
            let port: i64 = row.get(0)?;
            Ok(port as u16)
        })?
        .collect();
    
    let used_ports = used_ports?;
    
    for port in start_port..=end_port {
        if !used_ports.contains(&port) {
            return Ok(Some(port));
        }
    }
    
    Ok(None)
}

/// Get all registered decoys.
pub fn get_all_decoys(conn: &Connection) -> Result<Vec<DecoyRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
         "SELECT id, container_id, name, template_type, port_mapping, bridge_network,
                 subnet_cidr, state, auto_restart, c2_observe_mode, created_at, updated_at, realism_score,
                 tunnel_public_url, tunnel_provider, tunnel_remote_port, tunnel_pid
          FROM decoys WHERE state != 'deleted' ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(DecoyRow {
            id: row.get(0)?,
            container_id: row.get(1)?,
            name: row.get(2)?,
            template_type: row.get(3)?,
            port_mapping: row.get(4)?,
            bridge_network: row.get(5)?,
            subnet_cidr: row.get(6)?,
            state: row.get(7)?,
            auto_restart: row.get::<_, i32>(8)? != 0,
            c2_observe_mode: row.get::<_, i32>(9)? != 0,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
            realism_score: row.get(12)?,
            tunnel_public_url: row.get(13)?,
            tunnel_provider: row.get(14)?,
            tunnel_remote_port: row.get::<_, Option<i64>>(15)?.map(|v| v as u16),
            tunnel_pid: row.get::<_, Option<i64>>(16)?.map(|v| v as u32),
        })
    })?;
    rows.collect()
}

/// Get recent events for the incident feed table, including geo-coordinates.
pub fn get_recent_events(conn: &Connection, limit: u32) -> Result<Vec<EventRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.session_id, e.container_id, e.event_type, e.source_ip, e.attack_vector, e.raw_data, e.timestamp, e.mitre_ttp,
                s.geo_lat, s.geo_lon, s.tty_log_path
         FROM events e
         LEFT JOIN sessions s ON e.session_id = s.id
         ORDER BY e.timestamp DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit], |row| {
        Ok(EventRow {
            id: row.get(0)?,
            session_id: row.get(1)?,
            container_id: row.get(2)?,
            event_type: row.get(3)?,
            source_ip: row.get(4)?,
            attack_vector: row.get(5)?,
            raw_data: row.get(6)?,
            timestamp: row.get(7)?,
            mitre_ttp: row.get(8)?,
            geo_lat: row.get(9)?,
            geo_lon: row.get(10)?,
            tty_log_path: row.get(11)?,
        })
    })?;
    rows.collect()
}

/// Get daily stats for the specified number of recent days.
pub fn get_daily_stats(conn: &Connection, days: u32) -> Result<Vec<DailyStatRow>, rusqlite::Error> {
    let cutoff = format!("-{days} days");
    let mut stmt = conn.prepare(
        "SELECT date, total_sessions, unique_ips, payloads_captured, events_count
         FROM daily_stats WHERE date >= date('now', ?1) ORDER BY date DESC",
    )?;
    let rows = stmt.query_map(params![cutoff], |row| {
        Ok(DailyStatRow {
            date: row.get(0)?,
            total_sessions: row.get(1)?,
            unique_ips: row.get(2)?,
            payloads_captured: row.get(3)?,
            events_count: row.get(4)?,
        })
    })?;
    rows.collect()
}

/// Get sessions for a specific decoy.
pub fn get_sessions_for_decoy(
    conn: &Connection,
    container_id: &str,
) -> Result<Vec<SessionRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, decoy_id, container_id, source_ip, source_port, protocol,
                geo_country, geo_city, geo_lat, geo_lon, started_at, ended_at,
                ssh_client_version, ja3_fingerprint, tty_log_path
         FROM sessions WHERE container_id = ?1 ORDER BY started_at DESC",
    )?;
    let rows = stmt.query_map(params![container_id], |row| {
        Ok(SessionRow {
            id: row.get(0)?,
            decoy_id: row.get(1)?,
            container_id: row.get(2)?,
            source_ip: row.get(3)?,
            source_port: row.get(4)?,
            protocol: row.get(5)?,
            geo_country: row.get(6)?,
            geo_city: row.get(7)?,
            geo_lat: row.get(8)?,
            geo_lon: row.get(9)?,
            started_at: row.get(10)?,
            ended_at: row.get(11)?,
            ssh_client_version: row.get(12)?,
            ja3_fingerprint: row.get(13)?,
            tty_log_path: row.get(14)?,
        })
    })?;
    rows.collect()
}

/// Get all quarantined payloads.
pub fn get_quarantined_files(conn: &Connection) -> Result<Vec<CapturedFileRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, container_id, sha256, original_name, file_size,
                isolated_path, vt_status, vt_result_json, operator_upload_consent, captured_at
         FROM captured_files ORDER BY captured_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(CapturedFileRow {
            id: row.get(0)?,
            session_id: row.get(1)?,
            container_id: row.get(2)?,
            sha256: row.get(3)?,
            original_name: row.get(4)?,
            file_size: row.get(5)?,
            isolated_path: row.get(6)?,
            vt_status: row.get(7)?,
            vt_result_json: row.get(8)?,
            operator_upload_consent: row.get::<_, i32>(9)? != 0,
            captured_at: row.get(10)?,
        })
    })?;
    rows.collect()
}

/// Get dashboard counter values (live aggregates).
pub fn get_dashboard_counters(conn: &Connection) -> Result<DashboardCounters, rusqlite::Error> {
    let active_decoys: i64 = conn.query_row(
        "SELECT COUNT(*) FROM decoys WHERE state = 'running'",
        [],
        |row| row.get(0),
    )?;
    let active_sessions: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    let unique_actors: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT source_ip) FROM sessions",
        [],
        |row| row.get(0),
    )?;
    let payloads_captured: i64 =
        conn.query_row("SELECT COUNT(*) FROM captured_files", [], |row| row.get(0))?;
    let total_events: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
    Ok(DashboardCounters {
        active_decoys,
        active_sessions,
        unique_actors,
            payloads_captured,
        total_events,
    })
}

pub fn get_blocklist(conn: &Connection) -> Result<String, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT source_ip FROM sessions 
         WHERE started_at >= datetime('now', '-7 days') 
         AND source_ip IS NOT NULL 
         AND source_ip != ''",
    )?;
    
    let ips: Result<Vec<String>, _> = stmt.query_map([], |row| row.get(0))?.collect();
    let ips = ips?;
    
    Ok(ips.join("\n"))
}

// ---------------------------------------------------------------------------
// Quarantine & Settings
// ---------------------------------------------------------------------------

/// Get a specific session by its ID.
pub fn get_session_by_id(
    conn: &Connection,
    session_id: i64,
) -> Result<Option<SessionRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, decoy_id, container_id, source_ip, source_port, protocol,
                geo_country, geo_city, geo_lat, geo_lon, started_at, ended_at,
                ssh_client_version, ja3_fingerprint, tty_log_path
         FROM sessions WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![session_id], |row| {
        Ok(SessionRow {
            id: row.get(0)?,
            decoy_id: row.get(1)?,
            container_id: row.get(2)?,
            source_ip: row.get(3)?,
            source_port: row.get(4)?,
            protocol: row.get(5)?,
            geo_country: row.get(6)?,
            geo_city: row.get(7)?,
            geo_lat: row.get(8)?,
            geo_lon: row.get(9)?,
            started_at: row.get(10)?,
            ended_at: row.get(11)?,
            ssh_client_version: row.get(12)?,
            ja3_fingerprint: row.get(13)?,
            tty_log_path: row.get(14)?,
        })
    })?;
    
    if let Some(row) = rows.next() {
        row.map(Some)
    } else {
        Ok(None)
    }
}

/// Get all events for a specific session.
pub fn get_events_for_session(
    conn: &Connection,
    session_id: i64,
) -> Result<Vec<EventRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.session_id, e.container_id, e.event_type, e.source_ip,
                e.attack_vector, e.raw_data, e.timestamp, s.geo_lat, s.geo_lon,
                e.mitre_ttp, s.tty_log_path
         FROM events e
         LEFT JOIN sessions s ON e.session_id = s.id
         WHERE e.session_id = ?1
         ORDER BY e.timestamp ASC",
    )?;
    let rows = stmt.query_map(params![session_id], |row| {
        Ok(EventRow {
            id: row.get(0)?,
            session_id: row.get(1)?,
            container_id: row.get(2)?,
            event_type: row.get(3)?,
            source_ip: row.get(4)?,
            attack_vector: row.get(5)?,
            raw_data: row.get(6)?,
            timestamp: row.get(7)?,
            geo_lat: row.get(8)?,
            geo_lon: row.get(9)?,
            mitre_ttp: row.get(10)?,
            tty_log_path: row.get(11)?,
        })
    })?;
    rows.collect()
}

/// Get all captured files for a specific session.
pub fn get_captured_files_for_session(
    conn: &Connection,
    session_id: i64,
) -> Result<Vec<CapturedFileRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, container_id, sha256, original_name, file_size,
                isolated_path, vt_status, vt_result_json, operator_upload_consent, captured_at
         FROM captured_files WHERE session_id = ?1 ORDER BY captured_at ASC",
    )?;
    let rows = stmt.query_map(params![session_id], |row| {
        Ok(CapturedFileRow {
            id: row.get(0)?,
            session_id: row.get(1)?,
            container_id: row.get(2)?,
            sha256: row.get(3)?,
            original_name: row.get(4)?,
            file_size: row.get(5)?,
            isolated_path: row.get(6)?,
            vt_status: row.get(7)?,
            vt_result_json: row.get(8)?,
            operator_upload_consent: row.get::<_, i32>(9)? != 0,
            captured_at: row.get(10)?,
        })
    })?;
    rows.collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

pub fn get_recent_iocs(conn: &Connection, limit: u32) -> Result<Vec<IocRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, container_id, ioc_type, ioc_value, extracted_at
         FROM iocs
         ORDER BY extracted_at DESC
         LIMIT ?1",
    )?;

    let ioc_iter = stmt.query_map([limit], |row| {
        Ok(IocRow {
            id: row.get(0)?,
            session_id: row.get(1)?,
            container_id: row.get(2)?,
            ioc_type: row.get(3)?,
            ioc_value: row.get(4)?,
            extracted_at: row.get(5)?,
        })
    })?;

    let mut iocs = Vec::new();
    for i in ioc_iter {
        iocs.push(i?);
    }

    Ok(iocs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_database_sets_wal_mode() {
        let conn = open_database(":memory:").expect("failed to open in-memory db");
        let journal_mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("failed to query journal_mode");
        assert!(
            journal_mode == "wal" || journal_mode == "memory",
            "unexpected journal_mode: {journal_mode}"
        );
    }

    #[test]
    fn test_open_database_sets_busy_timeout() {
        let conn = open_database(":memory:").expect("failed to open in-memory db");
        let timeout: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .expect("failed to query busy_timeout");
        assert_eq!(timeout, 5000);
    }

    #[test]
    fn test_migrations_create_all_tables() {
        let conn = open_database(":memory:").expect("failed to open in-memory db");

        let tables: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect()
        };

        assert!(
            tables.contains(&"decoys".to_string()),
            "missing decoys table"
        );
        assert!(
            tables.contains(&"sessions".to_string()),
            "missing sessions table"
        );
        assert!(
            tables.contains(&"events".to_string()),
            "missing events table"
        );
        assert!(
            tables.contains(&"captured_files".to_string()),
            "missing captured_files table"
        );
        assert!(
            tables.contains(&"threat_intel_cache".to_string()),
            "missing threat_intel_cache table"
        );
        assert!(
            tables.contains(&"daily_stats".to_string()),
            "missing daily_stats table"
        );
        assert!(
            tables.contains(&"settings".to_string()),
            "missing settings table"
        );
    }

    #[test]
    fn test_schema_version_set() {
        let conn = open_database(":memory:").expect("failed to open in-memory db");
        let version: i32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("failed to query user_version");
        assert_eq!(version, 1);
    }

    #[test]
    fn test_insert_and_read_decoy() {
        let conn = open_database(":memory:").expect("failed to open in-memory db");

        conn.execute(
            "INSERT INTO decoys (container_id, name, template_type, port_mapping)
             VALUES ('abc123', 'ssh-decoy-01', 'cowrie', '2222:22')",
            [],
        )
        .expect("failed to insert decoy");

        let decoys = get_all_decoys(&conn).expect("failed to read decoys");
        assert_eq!(decoys.len(), 1);
        assert_eq!(decoys[0].container_id, "abc123");
        assert_eq!(decoys[0].name, "ssh-decoy-01");
        assert_eq!(decoys[0].template_type, "cowrie");
        assert_eq!(decoys[0].state, "created");
        assert!(!decoys[0].auto_restart);
        assert!(!decoys[0].c2_observe_mode);
    }

    #[test]
    fn test_dashboard_counters_empty() {
        let conn = open_database(":memory:").expect("failed to open in-memory db");
        let counters = get_dashboard_counters(&conn).expect("failed to get counters");
        assert_eq!(counters.active_decoys, 0);
        assert_eq!(counters.active_sessions, 0);
        assert_eq!(counters.unique_actors, 0);
        assert_eq!(counters.payloads_captured, 0);
        assert_eq!(counters.total_events, 0);
    }

    #[test]
    fn test_retention_default() {
        let conn = open_database(":memory:").expect("failed to open in-memory db");
        let retention: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'retention_days'",
                [],
                |row| row.get(0),
            )
            .expect("failed to read retention setting");
        assert_eq!(retention, "90");
    }

    #[test]
    fn test_prune_keeps_daily_stats() {
        let conn = open_database(":memory:").expect("failed to open in-memory db");

        // Insert a daily stat row
        conn.execute(
            "INSERT INTO daily_stats (date, total_sessions, unique_ips, payloads_captured, events_count)
             VALUES ('2020-01-01', 10, 5, 2, 50)",
            [],
        )
        .expect("failed to insert daily stat");

        // Run prune with 0 days retention (should delete everything old)
        handle_db_command(&conn, DbCommand::Prune { retention_days: 0 }).expect("prune failed");

        // daily_stats should survive
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM daily_stats", [], |row| row.get(0))
            .expect("failed to count daily_stats");
        assert_eq!(count, 1, "daily_stats should survive pruning");
    }

    #[tokio::test]
    async fn test_db_writer_recovers_from_error() {
        let conn = open_database(":memory:").expect("failed to open in-memory db");
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DbCommand>(10);
        
        let writer_handle = tokio::spawn(async move {
            let mut processed_count = 0;
            while let Some(cmd) = rx.recv().await {
                if let Err(e) = handle_db_command(&conn, cmd) {
                    eprintln!("simulated error: {}", e);
                }
                processed_count += 1;
            }
            processed_count
        });
        
        tx.send(DbCommand::InsertDecoy {
            container_id: "duplicate-id".to_string(),
            name: "test1".to_string(),
            template_type: "cowrie".to_string(),
            port_mapping: "2222:22".to_string(),
            bridge_network: None,
            subnet_cidr: None,
            realism_score: None,
            tunnel_public_url: None,
            tunnel_provider: None,
            tunnel_remote_port: None,
            tunnel_pid: None,
        }).await.unwrap();
        
        // This will fail due to UNIQUE constraint
        tx.send(DbCommand::InsertDecoy {
            container_id: "duplicate-id".to_string(),
            name: "test1".to_string(),
            template_type: "cowrie".to_string(),
            port_mapping: "2222:22".to_string(),
            bridge_network: None,
            subnet_cidr: None,
            realism_score: None,
            tunnel_public_url: None,
            tunnel_provider: None,
            tunnel_remote_port: None,
            tunnel_pid: None,
        }).await.unwrap();
        
        tx.send(DbCommand::InsertDecoy {
            container_id: "different-id".to_string(),
            name: "test2".to_string(),
            template_type: "cowrie".to_string(),
            port_mapping: "2223:22".to_string(),
            bridge_network: None,
            subnet_cidr: None,
            realism_score: None,
            tunnel_public_url: None,
            tunnel_provider: None,
            tunnel_remote_port: None,
            tunnel_pid: None,
        }).await.unwrap();
        
        drop(tx);
        
        let processed = writer_handle.await.unwrap();
        assert_eq!(processed, 3, "Writer loop should process all 3 commands even if one fails");
    }
}
