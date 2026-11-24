use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::mpsc;

use crate::db::DbCommand;
use crate::pipeline::ThreatIntelPipeline;
use crate::quarantine::QuarantineManager;

/// Watch honeypot log directories and parse JSON events in real-time.
pub struct LogWatcher {
    log_dir: PathBuf,
    db_path: PathBuf,
    pipeline: ThreatIntelPipeline,
    binaries_dir: Option<PathBuf>,
    quarantine: Option<Arc<QuarantineManager>>,
    db_writer: Option<mpsc::Sender<DbCommand>>,
}

impl LogWatcher {
    pub fn new(log_dir: impl AsRef<Path>, pipeline: ThreatIntelPipeline) -> Self {
        Self {
            log_dir: log_dir.as_ref().to_path_buf(),
            db_path: PathBuf::from("decoyops.db"),
            pipeline,
            binaries_dir: None,
            quarantine: None,
            db_writer: None,
        }
    }

    /// Set an explicit database path instead of defaulting to relative "decoyops.db" (MED-1 fix).
    pub fn with_db_path(mut self, db_path: impl AsRef<Path>) -> Self {
        self.db_path = db_path.as_ref().to_path_buf();
        self
    }

    /// Enable automatic quarantine isolation for captured honeypot binaries (HC#3).
    pub fn with_quarantine(
        mut self,
        binaries_dir: impl AsRef<Path>,
        quarantine: Arc<QuarantineManager>,
        db_writer: mpsc::Sender<DbCommand>,
    ) -> Self {
        self.binaries_dir = Some(binaries_dir.as_ref().to_path_buf());
        self.quarantine = Some(quarantine);
        self.db_writer = Some(db_writer);
        self
    }

    /// Spawns the background watching task.
    pub fn start(self) {
        let (tx, mut rx) = mpsc::channel(100);

        // Standard notify watcher setup running on a standard thread
        // which sends events over an async channel to tokio.
        let log_dir = self.log_dir.clone();

        // Ensure log directory exists
        if !log_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&log_dir) {
                eprintln!(
                    "Failed to create log directory {}: {}",
                    log_dir.display(),
                    e
                );
            }
        }

        std::thread::spawn(move || {
            let watcher_res = RecommendedWatcher::new(
                move |res: Result<Event, notify::Error>| {
                    if let Ok(event) = res {
                        let _ = tx.blocking_send(event);
                    }
                },
                Config::default().with_poll_interval(Duration::from_secs(2)),
            );

            let mut watcher = match watcher_res {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("LogWatcher: failed to create notify watcher (falling back to periodic sweep): {}", e);
                    return;
                }
            };

            let _ = watcher.watch(&log_dir, RecursiveMode::Recursive);

            // Keep thread alive
            loop {
                std::thread::park();
            }
        });

        // Async event processing loop
        let async_log_dir = self.log_dir.clone();
        let async_db_path = self.db_path.clone();
        let pipeline = self.pipeline.clone();
        let async_binaries_dir = self.binaries_dir.clone();
        let quarantine = self.quarantine.clone();
        let db_writer = self.db_writer.clone();

        tauri::async_runtime::spawn(async move {
            let mut file_positions: HashMap<PathBuf, u64> = HashMap::new();

            // Open a dedicated read connection for the log watcher (MED-1 fix: use configured path)
            let db_read = match crate::db::open_database(&async_db_path.to_string_lossy()) {
                Ok(conn) => std::sync::Mutex::new(conn),
                Err(e) => {
                    eprintln!("LogWatcher failed to open DB at {:?}: {e}", async_db_path);
                    return;
                }
            };

            // Immediately backfill any existing historical logs and isolate any existing binaries on startup
            Self::scan_and_process_dir(
                &async_log_dir,
                &async_log_dir,
                &mut file_positions,
                &pipeline,
                &db_read,
            )
            .await;
            if let (Some(bdir), Some(qmgr), Some(writer)) =
                (&async_binaries_dir, &quarantine, &db_writer)
            {
                Self::scan_and_quarantine_binaries(bdir, qmgr, writer, &db_read).await;
            }

            let mut periodic_timer = tokio::time::interval(Duration::from_secs(3));
            periodic_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    Some(event) = rx.recv() => {
                        if matches!(
                            event.kind,
                            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Any
                        ) {
                            for path in event.paths {
                                if path.is_dir() {
                                    Self::scan_and_process_dir(&async_log_dir, &path, &mut file_positions, &pipeline, &db_read).await;
                                } else if Self::is_telemetry_log_file(&path) {
                                    Self::process_log_file(&async_log_dir, &path, &mut file_positions, &pipeline, &db_read).await;
                                }
                            }
                        }
                    }
                    _ = periodic_timer.tick() => {
                        // Periodic sweep ensures Docker bind-mount writes are caught on Windows reliably
                        Self::scan_and_process_dir(&async_log_dir, &async_log_dir, &mut file_positions, &pipeline, &db_read).await;
                        if let (Some(bdir), Some(qmgr), Some(writer)) = (&async_binaries_dir, &quarantine, &db_writer) {
                            Self::scan_and_quarantine_binaries(bdir, qmgr, writer, &db_read).await;
                        }
                    }
                }
            }
        });
    }

    fn resolve_container_id(
        folder_name: &str,
        db_read: &std::sync::Mutex<rusqlite::Connection>,
    ) -> Option<String> {
        let decoy_name = folder_name.strip_prefix("decoy_").unwrap_or(folder_name);
        let conn = db_read.lock().ok()?;
        conn.query_row(
            "SELECT container_id FROM decoys WHERE LOWER(name) = LOWER(?1) AND state != 'deleted' ORDER BY id DESC LIMIT 1",
            [decoy_name],
            |r| r.get::<_, String>(0),
        )
        .ok()
    }

    fn resolve_any_container_id(
        folder_name: &str,
        db_read: &std::sync::Mutex<rusqlite::Connection>,
    ) -> String {
        let decoy_name = folder_name.strip_prefix("decoy_").unwrap_or(folder_name);
        if let Ok(conn) = db_read.lock() {
            conn.query_row(
                "SELECT container_id FROM decoys WHERE LOWER(name) = LOWER(?1) ORDER BY id DESC LIMIT 1",
                [decoy_name],
                |r| r.get::<_, String>(0),
            )
            .unwrap_or_else(|_| folder_name.to_string())
        } else {
            folder_name.to_string()
        }
    }

    async fn scan_and_quarantine_binaries(
        binaries_dir: &Path,
        quarantine: &QuarantineManager,
        db_writer: &mpsc::Sender<DbCommand>,
        db_read: &std::sync::Mutex<rusqlite::Connection>,
    ) {
        let Ok(decoy_dirs) = std::fs::read_dir(binaries_dir) else {
            return;
        };
        for entry in decoy_dirs.flatten() {
            let dir_path = entry.path();
            if !entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                continue;
            }
            let folder_name = dir_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown-container".to_string());
            let container_id = Self::resolve_any_container_id(&folder_name, db_read);

            let Ok(files) = std::fs::read_dir(&dir_path) else {
                continue;
            };
            for file_entry in files.flatten() {
                let fpath = file_entry.path();
                if !file_entry.file_type().is_ok_and(|ft| ft.is_file()) {
                    continue;
                }
                let fname = file_entry.file_name().to_string_lossy().to_string();
                if fname.starts_with('.') || fname.ends_with(".tmp") || fname.ends_with(".part") {
                    continue;
                }
                let file_size = std::fs::metadata(&fpath).ok().map(|m| m.len() as i64);
                if file_size == Some(0) {
                    continue;
                }
                if let Ok((sha256, isolated_path)) = quarantine.isolate_file(&fpath) {
                    let _ = db_writer
                        .send(DbCommand::InsertCapturedFile {
                            session_id: None,
                            container_id: container_id.clone(),
                            sha256,
                            original_name: Some(fname),
                            file_size,
                            isolated_path: isolated_path.to_string_lossy().to_string(),
                        })
                        .await;
                }
            }
        }
    }

    /// Returns true if `path` is a honeypot structured telemetry log we ingest.
    /// Includes `.json` files plus Mailoney (`commands.log`) and Endlessh (`endlessh.log`),
    /// while ignoring container debug logs (`dionaea.log`, `conpot.log`, `decoyops-audit.log`).
    fn is_telemetry_log_file(path: &Path) -> bool {
        if path.extension().is_some_and(|ext| ext == "json") {
            return true;
        }
        matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("commands.log" | "endlessh.log")
        )
    }

    /// Parses plain-text Endlessh log lines into a normalized JSON object.
    fn parse_endlessh_line(line: &str) -> Option<Value> {
        let mut parts = line.split_whitespace();
        let ts = parts.next()?;
        let reason = parts.next()?;
        if !matches!(reason, "ACCEPT" | "CLOSE") {
            return None;
        }
        let mut map = serde_json::Map::new();
        map.insert("timestamp".to_string(), Value::String(ts.to_string()));
        map.insert(
            "eventid".to_string(),
            Value::String(format!("endlessh.{}", reason.to_lowercase())),
        );
        for kv in parts {
            if let Some((k, v)) = kv.split_once('=') {
                match k {
                    "host" => {
                        let clean = v.strip_prefix("::ffff:").unwrap_or(v);
                        map.insert("src_ip".to_string(), Value::String(clean.to_string()));
                    }
                    "port" => {
                        if let Ok(p) = v.parse::<u16>() {
                            map.insert("src_port".to_string(), Value::from(p));
                        }
                    }
                    "time" => {
                        map.insert("duration".to_string(), Value::String(v.to_string()));
                    }
                    "bytes" => {
                        if let Ok(b) = v.parse::<u64>() {
                            map.insert("bytes".to_string(), Value::from(b));
                        }
                    }
                    _ => {}
                }
            }
        }
        map.contains_key("src_ip").then_some(Value::Object(map))
    }

    /// Extracts the top-level decoy folder name under `log_dir` even for nested subpaths.
    fn extract_decoy_folder(log_dir: &Path, path: &Path) -> String {
        if let Ok(rel) = path.strip_prefix(log_dir) {
            if let Some(std::path::Component::Normal(first)) = rel.components().next() {
                return first.to_string_lossy().to_string();
            }
        }
        path.parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown-container".to_string())
    }

    /// Recursively scans a directory and processes all supported telemetry log files.
    fn scan_and_process_dir<'a>(
        base_log_dir: &'a Path,
        dir: &'a Path,
        file_positions: &'a mut HashMap<PathBuf, u64>,
        pipeline: &'a ThreatIntelPipeline,
        db_read: &'a std::sync::Mutex<rusqlite::Connection>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(ft) = entry.file_type() {
                        if ft.is_dir() {
                            Self::scan_and_process_dir(
                                base_log_dir,
                                &path,
                                file_positions,
                                pipeline,
                                db_read,
                            )
                            .await;
                        } else if Self::is_telemetry_log_file(&path) {
                            Self::process_log_file(
                                base_log_dir,
                                &path,
                                file_positions,
                                pipeline,
                                db_read,
                            )
                            .await;
                        }
                    }
                }
            }
        })
    }

    /// Incrementally reads and parses new JSON lines from a honeypot log file.
    async fn process_log_file(
        base_log_dir: &Path,
        path: &Path,
        file_positions: &mut HashMap<PathBuf, u64>,
        pipeline: &ThreatIntelPipeline,
        db_read: &std::sync::Mutex<rusqlite::Connection>,
    ) {
        let mut pos = *file_positions.get(path).unwrap_or(&0);

        let Ok(mut file) = File::open(path).await else {
            return;
        };

        // Reset cursor if log file was truncated or rotated
        if let Ok(meta) = file.metadata().await {
            if meta.len() < pos {
                pos = 0;
            }
        }

        if file.seek(SeekFrom::Start(pos)).await.is_err() {
            return;
        }

        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut last_complete_pos = pos;

        // Extract container_id from the top-level log folder (e.g. data/logs/<container_name>/...)
        let folder_name = Self::extract_decoy_folder(base_log_dir, path);

        // Skip orphaned/deleted decoy log directories so stale logs never trigger NOT NULL session errors
        let Some(container_id) = Self::resolve_container_id(&folder_name, db_read) else {
            return;
        };

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let is_endlessh = file_name == "endlessh.log";
        let is_mailoney = file_name == "commands.log";
        let is_elasticpot = file_name.starts_with("elasticpot");
        let is_conpot = file_name.starts_with("conpot");

        while let Ok(bytes_read) = reader.read_line(&mut line).await {
            if bytes_read == 0 {
                break; // EOF
            }
            if !line.ends_with('\n') {
                // Wait for the concurrent writer to finish flushing the complete line
                line.clear();
                break;
            }
            last_complete_pos += bytes_read as u64;

            let raw_line = line.trim();
            if !raw_line.is_empty() {
                let parsed = if is_endlessh {
                    Self::parse_endlessh_line(raw_line)
                } else {
                    serde_json::from_str::<Value>(raw_line).ok()
                };
                if let Some(val) = parsed {
                    let json_str_owned;
                    let json_str = if is_endlessh {
                        json_str_owned = val.to_string();
                        json_str_owned.as_str()
                    } else {
                        raw_line
                    };

                    // Deduplicate against SQLite events table
                    let already_exists: bool = {
                        if let Ok(conn) = db_read.lock() {
                            conn.query_row(
                                "SELECT 1 FROM events WHERE container_id = ?1 AND raw_data = ?2 LIMIT 1",
                                [&container_id, json_str],
                                |_| Ok(true),
                            )
                            .unwrap_or(false)
                        } else {
                            false
                        }
                    };

                    if !already_exists {
                        let raw_src_ip = val
                            .get("src_ip")
                            .or_else(|| val.get("source_ip"))
                            .or_else(|| val.get("remote_host"))
                            .or_else(|| val.get("ip"))
                            .or_else(|| val.get("remote_ip"))
                            .or_else(|| val.get("connection").and_then(|c| c.get("remote_host")))
                            .or_else(|| val.get("connection").and_then(|c| c.get("remote_ip")))
                            .and_then(|v| v.as_str())
                            .or_else(|| {
                                val.get("remote").and_then(|r| {
                                    r.as_str().or_else(|| r.as_array()?.first()?.as_str())
                                })
                            })
                            .unwrap_or("127.0.0.1");
                        let src_ip = raw_src_ip
                            .strip_prefix("::ffff:")
                            .unwrap_or(raw_src_ip)
                            .to_string();

                        let event_type = val
                            .get("eventid")
                            .or_else(|| val.get("event_type"))
                            .or_else(|| val.get("action"))
                            .or_else(|| val.get("type"))
                            .or_else(|| val.get("name"))
                            .and_then(|v| v.as_str())
                            .map(|s| {
                                let lower = s.to_ascii_lowercase();
                                if is_conpot && !lower.contains("conpot") {
                                    format!("conpot.{s}")
                                } else if is_elasticpot && !lower.contains("elasticpot") {
                                    format!("elasticpot.{s}")
                                } else if is_mailoney && !lower.contains("mailoney") {
                                    format!("mailoney.{s}")
                                } else {
                                    s.to_string()
                                }
                            })
                            .unwrap_or_else(|| {
                                if is_conpot {
                                    let proto = val
                                        .get("data_type")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or("ics");
                                    format!("conpot.{proto}")
                                } else if is_mailoney {
                                    "mailoney.smtp.command".to_string()
                                } else if is_elasticpot {
                                    let method = val
                                        .get("request")
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("http");
                                    format!("elasticpot.{}", method.to_lowercase())
                                } else if let Some(conn) = val.get("connection") {
                                    let proto = conn
                                        .get("protocol")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or("unknown");
                                    let ctype = conn
                                        .get("type")
                                        .and_then(|t| t.as_str())
                                        .unwrap_or("connection");
                                    format!("dionaea.{proto}.{ctype}")
                                } else if val.get("credentials").is_some() {
                                    "dionaea.credentials".to_string()
                                } else {
                                    "generic.event".to_string()
                                }
                            });

                        let attack_vector = if event_type.contains("endlessh") {
                            Some("SSH Tarpit".to_string())
                        } else if event_type.contains("cowrie") || event_type.contains("ssh") {
                            Some("SSH".to_string())
                        } else if event_type.contains("mailoney") || event_type.contains("smtp") {
                            Some("SMTP".to_string())
                        } else if event_type.contains("elasticpot") {
                            Some("HTTP/Elastic".to_string())
                        } else if event_type.contains("conpot") {
                            Some("ICS/SCADA".to_string())
                        } else if event_type.contains("smb") {
                            Some("SMB".to_string())
                        } else if event_type.contains("http") {
                            Some("HTTP".to_string())
                        } else if event_type.contains("ftp") {
                            Some("FTP".to_string())
                        } else if event_type.contains("dionaea") {
                            Some("Malware/Exploit".to_string())
                        } else {
                            None
                        };

                        let session_id = match pipeline
                            .get_or_create_session(container_id.clone(), src_ip.clone())
                            .await
                        {
                            Ok(id) => id,
                            Err(e) => {
                                eprintln!(
                                    "LogWatcher: failed to get/create session for container={}, ip={}: {}. Skipping event.",
                                    container_id, src_ip, e
                                );
                                line.clear();
                                continue;
                            }
                        };

                        let mut ssh_client_version = None;
                        let mut ja3_fingerprint = None;
                        let mut tty_log_path = None;

                        if event_type == "cowrie.client.version" {
                            ssh_client_version = val
                                .get("version")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                        if event_type == "cowrie.session.connect"
                            || event_type == "cowrie.client.kex"
                        {
                            ja3_fingerprint = val
                                .get("hassh")
                                .or(val.get("ja3"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                        if event_type == "cowrie.log.closed" || val.get("ttylog").is_some() {
                            tty_log_path = val
                                .get("ttylog")
                                .and_then(|v| v.as_str())
                                .and_then(|s| std::path::Path::new(s).file_name())
                                .map(|fname| {
                                    format!("{}/tty/{}", folder_name, fname.to_string_lossy())
                                });
                        }

                        if ssh_client_version.is_some()
                            || ja3_fingerprint.is_some()
                            || tty_log_path.is_some()
                        {
                            pipeline
                                .update_fingerprint(
                                    session_id,
                                    ssh_client_version,
                                    ja3_fingerprint,
                                    tty_log_path,
                                )
                                .await;
                        }

                        if event_type == "cowrie.session.closed"
                            || event_type == "cowrie.log.closed"
                        {
                            pipeline.close_session(session_id).await;
                        }

                        let _ = pipeline
                            .process_event(
                                session_id,
                                container_id.clone(),
                                event_type,
                                Some(src_ip),
                                attack_vector,
                                Some(json_str.to_string()),
                                db_read,
                            )
                            .await;
                    }
                }
            }
            line.clear();
        }

        file_positions.insert(path.to_path_buf(), last_complete_pos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn test_log_watcher_ignores_malformed_json() {
        let log_dir = std::env::temp_dir().join(format!("decoy_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&log_dir);
        std::fs::create_dir_all(&log_dir).unwrap();

        let (tx, mut rx) = mpsc::channel(100);
        let pipeline = ThreatIntelPipeline::new(tx, None);
        let test_db = log_dir.join("test.db");
        // Pre-initialize SQLite schema and register decoy_test1 in test_db
        let conn = crate::db::open_database(&test_db.to_string_lossy()).unwrap();
        conn.execute(
            "INSERT INTO decoys (container_id, name, template_type, port_mapping, state)
             VALUES ('cid_test1', 'test1', 'cowrie', '2222:22', 'running')",
            [],
        )
        .unwrap();
        drop(conn);
        let watcher = LogWatcher::new(&log_dir, pipeline).with_db_path(&test_db);

        let container_dir = log_dir.join("decoy_test1");
        std::fs::create_dir_all(&container_dir).unwrap();
        let log_file_path = container_dir.join("cowrie.json");

        // Run start() which spawns watcher thread and async event loop
        watcher.start();

        // Small delay to let notify register the watch
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Write some valid and invalid data
        {
            let mut file = std::fs::File::create(&log_file_path).unwrap();
            // Write invalid JSON
            writeln!(file, "{{ malformed: json, oops }}").unwrap();
            // Write valid JSON
            writeln!(
                file,
                "{{\"eventid\":\"cowrie.session.connect\",\"src_ip\":\"1.2.3.4\"}}"
            )
            .unwrap();
            file.flush().unwrap();
            file.sync_all().unwrap();
        }

        // Wait for pipeline output (allow up to 6 seconds for watcher)
        let res = tokio::time::timeout(tokio::time::Duration::from_secs(6), rx.recv()).await;

        assert!(
            res.is_ok(),
            "Should have processed the valid JSON and skipped the malformed JSON without crashing"
        );
    }

    #[test]
    fn resolve_container_id_ignores_deleted_or_missing_decoys() {
        let conn = crate::db::open_database(":memory:").unwrap();
        conn.execute(
            "INSERT INTO decoys (container_id, name, template_type, port_mapping, state)
             VALUES ('cid_deleted', 'ssh-decoy', 'dionaea', '445:445', 'deleted')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO decoys (container_id, name, template_type, port_mapping, state)
             VALUES ('cid_active', 'mal', 'dionaea', '445:445', 'running')",
            [],
        )
        .unwrap();
        let db_read = std::sync::Mutex::new(conn);

        assert_eq!(
            LogWatcher::resolve_container_id("decoy_ssh-decoy", &db_read),
            None
        );
        assert_eq!(
            LogWatcher::resolve_container_id("decoy_missing", &db_read),
            None
        );
        assert_eq!(
            LogWatcher::resolve_container_id("decoy_mal", &db_read),
            Some("cid_active".to_string())
        );
    }

    #[test]
    fn parses_endlessh_plain_text_and_identifies_telemetry_files() {
        assert!(LogWatcher::is_telemetry_log_file(Path::new("cowrie.json")));
        assert!(LogWatcher::is_telemetry_log_file(Path::new("commands.log")));
        assert!(LogWatcher::is_telemetry_log_file(Path::new("endlessh.log")));
        assert!(!LogWatcher::is_telemetry_log_file(Path::new("dionaea.log")));
        assert!(!LogWatcher::is_telemetry_log_file(Path::new("conpot.log")));

        let parsed = LogWatcher::parse_endlessh_line(
            "2026-11-24T21:08:31.026Z CLOSE host=::ffff:203.0.113.5 port=54321 fd=4 time=20.015 bytes=24",
        )
        .unwrap();
        assert_eq!(parsed["eventid"], "endlessh.close");
        assert_eq!(parsed["src_ip"], "203.0.113.5");
        assert_eq!(parsed["src_port"], 54321);
        assert_eq!(parsed["bytes"], 24);
    }

    #[tokio::test]
    async fn extracts_conpot_remote_tuple_and_nested_folder() {
        let log_dir =
            std::env::temp_dir().join(format!("decoy_conpot_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&log_dir);
        let nested = log_dir.join("decoy_ics1").join("sub");
        std::fs::create_dir_all(&nested).unwrap();

        assert_eq!(
            LogWatcher::extract_decoy_folder(&log_dir, &nested.join("conpot.json")),
            "decoy_ics1"
        );

        let conn = crate::db::open_database(":memory:").unwrap();
        conn.execute(
            "INSERT INTO decoys (container_id, name, template_type, port_mapping, state)
             VALUES ('cid_ics1', 'ics1', 'conpot', '502:502', 'running')",
            [],
        )
        .unwrap();
        let db_read = std::sync::Mutex::new(conn);

        let (tx, mut rx) = mpsc::channel(16);
        let pipeline = ThreatIntelPipeline::new(tx, None);
        let json_path = nested.join("conpot.json");
        std::fs::write(
            &json_path,
            "{\"remote\":[\"203.0.113.99\",55123],\"data_type\":\"modbus\"}\n",
        )
        .unwrap();

        let writer = tokio::spawn(async move {
            let mut saw_ip = None;
            let mut saw_event_type = None;
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    DbCommand::InsertSession {
                        source_ip, reply, ..
                    } => {
                        saw_ip = Some(source_ip);
                        let _ = reply.send(Ok(1));
                    }
                    DbCommand::InsertEvent { event_type, .. } => {
                        saw_event_type = Some(event_type);
                        break;
                    }
                    _ => {}
                }
            }
            (saw_ip, saw_event_type)
        });

        let mut positions = HashMap::new();
        LogWatcher::process_log_file(&log_dir, &json_path, &mut positions, &pipeline, &db_read)
            .await;

        let (saw_ip, saw_event_type) = tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(saw_ip.as_deref(), Some("203.0.113.99"));
        assert_eq!(saw_event_type.as_deref(), Some("conpot.modbus"));
        assert!(positions.get(&json_path).copied().unwrap_or(0) > 0);
        let _ = std::fs::remove_dir_all(&log_dir);
    }
}
