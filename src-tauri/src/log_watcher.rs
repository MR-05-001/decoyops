use std::path::{Path, PathBuf};
use std::time::Duration;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use std::collections::HashMap;
use serde_json::Value;

use crate::pipeline::ThreatIntelPipeline;

/// Watch honeypot log directories and parse JSON events in real-time.
pub struct LogWatcher {
    log_dir: PathBuf,
    pipeline: ThreatIntelPipeline,
}

impl LogWatcher {
    pub fn new(log_dir: impl AsRef<Path>, pipeline: ThreatIntelPipeline) -> Self {
        Self {
            log_dir: log_dir.as_ref().to_path_buf(),
            pipeline,
        }
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
                eprintln!("Failed to create log directory {}: {}", log_dir.display(), e);
            }
        }

        std::thread::spawn(move || {
            let mut watcher = RecommendedWatcher::new(
                move |res: Result<Event, notify::Error>| {
                    if let Ok(event) = res {
                        let _ = tx.blocking_send(event);
                    }
                },
                Config::default().with_poll_interval(Duration::from_secs(2)),
            ).expect("Failed to create file watcher");

            let _ = watcher.watch(&log_dir, RecursiveMode::Recursive);
            
            // Keep thread alive
            loop {
                std::thread::park();
            }
        });

        // Async event processing loop
        let async_log_dir = self.log_dir.clone();
        tauri::async_runtime::spawn(async move {
            let mut file_positions: HashMap<PathBuf, u64> = HashMap::new();
            
            // Pre-scan existing files to avoid re-reading historical logs on startup
            if let Ok(entries) = std::fs::read_dir(&async_log_dir) {
                for entry in entries.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_dir() {
                            if let Ok(sub_entries) = std::fs::read_dir(entry.path()) {
                                for sub_entry in sub_entries.flatten() {
                                    let path = sub_entry.path();
                                    if path.extension().map_or(false, |ext| ext == "json") {
                                        if let Ok(metadata) = std::fs::metadata(&path) {
                                            file_positions.insert(path, metadata.len());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Open a dedicated read connection for the log watcher
            let db_path = "decoyops.db";
            let db_read = match crate::db::open_database(db_path) {
                Ok(conn) => std::sync::Mutex::new(conn),
                Err(e) => {
                    eprintln!("LogWatcher failed to open DB: {e}");
                    return;
                }
            };

            while let Some(event) = rx.recv().await {
                // We only care about data modification events
                if matches!(event.kind, EventKind::Modify(_)) {
                    for path in event.paths {
                        // Only process .json log files
                        if path.extension().map_or(true, |ext| ext != "json") {
                            continue;
                        }

                        let pos = *file_positions.get(&path).unwrap_or(&0);
                        
                        match File::open(&path).await {
                            Ok(mut file) => {
                                // Seek to last known position
                                if let Ok(_) = file.seek(SeekFrom::Start(pos)).await {
                                    let mut reader = BufReader::new(file);
                                    let mut line = String::new();
                                    
                                    while let Ok(bytes_read) = reader.read_line(&mut line).await {
                                        if bytes_read == 0 {
                                            break; // EOF
                                        }

                                        // We have a new log line (JSON event)
                                        let json_str = line.trim();
                                        if !json_str.is_empty() {
                                            if let Ok(val) = serde_json::from_str::<Value>(json_str) {
                                                // Extract container_id from the log path (e.g. data/logs/<container_name>/cowrie.json)
                                                let folder_name = path
                                                    .parent()
                                                    .and_then(|p| p.file_name())
                                                    .map(|n| n.to_string_lossy().to_string())
                                                    .unwrap_or_else(|| "unknown-container".to_string());
                                                    
                                                let decoy_name = folder_name.strip_prefix("decoy_").unwrap_or(&folder_name).to_string();
                                                
                                                // Resolve actual 64-char container ID from database
                                                let container_id = {
                                                    if let Ok(conn) = db_read.lock() {
                                                        conn.query_row("SELECT container_id FROM decoys WHERE name = ?1", [&decoy_name], |r| r.get::<_, String>(0))
                                                            .unwrap_or(folder_name)
                                                    } else {
                                                        folder_name
                                                    }
                                                };
                                                
                                                let src_ip = val.get("src_ip")
                                                    .or_else(|| val.get("source_ip"))
                                                    .or_else(|| val.get("remote_host"))
                                                    .or_else(|| val.get("ip"))
                                                    .or_else(|| val.get("remote_ip"))
                                                    .or_else(|| val.get("connection").and_then(|c| c.get("remote_host")))
                                                    .or_else(|| val.get("connection").and_then(|c| c.get("remote_ip")))
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("127.0.0.1")
                                                    .to_string();

                                                let event_type = val.get("eventid")
                                                    .or_else(|| val.get("event_type"))
                                                    .or_else(|| val.get("action"))
                                                    .or_else(|| val.get("type"))
                                                    .or_else(|| val.get("name"))
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or_else(|| {
                                                        if val.get("connection").is_some() {
                                                            "connection"
                                                        } else if val.get("credentials").is_some() {
                                                            "credentials"
                                                        } else {
                                                            "generic.event"
                                                        }
                                                    })
                                                    .to_string();
                                                
                                                // Get or create session ID based on IP
                                                let session_id = self.pipeline.get_or_create_session(
                                                    container_id.clone(),
                                                    src_ip.clone()
                                                ).await.unwrap_or(1);

                                                // Check for fingerprinting/TTY info
                                                let mut ssh_client_version = None;
                                                let mut ja3_fingerprint = None;
                                                let mut tty_log_path = None;

                                                if event_type == "cowrie.client.version" {
                                                    ssh_client_version = val.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
                                                }
                                                if event_type == "cowrie.session.connect" || event_type == "cowrie.client.kex" {
                                                    // Hassh or JA3 depending on protocol
                                                    ja3_fingerprint = val.get("hassh").or(val.get("ja3")).and_then(|v| v.as_str()).map(|s| s.to_string());
                                                }
                                                if event_type == "cowrie.log.closed" || val.get("ttylog").is_some() {
                                                    tty_log_path = val.get("ttylog").and_then(|v| v.as_str()).map(|s| s.to_string());
                                                }

                                                if ssh_client_version.is_some() || ja3_fingerprint.is_some() || tty_log_path.is_some() {
                                                    self.pipeline.update_fingerprint(
                                                        session_id,
                                                        ssh_client_version,
                                                        ja3_fingerprint,
                                                        tty_log_path
                                                    ).await;
                                                }

                                                // Send to pipeline
                                                let _ = self.pipeline.process_event(
                                                    session_id,
                                                    container_id,
                                                    event_type,
                                                    Some(src_ip),
                                                    None,
                                                    Some(json_str.to_string()),
                                                    &db_read
                                                ).await;
                                            }
                                        }
                                        line.clear();
                                    }
                                    
                                    // Update position
                                    if let Ok(new_pos) = reader.into_inner().stream_position().await {
                                        file_positions.insert(path, new_pos);
                                    }
                                }
                            }
                            Err(e) => eprintln!("Failed to open log file {}: {}", path.display(), e),
                        }
                    }
                }
            }
        });
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
        let watcher = LogWatcher::new(&log_dir, pipeline);
        
        // Write some valid and invalid data
        let log_file_path = log_dir.join("cowrie.json");
        let mut file = std::fs::File::create(&log_file_path).unwrap();
        
        // Write invalid JSON
        writeln!(file, "{{ malformed: json, oops }}").unwrap();
        // Write valid JSON
        writeln!(file, "{{\"eventid\":\"cowrie.session.connect\",\"src_ip\":\"1.2.3.4\"}}").unwrap();
        
        // Run start() which spawns threads
        watcher.start();
        
        // We can't easily wait for the exact moment the async loop reads it since it's event driven,
        // but the test proves that encountering `malformed: json` does not panic the thread, 
        // and we would eventually get a DbCommand from the valid JSON.
        
        // Small delay to let threads initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Trigger a modify event by writing again
        let mut file = std::fs::OpenOptions::new().append(true).open(&log_file_path).unwrap();
        writeln!(file, "{{\"eventid\":\"test\",\"src_ip\":\"1.2.3.4\"}}").unwrap();
        
        // Wait for pipeline output
        let res = tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv()).await;
        
        assert!(res.is_ok(), "Should have processed the valid JSON and skipped the malformed JSON without crashing");
    }
}
