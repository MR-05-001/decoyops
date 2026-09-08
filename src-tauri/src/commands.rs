//! Tauri IPC command stubs — the narrow, named commands exposed to the webview.
//!
//! These are the ONLY entry points from the frontend into the Rust backend.
//! Each command is registered in `lib.rs` via `tauri::generate_handler![]`
//! and scoped by the capabilities allowlist in `capabilities/main.json`.
//!
//! ## Security notes (AGENTS.md HC#4)
//!
//! - No generic "execute shell command" bridge exists or will be added.
//! - Each command does one specific thing with validated inputs.
//! - `commands.rs` is a thin relay — it calls into `docker.rs`, `db.rs`, etc.
//!   by name; it never constructs bollard types or touches the Docker socket.

use std::sync::Mutex;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tauri::{State, Manager};

use crate::db;
use regex::Regex;

fn validate_input(input: &str, field_name: &str) -> Result<(), String> {
    let re = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    if !re.is_match(input) {
        return Err(format!("Invalid characters in {}. Only alphanumeric, dashes, and underscores are allowed.", field_name));
    }
    Ok(())
}

fn validate_image_name(input: &str, field_name: &str) -> Result<(), String> {
    let re = Regex::new(r"^[a-zA-Z0-9_:/.-]+$").unwrap();
    if !re.is_match(input) {
        return Err(format!("Invalid characters in {}. Only standard docker image characters allowed.", field_name));
    }
    Ok(())
}
// ---------------------------------------------------------------------------
// Managed state wrappers
// ---------------------------------------------------------------------------

/// Read-only database connection, wrapped in a Mutex for thread safety.
/// WAL mode means this reader never blocks the single-writer task.
pub struct DbRead(pub Mutex<Connection>);

pub struct DbWriter(pub tokio::sync::mpsc::Sender<crate::db::DbCommand>);

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response returned by [`deploy_decoy`] on success.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeployResult {
    /// The Docker container ID of the newly deployed decoy.
    pub container_id: String,
}

/// Summary of a single decoy's current state, returned by [`get_fleet_telemetry`].
#[derive(Debug, Serialize, Deserialize)]
pub struct DecoyStatus {
    /// Docker container ID.
    pub container_id: String,
    /// Human-readable name (e.g., "ssh-decoy-01").
    pub name: String,
    /// Current state: "running", "stopped", "exited", etc.
    pub state: String,
    /// Realism score out of 100.
    pub realism_score: Option<i32>,
    /// Tunnel public URL (if any).
    pub tunnel_public_url: Option<String>,
    /// Tunnel provider (if any).
    pub tunnel_provider: Option<String>,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Deploy a new honeypot decoy container.
///
/// # Arguments
/// - `template_type` — Decoy template (e.g., "cowrie", "dionaea").
/// - `port_mapping` — Host:container port mapping (e.g., "2222:22").
///
/// # Returns
/// The container ID of the deployed decoy, or an error string.
fn calculate_realism_score(template_type: &str, port_mapping: &str) -> i32 {
    let mut score = 50; // base score

    if template_type.to_lowercase() == "cowrie" {
        score += 10;
    }

    // Check if mapping to default ports (e.g., 22 for SSH)
    if port_mapping.starts_with("22:") {
        score += 20;
    } else if port_mapping.starts_with("2222:") {
        score -= 10;
    }

    score.clamp(0, 100)
}

#[tauri::command]
pub async fn deploy_decoy(
    app: tauri::AppHandle,
    docker: State<'_, crate::docker::DockerProxy>,
    db_writer: State<'_, DbWriter>,
    db_read: State<'_, DbRead>,
    name: String,
    template_type: String,
    port_mapping: String,
    auto_restart: bool,
    network_name: Option<String>,
    is_unmanaged: bool,
    tunnel_provider: Option<String>,
) -> Result<DeployResult, String> {
    validate_input(&name, "name")?;
    validate_image_name(&template_type, "template_type")?;
    if let Some(ref net) = network_name {
        validate_input(net, "network_name")?;
    }
    if let Some(ref provider) = tunnel_provider {
        validate_input(provider, "tunnel_provider")?;
    }

    let mut resolved_port_mapping = port_mapping.clone();
    if resolved_port_mapping.starts_with("0:") {
        let container_port = resolved_port_mapping.trim_start_matches("0:");
        if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") {
            if let Ok(addr) = listener.local_addr() {
                resolved_port_mapping = format!("{}:{}", addr.port(), container_port);
            }
        }
    }

    let provider_instance = if let Some(ref p_name) = tunnel_provider {
        let conn = db_read.0.lock().map_err(|e| e.to_string())?;
        Some(get_provider(&conn, p_name))
    } else {
        None
    };

    let mut allocated_remote_port = None;
    if let Some(ref p) = provider_instance {
        if p.is_self_hosted() {
            let conn = db_read.0.lock().map_err(|e| e.to_string())?;
            let start_port = crate::db::get_setting(&conn, "frp_port_range_start").unwrap_or(None).unwrap_or_else(|| "10000".to_string()).parse().unwrap_or(10000);
            let end_port = crate::db::get_setting(&conn, "frp_port_range_end").unwrap_or(None).unwrap_or_else(|| "20000".to_string()).parse().unwrap_or(20000);
            allocated_remote_port = crate::db::get_next_available_remote_port(&conn, start_port, end_port).map_err(|e| e.to_string())?;
        }
    }

    let (container_id, tunnel_handle) = docker
        .deploy_decoy(
            &name, 
            &template_type, 
            &resolved_port_mapping, 
            auto_restart,
            network_name.as_deref(),
            is_unmanaged,
            provider_instance.as_deref(),
            allocated_remote_port,
        )
        .await?;

    let realism_score = calculate_realism_score(&template_type, &resolved_port_mapping);

    let _ = db_writer.0.send(crate::db::DbCommand::InsertDecoy {
        container_id: container_id.clone(),
        name: name.clone(),
        template_type: template_type.clone(),
        port_mapping: resolved_port_mapping,
        bridge_network: None,
        subnet_cidr: None,
        realism_score: Some(realism_score),
        tunnel_public_url: tunnel_handle.as_ref().and_then(|h| h.public_url.clone()),
        tunnel_provider: tunnel_handle.as_ref().map(|h| h.provider_name.clone()),
        tunnel_remote_port: tunnel_handle.as_ref().and_then(|h| h.remote_port),
        tunnel_pid: tunnel_handle.as_ref().and_then(|h| h.pid),
    }).await;

    // Active Verification: check if JSON log was created within 25 seconds
    let verify_name = name.clone();
    let verify_template = template_type.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(25)).await;
        let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let log_dir = current_dir.join("data").join("logs").join(format!("decoy_{}", verify_name));
        
        let mut json_found = false;
        if let Ok(entries) = std::fs::read_dir(&log_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().map_or(false, |ext| ext == "json") {
                    json_found = true;
                    break;
                }
            }
        }
        
        if !json_found {
            use tauri::Emitter;
            let _ = app.emit("telemetry-warning", format!("Telemetry Error: {} container deployed but no JSON log detected.", verify_template));
        }
    });

    Ok(DeployResult { container_id })
}

/// Start a stopped decoy.
#[tauri::command]
pub async fn start_decoy(
    docker: State<'_, crate::docker::DockerProxy>,
    container_id: String,
) -> Result<(), String> {
    validate_input(&container_id, "container_id")?;
    docker.start_decoy(&container_id).await
}

/// Stop a running decoy.
#[tauri::command]
pub async fn stop_decoy(
    docker: State<'_, crate::docker::DockerProxy>,
    container_id: String,
) -> Result<(), String> {
    validate_input(&container_id, "container_id")?;
    docker.stop_decoy(&container_id).await
}

/// Restart a decoy.
#[tauri::command]
pub async fn restart_decoy(
    docker: State<'_, crate::docker::DockerProxy>,
    container_id: String,
) -> Result<(), String> {
    validate_input(&container_id, "container_id")?;
    docker.restart_decoy(&container_id).await
}

/// Gracefully stop and remove a decoy container.
///
/// # Arguments
/// - `container_id` — The Docker container ID to terminate.
///
/// # Returns
/// `Ok(())` on success, or an error string.
#[tauri::command]
pub async fn terminate_decoy(
    docker: State<'_, crate::docker::DockerProxy>,
    db_writer: State<'_, DbWriter>,
    db_read: State<'_, DbRead>,
    container_id: String,
) -> Result<(), String> {
    validate_input(&container_id, "container_id")?;
    // 1. Stop tunnel if any
    let decoy = {
        let conn = db_read.0.lock().map_err(|e| e.to_string())?;
        crate::db::get_all_decoys(&conn).unwrap_or_default().into_iter().find(|d| d.container_id == container_id)
    };
    
    if let Some(decoy) = decoy {
        if let Some(provider_name) = decoy.tunnel_provider {
            let provider = {
                let conn = db_read.0.lock().map_err(|e| e.to_string())?;
                get_provider(&conn, &provider_name)
            };
            let handle = crate::tunnel::TunnelHandle {
                decoy_name: decoy.name,
                public_url: decoy.tunnel_public_url,
                provider_name,
                remote_port: decoy.tunnel_remote_port,
                pid: decoy.tunnel_pid,
            };
            let _ = provider.stop_tunnel(&handle).await;
        }
    }

    if let Err(e) = docker.terminate_decoy(&container_id).await {
        eprintln!("Warning: Failed to terminate container in Docker (it may have been manually deleted): {}", e);
    }
    let _ = db_writer.0.send(crate::db::DbCommand::DeleteDecoy {
        container_id,
    }).await;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct DecoyDetails {
    pub ip_address: Option<String>,
    pub network_name: Option<String>,
    pub gateway: Option<String>,
    pub ports: Vec<String>,
    pub created_at: Option<String>,
}

#[tauri::command]
pub async fn inspect_decoy(
    docker: tauri::State<'_, crate::docker::DockerProxy>,
    container_id: String,
) -> Result<DecoyDetails, String> {
    validate_input(&container_id, "container_id")?;
    let details = docker.inspect_decoy(&container_id).await?;
    
    Ok(DecoyDetails {
        ip_address: details.ip_address,
        network_name: details.network_name,
        gateway: details.gateway,
        ports: details.ports,
        created_at: details.created_at,
    })
}

#[tauri::command]
pub async fn verify_isolation(
    docker: tauri::State<'_, crate::docker::DockerProxy>,
    container_id: String,
) -> Result<String, String> {
    validate_input(&container_id, "container_id")?;
    docker.verify_isolation(&container_id).await
}

#[tauri::command]
pub async fn capture_pcap(
    docker: tauri::State<'_, crate::docker::DockerProxy>,
    container_id: String,
    duration: u64,
) -> Result<String, String> {
    validate_input(&container_id, "container_id")?;
    docker.capture_pcap(&container_id, duration).await
}

#[tauri::command]
pub async fn delete_network(
    docker: tauri::State<'_, crate::docker::DockerProxy>,
    network_name: String,
) -> Result<(), String> {
    docker.delete_network(&network_name).await
}

/// Check if the Docker daemon is reachable.
#[tauri::command]
pub async fn check_docker(
    docker: tauri::State<'_, crate::docker::DockerProxy>,
) -> Result<(), String> {
    docker.ping().await
}

/// Retrieve list of DecoyOps-managed Docker networks
#[tauri::command]
pub async fn get_docker_networks(
    docker: tauri::State<'_, crate::docker::DockerProxy>,
) -> Result<Vec<String>, String> {
    docker.list_networks().await
}

/// Retrieve the current telemetry snapshot for all managed decoys.
///
/// Reads from the database (populated by docker.rs event stream + reconcile).
///
/// # Returns
/// A list of decoy status summaries, or an error string.
#[tauri::command]
pub async fn get_fleet_telemetry(db_read: State<'_, DbRead>) -> Result<Vec<DecoyStatus>, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;
    let decoys = db::get_all_decoys(&conn).map_err(|e| e.to_string())?;
    Ok(decoys
        .into_iter()
        .map(|d| DecoyStatus {
            container_id: d.container_id,
            name: d.name,
            state: d.state,
            realism_score: d.realism_score,
            tunnel_public_url: d.tunnel_public_url,
            tunnel_provider: d.tunnel_provider,
        })
        .collect())
}

/// Generate an incident report in Markdown format.
#[tauri::command]
pub async fn generate_markdown_report(
    db_read: State<'_, DbRead>,
    session_id: i64,
) -> Result<String, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;

    let session = db::get_session_by_id(&conn, session_id)
        .map_err(|e| format!("Failed to fetch session: {}", e))?
        .ok_or("Session not found")?;

    let events = db::get_events_for_session(&conn, session_id)
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let files = db::get_captured_files_for_session(&conn, session_id)
        .map_err(|e| format!("Failed to fetch files: {}", e))?;

    let mut report = format!(
        "# DecoyOps Incident Report: Session {}\n\n## Overview\n- **Target Container ID**: {}\n- **Attacker IP**: {}\n- **Geo-Location**: {}, {}\n- **Started At**: {}\n- **Ended At**: {}\n\n",
        session_id,
        session.container_id,
        session.source_ip,
        session.geo_city.unwrap_or_else(|| "Unknown".to_string()),
        session.geo_country.unwrap_or_else(|| "Unknown".to_string()),
        session.started_at,
        session.ended_at.unwrap_or_else(|| "Ongoing".to_string())
    );

    report.push_str("## Events Timeline\n| Timestamp | Type | Vector / Detail | MITRE TTP |\n| --- | --- | --- | --- |\n");
    for ev in events {
        report.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            ev.timestamp,
            ev.event_type,
            ev.attack_vector.unwrap_or_else(|| "-".to_string()),
            ev.mitre_ttp.unwrap_or_else(|| "-".to_string())
        ));
    }

    report.push_str("\n## Captured Payloads\n| Captured At | Filename | SHA256 Hash | VT Status |\n| --- | --- | --- | --- |\n");
    if files.is_empty() {
        report.push_str("| - | No payloads captured | - | - |\n");
    } else {
        for f in files {
            report.push_str(&format!(
                "| {} | {} | `{}` | {} |\n",
                f.captured_at,
                f.original_name.unwrap_or_else(|| "unknown".to_string()),
                f.sha256,
                f.vt_status.unwrap_or_else(|| "pending".to_string())
            ));
        }
    }

    Ok(report)
}

/// Generate a STIX 2.1 JSON bundle for a session.
#[tauri::command]
pub async fn generate_stix_report(
    db_read: State<'_, DbRead>,
    session_id: i64,
) -> Result<String, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;

    let session = db::get_session_by_id(&conn, session_id)
        .map_err(|e| format!("Failed to fetch session: {}", e))?
        .ok_or("Session not found")?;

    let files = db::get_captured_files_for_session(&conn, session_id)
        .map_err(|e| format!("Failed to fetch files: {}", e))?;

    let mut stix_objects = vec![];

    // IP Address Object
    let ip_id = format!("ipv4-addr--{}", uuid::Uuid::new_v4());
    stix_objects.push(serde_json::json!({
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": ip_id,
        "value": session.source_ip,
    }));

    // Malware/File Objects for captured files
    for f in files {
        let file_id = format!("file--{}", uuid::Uuid::new_v4());
        stix_objects.push(serde_json::json!({
            "type": "file",
            "spec_version": "2.1",
            "id": file_id,
            "hashes": {
                "SHA-256": f.sha256
            },
            "name": f.original_name.unwrap_or_else(|| "unknown".to_string())
        }));
    }

    let bundle = serde_json::json!({
        "type": "bundle",
        "id": format!("bundle--{}", uuid::Uuid::new_v4()),
        "objects": stix_objects
    });

    serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())
}

/// Export all events to a CSV format string.
#[tauri::command]
pub async fn export_all_incidents_csv(
    db_read: State<'_, DbRead>,
) -> Result<String, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;

    let mut stmt = conn.prepare(
        "SELECT e.id, e.session_id, e.container_id, e.event_type, e.source_ip, e.attack_vector, e.raw_data, e.timestamp, e.mitre_ttp
         FROM events e
         ORDER BY e.timestamp DESC"
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map([], |row| {
        Ok(crate::db::EventRow {
            id: row.get(0)?,
            session_id: row.get(1)?,
            container_id: row.get(2)?,
            event_type: row.get(3)?,
            source_ip: row.get(4)?,
            attack_vector: row.get(5)?,
            raw_data: row.get(6)?,
            timestamp: row.get(7)?,
            mitre_ttp: row.get(8)?,
            geo_lat: None,
            geo_lon: None,
            tty_log_path: None,
        })
    }).map_err(|e| e.to_string())?;

    let mut csv_out = String::new();
    csv_out.push_str("Timestamp,SessionID,ContainerID,SourceIP,EventType,AttackVector,MitreTTP,RawData\n");

    for row in rows.flatten() {
        let raw_data = row.raw_data.unwrap_or_default().replace("\"", "\"\"");
        let attack_vector = row.attack_vector.unwrap_or_default().replace("\"", "\"\"");
        let source_ip = row.source_ip.unwrap_or_default();
        let mitre_ttp = row.mitre_ttp.unwrap_or_default();
        
        csv_out.push_str(&format!("{},{},{},{},{},\"{}\",\"{}\",\"{}\"\n",
            row.timestamp,
            row.session_id,
            row.container_id,
            source_ip,
            row.event_type,
            attack_vector,
            mitre_ttp,
            raw_data
        ));
    }

    Ok(csv_out)
}

/// Securely read a TTY log file.
#[tauri::command]
pub async fn read_tty_log(log_path: String) -> Result<String, String> {
    // Only allow reading from the data/logs directory to prevent path traversal
    let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let safe_base = current_dir.join("data").join("logs");
    
    let requested_path = std::path::PathBuf::from(&log_path);
    let abs_requested = std::fs::canonicalize(&requested_path).unwrap_or(requested_path);
    let abs_base = std::fs::canonicalize(&safe_base).unwrap_or(safe_base);
    
    if !abs_requested.starts_with(abs_base) {
        return Err("Path traversal attempt blocked.".to_string());
    }

    tokio::fs::read_to_string(abs_requested)
        .await
        .map_err(|e| format!("Failed to read log: {}", e))
}

/// Get recent events for the incident feed table.
///
/// # Arguments
/// - `limit` — Maximum number of events to return.
#[tauri::command]
pub async fn get_incident_feed(
    db_read: State<'_, DbRead>,
    limit: u32,
) -> Result<Vec<db::EventRow>, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;
    db::get_recent_events(&conn, limit).map_err(|e| e.to_string())
}

/// Get dashboard counter values (active decoys, sessions, unique actors, etc.).
#[tauri::command]
pub async fn get_dashboard_counters(
    db_read: State<'_, DbRead>,
) -> Result<db::DashboardCounters, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;
    crate::db::get_dashboard_counters(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_blocklist(db_read: tauri::State<'_, DbRead>) -> Result<String, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;
    crate::db::get_blocklist(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_quarantined_files(db_read: tauri::State<'_, DbRead>) -> Result<Vec<crate::db::CapturedFileRow>, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;
    db::get_quarantined_files(&conn).map_err(|e| e.to_string())
}

/// Read a chunk of a quarantined file as hex string (safe read-only inspection).
#[tauri::command]
pub async fn read_quarantine_hex(
    file_path: String,
) -> Result<String, String> {
    // Basic safety check: ensure the file has our expected quarantine extension
    if !file_path.ends_with(".isolated") {
        return Err("Not a quarantined file".to_string());
    }
    
    // Prevent path traversal by strictly requiring the file to be inside data/quarantine
    let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let safe_base = current_dir.join("data").join("quarantine");
    
    let requested_path = std::path::PathBuf::from(&file_path);
    let abs_requested = std::fs::canonicalize(&requested_path).unwrap_or(requested_path);
    let abs_base = std::fs::canonicalize(&safe_base).unwrap_or(safe_base);
    
    if !abs_requested.starts_with(abs_base) {
        return Err("Path traversal attempt blocked.".to_string());
    }
    
    // Read up to first 4KB only for the hex viewer
    use std::io::Read;
    let mut file = std::fs::File::open(&abs_requested).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut buffer = [0; 4096];
    let bytes_read = file.read(&mut buffer).unwrap_or(0);
    
// Convert to hex string
    let hex_string = hex::encode(&buffer[..bytes_read]);
    Ok(hex_string)
}

/// Securely save an API key to the OS keyring.
#[tauri::command]
pub async fn save_api_key(service: String, key: String) -> Result<(), String> {
    let entry = keyring::Entry::new("decoyops", &service).map_err(|e| e.to_string())?;
    if key.is_empty() {
        // Use delete_credential for keyring v3
        let _ = entry.delete_credential();
    } else {
        entry.set_password(&key).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Securely retrieve an API key from the OS keyring.
#[tauri::command]
pub async fn get_api_key(service: String) -> Result<String, String> {
    let entry = keyring::Entry::new("decoyops", &service).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(pw) => Ok(pw),
        Err(keyring::Error::NoEntry) => Ok("".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub async fn enrich_hash(
    pipeline: tauri::State<'_, crate::pipeline::ThreatIntelPipeline>,
    db_read: tauri::State<'_, DbRead>,
    hash: String,
) -> Result<(), String> {
    pipeline.enrich_hash(&hash, &db_read.0).await
}

#[tauri::command]
pub async fn enrich_ip(
    pipeline: tauri::State<'_, crate::pipeline::ThreatIntelPipeline>,
    db_read: tauri::State<'_, DbRead>,
    ip: String,
) -> Result<(), String> {
    pipeline.enrich_ip(&ip, &db_read.0).await
}

/// Retrieve the host operating system (e.g., "windows", "linux", "macos").
#[tauri::command]
pub async fn get_os() -> Result<String, String> {
    Ok(std::env::consts::OS.to_string())
}

/// Danger Zone: Purge all telemetry and historic payload data.
#[tauri::command]
pub async fn purge_telemetry(
    db_read: State<'_, DbRead>,
) -> Result<(), String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;
    
    // Wipe Database tables
    conn.execute("DELETE FROM events", []).map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM sessions", []).map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM captured_files", []).map_err(|e| e.to_string())?;
    
    // Reset the auto-increment counters so IDs start from 1 again
    let _ = conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('events', 'sessions', 'captured_files')", []);
    
    // Wipe Quarantine Disk Directory
    let app_data_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let quarantine_dir = app_data_dir.join("data").join("quarantine");
    let _ = std::fs::remove_dir_all(&quarantine_dir);
    let _ = std::fs::create_dir_all(&quarantine_dir);
    
    // Write an audit log trail
    use std::io::Write;
    let audit_log = app_data_dir.join("logs").join("decoyops-audit.log");
    if let Some(parent) = audit_log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(audit_log) {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let _ = writeln!(file, "[{}] SECURITY AUDIT: Operator executed purge_telemetry. All historic DB events and quarantined payloads deleted.", timestamp);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// FRP Tunnel Management
// ---------------------------------------------------------------------------

use sysinfo::System;

fn get_tools_dir() -> std::path::PathBuf {
    let app_data_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let mut tools_dir = app_data_dir.join("tools");
    
    // In Tauri dev mode, current_dir is src-tauri. Check the parent directory.
    if !tools_dir.exists() {
        let parent_tools = app_data_dir.join("..").join("tools");
        if parent_tools.exists() {
            tools_dir = parent_tools;
        }
    }
    
    tools_dir
}

#[tauri::command]
pub async fn start_frp_client() -> Result<(), String> {
    let tools_dir = get_tools_dir();
    let frp_dir = tools_dir.join("frp");
    
    let frpc_exe = if cfg!(target_os = "windows") { "frpc.exe" } else { "frpc" };
    let frpc_path = frp_dir.join(frpc_exe);

    if !frpc_path.exists() {
        return Err(format!("FRP client executable not found at {:?}", frpc_path));
    }

    // Spawn the child process detached
    std::process::Command::new(&frpc_path)
        .arg("-c")
        .arg(frp_dir.join("frpc.toml"))
        .current_dir(&frp_dir)
        .spawn()
        .map_err(|e| format!("Failed to start FRP client: {}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn stop_frp_client() -> Result<(), String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    let mut killed = 0;
    for process in sys.processes_by_exact_name(std::ffi::OsStr::new(if cfg!(target_os = "windows") { "frpc.exe" } else { "frpc" })) {
        if process.kill() {
            killed += 1;
        }
    }

    if killed > 0 {
        Ok(())
    } else {
        Err("No running FRP client found".to_string())
    }
}

#[tauri::command]
pub async fn get_frp_status() -> Result<bool, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    let is_running = sys.processes_by_exact_name(std::ffi::OsStr::new(if cfg!(target_os = "windows") { "frpc.exe" } else { "frpc" })).next().is_some();
    Ok(is_running)
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TunnelSettings {
    pub provider: String,
    pub ngrok_authtoken: String,
    pub ngrok_binary_path: String,
    pub frp_server_addr: String,
    pub frp_auth_token: String,
    pub frp_binary_path: String,
    pub frp_port_range_start: u16,
    pub frp_port_range_end: u16,
}

#[tauri::command]
pub async fn get_tunnel_settings(db_read: tauri::State<'_, DbRead>) -> Result<TunnelSettings, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;

    let provider = crate::db::get_setting(&conn, "tunnel_provider").unwrap_or(None).unwrap_or_else(|| "frp".to_string());
    let ngrok_binary_path = crate::db::get_setting(&conn, "ngrok_binary_path").unwrap_or(None).unwrap_or_else(|| "tools/ngrok/ngrok".to_string());
    let frp_binary_path = crate::db::get_setting(&conn, "frp_binary_path").unwrap_or(None).unwrap_or_else(|| "tools/frp/frpc".to_string());
    let frp_server_addr = crate::db::get_setting(&conn, "frp_server_addr").unwrap_or(None).unwrap_or_else(|| "".to_string());
    let frp_port_range_start = crate::db::get_setting(&conn, "frp_port_range_start").unwrap_or(None).unwrap_or_else(|| "10000".to_string()).parse().unwrap_or(10000);
    let frp_port_range_end = crate::db::get_setting(&conn, "frp_port_range_end").unwrap_or(None).unwrap_or_else(|| "20000".to_string()).parse().unwrap_or(20000);

    let ngrok_authtoken = match keyring::Entry::new("decoyops", "ngrok_authtoken").and_then(|e| e.get_password()) {
        Ok(key) => key,
        Err(_) => "".to_string(),
    };
    
    let frp_auth_token = match keyring::Entry::new("decoyops", "frp_auth_token").and_then(|e| e.get_password()) {
        Ok(key) => key,
        Err(_) => "".to_string(),
    };

    Ok(TunnelSettings {
        provider,
        ngrok_authtoken,
        ngrok_binary_path,
        frp_server_addr,
        frp_auth_token,
        frp_binary_path,
        frp_port_range_start,
        frp_port_range_end,
    })
}

#[tauri::command]
pub async fn save_tunnel_settings(
    db_writer: tauri::State<'_, DbWriter>,
    settings: TunnelSettings,
) -> Result<(), String> {
    let mut tasks = vec![];
    
    tasks.push(db_writer.0.send(crate::db::DbCommand::UpdateSetting { key: "tunnel_provider".to_string(), value: settings.provider.clone() }));
    tasks.push(db_writer.0.send(crate::db::DbCommand::UpdateSetting { key: "ngrok_binary_path".to_string(), value: settings.ngrok_binary_path.clone() }));
    tasks.push(db_writer.0.send(crate::db::DbCommand::UpdateSetting { key: "frp_binary_path".to_string(), value: settings.frp_binary_path.clone() }));
    tasks.push(db_writer.0.send(crate::db::DbCommand::UpdateSetting { key: "frp_server_addr".to_string(), value: settings.frp_server_addr.clone() }));
    tasks.push(db_writer.0.send(crate::db::DbCommand::UpdateSetting { key: "frp_port_range_start".to_string(), value: settings.frp_port_range_start.to_string() }));
    tasks.push(db_writer.0.send(crate::db::DbCommand::UpdateSetting { key: "frp_port_range_end".to_string(), value: settings.frp_port_range_end.to_string() }));
    
    for task in tasks {
        let _ = task.await;
    }
    
    if settings.ngrok_authtoken.is_empty() {
        let _ = keyring::Entry::new("decoyops", "ngrok_authtoken").and_then(|e| e.delete_credential());
    } else {
        let _ = keyring::Entry::new("decoyops", "ngrok_authtoken").and_then(|e| e.set_password(&settings.ngrok_authtoken));
    }

    if settings.frp_auth_token.is_empty() {
        let _ = keyring::Entry::new("decoyops", "frp_auth_token").and_then(|e| e.delete_credential());
    } else {
        let _ = keyring::Entry::new("decoyops", "frp_auth_token").and_then(|e| e.set_password(&settings.frp_auth_token));
    }

    Ok(())
}

pub fn get_provider(conn: &rusqlite::Connection, provider_name: &str) -> Box<dyn crate::tunnel::TunnelProvider> {
    if provider_name == "ngrok" {
        let authtoken = keyring::Entry::new("decoyops", "ngrok_authtoken").and_then(|e| e.get_password()).unwrap_or_default();
        let binary_path = crate::db::get_setting(conn, "ngrok_binary_path").unwrap_or(None).unwrap_or_default();
        Box::new(crate::tunnel::NgrokProvider { authtoken, binary_path })
    } else {
        let binary_path = crate::db::get_setting(conn, "frp_binary_path").unwrap_or(None).unwrap_or_default();
        let server_addr = crate::db::get_setting(conn, "frp_server_addr").unwrap_or(None).unwrap_or_default();
        let auth_token = keyring::Entry::new("decoyops", "frp_auth_token").and_then(|e| e.get_password()).unwrap_or_default();
        let tools_dir = get_tools_dir();
        let config_path = tools_dir.join("frp").join("frpc.toml").to_string_lossy().to_string();
        Box::new(crate::tunnel::FrpProvider { binary_path, config_path, server_addr, auth_token })
    }
}

#[derive(serde::Serialize)]
pub struct DependenciesStatus {
    pub docker: bool,
    pub ngrok: bool,
    pub frpc: bool,
}

#[tauri::command]
pub async fn check_dependencies(db_read: tauri::State<'_, DbRead>) -> Result<DependenciesStatus, String> {
    let docker_ok = std::process::Command::new("docker")
        .arg("-v")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let conn = db_read.0.lock().map_err(|e| e.to_string())?;

    let ngrok_path = crate::db::get_setting(&conn, "ngrok_binary_path")
        .unwrap_or(None)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ngrok".to_string());

    let ngrok_ok = std::process::Command::new(&ngrok_path)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let frp_path = crate::db::get_setting(&conn, "frp_binary_path")
        .unwrap_or(None)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| if cfg!(target_os = "windows") { "frpc.exe".to_string() } else { "frpc".to_string() });

    let frpc_ok = std::process::Command::new(&frp_path)
        .arg("-v")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    Ok(DependenciesStatus {
        docker: docker_ok,
        ngrok: ngrok_ok,
        frpc: frpc_ok,
    })
}

#[tauri::command]
pub async fn get_extracted_iocs(
    db_read: State<'_, DbRead>,
    limit: u32,
) -> Result<Vec<db::IocRow>, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;
    db::get_recent_iocs(&conn, limit).map_err(|e| e.to_string())
}


#[tauri::command]
pub async fn factory_reset(app_handle: tauri::AppHandle) -> Result<(), String> {
    // 1. Wipe keyrings
    let keys = ["abuseipdb", "virustotal", "ngrok_authtoken", "frp_auth_token"];
    for key in keys.iter() {
        if let Ok(entry) = keyring::Entry::new("decoyops", key) {
            let _ = entry.delete_credential();
        }
    }

    // 2. Wipe directories (data/logs, quarantine)
    let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let logs_dir = current_dir.join("data").join("logs");
    if logs_dir.exists() {
        let _ = std::fs::remove_dir_all(&logs_dir);
    }

    let app_data_dir = app_handle.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let quarantine_dir = app_data_dir.join("quarantine");
    if quarantine_dir.exists() {
        let _ = std::fs::remove_dir_all(&quarantine_dir);
    }

    // 3. Wipe Databases 
    // Since Windows locks the open sqlite DB file, we will drop the tables instead of deleting the file.
    // However, since it's easier to just exit and let the user restart (or drop tables), we'll do DROP.
    let db_path = "decoyops.db";
    if let Ok(conn) = rusqlite::Connection::open(db_path) {
        let _ = conn.execute_batch("
            PRAGMA writable_schema = 1;
            DELETE FROM sqlite_master WHERE type IN ('table', 'index', 'trigger');
            PRAGMA writable_schema = 0;
            VACUUM;
            PRAGMA user_version = 0;
        ");
    }

    Ok(())
}
