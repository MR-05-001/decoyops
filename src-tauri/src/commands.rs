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

use std::sync::{Mutex, OnceLock};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::db;
use regex::Regex;

/// Pre-compiled regex for general input validation (INFO-4 fix).
static INPUT_RE: OnceLock<Regex> = OnceLock::new();
/// Pre-compiled regex for Docker image name validation (INFO-4 fix).
static IMAGE_RE: OnceLock<Regex> = OnceLock::new();

fn validate_input(input: &str, field_name: &str) -> Result<(), String> {
    let re = INPUT_RE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap());
    if !re.is_match(input) {
        return Err(format!(
            "Invalid characters in {}. Only alphanumeric, dashes, and underscores are allowed.",
            field_name
        ));
    }
    Ok(())
}

fn validate_image_name(input: &str, field_name: &str) -> Result<(), String> {
    let re = IMAGE_RE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_:/.-]+$").unwrap());
    if !re.is_match(input) {
        return Err(format!(
            "Invalid characters in {}. Only standard docker image characters allowed.",
            field_name
        ));
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
    let tpl = template_type.to_lowercase();

    if tpl.contains("cowrie") || tpl.contains("dionaea") || tpl.contains("conpot") {
        score += 15;
    } else if tpl.contains("mailoney") || tpl.contains("elasticpot") || tpl.contains("endlessh") {
        score += 10;
    }

    if let Ok((_, host_port_str, _)) = crate::docker::validate_port_mapping(port_mapping) {
        if let Ok(host_port) = host_port_str.parse::<u16>() {
            match host_port {
                22 | 25 | 80 | 443 | 445 | 502 | 9200 => score += 20,
                2222 | 8080 => score -= 10,
                _ => {}
            }
        }
    }

    score.clamp(0, 100)
}

fn validate_api_service(service: &str) -> Result<(), String> {
    match service {
        "abuseipdb" | "virustotal" => Ok(()),
        _ => Err(format!("Unsupported API key service: '{}'", service)),
    }
}

fn escape_md_cell(val: &str) -> String {
    val.replace('|', "\\|")
        .replace(['\r', '\n'], " ")
        .replace('`', "\\`")
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn deploy_decoy(
    app: tauri::AppHandle,
    app_paths: State<'_, crate::AppPaths>,
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
        if !net.is_empty() {
            validate_input(net, "network_name")?;
        }
    }
    if let Some(ref provider) = tunnel_provider {
        validate_input(provider, "tunnel_provider")?;
    }

    let mut resolved_port_mapping = port_mapping.clone();
    if let Some(container_port) = resolved_port_mapping.strip_prefix("0:") {
        let port_num = container_port.parse::<u16>().map_err(|_| {
            "Invalid port_mapping: container port must be between 1-65535".to_string()
        })?;
        if port_num == 0 {
            return Err("Invalid port_mapping: container port must be between 1-65535".to_string());
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to allocate ephemeral host port: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("Failed to inspect ephemeral host port: {e}"))?;
        resolved_port_mapping = format!("{}:{}", addr.port(), port_num);
    }
    crate::docker::validate_port_mapping(&resolved_port_mapping)?;

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
            let start_port = crate::db::get_setting(&conn, "frp_port_range_start")
                .unwrap_or(None)
                .unwrap_or_else(|| "10000".to_string())
                .parse()
                .unwrap_or(10000);
            let end_port = crate::db::get_setting(&conn, "frp_port_range_end")
                .unwrap_or(None)
                .unwrap_or_else(|| "20000".to_string())
                .parse()
                .unwrap_or(20000);
            allocated_remote_port =
                crate::db::get_next_available_remote_port(&conn, start_port, end_port)
                    .map_err(|e| e.to_string())?;
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

    let _ = db_writer
        .0
        .send(crate::db::DbCommand::InsertDecoy {
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
        })
        .await;

    // Active Verification: poll for telemetry log creation up to 90 seconds for built-in templates
    // (Dionaea template copy + service init can take ~60s on Windows bind mounts)
    let verify_folder = crate::docker::sanitize_decoy_name(&name);
    let verify_logs_dir = app_paths.data_dir.join("logs");
    let verify_template = template_type.clone();
    let expects_telemetry = {
        let lower = verify_template.to_lowercase();
        lower.contains("cowrie")
            || lower.contains("dionaea")
            || lower.contains("conpot")
            || lower.contains("elasticpot")
            || lower.contains("mailoney")
            || lower.contains("endlessh")
    };
    if expects_telemetry {
        tauri::async_runtime::spawn(async move {
            let log_dir = verify_logs_dir.join(&verify_folder);
            let mut log_found = false;

            for _ in 0..18 {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if let Ok(entries) = std::fs::read_dir(&log_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().is_some_and(|ext| ext == "json")
                            || matches!(
                                p.file_name().and_then(|n| n.to_str()),
                                Some("commands.log" | "endlessh.log")
                            )
                        {
                            log_found = true;
                            break;
                        }
                    }
                }
                if log_found {
                    break;
                }
            }

            if !log_found {
                use tauri::Emitter;
                let _ = app.emit(
                    "telemetry-warning",
                    format!(
                        "Telemetry Error: {} container deployed but no telemetry log detected.",
                        verify_template
                    ),
                );
            }
        });
    }

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
        crate::db::get_all_decoys(&conn)
            .unwrap_or_default()
            .into_iter()
            .find(|d| d.container_id == container_id)
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
    let _ = db_writer
        .0
        .send(crate::db::DbCommand::DeleteDecoy { container_id })
        .await;
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

/// Delete a DecoyOps-managed Docker network.
///
/// CRIT-3 fix: validates input and verifies the network carries the
/// `decoyops.managed=true` label before deletion to prevent arbitrary
/// Docker network removal.
#[tauri::command]
pub async fn delete_network(
    docker: tauri::State<'_, crate::docker::DockerProxy>,
    network_name: String,
) -> Result<(), String> {
    validate_input(&network_name, "network_name")?;

    // Verify this is a DecoyOps-managed network before deleting
    let managed_networks = docker.list_networks().await?;
    if !managed_networks.contains(&network_name) {
        return Err(format!(
            "Refusing to delete '{}': not a DecoyOps-managed network",
            network_name
        ));
    }

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
        escape_md_cell(&session.container_id),
        escape_md_cell(&session.source_ip),
        escape_md_cell(&session.geo_city.unwrap_or_else(|| "Unknown".to_string())),
        escape_md_cell(&session.geo_country.unwrap_or_else(|| "Unknown".to_string())),
        escape_md_cell(&session.started_at),
        escape_md_cell(&session.ended_at.unwrap_or_else(|| "Ongoing".to_string()))
    );

    report.push_str("## Events Timeline\n| Timestamp | Type | Vector / Detail | MITRE TTP |\n| --- | --- | --- | --- |\n");
    for ev in events {
        report.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            escape_md_cell(&ev.timestamp),
            escape_md_cell(&ev.event_type),
            escape_md_cell(&ev.attack_vector.unwrap_or_else(|| "-".to_string())),
            escape_md_cell(&ev.mitre_ttp.unwrap_or_else(|| "-".to_string()))
        ));
    }

    report.push_str("\n## Captured Payloads\n| Captured At | Filename | SHA256 Hash | VT Status |\n| --- | --- | --- | --- |\n");
    if files.is_empty() {
        report.push_str("| - | No payloads captured | - | - |\n");
    } else {
        for f in files {
            report.push_str(&format!(
                "| {} | {} | `{}` | {} |\n",
                escape_md_cell(&f.captured_at),
                escape_md_cell(&f.original_name.unwrap_or_else(|| "unknown".to_string())),
                escape_md_cell(&f.sha256),
                escape_md_cell(&f.vt_status.unwrap_or_else(|| "pending".to_string()))
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

    // IP Address Object (emit ipv4-addr or ipv6-addr accurately)
    let stix_ip_type = match session.source_ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => "ipv6-addr",
        _ => "ipv4-addr",
    };
    let ip_id = format!("{}--{}", stix_ip_type, uuid::Uuid::new_v4());
    stix_objects.push(serde_json::json!({
        "type": stix_ip_type,
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
pub async fn export_all_incidents_csv(db_read: State<'_, DbRead>) -> Result<String, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;

    let mut stmt = conn.prepare(
        "SELECT e.id, e.session_id, e.container_id, e.event_type, e.source_ip, e.attack_vector, e.raw_data, e.timestamp, e.mitre_ttp
         FROM events e
         ORDER BY e.timestamp DESC"
    ).map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([], |row| {
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
        })
        .map_err(|e| e.to_string())?;

    let mut csv_out = String::new();
    csv_out.push_str(
        "\"Timestamp\",\"SessionID\",\"ContainerID\",\"SourceIP\",\"EventType\",\"AttackVector\",\"MitreTTP\",\"RawData\"\n",
    );

    // HIGH-7 fix: safely escape and quote all CSV fields, and prevent spreadsheet formula injection
    let escape_csv_field = |val: &str| -> String {
        let mut escaped = val.replace('\"', "\"\"");
        let trimmed = escaped.trim_start_matches([' ', '\t', '\r', '\n']);
        if escaped.starts_with(['=', '+', '-', '@', '\t', '\r'])
            || trimmed.starts_with(['=', '+', '-', '@'])
        {
            escaped = format!("'{}", escaped);
        }
        format!("\"{}\"", escaped)
    };

    for row in rows.flatten() {
        let timestamp = escape_csv_field(&row.timestamp);
        let session_id = row.session_id;
        let container_id = escape_csv_field(&row.container_id);
        let source_ip = escape_csv_field(&row.source_ip.unwrap_or_default());
        let event_type = escape_csv_field(&row.event_type);
        let attack_vector = escape_csv_field(&row.attack_vector.unwrap_or_default());
        let mitre_ttp = escape_csv_field(&row.mitre_ttp.unwrap_or_default());
        let raw_data = escape_csv_field(&row.raw_data.unwrap_or_default());

        csv_out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            timestamp,
            session_id,
            container_id,
            source_ip,
            event_type,
            attack_vector,
            mitre_ttp,
            raw_data
        ));
    }

    Ok(csv_out)
}

/// Securely read a TTY log file.
///
/// MED-8 fix: returns an error if path canonicalization fails instead of
/// falling back to the uncanonicalized path, which could allow traversal.
fn strip_ansi_and_controls(raw: &[u8]) -> String {
    let mut cleaned = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b == 0x1b {
            // ESC sequence
            if i + 1 < raw.len() {
                match raw[i + 1] {
                    b'[' => {
                        // CSI: ESC [ ... final byte (0x40..=0x7E)
                        i += 2;
                        while i < raw.len() && !(0x40..=0x7e).contains(&raw[i]) {
                            i += 1;
                        }
                        if i < raw.len() {
                            i += 1;
                        }
                        continue;
                    }
                    b']' => {
                        // OSC: ESC ] ... BEL (0x07) or ST (ESC \)
                        i += 2;
                        while i < raw.len() {
                            if raw[i] == 0x07 {
                                i += 1;
                                break;
                            }
                            if raw[i] == 0x1b && i + 1 < raw.len() && raw[i + 1] == b'\\' {
                                i += 2;
                                break;
                            }
                            i += 1;
                        }
                        continue;
                    }
                    b'(' | b')' | b'*' | b'+' => {
                        // 3-byte ISO-2022 charset selection (e.g., ESC ( B)
                        i += if i + 2 < raw.len() { 3 } else { 2 };
                        continue;
                    }
                    _ => {
                        // 2-byte ESC sequence
                        i += 2;
                        continue;
                    }
                }
            }
            i += 1;
        } else if b == b'\r' {
            i += 1;
        } else if b == 0x08 || b == 0x7f {
            // Backspace / DEL
            if cleaned.last().is_some_and(|&prev| prev != b'\n') {
                cleaned.pop();
            }
            i += 1;
        } else if b < 0x20 && b != b'\n' && b != b'\t' {
            i += 1;
        } else {
            cleaned.push(b);
            i += 1;
        }
    }
    String::from_utf8_lossy(&cleaned).into_owned()
}

/// Decodes a Cowrie UML binary TTY recording (24-byte `<iIIIII` headers: op, tty, len, dir, sec, usec)
/// into readable terminal output, or falls back to sanitized text for non-UML logs.
fn decode_cowrie_tty(bytes: &[u8]) -> String {
    if bytes.len() >= 24 {
        let mut offset = 0usize;
        let mut out_dir2 = Vec::new();
        let mut out_any = Vec::new();
        let mut valid_frames = 0usize;
        let mut saw_uml_open = false;
        let mut parsed_cleanly = true;

        while let Some(header_end) = offset.checked_add(24) {
            if header_end > bytes.len() {
                parsed_cleanly = false;
                break;
            }
            let h = &bytes[offset..header_end];
            let op = i32::from_le_bytes([h[0], h[1], h[2], h[3]]);
            let length = u32::from_le_bytes([h[8], h[9], h[10], h[11]]) as usize;
            let dir = u32::from_le_bytes([h[12], h[13], h[14], h[15]]);

            if !(1..=4).contains(&op) {
                parsed_cleanly = false;
                break;
            }
            if offset == 0 && op == 1 && length == 0 {
                saw_uml_open = true;
            }
            let Some(data_end) = header_end.checked_add(length) else {
                parsed_cleanly = false;
                break;
            };
            if data_end > bytes.len() {
                parsed_cleanly = false;
                break;
            }

            if op == 3 {
                let payload = &bytes[header_end..data_end];
                if dir == 2 {
                    out_dir2.extend_from_slice(payload);
                }
                out_any.extend_from_slice(payload);
            }

            valid_frames += 1;
            offset = data_end;
            if offset == bytes.len() {
                break;
            }
        }

        let complete = parsed_cleanly && valid_frames > 0 && offset == bytes.len();
        let truncated_uml =
            (saw_uml_open || valid_frames >= 2) && (!out_dir2.is_empty() || !out_any.is_empty());
        if complete || truncated_uml {
            let stream = if !out_dir2.is_empty() {
                &out_dir2
            } else {
                &out_any
            };
            return strip_ansi_and_controls(stream);
        }
    }

    strip_ansi_and_controls(bytes)
}

#[tauri::command]
pub async fn read_tty_log(
    app_paths: State<'_, crate::AppPaths>,
    log_path: String,
) -> Result<String, String> {
    // Only allow reading from the canonical logs directory to prevent path traversal
    let safe_base = app_paths.data_dir.join("logs");

    let req = std::path::PathBuf::from(&log_path);
    let mut requested_path = if req.is_relative() {
        safe_base.join(&req)
    } else {
        req
    };

    // Compatibility: older DB records stored Cowrie's container-relative path ("var/lib/cowrie/tty/<id>").
    // Map only the terminal filename into "<logs>/<decoy>/tty/<id>" safely without traversing.
    if !requested_path.exists()
        && (log_path.starts_with("var/lib/cowrie/tty/")
            || log_path.starts_with("var/log/cowrie/tty/"))
    {
        if let Some(fname) = std::path::Path::new(&log_path).file_name() {
            if let Ok(entries) = std::fs::read_dir(&safe_base) {
                for entry in entries.flatten() {
                    let candidate = entry.path().join("tty").join(fname);
                    if candidate.is_file() {
                        requested_path = candidate;
                        break;
                    }
                }
            }
        }
    }

    let abs_requested = std::fs::canonicalize(&requested_path).map_err(|_| {
        "TTY recording file not found on host (note: legacy Cowrie containers created before TTY mount support only stored recordings inside the container).".to_string()
    })?;
    let abs_base = std::fs::canonicalize(&safe_base)
        .map_err(|_| "Internal error: log base directory not found.".to_string())?;

    if !abs_requested.starts_with(abs_base) {
        return Err("Path traversal attempt blocked.".to_string());
    }

    const MAX_TTY_BYTES: u64 = 2 * 1024 * 1024;
    let meta = tokio::fs::metadata(&abs_requested)
        .await
        .map_err(|e| format!("Failed to stat log: {}", e))?;
    if meta.len() > MAX_TTY_BYTES {
        return Err("TTY log exceeds 2 MiB safety limit".to_string());
    }

    let bytes = tokio::fs::read(abs_requested)
        .await
        .map_err(|e| format!("Failed to read log: {}", e))?;
    Ok(decode_cowrie_tty(&bytes))
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
pub async fn get_quarantined_files(
    db_read: tauri::State<'_, DbRead>,
) -> Result<Vec<crate::db::CapturedFileRow>, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;
    db::get_quarantined_files(&conn).map_err(|e| e.to_string())
}

/// Read a chunk of a quarantined file as hex string (safe read-only inspection).
///
/// MED-8 fix: returns an error if canonicalization fails.
#[tauri::command]
pub async fn read_quarantine_hex(
    app_paths: State<'_, crate::AppPaths>,
    file_path: String,
) -> Result<String, String> {
    // Basic safety check: ensure the file has our expected quarantine extension
    if !file_path.ends_with(".isolated") {
        return Err("Not a quarantined file".to_string());
    }

    // Prevent path traversal by strictly requiring the file to be inside the canonical quarantine directory
    let safe_base = &app_paths.quarantine_dir;

    let requested_path = std::path::PathBuf::from(&file_path);
    let abs_requested = std::fs::canonicalize(&requested_path)
        .map_err(|_| "Path traversal attempt blocked: cannot resolve path.".to_string())?;
    let abs_base = std::fs::canonicalize(safe_base)
        .map_err(|_| "Internal error: quarantine directory not found.".to_string())?;

    if !abs_requested.starts_with(abs_base) {
        return Err("Path traversal attempt blocked.".to_string());
    }

    // Read up to first 4KB only for the hex viewer
    use std::io::Read;
    let mut file =
        std::fs::File::open(&abs_requested).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut buffer = [0; 4096];
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    // Convert to hex string
    let hex_string = hex::encode(&buffer[..bytes_read]);
    Ok(hex_string)
}

/// Securely save an API key to the OS keyring.
#[tauri::command]
pub async fn save_api_key(service: String, key: String) -> Result<(), String> {
    validate_api_service(&service)?;
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
    validate_api_service(&service)?;
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
) -> Result<String, String> {
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
///
/// CRIT-1 fix: routes all DELETE operations through the DbWriter channel
/// instead of writing through the read-only connection, preserving the
/// single-writer-task pattern (blueprint v3 §5).
#[tauri::command]
pub async fn purge_telemetry(
    app_paths: State<'_, crate::AppPaths>,
    db_writer: State<'_, DbWriter>,
) -> Result<(), String> {
    // Route the purge through the writer channel to maintain single-writer invariant
    db_writer
        .0
        .send(crate::db::DbCommand::PurgeAll)
        .await
        .map_err(|e| format!("Failed to send purge command: {}", e))?;

    // Small delay to let the writer process the purge before we clean disk
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Wipe Quarantine Disk Directory using canonical quarantine_dir
    let quarantine_dir = &app_paths.quarantine_dir;
    let _ = std::fs::remove_dir_all(quarantine_dir);
    let _ = std::fs::create_dir_all(quarantine_dir);

    // Write an audit log trail
    use std::io::Write;
    let audit_log = app_paths.data_dir.join("logs").join("decoyops-audit.log");
    if let Some(parent) = audit_log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_log)
    {
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
pub async fn start_frp_client(db_read: tauri::State<'_, DbRead>) -> Result<(), String> {
    // Prevent duplicate frpc client instances
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let frpc_proc_name = if cfg!(target_os = "windows") {
        "frpc.exe"
    } else {
        "frpc"
    };
    if sys
        .processes_by_exact_name(std::ffi::OsStr::new(frpc_proc_name))
        .next()
        .is_some()
    {
        return Err("FRP client is already running".to_string());
    }

    let tools_dir = get_tools_dir();
    let frp_dir = tools_dir.join("frp");

    let configured_path = {
        let conn = db_read.0.lock().map_err(|e| e.to_string())?;
        crate::db::get_setting(&conn, "frp_binary_path")
            .unwrap_or(None)
            .filter(|s| !s.trim().is_empty())
    };

    let frpc_path = if let Some(custom) = configured_path {
        crate::tunnel::validate_tunnel_binary(&custom, "frpc")?;
        std::path::PathBuf::from(custom)
    } else {
        frp_dir.join(frpc_proc_name)
    };

    if !frpc_path.exists() {
        return Err(format!(
            "FRP client executable not found at {:?}",
            frpc_path
        ));
    }

    let config_path = frp_dir.join("frpc.toml");
    if !config_path.exists() {
        return Err(format!("FRP configuration not found at {:?}", config_path));
    }

    let auth_token = keyring::Entry::new("decoyops", "frp_auth_token")
        .and_then(|e| e.get_password())
        .unwrap_or_default();

    // Spawn the child process detached with token injected via environment variable
    std::process::Command::new(&frpc_path)
        .arg("-c")
        .arg(&config_path)
        .current_dir(&frp_dir)
        .env("DECOYOPS_FRP_TOKEN", auth_token)
        .spawn()
        .map_err(|e| format!("Failed to start FRP client: {}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn stop_frp_client() -> Result<(), String> {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let mut killed = 0;
    for process in
        sys.processes_by_exact_name(std::ffi::OsStr::new(if cfg!(target_os = "windows") {
            "frpc.exe"
        } else {
            "frpc"
        }))
    {
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
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let is_running = sys
        .processes_by_exact_name(std::ffi::OsStr::new(if cfg!(target_os = "windows") {
            "frpc.exe"
        } else {
            "frpc"
        }))
        .next()
        .is_some();
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
pub async fn get_tunnel_settings(
    db_read: tauri::State<'_, DbRead>,
) -> Result<TunnelSettings, String> {
    let conn = db_read.0.lock().map_err(|e| e.to_string())?;

    let provider = crate::db::get_setting(&conn, "tunnel_provider")
        .unwrap_or(None)
        .unwrap_or_else(|| "frp".to_string());
    let ngrok_binary_path = crate::db::get_setting(&conn, "ngrok_binary_path")
        .unwrap_or(None)
        .unwrap_or_else(|| "tools/ngrok/ngrok".to_string());
    let frp_binary_path = crate::db::get_setting(&conn, "frp_binary_path")
        .unwrap_or(None)
        .unwrap_or_else(|| "tools/frp/frpc".to_string());
    let frp_server_addr = crate::db::get_setting(&conn, "frp_server_addr")
        .unwrap_or(None)
        .unwrap_or_default();
    let frp_port_range_start = crate::db::get_setting(&conn, "frp_port_range_start")
        .unwrap_or(None)
        .unwrap_or_else(|| "10000".to_string())
        .parse()
        .unwrap_or(10000);
    let frp_port_range_end = crate::db::get_setting(&conn, "frp_port_range_end")
        .unwrap_or(None)
        .unwrap_or_else(|| "20000".to_string())
        .parse()
        .unwrap_or(20000);

    let ngrok_authtoken =
        match keyring::Entry::new("decoyops", "ngrok_authtoken").and_then(|e| e.get_password()) {
            Ok(key) => key,
            Err(_) => "".to_string(),
        };

    let frp_auth_token =
        match keyring::Entry::new("decoyops", "frp_auth_token").and_then(|e| e.get_password()) {
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
    crate::tunnel::validate_tunnel_binary(&settings.ngrok_binary_path, "ngrok")?;
    crate::tunnel::validate_tunnel_binary(&settings.frp_binary_path, "frpc")?;
    if settings.frp_port_range_start == 0
        || settings.frp_port_range_start > settings.frp_port_range_end
    {
        return Err("Invalid FRP port range: start port must be >= 1 and <= end port".to_string());
    }
    if settings
        .frp_server_addr
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(
            "Invalid FRP server address: whitespace and control characters are not allowed"
                .to_string(),
        );
    }

    let tasks = vec![
        db_writer.0.send(crate::db::DbCommand::UpdateSetting {
            key: "tunnel_provider".to_string(),
            value: settings.provider.clone(),
        }),
        db_writer.0.send(crate::db::DbCommand::UpdateSetting {
            key: "ngrok_binary_path".to_string(),
            value: settings.ngrok_binary_path.clone(),
        }),
        db_writer.0.send(crate::db::DbCommand::UpdateSetting {
            key: "frp_binary_path".to_string(),
            value: settings.frp_binary_path.clone(),
        }),
        db_writer.0.send(crate::db::DbCommand::UpdateSetting {
            key: "frp_server_addr".to_string(),
            value: settings.frp_server_addr.clone(),
        }),
        db_writer.0.send(crate::db::DbCommand::UpdateSetting {
            key: "frp_port_range_start".to_string(),
            value: settings.frp_port_range_start.to_string(),
        }),
        db_writer.0.send(crate::db::DbCommand::UpdateSetting {
            key: "frp_port_range_end".to_string(),
            value: settings.frp_port_range_end.to_string(),
        }),
    ];

    for task in tasks {
        let _ = task.await;
    }

    if settings.ngrok_authtoken.is_empty() {
        let _ =
            keyring::Entry::new("decoyops", "ngrok_authtoken").and_then(|e| e.delete_credential());
    } else {
        let _ = keyring::Entry::new("decoyops", "ngrok_authtoken")
            .and_then(|e| e.set_password(&settings.ngrok_authtoken));
    }

    if settings.frp_auth_token.is_empty() {
        let _ =
            keyring::Entry::new("decoyops", "frp_auth_token").and_then(|e| e.delete_credential());
    } else {
        let _ = keyring::Entry::new("decoyops", "frp_auth_token")
            .and_then(|e| e.set_password(&settings.frp_auth_token));
    }

    Ok(())
}

pub fn get_provider(
    conn: &rusqlite::Connection,
    provider_name: &str,
) -> Box<dyn crate::tunnel::TunnelProvider> {
    if provider_name == "ngrok" {
        let authtoken = keyring::Entry::new("decoyops", "ngrok_authtoken")
            .and_then(|e| e.get_password())
            .unwrap_or_default();
        let binary_path = crate::db::get_setting(conn, "ngrok_binary_path")
            .unwrap_or(None)
            .unwrap_or_default();
        Box::new(crate::tunnel::NgrokProvider {
            authtoken,
            binary_path,
        })
    } else {
        let binary_path = crate::db::get_setting(conn, "frp_binary_path")
            .unwrap_or(None)
            .unwrap_or_default();
        let server_addr = crate::db::get_setting(conn, "frp_server_addr")
            .unwrap_or(None)
            .unwrap_or_default();
        let auth_token = keyring::Entry::new("decoyops", "frp_auth_token")
            .and_then(|e| e.get_password())
            .unwrap_or_default();
        let tools_dir = get_tools_dir();
        let config_path = tools_dir
            .join("frp")
            .join("frpc.toml")
            .to_string_lossy()
            .to_string();
        Box::new(crate::tunnel::FrpProvider {
            binary_path,
            config_path,
            server_addr,
            auth_token,
        })
    }
}

#[derive(serde::Serialize)]
pub struct DependenciesStatus {
    pub docker: bool,
    pub ngrok: bool,
    pub frpc: bool,
}

#[tauri::command]
pub async fn check_dependencies(
    db_read: tauri::State<'_, DbRead>,
) -> Result<DependenciesStatus, String> {
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

    let ngrok_ok = crate::tunnel::validate_tunnel_binary(&ngrok_path, "ngrok").is_ok()
        && std::process::Command::new(&ngrok_path)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

    let frp_path = crate::db::get_setting(&conn, "frp_binary_path")
        .unwrap_or(None)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if cfg!(target_os = "windows") {
                "frpc.exe".to_string()
            } else {
                "frpc".to_string()
            }
        });

    let frpc_ok = crate::tunnel::validate_tunnel_binary(&frp_path, "frpc").is_ok()
        && std::process::Command::new(&frp_path)
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

/// CRIT-2 fix: factory_reset routes database wipe through the writer channel
/// instead of opening a third unsynchronized connection. This prevents WAL
/// corruption and SQLITE_BUSY errors on Windows.
#[tauri::command]
pub async fn factory_reset(
    app_paths: State<'_, crate::AppPaths>,
    db_writer: State<'_, DbWriter>,
) -> Result<(), String> {
    // 1. Wipe keyrings
    let keys = [
        "abuseipdb",
        "virustotal",
        "ngrok_authtoken",
        "frp_auth_token",
    ];
    for key in keys.iter() {
        if let Ok(entry) = keyring::Entry::new("decoyops", key) {
            let _ = entry.delete_credential();
        }
    }

    // 2. Wipe directories (logs, binaries, configs, pcaps, quarantine)
    for sub in ["logs", "binaries", "configs", "pcaps"] {
        let dir = app_paths.data_dir.join(sub);
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    if app_paths.quarantine_dir.exists() {
        let _ = std::fs::remove_dir_all(&app_paths.quarantine_dir);
    }

    // 3. Wipe database through the writer channel (safe single-writer pattern)
    db_writer
        .0
        .send(crate::db::DbCommand::FactoryReset)
        .await
        .map_err(|e| format!("Failed to send factory reset command: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_uml_frame(buf: &mut Vec<u8>, op: i32, dir: u32, payload: &[u8]) {
        buf.extend_from_slice(&op.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&dir.to_le_bytes());
        buf.extend_from_slice(&1700000000u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(payload);
    }

    #[test]
    fn decodes_cowrie_uml_tty_frames_and_strips_ansi() {
        let mut raw = Vec::new();
        push_uml_frame(&mut raw, 1, 0, b"");
        push_uml_frame(&mut raw, 3, 2, b"\x1b[4hroot@svr04:~# ");
        push_uml_frame(&mut raw, 3, 1, b"l"); // client stdin should not double-print
        push_uml_frame(&mut raw, 3, 2, b"ls\r\n\x1b[4lbin\r\n");
        push_uml_frame(&mut raw, 2, 0, b"");

        let decoded = decode_cowrie_tty(&raw);
        assert_eq!(decoded, "root@svr04:~# ls\nbin\n");
    }

    #[test]
    fn falls_back_to_sanitized_plain_text_for_non_uml_logs() {
        let decoded = decode_cowrie_tty(b"\x1b[31mhello\x1b[0m\r\nworld");
        assert_eq!(decoded, "hello\nworld");
    }

    #[test]
    fn handles_malformed_uml_length_overflow_safely() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&3i32.to_le_bytes()); // OP_WRITE
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&u32::MAX.to_le_bytes()); // overflow length attack
        raw.extend_from_slice(&2u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(b"abc");
        let decoded = decode_cowrie_tty(&raw);
        assert!(decoded.ends_with("abc"));
    }

    #[test]
    fn realism_score_handles_all_templates_and_host_ip_ports() {
        assert!(
            calculate_realism_score("cowrie/cowrie:latest", "127.0.0.1:22:2222")
                > calculate_realism_score("cowrie/cowrie:latest", "127.0.0.1:2222:2222")
        );
        assert_eq!(
            calculate_realism_score("ghcr.io/telekom-security/conpot:24.04.1", "502:502"),
            85
        );
        assert_eq!(
            calculate_realism_score("ghcr.io/telekom-security/mailoney:24.04.1", "25:25"),
            80
        );
    }

    #[test]
    fn recovers_truncated_cowrie_uml_recording_without_binary_headers() {
        let mut raw = Vec::new();
        push_uml_frame(&mut raw, 1, 0, b"");
        push_uml_frame(&mut raw, 3, 2, b"\x1b(Broot@svr04:~# id\r\n");
        // Append incomplete trailing frame header
        raw.extend_from_slice(&[3, 0, 0, 0, 0, 0]);
        let decoded = decode_cowrie_tty(&raw);
        assert_eq!(decoded, "root@svr04:~# id\n");
    }
}
