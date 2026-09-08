use std::sync::Mutex;
use tokio::sync::mpsc;

mod commands;
mod db;
mod docker;
mod firewall;
mod pipeline;
mod log_watcher;
mod quarantine;
pub mod tunnel;

use commands::DbRead;
use docker::{DockerProxy, FleetEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            use tauri::Manager;
            
            let db_path = "decoyops.db".to_string();
            let read_conn =
                db::open_database(&db_path).expect("failed to open database for read connection");
        
            let db_writer = db::spawn_writer_task(db_path);
        
            // Initialize DockerProxy
            let docker_proxy = DockerProxy::connect().expect("Failed to connect to Docker daemon");
        
            // Spawn telemetry tasks
            let (tx_events, mut rx_events) = mpsc::channel::<FleetEvent>(100);
        
            let docker_proxy_clone1 = docker_proxy.clone();
            let tx_clone1 = tx_events.clone();
            tauri::async_runtime::spawn(async move {
                docker_proxy_clone1.watch_events(tx_clone1).await;
            });
        
            let docker_proxy_clone2 = docker_proxy.clone();
            let tx_clone2 = tx_events.clone();
            tauri::async_runtime::spawn(async move {
                docker_proxy_clone2.reconcile_loop(tx_clone2).await;
            });
        
            // Coordinator task: translate FleetEvents to DbCommands
            let db_writer_clone = db_writer.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx_events.recv().await {
                    match event {
                        FleetEvent::DockerEvent(ev) => {
                            if let Some(actor) = ev.actor {
                                if let Some(container_id) = actor.id {
                                    if let Some(action) = ev.action {
                                        let new_state = match action.as_str() {
                                            "start" => Some("running"),
                                            "die" | "stop" => Some("stopped"),
                                            "kill" => Some("exited"),
                                            _ => None,
                                        };
                                        if let Some(state) = new_state {
                                            let _ = db_writer_clone
                                                .send(db::DbCommand::UpdateDecoyState {
                                                    container_id,
                                                    state: state.to_string(),
                                                })
                                                .await;
                                        }
                                    }
                                }
                            }
                        }
                        FleetEvent::Reconcile(containers) => {
                            for container in containers {
                                if let Some(container_id) = container.id {
                                    let state = container.state.unwrap_or_else(|| "unknown".to_string());
                                    let _ = db_writer_clone
                                        .send(db::DbCommand::UpdateDecoyState {
                                            container_id,
                                            state,
                                        })
                                        .await;
                                }
                            }
                        }
                    }
                }
            });
        
            let app_data_dir = std::env::current_dir().map_err(|e| e.to_string())?; // Use current dir for test scaffold
            
            // Attempt to load MaxMind GeoIP database
            let geoip_reader = maxminddb::Reader::open_readfile(app_data_dir.join("data").join("GeoLite2-City.mmdb"))
                .ok()
                .map(std::sync::Arc::new);
                
            if geoip_reader.is_none() {
                println!("MaxMind GeoLite2-City.mmdb not found in data/. Map coordinates will be missing.");
            }
        
            let pipeline = pipeline::ThreatIntelPipeline::new(db_writer.clone(), geoip_reader);
            let quarantine = quarantine::QuarantineManager::new(&app_data_dir).map_err(|e| format!("{:?}", e))?;
            
            let watcher = log_watcher::LogWatcher::new(app_data_dir.join("data").join("logs"), pipeline.clone());
            watcher.start();

            app.manage(DbRead(Mutex::new(read_conn)));
            app.manage(commands::DbWriter(db_writer.clone()));
            app.manage(docker_proxy);
            app.manage(pipeline);
            app.manage(std::sync::Arc::new(quarantine));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::check_docker,
            commands::deploy_decoy,
            commands::start_decoy,
            commands::stop_decoy,
            commands::restart_decoy,
            commands::terminate_decoy,
            commands::inspect_decoy,
            commands::verify_isolation,
            commands::capture_pcap,
            commands::delete_network,
            commands::export_blocklist,
            commands::get_fleet_telemetry,
            commands::get_docker_networks,
            commands::get_incident_feed,
            commands::get_extracted_iocs,
            commands::get_dashboard_counters,
            commands::get_quarantined_files,
            commands::read_quarantine_hex,
            commands::save_api_key,
            commands::get_api_key,
            commands::enrich_hash,
            commands::enrich_ip,
            commands::get_os,
            commands::purge_telemetry,
            commands::generate_markdown_report,
            commands::generate_stix_report,
            commands::export_all_incidents_csv,
            commands::read_tty_log,
            commands::start_frp_client,
            commands::stop_frp_client,
            commands::get_frp_status,
            commands::get_tunnel_settings,
            commands::save_tunnel_settings,
            commands::check_dependencies,
            commands::factory_reset,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
