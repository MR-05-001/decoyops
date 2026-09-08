use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::process::Command;
use std::time::Duration;
use sysinfo::{Pid, System};
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct TunnelHandle {
    pub decoy_name: String,
    pub public_url: Option<String>,
    pub provider_name: String,
    pub remote_port: Option<u16>,
    pub pid: Option<u32>, // Exact child process PID for stopping ngrok
}

#[async_trait]
pub trait TunnelProvider: Send + Sync {
    async fn start_tunnel(
        &self,
        decoy_name: &str,
        local_port: u16,
        allocated_remote_port: Option<u16>,
    ) -> Result<TunnelHandle, String>;

    async fn stop_tunnel(&self, handle: &TunnelHandle) -> Result<(), String>;

    fn is_self_hosted(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Ngrok Provider
// ---------------------------------------------------------------------------

pub struct NgrokProvider {
    pub authtoken: String,
    pub binary_path: String,
}

#[derive(Deserialize)]
struct NgrokApiTunnels {
    tunnels: Vec<NgrokTunnel>,
}

#[derive(Deserialize)]
struct NgrokTunnel {
    public_url: String,
}

#[async_trait]
impl TunnelProvider for NgrokProvider {
    async fn start_tunnel(
        &self,
        decoy_name: &str,
        local_port: u16,
        _allocated_remote_port: Option<u16>,
    ) -> Result<TunnelHandle, String> {
        let binary = if self.binary_path.trim().is_empty() {
            "ngrok"
        } else {
            &self.binary_path
        };

        // Spawn ngrok as a child process
        let child = Command::new(binary)
            .arg("tcp")
            .arg(local_port.to_string())
            .env("NGROK_AUTHTOKEN", &self.authtoken)
            .spawn()
            .map_err(|e| format!("Failed to spawn ngrok: {}", e))?;

        let pid = child.id();

        // Poll local API for public URL
        let client = Client::new();
        let mut public_url = None;
        let mut attempts = 0;

        while attempts < 10 {
            sleep(Duration::from_millis(500)).await;
            if let Ok(resp) = client.get("http://127.0.0.1:4040/api/tunnels").send().await {
                if let Ok(data) = resp.json::<NgrokApiTunnels>().await {
                    if let Some(tunnel) = data.tunnels.first() {
                        public_url = Some(tunnel.public_url.clone());
                        break;
                    }
                }
            }
            attempts += 1;
        }

        Ok(TunnelHandle {
            decoy_name: decoy_name.to_string(),
            public_url,
            provider_name: "ngrok".to_string(),
            remote_port: None,
            pid: Some(pid),
        })
    }

    async fn stop_tunnel(&self, handle: &TunnelHandle) -> Result<(), String> {
        if let Some(pid) = handle.pid {
            let mut sys = System::new_all();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            if let Some(process) = sys.process(Pid::from_u32(pid)) {
                process.kill();
            }
        }
        Ok(())
    }

    fn is_self_hosted(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// FRP Provider
// ---------------------------------------------------------------------------

pub struct FrpProvider {
    pub binary_path: String,
    pub config_path: String,
    pub server_addr: String,
    pub auth_token: String,
}

#[async_trait]
impl TunnelProvider for FrpProvider {
    async fn start_tunnel(
        &self,
        decoy_name: &str,
        local_port: u16,
        allocated_remote_port: Option<u16>,
    ) -> Result<TunnelHandle, String> {
        let remote_port = allocated_remote_port.ok_or("FRP requires an allocated remote port")?;

        // Modify frpc.toml using toml_edit
        let config_content = std::fs::read_to_string(&self.config_path)
            .map_err(|e| format!("Failed to read frpc.toml: {}", e))?;
        
        let mut doc = config_content
            .parse::<toml_edit::DocumentMut>()
            .map_err(|e| format!("Failed to parse frpc.toml: {}", e))?;

        // Update server details
        doc["serverAddr"] = toml_edit::value(&self.server_addr);
        if !doc.contains_key("auth") {
            doc["auth"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        doc["auth"]["token"] = toml_edit::value(&self.auth_token);

        // Ensure proxies array exists
        if doc.get("proxies").is_none() {
            doc["proxies"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
        }

        if let Some(proxies) = doc["proxies"].as_array_of_tables_mut() {
            // Remove existing proxy if it matches the name
            let mut found_index = None;
            for (i, table) in proxies.iter().enumerate() {
                if let Some(name) = table.get("name") {
                    if name.as_str() == Some(decoy_name) {
                        found_index = Some(i);
                        break;
                    }
                }
            }
            if let Some(i) = found_index {
                proxies.remove(i);
            }

            // Create new proxy table
            let mut new_proxy = toml_edit::Table::new();
            new_proxy.insert("name", toml_edit::value(decoy_name));
            new_proxy.insert("type", toml_edit::value("tcp"));
            new_proxy.insert("localIP", toml_edit::value("127.0.0.1"));
            new_proxy.insert("localPort", toml_edit::value(local_port as i64));
            new_proxy.insert("remotePort", toml_edit::value(remote_port as i64));
            
            proxies.push(new_proxy);
        }

        std::fs::write(&self.config_path, doc.to_string())
            .map_err(|e| format!("Failed to save frpc.toml: {}", e))?;

        // Reload frpc
        let binary = if self.binary_path.trim().is_empty() {
            "frpc"
        } else {
            &self.binary_path
        };

        let reload_status = Command::new(binary)
            .arg("reload")
            .arg("-c")
            .arg(&self.config_path)
            .status()
            .map_err(|e| format!("Failed to execute frpc reload: {}", e))?;

        if !reload_status.success() {
            return Err("frpc reload failed".to_string());
        }

        // Get public URL from serverAddr config
        let server_addr = doc
            .get("serverAddr")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let public_url = format!("tcp://{}:{}", server_addr, remote_port);

        Ok(TunnelHandle {
            decoy_name: decoy_name.to_string(),
            public_url: Some(public_url),
            provider_name: "frp".to_string(),
            remote_port: Some(remote_port),
            pid: None,
        })
    }

    async fn stop_tunnel(&self, handle: &TunnelHandle) -> Result<(), String> {
        let config_content = std::fs::read_to_string(&self.config_path)
            .map_err(|e| format!("Failed to read frpc.toml: {}", e))?;
        
        let mut doc = config_content
            .parse::<toml_edit::DocumentMut>()
            .map_err(|e| format!("Failed to parse frpc.toml: {}", e))?;

        if let Some(proxies) = doc.get_mut("proxies").and_then(|p| p.as_array_of_tables_mut()) {
            let mut found_index = None;
            for (i, table) in proxies.iter().enumerate() {
                if let Some(name) = table.get("name") {
                    if name.as_str() == Some(&handle.decoy_name) {
                        found_index = Some(i);
                        break;
                    }
                }
            }
            if let Some(i) = found_index {
                proxies.remove(i);
                std::fs::write(&self.config_path, doc.to_string())
                    .map_err(|e| format!("Failed to save frpc.toml: {}", e))?;

                let binary = if self.binary_path.trim().is_empty() {
                    "frpc"
                } else {
                    &self.binary_path
                };
        
                Command::new(binary)
                    .arg("reload")
                    .arg("-c")
                    .arg(&self.config_path)
                    .status()
                    .map_err(|e| format!("Failed to execute frpc reload: {}", e))?;
            }
        }

        Ok(())
    }

    fn is_self_hosted(&self) -> bool {
        true
    }
}
