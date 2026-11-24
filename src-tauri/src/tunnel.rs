use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::process::Command;
use std::time::Duration;
use sysinfo::{Pid, System};
use tokio::time::sleep;

pub fn validate_tunnel_binary(path: &str, expected_stem: &str) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let file_stem = std::path::Path::new(trimmed)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("Invalid {} binary path", expected_stem))?;
    if !file_stem.eq_ignore_ascii_case(expected_stem) {
        return Err(format!(
            "Invalid {} binary path: executable name must be '{}'",
            expected_stem, expected_stem
        ));
    }
    Ok(())
}

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
    #[serde(default)]
    config: Option<NgrokTunnelConfig>,
}

#[derive(Deserialize)]
struct NgrokTunnelConfig {
    #[serde(default)]
    addr: String,
}

#[async_trait]
impl TunnelProvider for NgrokProvider {
    async fn start_tunnel(
        &self,
        decoy_name: &str,
        local_port: u16,
        _allocated_remote_port: Option<u16>,
    ) -> Result<TunnelHandle, String> {
        validate_tunnel_binary(&self.binary_path, "ngrok")?;
        let binary = if self.binary_path.trim().is_empty() {
            "ngrok"
        } else {
            self.binary_path.trim()
        };

        // Spawn ngrok as a child process
        let mut child = Command::new(binary)
            .arg("tcp")
            .arg(local_port.to_string())
            .env("NGROK_AUTHTOKEN", &self.authtoken)
            .spawn()
            .map_err(|e| format!("Failed to spawn ngrok: {}", e))?;

        let pid = child.id();

        // Poll local API for public URL
        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| Client::new());
        let mut public_url = None;
        let mut attempts = 0;
        let port_suffix = format!(":{}", local_port);

        while attempts < 10 {
            sleep(Duration::from_millis(500)).await;
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("ngrok exited early with status: {}", status));
            }
            if let Ok(resp) = client.get("http://127.0.0.1:4040/api/tunnels").send().await {
                if let Ok(data) = resp.json::<NgrokApiTunnels>().await {
                    let matched = data
                        .tunnels
                        .iter()
                        .find(|t| {
                            t.config
                                .as_ref()
                                .is_some_and(|c| c.addr.ends_with(&port_suffix))
                        })
                        .or_else(|| data.tunnels.first());
                    if let Some(tunnel) = matched {
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
            let mut sys = System::new();
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
        validate_tunnel_binary(&self.binary_path, "frpc")?;
        let trimmed_addr = self.server_addr.trim();
        if trimmed_addr.is_empty()
            || trimmed_addr
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err("Invalid FRP server address".to_string());
        }

        // Modify frpc.toml using toml_edit
        let config_content = std::fs::read_to_string(&self.config_path)
            .map_err(|e| format!("Failed to read frpc.toml: {}", e))?;

        let mut doc = config_content
            .parse::<toml_edit::DocumentMut>()
            .map_err(|e| format!("Failed to parse frpc.toml: {}", e))?;

        // Update server details (never persist keyring secret in plaintext on disk)
        doc["serverAddr"] = toml_edit::value(trimmed_addr);
        if !doc.contains_key("auth") {
            doc["auth"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        doc["auth"]["token"] = toml_edit::value("{{ .Envs.DECOYOPS_FRP_TOKEN }}");

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

            // Create new proxy table with rate-limit (blueprint v3 §2)
            let mut new_proxy = toml_edit::Table::new();
            new_proxy.insert("name", toml_edit::value(decoy_name));
            new_proxy.insert("type", toml_edit::value("tcp"));
            new_proxy.insert("localIP", toml_edit::value("127.0.0.1"));
            new_proxy.insert("localPort", toml_edit::value(local_port as i64));
            new_proxy.insert("remotePort", toml_edit::value(remote_port as i64));
            let mut transport_tbl = toml_edit::Table::new();
            transport_tbl.insert("bandwidthLimit", toml_edit::value("1MB"));
            new_proxy.insert("transport", toml_edit::Item::Table(transport_tbl));

            proxies.push(new_proxy);
        }

        std::fs::write(&self.config_path, doc.to_string())
            .map_err(|e| format!("Failed to save frpc.toml: {}", e))?;

        // Reload frpc
        let binary = if self.binary_path.trim().is_empty() {
            "frpc"
        } else {
            self.binary_path.trim()
        };

        let reload_status = Command::new(binary)
            .arg("reload")
            .arg("-c")
            .arg(&self.config_path)
            .env("DECOYOPS_FRP_TOKEN", &self.auth_token)
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

        if let Some(proxies) = doc
            .get_mut("proxies")
            .and_then(|p| p.as_array_of_tables_mut())
        {
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

                validate_tunnel_binary(&self.binary_path, "frpc")?;
                let binary = if self.binary_path.trim().is_empty() {
                    "frpc"
                } else {
                    self.binary_path.trim()
                };

                Command::new(binary)
                    .arg("reload")
                    .arg("-c")
                    .arg(&self.config_path)
                    .env("DECOYOPS_FRP_TOKEN", &self.auth_token)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_tunnel_binary_names() {
        assert!(validate_tunnel_binary("", "frpc").is_ok());
        assert!(validate_tunnel_binary("tools/frp/frpc.exe", "frpc").is_ok());
        assert!(validate_tunnel_binary("tools/ngrok/ngrok", "ngrok").is_ok());
        assert!(validate_tunnel_binary("cmd.exe", "frpc").is_err());
        assert!(validate_tunnel_binary("/bin/sh", "ngrok").is_err());
    }
}
