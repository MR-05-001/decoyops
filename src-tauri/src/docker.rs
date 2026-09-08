//! Restricted Docker API proxy — hard constraint #1 (ADR-001).
//!
//! This is the ONLY module that holds a connection to the Docker daemon.
//! All container operations in DecoyOps route through the curated public
//! API surface below. No other module may import `bollard` or touch the
//! Docker socket.

#![allow(dead_code)]

use std::collections::HashMap;
use std::time::Duration;

use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{ContainerSummary, EventMessage, HostConfig, PortBinding};
use bollard::network::CreateNetworkOptions;
use bollard::system::EventsOptions;
use bollard::Docker;
use futures_util::StreamExt;
use tokio::sync::mpsc::Sender;

use crate::firewall::get_firewall_backend;

/// Events emitted by the Docker telemetry system (blueprint v3 §1).
pub enum FleetEvent {
    /// A live event from the Docker stream.
    DockerEvent(EventMessage),
    /// A full state snapshot from the reconciliation loop.
    Reconcile(Vec<ContainerSummary>),
}

impl FleetEvent {
    pub fn from_docker(ev: EventMessage) -> Self {
        Self::DockerEvent(ev)
    }
}

/// Encapsulates the Docker client. The `client` field is intentionally
/// private — no other module should be able to extract or borrow it.
#[derive(Clone)]
pub struct DockerProxy {
    client: Docker,
}

#[derive(Debug)]
pub struct DecoyNetworkDetails {
    pub ip_address: Option<String>,
    pub network_name: Option<String>,
    pub gateway: Option<String>,
    pub ports: Vec<String>,
    pub created_at: Option<String>,
}

impl DockerProxy {
    pub fn connect() -> Result<Self, String> {
        let client = Docker::connect_with_local_defaults()
            .map_err(|e| format!("Failed to connect to Docker daemon: {e}"))?;
            
        Ok(Self { client })
    }

    /// Primary telemetry: live event stream (blueprint v3 §1)
    pub async fn watch_events(&self, tx: Sender<FleetEvent>) {
        let mut filters = HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);

        let mut stream = self.client.events(Some(EventsOptions {
            filters,
            ..Default::default()
        }));

        while let Some(event) = stream.next().await {
            if let Ok(ev) = event {
                // Ignore send errors if receiver dropped
                let _ = tx.send(FleetEvent::from_docker(ev)).await;
            }
        }
    }

    /// Backstop telemetry: reconcile actual state every 60s (blueprint v3 §1)
    pub async fn reconcile_loop(&self, tx: Sender<FleetEvent>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Ok(containers) = self.client.list_containers::<String>(None).await {
                let _ = tx.send(FleetEvent::Reconcile(containers)).await;
            }
        }
    }
    
    /// List DecoyOps-managed Docker networks
    pub async fn list_networks(&self) -> Result<Vec<String>, String> {
        let filters = HashMap::from([("label", vec!["decoyops.managed=true"])]);
        let networks = self.client.list_networks(Some(bollard::network::ListNetworksOptions { filters })).await.map_err(|e| e.to_string())?;
        
        let mut names = vec![];
        for net in networks {
            if let Some(name) = net.name {
                names.push(name);
            }
        }
        
        Ok(names)
    }

    /// Retrieve detailed container information for a decoy
    pub async fn inspect_decoy(&self, container_id: &str) -> Result<DecoyNetworkDetails, String> {
        let details = self.client.inspect_container(container_id, None).await.map_err(|e| e.to_string())?;
        let mut ip_address = None;
        let mut network_name = None;
        let mut gateway = None;
        let mut ports_vec = vec![];

        if let Some(net_settings) = details.network_settings {
            if let Some(networks) = net_settings.networks {
                if let Some((name, endpoint)) = networks.into_iter().next() {
                    network_name = Some(name);
                    if let Some(ip) = endpoint.ip_address { if !ip.is_empty() { ip_address = Some(ip); } }
                    if let Some(gw) = endpoint.gateway { if !gw.is_empty() { gateway = Some(gw); } }
                }
            }
            if ip_address.is_none() {
                if let Some(ip) = net_settings.ip_address { if !ip.is_empty() { ip_address = Some(ip); } }
            }
            if gateway.is_none() {
                if let Some(gw) = net_settings.gateway { if !gw.is_empty() { gateway = Some(gw); } }
            }
        }
        
        if let Some(host_config) = details.host_config {
            if let Some(port_bindings) = host_config.port_bindings {
                for (container_port, bindings) in port_bindings {
                    if let Some(binding) = bindings {
                        for b in binding {
                            let host_port = b.host_port.clone().unwrap_or_default();
                            ports_vec.push(format!("{}:{}", host_port, container_port));
                        }
                    }
                }
            }
        }
        
        Ok(DecoyNetworkDetails { 
            ip_address, 
            network_name, 
            gateway,
            ports: ports_vec,
            created_at: details.created,
        })
    }

    /// Delete a Docker network by name
    pub async fn delete_network(&self, network_name: &str) -> Result<(), String> {
        self.client.remove_network(network_name).await.map_err(|e| e.to_string())
    }

    /// Deploy a new honeypot decoy container.
    ///
    /// Adheres to HC#3 (egress-deny) by attempting to apply firewall rules to
    /// Deploys a new honeypot container with strict egress-deny isolation.
    pub async fn deploy_decoy(
        &self,
        name: &str,
        template: &str,
        port_mapping: &str,
        auto_restart: bool,
        network_name_opt: Option<&str>,
        is_unmanaged: bool,
        tunnel_provider: Option<&dyn crate::tunnel::TunnelProvider>,
        allocated_remote_port: Option<u16>,
    ) -> Result<(String, Option<crate::tunnel::TunnelHandle>), String> {
        // Sanitize name to prevent path traversal in log directory creation
        let sanitized_name: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
            .collect();
        let container_name = format!("decoy_{}", sanitized_name.to_lowercase());
        let image = template;

        // 1. Pull the image (if not already present)
        let pull_opts = CreateImageOptions {
            from_image: image,
            ..Default::default()
        };
        let mut pull_stream = self.client.create_image(Some(pull_opts), None, None);
        while let Some(res) = pull_stream.next().await {
            if let Err(e) = res {
                return Err(format!("Failed to pull image: {e}"));
            }
        }

        // 2. Create or use an isolated network for this decoy
        let network_name = network_name_opt
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}-net", name));
            
        let mut labels = HashMap::new();
        if !is_unmanaged {
            labels.insert("decoyops.managed", "true");
        }

        let net_opts = CreateNetworkOptions {
            name: network_name.as_str(),
            driver: "bridge",
            labels,
            internal: false, // Egress-deny is handled by the firewall backend, not Docker internal networks (which breaks ingress port mapping)
            ..Default::default()
        };

        // If the network exists, this might fail with a 409. We can safely ignore it.
        if let Err(e) = self.client.create_network(net_opts).await {
            let err_str = e.to_string();
            if !err_str.contains("409") && !err_str.contains("already exists") {
                return Err(format!("Failed to create network: {err_str}"));
            }
        }

        // Try to fetch subnet CIDR (docker might autogenerate it)
        let mut subnet_cidr = "unknown".to_string();
        if let Ok(network_details) = self
            .client
            .inspect_network::<&str>(&network_name, None)
            .await
        {
            if let Some(ipam) = network_details.ipam {
                if let Some(configs) = ipam.config {
                    if let Some(cfg) = configs.first() {
                        if let Some(subnet) = &cfg.subnet {
                            subnet_cidr = subnet.clone();
                        }
                    }
                }
            }
        }

        // 3. Apply Firewall rules (HC#3) - ONLY if managed
        if !is_unmanaged {
            let firewall = get_firewall_backend();
            if let Err(e) = firewall.apply_egress_drop(&subnet_cidr) {
                // Rollback network if we created it (best effort)
                let _ = self.client.remove_network(&network_name).await;
                return Err(e.to_string());
            }
        }

        // 4. Create the container
        let mut port_bindings = HashMap::new();
        let mut exposed_ports = HashMap::new();
        // port_mapping example: "2222:22" (host:container)
        let parts: Vec<&str> = port_mapping.split(':').collect();
        if parts.len() == 2 {
            let host_port_str = parts[0];
            let container_port_str = parts[1];

            // Validate that both are valid u16 ports
            if host_port_str.parse::<u16>().is_err() || container_port_str.parse::<u16>().is_err() {
                let _ = self.client.remove_network(&network_name).await;
                return Err("Invalid port_mapping: ports must be valid numbers between 1-65535".to_string());
            }

            let container_port = format!("{container_port_str}/tcp");
            
            // Add to exposed_ports
            exposed_ports.insert(container_port.clone(), HashMap::new());

            port_bindings.insert(
                container_port,
                Some(vec![PortBinding {
                    host_ip: Some("0.0.0.0".to_string()),
                    host_port: Some(host_port_str.to_string()),
                }]),
            );
        } else {
            // Rollback network
            let _ = self.client.remove_network(&network_name).await;
            return Err(
                "Invalid port_mapping format, expected host_port:container_port".to_string(),
            );
        }

        let restart_policy = if auto_restart {
            Some(bollard::models::RestartPolicy {
                name: Some(bollard::models::RestartPolicyNameEnum::ON_FAILURE),
                maximum_retry_count: Some(5),
            })
        } else {
            None
        };

        // 4b. Configure bind mounts for logs
        // Make sure the data/logs directory exists
        let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let host_log_dir = current_dir.join("data").join("logs").join(&container_name);
        let _ = std::fs::create_dir_all(&host_log_dir);

        let mut binds = vec![];
        let mut env = vec![];
        let mut cap_add = vec![];
        let mut cap_drop = vec![];
        let mut tmpfs = HashMap::new();
        
        let template_lower = template.to_lowercase();
        let host_path = host_log_dir.to_string_lossy().to_string();

        if template_lower.contains("cowrie") {
            binds.push(format!("{host_path}:/cowrie/cowrie-git/var/log/cowrie:rw"));
            tmpfs.insert("/tmp/cowrie".to_string(), String::new());
            cap_drop.push("ALL".to_string());
        } else if template_lower.contains("dionaea") {
            let host_binaries_dir = current_dir.join("data").join("binaries").join(&container_name);
            let _ = std::fs::create_dir_all(&host_binaries_dir);
            cap_drop.push("ALL".to_string());
            cap_add.push("CHOWN".to_string());
            cap_add.push("DAC_OVERRIDE".to_string());
            cap_add.push("FOWNER".to_string());
            
            // Revert back to var/log mapping so we can place our custom json file there
            binds.push(format!("{host_path}:/opt/dionaea/var/log:rw"));
            binds.push(format!("{}:/opt/dionaea/var/dionaea/binaries:rw", host_binaries_dir.to_string_lossy()));
            
            // Custom Config Injection to enable log_json and output to var/log/dionaea.json
            let host_config_dir = current_dir.join("data").join("configs").join(&container_name);
            let _ = std::fs::create_dir_all(&host_config_dir);
            let log_json_path = host_config_dir.join("log_json.yaml");
            let log_json_content = r#"- name: log_json
  config:
    handlers:
      - file:///opt/dionaea/var/log/dionaea.json
"#;
            let _ = std::fs::write(&log_json_path, log_json_content.replace("\r\n", "\n"));
            
            // Note: Since this is mounted to ihandlers-enabled/, it forces the JSON module to load natively.
            binds.push(format!("{}:/opt/dionaea/etc/dionaea/ihandlers-enabled/log_json.yaml:ro", log_json_path.to_string_lossy().replace("\\", "/")));
            
            // Critical: bind-mounting a file into /opt/dionaea/etc/dionaea prevents the Docker image from automatically
            // initializing the volume. We MUST force the entrypoint to copy the template configs over, otherwise dionaea.cfg is missing.
            env.push("DIONAEA_FORCE_INIT=1".to_string());
        } else if template_lower.contains("mailoney") {
            binds.push(format!("{host_path}:/opt/mailoney/logs:rw"));
        } else if template_lower.contains("conpot") {
            binds.push(format!("{host_path}:/var/log/conpot:rw"));
            env.push("CONPOT_CONFIG=/etc/conpot/conpot.cfg".to_string());
            env.push("CONPOT_JSON_LOG=/var/log/conpot/conpot.json".to_string());
            env.push("CONPOT_LOG=/var/log/conpot/conpot.log".to_string());
            env.push("CONPOT_TEMPLATE=default".to_string());
            env.push("CONPOT_TMP=/tmp/conpot".to_string());
            tmpfs.insert("/tmp/conpot".to_string(), String::new());
        } else if template_lower.contains("elasticpot") {
            binds.push(format!("{host_path}:/opt/elasticpot/log:rw"));
        }

        let host_config = HostConfig {
            port_bindings: Some(port_bindings),
            network_mode: Some(network_name.clone()),
            restart_policy,
            binds: Some(binds),
            cap_add: if cap_add.is_empty() { None } else { Some(cap_add) },
            cap_drop: if cap_drop.is_empty() { None } else { Some(cap_drop) },
            tmpfs: if tmpfs.is_empty() { None } else { Some(tmpfs) },
            ..Default::default()
        };

        let config = Config {
            image: Some(image.to_string()),
            exposed_ports: Some(exposed_ports),
            host_config: Some(host_config),
            env: if env.is_empty() { None } else { Some(env) },
            ..Default::default()
        };

        let create_opts = CreateContainerOptions {
            name,
            platform: None,
        };

        let create_res = self
            .client
            .create_container(Some(create_opts), config)
            .await
            .map_err(|e| {
                // Rollback network doesn't happen automatically here in async without manual cleanup,
                // but this is a simplified scaffold.
                format!("Failed to create container: {e}")
            })?;

        // 5. Start the container
        self.client
            .start_container::<String>(&create_res.id, None)
            .await
            .map_err(|e| format!("Failed to start container: {e}"))?;

        // 6. Start the tunnel if a provider is configured
        let mut tunnel_handle = None;
        if let Some(provider) = tunnel_provider {
            // Parse host port again to pass to tunnel
            let parts: Vec<&str> = port_mapping.split(':').collect();
            if parts.len() == 2 {
                if let Ok(host_port) = parts[0].parse::<u16>() {
                    match provider.start_tunnel(name, host_port, allocated_remote_port).await {
                        Ok(handle) => {
                            tunnel_handle = Some(handle);
                        }
                        Err(e) => {
                            // Fatal error: abort deploy and rollback container and network
                            let rm_opts = bollard::container::RemoveContainerOptions { v: true, force: true, link: false };
                            if let Err(err) = self.client.remove_container(&create_res.id, Some(rm_opts)).await {
                                eprintln!("CRITICAL: Failed to rollback container {} after tunnel failure: {}", create_res.id, err);
                            }
                            // Prevent race condition: wait for Docker to detach network endpoints before network removal
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            if let Err(err) = self.client.remove_network(&network_name).await {
                                eprintln!("CRITICAL: Failed to rollback network {} after tunnel failure: {}", network_name, err);
                            }
                            return Err(format!("Tunnel provider failed to start: {}", e));
                        }
                    }
                }
            }
        }

        Ok((create_res.id, tunnel_handle))
    }

    /// Start a deployed decoy container.
    pub async fn start_decoy(&self, name_or_id: &str) -> Result<(), String> {
        self.client
            .start_container::<String>(name_or_id, None)
            .await
            .map_err(|e| format!("Failed to start container {}: {}", name_or_id, e))
    }

    /// Stop a running decoy container.
    pub async fn stop_decoy(&self, name_or_id: &str) -> Result<(), String> {
        let stop_opts = StopContainerOptions { t: 10 };
        self.client
            .stop_container(name_or_id, Some(stop_opts))
            .await
            .map_err(|e| format!("Failed to stop container {}: {}", name_or_id, e))
    }

    /// Restart a running or stopped decoy container.
    pub async fn restart_decoy(&self, name_or_id: &str) -> Result<(), String> {
        let restart_opts = bollard::container::RestartContainerOptions { t: 10 };
        self.client
            .restart_container(name_or_id, Some(restart_opts))
            .await
            .map_err(|e| format!("Failed to restart container {}: {}", name_or_id, e))
    }

    /// Gracefully stops and removes a decoy container and its network.
    pub async fn terminate_decoy(&self, name_or_id: &str) -> Result<(), String> {
        // Stop container
        let stop_opts = StopContainerOptions { t: 10 };
        let _ = self
            .client
            .stop_container(name_or_id, Some(stop_opts))
            .await;

        // Inspect to get network name before removing container
        let mut network_to_remove = None;
        if let Ok(details) = self.client.inspect_container(name_or_id, None).await {
            if let Some(net_settings) = details.network_settings {
                if let Some(networks) = net_settings.networks {
                    // Grab the first custom network (assumes one network per decoy)
                    if let Some(name) = networks.keys().next() {
                        if name != "bridge" && name != "host" && name != "none" {
                            network_to_remove = Some(name.clone());
                        }
                    }
                }
            }
        }

        // Remove container
        let rm_opts = RemoveContainerOptions {
            v: true,
            force: true,
            link: false,
        };
        self.client
            .remove_container(name_or_id, Some(rm_opts))
            .await
            .map_err(|e| format!("Failed to remove container: {e}"))?;

        // Remove dedicated network
        if let Some(net) = network_to_remove {
            let _ = self.client.remove_network(&net).await;
        }

        Ok(())
    }

    /// Pings the Docker daemon to check if it's reachable.
    pub async fn ping(&self) -> Result<(), String> {
        self.client.ping().await.map(|_| ()).map_err(|e| e.to_string())
    }

    /// Verifies isolation by running a ping command inside the container.
    pub async fn verify_isolation(&self, container_id: &str) -> Result<String, String> {
        use bollard::exec::{CreateExecOptions, StartExecResults};
        use futures_util::StreamExt;

        let exec = self.client.create_exec(container_id, CreateExecOptions {
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            cmd: Some(vec![
                "ping".to_string(), 
                "-c".to_string(), 
                "3".to_string(), 
                "-W".to_string(), 
                "2".to_string(), 
                "8.8.8.8".to_string()
            ]),
            ..Default::default()
        }).await.map_err(|e| format!("Exec create failed (ping might not be installed): {}", e))?;

        let res = self.client.start_exec(&exec.id, None).await.map_err(|e| e.to_string())?;
        
        let mut output = String::new();
        if let StartExecResults::Attached { output: mut stream, .. } = res {
            while let Some(Ok(msg)) = stream.next().await {
                output.push_str(&msg.to_string());
            }
        }
        
        Ok(output)
    }

    /// Captures a PCAP from the container's network namespace using a sidecar
    pub async fn capture_pcap(&self, container_id: &str, duration_secs: u64) -> Result<String, String> {
        use bollard::container::{Config, CreateContainerOptions, StartContainerOptions};
        use bollard::models::HostConfig;
        use futures_util::StreamExt;
        use std::io::Write;
        
        // Generate a unique name to prevent 409 Conflict if previous runs crashed
        let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
        let short_id = &container_id[..std::cmp::min(8, container_id.len())];
        let sidecar_name = format!("pcap_{}_{}", short_id, timestamp);
        
        // Ensure data/pcaps directory exists
        let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let pcaps_dir = current_dir.join("data").join("pcaps");
        if !pcaps_dir.exists() {
            let _ = std::fs::create_dir_all(&pcaps_dir);
        }
        
        // Create an absolute path for the output file
        let file_name = format!("decoy_{}_traffic_{}.pcap", short_id, timestamp);
        let output_path = pcaps_dir.join(&file_name);
        
        // Ensure image exists (block until download completes)
        let mut pull_stream = self.client.create_image(
            Some(bollard::image::CreateImageOptions {
                from_image: "nicolaka/netshoot",
                tag: "latest",
                ..Default::default()
            }),
            None,
            None,
        );
        
        while let Some(msg) = pull_stream.next().await {
            if let Err(e) = msg {
                return Err(format!("Failed to pull nicolaka/netshoot image: {}", e));
            }
        }

        let config = Config {
            image: Some("nicolaka/netshoot:latest".to_string()),
            host_config: Some(HostConfig {
                network_mode: Some(format!("container:{}", container_id)),
                auto_remove: Some(true), // Ensure Docker cleans it up automatically when it exits
                ..Default::default()
            }),
            // -G <duration> = rotate after X secs. -W 1 = exit after 1 file. -w - = write to stdout
            cmd: Some(vec![
                "tcpdump".to_string(), 
                "-i".to_string(), 
                "any".to_string(), 
                "-G".to_string(), 
                duration_secs.to_string(), 
                "-W".to_string(), 
                "1".to_string(), 
                "-w".to_string(), 
                "-".to_string()
            ]),
            ..Default::default()
        };

        let create_res = self.client.create_container(
            Some(CreateContainerOptions {
                name: sidecar_name.clone(),
                platform: None,
            }),
            config,
        ).await.map_err(|e| e.to_string())?;

        let _ = self.client.start_container(&create_res.id, None::<StartContainerOptions<String>>).await;

        // Attach to capture stdout (the raw pcap bytes)
        let mut logs = self.client.logs(
            &create_res.id,
            Some(bollard::container::LogsOptions::<String> {
                stdout: true,
                follow: true,
                ..Default::default()
            })
        );

        let mut file = std::fs::File::create(&output_path).map_err(|e| format!("Failed to create output file: {}", e))?;
        
        while let Some(Ok(log)) = logs.next().await {
            file.write_all(log.into_bytes().as_ref()).map_err(|e| e.to_string())?;
        }

        Ok(output_path.to_string_lossy().into_owned())
    }
}
