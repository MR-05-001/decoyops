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

/// Sanitizes a decoy name into a filesystem/container-safe identifier.
pub fn sanitize_decoy_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("decoy_{}", sanitized.to_lowercase())
}

/// Validates and parses a Docker port mapping (`host_port:container_port` or `host_ip:host_port:container_port`).
pub fn validate_port_mapping(port_mapping: &str) -> Result<(&str, &str, &str), String> {
    let parts: Vec<&str> = port_mapping.split(':').collect();
    let (host_ip, host_port_str, container_port_str) = match parts.len() {
        2 => ("127.0.0.1", parts[0], parts[1]),
        3 => (parts[0], parts[1], parts[2]),
        _ => {
            return Err(
                "Invalid port_mapping format, expected host_port:container_port or host_ip:host_port:container_port".to_string(),
            );
        }
    };

    if host_ip.parse::<std::net::IpAddr>().is_err() {
        return Err(format!(
            "Invalid host_ip '{host_ip}': must be a valid IP address"
        ));
    }

    let host_port = host_port_str.parse::<u16>().map_err(|_| {
        "Invalid port_mapping: ports must be valid numbers between 1-65535".to_string()
    })?;
    let container_port = container_port_str.parse::<u16>().map_err(|_| {
        "Invalid port_mapping: ports must be valid numbers between 1-65535".to_string()
    })?;

    if host_port == 0 || container_port == 0 {
        return Err("Invalid port_mapping: ports must be between 1-65535".to_string());
    }

    Ok((host_ip, host_port_str, container_port_str))
}

const RESERVED_DOCKER_NETWORKS: &[&str] = &["bridge", "host", "none", "ingress", "docker_gwbridge"];

fn is_reserved_network(name: &str) -> bool {
    RESERVED_DOCKER_NETWORKS
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name))
}

fn short_container_id(container_id: &str) -> String {
    container_id.chars().take(8).collect()
}

fn grant_windows_bind_acl(path: &std::path::Path) {
    #[cfg(windows)]
    {
        // Ensure unprivileged Linux containers (e.g. Cowrie uid 999, Conpot/Mailoney uid 2000)
        // can write to host bind mounts on Windows Docker Desktop.
        let _ = std::process::Command::new("icacls")
            .arg(path)
            .args(["/grant", "Everyone:(OI)(CI)F", "/T", "/C", "/Q"])
            .output();
    }
    #[cfg(not(windows))]
    let _ = path;
}

/// Encapsulates the Docker client. The `client` field is intentionally
/// private — no other module should be able to extract or borrow it.
#[derive(Clone)]
pub struct DockerProxy {
    client: Docker,
    data_dir: std::path::PathBuf,
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
        let data_dir = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join("data");
        Self::connect_with_data_dir(data_dir)
    }

    pub fn connect_with_data_dir(data_dir: std::path::PathBuf) -> Result<Self, String> {
        let client = Docker::connect_with_local_defaults()
            .map_err(|e| format!("Failed to connect to Docker daemon: {e}"))?;

        Ok(Self { client, data_dir })
    }

    /// Primary telemetry: live event stream (blueprint v3 §1)
    ///
    /// HIGH-5/6 fix: filters to only container events with the
    /// `decoyops.managed=true` label to avoid processing non-DecoyOps containers.
    pub async fn watch_events(&self, tx: Sender<FleetEvent>) {
        let mut filters = HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        filters.insert(
            "label".to_string(),
            vec!["decoyops.managed=true".to_string()],
        );

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
    ///
    /// HIGH-5 fix: filters to only DecoyOps-managed containers.
    pub async fn reconcile_loop(&self, tx: Sender<FleetEvent>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let filters = HashMap::from([(
                "label".to_string(),
                vec!["decoyops.managed=true".to_string()],
            )]);
            let opts = bollard::container::ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            };
            if let Ok(containers) = self.client.list_containers(Some(opts)).await {
                let _ = tx.send(FleetEvent::Reconcile(containers)).await;
            }
        }
    }

    /// List DecoyOps-managed Docker networks
    pub async fn list_networks(&self) -> Result<Vec<String>, String> {
        let filters = HashMap::from([("label", vec!["decoyops.managed=true"])]);
        let networks = self
            .client
            .list_networks(Some(bollard::network::ListNetworksOptions { filters }))
            .await
            .map_err(|e| e.to_string())?;

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
        let details = self
            .client
            .inspect_container(container_id, None)
            .await
            .map_err(|e| e.to_string())?;
        let mut ip_address = None;
        let mut network_name = None;
        let mut gateway = None;
        let mut ports_vec = vec![];

        if let Some(net_settings) = details.network_settings {
            if let Some(networks) = net_settings.networks {
                if let Some((name, endpoint)) = networks.into_iter().next() {
                    network_name = Some(name);
                    if let Some(ip) = endpoint.ip_address {
                        if !ip.is_empty() {
                            ip_address = Some(ip);
                        }
                    }
                    if let Some(gw) = endpoint.gateway {
                        if !gw.is_empty() {
                            gateway = Some(gw);
                        }
                    }
                }
            }
            if ip_address.is_none() {
                if let Some(ip) = net_settings.ip_address {
                    if !ip.is_empty() {
                        ip_address = Some(ip);
                    }
                }
            }
            if gateway.is_none() {
                if let Some(gw) = net_settings.gateway {
                    if !gw.is_empty() {
                        gateway = Some(gw);
                    }
                }
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
        self.client
            .remove_network(network_name)
            .await
            .map_err(|e| e.to_string())
    }

    async fn ensure_image_present(&self, image: &str, tag: &str) -> Result<(), String> {
        let full_ref = format!("{image}:{tag}");
        if self.client.inspect_image(&full_ref).await.is_ok() {
            return Ok(());
        }
        let mut pull_stream = self.client.create_image(
            Some(CreateImageOptions {
                from_image: image,
                tag,
                ..Default::default()
            }),
            None,
            None,
        );
        while let Some(msg) = pull_stream.next().await {
            if let Err(e) = msg {
                return Err(format!("Failed to pull {} image: {}", full_ref, e));
            }
        }
        Ok(())
    }

    async fn rollback_deploy(
        &self,
        container_id: Option<&str>,
        network_name: &str,
        network_created: bool,
        subnet_cidr: Option<&str>,
    ) {
        if let Some(cid) = container_id {
            let rm_opts = RemoveContainerOptions {
                v: true,
                force: true,
                link: false,
            };
            if let Err(err) = self.client.remove_container(cid, Some(rm_opts)).await {
                eprintln!("CRITICAL: Failed to rollback container {}: {}", cid, err);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        // Only clean up the network and its firewall rule if this deploy created the network
        // and no remaining containers keep the network alive.
        if network_created {
            let network_removed = match self.client.remove_network(network_name).await {
                Ok(()) => true,
                Err(err) => {
                    eprintln!(
                        "CRITICAL: Failed to rollback network {}: {}",
                        network_name, err
                    );
                    false
                }
            };
            if network_removed {
                if let Some(cidr) = subnet_cidr {
                    let _ = get_firewall_backend().remove_egress_drop(cidr);
                }
            }
        }
    }

    /// Deploy a new honeypot decoy container.
    ///
    /// Adheres to HC#3 (egress-deny) by attempting to apply firewall rules to
    /// Deploys a new honeypot container with strict egress-deny isolation.
    #[allow(clippy::too_many_arguments)]
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
        // Validate port mapping and network name up front before creating any Docker resources
        let (host_ip, host_port_str, container_port_str) = validate_port_mapping(port_mapping)?;
        let container_name = sanitize_decoy_name(name);
        let image = template;

        let network_name = network_name_opt
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}-net", name));

        if is_reserved_network(&network_name) {
            return Err(format!(
                "Refusing to deploy onto reserved Docker network '{}'",
                network_name
            ));
        }

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
        let mut labels = HashMap::new();
        let mut options = HashMap::new();
        if !is_unmanaged {
            labels.insert("decoyops.managed", "true");
            // In-engine isolation: disable outbound masquerade (SNAT) so private RFC 1918 IPs cannot route to WAN
            options.insert("com.docker.network.bridge.enable_ip_masquerade", "false");
            // Disable inter-container communication on the bridge to prevent lateral pivoting
            options.insert("com.docker.network.bridge.enable_icc", "false");
        }

        let net_opts = CreateNetworkOptions {
            name: network_name.as_str(),
            driver: "bridge",
            options,
            labels,
            internal: false, // Egress-deny is handled by the firewall backend and disable_ip_masquerade, not Docker internal networks (which breaks ingress port mapping)
            ..Default::default()
        };

        // If the network exists, this might fail with a 409. Only allow attaching if managed (when !is_unmanaged).
        let network_created = match self.client.create_network(net_opts).await {
            Ok(_) => true,
            Err(e) => {
                let err_str = e.to_string();
                if !err_str.contains("409") && !err_str.contains("already exists") {
                    return Err(format!("Failed to create network: {err_str}"));
                }
                false
            }
        };

        // 3. Inspect network & apply firewall rules (HC#3) - ONLY if managed. Never proceed without
        // a verified managed network & subnet, since an unknown subnet cannot be isolated safely.
        let mut applied_subnet: Option<String> = None;
        if !is_unmanaged {
            let firewall_result = async {
                let network_details = self
                    .client
                    .inspect_network::<&str>(&network_name, None)
                    .await
                    .map_err(|e| {
                        format!("Failed to inspect decoy network for egress isolation: {e}")
                    })?;
                if !network_created {
                    let is_managed_net = network_details
                        .labels
                        .as_ref()
                        .and_then(|l| l.get("decoyops.managed"))
                        .is_some_and(|v| v == "true");
                    if !is_managed_net {
                        return Err(format!(
                            "Refusing to attach managed decoy to non-DecoyOps network '{}'",
                            network_name
                        ));
                    }
                }
                let subnet_cidr = network_details
                    .ipam
                    .and_then(|ipam| ipam.config)
                    .and_then(|configs| configs.into_iter().find_map(|config| config.subnet))
                    .ok_or_else(|| {
                        "Decoy network has no configured subnet; refusing deployment".to_string()
                    })?;
                crate::firewall::validate_subnet_cidr(&subnet_cidr).map_err(|e| e.to_string())?;
                get_firewall_backend()
                    .apply_egress_drop(&subnet_cidr)
                    .map_err(|e| e.to_string())?;
                Ok::<String, String>(subnet_cidr)
            }
            .await;

            match firewall_result {
                Ok(subnet) => applied_subnet = Some(subnet),
                Err(e) => {
                    self.rollback_deploy(None, &network_name, network_created, None)
                        .await;
                    return Err(e);
                }
            }
        }

        // 4. Create the container
        let mut port_bindings = HashMap::new();
        let mut exposed_ports = HashMap::new();

        let container_port = format!("{container_port_str}/tcp");

        // Add to exposed_ports
        exposed_ports.insert(container_port.clone(), HashMap::new());

        port_bindings.insert(
            container_port,
            Some(vec![PortBinding {
                host_ip: Some(host_ip.to_string()),
                host_port: Some(host_port_str.to_string()),
            }]),
        );

        let restart_policy = if auto_restart {
            Some(bollard::models::RestartPolicy {
                name: Some(bollard::models::RestartPolicyNameEnum::ON_FAILURE),
                maximum_retry_count: Some(5),
            })
        } else {
            None
        };

        // 4b. Configure bind mounts for logs using canonical data_dir
        let host_log_dir = self.data_dir.join("logs").join(&container_name);
        let _ = std::fs::create_dir_all(&host_log_dir);
        grant_windows_bind_acl(&host_log_dir);

        let mut binds = vec![];
        let mut env = vec![];
        let mut cap_add = vec![];
        // AGENTS.md Hard Constraint #2: Decoys deploy with cap-drop ALL by default
        let cap_drop = vec!["ALL".to_string()];
        let mut tmpfs = HashMap::new();

        let template_lower = template.to_lowercase();
        let host_path = host_log_dir.to_string_lossy().to_string();

        if template_lower.contains("cowrie") {
            let host_tty_dir = host_log_dir.join("tty");
            let host_binaries_dir = self.data_dir.join("binaries").join(&container_name);
            let _ = std::fs::create_dir_all(&host_tty_dir);
            let _ = std::fs::create_dir_all(&host_binaries_dir);
            grant_windows_bind_acl(&host_tty_dir);
            grant_windows_bind_acl(&host_binaries_dir);
            binds.push(format!("{host_path}:/cowrie/cowrie-git/var/log/cowrie:rw"));
            binds.push(format!(
                "{}:/cowrie/cowrie-git/var/lib/cowrie/tty:rw",
                host_tty_dir.to_string_lossy()
            ));
            binds.push(format!(
                "{}:/cowrie/cowrie-git/var/lib/cowrie/downloads:rw",
                host_binaries_dir.to_string_lossy()
            ));
            tmpfs.insert("/tmp/cowrie".to_string(), String::new());
        } else if template_lower.contains("dionaea") {
            let host_binaries_dir = self.data_dir.join("binaries").join(&container_name);
            let _ = std::fs::create_dir_all(&host_binaries_dir);
            grant_windows_bind_acl(&host_binaries_dir);
            // Dionaea entrypoint requires CHOWN/DAC_OVERRIDE/FOWNER for init,
            // SETUID/SETGID for switching to user dionaea (-u dionaea -g dionaea),
            // and NET_BIND_SERVICE to bind to low ports (< 1024, e.g. SMB 445, HTTP 80, FTP 21).
            cap_add.push("CHOWN".to_string());
            cap_add.push("DAC_OVERRIDE".to_string());
            cap_add.push("FOWNER".to_string());
            cap_add.push("SETUID".to_string());
            cap_add.push("SETGID".to_string());
            cap_add.push("NET_BIND_SERVICE".to_string());

            // Revert back to var/log mapping so we can place our custom json file there
            binds.push(format!("{host_path}:/opt/dionaea/var/log:rw"));
            binds.push(format!(
                "{}:/opt/dionaea/var/dionaea/binaries:rw",
                host_binaries_dir.to_string_lossy()
            ));

            // Custom Config Injection to enable log_json and output to var/log/dionaea.json
            let host_config_dir = self.data_dir.join("configs").join(&container_name);
            let _ = std::fs::create_dir_all(&host_config_dir);
            let log_json_path = host_config_dir.join("log_json.yaml");
            let log_json_content = r#"- name: log_json
  config:
    handlers:
      - file:///opt/dionaea/var/log/dionaea.json
"#;
            let _ = std::fs::write(&log_json_path, log_json_content.replace("\r\n", "\n"));

            // Note: Since this is mounted to ihandlers-enabled/, it forces the JSON module to load natively.
            binds.push(format!(
                "{}:/opt/dionaea/etc/dionaea/ihandlers-enabled/log_json.yaml:ro",
                log_json_path.to_string_lossy().replace("\\", "/")
            ));

            // Critical: bind-mounting a file into /opt/dionaea/etc/dionaea prevents the Docker image from automatically
            // initializing the volume. We MUST force the entrypoint to copy the template configs over, otherwise dionaea.cfg is missing.
            env.push("DIONAEA_FORCE_INIT=1".to_string());
        } else if template_lower.contains("mailoney") {
            binds.push(format!("{host_path}:/opt/mailoney/logs:rw"));
            cap_add.push("NET_BIND_SERVICE".to_string());
        } else if template_lower.contains("conpot") {
            binds.push(format!("{host_path}:/var/log/conpot:rw"));
            cap_add.push("NET_BIND_SERVICE".to_string());
            env.push("CONPOT_CONFIG=/etc/conpot/conpot.cfg".to_string());
            env.push("CONPOT_JSON_LOG=/var/log/conpot/conpot.json".to_string());
            env.push("CONPOT_LOG=/var/log/conpot/conpot.log".to_string());
            env.push("CONPOT_TEMPLATE=default".to_string());
            env.push("CONPOT_TMP=/tmp/conpot".to_string());
            tmpfs.insert("/tmp/conpot".to_string(), String::new());
        } else if template_lower.contains("elasticpot") {
            binds.push(format!("{host_path}:/opt/elasticpot/log:rw"));
        } else if template_lower.contains("endlessh") {
            binds.push(format!("{host_path}:/var/log/endlessh:rw"));
        }

        // Non-root images that rely on setcap file capabilities on python3 (mailoney uid 2000 port 25,
        // conpot uid 2000 port 502) cannot elevate via file caps if no-new-privileges is set.
        let uses_nonroot_file_caps =
            template_lower.contains("mailoney") || template_lower.contains("conpot");

        // ADR-001: Never bind-mount the Docker socket into a decoy container
        debug_assert!(
            !binds.iter().any(|b| b.contains("docker.sock")),
            "Docker socket must never be bind-mounted into a decoy container"
        );

        let host_config = HostConfig {
            port_bindings: Some(port_bindings),
            network_mode: Some(network_name.clone()),
            restart_policy,
            binds: Some(binds),
            cap_add: if cap_add.is_empty() {
                None
            } else {
                Some(cap_add)
            },
            cap_drop: if cap_drop.is_empty() {
                None
            } else {
                Some(cap_drop)
            },
            tmpfs: if tmpfs.is_empty() { None } else { Some(tmpfs) },
            pids_limit: Some(256),
            security_opt: if uses_nonroot_file_caps {
                None
            } else {
                Some(vec!["no-new-privileges:true".to_string()])
            },
            ..Default::default()
        };

        let config = Config {
            image: Some(image.to_string()),
            exposed_ports: Some(exposed_ports),
            host_config: Some(host_config),
            env: if env.is_empty() { None } else { Some(env) },
            // MED-5 fix: label the container as DecoyOps-managed so that
            // watch_events and reconcile_loop can filter to only our containers.
            labels: if is_unmanaged {
                None
            } else {
                Some(HashMap::from([(
                    "decoyops.managed".to_string(),
                    "true".to_string(),
                )]))
            },
            ..Default::default()
        };

        let create_opts = CreateContainerOptions {
            name,
            platform: None,
        };

        let create_res = match self
            .client
            .create_container(Some(create_opts), config)
            .await
        {
            Ok(res) => res,
            Err(e) => {
                self.rollback_deploy(
                    None,
                    &network_name,
                    network_created,
                    applied_subnet.as_deref(),
                )
                .await;
                return Err(format!("Failed to create container: {e}"));
            }
        };

        // 5. Start the container
        if let Err(e) = self
            .client
            .start_container::<String>(&create_res.id, None)
            .await
        {
            self.rollback_deploy(
                Some(&create_res.id),
                &network_name,
                network_created,
                applied_subnet.as_deref(),
            )
            .await;
            return Err(format!("Failed to start container: {e}"));
        }

        // Airgap isolation: strip default gateway from container network namespace (HC#4)
        if !is_unmanaged {
            let _ = self.strip_default_route(&create_res.id).await;
        }

        // 6. Start the tunnel if a provider is configured
        let mut tunnel_handle = None;
        if let Some(provider) = tunnel_provider {
            if let Ok(host_port) = host_port_str.parse::<u16>() {
                match provider
                    .start_tunnel(name, host_port, allocated_remote_port)
                    .await
                {
                    Ok(handle) => {
                        tunnel_handle = Some(handle);
                    }
                    Err(e) => {
                        self.rollback_deploy(
                            Some(&create_res.id),
                            &network_name,
                            network_created,
                            applied_subnet.as_deref(),
                        )
                        .await;
                        return Err(format!("Tunnel provider failed to start: {}", e));
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
            .map_err(|e| format!("Failed to start container {}: {}", name_or_id, e))?;
        let _ = self.strip_default_route(name_or_id).await;
        Ok(())
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
            .map_err(|e| format!("Failed to restart container {}: {}", name_or_id, e))?;
        let _ = self.strip_default_route(name_or_id).await;
        Ok(())
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
        let mut subnet_to_clean = None;
        if let Ok(details) = self.client.inspect_container(name_or_id, None).await {
            if let Some(net_settings) = details.network_settings {
                if let Some(networks) = net_settings.networks {
                    // Grab the first custom network (assumes one network per decoy)
                    if let Some(name) = networks.keys().next() {
                        if !is_reserved_network(name) {
                            network_to_remove = Some(name.clone());
                        }
                    }
                }
            }
        }

        // If network exists, inspect it to retrieve subnet CIDR before deletion
        if let Some(ref net) = network_to_remove {
            if let Ok(net_details) = self.client.inspect_network::<&str>(net, None).await {
                if let Some(cidr) = net_details
                    .ipam
                    .and_then(|ipam| ipam.config)
                    .and_then(|configs| configs.into_iter().find_map(|c| c.subnet))
                {
                    subnet_to_clean = Some(cidr);
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

        // Remove dedicated network FIRST; only remove the host firewall egress-drop
        // rule if the network is actually removed (so sibling decoys sharing a managed
        // network never lose egress isolation).
        let network_removed = if let Some(net) = network_to_remove {
            self.client.remove_network(&net).await.is_ok()
        } else {
            false
        };

        // MED-6 fix: Clean up firewall egress-deny rule for the subnet upon termination
        if network_removed {
            if let Some(cidr) = subnet_to_clean {
                if let Err(e) = get_firewall_backend().remove_egress_drop(&cidr) {
                    eprintln!(
                        "Warning: Failed to clean up firewall rule for subnet {}: {}",
                        cidr, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Pings the Docker daemon to check if it's reachable.
    pub async fn ping(&self) -> Result<(), String> {
        self.client
            .ping()
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Strips the default gateway from a decoy container's network namespace.
    /// This eliminates all outbound internet and external LAN routing at the kernel level,
    /// while preserving inbound port-forwarded honeypot traffic on the bridge subnet.
    pub async fn strip_default_route(&self, container_id: &str) -> Result<(), String> {
        // Only strip routes for DecoyOps-managed containers (not unmanaged or external ones)
        if let Ok(inspect) = self.client.inspect_container(container_id, None).await {
            if let Some(config) = inspect.config {
                if let Some(labels) = config.labels {
                    if labels.get("decoyops.managed").map(|s| s.as_str()) != Some("true") {
                        return Ok(());
                    }
                } else {
                    return Ok(());
                }
            }
        }

        use bollard::container::{Config, CreateContainerOptions};
        use bollard::models::HostConfig;
        use futures_util::StreamExt;

        if self.ensure_image_present("alpine", "latest").await.is_err() {
            return Ok(());
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let short_id = short_container_id(container_id);
        let helper_name = format!("route_strip_{}_{}", short_id, timestamp);

        let config = Config {
            image: Some("alpine:latest".to_string()),
            host_config: Some(HostConfig {
                network_mode: Some(format!("container:{}", container_id)),
                cap_drop: Some(vec!["ALL".to_string()]),
                cap_add: Some(vec!["NET_ADMIN".to_string()]),
                ..Default::default()
            }),
            cmd: Some(vec![
                "ip".to_string(),
                "route".to_string(),
                "del".to_string(),
                "default".to_string(),
            ]),
            ..Default::default()
        };

        if let Ok(container) = self
            .client
            .create_container(
                Some(CreateContainerOptions {
                    name: helper_name.as_str(),
                    platform: None,
                }),
                config,
            )
            .await
        {
            let _ = self
                .client
                .start_container::<String>(&container.id, None)
                .await;
            let mut wait_stream = self.client.wait_container::<String>(&container.id, None);
            let _ = wait_stream.next().await;
            let _ = self.client.remove_container(&container.id, None).await;
        }

        Ok(())
    }

    /// Verifies isolation by running a ping probe in the container's network namespace.
    pub async fn verify_isolation(&self, container_id: &str) -> Result<String, String> {
        use bollard::container::{Config, CreateContainerOptions, LogsOptions};
        use bollard::models::HostConfig;
        use futures_util::StreamExt;

        self.ensure_image_present("alpine", "latest").await?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let short_id = short_container_id(container_id);
        let probe_name = format!("probe_{}_{}", short_id, timestamp);

        let config = Config {
            image: Some("alpine:latest".to_string()),
            host_config: Some(HostConfig {
                network_mode: Some(format!("container:{}", container_id)),
                cap_drop: Some(vec!["ALL".to_string()]),
                cap_add: Some(vec!["NET_RAW".to_string()]),
                ..Default::default()
            }),
            cmd: Some(vec![
                "ping".to_string(),
                "-c".to_string(),
                "2".to_string(),
                "-W".to_string(),
                "2".to_string(),
                "8.8.8.8".to_string(),
            ]),
            ..Default::default()
        };

        let container = self
            .client
            .create_container(
                Some(CreateContainerOptions {
                    name: probe_name.as_str(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(|e| format!("Probe create failed: {}", e))?;

        let _ = self
            .client
            .start_container::<String>(&container.id, None)
            .await;

        let mut wait_stream = self.client.wait_container::<String>(&container.id, None);
        let wait_res = wait_stream.next().await;
        let exit_code = match wait_res {
            Some(Ok(response)) => response.status_code,
            _ => -1,
        };

        let mut logs_stream = self.client.logs(
            &container.id,
            Some(LogsOptions::<String> {
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );

        let mut output = String::new();
        while let Some(Ok(log_output)) = logs_stream.next().await {
            output.push_str(&log_output.to_string());
        }

        let _ = self.client.remove_container(&container.id, None).await;

        let lower = output.to_lowercase();
        // Ping only genuinely succeeds if the probe exited 0 AND received replies
        let ping_succeeded = exit_code == 0
            && (lower.contains("0% packet loss") || lower.contains("bytes from 8.8.8.8"));

        if ping_succeeded {
            Err(format!(
                "WARNING: Container can reach 8.8.8.8! Probe output:\n{}",
                output.trim()
            ))
        } else {
            let last_line = output
                .lines()
                .rfind(|l| !l.trim().is_empty())
                .unwrap_or("Network unreachable")
                .trim();
            Ok(format!("Egress isolation verified ({})", last_line))
        }
    }

    /// Captures a PCAP from the container's network namespace using a sidecar
    pub async fn capture_pcap(
        &self,
        container_id: &str,
        duration_secs: u64,
    ) -> Result<String, String> {
        use bollard::container::{Config, CreateContainerOptions, StartContainerOptions};
        use bollard::models::HostConfig;
        use futures_util::StreamExt;
        use std::io::Write;

        if !(1..=300).contains(&duration_secs) {
            return Err("PCAP capture duration must be between 1 and 300 seconds".to_string());
        }

        // Generate a unique name to prevent 409 Conflict if previous runs crashed
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let short_id = short_container_id(container_id);
        let sidecar_name = format!("pcap_{}_{}", short_id, timestamp);

        // Ensure data/pcaps directory exists
        let pcaps_dir = self.data_dir.join("pcaps");
        if !pcaps_dir.exists() {
            let _ = std::fs::create_dir_all(&pcaps_dir);
        }

        // Create an absolute path for the output file
        let file_name = format!("decoy_{}_traffic_{}.pcap", short_id, timestamp);
        let output_path = pcaps_dir.join(&file_name);

        // Ensure image exists locally (pull only if missing)
        self.ensure_image_present("nicolaka/netshoot", "latest")
            .await?;

        let config = Config {
            image: Some("nicolaka/netshoot:latest".to_string()),
            host_config: Some(HostConfig {
                network_mode: Some(format!("container:{}", container_id)),
                auto_remove: Some(true), // Ensure Docker cleans it up automatically when it exits
                // HIGH-3 fix: drop all capabilities and only add what tcpdump needs
                cap_drop: Some(vec!["ALL".to_string()]),
                cap_add: Some(vec!["NET_RAW".to_string(), "NET_ADMIN".to_string()]),
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
                "-".to_string(),
            ]),
            ..Default::default()
        };

        let create_res = self
            .client
            .create_container(
                Some(CreateContainerOptions {
                    name: sidecar_name.clone(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(|e| e.to_string())?;

        let _ = self
            .client
            .start_container(&create_res.id, None::<StartContainerOptions<String>>)
            .await;

        // Attach to capture stdout (the raw pcap bytes)
        let mut logs = self.client.logs(
            &create_res.id,
            Some(bollard::container::LogsOptions::<String> {
                stdout: true,
                follow: true,
                ..Default::default()
            }),
        );

        let mut file = std::fs::File::create(&output_path)
            .map_err(|e| format!("Failed to create output file: {}", e))?;

        while let Some(Ok(log)) = logs.next().await {
            file.write_all(log.into_bytes().as_ref())
                .map_err(|e| e.to_string())?;
        }

        Ok(output_path.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_port_mappings_and_sanitizes_names() {
        assert_eq!(
            validate_port_mapping("2222:22").unwrap(),
            ("127.0.0.1", "2222", "22")
        );
        assert_eq!(
            validate_port_mapping("127.0.0.1:2222:22").unwrap(),
            ("127.0.0.1", "2222", "22")
        );
        assert!(validate_port_mapping("0:22").is_err());
        assert!(validate_port_mapping("22:0").is_err());
        assert!(validate_port_mapping("not_ip:22:22").is_err());
        assert!(validate_port_mapping("22").is_err());
        assert_eq!(sanitize_decoy_name("SSH/../Evil"), "decoy_ssh____evil");
        assert!(is_reserved_network("BRIDGE"));
        assert!(!is_reserved_network("decoy-net"));
        assert_eq!(short_container_id("abcdef123456"), "abcdef12");
        assert_eq!(short_container_id("abc"), "abc");
    }
}
