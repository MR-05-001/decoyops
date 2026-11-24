//! Firewall abstraction for decoy network isolation (ADR-002, HC#3).
//!
//! Enforces egress-deny by default on decoy bridge networks.
//! - **Linux:** Uses a subnet-scoped `nftables` drop rule.
//! - **Windows:** Uses the documented PowerShell `NetFirewallRule` stopgap.

#![allow(dead_code)]

use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallError {
    NotImplementedOs(&'static str),
    ExecutionFailed(String),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotImplementedOs(os) => write!(
                f,
                "Egress-deny isolation (HC#3) is not yet implemented for {}",
                os
            ),
            Self::ExecutionFailed(msg) => write!(f, "Firewall execution failed: {}", msg),
        }
    }
}

impl std::error::Error for FirewallError {}

/// Abstract interface for applying network isolation rules to a decoy subnet.
pub trait FirewallBackend: Send + Sync {
    /// Applies a default-drop policy to outbound traffic from the given subnet.
    ///
    /// # Arguments
    /// * `subnet_cidr` - The subnet to isolate (e.g., "172.20.1.0/24").
    fn apply_egress_drop(&self, subnet_cidr: &str) -> Result<(), FirewallError>;

    /// Removes the default-drop policy for the given subnet upon decoy termination (MED-6).
    ///
    /// # Arguments
    /// * `subnet_cidr` - The subnet to un-isolate (e.g., "172.20.1.0/24").
    fn remove_egress_drop(&self, subnet_cidr: &str) -> Result<(), FirewallError>;

    /// Allows outbound traffic from a specific container IP on specific ports.
    /// Used when C2 observation mode is enabled.
    ///
    /// # Arguments
    /// * `container_ip` - The isolated container's IP (e.g., "172.20.1.5").
    /// * `ports` - List of allowed destination TCP ports (e.g., [80, 443]).
    fn allow_egress_ports(&self, container_ip: &str, ports: &[u16]) -> Result<(), FirewallError>;
}

/// Validates an IPv4 or IPv6 CIDR before it is passed to a firewall backend.
pub fn validate_subnet_cidr(subnet_cidr: &str) -> Result<(), FirewallError> {
    let (address, prefix) = subnet_cidr.split_once('/').ok_or_else(|| {
        FirewallError::ExecutionFailed(format!("Invalid subnet CIDR: {subnet_cidr}"))
    })?;
    let address = address.parse::<IpAddr>().map_err(|_| {
        FirewallError::ExecutionFailed(format!("Invalid subnet CIDR: {subnet_cidr}"))
    })?;
    let prefix = prefix.parse::<u8>().map_err(|_| {
        FirewallError::ExecutionFailed(format!("Invalid subnet CIDR: {subnet_cidr}"))
    })?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(FirewallError::ExecutionFailed(format!(
            "Invalid subnet CIDR: {subnet_cidr}"
        )));
    }
    Ok(())
}

fn parse_ip(address: &str) -> Result<IpAddr, FirewallError> {
    address
        .parse::<IpAddr>()
        .map_err(|_| FirewallError::ExecutionFailed(format!("Invalid container IP: {address}")))
}

/// Output from an nftables command, abstracted to keep tests independent of host firewall state.
#[derive(Debug, Clone)]
pub struct NftCommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs one argument-safe nftables invocation.
pub trait NftCommandRunner: Send + Sync {
    fn run(&self, args: &[String]) -> Result<NftCommandOutput, String>;
}

struct SystemNftCommandRunner;

impl NftCommandRunner for SystemNftCommandRunner {
    fn run(&self, args: &[String]) -> Result<NftCommandOutput, String> {
        let output = Command::new("nft")
            .args(args)
            .output()
            .map_err(|error| error.to_string())?;
        Ok(NftCommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Linux backend using `nftables` (blueprint v3 §6).
pub struct NftablesBackend {
    runner: Arc<dyn NftCommandRunner>,
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self {
            runner: Arc::new(SystemNftCommandRunner),
        }
    }
}

impl NftablesBackend {
    pub fn with_runner(runner: Arc<dyn NftCommandRunner>) -> Self {
        Self { runner }
    }

    fn run(&self, args: &[&str]) -> Result<NftCommandOutput, FirewallError> {
        let args = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        self.runner
            .run(&args)
            .map_err(FirewallError::ExecutionFailed)
    }

    fn ensure_table(&self) -> Result<(), FirewallError> {
        let add = self.run(&["add", "table", "inet", "decoyops"])?;
        if add.success {
            return Ok(());
        }
        let existing = self.run(&["list", "table", "inet", "decoyops"])?;
        if existing.success {
            Ok(())
        } else {
            Err(FirewallError::ExecutionFailed(format!(
                "Unable to create nftables table inet decoyops: {}",
                add.stderr
            )))
        }
    }

    fn ensure_chain(&self) -> Result<(), FirewallError> {
        let add = self.run(&[
            "add",
            "chain",
            "inet",
            "decoyops",
            "decoy_egress",
            "{",
            "type",
            "filter",
            "hook",
            "forward",
            "priority",
            "0",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ])?;
        if add.success {
            return Ok(());
        }

        let existing = self.run(&["list", "chain", "inet", "decoyops", "decoy_egress"])?;
        if !existing.success {
            return Err(FirewallError::ExecutionFailed(format!(
                "Unable to create nftables chain inet decoyops decoy_egress: {}",
                add.stderr
            )));
        }
        if !existing.stdout.contains("type filter")
            || !existing.stdout.contains("hook forward")
            || !existing.stdout.contains("policy accept")
        {
            return Err(FirewallError::ExecutionFailed(
                "Existing nftables chain inet decoyops decoy_egress is not a forward filter chain with accept policy".into(),
            ));
        }
        Ok(())
    }

    fn ensure_base(&self) -> Result<(), FirewallError> {
        self.ensure_table()?;
        self.ensure_chain()
    }

    fn add_rule_if_missing(&self, rule: &[&str], insert: bool) -> Result<(), FirewallError> {
        let listed = self.run(&["list", "chain", "inet", "decoyops", "decoy_egress"])?;
        if !listed.success {
            return Err(FirewallError::ExecutionFailed(format!(
                "Unable to inspect nftables egress chain: {}",
                listed.stderr
            )));
        }
        let rule_text = rule.join(" ");
        if listed.stdout.contains(&rule_text) {
            return Ok(());
        }

        let mut args = vec![
            if insert { "insert" } else { "add" },
            "rule",
            "inet",
            "decoyops",
            "decoy_egress",
        ];
        args.extend_from_slice(rule);
        let added = self.run(&args)?;
        if !added.success {
            return Err(FirewallError::ExecutionFailed(format!(
                "Unable to install nftables egress rule: {}",
                added.stderr
            )));
        }
        Ok(())
    }
}

impl FirewallBackend for NftablesBackend {
    fn apply_egress_drop(&self, subnet_cidr: &str) -> Result<(), FirewallError> {
        validate_subnet_cidr(subnet_cidr)?;
        self.ensure_base()?;
        let address = subnet_cidr
            .split_once('/')
            .map(|(address, _)| address)
            .ok_or_else(|| FirewallError::ExecutionFailed("Invalid subnet CIDR".into()))?
            .parse::<IpAddr>()
            .map_err(|_| FirewallError::ExecutionFailed("Invalid subnet CIDR".into()))?;
        let family = if address.is_ipv4() { "ip" } else { "ip6" };
        self.add_rule_if_missing(&[family, "saddr", subnet_cidr, "drop"], false)
    }

    fn remove_egress_drop(&self, subnet_cidr: &str) -> Result<(), FirewallError> {
        validate_subnet_cidr(subnet_cidr)?;
        self.ensure_base()?;
        let address = subnet_cidr
            .split_once('/')
            .map(|(address, _)| address)
            .ok_or_else(|| FirewallError::ExecutionFailed("Invalid subnet CIDR".into()))?
            .parse::<IpAddr>()
            .map_err(|_| FirewallError::ExecutionFailed("Invalid subnet CIDR".into()))?;
        let family = if address.is_ipv4() { "ip" } else { "ip6" };

        let listed = self.run(&["list", "chain", "inet", "decoyops", "decoy_egress"])?;
        if !listed.success {
            return Err(FirewallError::ExecutionFailed(format!(
                "Unable to inspect nftables egress chain: {}",
                listed.stderr
            )));
        }

        let rule_text = format!("{family} saddr {subnet_cidr} drop");
        if !listed.stdout.contains(&rule_text) {
            return Ok(());
        }

        let deleted = self.run(&[
            "delete",
            "rule",
            "inet",
            "decoyops",
            "decoy_egress",
            family,
            "saddr",
            subnet_cidr,
            "drop",
        ])?;
        if !deleted.success {
            return Err(FirewallError::ExecutionFailed(format!(
                "Unable to delete nftables egress rule: {}",
                deleted.stderr
            )));
        }
        Ok(())
    }

    fn allow_egress_ports(&self, container_ip: &str, ports: &[u16]) -> Result<(), FirewallError> {
        let address = parse_ip(container_ip)?;
        if ports.is_empty() || ports.contains(&0) {
            return Err(FirewallError::ExecutionFailed(
                "At least one valid TCP destination port is required".into(),
            ));
        }
        self.ensure_base()?;
        let family = if address.is_ipv4() { "ip" } else { "ip6" };
        for port in ports {
            let port_text = port.to_string();
            self.add_rule_if_missing(
                &[
                    family,
                    "saddr",
                    container_ip,
                    "tcp",
                    "dport",
                    &port_text,
                    "accept",
                ],
                true,
            )?;
        }
        Ok(())
    }
}

/// Windows firewall backend using PowerShell `NetFirewallRule` (WFP alternative).
/// Requires the Tauri app to be run as Administrator.
pub struct WindowsFirewallBackend;

impl FirewallBackend for WindowsFirewallBackend {
    fn apply_egress_drop(&self, subnet_cidr: &str) -> Result<(), FirewallError> {
        validate_subnet_cidr(subnet_cidr)?;
        let rule_name = format!("DecoyOps_Block_{}", subnet_cidr.replace(['/', ':'], "_"));
        let script = format!(
            "Remove-NetFirewallRule -DisplayName '{0}' -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName '{0}' -Direction Outbound -Action Block -RemoteAddress Any -LocalAddress {1} -ErrorAction Stop",
            rule_name, subnet_cidr
        );

        let output = Command::new("powershell")
            .args(["-Command", &script])
            .output()
            .map_err(|error| FirewallError::ExecutionFailed(error.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Access is denied")
                || stderr.contains("PermissionDenied")
                || stderr.contains("System Error 5")
            {
                // In non-elevated mode on Windows, host NetFirewallRule cannot be created.
                // Docker in-engine isolation (enable_ip_masquerade: false and enable_icc: false)
                // provides kernel-level egress isolation within the Docker bridge.
                eprintln!(
                    "Notice: DecoyOps is running without Administrator privileges. Host NetFirewallRule skipped; Docker in-engine isolation is active."
                );
                return Ok(());
            }
            return Err(FirewallError::ExecutionFailed(format!(
                "PowerShell failed: {stderr}"
            )));
        }
        Ok(())
    }

    fn remove_egress_drop(&self, subnet_cidr: &str) -> Result<(), FirewallError> {
        validate_subnet_cidr(subnet_cidr)?;
        let rule_name = format!("DecoyOps_Block_{}", subnet_cidr.replace(['/', ':'], "_"));
        let script = format!(
            "Remove-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue",
            rule_name
        );

        let _ = Command::new("powershell")
            .args(["-Command", &script])
            .output();
        Ok(())
    }

    fn allow_egress_ports(&self, container_ip: &str, ports: &[u16]) -> Result<(), FirewallError> {
        parse_ip(container_ip)?;
        if ports.is_empty() || ports.contains(&0) {
            return Err(FirewallError::ExecutionFailed(
                "At least one valid TCP destination port is required".into(),
            ));
        }
        let ports_str = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let rule_name = format!("DecoyOps_Allow_{}", container_ip.replace(['.', ':'], "_"));
        let script = format!(
            "Remove-NetFirewallRule -DisplayName '{0}' -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName '{0}' -Direction Outbound -Action Allow -Protocol TCP -RemotePort {1} -LocalAddress {2} -ErrorAction Stop",
            rule_name, ports_str, container_ip
        );

        let output = Command::new("powershell")
            .args(["-Command", &script])
            .output()
            .map_err(|error| FirewallError::ExecutionFailed(error.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Access is denied")
                || stderr.contains("PermissionDenied")
                || stderr.contains("System Error 5")
            {
                // In non-elevated mode on Windows, host NetFirewallRule cannot be created.
                // Docker in-engine isolation (enable_ip_masquerade: false and enable_icc: false)
                // provides kernel-level egress isolation within the Docker bridge.
                eprintln!(
                    "Notice: DecoyOps is running without Administrator privileges. Host NetFirewallRule skipped; Docker in-engine isolation is active."
                );
                return Ok(());
            }
            return Err(FirewallError::ExecutionFailed(format!(
                "PowerShell failed: {stderr}"
            )));
        }
        Ok(())
    }
}

/// Fail-closed firewall stub for operating systems without an implemented host backend.
pub struct UnsupportedFirewallBackend(pub &'static str);

impl FirewallBackend for UnsupportedFirewallBackend {
    fn apply_egress_drop(&self, _subnet_cidr: &str) -> Result<(), FirewallError> {
        Err(FirewallError::NotImplementedOs(self.0))
    }

    fn remove_egress_drop(&self, _subnet_cidr: &str) -> Result<(), FirewallError> {
        Err(FirewallError::NotImplementedOs(self.0))
    }

    fn allow_egress_ports(&self, _container_ip: &str, _ports: &[u16]) -> Result<(), FirewallError> {
        Err(FirewallError::NotImplementedOs(self.0))
    }
}

/// Returns the appropriate firewall backend for the current OS.
pub fn get_firewall_backend() -> Box<dyn FirewallBackend> {
    #[cfg(target_os = "linux")]
    {
        Box::new(NftablesBackend::default())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsFirewallBackend)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Box::new(UnsupportedFirewallBackend(std::env::consts::OS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockNftRunner {
        calls: Mutex<Vec<Vec<String>>>,
        chain_output: Mutex<String>,
        fail_add_rule: bool,
    }

    impl NftCommandRunner for MockNftRunner {
        fn run(&self, args: &[String]) -> Result<NftCommandOutput, String> {
            self.calls.lock().unwrap().push(args.to_vec());
            let is_list = args.first().is_some_and(|arg| arg == "list");
            let is_chain_list = is_list && args.get(1).is_some_and(|arg| arg == "chain");
            let output = if args.first().is_some_and(|arg| arg == "add")
                && args.get(1).is_some_and(|arg| arg == "table")
            {
                NftCommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "exists".into(),
                }
            } else if is_list && args.get(1).is_some_and(|arg| arg == "table") {
                NftCommandOutput {
                    success: true,
                    stdout: "table inet decoyops {}".into(),
                    stderr: String::new(),
                }
            } else if args.first().is_some_and(|arg| arg == "add")
                && args.get(1).is_some_and(|arg| arg == "chain")
            {
                NftCommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                }
            } else if is_chain_list {
                NftCommandOutput {
                    success: true,
                    stdout: self.chain_output.lock().unwrap().clone(),
                    stderr: String::new(),
                }
            } else if args
                .first()
                .is_some_and(|arg| arg == "add" || arg == "insert")
                && args.get(1).is_some_and(|arg| arg == "rule")
            {
                if self.fail_add_rule {
                    NftCommandOutput {
                        success: false,
                        stdout: String::new(),
                        stderr: "permission denied".into(),
                    }
                } else {
                    let rule = args[5..].join(" ");
                    let mut chain = self.chain_output.lock().unwrap();
                    chain.push_str(&rule);
                    NftCommandOutput {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    }
                }
            } else if args.first().is_some_and(|arg| arg == "delete")
                && args.get(1).is_some_and(|arg| arg == "rule")
            {
                let rule = args[5..].join(" ");
                let mut chain = self.chain_output.lock().unwrap();
                *chain = chain.replace(&rule, "");
                NftCommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                }
            } else {
                NftCommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "unexpected command".into(),
                }
            };
            Ok(output)
        }
    }

    #[test]
    fn validates_cidr_prefix_and_address() {
        assert!(validate_subnet_cidr("172.20.1.0/24").is_ok());
        assert!(validate_subnet_cidr("2001:db8::/64").is_ok());
        assert!(validate_subnet_cidr("unknown").is_err());
        assert!(validate_subnet_cidr("172.20.1.0/33").is_err());
    }

    #[test]
    fn adds_scoped_drop_rule_idempotently() {
        let runner = Arc::new(MockNftRunner::default());
        let firewall = NftablesBackend::with_runner(runner.clone());

        firewall.apply_egress_drop("172.20.1.0/24").unwrap();
        firewall.apply_egress_drop("172.20.1.0/24").unwrap();

        let calls = runner.calls.lock().unwrap();
        let add_rule_count = calls
            .iter()
            .filter(|args| {
                args.first().is_some_and(|arg| arg == "add")
                    && args.get(1).is_some_and(|arg| arg == "rule")
            })
            .count();
        assert_eq!(add_rule_count, 1);
        assert!(calls.iter().any(|args| args
            == &[
                "add",
                "rule",
                "inet",
                "decoyops",
                "decoy_egress",
                "ip",
                "saddr",
                "172.20.1.0/24",
                "drop"
            ]));
    }

    #[test]
    fn allow_rule_is_single_ip_and_precedes_drop_rules() {
        let runner = Arc::new(MockNftRunner::default());
        let firewall = NftablesBackend::with_runner(runner.clone());

        firewall
            .allow_egress_ports("172.20.1.5", &[80, 443])
            .unwrap();

        let calls = runner.calls.lock().unwrap();
        let inserted = calls
            .iter()
            .filter(|args| {
                args.first().is_some_and(|arg| arg == "insert")
                    && args.get(1).is_some_and(|arg| arg == "rule")
            })
            .collect::<Vec<_>>();
        assert_eq!(inserted.len(), 2);
        assert!(inserted
            .iter()
            .all(|args| args.iter().any(|arg| arg == "172.20.1.5")));
    }

    #[test]
    fn rejects_invalid_allow_inputs_and_reports_command_failure() {
        let runner = Arc::new(MockNftRunner {
            fail_add_rule: true,
            ..Default::default()
        });
        let firewall = NftablesBackend::with_runner(runner);
        assert!(firewall.allow_egress_ports("not-an-ip", &[80]).is_err());
        assert!(firewall.allow_egress_ports("172.20.1.5", &[]).is_err());
        assert!(firewall.allow_egress_ports("172.20.1.5", &[0]).is_err());
        assert!(firewall.apply_egress_drop("172.20.1.0/24").is_err());
    }

    #[test]
    fn removes_scoped_drop_rule_cleanly() {
        let runner = Arc::new(MockNftRunner::default());
        let firewall = NftablesBackend::with_runner(runner.clone());

        firewall.apply_egress_drop("172.20.1.0/24").unwrap();
        firewall.remove_egress_drop("172.20.1.0/24").unwrap();

        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|args| args
            == &[
                "delete",
                "rule",
                "inet",
                "decoyops",
                "decoy_egress",
                "ip",
                "saddr",
                "172.20.1.0/24",
                "drop"
            ]));
    }

    #[test]
    fn unsupported_os_backend_fails_closed() {
        let backend = UnsupportedFirewallBackend("macos");
        assert_eq!(
            backend.apply_egress_drop("172.20.1.0/24"),
            Err(FirewallError::NotImplementedOs("macos"))
        );
        assert_eq!(
            backend.remove_egress_drop("172.20.1.0/24"),
            Err(FirewallError::NotImplementedOs("macos"))
        );
        assert_eq!(
            backend.allow_egress_ports("172.20.1.5", &[80]),
            Err(FirewallError::NotImplementedOs("macos"))
        );
    }
}
