//! Firewall abstraction for decoy network isolation (ADR-002, HC#3).
//!
//! Enforces egress-deny by default on decoy bridge networks.
//! - **Linux:** Uses `nftables`.
//! - **Windows:** Stubbed (WFP backend not yet implemented). Returns a specific error.

#![allow(dead_code)]

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

    /// Allows outbound traffic from a specific container IP on specific ports.
    /// Used when C2 observation mode is enabled.
    ///
    /// # Arguments
    /// * `container_ip` - The isolated container's IP (e.g., "172.20.1.5").
    /// * `ports` - List of allowed destination TCP ports (e.g., [80, 443]).
    fn allow_egress_ports(&self, container_ip: &str, ports: &[u16]) -> Result<(), FirewallError>;
}

/// Linux backend using `nftables` (blueprint v3 §6).
pub struct NftablesBackend;

impl FirewallBackend for NftablesBackend {
    fn apply_egress_drop(&self, subnet_cidr: &str) -> Result<(), FirewallError> {
        // TODO: invoke `nft` via std::process::Command to add the drop rule.
        // E.g.: nft add rule inet decoyops decoy_egress ip saddr <subnet_cidr> drop
        let _ = subnet_cidr;
        // In a real implementation we would run the command here.
        Ok(())
    }

    fn allow_egress_ports(&self, container_ip: &str, ports: &[u16]) -> Result<(), FirewallError> {
        // TODO: invoke `nft` via std::process::Command to add the allow rule.
        // E.g.: nft add rule inet decoyops decoy_egress ip saddr <container_ip> tcp dport { <ports> } accept
        let _ = (container_ip, ports);
        Ok(())
    }
}

/// Windows firewall backend using PowerShell `NetFirewallRule` (WFP alternative).
/// Requires the Tauri app to be run as Administrator.
pub struct WindowsFirewallBackend;

impl FirewallBackend for WindowsFirewallBackend {
    fn apply_egress_drop(&self, subnet_cidr: &str) -> Result<(), FirewallError> {
        let rule_name = format!("DecoyOps_Block_{}", subnet_cidr.replace("/", "_"));
        
        let script = format!(
            "New-NetFirewallRule -DisplayName '{}' -Direction Outbound -Action Block -RemoteAddress Any -LocalAddress {} -ErrorAction Stop",
            rule_name, subnet_cidr
        );

        let output = std::process::Command::new("powershell")
            .args(&["-Command", &script])
            .output()
            .map_err(|e| FirewallError::ExecutionFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::ExecutionFailed(format!("PowerShell failed: {}", stderr)));
        }

        Ok(())
    }

    fn allow_egress_ports(&self, container_ip: &str, ports: &[u16]) -> Result<(), FirewallError> {
        let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        let rule_name = format!("DecoyOps_Allow_{}", container_ip.replace(".", "_"));

        let script = format!(
            "New-NetFirewallRule -DisplayName '{}' -Direction Outbound -Action Allow -Protocol TCP -RemotePort {} -LocalAddress {} -ErrorAction Stop",
            rule_name, ports_str, container_ip
        );

        let output = std::process::Command::new("powershell")
            .args(&["-Command", &script])
            .output()
            .map_err(|e| FirewallError::ExecutionFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::ExecutionFailed(format!("PowerShell failed: {}", stderr)));
        }

        Ok(())
    }
}

/// Returns the appropriate firewall backend for the current OS.
pub fn get_firewall_backend() -> Box<dyn FirewallBackend> {
    #[cfg(target_os = "linux")]
    {
        Box::new(NftablesBackend)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsFirewallBackend)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Box::new(WindowsFirewallBackend) // Fallback for macOS, etc.
    }
}
