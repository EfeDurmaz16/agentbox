use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSpec {
    pub name: String,
    pub containers: Vec<ContainerSpec>,
    pub network: NetworkPolicy,
    pub resources: ResourceLimits,
    pub mounts: Vec<MountSpec>,
    pub env: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    pub env: HashMap<String, String>,
    pub ports: Vec<PortMapping>,
    pub role: ContainerRole,
    #[serde(default)]
    pub readiness: Option<ReadinessProbe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessProbe {
    pub command: Vec<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainerRole {
    Workspace,
    Sidecar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountSpec {
    pub host_path: PathBuf,
    pub container_path: String,
    pub read_only: bool,
    #[serde(default)]
    pub kind: MountKind,
    #[serde(default)]
    pub one_time: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountKind {
    Workspace,
    WorkspaceOverlay,
    #[default]
    ReadOnlyHost,
    Credential,
    SystemBridge,
    ServiceData,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub allow_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMode {
    None,
    Restricted,
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub memory_bytes: u64,
    pub cpu_shares: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 1_073_741_824,
            cpu_shares: 2048,
        }
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Restricted,
            allow_domains: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PodStatus {
    Creating,
    Running,
    Paused,
    Stopped,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSession {
    pub id: String,
    pub spec: PodSpec,
    pub status: PodStatus,
    pub created_at: DateTime<Utc>,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub working_dir: Option<String>,
    pub env: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory_bytes, 1_073_741_824); // 1 GiB
        assert_eq!(limits.cpu_shares, 2048);
    }

    #[test]
    fn test_network_policy_default() {
        let policy = NetworkPolicy::default();
        assert!(matches!(policy.mode, NetworkMode::Restricted));
        assert!(policy.allow_domains.is_empty());
    }

    #[test]
    fn legacy_mount_specs_default_to_read_only_host_kind() {
        let json = serde_json::json!({
            "host_path": "/tmp/config",
            "container_path": "/mnt/config",
            "read_only": true
        });

        let mount: MountSpec = serde_json::from_value(json).unwrap();

        assert!(matches!(mount.kind, MountKind::ReadOnlyHost));
        assert!(!mount.one_time);
    }
}
