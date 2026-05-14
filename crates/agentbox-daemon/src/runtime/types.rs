use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeCapability {
    ContainerIsolation,
    VmIsolation,
    NativeNamespaces,
    EndpointSecurity,
    WindowsJobObjects,
    AppContainer,
    FilesystemPolicy,
    NetworkPolicy,
    CredentialPolicy,
    ApprovalBridge,
    EvidenceExport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeStatus {
    Creating,
    Running,
    Paused,
    Stopped,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountKind {
    Workspace,
    #[default]
    ReadOnlyHost,
    Credential,
    SystemBridge,
    ServiceData,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensitivePathClass {
    Ssh,
    CloudCredentials,
    BrowserProfile,
    Keychain,
    EnvFile,
    HomeDirectory,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountRule {
    pub host_path: PathBuf,
    pub guest_path: String,
    pub mode: MountMode,
    #[serde(default)]
    pub kind: MountKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedPath {
    pub path: PathBuf,
    pub class: SensitivePathClass,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    pub workspace_host_path: PathBuf,
    pub workspace_guest_path: String,
    pub mounts: Vec<MountRule>,
    pub protected_paths: Vec<ProtectedPath>,
    pub deny_home_by_default: bool,
}

impl FilesystemPolicy {
    pub fn workspace(path: impl Into<PathBuf>) -> Self {
        Self {
            workspace_host_path: path.into(),
            workspace_guest_path: "/workspace".to_string(),
            mounts: vec![],
            protected_paths: default_protected_paths(),
            deny_home_by_default: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    None,
    DenyByDefault,
    AllowListed,
    ApprovalOnFirstContact,
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub allowed_domains: Vec<String>,
    pub denied_domains: Vec<String>,
    pub allow_localhost: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::DenyByDefault,
            allowed_domains: vec![],
            denied_domains: vec![],
            allow_localhost: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialGrantKind {
    EnvVar,
    FileMount,
    Socket,
    ProviderToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGrant {
    pub name: String,
    pub kind: CredentialGrantKind,
    pub target: String,
    pub one_time: bool,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPolicy {
    pub inherit_host_env: bool,
    pub grants: Vec<CredentialGrant>,
    pub redact_in_audit: bool,
}

impl Default for CredentialPolicy {
    fn default() -> Self {
        Self {
            inherit_host_env: false,
            grants: vec![],
            redact_in_audit: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePolicy {
    pub memory_bytes: u64,
    pub cpu_shares: u32,
    pub timeout_seconds: Option<u64>,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            memory_bytes: 1_073_741_824,
            cpu_shares: 2048,
            timeout_seconds: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileAccessMode {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalScope {
    Once,
    Command {
        binary: String,
        args_prefix: Vec<String>,
    },
    Path {
        path: PathBuf,
        access: FileAccessMode,
    },
    Domain {
        domain: String,
    },
    Session {
        session_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalGrant {
    pub id: String,
    pub scope: ApprovalScope,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProfile {
    pub name: String,
    pub kind: String,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    pub name: String,
    pub image: String,
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinipodSpec {
    pub id: String,
    pub name: String,
    pub agent: AgentProfile,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub credentials: CredentialPolicy,
    pub resources: ResourcePolicy,
    pub services: Vec<ServiceSpec>,
    pub labels: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

impl MinipodSpec {
    pub fn for_agent_task(agent_name: impl Into<String>, workspace: impl Into<PathBuf>) -> Self {
        let id = Ulid::new().to_string().to_lowercase();
        let short = &id[..12];
        let agent_name = agent_name.into();

        Self {
            id: id.clone(),
            name: format!("agentbox-{short}"),
            agent: AgentProfile {
                name: agent_name.clone(),
                kind: "autonomous-agent".to_string(),
                command: vec![agent_name],
            },
            filesystem: FilesystemPolicy::workspace(workspace),
            network: NetworkPolicy::default(),
            credentials: CredentialPolicy::default(),
            resources: ResourcePolicy::default(),
            services: vec![],
            labels: HashMap::new(),
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSession {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub platform: String,
    pub status: RuntimeStatus,
    pub spec: MinipodSpec,
    pub started_at: DateTime<Utc>,
    pub stopped_at: Option<DateTime<Utc>>,
}

impl RuntimeSession {
    pub fn new(name: String, provider: String, platform: String, spec: MinipodSpec) -> Self {
        Self {
            id: spec.id.clone(),
            name,
            provider,
            platform,
            status: RuntimeStatus::Creating,
            spec,
            started_at: Utc::now(),
            stopped_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecCommand {
    pub argv: Vec<String>,
    pub working_dir: Option<String>,
    pub env: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

fn default_protected_paths() -> Vec<ProtectedPath> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));

    vec![
        ProtectedPath {
            path: home.join(".ssh"),
            class: SensitivePathClass::Ssh,
            reason: "SSH private keys and config must not be visible by default".to_string(),
        },
        ProtectedPath {
            path: home.join(".aws"),
            class: SensitivePathClass::CloudCredentials,
            reason: "Cloud credentials require an explicit grant".to_string(),
        },
        ProtectedPath {
            path: home.join(".config/gcloud"),
            class: SensitivePathClass::CloudCredentials,
            reason: "Cloud credentials require an explicit grant".to_string(),
        },
        ProtectedPath {
            path: home.join("Library/Application Support"),
            class: SensitivePathClass::BrowserProfile,
            reason: "Browser and app profiles are not part of the task workspace".to_string(),
        },
        ProtectedPath {
            path: home.join("Library/Keychains"),
            class: SensitivePathClass::Keychain,
            reason: "macOS keychains require explicit mediation".to_string(),
        },
        ProtectedPath {
            path: home.join(".env"),
            class: SensitivePathClass::EnvFile,
            reason: "environment files often contain secrets".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_minipod_is_deny_by_default() {
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");

        assert!(spec.name.starts_with("agentbox-"));
        assert_eq!(spec.agent.name, "openclaw");
        assert_eq!(spec.filesystem.workspace_guest_path, "/workspace");
        assert!(spec.filesystem.deny_home_by_default);
        assert!(matches!(spec.network.mode, NetworkMode::DenyByDefault));
        assert!(!spec.credentials.inherit_host_env);
        assert!(spec.credentials.redact_in_audit);
    }

    #[test]
    fn protected_paths_include_common_credentials() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let classes: Vec<&SensitivePathClass> = spec
            .filesystem
            .protected_paths
            .iter()
            .map(|p| &p.class)
            .collect();

        assert!(classes.contains(&&SensitivePathClass::Ssh));
        assert!(classes.contains(&&SensitivePathClass::CloudCredentials));
        assert!(classes.contains(&&SensitivePathClass::BrowserProfile));
        assert!(classes.contains(&&SensitivePathClass::Keychain));
        assert!(classes.contains(&&SensitivePathClass::EnvFile));
    }

    #[test]
    fn runtime_session_uses_spec_id() {
        let spec = MinipodSpec::for_agent_task("aspendos", "/tmp/agentbox-work");
        let session = RuntimeSession::new(
            spec.name.clone(),
            "podman".to_string(),
            "macos".to_string(),
            spec.clone(),
        );

        assert_eq!(session.id, spec.id);
        assert_eq!(session.name, spec.name);
        assert_eq!(session.provider, "podman");
        assert!(matches!(session.status, RuntimeStatus::Creating));
    }

    #[test]
    fn mount_rule_carries_boundary_kind() {
        let mount = MountRule {
            host_path: "/tmp/config".into(),
            guest_path: "/mnt/config".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::Credential,
        };

        assert!(matches!(mount.kind, MountKind::Credential));
    }

    #[test]
    fn old_mount_rules_default_to_read_only_host_kind() {
        let json = serde_json::json!({
            "host_path": "/tmp/readme",
            "guest_path": "/mnt/readme",
            "mode": "ReadOnly"
        });

        let mount: MountRule = serde_json::from_value(json).unwrap();

        assert!(matches!(mount.kind, MountKind::ReadOnlyHost));
    }

    #[test]
    fn minipod_manifest_roundtrips_all_boundary_fields() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.agent.command = vec!["hermes".into(), "run".into()];
        spec.filesystem.mounts.push(MountRule {
            host_path: "/tmp/docs".into(),
            guest_path: "/mnt/docs".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::ReadOnlyHost,
        });
        spec.network.mode = NetworkMode::AllowListed;
        spec.network.allowed_domains = vec!["api.openai.com".into()];
        spec.network.denied_domains = vec!["metadata.google.internal".into()];
        spec.credentials.grants.push(CredentialGrant {
            name: "OPENAI_API_KEY".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "OPENAI_API_KEY".into(),
            one_time: true,
            requires_approval: true,
        });
        spec.resources.timeout_seconds = Some(600);
        spec.services.push(ServiceSpec {
            name: "postgres".into(),
            image: "postgres:17-alpine".into(),
            env: HashMap::from([("POSTGRES_PASSWORD".into(), "agentbox".into())]),
        });
        spec.labels
            .insert("agentbox.provider".into(), "agentpod-linux".into());

        let encoded = serde_json::to_string_pretty(&spec).unwrap();
        let decoded: MinipodSpec = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, spec);
        assert!(encoded.contains("\"network\""));
        assert!(encoded.contains("\"credentials\""));
        assert!(encoded.contains("\"agentbox.provider\""));
    }

    #[test]
    fn legacy_minipod_manifest_mounts_default_to_read_only_host_kind() {
        let json = serde_json::json!({
            "id": "01legacyagentpod",
            "name": "agentbox-legacy",
            "agent": {
                "name": "codex",
                "kind": "autonomous-agent",
                "command": ["codex"]
            },
            "filesystem": {
                "workspace_host_path": "/tmp/work",
                "workspace_guest_path": "/workspace",
                "mounts": [{
                    "host_path": "/tmp/docs",
                    "guest_path": "/mnt/docs",
                    "mode": "ReadOnly"
                }],
                "protected_paths": [],
                "deny_home_by_default": true
            },
            "network": {
                "mode": "DenyByDefault",
                "allowed_domains": [],
                "denied_domains": [],
                "allow_localhost": true
            },
            "credentials": {
                "inherit_host_env": false,
                "grants": [],
                "redact_in_audit": true
            },
            "resources": {
                "memory_bytes": 1073741824,
                "cpu_shares": 2048,
                "timeout_seconds": null
            },
            "services": [],
            "labels": {},
            "created_at": "2026-05-14T00:00:00Z"
        });

        let spec: MinipodSpec = serde_json::from_value(json).unwrap();

        assert!(matches!(
            spec.filesystem.mounts[0].kind,
            MountKind::ReadOnlyHost
        ));
    }

    #[test]
    fn approval_scope_models_sensitive_file_access() {
        let grant = ApprovalGrant {
            id: "grant-1".to_string(),
            scope: ApprovalScope::Path {
                path: "/tmp/secret.env".into(),
                access: FileAccessMode::Read,
            },
            reason: "agent needs one config file".to_string(),
            expires_at: None,
        };

        assert!(matches!(
            grant.scope,
            ApprovalScope::Path {
                access: FileAccessMode::Read,
                ..
            }
        ));
    }

    #[test]
    fn approval_scope_serializes_command_and_session_scopes() {
        let scopes = vec![
            ApprovalScope::Once,
            ApprovalScope::Command {
                binary: "cat".into(),
                args_prefix: vec!["/tmp/secret.env".into()],
            },
            ApprovalScope::Session {
                session_id: "session-1".into(),
            },
        ];

        let encoded = serde_json::to_string(&scopes).unwrap();
        let decoded: Vec<ApprovalScope> = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, scopes);
    }
}
