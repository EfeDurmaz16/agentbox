use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use ulid::Ulid;

use crate::audit::AuditEvent;

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

impl ApprovalGrant {
    pub fn bound_to_session(mut self, session_id: &str) -> Self {
        if let ApprovalScope::Session { session_id: scope } = &mut self.scope {
            if scope.is_empty() {
                *scope = session_id.to_string();
            }
        }
        self
    }

    pub fn session_scope_id(&self) -> Option<&str> {
        match &self.scope {
            ApprovalScope::Session { session_id } => Some(session_id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskPolicyBundle {
    #[serde(default = "default_task_policy_bundle_schema_version")]
    pub schema_version: u32,
    pub id: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub denied_domains: Vec<String>,
    #[serde(default)]
    pub read_only_mounts: Vec<MountRule>,
    #[serde(default)]
    pub credential_grants: Vec<CredentialGrant>,
    #[serde(default)]
    pub approval_grants: Vec<ApprovalGrant>,
    #[serde(default)]
    pub protected_paths: Vec<ProtectedPath>,
}

fn default_task_policy_bundle_schema_version() -> u32 {
    1
}

impl Default for TaskPolicyBundle {
    fn default() -> Self {
        Self {
            schema_version: default_task_policy_bundle_schema_version(),
            id: String::new(),
            source: None,
            description: None,
            labels: HashMap::new(),
            allowed_domains: vec![],
            denied_domains: vec![],
            read_only_mounts: vec![],
            credential_grants: vec![],
            approval_grants: vec![],
            protected_paths: vec![],
        }
    }
}

impl TaskPolicyBundle {
    pub fn apply_to_minipod(&self, spec: &mut MinipodSpec) {
        spec.labels.insert(
            format!("agentbox.policy_bundle.{}", self.id),
            self.source.clone().unwrap_or_else(|| "inline".to_string()),
        );
        for (key, value) in &self.labels {
            spec.labels.insert(key.clone(), value.clone());
        }
        if !self.allowed_domains.is_empty() {
            spec.network.mode = NetworkMode::AllowListed;
            append_unique(&mut spec.network.allowed_domains, &self.allowed_domains);
        }
        append_unique(&mut spec.network.denied_domains, &self.denied_domains);
        spec.filesystem
            .mounts
            .extend(self.read_only_mounts.iter().cloned());
        spec.filesystem
            .protected_paths
            .extend(self.protected_paths.iter().cloned());
        spec.credentials
            .grants
            .extend(self.credential_grants.iter().cloned());
        spec.approvals.extend(self.approval_grants.iter().cloned());
        spec.policy_bundles.push(self.clone());
    }
}

fn append_unique(values: &mut Vec<String>, additions: &[String]) {
    for addition in additions {
        if !values.iter().any(|value| value == addition) {
            values.push(addition.clone());
        }
    }
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
    #[serde(default)]
    pub approvals: Vec<ApprovalGrant>,
    #[serde(default)]
    pub policy_bundles: Vec<TaskPolicyBundle>,
    pub services: Vec<ServiceSpec>,
    pub labels: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

impl MinipodSpec {
    pub fn for_agent_task(agent_name: impl Into<String>, workspace: impl Into<PathBuf>) -> Self {
        let id = Ulid::new().to_string().to_lowercase();
        let short = &id[..12];
        let agent_name = agent_name.into();
        let workspace = workspace.into();
        let mut labels = HashMap::new();
        labels.insert("agentbox.agent".to_string(), agent_name.clone());
        labels.insert("agentbox.task".to_string(), id.clone());
        labels.insert(
            "agentbox.workspace".to_string(),
            workspace.display().to_string(),
        );

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
            approvals: vec![],
            policy_bundles: vec![],
            services: vec![],
            labels,
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
    #[serde(default)]
    pub approval_grants: Vec<ApprovalGrant>,
    pub started_at: DateTime<Utc>,
    pub stopped_at: Option<DateTime<Utc>>,
}

impl RuntimeSession {
    pub fn new(name: String, provider: String, platform: String, spec: MinipodSpec) -> Self {
        let mut spec = spec;
        let approval_grants = spec
            .approvals
            .iter()
            .cloned()
            .map(|grant| grant.bound_to_session(&spec.id))
            .collect();
        spec.labels
            .entry("agentbox.session".to_string())
            .or_insert_with(|| spec.id.clone());
        spec.labels
            .entry("agentbox.provider".to_string())
            .or_insert_with(|| provider.clone());
        spec.labels
            .entry("agentbox.platform".to_string())
            .or_insert_with(|| platform.clone());

        Self {
            id: spec.id.clone(),
            name,
            provider,
            platform,
            status: RuntimeStatus::Creating,
            spec,
            approval_grants,
            started_at: Utc::now(),
            stopped_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvidenceEvent {
    pub audit_event_id: String,
    pub timestamp: String,
    pub bucket: String,
    pub decision: String,
    pub command: String,
    pub event_hash: Option<String>,
}

impl From<&AuditEvent> for SessionEvidenceEvent {
    fn from(event: &AuditEvent) -> Self {
        Self {
            audit_event_id: event.id.clone(),
            timestamp: event.timestamp.clone(),
            bucket: event.bucket.clone(),
            decision: event.decision.clone(),
            command: event.command.clone(),
            event_hash: event.event_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvidenceBundle {
    pub schema_version: i64,
    pub bundle_id: String,
    pub session_id: String,
    pub session_name: String,
    pub provider: String,
    pub platform: String,
    pub status: RuntimeStatus,
    pub manifest: MinipodSpec,
    pub approvals: Vec<SessionEvidenceEvent>,
    pub commands: Vec<SessionEvidenceEvent>,
    pub boundary_events: Vec<SessionEvidenceEvent>,
    pub generated_at: DateTime<Utc>,
}

impl SessionEvidenceBundle {
    pub fn from_session_events(session: &RuntimeSession, events: &[AuditEvent]) -> Self {
        let mut approvals = Vec::new();
        let mut commands = Vec::new();
        let mut boundary_events = Vec::new();

        for event in events {
            let evidence_event = SessionEvidenceEvent::from(event);
            match event.bucket.as_str() {
                "approve" => approvals.push(evidence_event),
                "allow" | "block" => commands.push(evidence_event),
                _ => boundary_events.push(evidence_event),
            }
        }

        Self {
            schema_version: 1,
            bundle_id: Ulid::new().to_string(),
            session_id: session.id.clone(),
            session_name: session.name.clone(),
            provider: session.provider.clone(),
            platform: session.platform.clone(),
            status: session.status.clone(),
            manifest: session.spec.clone(),
            approvals,
            commands,
            boundary_events,
            generated_at: Utc::now(),
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
    fn minipod_spec_carries_standard_task_labels() {
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");

        assert_eq!(spec.labels.get("agentbox.agent"), Some(&"openclaw".into()));
        assert_eq!(spec.labels.get("agentbox.task"), Some(&spec.id));
        assert_eq!(
            spec.labels.get("agentbox.workspace"),
            Some(&"/tmp/agentbox-work".into())
        );
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
        assert_eq!(
            session.spec.labels.get("agentbox.session"),
            Some(&session.id)
        );
        assert_eq!(
            session.spec.labels.get("agentbox.provider"),
            Some(&"podman".to_string())
        );
        assert_eq!(
            session.spec.labels.get("agentbox.platform"),
            Some(&"macos".to_string())
        );
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
        spec.approvals.push(ApprovalGrant {
            id: "approval-1".into(),
            scope: ApprovalScope::Domain {
                domain: "api.openai.com".into(),
            },
            reason: "model API access".into(),
            expires_at: None,
        });
        spec.policy_bundles.push(TaskPolicyBundle {
            id: "research".into(),
            source: Some("policy/research.json".into()),
            allowed_domains: vec!["api.openai.com".into()],
            ..TaskPolicyBundle::default()
        });
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
        assert!(encoded.contains("\"policy_bundles\""));
        assert!(encoded.contains("\"agentbox.provider\""));
    }

    #[test]
    fn session_evidence_bundle_groups_audit_events() {
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = RuntimeSession::new(
            spec.name.clone(),
            "agentpod-linux".into(),
            "linux".into(),
            spec,
        );
        let events = vec![
            AuditEvent::new(
                1,
                Some("openclaw".into()),
                format!("runtime.create {}", session.id),
                "/tmp/agentbox-work".into(),
                "runtime".into(),
                "created".into(),
                None,
                Some("agentpod-linux".into()),
            ),
            AuditEvent::new(
                1,
                Some("openclaw".into()),
                "git push origin main".into(),
                "/tmp/agentbox-work".into(),
                "approve".into(),
                "approved".into(),
                Some(1200),
                Some("agentbox-shim".into()),
            ),
            AuditEvent::new(
                1,
                Some("openclaw".into()),
                "rm -rf /".into(),
                "/tmp/agentbox-work".into(),
                "block".into(),
                "blocked".into(),
                None,
                Some("agentbox-shim".into()),
            ),
        ];

        let bundle = SessionEvidenceBundle::from_session_events(&session, &events);

        assert_eq!(bundle.schema_version, 1);
        assert_eq!(bundle.session_id, session.id);
        assert_eq!(bundle.provider, "agentpod-linux");
        assert_eq!(bundle.approvals.len(), 1);
        assert_eq!(bundle.commands.len(), 1);
        assert_eq!(bundle.boundary_events.len(), 1);
        assert_eq!(bundle.manifest.agent.name, "openclaw");
    }

    #[test]
    fn network_policy_manifest_covers_governed_egress_modes() {
        let policies = vec![
            NetworkPolicy {
                mode: NetworkMode::DenyByDefault,
                allowed_domains: vec![],
                denied_domains: vec![],
                allow_localhost: true,
            },
            NetworkPolicy {
                mode: NetworkMode::AllowListed,
                allowed_domains: vec!["api.openai.com".into(), "github.com".into()],
                denied_domains: vec!["metadata.google.internal".into()],
                allow_localhost: false,
            },
            NetworkPolicy {
                mode: NetworkMode::ApprovalOnFirstContact,
                allowed_domains: vec![],
                denied_domains: vec!["169.254.169.254".into()],
                allow_localhost: true,
            },
        ];

        for policy in policies {
            let encoded = serde_json::to_string(&policy).unwrap();
            let decoded: NetworkPolicy = serde_json::from_str(&encoded).unwrap();

            assert_eq!(decoded, policy);
        }
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
        assert!(spec.approvals.is_empty());
        assert!(spec.policy_bundles.is_empty());
    }

    #[test]
    fn task_policy_bundle_applies_task_scoped_boundaries() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let bundle = TaskPolicyBundle {
            schema_version: 1,
            id: "deploy-preview".into(),
            source: Some("/tmp/deploy-preview.policy.json".into()),
            description: Some("preview deployment task policy".into()),
            labels: HashMap::from([("agentbox.task.kind".into(), "deploy-preview".into())]),
            allowed_domains: vec!["api.github.com".into(), "api.github.com".into()],
            denied_domains: vec!["metadata.google.internal".into()],
            read_only_mounts: vec![MountRule {
                host_path: "/tmp/docs".into(),
                guest_path: "/mnt/docs".into(),
                mode: MountMode::ReadOnly,
                kind: MountKind::ReadOnlyHost,
            }],
            credential_grants: vec![CredentialGrant {
                name: "github-token".into(),
                kind: CredentialGrantKind::EnvVar,
                target: "GITHUB_TOKEN".into(),
                one_time: true,
                requires_approval: true,
            }],
            approval_grants: vec![ApprovalGrant {
                id: "approve-github".into(),
                scope: ApprovalScope::Domain {
                    domain: "api.github.com".into(),
                },
                reason: "GitHub issue sync".into(),
                expires_at: None,
            }],
            protected_paths: vec![ProtectedPath {
                path: "/tmp/private".into(),
                class: SensitivePathClass::Custom("private".into()),
                reason: "private operator files".into(),
            }],
        };

        bundle.apply_to_minipod(&mut spec);

        assert!(matches!(spec.network.mode, NetworkMode::AllowListed));
        assert_eq!(spec.network.allowed_domains, vec!["api.github.com"]);
        assert_eq!(
            spec.network.denied_domains,
            vec!["metadata.google.internal"]
        );
        assert_eq!(spec.filesystem.mounts.len(), 1);
        assert_eq!(spec.credentials.grants.len(), 1);
        assert_eq!(spec.approvals.len(), 1);
        assert_eq!(spec.policy_bundles.len(), 1);
        assert_eq!(
            spec.labels.get("agentbox.policy_bundle.deploy-preview"),
            Some(&"/tmp/deploy-preview.policy.json".into())
        );
        assert_eq!(
            spec.labels.get("agentbox.task.kind"),
            Some(&"deploy-preview".into())
        );
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

    #[test]
    fn runtime_session_carries_session_bound_approval_grants() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.approvals.push(ApprovalGrant {
            id: "session-approval".into(),
            scope: ApprovalScope::Session {
                session_id: String::new(),
            },
            reason: "allow repeated task-local operation".into(),
            expires_at: None,
        });

        let session = RuntimeSession::new(
            spec.name.clone(),
            "native-test".into(),
            "test".into(),
            spec.clone(),
        );

        assert_eq!(session.approval_grants.len(), 1);
        assert_eq!(
            session.approval_grants[0].session_scope_id(),
            Some(spec.id.as_str())
        );
    }
}
