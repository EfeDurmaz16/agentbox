use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use ulid::Ulid;

use crate::audit::AuditEvent;

pub const AGENTPOD_SPEC_SCHEMA_VERSION: u32 = 1;
pub const AGENTPOD_SPEC_KIND: &str = "AgentPod";

pub type AgentPodSpec = MinipodSpec;

fn default_agentpod_spec_schema_version() -> u32 {
    AGENTPOD_SPEC_SCHEMA_VERSION
}

fn default_agentpod_spec_kind() -> String {
    AGENTPOD_SPEC_KIND.to_string()
}

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
pub enum NetworkEnforcementCapability {
    ContainerNetworkMode,
    DomainAllowlist,
    DomainDenylist,
    FirstContactApproval,
    KernelPacketFilter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeStatus {
    Creating,
    Running,
    Paused,
    Stopped,
    Failed(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentPodRiskLevel {
    Low,
    #[default]
    Medium,
    High,
    VeryHigh,
}

impl AgentPodRiskLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::VeryHigh => "very-high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkspaceWritePolicy {
    #[default]
    Direct,
    WritableOverlay,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentPodWorkspaceMode {
    #[default]
    Direct,
    OverlayReview,
    Ephemeral,
    CommitGated,
}

impl AgentPodWorkspaceMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::OverlayReview => "overlay-review",
            Self::Ephemeral => "ephemeral",
            Self::CommitGated => "commit-gated",
        }
    }

    pub fn write_policy(&self) -> WorkspaceWritePolicy {
        match self {
            Self::Direct => WorkspaceWritePolicy::Direct,
            Self::OverlayReview | Self::Ephemeral | Self::CommitGated => {
                WorkspaceWritePolicy::WritableOverlay
            }
        }
    }
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkspaceOverlayMode {
    #[default]
    Disabled,
    ReviewRequired,
    DiscardOnDestroy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceOverlayPolicy {
    #[serde(default)]
    pub mode: WorkspaceOverlayMode,
    #[serde(default)]
    pub upper_host_path: Option<PathBuf>,
    #[serde(default)]
    pub work_host_path: Option<PathBuf>,
    #[serde(default = "default_workspace_overlay_guest_path")]
    pub guest_path: String,
}

impl Default for WorkspaceOverlayPolicy {
    fn default() -> Self {
        Self {
            mode: WorkspaceOverlayMode::Disabled,
            upper_host_path: None,
            work_host_path: None,
            guest_path: default_workspace_overlay_guest_path(),
        }
    }
}

impl WorkspaceOverlayPolicy {
    pub fn review_required(base_host_path: Option<PathBuf>) -> Self {
        let (upper_host_path, work_host_path) = base_host_path
            .map(|base| (Some(base.join("upper")), Some(base.join("work"))))
            .unwrap_or((None, None));

        Self {
            mode: WorkspaceOverlayMode::ReviewRequired,
            upper_host_path,
            work_host_path,
            guest_path: default_workspace_overlay_guest_path(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self.mode, WorkspaceOverlayMode::Disabled)
    }
}

fn default_workspace_overlay_guest_path() -> String {
    "/workspace".to_string()
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
    #[serde(default)]
    pub workspace_write_policy: WorkspaceWritePolicy,
    #[serde(default)]
    pub workspace_overlay: WorkspaceOverlayPolicy,
    pub mounts: Vec<MountRule>,
    pub protected_paths: Vec<ProtectedPath>,
    pub deny_home_by_default: bool,
}

impl FilesystemPolicy {
    pub fn workspace(path: impl Into<PathBuf>) -> Self {
        Self {
            workspace_host_path: path.into(),
            workspace_guest_path: "/workspace".to_string(),
            workspace_write_policy: WorkspaceWritePolicy::Direct,
            workspace_overlay: WorkspaceOverlayPolicy::default(),
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
    OpenWithGuardrails,
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
            mode: NetworkMode::OpenWithGuardrails,
            allowed_domains: vec![],
            denied_domains: cloud_metadata_domains(),
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
pub struct CredentialRevocationEvent {
    pub schema_version: i64,
    pub session_id: String,
    pub grant_name: String,
    pub kind: CredentialGrantKind,
    pub target: String,
    pub one_time: bool,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}

impl CredentialRevocationEvent {
    pub fn from_grant(
        session_id: impl Into<String>,
        grant: &CredentialGrant,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            session_id: session_id.into(),
            grant_name: grant.name.clone(),
            kind: grant.kind.clone(),
            target: grant.target.clone(),
            one_time: grant.one_time,
            reason: reason.into(),
            revoked_at: Utc::now(),
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
pub enum SeccompAction {
    Allow,
    Errno(i32),
    KillProcess,
    Log,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccompRule {
    pub syscall: String,
    pub action: SeccompAction,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccompProfile {
    pub enabled: bool,
    pub default_action: SeccompAction,
    pub rules: Vec<SeccompRule>,
    pub requires_linux: bool,
}

impl Default for SeccompProfile {
    fn default() -> Self {
        Self {
            enabled: false,
            default_action: SeccompAction::Allow,
            rules: vec![],
            requires_linux: true,
        }
    }
}

impl SeccompProfile {
    pub fn deny_syscalls(syscalls: &[&str], reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            enabled: true,
            default_action: SeccompAction::Allow,
            rules: syscalls
                .iter()
                .map(|syscall| SeccompRule {
                    syscall: (*syscall).to_string(),
                    action: SeccompAction::Errno(libc::EPERM),
                    reason: reason.clone(),
                })
                .collect(),
            requires_linux: true,
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
pub struct ApprovalSignature {
    pub signer: String,
    pub algorithm: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedApprovalRecord {
    pub schema_version: i64,
    pub grant_id: String,
    pub session_id: Option<String>,
    pub scope: ApprovalScope,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub evidence_refs: Vec<String>,
    pub signature: Option<ApprovalSignature>,
}

impl SignedApprovalRecord {
    pub fn unsigned_from_grant(
        grant: &ApprovalGrant,
        session_id: Option<String>,
        evidence_refs: Vec<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            grant_id: grant.id.clone(),
            session_id,
            scope: grant.scope.clone(),
            reason: grant.reason.clone(),
            expires_at: grant.expires_at,
            evidence_refs,
            signature: None,
        }
    }

    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

impl ApprovalGrant {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

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
    pub workspace_write_policy: Option<WorkspaceWritePolicy>,
    #[serde(default)]
    pub workspace_overlay: Option<WorkspaceOverlayPolicy>,
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
            workspace_write_policy: None,
            workspace_overlay: None,
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
        if let Some(policy) = &self.workspace_write_policy {
            spec.filesystem.workspace_write_policy = policy.clone();
        }
        if let Some(overlay) = &self.workspace_overlay {
            spec.filesystem.workspace_overlay = overlay.clone();
        }
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
pub struct AgentPolicyProfile {
    pub id: String,
    pub description: String,
    pub network: NetworkPolicy,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

impl Default for AgentPolicyProfile {
    fn default() -> Self {
        Self::named("general")
    }
}

impl AgentPolicyProfile {
    pub fn named(id: impl Into<String>) -> Self {
        let id = id.into();
        let normalized = id.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "" | "general" => Self::profile(
                "general",
                "Usable default profile for general autonomous agents with dangerous destinations blocked.",
                NetworkPolicy::default(),
            ),
            "coding" => Self::profile(
                "coding",
                "Software engineering agent profile with metadata endpoints denied.",
                NetworkPolicy {
                    mode: NetworkMode::DenyByDefault,
                    denied_domains: cloud_metadata_domains(),
                    ..NetworkPolicy::default()
                },
            ),
            "research" => Self::profile(
                "research",
                "Research agent profile that expects first-contact approval for external domains.",
                NetworkPolicy {
                    mode: NetworkMode::ApprovalOnFirstContact,
                    denied_domains: cloud_metadata_domains(),
                    allow_localhost: false,
                    ..NetworkPolicy::default()
                },
            ),
            "deploy" => Self::profile(
                "deploy",
                "Deployment agent profile with deny-by-default egress and metadata endpoints denied.",
                NetworkPolicy {
                    mode: NetworkMode::DenyByDefault,
                    denied_domains: cloud_metadata_domains(),
                    allow_localhost: false,
                    ..NetworkPolicy::default()
                },
            ),
            custom => Self::profile(
                custom,
                "Custom agent policy profile with conservative defaults.",
                NetworkPolicy {
                    mode: NetworkMode::DenyByDefault,
                    allowed_domains: vec![],
                    denied_domains: vec![],
                    allow_localhost: true,
                },
            ),
        }
    }

    fn profile(id: &str, description: &str, network: NetworkPolicy) -> Self {
        Self {
            id: id.to_string(),
            description: description.to_string(),
            network,
            labels: HashMap::from([("agentbox.policy_profile".into(), id.to_string())]),
        }
    }
}

fn cloud_metadata_domains() -> Vec<String> {
    vec![
        "169.254.169.254".into(),
        "metadata.google.internal".into(),
        "metadata.aws.internal".into(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    pub name: String,
    pub image: String,
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub readiness: Option<ServiceReadinessProbe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceReadinessProbe {
    pub command: Vec<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

impl ServiceReadinessProbe {
    pub fn command(command: Vec<String>) -> Self {
        Self {
            command,
            interval_ms: 500,
            timeout_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinipodSpec {
    #[serde(default = "default_agentpod_spec_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_agentpod_spec_kind")]
    pub kind: String,
    pub id: String,
    pub name: String,
    pub agent: AgentProfile,
    #[serde(default)]
    pub risk: AgentPodRiskLevel,
    #[serde(default)]
    pub workspace_mode: AgentPodWorkspaceMode,
    #[serde(default)]
    pub policy_profile: AgentPolicyProfile,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub credentials: CredentialPolicy,
    pub resources: ResourcePolicy,
    #[serde(default)]
    pub seccomp: SeccompProfile,
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
        Self::for_agent_task_with_profile(agent_name, workspace, "general")
    }

    pub fn for_agent_task_with_profile(
        agent_name: impl Into<String>,
        workspace: impl Into<PathBuf>,
        policy_profile: impl Into<String>,
    ) -> Self {
        let id = Ulid::new().to_string().to_lowercase();
        let short = &id[..12];
        let agent_name = agent_name.into();
        let workspace = workspace.into();
        let policy_profile = AgentPolicyProfile::named(policy_profile);
        let mut labels = HashMap::new();
        labels.insert("agentbox.agent".to_string(), agent_name.clone());
        labels.insert("agentbox.task".to_string(), id.clone());
        labels.insert(
            "agentbox.workspace".to_string(),
            workspace.display().to_string(),
        );

        Self {
            schema_version: AGENTPOD_SPEC_SCHEMA_VERSION,
            kind: AGENTPOD_SPEC_KIND.to_string(),
            id: id.clone(),
            name: format!("agentbox-{short}"),
            agent: AgentProfile {
                name: agent_name.clone(),
                kind: "autonomous-agent".to_string(),
                command: vec![agent_name],
            },
            risk: AgentPodRiskLevel::Medium,
            workspace_mode: AgentPodWorkspaceMode::Direct,
            policy_profile: policy_profile.clone(),
            filesystem: FilesystemPolicy::workspace(workspace),
            network: policy_profile.network.clone(),
            credentials: CredentialPolicy::default(),
            resources: ResourcePolicy::default(),
            seccomp: SeccompProfile::default(),
            approvals: vec![],
            policy_bundles: vec![],
            services: vec![],
            labels: labels
                .into_iter()
                .chain(policy_profile.labels.clone())
                .collect(),
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
    #[serde(default)]
    pub transcripts: Vec<CommandTranscript>,
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
            transcripts: vec![],
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
    pub risk: AgentPodRiskLevel,
    pub workspace_mode: AgentPodWorkspaceMode,
    #[serde(default)]
    pub provider_selection_reason: Option<String>,
    pub manifest: MinipodSpec,
    pub lifecycle_events: Vec<SessionEvidenceEvent>,
    pub approvals: Vec<SessionEvidenceEvent>,
    pub commands: Vec<SessionEvidenceEvent>,
    pub boundary_events: Vec<SessionEvidenceEvent>,
    #[serde(default)]
    pub transcripts: Vec<CommandTranscript>,
    pub replay: SessionReplayMetadata,
    pub generated_at: DateTime<Utc>,
}

impl SessionEvidenceBundle {
    pub fn from_session_events(session: &RuntimeSession, events: &[AuditEvent]) -> Self {
        let mut lifecycle_events = Vec::new();
        let mut approvals = Vec::new();
        let mut commands = Vec::new();
        let mut boundary_events = Vec::new();

        for event in events {
            let evidence_event = SessionEvidenceEvent::from(event);
            match event.bucket.as_str() {
                "runtime" => lifecycle_events.push(evidence_event),
                "approve" => approvals.push(evidence_event),
                "allow" | "block" => commands.push(evidence_event),
                _ => boundary_events.push(evidence_event),
            }
        }

        let replay = SessionReplayMetadata::from_session_events(session, events);

        Self {
            schema_version: 1,
            bundle_id: Ulid::new().to_string(),
            session_id: session.id.clone(),
            session_name: session.name.clone(),
            provider: session.provider.clone(),
            platform: session.platform.clone(),
            status: session.status.clone(),
            risk: session.spec.risk.clone(),
            workspace_mode: session.spec.workspace_mode.clone(),
            provider_selection_reason: session
                .spec
                .labels
                .get("agentbox.provider.selection_reason")
                .cloned(),
            manifest: session.spec.clone(),
            lifecycle_events,
            approvals,
            commands,
            boundary_events,
            transcripts: session.transcripts.clone(),
            replay,
            generated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReplayMetadata {
    pub schema_version: i64,
    pub replay_id: String,
    pub session_id: String,
    pub provider: String,
    pub platform: String,
    pub replayable: bool,
    pub limitations: Vec<String>,
    pub steps: Vec<SessionReplayStep>,
    pub generated_at: DateTime<Utc>,
}

impl SessionReplayMetadata {
    pub fn from_session_events(session: &RuntimeSession, events: &[AuditEvent]) -> Self {
        let steps = events
            .iter()
            .enumerate()
            .map(|(index, event)| SessionReplayStep::from_audit_event(index as i64 + 1, event))
            .collect();

        Self {
            schema_version: 1,
            replay_id: Ulid::new().to_string(),
            session_id: session.id.clone(),
            provider: session.provider.clone(),
            platform: session.platform.clone(),
            replayable: false,
            limitations: vec![
                "metadata-only: Agentbox does not rerun commands from evidence bundles".into(),
                "external side effects require operator review before manual replay".into(),
                "transcripts are redacted and may be truncated".into(),
            ],
            steps,
            generated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReplayStep {
    pub schema_version: i64,
    pub sequence: i64,
    pub timestamp: String,
    pub audit_event_id: String,
    pub event_hash: Option<String>,
    pub previous_event_hash: Option<String>,
    pub command: String,
    pub working_dir: String,
    pub policy_bucket: String,
    pub decision: String,
    pub parent_process: Option<String>,
}

impl SessionReplayStep {
    pub fn from_audit_event(sequence: i64, event: &AuditEvent) -> Self {
        Self {
            schema_version: 1,
            sequence,
            timestamp: event.timestamp.clone(),
            audit_event_id: event.id.clone(),
            event_hash: event.event_hash.clone(),
            previous_event_hash: event.prev_hash.clone(),
            command: event.command.clone(),
            working_dir: event.cwd.clone(),
            policy_bucket: event.bucket.clone(),
            decision: event.decision.clone(),
            parent_process: event.parent_process.clone(),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandTranscript {
    pub schema_version: i64,
    pub transcript_id: String,
    pub session_id: String,
    pub command_argv: Vec<String>,
    pub working_dir: Option<String>,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout: TranscriptStream,
    pub stderr: TranscriptStream,
    pub redaction: TranscriptRedaction,
    pub generated_at: DateTime<Utc>,
}

impl CommandTranscript {
    pub fn from_command_result(
        session_id: impl Into<String>,
        command: &ExecCommand,
        result: &CommandResult,
    ) -> Self {
        Self {
            schema_version: 1,
            transcript_id: Ulid::new().to_string(),
            session_id: session_id.into(),
            command_argv: command
                .argv
                .iter()
                .map(|arg| crate::audit::redact_sensitive_text(arg))
                .collect(),
            working_dir: command
                .working_dir
                .as_deref()
                .map(crate::audit::redact_sensitive_text),
            exit_code: result.exit_code,
            duration_ms: result.duration_ms,
            stdout: TranscriptStream::redacted(&result.stdout),
            stderr: TranscriptStream::redacted(&result.stderr),
            redaction: TranscriptRedaction::default(),
            generated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptStream {
    pub text: String,
    pub original_bytes: usize,
    pub original_lines: usize,
    pub stored_bytes: usize,
    pub truncated: bool,
}

impl TranscriptStream {
    pub fn redacted(input: &str) -> Self {
        const MAX_TRANSCRIPT_BYTES: usize = 16 * 1024;
        let redacted = input
            .lines()
            .map(crate::audit::redact_sensitive_text)
            .collect::<Vec<_>>()
            .join("\n");
        let original_bytes = input.len();
        let original_lines = input.lines().count();
        let (text, truncated) = truncate_utf8(&redacted, MAX_TRANSCRIPT_BYTES);
        let stored_bytes = text.len();

        Self {
            text,
            original_bytes,
            original_lines,
            stored_bytes,
            truncated,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptRedaction {
    pub marker: String,
    pub values_redacted: bool,
    pub max_stream_bytes: usize,
}

impl Default for TranscriptRedaction {
    fn default() -> Self {
        Self {
            marker: "<redacted>".to_string(),
            values_redacted: true,
            max_stream_bytes: 16 * 1024,
        }
    }
}

fn truncate_utf8(input: &str, max_bytes: usize) -> (String, bool) {
    if input.len() <= max_bytes {
        return (input.to_string(), false);
    }

    let mut end = max_bytes;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    (input[..end].to_string(), true)
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
    fn default_minipod_uses_open_network_with_guardrails() {
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");

        assert_eq!(spec.schema_version, AGENTPOD_SPEC_SCHEMA_VERSION);
        assert_eq!(spec.kind, AGENTPOD_SPEC_KIND);
        assert_eq!(spec.risk, AgentPodRiskLevel::Medium);
        assert_eq!(spec.workspace_mode, AgentPodWorkspaceMode::Direct);
        assert!(spec.name.starts_with("agentbox-"));
        assert_eq!(spec.agent.name, "openclaw");
        assert_eq!(spec.filesystem.workspace_guest_path, "/workspace");
        assert!(spec.filesystem.deny_home_by_default);
        assert!(matches!(
            spec.filesystem.workspace_write_policy,
            WorkspaceWritePolicy::Direct
        ));
        assert!(!spec.filesystem.workspace_overlay.is_enabled());
        assert!(matches!(spec.network.mode, NetworkMode::OpenWithGuardrails));
        assert!(spec
            .network
            .denied_domains
            .contains(&"169.254.169.254".into()));
        assert!(!spec.credentials.inherit_host_env);
        assert!(spec.credentials.redact_in_audit);
    }

    #[test]
    fn minipod_spec_carries_standard_task_labels() {
        let spec: AgentPodSpec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");

        assert_eq!(spec.labels.get("agentbox.agent"), Some(&"openclaw".into()));
        assert_eq!(spec.labels.get("agentbox.task"), Some(&spec.id));
        assert_eq!(
            spec.labels.get("agentbox.policy_profile"),
            Some(&"general".into())
        );
        assert_eq!(
            spec.labels.get("agentbox.workspace"),
            Some(&"/tmp/agentbox-work".into())
        );
    }

    #[test]
    fn agentpod_risk_levels_have_stable_labels() {
        assert_eq!(AgentPodRiskLevel::Low.label(), "low");
        assert_eq!(AgentPodRiskLevel::Medium.label(), "medium");
        assert_eq!(AgentPodRiskLevel::High.label(), "high");
        assert_eq!(AgentPodRiskLevel::VeryHigh.label(), "very-high");
    }

    #[test]
    fn agentpod_workspace_modes_have_stable_labels_and_write_policies() {
        assert_eq!(AgentPodWorkspaceMode::Direct.label(), "direct");
        assert_eq!(
            AgentPodWorkspaceMode::OverlayReview.label(),
            "overlay-review"
        );
        assert_eq!(AgentPodWorkspaceMode::Ephemeral.label(), "ephemeral");
        assert_eq!(AgentPodWorkspaceMode::CommitGated.label(), "commit-gated");
        assert_eq!(
            AgentPodWorkspaceMode::Direct.write_policy(),
            WorkspaceWritePolicy::Direct
        );
        assert_eq!(
            AgentPodWorkspaceMode::OverlayReview.write_policy(),
            WorkspaceWritePolicy::WritableOverlay
        );
    }

    #[test]
    fn per_agent_policy_profiles_set_network_defaults() {
        let coding =
            MinipodSpec::for_agent_task_with_profile("codex", "/tmp/agentbox-work", "coding");
        let research =
            MinipodSpec::for_agent_task_with_profile("hermes", "/tmp/agentbox-work", "research");
        let deploy =
            MinipodSpec::for_agent_task_with_profile("aspendos", "/tmp/agentbox-work", "deploy");

        assert_eq!(coding.policy_profile.id, "coding");
        assert!(matches!(coding.network.mode, NetworkMode::DenyByDefault));
        assert!(coding
            .network
            .denied_domains
            .contains(&"169.254.169.254".into()));
        assert_eq!(
            research.labels.get("agentbox.policy_profile"),
            Some(&"research".into())
        );
        assert!(matches!(
            research.network.mode,
            NetworkMode::ApprovalOnFirstContact
        ));
        assert!(!research.network.allow_localhost);
        assert_eq!(deploy.policy_profile.id, "deploy");
        assert!(!deploy.network.allow_localhost);
    }

    #[test]
    fn custom_agent_policy_profile_uses_conservative_defaults() {
        let spec =
            MinipodSpec::for_agent_task_with_profile("openclaw", "/tmp/agentbox-work", "browser");

        assert_eq!(spec.policy_profile.id, "browser");
        assert!(matches!(spec.network.mode, NetworkMode::DenyByDefault));
        assert!(spec.network.denied_domains.is_empty());
        assert_eq!(
            spec.labels.get("agentbox.policy_profile"),
            Some(&"browser".into())
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
    fn workspace_overlay_policy_models_reviewable_writes() {
        let overlay = WorkspaceOverlayPolicy::review_required(Some(
            "/tmp/agentbox-overlays/session-1".into(),
        ));

        assert!(overlay.is_enabled());
        assert!(matches!(overlay.mode, WorkspaceOverlayMode::ReviewRequired));
        assert_eq!(
            overlay.upper_host_path.as_deref(),
            Some(std::path::Path::new(
                "/tmp/agentbox-overlays/session-1/upper"
            ))
        );
        assert_eq!(
            overlay.work_host_path.as_deref(),
            Some(std::path::Path::new(
                "/tmp/agentbox-overlays/session-1/work"
            ))
        );
        assert_eq!(overlay.guest_path, "/workspace");
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
            readiness: Some(ServiceReadinessProbe::command(vec![
                "pg_isready".into(),
                "-U".into(),
                "postgres".into(),
            ])),
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
    fn credential_revocation_event_models_one_time_file_grants() {
        let grant = CredentialGrant {
            name: "openai".into(),
            kind: CredentialGrantKind::FileMount,
            target: "/tmp/agentbox-openai-key".into(),
            one_time: true,
            requires_approval: true,
        };

        let event =
            CredentialRevocationEvent::from_grant("01agentboxsession", &grant, "session destroyed");

        assert_eq!(event.schema_version, 1);
        assert_eq!(event.session_id, "01agentboxsession");
        assert_eq!(event.grant_name, "openai");
        assert!(event.one_time);
        assert_eq!(event.reason, "session destroyed");
    }

    #[test]
    fn session_evidence_bundle_groups_audit_events() {
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.labels.insert(
            "agentbox.provider.selection_reason".into(),
            "explicit provider requested".into(),
        );
        let mut session = RuntimeSession::new(
            spec.name.clone(),
            "agentpod-linux".into(),
            "linux".into(),
            spec,
        );
        session
            .transcripts
            .push(CommandTranscript::from_command_result(
                session.id.clone(),
                &ExecCommand {
                    argv: vec!["echo".into(), "hello".into()],
                    working_dir: Some("/workspace".into()),
                    env: Default::default(),
                    timeout_seconds: None,
                },
                &CommandResult {
                    exit_code: 0,
                    stdout: "hello\n".into(),
                    stderr: String::new(),
                    duration_ms: 2,
                },
            ));
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
        assert_eq!(bundle.risk, AgentPodRiskLevel::Medium);
        assert_eq!(bundle.workspace_mode, AgentPodWorkspaceMode::Direct);
        assert_eq!(
            bundle.provider_selection_reason.as_deref(),
            Some("explicit provider requested")
        );
        assert_eq!(bundle.lifecycle_events.len(), 1);
        assert_eq!(bundle.approvals.len(), 1);
        assert_eq!(bundle.commands.len(), 1);
        assert_eq!(bundle.boundary_events.len(), 0);
        assert_eq!(bundle.transcripts.len(), 1);
        assert_eq!(bundle.transcripts[0].stdout.text, "hello");
        assert_eq!(bundle.replay.session_id, session.id);
        assert_eq!(bundle.replay.steps.len(), 3);
        assert!(!bundle.replay.replayable);
        assert_eq!(bundle.replay.steps[0].sequence, 1);
        assert_eq!(bundle.replay.steps[1].policy_bucket, "approve");
        assert_eq!(bundle.manifest.agent.name, "openclaw");
    }

    #[test]
    fn session_replay_metadata_preserves_hash_chain_references() {
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = RuntimeSession::new(
            spec.name.clone(),
            "agentpod-linux".into(),
            "linux".into(),
            spec,
        );
        let mut first = AuditEvent::new(
            1,
            Some("openclaw".into()),
            format!("runtime.create {}", session.id),
            "/tmp/agentbox-work".into(),
            "runtime".into(),
            "created".into(),
            None,
            Some("agentpod-linux".into()),
        );
        first.event_hash = Some("hash-1".into());
        let mut second = AuditEvent::new(
            1,
            Some("openclaw".into()),
            format!("runtime.exec {} echo hello", session.id),
            "/tmp/agentbox-work".into(),
            "runtime".into(),
            "exit_code:0".into(),
            None,
            Some("agentpod-linux".into()),
        );
        second.prev_hash = first.event_hash.clone();
        second.event_hash = Some("hash-2".into());

        let replay = SessionReplayMetadata::from_session_events(&session, &[first, second]);

        assert_eq!(replay.schema_version, 1);
        assert_eq!(replay.session_id, session.id);
        assert_eq!(replay.provider, "agentpod-linux");
        assert!(!replay.replayable);
        assert_eq!(replay.steps.len(), 2);
        assert_eq!(replay.steps[1].sequence, 2);
        assert_eq!(replay.steps[1].event_hash.as_deref(), Some("hash-2"));
        assert_eq!(
            replay.steps[1].previous_event_hash.as_deref(),
            Some("hash-1")
        );
        assert!(replay
            .limitations
            .iter()
            .any(|limitation| limitation.contains("metadata-only")));
    }

    #[test]
    fn command_transcript_redacts_sensitive_streams_and_args() {
        let command = ExecCommand {
            argv: vec![
                "curl".into(),
                "-H".into(),
                "Authorization: Bearer sk-test-secret".into(),
            ],
            working_dir: Some("/tmp/project/.env".into()),
            env: Default::default(),
            timeout_seconds: None,
        };
        let result = CommandResult {
            exit_code: 1,
            stdout: "token sk-test-secret\nnormal line".into(),
            stderr: "Authorization: Bearer sk-test-secret".into(),
            duration_ms: 5,
        };

        let transcript =
            CommandTranscript::from_command_result("01agentboxsession", &command, &result);
        let json = serde_json::to_string(&transcript).unwrap();

        assert_eq!(transcript.session_id, "01agentboxsession");
        assert_eq!(transcript.exit_code, 1);
        assert!(transcript.redaction.values_redacted);
        assert!(json.contains("<redacted>"));
        assert!(!json.contains("sk-test-secret"));
        assert!(!json.contains("/tmp/project/.env"));
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
            NetworkPolicy {
                mode: NetworkMode::OpenWithGuardrails,
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
    fn default_seccomp_profile_is_explicitly_disabled() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");

        assert!(!spec.seccomp.enabled);
        assert_eq!(spec.seccomp.default_action, SeccompAction::Allow);
        assert!(spec.seccomp.rules.is_empty());
        assert!(spec.seccomp.requires_linux);
    }

    #[test]
    fn seccomp_profile_models_targeted_syscall_denial() {
        let profile = SeccompProfile::deny_syscalls(
            &["ptrace", "bpf"],
            "debugging and kernel instrumentation require explicit product support",
        );

        assert!(profile.enabled);
        assert_eq!(profile.default_action, SeccompAction::Allow);
        assert_eq!(profile.rules.len(), 2);
        assert_eq!(profile.rules[0].syscall, "ptrace");
        assert_eq!(profile.rules[0].action, SeccompAction::Errno(libc::EPERM));
        assert!(profile.rules[1].reason.contains("kernel instrumentation"));
    }

    #[test]
    fn network_enforcement_capabilities_roundtrip_as_explicit_flags() {
        let capabilities = vec![
            NetworkEnforcementCapability::ContainerNetworkMode,
            NetworkEnforcementCapability::DomainAllowlist,
            NetworkEnforcementCapability::DomainDenylist,
            NetworkEnforcementCapability::FirstContactApproval,
            NetworkEnforcementCapability::KernelPacketFilter,
        ];

        let encoded = serde_json::to_string(&capabilities).unwrap();
        let decoded: Vec<NetworkEnforcementCapability> = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, capabilities);
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

        assert_eq!(spec.schema_version, AGENTPOD_SPEC_SCHEMA_VERSION);
        assert_eq!(spec.kind, AGENTPOD_SPEC_KIND);
        assert_eq!(spec.risk, AgentPodRiskLevel::Medium);
        assert_eq!(spec.workspace_mode, AgentPodWorkspaceMode::Direct);
        assert!(matches!(
            spec.filesystem.mounts[0].kind,
            MountKind::ReadOnlyHost
        ));
        assert_eq!(spec.policy_profile.id, "general");
        assert!(spec.approvals.is_empty());
        assert!(spec.policy_bundles.is_empty());
        assert!(matches!(
            spec.filesystem.workspace_write_policy,
            WorkspaceWritePolicy::Direct
        ));
        assert!(!spec.filesystem.workspace_overlay.is_enabled());
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
            workspace_write_policy: Some(WorkspaceWritePolicy::WritableOverlay),
            workspace_overlay: Some(WorkspaceOverlayPolicy::review_required(None)),
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
        assert!(spec
            .network
            .denied_domains
            .contains(&"metadata.google.internal".into()));
        assert!(spec
            .network
            .denied_domains
            .contains(&"169.254.169.254".into()));
        assert_eq!(spec.filesystem.mounts.len(), 1);
        assert!(matches!(
            spec.filesystem.workspace_write_policy,
            WorkspaceWritePolicy::WritableOverlay
        ));
        assert!(spec.filesystem.workspace_overlay.is_enabled());
        assert!(matches!(
            spec.filesystem.workspace_overlay.mode,
            WorkspaceOverlayMode::ReviewRequired
        ));
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
    fn signed_approval_record_models_unsigned_and_signed_states() {
        let grant = ApprovalGrant {
            id: "grant-git-push".into(),
            scope: ApprovalScope::Command {
                binary: "git".into(),
                args_prefix: vec!["push".into()],
            },
            reason: "operator approved git push".into(),
            expires_at: None,
        };

        let mut record = SignedApprovalRecord::unsigned_from_grant(
            &grant,
            Some("01agentboxsession".into()),
            vec!["audit-event-1".into()],
        );

        assert_eq!(record.schema_version, 1);
        assert_eq!(record.grant_id, grant.id);
        assert_eq!(record.session_id.as_deref(), Some("01agentboxsession"));
        assert_eq!(record.evidence_refs, vec!["audit-event-1"]);
        assert!(!record.is_signed());

        record.signature = Some(ApprovalSignature {
            signer: "did:fides:agentbox-authority".into(),
            algorithm: "ed25519".into(),
            signature: "base64url-signature-placeholder".into(),
            signed_at: Utc::now(),
        });

        assert!(record.is_signed());
    }

    #[test]
    fn approval_grant_expiry_uses_inclusive_deadline() {
        let now = Utc::now();
        let active = ApprovalGrant {
            id: "active".into(),
            scope: ApprovalScope::Once,
            reason: "active".into(),
            expires_at: Some(now + chrono::Duration::seconds(60)),
        };
        let expired = ApprovalGrant {
            id: "expired".into(),
            scope: ApprovalScope::Once,
            reason: "expired".into(),
            expires_at: Some(now),
        };

        assert!(!active.is_expired_at(now));
        assert!(expired.is_expired_at(now));
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
