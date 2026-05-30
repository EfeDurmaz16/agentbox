use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use ulid::Ulid;

use agentbox_agentpod::{
    is_native_agentpod_provider, runner_phase_status_counts_as_enforced,
    runner_phase_status_counts_as_skipped, skipped_primitives_for_provider,
    AgentPodEnforcementStatus,
};
pub use agentbox_agentpod::{AgentPodNativeReceiptSummary, AgentPodRunnerPhaseReceipt};

use crate::audit::{redact_command_argv, redact_command_env, redact_sensitive_text, AuditEvent};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl CredentialGrant {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }
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
    #[serde(
        default,
        skip_serializing_if = "SeccompProfileSource::is_agentbox_generated"
    )]
    pub source: SeccompProfileSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SeccompProfileSource {
    #[default]
    AgentboxGenerated,
    ImportedOciLibseccomp {
        source: String,
    },
}

impl SeccompProfileSource {
    pub fn is_agentbox_generated(&self) -> bool {
        matches!(self, Self::AgentboxGenerated)
    }
}

impl Default for SeccompProfile {
    fn default() -> Self {
        Self {
            enabled: false,
            default_action: SeccompAction::Allow,
            rules: vec![],
            requires_linux: true,
            source: SeccompProfileSource::AgentboxGenerated,
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
            source: SeccompProfileSource::AgentboxGenerated,
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
#[serde(rename_all = "snake_case")]
pub enum ApprovalReceiptDecision {
    Granted,
    Denied,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedApprovalRecord {
    pub schema_version: i64,
    pub grant_id: String,
    pub session_id: Option<String>,
    pub scope: ApprovalScope,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub decision: ApprovalReceiptDecision,
    pub evidence_hash: String,
    pub evidence_refs: Vec<String>,
    pub signature: Option<ApprovalSignature>,
}

impl SignedApprovalRecord {
    pub fn unsigned_from_grant(
        grant: &ApprovalGrant,
        session_id: Option<String>,
        decision: ApprovalReceiptDecision,
        evidence_hash: String,
        evidence_refs: Vec<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            grant_id: grant.id.clone(),
            session_id,
            scope: grant.scope.clone(),
            reason: grant.reason.clone(),
            expires_at: grant.expires_at,
            decision,
            evidence_hash,
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
        "169.254.170.2".into(),
        "100.100.100.200".into(),
        "metadata.google.internal".into(),
        "metadata".into(),
        "metadata.aws.internal".into(),
        "fd00:ec2::254".into(),
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
    #[serde(default)]
    pub previous_event_hash: Option<String>,
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
            previous_event_hash: event.prev_hash.clone(),
            event_hash: event.event_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvidenceHashChain {
    pub schema_version: i64,
    pub algorithm: String,
    pub event_count: usize,
    pub first_event_hash: Option<String>,
    pub last_event_hash: Option<String>,
    pub events: Vec<SessionEvidenceHashChainEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvidenceHashChainEvent {
    pub schema_version: i64,
    pub sequence: i64,
    pub audit_event_id: String,
    pub audit_previous_event_hash: Option<String>,
    pub audit_event_hash: Option<String>,
    pub bundle_previous_event_hash: Option<String>,
    pub bundle_event_hash: String,
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
    pub credential_grants: Vec<CredentialEvidenceSummary>,
    #[serde(default)]
    pub credential_events: Vec<SessionEvidenceEvent>,
    #[serde(default)]
    pub transcripts: Vec<CommandTranscript>,
    #[serde(default)]
    pub integration_descriptors: Vec<EvidenceIntegrationDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agentpod_receipt: Option<AgentPodNativeReceiptSummary>,
    pub replay: SessionReplayMetadata,
    #[serde(default)]
    pub hash_chain: SessionEvidenceHashChain,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceIntegrationDescriptor {
    pub schema_version: i64,
    pub integration: String,
    pub descriptor_kind: String,
    pub status: String,
    pub live_support: bool,
    pub requires_external_adapter: bool,
    pub evidence_refs: Vec<String>,
    pub limitations: Vec<String>,
}

impl EvidenceIntegrationDescriptor {
    fn disabled(
        integration: &str,
        descriptor_kind: &str,
        status: &str,
        evidence_refs: &[String],
        limitations: &[&str],
    ) -> Self {
        Self {
            schema_version: 1,
            integration: integration.to_string(),
            descriptor_kind: descriptor_kind.to_string(),
            status: status.to_string(),
            live_support: false,
            requires_external_adapter: true,
            evidence_refs: evidence_refs.to_vec(),
            limitations: limitations
                .iter()
                .map(|limitation| limitation.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialEvidenceSummary {
    pub schema_version: i64,
    pub grant_name: String,
    pub kind: CredentialGrantKind,
    pub target: String,
    pub one_time: bool,
    pub requires_approval: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub status: String,
}

impl CredentialEvidenceSummary {
    pub fn from_grant(grant: &CredentialGrant, now: DateTime<Utc>) -> Self {
        Self {
            schema_version: 1,
            grant_name: grant.name.clone(),
            kind: grant.kind.clone(),
            target: redact_sensitive_text(&grant.target),
            one_time: grant.one_time,
            requires_approval: grant.requires_approval,
            expires_at: grant.expires_at,
            status: if grant.is_expired_at(now) {
                "expired".to_string()
            } else {
                "active".to_string()
            },
        }
    }
}

impl SessionEvidenceBundle {
    pub fn from_session_events(session: &RuntimeSession, events: &[AuditEvent]) -> Self {
        let mut lifecycle_events = Vec::new();
        let mut approvals = Vec::new();
        let mut commands = Vec::new();
        let mut boundary_events = Vec::new();
        let mut credential_events = Vec::new();

        for event in events {
            let evidence_event = SessionEvidenceEvent::from(event);
            match event.bucket.as_str() {
                "runtime" => lifecycle_events.push(evidence_event),
                "approve" => approvals.push(evidence_event),
                "allow" | "block" => commands.push(evidence_event),
                "credential" => credential_events.push(evidence_event),
                _ => boundary_events.push(evidence_event),
            }
        }

        let replay = SessionReplayMetadata::from_session_events(session, events);
        let hash_chain = SessionEvidenceHashChain::from_replay(&replay);
        let evidence_refs = evidence_refs_for_events(events);
        let integration_descriptors = evidence_integration_descriptors(&evidence_refs);
        let agentpod_receipt = agentpod_native_receipt_summary(session, events);
        let now = Utc::now();

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
            credential_grants: session
                .spec
                .credentials
                .grants
                .iter()
                .map(|grant| CredentialEvidenceSummary::from_grant(grant, now))
                .collect(),
            credential_events,
            transcripts: session.transcripts.clone(),
            integration_descriptors,
            agentpod_receipt,
            replay,
            hash_chain,
            generated_at: Utc::now(),
        }
    }

    pub fn verify_hash_chain(&self) -> Result<(), String> {
        let expected = SessionEvidenceHashChain::from_replay(&self.replay);
        if self.hash_chain != expected {
            return Err("session evidence hash chain does not match replay steps".to_string());
        }

        let grouped_events = self.grouped_evidence_events();
        if grouped_events.len() != self.replay.steps.len() {
            return Err(format!(
                "session evidence event count mismatch: replay has {}, grouped events have {}",
                self.replay.steps.len(),
                grouped_events.len()
            ));
        }

        for step in &self.replay.steps {
            let Some((category, event)) = grouped_events
                .iter()
                .find(|(_, event)| event.audit_event_id == step.audit_event_id)
            else {
                return Err(format!(
                    "replay step {} is missing grouped evidence event {}",
                    step.sequence, step.audit_event_id
                ));
            };
            if event.bucket != step.policy_bucket
                || event.decision != step.decision
                || event.command != step.command
                || event.event_hash != step.event_hash
                || event.previous_event_hash != step.previous_event_hash
            {
                return Err(format!(
                    "grouped {category} evidence event {} does not match replay step {}",
                    event.audit_event_id, step.sequence
                ));
            }
        }

        Ok(())
    }

    fn grouped_evidence_events(&self) -> Vec<(&'static str, &SessionEvidenceEvent)> {
        self.lifecycle_events
            .iter()
            .map(|event| ("lifecycle_events", event))
            .chain(self.approvals.iter().map(|event| ("approvals", event)))
            .chain(self.commands.iter().map(|event| ("commands", event)))
            .chain(
                self.boundary_events
                    .iter()
                    .map(|event| ("boundary_events", event)),
            )
            .chain(
                self.credential_events
                    .iter()
                    .map(|event| ("credential_events", event)),
            )
            .collect()
    }
}

impl SessionEvidenceHashChain {
    pub fn from_replay(replay: &SessionReplayMetadata) -> Self {
        let mut previous_bundle_hash = None;
        let mut events = Vec::with_capacity(replay.steps.len());

        for step in &replay.steps {
            let bundle_event_hash =
                session_evidence_bundle_event_hash(previous_bundle_hash.as_deref(), step);
            events.push(SessionEvidenceHashChainEvent {
                schema_version: 1,
                sequence: step.sequence,
                audit_event_id: step.audit_event_id.clone(),
                audit_previous_event_hash: step.previous_event_hash.clone(),
                audit_event_hash: step.event_hash.clone(),
                bundle_previous_event_hash: previous_bundle_hash.clone(),
                bundle_event_hash: bundle_event_hash.clone(),
            });
            previous_bundle_hash = Some(bundle_event_hash);
        }

        Self {
            schema_version: 1,
            algorithm: "sha256-session-replay-step-v1".to_string(),
            event_count: events.len(),
            first_event_hash: events.first().map(|event| event.bundle_event_hash.clone()),
            last_event_hash: events.last().map(|event| event.bundle_event_hash.clone()),
            events,
        }
    }
}

fn session_evidence_bundle_event_hash(
    previous_bundle_hash: Option<&str>,
    step: &SessionReplayStep,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"agentbox-session-evidence-event-v1\0");
    hash_field(&mut hasher, previous_bundle_hash);
    hash_field(&mut hasher, Some(&step.sequence.to_string()));
    hash_field(&mut hasher, Some(&step.timestamp));
    hash_field(&mut hasher, Some(&step.audit_event_id));
    hash_field(&mut hasher, step.event_hash.as_deref());
    hash_field(&mut hasher, step.previous_event_hash.as_deref());
    hash_field(&mut hasher, Some(&step.command));
    hash_field(&mut hasher, Some(&step.working_dir));
    hash_field(&mut hasher, Some(&step.policy_bucket));
    hash_field(&mut hasher, Some(&step.decision));
    hash_field(&mut hasher, step.parent_process.as_deref());
    hex_digest(hasher.finalize().as_slice())
}

fn hash_field(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(value.len().to_string().as_bytes());
            hasher.update(b":");
            hasher.update(value.as_bytes());
        }
        None => hasher.update(b"null"),
    }
    hasher.update(b"\0");
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn agentpod_native_receipt_summary(
    session: &RuntimeSession,
    events: &[AuditEvent],
) -> Option<AgentPodNativeReceiptSummary> {
    if !is_native_agentpod_provider(&session.provider) {
        return None;
    }

    let runner_phases: Vec<_> = events
        .iter()
        .filter(|event| event.bucket == "native-runner")
        .filter_map(agentpod_runner_phase_receipt_from_event)
        .collect();
    let mut enforced_phases: Vec<String> = runner_phases
        .iter()
        .filter(|phase| runner_phase_status_counts_as_enforced(&phase.status))
        .map(|phase| phase.phase.clone())
        .collect();
    enforced_phases.sort();
    enforced_phases.dedup();

    let mut skipped_planned_primitives = Vec::new();
    skipped_planned_primitives.extend(skipped_primitives_for_provider(&session.provider));
    for phase in &runner_phases {
        if runner_phase_status_counts_as_skipped(&phase.status) {
            skipped_planned_primitives.push(format!("{} phase {}", phase.phase, phase.status));
        }
    }
    skipped_planned_primitives.sort();
    skipped_planned_primitives.dedup();

    let evidence_refs = runner_phases
        .iter()
        .filter_map(|phase| phase.evidence_ref.clone())
        .collect();

    Some(AgentPodNativeReceiptSummary {
        schema_version: 1,
        provider: session.provider.clone(),
        enforcement_status: if runner_phases.is_empty() {
            AgentPodEnforcementStatus::DescriptorOnlyOrUnobserved
        } else {
            AgentPodEnforcementStatus::PrototypeNativeRunnerEvidence
        }
        .as_str()
        .to_string(),
        runner_phases,
        enforced_phases,
        skipped_planned_primitives,
        evidence_refs,
    })
}

fn agentpod_runner_phase_receipt_from_event(
    event: &AuditEvent,
) -> Option<AgentPodRunnerPhaseReceipt> {
    let mut command_parts = event.command.split_whitespace();
    let event_name = command_parts.next()?;
    if !event_name.starts_with("agentpod.") || !event_name.contains(".runner.") {
        return None;
    }
    let phase_from_command = command_parts.next()?;
    let (phase, status) = event.decision.rsplit_once(':')?;
    Some(AgentPodRunnerPhaseReceipt {
        phase: if phase.is_empty() {
            phase_from_command.to_string()
        } else {
            phase.to_string()
        },
        status: status.to_string(),
        event_name: event_name.to_string(),
        evidence_ref: event.event_hash.clone(),
    })
}

fn evidence_refs_for_events(events: &[AuditEvent]) -> Vec<String> {
    events
        .iter()
        .map(|event| {
            event
                .event_hash
                .clone()
                .unwrap_or_else(|| format!("audit-event:{}", event.id))
        })
        .collect()
}

fn evidence_integration_descriptors(
    evidence_refs: &[String],
) -> Vec<EvidenceIntegrationDescriptor> {
    vec![
        EvidenceIntegrationDescriptor::disabled(
            "fides",
            "signed-action-draft",
            "external-authority-required",
            evidence_refs,
            &[
                "FIDES authority is not configured by Agentbox",
                "descriptor contains evidence references only and no signature",
            ],
        ),
        EvidenceIntegrationDescriptor::disabled(
            "agit",
            "lineage-draft",
            "external-adapter-required",
            evidence_refs,
            &[
                "AGIT publisher is not configured by Agentbox",
                "descriptor does not claim a committed lineage record",
            ],
        ),
        EvidenceIntegrationDescriptor::disabled(
            "oaps",
            "interoperability-profile-draft",
            "descriptor-only",
            evidence_refs,
            &[
                "OAPS profile publication is not configured by Agentbox",
                "descriptor is not a conformance claim",
            ],
        ),
    ]
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
    #[serde(default)]
    pub environment: TranscriptEnvironment,
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
            command_argv: redact_command_argv(&command.argv),
            working_dir: command
                .working_dir
                .as_deref()
                .map(crate::audit::redact_sensitive_text),
            environment: TranscriptEnvironment::from_env(&command.env),
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
pub struct TranscriptEnvironment {
    pub variable_count: usize,
    pub names: Vec<String>,
    pub values: BTreeMap<String, String>,
    pub values_redacted: bool,
}

impl TranscriptEnvironment {
    pub fn from_env(env: &HashMap<String, String>) -> Self {
        let values = redact_command_env(env);
        let names = values.keys().cloned().collect::<Vec<_>>();

        Self {
            variable_count: values.len(),
            names,
            values,
            values_redacted: true,
        }
    }
}

impl Default for TranscriptEnvironment {
    fn default() -> Self {
        Self {
            variable_count: 0,
            names: Vec::new(),
            values: BTreeMap::new(),
            values_redacted: true,
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
    #[serde(default = "default_transcript_redaction_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_transcript_redaction_rules")]
    pub rules: Vec<String>,
}

impl Default for TranscriptRedaction {
    fn default() -> Self {
        Self {
            marker: "<redacted>".to_string(),
            values_redacted: true,
            max_stream_bytes: 16 * 1024,
            scopes: default_transcript_redaction_scopes(),
            rules: default_transcript_redaction_rules(),
        }
    }
}

fn default_transcript_redaction_scopes() -> Vec<String> {
    vec![
        "argv".to_string(),
        "environment".to_string(),
        "working_dir".to_string(),
        "stdout".to_string(),
        "stderr".to_string(),
    ]
}

fn default_transcript_redaction_rules() -> Vec<String> {
    vec![
        "sensitive environment keys".to_string(),
        "credential-like argv flags".to_string(),
        "Authorization bearer values".to_string(),
        "known token prefixes".to_string(),
        "JWT-like tokens".to_string(),
        "URL userinfo".to_string(),
        "sensitive credential paths".to_string(),
        "UTF-8 stream truncation".to_string(),
    ]
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
        assert!(coding
            .network
            .denied_domains
            .contains(&"169.254.170.2".into()));
        assert!(coding
            .network
            .denied_domains
            .contains(&"100.100.100.200".into()));
        assert!(coding
            .network
            .denied_domains
            .contains(&"fd00:ec2::254".into()));
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
            expires_at: None,
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
            expires_at: None,
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
        spec.credentials.grants.push(CredentialGrant {
            name: "OPENAI_API_KEY".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "OPENAI_API_KEY".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });
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
            AuditEvent::new(
                1,
                Some("openclaw".into()),
                format!("credential.revoke OPENAI_API_KEY {}", session.id),
                "/tmp/agentbox-work".into(),
                "credential".into(),
                "revoked:one_time_exec:EnvVar".into(),
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
        assert_eq!(bundle.credential_grants.len(), 1);
        assert_eq!(bundle.credential_grants[0].grant_name, "OPENAI_API_KEY");
        assert_eq!(bundle.credential_grants[0].target, "OPENAI_API_KEY");
        assert_eq!(bundle.credential_grants[0].status, "active");
        assert_eq!(bundle.credential_events.len(), 1);
        assert_eq!(bundle.boundary_events.len(), 0);
        assert_eq!(bundle.transcripts.len(), 1);
        assert_eq!(bundle.transcripts[0].stdout.text, "hello");
        assert_eq!(bundle.integration_descriptors.len(), 3);
        assert!(bundle
            .integration_descriptors
            .iter()
            .all(|descriptor| !descriptor.live_support && descriptor.requires_external_adapter));
        assert!(bundle
            .integration_descriptors
            .iter()
            .any(|descriptor| descriptor.integration == "fides"
                && descriptor.status == "external-authority-required"));
        assert!(bundle
            .integration_descriptors
            .iter()
            .any(|descriptor| descriptor.integration == "agit"
                && descriptor.status == "external-adapter-required"));
        assert!(bundle
            .integration_descriptors
            .iter()
            .any(|descriptor| descriptor.integration == "oaps"
                && descriptor.status == "descriptor-only"));
        assert_eq!(bundle.replay.session_id, session.id);
        assert_eq!(bundle.replay.steps.len(), 4);
        assert!(!bundle.replay.replayable);
        assert_eq!(bundle.replay.steps[0].sequence, 1);
        assert_eq!(bundle.replay.steps[1].policy_bucket, "approve");
        assert_eq!(bundle.hash_chain.event_count, 4);
        assert_eq!(bundle.hash_chain.events[0].sequence, 1);
        assert_eq!(
            bundle.hash_chain.events[1].bundle_previous_event_hash,
            Some(bundle.hash_chain.events[0].bundle_event_hash.clone())
        );
        assert!(bundle.verify_hash_chain().is_ok());
        assert_eq!(bundle.manifest.agent.name, "openclaw");
    }

    #[test]
    fn agentpod_receipt_summary_lists_phase_events_and_skipped_primitives() {
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = RuntimeSession::new(
            spec.name.clone(),
            "agentpod-linux".into(),
            "linux".into(),
            spec,
        );
        let mut namespace_event = AuditEvent::new(
            1,
            Some("openclaw".into()),
            format!(
                "agentpod.linux.runner.namespaces.entered enter-user-mount-pid-namespaces {}",
                session.id
            ),
            "/tmp/agentbox-work".into(),
            "native-runner".into(),
            "enter-user-mount-pid-namespaces:prototype".into(),
            None,
            Some("agentpod-linux".into()),
        );
        namespace_event.event_hash = Some("hash-namespace".into());
        let mut seccomp_event = AuditEvent::new(
            1,
            Some("openclaw".into()),
            format!(
                "agentpod.linux.runner.seccomp.applied apply-seccomp {}",
                session.id
            ),
            "/tmp/agentbox-work".into(),
            "native-runner".into(),
            "apply-seccomp:prototype".into(),
            None,
            Some("agentpod-linux".into()),
        );
        seccomp_event.event_hash = Some("hash-seccomp".into());

        let bundle =
            SessionEvidenceBundle::from_session_events(&session, &[namespace_event, seccomp_event]);
        let receipt = bundle
            .agentpod_receipt
            .expect("agentpod-linux bundles should include a native receipt");

        assert_eq!(receipt.schema_version, 1);
        assert_eq!(receipt.provider, "agentpod-linux");
        assert_eq!(
            receipt.enforcement_status,
            "prototype-native-runner-evidence"
        );
        assert_eq!(receipt.runner_phases.len(), 2);
        assert!(receipt
            .enforced_phases
            .contains(&"apply-seccomp".to_string()));
        assert!(receipt.evidence_refs.contains(&"hash-seccomp".to_string()));
        assert!(receipt
            .skipped_planned_primitives
            .contains(&"nftables packet/domain enforcement".to_string()));
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
    fn session_evidence_bundle_verification_rejects_tampered_replay_or_grouped_events() {
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = RuntimeSession::new(
            spec.name.clone(),
            "direct-host".into(),
            "macos".into(),
            spec,
        );
        let mut create_event = AuditEvent::new(
            1,
            Some("openclaw".into()),
            format!("runtime.create {}", session.id),
            "/tmp/agentbox-work".into(),
            "runtime".into(),
            "created".into(),
            None,
            Some("direct-host".into()),
        );
        create_event.event_hash = Some("hash-create".into());
        let mut exec_event = AuditEvent::new(
            1,
            Some("openclaw".into()),
            format!("runtime.exec {} echo ok", session.id),
            "/tmp/agentbox-work".into(),
            "runtime".into(),
            "exit_code:0".into(),
            None,
            Some("direct-host".into()),
        );
        exec_event.prev_hash = create_event.event_hash.clone();
        exec_event.event_hash = Some("hash-exec".into());
        let bundle =
            SessionEvidenceBundle::from_session_events(&session, &[create_event, exec_event]);

        assert!(bundle.verify_hash_chain().is_ok());

        let mut tampered_replay = bundle.clone();
        tampered_replay.replay.steps[1].decision = "exit_code:1".into();
        assert!(tampered_replay
            .verify_hash_chain()
            .unwrap_err()
            .contains("hash chain"));

        let mut tampered_grouped_event = bundle;
        tampered_grouped_event.lifecycle_events[0].command = "runtime.create other-session".into();
        assert!(tampered_grouped_event
            .verify_hash_chain()
            .unwrap_err()
            .contains("grouped"));
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
            env: HashMap::from([
                ("OPENAI_API_KEY".into(), "sk-env-secret".into()),
                (
                    "DATABASE_URL".into(),
                    "postgres://user:pass@db.example/app".into(),
                ),
                ("SAFE_FLAG".into(), "enabled".into()),
            ]),
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
        assert_eq!(transcript.environment.variable_count, 3);
        assert_eq!(
            transcript
                .environment
                .values
                .get("OPENAI_API_KEY")
                .map(String::as_str),
            Some("<redacted>")
        );
        assert_eq!(
            transcript
                .environment
                .values
                .get("DATABASE_URL")
                .map(String::as_str),
            Some("postgres://<redacted>@db.example/app")
        );
        assert_eq!(
            transcript
                .environment
                .values
                .get("SAFE_FLAG")
                .map(String::as_str),
            Some("enabled")
        );
        assert!(transcript
            .redaction
            .scopes
            .contains(&"environment".to_string()));
        assert!(json.contains("<redacted>"));
        assert!(!json.contains("sk-test-secret"));
        assert!(!json.contains("sk-env-secret"));
        assert!(!json.contains("/tmp/project/.env"));
    }

    #[test]
    fn command_transcript_reads_legacy_records_without_new_redaction_fields() {
        let legacy = serde_json::json!({
            "schema_version": 1,
            "transcript_id": "01legacytranscript",
            "session_id": "01agentboxsession",
            "command_argv": ["echo", "hello"],
            "working_dir": null,
            "exit_code": 0,
            "duration_ms": 1,
            "stdout": {
                "text": "hello",
                "original_bytes": 5,
                "original_lines": 1,
                "stored_bytes": 5,
                "truncated": false
            },
            "stderr": {
                "text": "",
                "original_bytes": 0,
                "original_lines": 0,
                "stored_bytes": 0,
                "truncated": false
            },
            "redaction": {
                "marker": "<redacted>",
                "values_redacted": true,
                "max_stream_bytes": 16384
            },
            "generated_at": "2026-05-30T00:00:00Z"
        });

        let transcript: CommandTranscript = serde_json::from_value(legacy).unwrap();

        assert_eq!(transcript.environment.variable_count, 0);
        assert!(transcript.environment.values.is_empty());
        assert!(transcript
            .redaction
            .scopes
            .contains(&"environment".to_string()));
        assert!(transcript
            .redaction
            .rules
            .contains(&"sensitive environment keys".to_string()));
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
                expires_at: None,
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
            expires_at: Some(Utc::now() + chrono::Duration::seconds(300)),
        };

        let mut record = SignedApprovalRecord::unsigned_from_grant(
            &grant,
            Some("01agentboxsession".into()),
            ApprovalReceiptDecision::Granted,
            "sha256:approval-evidence-root".into(),
            vec!["audit-event-1".into()],
        );

        assert_eq!(record.schema_version, 1);
        assert_eq!(record.grant_id, grant.id);
        assert_eq!(record.session_id.as_deref(), Some("01agentboxsession"));
        assert_eq!(record.scope, grant.scope);
        assert_eq!(record.expires_at, grant.expires_at);
        assert_eq!(record.decision, ApprovalReceiptDecision::Granted);
        assert_eq!(record.evidence_hash, "sha256:approval-evidence-root");
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
    fn signed_approval_record_fixture_contains_required_receipt_fields() {
        let record: SignedApprovalRecord =
            serde_json::from_str(include_str!("../../fixtures/signed-approval-receipt.json"))
                .unwrap();

        assert_eq!(record.schema_version, 1);
        assert_eq!(record.grant_id, "grant-git-push");
        assert_eq!(record.session_id.as_deref(), Some("01agentboxsession"));
        assert!(matches!(
            record.scope,
            ApprovalScope::Command {
                ref binary,
                ref args_prefix,
            } if binary == "git" && args_prefix == &vec!["push".to_string()]
        ));
        assert!(record.expires_at.is_some());
        assert_eq!(record.decision, ApprovalReceiptDecision::Granted);
        assert_eq!(record.evidence_hash, "sha256:approval-evidence-root");
        assert_eq!(record.evidence_refs, vec!["audit-event-1"]);
        let signature = record.signature.expect("fixture must carry signature");
        assert_eq!(signature.signer, "did:fides:agentbox-authority");
        assert_eq!(signature.algorithm, "ed25519");
        assert!(!signature.signature.is_empty());
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
