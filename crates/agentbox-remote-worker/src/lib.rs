use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use agentbox_daemon::runtime::providers::remote::{
    Ed25519HandshakeVerifier, RemoteAgentPodApprovalDenyRequest,
    RemoteAgentPodApprovalDenyResponse, RemoteAgentPodApprovalGrantRequest,
    RemoteAgentPodApprovalGrantResponse, RemoteAgentPodApprovalPrompt,
    RemoteAgentPodCreateSessionRequest, RemoteAgentPodCreateSessionResponse,
    RemoteAgentPodCredentialStatus, RemoteAgentPodDestroySessionRequest,
    RemoteAgentPodDestroySessionResponse, RemoteAgentPodEventStreamDescriptor,
    RemoteAgentPodEvidenceStreamChunkRequest, RemoteAgentPodEvidenceStreamChunkResponse,
    RemoteAgentPodEvidenceStreamStatus, RemoteAgentPodEvidenceUploadRequest,
    RemoteAgentPodEvidenceUploadResponse, RemoteAgentPodExecRequest, RemoteAgentPodExecResponse,
    RemoteAgentPodHandshakeAck, RemoteAgentPodHandshakeDescriptor, RemoteAgentPodLifecycleEvent,
    RemoteAgentPodLifecycleEventRecord, RemoteAgentPodLifecycleEventsResponse,
    RemoteAgentPodPendingApprovalStatus, RemoteAgentPodRestartPolicy,
    RemoteAgentPodRestartSessionRequest, RemoteAgentPodRestartSessionResponse,
    RemoteAgentPodWorkspaceBundle, RemoteAgentPodWorkspaceExportResponse,
    RemoteAgentPodWorkspaceFile,
};
use agentbox_daemon::runtime::types::{
    ApprovalGrant, ApprovalScope, CommandResult, CredentialGrant, CredentialGrantKind,
    FileAccessMode, MountKind, MountMode, NetworkMode, RuntimeCapability, RuntimeStatus,
};
use agentbox_policy::classify::{self, Bucket, CommandContext, PolicyConfig, PolicyNetworkMode};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio::sync::{watch, Mutex};
use tokio::time;

#[derive(Clone)]
pub struct RemoteWorkerConfig {
    pub worker_identity: String,
    pub evidence_endpoint: String,
    pub signing_key: SigningKey,
    pub state_dir: Option<PathBuf>,
}

impl RemoteWorkerConfig {
    pub fn new(
        worker_identity: impl Into<String>,
        evidence_endpoint: impl Into<String>,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            worker_identity: worker_identity.into(),
            evidence_endpoint: evidence_endpoint.into(),
            signing_key,
            state_dir: None,
        }
    }

    pub fn with_state_dir(mut self, state_dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(state_dir.into());
        self
    }

    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.signing_key.verifying_key().to_bytes())
    }
}

struct RemoteWorkerState {
    config: RemoteWorkerConfig,
    supervision: WorkerSupervisionState,
    sessions: Mutex<HashMap<String, WorkerSession>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerSupervisionState {
    schema_version: i64,
    boot_id: String,
    boot_count: u64,
    previous_boot_id: Option<String>,
    started_at: DateTime<Utc>,
    recovered_sessions: usize,
    state_dir: Option<PathBuf>,
    persistence: WorkerSupervisionPersistence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum WorkerSupervisionPersistence {
    MemoryOnly,
    StateDir,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerSupervisionSnapshot {
    schema_version: i64,
    boot_id: String,
    boot_count: u64,
    started_at: DateTime<Utc>,
}

#[derive(Clone)]
struct WorkerSession {
    session_id: String,
    workspace_host_path: PathBuf,
    policy: WorkerPolicy,
    env_credentials: Vec<WorkerEnvCredentialGrant>,
    file_credentials: Vec<WorkerFileCredentialGrant>,
    approval_grants: Vec<ApprovalGrant>,
    status: RuntimeStatus,
    kill_tx: watch::Sender<bool>,
    commands_started: u64,
    commands_finished: u64,
    active_command_count: u64,
    last_command_exit_code: Option<i32>,
    last_command_finished_at: Option<DateTime<Utc>>,
    restart_policy: RemoteAgentPodRestartPolicy,
    restart_attempts: u64,
    heartbeat_interval_seconds: u64,
    last_heartbeat_at: DateTime<Utc>,
    evidence_receipts: Vec<WorkerEvidenceReceipt>,
    stored_evidence_bundles: Vec<WorkerStoredEvidenceBundle>,
    evidence_streams: HashMap<String, WorkerEvidenceStream>,
    pending_approvals: Vec<WorkerPendingApproval>,
    lifecycle_events: Vec<RemoteAgentPodLifecycleEventRecord>,
}

#[derive(Clone)]
struct WorkerLifecycleConfig {
    restart_policy: RemoteAgentPodRestartPolicy,
    heartbeat_interval_seconds: u64,
}

impl WorkerLifecycleConfig {
    fn from_request(request: &RemoteAgentPodCreateSessionRequest) -> Self {
        Self {
            restart_policy: request.transport.lifecycle.restart_policy.clone(),
            heartbeat_interval_seconds: request.transport.lifecycle.heartbeat_interval_seconds,
        }
    }
}

impl Default for WorkerLifecycleConfig {
    fn default() -> Self {
        Self {
            restart_policy: RemoteAgentPodRestartPolicy::default(),
            heartbeat_interval_seconds: default_worker_heartbeat_interval_seconds(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkerEnvCredentialGrant {
    name: String,
    one_time: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkerFileCredentialGrant {
    name: String,
    guest_path: String,
    host_path: PathBuf,
    sha256: String,
    bytes: usize,
    one_time: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerPolicy {
    workspace_guest_path: String,
    allowed_domains: Vec<String>,
    denied_domains: Vec<String>,
    allow_localhost: bool,
    network_mode: WorkerPolicyNetworkMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum WorkerPolicyNetworkMode {
    None,
    DenyByDefault,
    AllowListed,
    ApprovalOnFirstContact,
    OpenWithGuardrails,
    Host,
}

#[derive(Clone)]
struct WorkerEvidenceReceipt {
    bundle_sha256: String,
    derived_from_bundle: bool,
    bundle_id: Option<String>,
    bundle_root_sha256: Option<String>,
    event_count: u64,
    sealed_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
struct WorkerStoredEvidenceBundle {
    bundle_sha256: String,
    stored_bytes: u64,
    storage_path: PathBuf,
}

#[derive(Clone)]
struct WorkerEvidenceStream {
    stream_id: String,
    next_sequence: u64,
    next_offset: u64,
    received_bytes: u64,
    chunks: u64,
    sealed: bool,
    stream_sha256: Option<String>,
    updated_at: Option<DateTime<Utc>>,
    contents_utf8: String,
}

#[derive(Clone)]
struct WorkerPendingApproval {
    request_id: String,
    command_argv: Vec<String>,
    reason: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerSessionSnapshot {
    session_id: String,
    worker_session_id: String,
    #[serde(default = "default_worker_workspace")]
    workspace_host_path: PathBuf,
    #[serde(default)]
    policy: WorkerPolicy,
    #[serde(default)]
    env_credentials: Vec<WorkerEnvCredentialGrant>,
    #[serde(default)]
    file_credentials: Vec<WorkerFileCredentialGrantSnapshot>,
    #[serde(default)]
    approval_grants: Vec<ApprovalGrant>,
    status: RuntimeStatus,
    #[serde(default)]
    commands_started: u64,
    #[serde(default)]
    commands_finished: u64,
    #[serde(default)]
    active_command_count: u64,
    #[serde(default)]
    last_command_exit_code: Option<i32>,
    #[serde(default)]
    last_command_finished_at: Option<DateTime<Utc>>,
    #[serde(default)]
    restart_policy: RemoteAgentPodRestartPolicy,
    #[serde(default)]
    restart_attempts: u64,
    #[serde(default = "default_worker_heartbeat_interval_seconds")]
    heartbeat_interval_seconds: u64,
    #[serde(default)]
    last_heartbeat_at: Option<DateTime<Utc>>,
    evidence_receipts: Vec<WorkerEvidenceReceiptSnapshot>,
    #[serde(default)]
    stored_evidence_bundles: Vec<WorkerStoredEvidenceBundleSnapshot>,
    #[serde(default)]
    evidence_streams: Vec<WorkerEvidenceStreamSnapshot>,
    #[serde(default)]
    pending_approvals: Vec<WorkerPendingApprovalSnapshot>,
    #[serde(default)]
    lifecycle_events: Vec<RemoteAgentPodLifecycleEventRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerEvidenceReceiptSnapshot {
    bundle_sha256: String,
    #[serde(default)]
    derived_from_bundle: bool,
    #[serde(default)]
    bundle_id: Option<String>,
    #[serde(default)]
    bundle_root_sha256: Option<String>,
    event_count: u64,
    #[serde(default)]
    sealed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerStoredEvidenceBundleSnapshot {
    bundle_sha256: String,
    stored_bytes: u64,
    storage_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerEvidenceStreamSnapshot {
    stream_id: String,
    next_sequence: u64,
    next_offset: u64,
    received_bytes: u64,
    chunks: u64,
    sealed: bool,
    #[serde(default)]
    stream_sha256: Option<String>,
    #[serde(default)]
    updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    contents_utf8: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerPendingApprovalSnapshot {
    request_id: String,
    command_argv: Vec<String>,
    reason: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerFileCredentialGrantSnapshot {
    name: String,
    guest_path: String,
    host_path: PathBuf,
    sha256: String,
    bytes: usize,
    one_time: bool,
}

#[derive(Debug, Clone, Serialize)]
struct WorkerError {
    error: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkerEvidenceBundleUploadRequest {
    session_id: String,
    worker_session_id: String,
    bundle_sha256: String,
    bundle_json: String,
    secret_material_included: bool,
}

#[derive(Debug, Clone, Serialize)]
struct WorkerEvidenceBundleUploadResponse {
    session_id: String,
    worker_session_id: String,
    stored_bundle_sha256: String,
    stored_bytes: u64,
    storage_path: String,
    lifecycle_events: Vec<RemoteAgentPodLifecycleEvent>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkerEvidenceBundleEnvelope {
    schema_version: i64,
    kind: String,
    session_id: String,
    worker_session_id: String,
    index: WorkerEvidenceBundleIndex,
    files: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkerEvidenceBundleIndex {
    schema_version: i64,
    session_id: String,
    root_sha256: String,
    files: Vec<WorkerEvidenceBundleFile>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkerEvidenceBundleFile {
    path: String,
    media_type: String,
    sha256: String,
    bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkerEvidenceStatusQuery {
    session_id: String,
    after_sequence: Option<u64>,
    limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct WorkerEvidenceStatusResponse {
    session_id: String,
    worker_session_id: String,
    event_stream: RemoteAgentPodEventStreamDescriptor,
    status: RuntimeStatus,
    commands_started: u64,
    commands_finished: u64,
    active_command_count: u64,
    last_command_exit_code: Option<i32>,
    last_command_finished_at: Option<DateTime<Utc>>,
    restart_policy: RemoteAgentPodRestartPolicy,
    heartbeat_interval_seconds: u64,
    last_heartbeat_at: Option<DateTime<Utc>>,
    kill_switch_armed: bool,
    evidence_sealed: bool,
    evidence_receipts: Vec<WorkerEvidenceReceiptSnapshot>,
    stored_evidence_bundles: Vec<WorkerStoredEvidenceBundleSnapshot>,
    evidence_streams: Vec<RemoteAgentPodEvidenceStreamStatus>,
    pending_approvals: Vec<RemoteAgentPodPendingApprovalStatus>,
    credentials: Vec<RemoteAgentPodCredentialStatus>,
    supervision: WorkerSupervisionStatus,
}

#[derive(Debug, Clone, Serialize)]
struct WorkerSupervisionStatus {
    boot_id: String,
    boot_count: u64,
    previous_boot_id: Option<String>,
    started_at: DateTime<Utc>,
    recovered_sessions: usize,
    persistence: WorkerSupervisionPersistence,
}

type WorkerRouteResult<T> = Result<Json<T>, (StatusCode, Json<WorkerError>)>;

fn worker_error(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<WorkerError>) {
    (
        status,
        Json(WorkerError {
            error: message.into(),
        }),
    )
}

impl Default for WorkerPolicy {
    fn default() -> Self {
        Self {
            workspace_guest_path: "/workspace".into(),
            allowed_domains: Vec::new(),
            denied_domains: Vec::new(),
            allow_localhost: false,
            network_mode: WorkerPolicyNetworkMode::DenyByDefault,
        }
    }
}

impl WorkerPolicy {
    fn from_spec(spec: &agentbox_daemon::runtime::types::MinipodSpec) -> Self {
        Self {
            workspace_guest_path: spec.filesystem.workspace_guest_path.clone(),
            allowed_domains: spec.network.allowed_domains.clone(),
            denied_domains: spec.network.denied_domains.clone(),
            allow_localhost: spec.network.allow_localhost,
            network_mode: WorkerPolicyNetworkMode::from_network_mode(&spec.network.mode),
        }
    }

    fn to_policy_config(&self, workspace_host_path: &Path) -> PolicyConfig {
        PolicyConfig {
            workspace: Some(workspace_host_path.display().to_string()),
            allowed_domains: self.allowed_domains.clone(),
            denied_domains: self.denied_domains.clone(),
            allow_localhost: self.allow_localhost,
            network_mode: self.network_mode.to_policy_network_mode(),
            always_allow: Vec::new(),
            always_block: Vec::new(),
        }
    }
}

impl WorkerPolicyNetworkMode {
    fn from_network_mode(mode: &NetworkMode) -> Self {
        match mode {
            NetworkMode::None => Self::None,
            NetworkMode::DenyByDefault => Self::DenyByDefault,
            NetworkMode::AllowListed => Self::AllowListed,
            NetworkMode::ApprovalOnFirstContact => Self::ApprovalOnFirstContact,
            NetworkMode::OpenWithGuardrails => Self::OpenWithGuardrails,
            NetworkMode::Host => Self::Host,
        }
    }

    fn to_policy_network_mode(self) -> PolicyNetworkMode {
        match self {
            Self::None => PolicyNetworkMode::None,
            Self::DenyByDefault => PolicyNetworkMode::DenyByDefault,
            Self::AllowListed => PolicyNetworkMode::AllowListed,
            Self::ApprovalOnFirstContact => PolicyNetworkMode::ApprovalOnFirstContact,
            Self::OpenWithGuardrails => PolicyNetworkMode::OpenWithGuardrails,
            Self::Host => PolicyNetworkMode::Host,
        }
    }
}

impl WorkerSession {
    #[cfg(test)]
    fn new(session_id: String, workspace_host_path: PathBuf, policy: WorkerPolicy) -> Self {
        Self::new_with_env_credentials(
            session_id,
            workspace_host_path,
            policy,
            Vec::new(),
            Vec::new(),
        )
    }

    #[cfg(test)]
    fn new_with_env_credentials(
        session_id: String,
        workspace_host_path: PathBuf,
        policy: WorkerPolicy,
        env_credentials: Vec<WorkerEnvCredentialGrant>,
        approval_grants: Vec<ApprovalGrant>,
    ) -> Self {
        Self::new_with_credentials(
            session_id,
            workspace_host_path,
            policy,
            env_credentials,
            Vec::new(),
            approval_grants,
            WorkerLifecycleConfig::default(),
        )
    }

    fn new_with_credentials(
        session_id: String,
        workspace_host_path: PathBuf,
        policy: WorkerPolicy,
        env_credentials: Vec<WorkerEnvCredentialGrant>,
        file_credentials: Vec<WorkerFileCredentialGrant>,
        approval_grants: Vec<ApprovalGrant>,
        lifecycle: WorkerLifecycleConfig,
    ) -> Self {
        let (kill_tx, _kill_rx) = watch::channel(false);
        Self {
            session_id,
            workspace_host_path,
            policy,
            env_credentials,
            file_credentials,
            approval_grants,
            status: RuntimeStatus::Running,
            kill_tx,
            commands_started: 0,
            commands_finished: 0,
            active_command_count: 0,
            last_command_exit_code: None,
            last_command_finished_at: None,
            restart_policy: lifecycle.restart_policy,
            restart_attempts: 0,
            heartbeat_interval_seconds: lifecycle.heartbeat_interval_seconds,
            last_heartbeat_at: Utc::now(),
            evidence_receipts: Vec::new(),
            stored_evidence_bundles: Vec::new(),
            evidence_streams: HashMap::new(),
            pending_approvals: Vec::new(),
            lifecycle_events: Vec::new(),
        }
    }

    fn kill_receiver(&self) -> watch::Receiver<bool> {
        self.kill_tx.subscribe()
    }

    fn mark_stopped(&mut self) {
        self.status = RuntimeStatus::Stopped;
        let _ = self.kill_tx.send(true);
    }

    fn mark_restarted(&mut self) -> u64 {
        let (kill_tx, _kill_rx) = watch::channel(false);
        self.kill_tx = kill_tx;
        self.status = RuntimeStatus::Running;
        self.active_command_count = 0;
        self.restart_attempts = self.restart_attempts.saturating_add(1);
        self.restart_attempts
    }

    fn from_snapshot(snapshot: WorkerSessionSnapshot) -> Self {
        let (kill_tx, _kill_rx) = watch::channel(matches!(snapshot.status, RuntimeStatus::Stopped));
        Self {
            session_id: snapshot.session_id,
            workspace_host_path: snapshot.workspace_host_path,
            policy: snapshot.policy,
            env_credentials: snapshot.env_credentials,
            file_credentials: snapshot
                .file_credentials
                .into_iter()
                .map(|credential| WorkerFileCredentialGrant {
                    name: credential.name,
                    guest_path: credential.guest_path,
                    host_path: credential.host_path,
                    sha256: credential.sha256,
                    bytes: credential.bytes,
                    one_time: credential.one_time,
                })
                .collect(),
            approval_grants: snapshot.approval_grants,
            status: snapshot.status,
            kill_tx,
            commands_started: snapshot.commands_started,
            commands_finished: snapshot.commands_finished,
            active_command_count: 0,
            last_command_exit_code: snapshot.last_command_exit_code,
            last_command_finished_at: snapshot.last_command_finished_at,
            restart_policy: snapshot.restart_policy,
            restart_attempts: snapshot.restart_attempts,
            heartbeat_interval_seconds: snapshot.heartbeat_interval_seconds,
            last_heartbeat_at: snapshot.last_heartbeat_at.unwrap_or_else(Utc::now),
            evidence_receipts: snapshot
                .evidence_receipts
                .into_iter()
                .map(|receipt| WorkerEvidenceReceipt {
                    bundle_sha256: receipt.bundle_sha256,
                    derived_from_bundle: receipt.derived_from_bundle,
                    bundle_id: receipt.bundle_id,
                    bundle_root_sha256: receipt.bundle_root_sha256,
                    event_count: receipt.event_count,
                    sealed_at: receipt.sealed_at,
                })
                .collect(),
            stored_evidence_bundles: snapshot
                .stored_evidence_bundles
                .into_iter()
                .map(|bundle| WorkerStoredEvidenceBundle {
                    bundle_sha256: bundle.bundle_sha256,
                    stored_bytes: bundle.stored_bytes,
                    storage_path: bundle.storage_path,
                })
                .collect(),
            evidence_streams: snapshot
                .evidence_streams
                .into_iter()
                .map(|stream| {
                    (
                        stream.stream_id.clone(),
                        WorkerEvidenceStream {
                            stream_id: stream.stream_id,
                            next_sequence: stream.next_sequence,
                            next_offset: stream.next_offset,
                            received_bytes: stream.received_bytes,
                            chunks: stream.chunks,
                            sealed: stream.sealed,
                            stream_sha256: stream.stream_sha256,
                            updated_at: stream.updated_at,
                            contents_utf8: stream.contents_utf8,
                        },
                    )
                })
                .collect(),
            pending_approvals: snapshot
                .pending_approvals
                .into_iter()
                .map(|approval| WorkerPendingApproval {
                    request_id: approval.request_id,
                    command_argv: approval.command_argv,
                    reason: approval.reason,
                    created_at: approval.created_at,
                })
                .collect(),
            lifecycle_events: snapshot.lifecycle_events,
        }
    }

    fn record_lifecycle_event(
        &mut self,
        event: RemoteAgentPodLifecycleEvent,
        reason: Option<String>,
    ) {
        let sequence = self
            .lifecycle_events
            .last()
            .map(|event| event.sequence.saturating_add(1))
            .unwrap_or(1);
        self.lifecycle_events
            .push(RemoteAgentPodLifecycleEventRecord {
                sequence,
                event,
                occurred_at: Utc::now(),
                reason,
            });
    }

    fn to_snapshot(&self, worker_session_id: String) -> WorkerSessionSnapshot {
        WorkerSessionSnapshot {
            session_id: self.session_id.clone(),
            worker_session_id,
            workspace_host_path: self.workspace_host_path.clone(),
            policy: self.policy.clone(),
            env_credentials: self.env_credentials.clone(),
            file_credentials: self
                .file_credentials
                .iter()
                .map(|credential| WorkerFileCredentialGrantSnapshot {
                    name: credential.name.clone(),
                    guest_path: credential.guest_path.clone(),
                    host_path: credential.host_path.clone(),
                    sha256: credential.sha256.clone(),
                    bytes: credential.bytes,
                    one_time: credential.one_time,
                })
                .collect(),
            approval_grants: self.approval_grants.clone(),
            status: self.status.clone(),
            commands_started: self.commands_started,
            commands_finished: self.commands_finished,
            active_command_count: self.active_command_count,
            last_command_exit_code: self.last_command_exit_code,
            last_command_finished_at: self.last_command_finished_at,
            restart_policy: self.restart_policy.clone(),
            restart_attempts: self.restart_attempts,
            heartbeat_interval_seconds: self.heartbeat_interval_seconds,
            last_heartbeat_at: Some(self.last_heartbeat_at),
            evidence_receipts: self
                .evidence_receipts
                .iter()
                .map(|receipt| WorkerEvidenceReceiptSnapshot {
                    bundle_sha256: receipt.bundle_sha256.clone(),
                    derived_from_bundle: receipt.derived_from_bundle,
                    bundle_id: receipt.bundle_id.clone(),
                    bundle_root_sha256: receipt.bundle_root_sha256.clone(),
                    event_count: receipt.event_count,
                    sealed_at: receipt.sealed_at,
                })
                .collect(),
            stored_evidence_bundles: self
                .stored_evidence_bundles
                .iter()
                .map(|bundle| WorkerStoredEvidenceBundleSnapshot {
                    bundle_sha256: bundle.bundle_sha256.clone(),
                    stored_bytes: bundle.stored_bytes,
                    storage_path: bundle.storage_path.clone(),
                })
                .collect(),
            evidence_streams: self
                .evidence_streams
                .values()
                .map(|stream| WorkerEvidenceStreamSnapshot {
                    stream_id: stream.stream_id.clone(),
                    next_sequence: stream.next_sequence,
                    next_offset: stream.next_offset,
                    received_bytes: stream.received_bytes,
                    chunks: stream.chunks,
                    sealed: stream.sealed,
                    stream_sha256: stream.stream_sha256.clone(),
                    updated_at: stream.updated_at,
                    contents_utf8: stream.contents_utf8.clone(),
                })
                .collect(),
            pending_approvals: self
                .pending_approvals
                .iter()
                .map(|approval| WorkerPendingApprovalSnapshot {
                    request_id: approval.request_id.clone(),
                    command_argv: approval.command_argv.clone(),
                    reason: approval.reason.clone(),
                    created_at: approval.created_at,
                })
                .collect(),
            lifecycle_events: self.lifecycle_events.clone(),
        }
    }
}

fn default_worker_workspace() -> PathBuf {
    PathBuf::from(".")
}

fn default_worker_heartbeat_interval_seconds() -> u64 {
    30
}

impl WorkerSupervisionState {
    fn memory_only(recovered_sessions: usize) -> Self {
        let started_at = Utc::now();
        Self {
            schema_version: 1,
            boot_id: worker_boot_id(started_at),
            boot_count: 1,
            previous_boot_id: None,
            started_at,
            recovered_sessions,
            state_dir: None,
            persistence: WorkerSupervisionPersistence::MemoryOnly,
        }
    }

    fn status(&self) -> WorkerSupervisionStatus {
        WorkerSupervisionStatus {
            boot_id: self.boot_id.clone(),
            boot_count: self.boot_count,
            previous_boot_id: self.previous_boot_id.clone(),
            started_at: self.started_at,
            recovered_sessions: self.recovered_sessions,
            persistence: self.persistence.clone(),
        }
    }

    fn snapshot(&self) -> WorkerSupervisionSnapshot {
        WorkerSupervisionSnapshot {
            schema_version: self.schema_version,
            boot_id: self.boot_id.clone(),
            boot_count: self.boot_count,
            started_at: self.started_at,
        }
    }
}

fn worker_boot_id(started_at: DateTime<Utc>) -> String {
    format!(
        "worker-{}-{}",
        std::process::id(),
        started_at.timestamp_nanos_opt().unwrap_or_default()
    )
}

fn load_or_initialize_supervision(
    config: &RemoteWorkerConfig,
    recovered_sessions: usize,
) -> Result<WorkerSupervisionState, String> {
    let Some(path) = worker_supervision_path(config) else {
        return Ok(WorkerSupervisionState::memory_only(recovered_sessions));
    };
    let previous = if path.exists() {
        let contents = std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read remote worker supervision state: {err}"))?;
        if contents.trim().is_empty() {
            None
        } else {
            Some(
                serde_json::from_str::<WorkerSupervisionSnapshot>(&contents).map_err(|err| {
                    format!("failed to parse remote worker supervision state: {err}")
                })?,
            )
        }
    } else {
        None
    };
    let started_at = Utc::now();
    let state = WorkerSupervisionState {
        schema_version: 1,
        boot_id: worker_boot_id(started_at),
        boot_count: previous
            .as_ref()
            .map(|snapshot| snapshot.boot_count.saturating_add(1))
            .unwrap_or(1),
        previous_boot_id: previous.map(|snapshot| snapshot.boot_id),
        started_at,
        recovered_sessions,
        state_dir: config.state_dir.clone(),
        persistence: WorkerSupervisionPersistence::StateDir,
    };
    persist_supervision_snapshot(&path, &state.snapshot())?;
    Ok(state)
}

pub fn router(config: RemoteWorkerConfig) -> Router {
    let sessions = load_persisted_sessions(&config).unwrap_or_default();
    let supervision = load_or_initialize_supervision(&config, sessions.len())
        .unwrap_or_else(|_| WorkerSupervisionState::memory_only(sessions.len()));
    Router::new()
        .route("/worker/status", get(worker_status))
        .route("/handshake", post(handshake))
        .route("/sessions", post(create_session))
        .route("/sessions/{worker_session_id}/exec", post(exec_command))
        .route(
            "/sessions/{worker_session_id}/evidence",
            post(upload_evidence),
        )
        .route(
            "/sessions/{worker_session_id}/evidence/status",
            get(evidence_status),
        )
        .route(
            "/sessions/{worker_session_id}/events",
            get(lifecycle_events),
        )
        .route(
            "/sessions/{worker_session_id}/evidence/bundle",
            post(upload_evidence_bundle),
        )
        .route(
            "/sessions/{worker_session_id}/evidence/stream",
            post(upload_evidence_stream_chunk),
        )
        .route(
            "/sessions/{worker_session_id}/approvals/grant",
            post(grant_approval),
        )
        .route(
            "/sessions/{worker_session_id}/approvals/deny",
            post(deny_approval),
        )
        .route(
            "/sessions/{worker_session_id}/workspace/export",
            get(export_workspace),
        )
        .route(
            "/sessions/{worker_session_id}/restart",
            post(restart_session),
        )
        .route(
            "/sessions/{worker_session_id}/destroy",
            post(destroy_session),
        )
        .with_state(Arc::new(RemoteWorkerState {
            config,
            supervision,
            sessions: Mutex::new(sessions),
        }))
}

pub async fn serve(addr: SocketAddr, config: RemoteWorkerConfig) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(config)).await
}

async fn worker_status(
    State(state): State<Arc<RemoteWorkerState>>,
) -> Json<WorkerSupervisionStatus> {
    Json(state.supervision.status())
}

async fn handshake(
    State(state): State<Arc<RemoteWorkerState>>,
    Json(descriptor): Json<RemoteAgentPodHandshakeDescriptor>,
) -> Json<RemoteAgentPodHandshakeAck> {
    let mut ack = RemoteAgentPodHandshakeAck {
        worker_identity: state.config.worker_identity.clone(),
        worker_public_key: format!("ed25519:{}", state.config.public_key_hex()),
        signed_challenge: String::new(),
        capabilities: vec![
            RuntimeCapability::ApprovalBridge,
            RuntimeCapability::EvidenceExport,
            RuntimeCapability::NetworkPolicy,
        ],
        evidence_endpoint: state.config.evidence_endpoint.clone(),
        lifecycle_ack: true,
        secret_material_included: false,
        expires_at: descriptor.created_at + Duration::seconds(60),
    };
    if ack.expires_at > descriptor.expires_at {
        ack.expires_at = descriptor.expires_at;
    }
    let payload = Ed25519HandshakeVerifier::signing_payload(&descriptor, &ack);
    let signature = state.config.signing_key.sign(payload.as_bytes());
    ack.signed_challenge = format!(
        "ed25519:{}:{}",
        descriptor.challenge_id,
        hex_encode(&signature.to_bytes())
    );
    Json(ack)
}

async fn create_session(
    State(state): State<Arc<RemoteWorkerState>>,
    Json(request): Json<RemoteAgentPodCreateSessionRequest>,
) -> WorkerRouteResult<RemoteAgentPodCreateSessionResponse> {
    validate_create_material(&request)?;
    let worker_session_id = format!("worker-{}", request.spec.id);
    reject_duplicate_worker_session(&state, &worker_session_id).await?;
    let workspace_host_path = request.spec.filesystem.workspace_host_path.clone();
    prepare_worker_workspace(&workspace_host_path).await?;
    if let Some(bundle) = request.workspace_bundle.as_ref() {
        materialize_worker_workspace_bundle(&workspace_host_path, bundle).await?;
    }
    let file_credentials =
        materialize_worker_credential_files(&workspace_host_path, &request).await?;
    let mut session = WorkerSession::new_with_credentials(
        request.spec.id.clone(),
        workspace_host_path,
        WorkerPolicy::from_spec(&request.spec),
        worker_env_credentials(&request.spec.credentials.grants),
        file_credentials,
        worker_approval_grants(&request.spec.id, &request.spec.approvals),
        WorkerLifecycleConfig::from_request(&request),
    );
    session.record_lifecycle_event(
        RemoteAgentPodLifecycleEvent::WorkerAllocated,
        Some("remote worker allocated session".into()),
    );
    session.record_lifecycle_event(
        RemoteAgentPodLifecycleEvent::SessionCreated,
        Some("remote worker created session".into()),
    );
    state
        .sessions
        .lock()
        .await
        .insert(worker_session_id.clone(), session);
    persist_sessions(&state).await.map_err(worker_state_error)?;
    Ok(Json(RemoteAgentPodCreateSessionResponse {
        session_id: request.spec.id.clone(),
        worker_session_id,
        status: RuntimeStatus::Running,
        lifecycle_events: vec![
            RemoteAgentPodLifecycleEvent::WorkerAllocated,
            RemoteAgentPodLifecycleEvent::SessionCreated,
        ],
    }))
}

async fn reject_duplicate_worker_session(
    state: &Arc<RemoteWorkerState>,
    worker_session_id: &str,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    if state.sessions.lock().await.contains_key(worker_session_id) {
        return Err(worker_error(
            StatusCode::CONFLICT,
            format!("agentbox remote worker session {worker_session_id} already exists"),
        ));
    }
    Ok(())
}

fn validate_create_material(
    request: &RemoteAgentPodCreateSessionRequest,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    request
        .transport
        .validate()
        .map_err(|err| worker_error(StatusCode::BAD_REQUEST, err.to_string()))?;
    if request.spec.credentials.inherit_host_env || !request.spec.credentials.grants.is_empty() {
        if !request.spec.credentials.inherit_host_env
            && request.spec.credentials.grants.iter().all(|grant| {
                matches!(
                    grant.kind,
                    CredentialGrantKind::EnvVar | CredentialGrantKind::FileMount
                )
            })
        {
            return Ok(());
        }
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker only accepts explicit environment and file credential grants; socket, provider-token, and host env inheritance are refused",
        ));
    }
    Ok(())
}

fn worker_env_credentials(grants: &[CredentialGrant]) -> Vec<WorkerEnvCredentialGrant> {
    grants
        .iter()
        .filter(|grant| matches!(grant.kind, CredentialGrantKind::EnvVar))
        .map(|grant| WorkerEnvCredentialGrant {
            name: grant.name.clone(),
            one_time: grant.one_time,
        })
        .collect()
}

async fn materialize_worker_credential_files(
    workspace_host_path: &Path,
    request: &RemoteAgentPodCreateSessionRequest,
) -> Result<Vec<WorkerFileCredentialGrant>, (StatusCode, Json<WorkerError>)> {
    let mut credentials = Vec::new();
    for grant in request
        .spec
        .credentials
        .grants
        .iter()
        .filter(|grant| matches!(grant.kind, CredentialGrantKind::FileMount))
    {
        let payload = request
            .credential_files
            .iter()
            .find(|file| file.name == grant.name)
            .ok_or_else(|| {
                worker_error(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "agentbox remote worker file credential grant `{}` requires a matching payload",
                        grant.name
                    ),
                )
            })?;
        payload.validate().map_err(|err| {
            worker_error(
                StatusCode::BAD_REQUEST,
                format!("agentbox remote worker rejected credential file payload: {err}"),
            )
        })?;
        if grant
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return Err(worker_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "agentbox remote worker file credential grant `{}` is expired",
                    grant.name
                ),
            ));
        }
        let mount = request
            .spec
            .filesystem
            .mounts
            .iter()
            .find(|mount| {
                matches!(mount.kind, MountKind::Credential)
                    && matches!(mount.mode, MountMode::ReadOnly)
                    && mount.host_path.display().to_string() == grant.target
                    && mount.guest_path == payload.guest_path
            })
            .ok_or_else(|| {
                worker_error(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "agentbox remote worker file credential grant `{}` requires a matching read-only credential mount",
                        grant.name
                    ),
                )
            })?;
        let host_path = worker_guest_path_to_workspace_path(
            workspace_host_path,
            &request.spec.filesystem.workspace_guest_path,
            &mount.guest_path,
        )?;
        if let Some(parent) = host_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|err| {
                worker_error(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "agentbox remote worker failed to prepare credential directory {}: {err}",
                        parent.display()
                    ),
                )
            })?;
        }
        tokio::fs::write(&host_path, payload.contents_utf8.as_bytes())
            .await
            .map_err(|err| {
                worker_error(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "agentbox remote worker failed to materialize credential file {}: {err}",
                        host_path.display()
                    ),
                )
            })?;
        credentials.push(WorkerFileCredentialGrant {
            name: grant.name.clone(),
            guest_path: mount.guest_path.clone(),
            host_path,
            sha256: payload.sha256.clone(),
            bytes: payload.bytes,
            one_time: grant.one_time,
        });
    }
    if request.credential_files.len() != credentials.len() {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker received credential file payload without matching grant",
        ));
    }
    Ok(credentials)
}

fn worker_guest_path_to_workspace_path(
    workspace_host_path: &Path,
    workspace_guest_path: &str,
    guest_path: &str,
) -> Result<PathBuf, (StatusCode, Json<WorkerError>)> {
    let workspace_guest_path = workspace_guest_path.trim_end_matches('/');
    if workspace_guest_path.is_empty()
        || (guest_path != workspace_guest_path
            && !guest_path.starts_with(&format!("{workspace_guest_path}/")))
    {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker only materializes file credentials under the workspace guest path",
        ));
    }
    let relative = guest_path
        .trim_start_matches(workspace_guest_path)
        .trim_start_matches('/');
    if relative.is_empty()
        || Path::new(relative).components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker credential guest path is unsafe",
        ));
    }
    Ok(workspace_host_path.join(relative))
}

fn worker_approval_grants(session_id: &str, grants: &[ApprovalGrant]) -> Vec<ApprovalGrant> {
    grants
        .iter()
        .cloned()
        .map(|grant| grant.bound_to_session(session_id))
        .collect()
}

async fn prepare_worker_workspace(
    workspace_host_path: &Path,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    tokio::fs::create_dir_all(workspace_host_path)
        .await
        .map_err(|err| {
            worker_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "agentbox remote worker failed to prepare workspace {}: {err}",
                    workspace_host_path.display()
                ),
            )
        })?;
    let metadata = tokio::fs::metadata(workspace_host_path)
        .await
        .map_err(|err| {
            worker_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "agentbox remote worker failed to inspect workspace {}: {err}",
                    workspace_host_path.display()
                ),
            )
        })?;
    if !metadata.is_dir() {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            format!(
                "agentbox remote worker workspace is not a directory: {}",
                workspace_host_path.display()
            ),
        ));
    }
    Ok(())
}

async fn materialize_worker_workspace_bundle(
    workspace_host_path: &Path,
    bundle: &RemoteAgentPodWorkspaceBundle,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    bundle.validate().map_err(|err| {
        worker_error(
            StatusCode::BAD_REQUEST,
            format!("agentbox remote worker rejected workspace bundle: {err}"),
        )
    })?;
    for file in &bundle.files {
        let relative = safe_worker_bundle_path(&file.path)?;
        let path = workspace_host_path.join(relative);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|err| {
                worker_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "agentbox remote worker failed to prepare workspace bundle directory {}: {err}",
                        parent.display()
                    ),
                )
            })?;
        }
        tokio::fs::write(&path, file.contents_utf8.as_bytes())
            .await
            .map_err(|err| {
                worker_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "agentbox remote worker failed to materialize workspace bundle file {}: {err}",
                        path.display()
                    ),
                )
            })?;
    }
    Ok(())
}

fn safe_worker_bundle_path(path: &str) -> Result<PathBuf, (StatusCode, Json<WorkerError>)> {
    let candidate = PathBuf::from(path);
    if candidate.as_os_str().is_empty()
        || candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker workspace bundle file path is unsafe",
        ));
    }
    Ok(candidate)
}

async fn exec_command(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(route_worker_session_id): AxumPath<String>,
    Json(request): Json<RemoteAgentPodExecRequest>,
) -> WorkerRouteResult<RemoteAgentPodExecResponse> {
    require_route_worker_session_id(&route_worker_session_id, &request.worker_session_id)?;
    let started = Instant::now();
    let context = session_exec_context(&state, &request).await?;
    validate_exec_material(&request, &context)?;
    record_command_started(&state, &request.worker_session_id, &request.session_id).await?;
    let worker_session_id = request.worker_session_id.clone();
    let session_id = request.session_id.clone();
    let result = execute_command(state.clone(), request, started, context).await;
    record_command_finished(&state, &worker_session_id, &session_id, &result).await?;
    Ok(Json(RemoteAgentPodExecResponse {
        result,
        lifecycle_events: vec![
            RemoteAgentPodLifecycleEvent::CommandStarted,
            RemoteAgentPodLifecycleEvent::CommandFinished,
            RemoteAgentPodLifecycleEvent::EvidenceSealed,
        ],
    }))
}

fn validate_exec_material(
    request: &RemoteAgentPodExecRequest,
    context: &WorkerExecContext,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    let allowed_env_names = context
        .env_credentials
        .iter()
        .map(|grant| grant.name.as_str())
        .collect::<std::collections::HashSet<_>>();
    if request
        .command
        .env
        .keys()
        .any(|key| !allowed_env_names.contains(key.as_str()))
    {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker refuses command environment material without a matching session credential grant",
        ));
    }
    Ok(())
}

fn file_credential_env_name(name: &str) -> String {
    let suffix = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("AGENTBOX_CREDENTIAL_FILE_{suffix}")
}

fn require_route_worker_session_id(
    route_worker_session_id: &str,
    body_worker_session_id: &str,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    if route_worker_session_id != body_worker_session_id {
        return Err(worker_error(
            StatusCode::CONFLICT,
            "agentbox remote worker route worker session id does not match request body",
        ));
    }
    Ok(())
}

async fn record_command_started(
    state: &Arc<RemoteWorkerState>,
    worker_session_id: &str,
    session_id: &str,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    {
        let mut sessions = state.sessions.lock().await;
        let session = get_matching_session_mut(&mut sessions, worker_session_id, session_id)?;
        session.commands_started = session.commands_started.saturating_add(1);
        session.active_command_count = session.active_command_count.saturating_add(1);
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::CommandStarted,
            Some("remote worker started command".into()),
        );
    }
    persist_sessions(state).await.map_err(worker_state_error)
}

async fn record_command_finished(
    state: &Arc<RemoteWorkerState>,
    worker_session_id: &str,
    session_id: &str,
    result: &CommandResult,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    let mut consumed_file_credentials = Vec::new();
    {
        let mut sessions = state.sessions.lock().await;
        let session = get_matching_session_mut(&mut sessions, worker_session_id, session_id)?;
        session.commands_finished = session.commands_finished.saturating_add(1);
        session.active_command_count = session.active_command_count.saturating_sub(1);
        session.last_command_exit_code = Some(result.exit_code);
        session.last_command_finished_at = Some(Utc::now());
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::CommandFinished,
            Some(format!("remote worker command exited {}", result.exit_code)),
        );
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::EvidenceSealed,
            Some("remote worker sealed command evidence".into()),
        );
        let mut retained = Vec::with_capacity(session.file_credentials.len());
        for credential in session.file_credentials.drain(..) {
            if credential.one_time {
                consumed_file_credentials.push(credential.host_path);
            } else {
                retained.push(credential);
            }
        }
        session.file_credentials = retained;
    }
    persist_sessions(state).await.map_err(worker_state_error)?;
    remove_consumed_file_credentials(consumed_file_credentials)
        .await
        .map_err(worker_state_error)
}

async fn remove_consumed_file_credentials(paths: Vec<PathBuf>) -> Result<(), String> {
    for path in paths {
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "failed to remove consumed file credential {}: {err}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

async fn record_pending_approval(
    state: &Arc<RemoteWorkerState>,
    worker_session_id: &str,
    session_id: &str,
    command_argv: &[String],
    reason: &str,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    {
        let mut sessions = state.sessions.lock().await;
        let session = get_matching_session_mut(&mut sessions, worker_session_id, session_id)?;
        let request_id = pending_approval_id(worker_session_id, command_argv, reason);
        if !session
            .pending_approvals
            .iter()
            .any(|approval| approval.request_id == request_id)
        {
            session.pending_approvals.push(WorkerPendingApproval {
                request_id,
                command_argv: command_argv.to_vec(),
                reason: reason.to_string(),
                created_at: Utc::now(),
            });
            session.record_lifecycle_event(
                RemoteAgentPodLifecycleEvent::EvidenceSealed,
                Some("remote worker recorded pending approval evidence".into()),
            );
        }
    }
    persist_sessions(state).await.map_err(worker_state_error)
}

fn pending_approval_id(worker_session_id: &str, command_argv: &[String], reason: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(worker_session_id.as_bytes());
    hasher.update(b"\0");
    for arg in command_argv {
        hasher.update(arg.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(reason.as_bytes());
    let digest = hex_encode(&hasher.finalize());
    format!("approval-{}", &digest[..16])
}

struct WorkerExecContext {
    kill_rx: watch::Receiver<bool>,
    session_id: String,
    workspace_host_path: PathBuf,
    policy: WorkerPolicy,
    env_credentials: Vec<WorkerEnvCredentialGrant>,
    file_credentials: Vec<WorkerFileCredentialGrant>,
    approval_grants: Vec<ApprovalGrant>,
}

async fn session_exec_context(
    state: &Arc<RemoteWorkerState>,
    request: &RemoteAgentPodExecRequest,
) -> Result<WorkerExecContext, (StatusCode, Json<WorkerError>)> {
    let mut sessions = state.sessions.lock().await;
    let Some(session) = sessions.get_mut(&request.worker_session_id) else {
        return Err(worker_error(
            StatusCode::NOT_FOUND,
            format!(
                "agentbox remote worker session {} has not been created",
                request.worker_session_id
            ),
        ));
    };
    if session.session_id != request.session_id {
        return Err(worker_error(
            StatusCode::CONFLICT,
            "agentbox remote worker session id does not match worker session",
        ));
    }
    if !matches!(session.status, RuntimeStatus::Running) {
        return Err(worker_error(
            StatusCode::CONFLICT,
            format!(
                "agentbox remote worker session {} is not running",
                request.worker_session_id
            ),
        ));
    }
    Ok(WorkerExecContext {
        kill_rx: session.kill_receiver(),
        session_id: session.session_id.clone(),
        workspace_host_path: session.workspace_host_path.clone(),
        policy: session.policy.clone(),
        env_credentials: session.env_credentials.clone(),
        file_credentials: session.file_credentials.clone(),
        approval_grants: session.approval_grants.clone(),
    })
}

async fn execute_command(
    state: Arc<RemoteWorkerState>,
    request: RemoteAgentPodExecRequest,
    started: Instant,
    mut context: WorkerExecContext,
) -> CommandResult {
    let Some(program) = request.command.argv.first() else {
        return CommandResult {
            exit_code: 127,
            stdout: String::new(),
            stderr: "agentbox remote worker received an empty argv".to_string(),
            duration_ms: elapsed_ms(started),
        };
    };
    let mut command = Command::new(program);
    command.args(request.command.argv.iter().skip(1));
    command.env_clear();
    for credential in &context.file_credentials {
        command.env(
            file_credential_env_name(&credential.name),
            credential.host_path.display().to_string(),
        );
    }
    command.envs(&request.command.env);
    let working_dir = request
        .command
        .working_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| context.workspace_host_path.clone());
    let working_dir = resolve_worker_path(&context.workspace_host_path, &working_dir);
    if !path_is_within(&working_dir, &context.workspace_host_path) {
        return CommandResult {
            exit_code: 126,
            stdout: String::new(),
            stderr: format!(
                "agentbox remote worker refused working directory outside workspace: {}",
                working_dir.display()
            ),
            duration_ms: elapsed_ms(started),
        };
    }
    if let Some(result) =
        enforce_worker_policy(&state, &request, &context, &working_dir, started).await
    {
        return result;
    }
    command.current_dir(&working_dir);
    command.kill_on_drop(true);

    if *context.kill_rx.borrow() {
        return CommandResult {
            exit_code: 130,
            stdout: String::new(),
            stderr: "agentbox remote worker command killed before start".to_string(),
            duration_ms: elapsed_ms(started),
        };
    }

    let timeout_seconds = request.command.timeout_seconds;
    let timeout_sleep = time::sleep(std::time::Duration::from_secs(
        timeout_seconds.unwrap_or(365 * 24 * 60 * 60),
    ));
    tokio::pin!(timeout_sleep);
    let output_future = command.output();
    tokio::pin!(output_future);

    let output = tokio::select! {
        output = &mut output_future => output,
        killed = wait_for_kill(&mut context.kill_rx) => {
            if killed {
                return CommandResult {
                    exit_code: 130,
                    stdout: String::new(),
                    stderr: "agentbox remote worker command killed by session destroy".to_string(),
                    duration_ms: elapsed_ms(started),
                };
            }
            output_future.await
        }
        _ = &mut timeout_sleep, if timeout_seconds.is_some() => {
            return CommandResult {
                exit_code: 124,
                stdout: String::new(),
                stderr: format!(
                    "agentbox remote worker command timed out after {}s",
                    timeout_seconds.unwrap_or_default()
                ),
                duration_ms: elapsed_ms(started),
            };
        }
    };

    match output {
        Ok(output) => CommandResult {
            exit_code: output.status.code().unwrap_or(128),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration_ms: elapsed_ms(started),
        },
        Err(err) => CommandResult {
            exit_code: 127,
            stdout: String::new(),
            stderr: format!("agentbox remote worker failed to start command: {err}"),
            duration_ms: elapsed_ms(started),
        },
    }
}

async fn enforce_worker_policy(
    state: &Arc<RemoteWorkerState>,
    request: &RemoteAgentPodExecRequest,
    context: &WorkerExecContext,
    working_dir: &Path,
    started: Instant,
) -> Option<CommandResult> {
    let program = request.command.argv.first()?;
    let ctx = CommandContext {
        binary: program.clone(),
        args: request.command.argv.iter().skip(1).cloned().collect(),
        cwd: working_dir.display().to_string(),
        parent_process: Some("agentbox-remote-worker".into()),
        pid: std::process::id(),
    };
    let classification = classify::classify(
        &ctx,
        &context
            .policy
            .to_policy_config(&context.workspace_host_path),
    );
    if matches!(classification.bucket, Bucket::Allow) {
        return None;
    }
    if matches!(classification.bucket, Bucket::Approve) {
        if context
            .approval_grants
            .iter()
            .any(|grant| worker_approval_grant_matches(grant, request, context, working_dir))
        {
            return None;
        }
        if let Err(err) = record_pending_approval(
            state,
            &request.worker_session_id,
            &request.session_id,
            &request.command.argv,
            &classification.reason,
        )
        .await
        {
            return Some(CommandResult {
                exit_code: 126,
                stdout: String::new(),
                stderr: err.1 .0.error,
                duration_ms: elapsed_ms(started),
            });
        }
    }

    Some(CommandResult {
        exit_code: 126,
        stdout: String::new(),
        stderr: format!(
            "agentbox remote worker policy denied command before execution: {:?}: {}",
            classification.bucket, classification.reason
        ),
        duration_ms: elapsed_ms(started),
    })
}

fn worker_approval_grant_matches(
    grant: &ApprovalGrant,
    request: &RemoteAgentPodExecRequest,
    context: &WorkerExecContext,
    working_dir: &Path,
) -> bool {
    if grant.is_expired_at(Utc::now()) {
        return false;
    }
    let binary = request.command.argv.first().cloned().unwrap_or_default();
    let args = request
        .command
        .argv
        .iter()
        .skip(1)
        .cloned()
        .collect::<Vec<_>>();
    match &grant.scope {
        ApprovalScope::Once => false,
        ApprovalScope::Command {
            binary: grant_binary,
            args_prefix,
        } => binary == *grant_binary && args.starts_with(args_prefix),
        ApprovalScope::Domain { domain } => args
            .iter()
            .filter_map(|arg| worker_extract_domain(arg))
            .any(|candidate| worker_domain_matches(domain, &candidate)),
        ApprovalScope::Session { session_id } => session_id == &context.session_id,
        ApprovalScope::Path { path, access } => worker_command_paths(&args, working_dir)
            .iter()
            .any(|candidate| {
                worker_path_matches(path, candidate)
                    && worker_access_allows(access, &worker_path_access(&binary))
            }),
    }
}

fn worker_command_paths(args: &[String], working_dir: &Path) -> Vec<PathBuf> {
    args.iter()
        .filter(|arg| !arg.starts_with('-') && !arg.contains("://"))
        .map(|arg| {
            let path = PathBuf::from(arg);
            if path.is_absolute() {
                normalize_path(path)
            } else {
                normalize_path(working_dir.join(path))
            }
        })
        .collect()
}

fn worker_path_matches(grant_path: &Path, candidate: &Path) -> bool {
    normalize_path(candidate.to_path_buf()).starts_with(normalize_path(grant_path.to_path_buf()))
}

fn worker_path_access(binary: &str) -> FileAccessMode {
    match binary {
        "cat" | "less" | "more" | "head" | "tail" | "grep" | "rg" => FileAccessMode::Read,
        "rm" | "touch" | "mkdir" | "rmdir" | "mv" | "cp" | "chmod" | "chown" | "nano" | "vim"
        | "vi" | "code" => FileAccessMode::Write,
        _ => FileAccessMode::ReadWrite,
    }
}

fn worker_access_allows(grant: &FileAccessMode, requested: &FileAccessMode) -> bool {
    matches!(grant, FileAccessMode::ReadWrite) || grant == requested
}

fn worker_extract_domain(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .rsplit('@')
        .next()
        .unwrap_or("");
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split_once(']')?.0
    } else {
        authority.split(':').next().unwrap_or("")
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn worker_domain_matches(grant_domain: &str, candidate: &str) -> bool {
    let grant_domain = grant_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let candidate = candidate.trim().trim_end_matches('.').to_ascii_lowercase();
    candidate == grant_domain || candidate.ends_with(&format!(".{grant_domain}"))
}

async fn wait_for_kill(kill_rx: &mut watch::Receiver<bool>) -> bool {
    while kill_rx.changed().await.is_ok() {
        if *kill_rx.borrow() {
            return true;
        }
    }
    false
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn resolve_worker_path(workspace: &Path, requested: &Path) -> PathBuf {
    let path = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        workspace.join(requested)
    };
    normalize_path(path)
}

fn path_is_within(path: &Path, workspace: &Path) -> bool {
    let path = normalize_path(path.to_path_buf());
    let workspace = normalize_path(workspace.to_path_buf());
    path == workspace || path.starts_with(workspace)
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

async fn upload_evidence(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(route_worker_session_id): AxumPath<String>,
    Json(request): Json<RemoteAgentPodEvidenceUploadRequest>,
) -> WorkerRouteResult<RemoteAgentPodEvidenceUploadResponse> {
    require_route_worker_session_id(&route_worker_session_id, &request.worker_session_id)?;
    let accepted = accept_evidence(&state, &request).await?;
    Ok(Json(RemoteAgentPodEvidenceUploadResponse {
        session_id: request.session_id,
        worker_session_id: request.worker_session_id,
        accepted_bundle_sha256: accepted.bundle_sha256,
        accepted_event_count: accepted.event_count,
        lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
    }))
}

async fn upload_evidence_bundle(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(route_worker_session_id): AxumPath<String>,
    Json(request): Json<WorkerEvidenceBundleUploadRequest>,
) -> WorkerRouteResult<WorkerEvidenceBundleUploadResponse> {
    require_route_worker_session_id(&route_worker_session_id, &request.worker_session_id)?;
    validate_evidence_bundle_upload(&request)?;
    require_matching_session(&state, &request.worker_session_id, &request.session_id).await?;
    let path = persist_evidence_bundle(&state.config, &request).await?;
    record_stored_evidence_bundle(&state, &request, &path).await?;
    Ok(Json(WorkerEvidenceBundleUploadResponse {
        session_id: request.session_id,
        worker_session_id: request.worker_session_id,
        stored_bundle_sha256: request.bundle_sha256,
        stored_bytes: path.stored_bytes,
        storage_path: path.path.display().to_string(),
        lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
    }))
}

async fn upload_evidence_stream_chunk(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(route_worker_session_id): AxumPath<String>,
    Json(request): Json<RemoteAgentPodEvidenceStreamChunkRequest>,
) -> WorkerRouteResult<RemoteAgentPodEvidenceStreamChunkResponse> {
    require_route_worker_session_id(&route_worker_session_id, &request.worker_session_id)?;
    request
        .validate()
        .map_err(|err| worker_error(StatusCode::BAD_REQUEST, err.to_string()))?;
    let stream_sha256 = accept_evidence_stream_chunk(&state, &request).await?;
    Ok(Json(RemoteAgentPodEvidenceStreamChunkResponse {
        session_id: request.session_id,
        worker_session_id: request.worker_session_id,
        stream_id: request.stream_id,
        accepted_sequence: request.sequence,
        accepted_offset: request.offset,
        accepted_bytes: request.chunk_bytes,
        stream_sha256,
        lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
    }))
}

async fn grant_approval(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(route_worker_session_id): AxumPath<String>,
    Json(request): Json<RemoteAgentPodApprovalGrantRequest>,
) -> WorkerRouteResult<RemoteAgentPodApprovalGrantResponse> {
    require_route_worker_session_id(&route_worker_session_id, &request.worker_session_id)?;
    request
        .validate()
        .map_err(|err| worker_error(StatusCode::BAD_REQUEST, err.to_string()))?;
    let remaining_pending_approvals = accept_approval_grant(&state, &request).await?;
    Ok(Json(RemoteAgentPodApprovalGrantResponse {
        session_id: request.session_id,
        worker_session_id: request.worker_session_id,
        request_id: request.request_id,
        accepted_grant_id: request.grant.id,
        remaining_pending_approvals,
        lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
    }))
}

async fn deny_approval(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(route_worker_session_id): AxumPath<String>,
    Json(request): Json<RemoteAgentPodApprovalDenyRequest>,
) -> WorkerRouteResult<RemoteAgentPodApprovalDenyResponse> {
    require_route_worker_session_id(&route_worker_session_id, &request.worker_session_id)?;
    request
        .validate()
        .map_err(|err| worker_error(StatusCode::BAD_REQUEST, err.to_string()))?;
    let remaining_pending_approvals = deny_pending_approval(&state, &request).await?;
    Ok(Json(RemoteAgentPodApprovalDenyResponse {
        session_id: request.session_id,
        worker_session_id: request.worker_session_id,
        request_id: request.request_id,
        denied: true,
        remaining_pending_approvals,
        lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
    }))
}

async fn evidence_status(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(worker_session_id): AxumPath<String>,
    Query(query): Query<WorkerEvidenceStatusQuery>,
) -> WorkerRouteResult<WorkerEvidenceStatusResponse> {
    let sessions = state.sessions.lock().await;
    let Some(session) = sessions.get(&worker_session_id) else {
        return Err(worker_error(
            StatusCode::NOT_FOUND,
            format!("agentbox remote worker session {worker_session_id} has not been created"),
        ));
    };
    if session.session_id != query.session_id {
        return Err(worker_error(
            StatusCode::CONFLICT,
            "agentbox remote worker session id does not match worker session",
        ));
    }
    Ok(Json(WorkerEvidenceStatusResponse {
        session_id: session.session_id.clone(),
        worker_session_id: worker_session_id.clone(),
        event_stream: worker_event_stream_descriptor(&session.session_id, &worker_session_id),
        status: session.status.clone(),
        commands_started: session.commands_started,
        commands_finished: session.commands_finished,
        active_command_count: session.active_command_count,
        last_command_exit_code: session.last_command_exit_code,
        last_command_finished_at: session.last_command_finished_at,
        restart_policy: session.restart_policy.clone(),
        heartbeat_interval_seconds: session.heartbeat_interval_seconds,
        last_heartbeat_at: Some(session.last_heartbeat_at),
        kill_switch_armed: matches!(session.status, RuntimeStatus::Running),
        evidence_sealed: session
            .evidence_streams
            .values()
            .any(|stream| stream.sealed)
            || !session.evidence_receipts.is_empty()
            || !session.stored_evidence_bundles.is_empty(),
        evidence_receipts: session
            .evidence_receipts
            .iter()
            .map(|receipt| WorkerEvidenceReceiptSnapshot {
                bundle_sha256: receipt.bundle_sha256.clone(),
                derived_from_bundle: receipt.derived_from_bundle,
                bundle_id: receipt.bundle_id.clone(),
                bundle_root_sha256: receipt.bundle_root_sha256.clone(),
                event_count: receipt.event_count,
                sealed_at: receipt.sealed_at,
            })
            .collect(),
        stored_evidence_bundles: session
            .stored_evidence_bundles
            .iter()
            .map(|bundle| WorkerStoredEvidenceBundleSnapshot {
                bundle_sha256: bundle.bundle_sha256.clone(),
                stored_bytes: bundle.stored_bytes,
                storage_path: bundle.storage_path.clone(),
            })
            .collect(),
        evidence_streams: session
            .evidence_streams
            .values()
            .map(worker_evidence_stream_status)
            .collect(),
        pending_approvals: session
            .pending_approvals
            .iter()
            .map(|approval| {
                worker_pending_approval_status(&session.session_id, &worker_session_id, approval)
            })
            .collect(),
        credentials: worker_credential_status(session),
        supervision: state.supervision.status(),
    }))
}

async fn lifecycle_events(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(worker_session_id): AxumPath<String>,
    Query(query): Query<WorkerEvidenceStatusQuery>,
) -> WorkerRouteResult<RemoteAgentPodLifecycleEventsResponse> {
    let sessions = state.sessions.lock().await;
    let Some(session) = sessions.get(&worker_session_id) else {
        return Err(worker_error(
            StatusCode::NOT_FOUND,
            format!("agentbox remote worker session {worker_session_id} has not been created"),
        ));
    };
    if session.session_id != query.session_id {
        return Err(worker_error(
            StatusCode::CONFLICT,
            "agentbox remote worker session id does not match worker session",
        ));
    }
    if query
        .limit
        .is_some_and(|limit| limit == 0 || limit > 10_000)
    {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker lifecycle event limit must be between 1 and 10000",
        ));
    }
    let after_sequence = query.after_sequence.unwrap_or(0);
    let limit = query.limit.unwrap_or(u64::MAX);
    let matching_events: Vec<_> = session
        .lifecycle_events
        .iter()
        .filter(|event| event.sequence > after_sequence)
        .cloned()
        .collect();
    let has_more = matching_events.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    let events: Vec<_> = matching_events
        .into_iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .collect();
    let next_sequence = events
        .last()
        .map(|event| event.sequence.saturating_add(1))
        .or_else(|| {
            session
                .lifecycle_events
                .last()
                .map(|event| event.sequence.saturating_add(1))
        })
        .unwrap_or(after_sequence.saturating_add(1));
    Ok(Json(RemoteAgentPodLifecycleEventsResponse {
        session_id: session.session_id.clone(),
        event_stream: worker_event_stream_descriptor(&session.session_id, &worker_session_id),
        worker_session_id,
        next_sequence,
        returned_count: events.len().try_into().unwrap_or(u64::MAX),
        has_more,
        events,
    }))
}

async fn export_workspace(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(worker_session_id): AxumPath<String>,
    Query(query): Query<WorkerEvidenceStatusQuery>,
) -> WorkerRouteResult<RemoteAgentPodWorkspaceExportResponse> {
    let sessions = state.sessions.lock().await;
    let Some(session) = sessions.get(&worker_session_id) else {
        return Err(worker_error(
            StatusCode::NOT_FOUND,
            format!("agentbox remote worker session {worker_session_id} has not been created"),
        ));
    };
    if session.session_id != query.session_id {
        return Err(worker_error(
            StatusCode::CONFLICT,
            "agentbox remote worker session id does not match worker session",
        ));
    }
    let bundle = build_worker_workspace_bundle(&session.workspace_host_path).await?;
    Ok(Json(RemoteAgentPodWorkspaceExportResponse {
        session_id: session.session_id.clone(),
        worker_session_id,
        status: session.status.clone(),
        workspace_bundle: bundle,
        lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
    }))
}

async fn restart_session(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(route_worker_session_id): AxumPath<String>,
    Json(request): Json<RemoteAgentPodRestartSessionRequest>,
) -> WorkerRouteResult<RemoteAgentPodRestartSessionResponse> {
    require_route_worker_session_id(&route_worker_session_id, &request.worker_session_id)?;
    request
        .validate()
        .map_err(|err| worker_error(StatusCode::BAD_REQUEST, err.to_string()))?;
    let restart_attempt = {
        let mut sessions = state.sessions.lock().await;
        let Some(session) = sessions.get_mut(&request.worker_session_id) else {
            return Err(worker_error(
                StatusCode::NOT_FOUND,
                format!(
                    "agentbox remote worker session {} has not been created",
                    request.worker_session_id
                ),
            ));
        };
        if session.session_id != request.session_id {
            return Err(worker_error(
                StatusCode::CONFLICT,
                "agentbox remote worker session id does not match worker session",
            ));
        }
        if matches!(session.status, RuntimeStatus::Running) {
            return Err(worker_error(
                StatusCode::CONFLICT,
                "agentbox remote worker can restart only stopped or failed sessions",
            ));
        }
        let restart_attempt = session.mark_restarted();
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::WorkerRestarted,
            Some(request.reason.clone()),
        );
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::SessionResumed,
            Some("remote worker resumed session".into()),
        );
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::EvidenceSealed,
            Some("remote worker sealed restart evidence".into()),
        );
        restart_attempt
    };
    persist_sessions(&state).await.map_err(worker_state_error)?;
    Ok(Json(RemoteAgentPodRestartSessionResponse {
        session_id: request.session_id,
        worker_session_id: request.worker_session_id,
        status: RuntimeStatus::Running,
        restart_attempt,
        lifecycle_events: vec![
            RemoteAgentPodLifecycleEvent::WorkerRestarted,
            RemoteAgentPodLifecycleEvent::SessionResumed,
            RemoteAgentPodLifecycleEvent::EvidenceSealed,
        ],
    }))
}

struct StoredEvidenceBundlePath {
    path: PathBuf,
    stored_bytes: u64,
}

fn validate_evidence_bundle_upload(
    request: &WorkerEvidenceBundleUploadRequest,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    if request.secret_material_included {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker refuses evidence bundle payloads that include secret material",
        ));
    }
    if !is_sha256_hex(&request.bundle_sha256) {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker evidence bundle hash must be 64 lowercase hex characters",
        ));
    }
    let computed = sha256_hex(request.bundle_json.as_bytes());
    if computed != request.bundle_sha256 {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker evidence bundle hash does not match payload",
        ));
    }
    validate_evidence_bundle_envelope(request)?;
    Ok(())
}

fn validate_evidence_bundle_envelope(
    request: &WorkerEvidenceBundleUploadRequest,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    let envelope: WorkerEvidenceBundleEnvelope = serde_json::from_str(&request.bundle_json)
        .map_err(|err| {
            worker_error(
                StatusCode::BAD_REQUEST,
                format!("agentbox remote worker evidence bundle payload is not valid JSON: {err}"),
            )
        })?;
    if envelope.schema_version != 1 || envelope.kind != "AgentboxEvidenceBundleUpload" {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker evidence bundle payload must be an AgentboxEvidenceBundleUpload v1 envelope",
        ));
    }
    if envelope.session_id != request.session_id
        || envelope.worker_session_id != request.worker_session_id
        || envelope.index.session_id != request.session_id
    {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker evidence bundle envelope session ids do not match request",
        ));
    }
    if envelope.index.schema_version != 1 {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker evidence bundle index schema version is unsupported",
        ));
    }
    if envelope.index.files.is_empty() {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker evidence bundle envelope must include indexed files",
        ));
    }
    let computed_root = evidence_bundle_root_sha256(&envelope.index.files)?;
    if envelope.index.root_sha256 != computed_root {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker evidence bundle root hash does not match index",
        ));
    }
    for file in &envelope.index.files {
        validate_bundle_file_path(&file.path)?;
        if !is_sha256_hex(&file.sha256) {
            return Err(worker_error(
                StatusCode::BAD_REQUEST,
                "agentbox remote worker evidence bundle file hash must be 64 lowercase hex characters",
            ));
        }
        let Some(contents) = envelope.files.get(&file.path) else {
            return Err(worker_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "agentbox remote worker evidence bundle payload is missing indexed file {}",
                    file.path
                ),
            ));
        };
        let bytes = contents.as_bytes();
        if bytes.len() != file.bytes || sha256_hex(bytes) != file.sha256 {
            return Err(worker_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "agentbox remote worker evidence bundle file {} does not match indexed bytes or hash",
                    file.path
                ),
            ));
        }
    }
    Ok(())
}

fn evidence_bundle_root_sha256(
    files: &[WorkerEvidenceBundleFile],
) -> Result<String, (StatusCode, Json<WorkerError>)> {
    let mut entries = Vec::with_capacity(files.len());
    for file in files {
        validate_bundle_file_path(&file.path)?;
        if file.media_type.trim().is_empty() {
            return Err(worker_error(
                StatusCode::BAD_REQUEST,
                "agentbox remote worker evidence bundle file media type cannot be empty",
            ));
        }
        entries.push(format!(
            "{}\0{}\0{}\0{}",
            file.path, file.sha256, file.bytes, file.media_type
        ));
    }
    entries.sort();
    Ok(sha256_hex(
        format!("agentbox-evidence-root-v1\n{}", entries.join("\n")).as_bytes(),
    ))
}

async fn build_worker_workspace_bundle(
    workspace_host_path: &Path,
) -> Result<RemoteAgentPodWorkspaceBundle, (StatusCode, Json<WorkerError>)> {
    let workspace = tokio::fs::canonicalize(workspace_host_path)
        .await
        .map_err(|err| {
            worker_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "agentbox remote worker failed to resolve workspace {}: {err}",
                    workspace_host_path.display()
                ),
            )
        })?;
    let mut files = Vec::new();
    collect_worker_workspace_files(&workspace, &workspace, &mut files)?;
    let root_sha256 = worker_workspace_root_sha256(&files)?;
    let bundle = RemoteAgentPodWorkspaceBundle {
        schema_version: 1,
        root_sha256,
        files,
        secret_material_included: false,
    };
    bundle.validate().map_err(|err| {
        worker_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("agentbox remote worker built invalid workspace bundle: {err}"),
        )
    })?;
    Ok(bundle)
}

fn collect_worker_workspace_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<RemoteAgentPodWorkspaceFile>,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    let mut entries = std::fs::read_dir(current)
        .map_err(|err| {
            worker_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "agentbox remote worker failed to read workspace directory {}: {err}",
                    current.display()
                ),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            worker_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("agentbox remote worker failed to read workspace entry: {err}"),
            )
        })?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|err| {
            worker_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("agentbox remote worker failed to derive relative path: {err}"),
            )
        })?;
        if should_skip_worker_workspace_path(relative) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|err| {
            worker_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "agentbox remote worker failed to inspect workspace file {}: {err}",
                    path.display()
                ),
            )
        })?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_worker_workspace_files(root, &path, files)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|err| {
            worker_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "agentbox remote worker failed to read workspace file {}: {err}",
                    path.display()
                ),
            )
        })?;
        let Ok(contents_utf8) = String::from_utf8(bytes) else {
            continue;
        };
        let relative = safe_worker_workspace_relative_path(relative)?;
        files.push(RemoteAgentPodWorkspaceFile {
            path: relative,
            media_type: "text/plain; charset=utf-8".into(),
            sha256: sha256_hex(contents_utf8.as_bytes()),
            bytes: contents_utf8.len(),
            contents_utf8,
        });
    }
    Ok(())
}

fn worker_workspace_root_sha256(
    files: &[RemoteAgentPodWorkspaceFile],
) -> Result<String, (StatusCode, Json<WorkerError>)> {
    let mut entries = Vec::with_capacity(files.len());
    for file in files {
        entries.push(format!(
            "{}\0{}\0{}\0{}",
            file.path, file.sha256, file.bytes, file.media_type
        ));
    }
    entries.sort();
    Ok(sha256_hex(
        format!("agentbox-workspace-root-v1\n{}", entries.join("\n")).as_bytes(),
    ))
}

fn safe_worker_workspace_relative_path(
    relative: &Path,
) -> Result<String, (StatusCode, Json<WorkerError>)> {
    let parts = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => Ok(value.to_string_lossy().to_string()),
            _ => Err(worker_error(
                StatusCode::BAD_REQUEST,
                "agentbox remote worker workspace export path is unsafe",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parts.is_empty() {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker workspace export path is empty",
        ));
    }
    Ok(parts.join("/"))
}

fn should_skip_worker_workspace_path(relative: &Path) -> bool {
    relative.components().any(|component| {
        let std::path::Component::Normal(value) = component else {
            return true;
        };
        matches!(
            value.to_string_lossy().as_ref(),
            ".git"
                | ".agentbox"
                | ".symphony"
                | ".projects"
                | ".env"
                | ".env.local"
                | ".ssh"
                | ".aws"
                | "node_modules"
                | "target"
                | ".turbo"
        )
    })
}

fn validate_bundle_file_path(path: &str) -> Result<(), (StatusCode, Json<WorkerError>)> {
    let candidate = PathBuf::from(path);
    if candidate.as_os_str().is_empty()
        || candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker evidence bundle file path is unsafe",
        ));
    }
    Ok(())
}

async fn persist_evidence_bundle(
    config: &RemoteWorkerConfig,
    request: &WorkerEvidenceBundleUploadRequest,
) -> Result<StoredEvidenceBundlePath, (StatusCode, Json<WorkerError>)> {
    let Some(state_dir) = config.state_dir.as_ref() else {
        return Err(worker_error(
            StatusCode::PRECONDITION_REQUIRED,
            "agentbox remote worker requires --state-dir before storing evidence bundle payloads",
        ));
    };
    let safe_worker_session_id = safe_path_segment(&request.worker_session_id)?;
    let dir = worker_state_root(state_dir)
        .join("evidence")
        .join(safe_worker_session_id);
    tokio::fs::create_dir_all(&dir).await.map_err(|err| {
        worker_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "agentbox remote worker failed to prepare evidence bundle directory {}: {err}",
                dir.display()
            ),
        )
    })?;
    let path = dir.join(format!("{}.json", request.bundle_sha256));
    tokio::fs::write(&path, request.bundle_json.as_bytes())
        .await
        .map_err(|err| {
            worker_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "agentbox remote worker failed to store evidence bundle {}: {err}",
                    path.display()
                ),
            )
        })?;
    Ok(StoredEvidenceBundlePath {
        path,
        stored_bytes: request.bundle_json.len().try_into().unwrap_or(u64::MAX),
    })
}

async fn record_stored_evidence_bundle(
    state: &Arc<RemoteWorkerState>,
    request: &WorkerEvidenceBundleUploadRequest,
    stored: &StoredEvidenceBundlePath,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    let mut sessions = state.sessions.lock().await;
    let session = get_matching_session_mut(
        &mut sessions,
        &request.worker_session_id,
        &request.session_id,
    )?;
    if let Some(existing) = session
        .stored_evidence_bundles
        .iter_mut()
        .find(|bundle| bundle.bundle_sha256 == request.bundle_sha256)
    {
        existing.stored_bytes = stored.stored_bytes;
        existing.storage_path = stored.path.clone();
    } else {
        session
            .stored_evidence_bundles
            .push(WorkerStoredEvidenceBundle {
                bundle_sha256: request.bundle_sha256.clone(),
                stored_bytes: stored.stored_bytes,
                storage_path: stored.path.clone(),
            });
    }
    session.record_lifecycle_event(
        RemoteAgentPodLifecycleEvent::EvidenceSealed,
        Some("remote worker stored evidence bundle".into()),
    );
    drop(sessions);
    persist_sessions(state).await.map_err(worker_state_error)?;
    Ok(())
}

async fn accept_evidence(
    state: &Arc<RemoteWorkerState>,
    request: &RemoteAgentPodEvidenceUploadRequest,
) -> Result<WorkerEvidenceReceipt, (StatusCode, Json<WorkerError>)> {
    request
        .validate()
        .map_err(|err| worker_error(StatusCode::BAD_REQUEST, err.to_string()))?;
    let mut sessions = state.sessions.lock().await;
    let session = get_matching_session_mut(
        &mut sessions,
        &request.worker_session_id,
        &request.session_id,
    )?;
    let receipt = WorkerEvidenceReceipt {
        bundle_sha256: request.bundle_sha256.clone(),
        derived_from_bundle: request.derived_from_bundle,
        bundle_id: request.bundle_id.clone(),
        bundle_root_sha256: request.bundle_root_sha256.clone(),
        event_count: request.event_count,
        sealed_at: Some(request.sealed_at),
    };
    session.evidence_receipts.push(receipt.clone());
    session.record_lifecycle_event(
        RemoteAgentPodLifecycleEvent::EvidenceSealed,
        Some("remote worker accepted evidence receipt".into()),
    );
    drop(sessions);
    persist_sessions(state).await.map_err(worker_state_error)?;
    Ok(receipt)
}

async fn accept_evidence_stream_chunk(
    state: &Arc<RemoteWorkerState>,
    request: &RemoteAgentPodEvidenceStreamChunkRequest,
) -> Result<Option<String>, (StatusCode, Json<WorkerError>)> {
    let mut sessions = state.sessions.lock().await;
    let session = get_matching_session_mut(
        &mut sessions,
        &request.worker_session_id,
        &request.session_id,
    )?;
    let stream = session
        .evidence_streams
        .entry(request.stream_id.clone())
        .or_insert_with(|| WorkerEvidenceStream {
            stream_id: request.stream_id.clone(),
            next_sequence: 0,
            next_offset: 0,
            received_bytes: 0,
            chunks: 0,
            sealed: false,
            stream_sha256: None,
            updated_at: None,
            contents_utf8: String::new(),
        });
    if stream.sealed {
        return Err(worker_error(
            StatusCode::CONFLICT,
            "agentbox remote worker evidence stream is already sealed",
        ));
    }
    if request.sequence != stream.next_sequence || request.offset != stream.next_offset {
        return Err(worker_error(
            StatusCode::CONFLICT,
            format!(
                "agentbox remote worker evidence stream chunk is out of order: expected sequence {} offset {}",
                stream.next_sequence, stream.next_offset
            ),
        ));
    }
    stream.contents_utf8.push_str(&request.chunk_utf8);
    stream.chunks = stream.chunks.saturating_add(1);
    stream.received_bytes = stream.received_bytes.saturating_add(request.chunk_bytes);
    stream.next_sequence = stream.next_sequence.saturating_add(1);
    stream.next_offset = stream.received_bytes;
    stream.updated_at = Some(Utc::now());
    if request.final_chunk {
        stream.sealed = true;
        stream.stream_sha256 = Some(sha256_hex(stream.contents_utf8.as_bytes()));
    }
    let stream_sha256 = stream.stream_sha256.clone();
    if request.final_chunk {
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::EvidenceSealed,
            Some(format!(
                "remote worker sealed evidence stream {}",
                request.stream_id
            )),
        );
    }
    drop(sessions);
    persist_sessions(state).await.map_err(worker_state_error)?;
    Ok(stream_sha256)
}

fn worker_evidence_stream_status(
    stream: &WorkerEvidenceStream,
) -> RemoteAgentPodEvidenceStreamStatus {
    RemoteAgentPodEvidenceStreamStatus {
        stream_id: stream.stream_id.clone(),
        next_sequence: stream.next_sequence,
        next_offset: stream.next_offset,
        received_bytes: stream.received_bytes,
        chunks: stream.chunks,
        sealed: stream.sealed,
        stream_sha256: stream.stream_sha256.clone(),
        updated_at: stream.updated_at,
    }
}

async fn accept_approval_grant(
    state: &Arc<RemoteWorkerState>,
    request: &RemoteAgentPodApprovalGrantRequest,
) -> Result<u64, (StatusCode, Json<WorkerError>)> {
    let mut sessions = state.sessions.lock().await;
    let session = get_matching_session_mut(
        &mut sessions,
        &request.worker_session_id,
        &request.session_id,
    )?;
    let Some(index) = session
        .pending_approvals
        .iter()
        .position(|approval| approval.request_id == request.request_id)
    else {
        return Err(worker_error(
            StatusCode::NOT_FOUND,
            "agentbox remote worker pending approval request was not found",
        ));
    };
    let pending = &session.pending_approvals[index];
    ensure_grant_matches_pending_approval(&request.grant, pending)?;
    if !session
        .approval_grants
        .iter()
        .any(|grant| grant.id == request.grant.id)
    {
        session
            .approval_grants
            .push(request.grant.clone().bound_to_session(&request.session_id));
    }
    session.pending_approvals.remove(index);
    session.record_lifecycle_event(
        RemoteAgentPodLifecycleEvent::EvidenceSealed,
        Some("remote worker accepted approval grant".into()),
    );
    let remaining = session
        .pending_approvals
        .len()
        .try_into()
        .unwrap_or(u64::MAX);
    drop(sessions);
    persist_sessions(state).await.map_err(worker_state_error)?;
    Ok(remaining)
}

async fn deny_pending_approval(
    state: &Arc<RemoteWorkerState>,
    request: &RemoteAgentPodApprovalDenyRequest,
) -> Result<u64, (StatusCode, Json<WorkerError>)> {
    let mut sessions = state.sessions.lock().await;
    let session = get_matching_session_mut(
        &mut sessions,
        &request.worker_session_id,
        &request.session_id,
    )?;
    let Some(index) = session
        .pending_approvals
        .iter()
        .position(|approval| approval.request_id == request.request_id)
    else {
        return Err(worker_error(
            StatusCode::NOT_FOUND,
            "agentbox remote worker pending approval request was not found",
        ));
    };
    session.pending_approvals.remove(index);
    session.record_lifecycle_event(
        RemoteAgentPodLifecycleEvent::EvidenceSealed,
        Some(format!("remote worker denied approval: {}", request.reason)),
    );
    let remaining = session
        .pending_approvals
        .len()
        .try_into()
        .unwrap_or(u64::MAX);
    drop(sessions);
    persist_sessions(state).await.map_err(worker_state_error)?;
    Ok(remaining)
}

fn ensure_grant_matches_pending_approval(
    grant: &ApprovalGrant,
    pending: &WorkerPendingApproval,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    let ApprovalScope::Command {
        binary,
        args_prefix,
    } = &grant.scope
    else {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker only accepts command-scope approval grants",
        ));
    };
    if pending.command_argv.first() != Some(binary) {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker approval grant binary does not match pending command",
        ));
    }
    let pending_args = pending
        .command_argv
        .iter()
        .skip(1)
        .cloned()
        .collect::<Vec<_>>();
    if !pending_args.starts_with(args_prefix) {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker approval grant args do not match pending command",
        ));
    }
    Ok(())
}

fn worker_pending_approval_status(
    session_id: &str,
    worker_session_id: &str,
    approval: &WorkerPendingApproval,
) -> RemoteAgentPodPendingApprovalStatus {
    RemoteAgentPodPendingApprovalStatus {
        request_id: approval.request_id.clone(),
        command_argv: approval.command_argv.clone(),
        reason: approval.reason.clone(),
        prompt: worker_pending_approval_prompt(session_id, worker_session_id, approval),
        created_at: approval.created_at,
    }
}

fn worker_event_stream_descriptor(
    session_id: &str,
    worker_session_id: &str,
) -> RemoteAgentPodEventStreamDescriptor {
    RemoteAgentPodEventStreamDescriptor {
        schema_version: 1,
        delivery: "http-polling-contract".into(),
        lifecycle_stream_id: format!("lifecycle:{session_id}:{worker_session_id}"),
        evidence_stream_prefix: format!("evidence:{session_id}:{worker_session_id}:"),
        lifecycle_events_path: format!(
            "/sessions/{worker_session_id}/events?session_id={session_id}"
        ),
        evidence_status_path: format!(
            "/sessions/{worker_session_id}/evidence/status?session_id={session_id}"
        ),
        evidence_chunk_path: format!("/sessions/{worker_session_id}/evidence/stream"),
        ordering: "monotonic lifecycle sequence; per-stream evidence sequence".into(),
        replay: "full journal/status replay over polling endpoints".into(),
        claim_boundary: "descriptor only; not a live bidirectional event bus".into(),
    }
}

fn worker_pending_approval_prompt(
    session_id: &str,
    worker_session_id: &str,
    approval: &WorkerPendingApproval,
) -> RemoteAgentPodApprovalPrompt {
    RemoteAgentPodApprovalPrompt {
        schema_version: 1,
        title: "Remote AgentPod approval required".into(),
        body: format!(
            "Approve remote command `{}` for worker session `{}`.",
            approval.command_argv.join(" "),
            worker_session_id
        ),
        approve_command: format!(
            "agentbox remote-approval-grant --session {session_id} --worker-session {worker_session_id} --request {} --reason <reason>",
            approval.request_id
        ),
        deny_command: Some(format!(
            "agentbox remote-approval-deny --session {session_id} --worker-session {worker_session_id} --request {} --reason <reason>",
            approval.request_id
        )),
        claim_boundary:
            "prompt descriptor only; rich interactive remote approval UI is not wired".into(),
    }
}

fn worker_credential_status(session: &WorkerSession) -> Vec<RemoteAgentPodCredentialStatus> {
    let mut credentials = Vec::new();
    credentials.extend(session.env_credentials.iter().map(|credential| {
        RemoteAgentPodCredentialStatus {
            name: credential.name.clone(),
            kind: CredentialGrantKind::EnvVar,
            guest_path: None,
            sha256: None,
            bytes: None,
            one_time: credential.one_time,
        }
    }));
    credentials.extend(session.file_credentials.iter().map(|credential| {
        RemoteAgentPodCredentialStatus {
            name: credential.name.clone(),
            kind: CredentialGrantKind::FileMount,
            guest_path: Some(credential.guest_path.clone()),
            sha256: Some(credential.sha256.clone()),
            bytes: Some(credential.bytes),
            one_time: credential.one_time,
        }
    }));
    credentials
}

async fn require_matching_session(
    state: &Arc<RemoteWorkerState>,
    worker_session_id: &str,
    session_id: &str,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    let mut sessions = state.sessions.lock().await;
    get_matching_session_mut(&mut sessions, worker_session_id, session_id)?;
    Ok(())
}

fn get_matching_session_mut<'a>(
    sessions: &'a mut HashMap<String, WorkerSession>,
    worker_session_id: &str,
    session_id: &str,
) -> Result<&'a mut WorkerSession, (StatusCode, Json<WorkerError>)> {
    let Some(session) = sessions.get_mut(worker_session_id) else {
        return Err(worker_error(
            StatusCode::NOT_FOUND,
            format!("agentbox remote worker session {worker_session_id} has not been created"),
        ));
    };
    if session.session_id != session_id {
        return Err(worker_error(
            StatusCode::CONFLICT,
            "agentbox remote worker session id does not match worker session",
        ));
    }
    Ok(session)
}

async fn destroy_session(
    State(state): State<Arc<RemoteWorkerState>>,
    AxumPath(route_worker_session_id): AxumPath<String>,
    Json(request): Json<RemoteAgentPodDestroySessionRequest>,
) -> WorkerRouteResult<RemoteAgentPodDestroySessionResponse> {
    require_route_worker_session_id(&route_worker_session_id, &request.worker_session_id)?;
    let mut sessions = state.sessions.lock().await;
    let Some(session) = sessions.get_mut(&request.worker_session_id) else {
        return Err(worker_error(
            StatusCode::NOT_FOUND,
            format!(
                "agentbox remote worker session {} has not been created",
                request.worker_session_id
            ),
        ));
    };
    if session.session_id != request.session_id {
        return Err(worker_error(
            StatusCode::CONFLICT,
            "agentbox remote worker session id does not match worker session",
        ));
    }
    session.mark_stopped();
    session.record_lifecycle_event(
        RemoteAgentPodLifecycleEvent::KillSwitchAck,
        Some(request.reason.clone()),
    );
    session.record_lifecycle_event(
        RemoteAgentPodLifecycleEvent::WorkerDestroyed,
        Some("remote worker destroyed session".into()),
    );
    drop(sessions);
    persist_sessions(&state).await.map_err(worker_state_error)?;
    Ok(Json(RemoteAgentPodDestroySessionResponse {
        session_id: request.session_id,
        worker_session_id: request.worker_session_id,
        status: RuntimeStatus::Stopped,
        lifecycle_events: vec![
            RemoteAgentPodLifecycleEvent::KillSwitchAck,
            RemoteAgentPodLifecycleEvent::WorkerDestroyed,
        ],
    }))
}

fn load_persisted_sessions(
    config: &RemoteWorkerConfig,
) -> Result<HashMap<String, WorkerSession>, String> {
    let Some(path) = worker_state_path(config) else {
        return Ok(HashMap::new());
    };
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let contents = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read remote worker state: {err}"))?;
    if contents.trim().is_empty() {
        return Ok(HashMap::new());
    }
    let snapshots: Vec<WorkerSessionSnapshot> = serde_json::from_str(&contents)
        .map_err(|err| format!("failed to parse remote worker state: {err}"))?;
    Ok(snapshots
        .into_iter()
        .map(|snapshot| {
            (
                snapshot.worker_session_id.clone(),
                WorkerSession::from_snapshot(snapshot),
            )
        })
        .collect())
}

async fn persist_sessions(state: &Arc<RemoteWorkerState>) -> Result<(), String> {
    let Some(path) = worker_state_path(&state.config) else {
        return Ok(());
    };
    let snapshots = {
        let sessions = state.sessions.lock().await;
        sessions
            .iter()
            .map(|(worker_session_id, session)| session.to_snapshot(worker_session_id.clone()))
            .collect::<Vec<_>>()
    };
    let contents = serde_json::to_string_pretty(&snapshots)
        .map_err(|err| format!("failed to serialize remote worker state: {err}"))?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            format!(
                "failed to prepare remote worker state directory {}: {err}",
                parent.display()
            )
        })?;
    }
    tokio::fs::write(&path, contents).await.map_err(|err| {
        format!(
            "failed to write remote worker state {}: {err}",
            path.display()
        )
    })
}

fn worker_state_error(message: String) -> (StatusCode, Json<WorkerError>) {
    worker_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("agentbox remote worker could not persist session state: {message}"),
    )
}

fn worker_state_path(config: &RemoteWorkerConfig) -> Option<PathBuf> {
    config.state_dir.as_ref().map(|state_dir| {
        if state_dir.extension().is_some() {
            state_dir.clone()
        } else {
            state_dir.join("worker-sessions.json")
        }
    })
}

fn worker_supervision_path(config: &RemoteWorkerConfig) -> Option<PathBuf> {
    config.state_dir.as_ref().map(|state_dir| {
        if state_dir.extension().is_some() {
            worker_state_root(state_dir).join("worker-supervision.json")
        } else {
            state_dir.join("worker-supervision.json")
        }
    })
}

fn persist_supervision_snapshot(
    path: &Path,
    snapshot: &WorkerSupervisionSnapshot,
) -> Result<(), String> {
    let contents = serde_json::to_string_pretty(snapshot)
        .map_err(|err| format!("failed to serialize remote worker supervision state: {err}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to prepare remote worker supervision directory {}: {err}",
                parent.display()
            )
        })?;
    }
    std::fs::write(path, contents).map_err(|err| {
        format!(
            "failed to write remote worker supervision state {}: {err}",
            path.display()
        )
    })
}

fn worker_state_root(state_dir: &Path) -> PathBuf {
    if state_dir.extension().is_some() {
        state_dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        state_dir.to_path_buf()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn safe_path_segment(value: &str) -> Result<&str, (StatusCode, Json<WorkerError>)> {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
    {
        Ok(value)
    } else {
        Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker received an unsafe path segment",
        ))
    }
}

pub fn signing_key_from_hex_seed(seed_hex: &str) -> Result<SigningKey, String> {
    let bytes = decode_hex_exact::<32>(seed_hex)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("expected {} hex characters", N * 2));
    }
    let mut out = [0_u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        let high = decode_hex_nibble(bytes[index * 2])?;
        let low = decode_hex_nibble(bytes[index * 2 + 1])?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn decode_hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("seed must contain only hex characters".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentbox_daemon::runtime::providers::remote::{
        Ed25519HandshakeVerifier, RemoteAgentPodAuthKind, RemoteAgentPodCredentialFile,
        RemoteAgentPodDestroySessionRequest, RemoteAgentPodEvidenceMode,
        RemoteAgentPodHandshakeVerifier, RemoteAgentPodTransportDescriptor,
        RemoteAgentPodWorkspaceBundle,
    };
    use agentbox_daemon::runtime::types::{
        CredentialGrant, CredentialGrantKind, ExecCommand, MinipodSpec, MountKind, MountMode,
        MountRule,
    };
    use std::collections::HashMap;

    fn test_state(config: RemoteWorkerConfig) -> Arc<RemoteWorkerState> {
        Arc::new(RemoteWorkerState {
            config,
            supervision: WorkerSupervisionState::memory_only(0),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn state_file(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-{}-{name}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn worker_session_path() -> AxumPath<String> {
        AxumPath("worker-session-1".into())
    }

    #[test]
    fn worker_guest_path_to_workspace_path_requires_workspace_boundary() {
        let workspace = std::env::temp_dir().join("agentbox-remote-worker-path-boundary");
        let err =
            worker_guest_path_to_workspace_path(&workspace, "/workspace", "/workspace2/secret")
                .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err
            .1
             .0
            .error
            .contains("only materializes file credentials under the workspace guest path"));
    }

    fn create_session_request(workspace: PathBuf) -> RemoteAgentPodCreateSessionRequest {
        RemoteAgentPodCreateSessionRequest {
            transport: RemoteAgentPodTransportDescriptor::new(
                "https://worker.example.com/agentpod",
                RemoteAgentPodAuthKind::SignedChallenge,
                RemoteAgentPodEvidenceMode::BundleUpload,
            )
            .unwrap(),
            handshake_ack: RemoteAgentPodHandshakeAck {
                worker_identity: "worker.local/dev".into(),
                worker_public_key: "ed25519:placeholder".into(),
                signed_challenge: "ed25519:placeholder".into(),
                capabilities: Vec::new(),
                evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
                lifecycle_ack: true,
                secret_material_included: false,
                expires_at: chrono::Utc::now() + Duration::seconds(60),
            },
            spec: MinipodSpec::for_agent_task("remote-test-agent", workspace),
            workspace_bundle: None,
            credential_files: Vec::new(),
        }
    }

    fn test_evidence_bundle_upload_json(
        session_id: &str,
        worker_session_id: &str,
    ) -> (String, String) {
        let bundle_json = format!(
            r#"{{"schema_version":1,"session_id":"{session_id}","commands":[{{"audit_event_id":"evt_1"}}],"approvals":[],"lifecycle_events":[],"boundary_events":[],"credential_events":[]}}"#
        );
        let manifest_json = r#"{"schema_version":1,"kind":"AgentPod"}"#.to_string();
        let files = vec![
            WorkerEvidenceBundleFile {
                path: "bundle.json".into(),
                media_type: "application/json".into(),
                sha256: sha256_hex(bundle_json.as_bytes()),
                bytes: bundle_json.len(),
            },
            WorkerEvidenceBundleFile {
                path: "manifest.json".into(),
                media_type: "application/json".into(),
                sha256: sha256_hex(manifest_json.as_bytes()),
                bytes: manifest_json.len(),
            },
        ];
        let root_sha256 = evidence_bundle_root_sha256(&files).unwrap();
        let envelope = serde_json::json!({
            "schema_version": 1,
            "kind": "AgentboxEvidenceBundleUpload",
            "session_id": session_id,
            "worker_session_id": worker_session_id,
            "index": {
                "schema_version": 1,
                "bundle_id": "bundle-test",
                "session_id": session_id,
                "provider": "direct-host",
                "status": "Stopped",
                "root_sha256": root_sha256,
                "files": files
                    .iter()
                    .map(|file| serde_json::json!({
                        "path": file.path,
                        "media_type": file.media_type,
                        "description": "test evidence file",
                        "sha256": file.sha256,
                        "bytes": file.bytes,
                    }))
                    .collect::<Vec<_>>(),
            },
            "files": {
                "bundle.json": bundle_json,
                "manifest.json": manifest_json,
            },
        });
        let envelope_json =
            serde_json::to_string(&envelope).expect("failed to serialize test envelope");
        let envelope_sha256 = sha256_hex(envelope_json.as_bytes());
        (envelope_json, envelope_sha256)
    }

    fn test_workspace_bundle(path: &str, contents: &str) -> RemoteAgentPodWorkspaceBundle {
        let file = RemoteAgentPodWorkspaceFile {
            path: path.into(),
            media_type: "text/plain".into(),
            sha256: sha256_hex(contents.as_bytes()),
            bytes: contents.len(),
            contents_utf8: contents.into(),
        };
        let root = sha256_hex(
            format!(
                "agentbox-workspace-root-v1\n{}\0{}\0{}\0{}",
                file.path, file.sha256, file.bytes, file.media_type
            )
            .as_bytes(),
        );
        RemoteAgentPodWorkspaceBundle {
            schema_version: 1,
            root_sha256: root,
            files: vec![file],
            secret_material_included: false,
        }
    }

    #[tokio::test]
    async fn handshake_response_is_ed25519_verifiable() {
        let signing_key = SigningKey::from_bytes(&[21_u8; 32]);
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            signing_key,
        );
        let descriptor = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();

        let Json(ack) = handshake(State(test_state(config)), Json(descriptor.clone())).await;

        let verified = Ed25519HandshakeVerifier
            .verify(&descriptor, &ack, descriptor.created_at)
            .unwrap();
        assert!(verified.cryptographic_signature_verified);
        assert_eq!(verified.worker_identity, "worker.local/dev");
    }

    #[test]
    fn signing_key_seed_requires_exact_hex() {
        assert!(signing_key_from_hex_seed(&"a".repeat(64)).is_ok());
        assert!(signing_key_from_hex_seed("abc").is_err());
        assert!(signing_key_from_hex_seed(&"z".repeat(64)).is_err());
    }

    #[tokio::test]
    async fn exec_command_runs_argv_without_shell() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[22_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["printf".into(), "hello-agentbox".into()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };

        let response = exec_command(State(state.clone()), worker_session_path(), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.result.exit_code, 0);
        assert_eq!(response.result.stdout, "hello-agentbox");
        assert!(response.result.stderr.is_empty());
        assert!(response
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::EvidenceSealed));
        let sessions = state.sessions.lock().await;
        let session = sessions.get("worker-session-1").unwrap();
        assert_eq!(session.commands_started, 1);
        assert_eq!(session.commands_finished, 1);
        assert_eq!(session.active_command_count, 0);
        assert_eq!(session.last_command_exit_code, Some(0));
        assert!(session.last_command_finished_at.is_some());
    }

    #[tokio::test]
    async fn exec_command_rejects_empty_argv() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[23_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: Vec::new(),
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };

        let response = exec_command(State(state), worker_session_path(), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.result.exit_code, 127);
        assert!(response.result.stderr.contains("empty argv"));
    }

    #[tokio::test]
    async fn exec_command_requires_created_running_session() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[25_u8; 32]),
        );
        let state = test_state(config);
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["printf".into(), "hello".into()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };

        let err = exec_command(State(state), worker_session_path(), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert!(err.1 .0.error.contains("has not been created"));
    }

    #[tokio::test]
    async fn mutating_routes_reject_worker_session_path_mismatch() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[45_u8; 32]),
        )
        .with_state_dir(std::env::temp_dir());
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let exec_err = exec_command(
            State(state.clone()),
            AxumPath("worker-session-other".into()),
            Json(RemoteAgentPodExecRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                command: ExecCommand {
                    argv: vec!["printf".into(), "hello".into()],
                    working_dir: None,
                    env: HashMap::new(),
                    timeout_seconds: Some(5),
                },
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(exec_err.0, StatusCode::CONFLICT);

        let evidence_err = upload_evidence(
            State(state.clone()),
            AxumPath("worker-session-other".into()),
            Json(RemoteAgentPodEvidenceUploadRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                evidence_mode: RemoteAgentPodEvidenceMode::BundleUpload,
                bundle_sha256: "a".repeat(64),
                derived_from_bundle: false,
                bundle_id: None,
                bundle_root_sha256: None,
                event_count: 1,
                sealed_at: chrono::Utc::now(),
                secret_material_included: false,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(evidence_err.0, StatusCode::CONFLICT);

        let bundle_err = upload_evidence_bundle(
            State(state.clone()),
            AxumPath("worker-session-other".into()),
            Json(WorkerEvidenceBundleUploadRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                bundle_sha256: "0".repeat(64),
                bundle_json: "{}".into(),
                secret_material_included: false,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(bundle_err.0, StatusCode::CONFLICT);

        let stream_err = upload_evidence_stream_chunk(
            State(state.clone()),
            AxumPath("worker-session-other".into()),
            Json(RemoteAgentPodEvidenceStreamChunkRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                stream_id: "stdout".into(),
                sequence: 0,
                offset: 0,
                chunk_sha256: sha256_hex(b"hello"),
                chunk_bytes: 5,
                chunk_utf8: "hello".into(),
                final_chunk: false,
                secret_material_included: false,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(stream_err.0, StatusCode::CONFLICT);

        let destroy_err = destroy_session(
            State(state),
            AxumPath("worker-session-other".into()),
            Json(RemoteAgentPodDestroySessionRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                reason: "route mismatch".into(),
                kill_switch_required: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(destroy_err.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn exec_command_refuses_working_dir_outside_workspace() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[30_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-workspace-{}",
            std::process::id()
        ));
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new("session-1".into(), workspace, WorkerPolicy::default()),
        );
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["printf".into(), "hello".into()],
                working_dir: Some("/".into()),
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };

        let response = exec_command(State(state), worker_session_path(), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.result.exit_code, 126);
        assert!(response.result.stderr.contains("outside workspace"));
    }

    #[tokio::test]
    async fn exec_command_rejects_environment_material() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[32_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["printf".into(), "hello".into()],
                working_dir: None,
                env: HashMap::from([("OPENAI_API_KEY".into(), "secret".into())]),
                timeout_seconds: Some(5),
            },
        };

        let err = exec_command(State(state), worker_session_path(), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("matching session credential grant"));
    }

    #[tokio::test]
    async fn exec_command_allows_session_bound_env_credentials() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[42_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new_with_env_credentials(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
                vec![WorkerEnvCredentialGrant {
                    name: "AGENTBOX_TEST_TOKEN".into(),
                    one_time: true,
                }],
                Vec::new(),
            ),
        );
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    "printf %s \"$AGENTBOX_TEST_TOKEN\"".into(),
                ],
                working_dir: None,
                env: HashMap::from([("AGENTBOX_TEST_TOKEN".into(), "remote-secret".into())]),
                timeout_seconds: Some(5),
            },
        };

        let response = exec_command(State(state), worker_session_path(), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.result.exit_code, 0);
        assert_eq!(response.result.stdout, "remote-secret");
    }

    #[tokio::test]
    async fn exec_command_exposes_file_credential_paths_without_secret_env_values() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[46_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-file-credential-exec-{}",
            std::process::id()
        ));
        let credential_path = workspace.join(".agentbox/credentials/openai");
        std::fs::create_dir_all(credential_path.parent().unwrap()).unwrap();
        std::fs::write(&credential_path, "agentbox-test-credential\n").unwrap();
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new_with_credentials(
                "session-1".into(),
                workspace.clone(),
                WorkerPolicy::default(),
                Vec::new(),
                vec![WorkerFileCredentialGrant {
                    name: "openai".into(),
                    guest_path: "/workspace/.agentbox/credentials/openai".into(),
                    host_path: credential_path.clone(),
                    sha256: hex_encode(&Sha256::digest(b"agentbox-test-credential\n")),
                    bytes: "agentbox-test-credential\n".len(),
                    one_time: true,
                }],
                Vec::new(),
                WorkerLifecycleConfig::default(),
            ),
        );
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    "cat \"$AGENTBOX_CREDENTIAL_FILE_OPENAI\"".into(),
                ],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };

        let response = exec_command(State(state.clone()), worker_session_path(), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.result.exit_code, 0);
        assert_eq!(response.result.stdout, "agentbox-test-credential\n");
        assert!(!credential_path.exists());
        {
            let sessions = state.sessions.lock().await;
            let session = sessions.get("worker-session-1").unwrap();
            assert!(session.file_credentials.is_empty());
        }

        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    "test -z \"${AGENTBOX_CREDENTIAL_FILE_OPENAI+x}\"".into(),
                ],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };
        let response = exec_command(State(state), worker_session_path(), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.result.exit_code, 0);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn exec_command_enforces_worker_network_policy_before_spawn() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[41_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy {
                    network_mode: WorkerPolicyNetworkMode::DenyByDefault,
                    ..WorkerPolicy::default()
                },
            ),
        );
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["curl".into(), "https://unknown.example.com".into()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };

        let response = exec_command(State(state), worker_session_path(), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.result.exit_code, 126);
        assert!(response.result.stderr.contains("policy denied"));
        assert!(response.result.stderr.contains("unknown.example.com"));
    }

    #[tokio::test]
    async fn exec_command_records_pending_approval_for_approval_bucket() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[48_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy {
                    network_mode: WorkerPolicyNetworkMode::ApprovalOnFirstContact,
                    ..WorkerPolicy::default()
                },
            ),
        );
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["curl".into(), "https://approval.example.com".into()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };

        let response = exec_command(State(state.clone()), worker_session_path(), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.result.exit_code, 126);
        assert!(response.result.stderr.contains("policy denied"));
        let sessions = state.sessions.lock().await;
        let approvals = &sessions.get("worker-session-1").unwrap().pending_approvals;
        assert_eq!(approvals.len(), 1);
        assert_eq!(
            approvals[0].command_argv,
            vec!["curl", "https://approval.example.com"]
        );
        assert!(!approvals[0].reason.is_empty());
    }

    #[tokio::test]
    async fn grant_approval_accepts_pending_command_scope_grant() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[49_u8; 32]),
        );
        let state = test_state(config);
        let mut session = WorkerSession::new(
            "session-1".into(),
            std::env::temp_dir(),
            WorkerPolicy::default(),
        );
        session.pending_approvals.push(WorkerPendingApproval {
            request_id: "approval-1".into(),
            command_argv: vec!["curl".into(), "https://approval.example.com".into()],
            reason: "first contact".into(),
            created_at: Utc::now(),
        });
        state
            .sessions
            .lock()
            .await
            .insert("worker-session-1".into(), session);

        let response = grant_approval(
            State(state.clone()),
            worker_session_path(),
            Json(RemoteAgentPodApprovalGrantRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                request_id: "approval-1".into(),
                grant: ApprovalGrant {
                    id: "grant-1".into(),
                    scope: ApprovalScope::Command {
                        binary: "curl".into(),
                        args_prefix: vec!["https://approval.example.com".into()],
                    },
                    reason: "operator approved".into(),
                    expires_at: None,
                },
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(response.accepted_grant_id, "grant-1");
        assert_eq!(response.remaining_pending_approvals, 0);
        let sessions = state.sessions.lock().await;
        let session = sessions.get("worker-session-1").unwrap();
        assert!(session.pending_approvals.is_empty());
        assert_eq!(session.approval_grants.len(), 1);
        assert_eq!(session.approval_grants[0].id, "grant-1");
    }

    #[tokio::test]
    async fn deny_approval_removes_pending_request_without_grant() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[79_u8; 32]),
        );
        let state = test_state(config);
        let mut session = WorkerSession::new(
            "session-1".into(),
            std::env::temp_dir(),
            WorkerPolicy::default(),
        );
        session.pending_approvals.push(WorkerPendingApproval {
            request_id: "approval-1".into(),
            command_argv: vec!["curl".into(), "https://approval.example.com".into()],
            reason: "first contact".into(),
            created_at: Utc::now(),
        });
        state
            .sessions
            .lock()
            .await
            .insert("worker-session-1".into(), session);

        let response = deny_approval(
            State(state.clone()),
            worker_session_path(),
            Json(RemoteAgentPodApprovalDenyRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                request_id: "approval-1".into(),
                reason: "operator denied test command".into(),
            }),
        )
        .await
        .unwrap()
        .0;

        assert!(response.denied);
        assert_eq!(response.remaining_pending_approvals, 0);
        let sessions = state.sessions.lock().await;
        let session = sessions.get("worker-session-1").unwrap();
        assert!(session.pending_approvals.is_empty());
        assert!(session.approval_grants.is_empty());
        assert!(session.lifecycle_events.iter().any(|event| event
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("denied approval"))));
    }

    #[tokio::test]
    async fn grant_approval_rejects_mismatched_pending_command() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[50_u8; 32]),
        );
        let state = test_state(config);
        let mut session = WorkerSession::new(
            "session-1".into(),
            std::env::temp_dir(),
            WorkerPolicy::default(),
        );
        session.pending_approvals.push(WorkerPendingApproval {
            request_id: "approval-1".into(),
            command_argv: vec!["curl".into(), "https://approval.example.com".into()],
            reason: "first contact".into(),
            created_at: Utc::now(),
        });
        state
            .sessions
            .lock()
            .await
            .insert("worker-session-1".into(), session);

        let err = grant_approval(
            State(state),
            worker_session_path(),
            Json(RemoteAgentPodApprovalGrantRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                request_id: "approval-1".into(),
                grant: ApprovalGrant {
                    id: "grant-1".into(),
                    scope: ApprovalScope::Command {
                        binary: "rm".into(),
                        args_prefix: Vec::new(),
                    },
                    reason: "operator approved".into(),
                    expires_at: None,
                },
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("does not match"));
    }

    #[test]
    fn worker_approval_grant_matches_command_scope() {
        let context = WorkerExecContext {
            kill_rx: watch::channel(false).1,
            session_id: "session-1".into(),
            workspace_host_path: std::env::temp_dir(),
            policy: WorkerPolicy::default(),
            env_credentials: Vec::new(),
            file_credentials: Vec::new(),
            approval_grants: Vec::new(),
        };
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["git".into(), "push".into(), "origin".into(), "main".into()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };
        let grant = ApprovalGrant {
            id: "grant-git-push".into(),
            scope: ApprovalScope::Command {
                binary: "git".into(),
                args_prefix: vec!["push".into()],
            },
            reason: "operator approved git push".into(),
            expires_at: None,
        };

        assert!(worker_approval_grant_matches(
            &grant,
            &request,
            &context,
            &std::env::temp_dir()
        ));
    }

    #[test]
    fn worker_approval_grant_matches_domain_session_and_path_scopes() {
        let workspace = std::env::temp_dir().join("agentbox-remote-worker-approval-scope-test");
        let context = WorkerExecContext {
            kill_rx: watch::channel(false).1,
            session_id: "session-1".into(),
            workspace_host_path: workspace.clone(),
            policy: WorkerPolicy::default(),
            env_credentials: Vec::new(),
            file_credentials: Vec::new(),
            approval_grants: Vec::new(),
        };
        let curl_request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["curl".into(), "https://api.example.com/v1".into()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };
        let domain_grant = ApprovalGrant {
            id: "grant-domain".into(),
            scope: ApprovalScope::Domain {
                domain: "example.com".into(),
            },
            reason: "operator approved example.com".into(),
            expires_at: None,
        };
        assert!(worker_approval_grant_matches(
            &domain_grant,
            &curl_request,
            &context,
            &workspace
        ));

        let session_grant = ApprovalGrant {
            id: "grant-session".into(),
            scope: ApprovalScope::Session {
                session_id: "session-1".into(),
            },
            reason: "operator approved session".into(),
            expires_at: None,
        };
        assert!(worker_approval_grant_matches(
            &session_grant,
            &curl_request,
            &context,
            &workspace
        ));

        let cat_request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["cat".into(), "allowed/notes.txt".into()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };
        let path_grant = ApprovalGrant {
            id: "grant-path".into(),
            scope: ApprovalScope::Path {
                path: workspace.join("allowed"),
                access: FileAccessMode::Read,
            },
            reason: "operator approved reading allowed paths".into(),
            expires_at: None,
        };
        assert!(worker_approval_grant_matches(
            &path_grant,
            &cat_request,
            &context,
            &workspace
        ));
    }

    #[test]
    fn worker_approval_grant_rejects_once_and_expired_grants() {
        let workspace = std::env::temp_dir();
        let context = WorkerExecContext {
            kill_rx: watch::channel(false).1,
            session_id: "session-1".into(),
            workspace_host_path: workspace.clone(),
            policy: WorkerPolicy::default(),
            env_credentials: Vec::new(),
            file_credentials: Vec::new(),
            approval_grants: Vec::new(),
        };
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["git".into(), "push".into()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(5),
            },
        };
        let once_grant = ApprovalGrant {
            id: "grant-once".into(),
            scope: ApprovalScope::Once,
            reason: "one-time grant cannot be consumed remotely yet".into(),
            expires_at: None,
        };
        assert!(!worker_approval_grant_matches(
            &once_grant,
            &request,
            &context,
            &workspace
        ));

        let expired_grant = ApprovalGrant {
            id: "grant-expired".into(),
            scope: ApprovalScope::Command {
                binary: "git".into(),
                args_prefix: vec!["push".into()],
            },
            reason: "expired approval".into(),
            expires_at: Some(Utc::now() - Duration::seconds(1)),
        };
        assert!(!worker_approval_grant_matches(
            &expired_grant,
            &request,
            &context,
            &workspace
        ));
    }

    #[tokio::test]
    async fn create_session_rejects_unpreparable_workspace() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[31_u8; 32]),
        );
        let state = test_state(config);
        let workspace_file = state_file("workspace-file");
        std::fs::write(&workspace_file, b"not-a-directory").unwrap();
        let request = create_session_request(workspace_file.clone());

        let err = create_session(State(state.clone()), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("failed to prepare workspace"));
        assert!(state.sessions.lock().await.is_empty());
        let _ = std::fs::remove_file(workspace_file);
    }

    #[tokio::test]
    async fn create_session_rejects_invalid_event_stream_descriptor() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[32_u8; 32]),
        );
        let state = test_state(config);
        let mut request = create_session_request(std::env::temp_dir());
        request.transport.event_stream.delivery = "websocket".into();
        request.transport.event_stream.claim_boundary =
            "live bidirectional event bus is ready".into();

        let err = create_session(State(state.clone()), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("polling-only delivery"));
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn create_session_materializes_workspace_bundle() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[33_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-workspace-bundle-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        let mut request = create_session_request(workspace.clone());
        request.workspace_bundle = Some(test_workspace_bundle("src/main.rs", "fn main() {}\n"));

        let Json(response) = create_session(State(state.clone()), Json(request))
            .await
            .unwrap();

        assert_eq!(response.status, RuntimeStatus::Running);
        let materialized = std::fs::read_to_string(workspace.join("src/main.rs")).unwrap();
        assert_eq!(materialized, "fn main() {}\n");
        assert_eq!(state.sessions.lock().await.len(), 1);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn create_session_rejects_duplicate_worker_session_id() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[46_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-duplicate-create-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        let request = create_session_request(workspace.clone());

        let _ = create_session(State(state.clone()), Json(request.clone()))
            .await
            .unwrap();
        let err = create_session(State(state.clone()), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(err.1 .0.error.contains("already exists"));
        assert_eq!(state.sessions.lock().await.len(), 1);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn workspace_export_returns_verified_workspace_bundle() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[34_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-workspace-export-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("src")).unwrap();
        std::fs::write(workspace.join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(workspace.join(".env"), "TOKEN=secret\n").unwrap();
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                workspace.clone(),
                WorkerPolicy::default(),
            ),
        );

        let Json(response) = export_workspace(
            State(state),
            AxumPath("worker-session-1".into()),
            Query(WorkerEvidenceStatusQuery {
                session_id: "session-1".into(),
                after_sequence: None,
                limit: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.session_id, "session-1");
        assert_eq!(response.worker_session_id, "worker-session-1");
        assert!(response
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::EvidenceSealed));
        response.workspace_bundle.validate().unwrap();
        assert_eq!(response.workspace_bundle.files.len(), 1);
        assert_eq!(response.workspace_bundle.files[0].path, "src/main.rs");
        assert_eq!(
            response.workspace_bundle.files[0].contents_utf8,
            "fn main() {}\n"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn create_session_accepts_explicit_env_credential_grants() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[33_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-env-credential-workspace-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        let mut request = create_session_request(workspace.clone());
        request.spec.credentials.grants.push(CredentialGrant {
            name: "OPENAI_API_KEY".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "HOST_OPENAI_API_KEY".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });

        let response = create_session(State(state.clone()), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.status, RuntimeStatus::Running);
        let sessions = state.sessions.lock().await;
        let session = sessions.get(&response.worker_session_id).unwrap();
        assert_eq!(session.env_credentials.len(), 1);
        assert_eq!(session.env_credentials[0].name, "OPENAI_API_KEY");
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn create_session_materializes_file_credential_payloads() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[45_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-file-credential-materialized-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        let mut request = create_session_request(workspace.clone());
        let host_source = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-source-credential-{}",
            std::process::id()
        ));
        request.spec.filesystem.mounts.push(MountRule {
            host_path: host_source.clone(),
            guest_path: "/workspace/.agentbox/credentials/openai".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::Credential,
        });
        request.spec.credentials.grants.push(CredentialGrant {
            name: "openai".into(),
            kind: CredentialGrantKind::FileMount,
            target: host_source.display().to_string(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });
        let contents = "agentbox-test-credential\n";
        request.credential_files.push(RemoteAgentPodCredentialFile {
            name: "openai".into(),
            guest_path: "/workspace/.agentbox/credentials/openai".into(),
            sha256: hex_encode(&Sha256::digest(contents.as_bytes())),
            bytes: contents.len(),
            contents_utf8: contents.into(),
            one_time: true,
            expires_at: None,
        });

        let response = create_session(State(state.clone()), Json(request))
            .await
            .unwrap()
            .0;

        let materialized = workspace.join(".agentbox/credentials/openai");
        assert_eq!(
            std::fs::read_to_string(&materialized).unwrap(),
            "agentbox-test-credential\n"
        );
        let sessions = state.sessions.lock().await;
        let session = sessions.get(&response.worker_session_id).unwrap();
        assert_eq!(session.file_credentials.len(), 1);
        assert_eq!(session.file_credentials[0].name, "openai");
        assert_eq!(session.file_credentials[0].host_path, materialized);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn create_session_rejects_file_credential_without_payload() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[47_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-missing-file-credential-{}",
            std::process::id()
        ));
        let host_source = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-missing-source-credential-{}",
            std::process::id()
        ));
        let mut request = create_session_request(workspace.clone());
        request.spec.filesystem.mounts.push(MountRule {
            host_path: host_source.clone(),
            guest_path: "/workspace/.agentbox/credentials/openai".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::Credential,
        });
        request.spec.credentials.grants.push(CredentialGrant {
            name: "openai".into(),
            kind: CredentialGrantKind::FileMount,
            target: host_source.display().to_string(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });

        let err = create_session(State(state), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("requires a matching payload"));
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn create_session_rejects_file_credential_payload_without_grant() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[48_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-extra-file-credential-{}",
            std::process::id()
        ));
        let mut request = create_session_request(workspace.clone());
        let contents = "agentbox-test-credential\n";
        request.credential_files.push(RemoteAgentPodCredentialFile {
            name: "openai".into(),
            guest_path: "/workspace/.agentbox/credentials/openai".into(),
            sha256: hex_encode(&Sha256::digest(contents.as_bytes())),
            bytes: contents.len(),
            contents_utf8: contents.into(),
            one_time: true,
            expires_at: None,
        });

        let err = create_session(State(state), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("payload without matching grant"));
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn create_session_persists_manifest_approval_grants() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[44_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-approval-workspace-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        let mut request = create_session_request(workspace.clone());
        request.spec.approvals.push(ApprovalGrant {
            id: "grant-git-push".into(),
            scope: ApprovalScope::Command {
                binary: "git".into(),
                args_prefix: vec!["push".into()],
            },
            reason: "operator approved git push".into(),
            expires_at: None,
        });

        let response = create_session(State(state.clone()), Json(request))
            .await
            .unwrap()
            .0;

        let sessions = state.sessions.lock().await;
        let session = sessions.get(&response.worker_session_id).unwrap();
        assert_eq!(session.approval_grants.len(), 1);
        assert_eq!(session.approval_grants[0].id, "grant-git-push");
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn create_session_rejects_unsupported_credential_grants() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[43_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-file-credential-workspace-{}",
            std::process::id()
        ));
        let mut request = create_session_request(workspace.clone());
        request.spec.credentials.grants.push(CredentialGrant {
            name: "deploy-token".into(),
            kind: CredentialGrantKind::ProviderToken,
            target: "vercel".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });

        let err = create_session(State(state.clone()), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err
            .1
             .0
            .error
            .contains("only accepts explicit environment and file"));
        assert!(state.sessions.lock().await.is_empty());
        assert!(!workspace.exists());
    }

    #[tokio::test]
    async fn destroy_session_kills_running_command() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[24_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let request = RemoteAgentPodExecRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            command: ExecCommand {
                argv: vec!["sleep".into(), "5".into()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(30),
            },
        };
        let exec_state = state.clone();
        let exec = tokio::spawn(async move {
            exec_command(State(exec_state), worker_session_path(), Json(request)).await
        });

        time::sleep(std::time::Duration::from_millis(100)).await;
        let destroy = destroy_session(
            State(state),
            worker_session_path(),
            Json(RemoteAgentPodDestroySessionRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                reason: "test kill".into(),
                kill_switch_required: true,
            }),
        )
        .await
        .unwrap()
        .0;
        let response = exec.await.unwrap().unwrap().0;

        assert_eq!(destroy.status, RuntimeStatus::Stopped);
        assert_eq!(response.result.exit_code, 130);
        assert!(response.result.stderr.contains("killed"));
    }

    #[tokio::test]
    async fn restart_session_resumes_stopped_session_for_later_exec() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[41_u8; 32]),
        );
        let state = test_state(config);
        let mut session = WorkerSession::new(
            "session-1".into(),
            std::env::temp_dir(),
            WorkerPolicy::default(),
        );
        session.mark_stopped();
        state
            .sessions
            .lock()
            .await
            .insert("worker-session-1".into(), session);

        let restart = restart_session(
            State(state.clone()),
            worker_session_path(),
            Json(RemoteAgentPodRestartSessionRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                reason: "operator restart".into(),
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(restart.status, RuntimeStatus::Running);
        assert_eq!(restart.restart_attempt, 1);
        assert!(restart
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::WorkerRestarted));
        assert!(restart
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::SessionResumed));

        let exec = exec_command(
            State(state),
            worker_session_path(),
            Json(RemoteAgentPodExecRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                command: ExecCommand {
                    argv: vec!["printf".into(), "restarted".into()],
                    working_dir: None,
                    env: HashMap::new(),
                    timeout_seconds: Some(5),
                },
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(exec.result.exit_code, 0);
        assert_eq!(exec.result.stdout, "restarted");
    }

    #[tokio::test]
    async fn upload_evidence_records_session_receipt() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[26_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let sealed_at = chrono::Utc::now();
        let request = RemoteAgentPodEvidenceUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            evidence_mode: RemoteAgentPodEvidenceMode::BundleUpload,
            bundle_sha256: "a".repeat(64),
            derived_from_bundle: true,
            bundle_id: Some("bundle-1".into()),
            bundle_root_sha256: Some("a".repeat(64)),
            event_count: 7,
            sealed_at,
            secret_material_included: false,
        };

        let response = upload_evidence(State(state.clone()), worker_session_path(), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.accepted_event_count, 7);
        let sessions = state.sessions.lock().await;
        let session = sessions.get("worker-session-1").unwrap();
        assert_eq!(session.evidence_receipts.len(), 1);
        assert_eq!(session.evidence_receipts[0].bundle_sha256, "a".repeat(64));
        assert!(session.evidence_receipts[0].derived_from_bundle);
        assert_eq!(
            session.evidence_receipts[0].bundle_id.as_deref(),
            Some("bundle-1")
        );
        assert_eq!(
            session.evidence_receipts[0].bundle_root_sha256,
            Some("a".repeat(64))
        );
        assert_eq!(session.evidence_receipts[0].event_count, 7);
        assert_eq!(session.evidence_receipts[0].sealed_at, Some(sealed_at));
    }

    #[tokio::test]
    async fn upload_evidence_bundle_stores_hash_verified_payload() {
        let state_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-bundle-state-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&state_dir);
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[34_u8; 32]),
        )
        .with_state_dir(&state_dir);
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let (bundle_json, bundle_sha256) =
            test_evidence_bundle_upload_json("session-1", "worker-session-1");
        let request = WorkerEvidenceBundleUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            bundle_sha256: bundle_sha256.clone(),
            bundle_json: bundle_json.clone(),
            secret_material_included: false,
        };

        let response =
            upload_evidence_bundle(State(state.clone()), worker_session_path(), Json(request))
                .await
                .unwrap()
                .0;

        assert_eq!(response.stored_bundle_sha256, bundle_sha256);
        assert_eq!(response.stored_bytes, bundle_json.len() as u64);
        assert_eq!(
            std::fs::read_to_string(response.storage_path).unwrap(),
            bundle_json
        );
        let sessions = state.sessions.lock().await;
        let session = sessions.get("worker-session-1").unwrap();
        assert_eq!(session.stored_evidence_bundles.len(), 1);
        assert_eq!(
            session.stored_evidence_bundles[0].bundle_sha256,
            bundle_sha256
        );
        assert_eq!(
            session.stored_evidence_bundles[0].stored_bytes,
            bundle_json.len() as u64
        );
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn evidence_status_reports_receipts_and_stored_bundles() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[38_u8; 32]),
        );
        let state = test_state(config);
        let sealed_at = chrono::Utc::now();
        let mut session = WorkerSession::new(
            "session-1".into(),
            std::env::temp_dir(),
            WorkerPolicy::default(),
        );
        session.commands_started = 2;
        session.commands_finished = 1;
        session.active_command_count = 1;
        session.last_command_exit_code = Some(0);
        session.last_command_finished_at = Some(sealed_at);
        session.evidence_receipts.push(WorkerEvidenceReceipt {
            bundle_sha256: "c".repeat(64),
            derived_from_bundle: true,
            bundle_id: Some("bundle-status".into()),
            bundle_root_sha256: Some("c".repeat(64)),
            event_count: 3,
            sealed_at: Some(sealed_at),
        });
        session
            .stored_evidence_bundles
            .push(WorkerStoredEvidenceBundle {
                bundle_sha256: "c".repeat(64),
                stored_bytes: 42,
                storage_path: PathBuf::from("/tmp/evidence/worker-session-1/bundle.json"),
            });
        session.evidence_streams.insert(
            "stdout".into(),
            WorkerEvidenceStream {
                stream_id: "stdout".into(),
                next_sequence: 2,
                next_offset: 12,
                received_bytes: 12,
                chunks: 2,
                sealed: true,
                stream_sha256: Some(sha256_hex(b"hello world\n")),
                updated_at: Some(sealed_at),
                contents_utf8: "hello world\n".into(),
            },
        );
        session.pending_approvals.push(WorkerPendingApproval {
            request_id: "approval-status".into(),
            command_argv: vec!["curl".into(), "https://approval.example.com".into()],
            reason: "first contact requires approval".into(),
            created_at: sealed_at,
        });
        session.env_credentials.push(WorkerEnvCredentialGrant {
            name: "OPENAI_API_KEY".into(),
            one_time: false,
        });
        session.file_credentials.push(WorkerFileCredentialGrant {
            name: "openai".into(),
            guest_path: "/workspace/.agentbox/credentials/openai".into(),
            host_path: PathBuf::from("/tmp/workspace/.agentbox/credentials/openai"),
            sha256: "d".repeat(64),
            bytes: 31,
            one_time: true,
        });
        state
            .sessions
            .lock()
            .await
            .insert("worker-session-1".into(), session);

        let response = evidence_status(
            State(state),
            AxumPath("worker-session-1".into()),
            Query(WorkerEvidenceStatusQuery {
                session_id: "session-1".into(),
                after_sequence: None,
                limit: None,
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(response.session_id, "session-1");
        assert_eq!(response.worker_session_id, "worker-session-1");
        assert_eq!(response.event_stream.delivery, "http-polling-contract");
        assert!(response
            .event_stream
            .lifecycle_stream_id
            .contains("worker-session-1"));
        assert!(response
            .event_stream
            .claim_boundary
            .contains("not a live bidirectional event bus"));
        assert_eq!(response.status, RuntimeStatus::Running);
        assert_eq!(response.commands_started, 2);
        assert_eq!(response.commands_finished, 1);
        assert_eq!(response.active_command_count, 1);
        assert_eq!(response.last_command_exit_code, Some(0));
        assert_eq!(response.last_command_finished_at, Some(sealed_at));
        assert_eq!(
            response.restart_policy,
            RemoteAgentPodRestartPolicy::default()
        );
        assert_eq!(response.heartbeat_interval_seconds, 30);
        assert!(response.last_heartbeat_at.is_some());
        assert!(response.kill_switch_armed);
        assert!(response.evidence_sealed);
        assert_eq!(response.evidence_receipts.len(), 1);
        assert_eq!(response.evidence_receipts[0].event_count, 3);
        assert_eq!(
            response.evidence_receipts[0].bundle_id.as_deref(),
            Some("bundle-status")
        );
        assert_eq!(response.stored_evidence_bundles.len(), 1);
        assert_eq!(response.stored_evidence_bundles[0].stored_bytes, 42);
        assert_eq!(response.evidence_streams.len(), 1);
        assert_eq!(response.evidence_streams[0].stream_id, "stdout");
        assert_eq!(response.evidence_streams[0].next_sequence, 2);
        assert_eq!(response.evidence_streams[0].next_offset, 12);
        assert_eq!(response.evidence_streams[0].received_bytes, 12);
        assert!(response.evidence_streams[0].sealed);
        assert_eq!(
            response.evidence_streams[0].stream_sha256.as_deref(),
            Some(sha256_hex(b"hello world\n").as_str())
        );
        assert_eq!(response.pending_approvals.len(), 1);
        assert_eq!(response.pending_approvals[0].request_id, "approval-status");
        assert_eq!(
            response.pending_approvals[0].command_argv,
            vec!["curl", "https://approval.example.com"]
        );
        let approval_prompt = &response.pending_approvals[0].prompt;
        assert_eq!(approval_prompt.schema_version, 1);
        assert!(approval_prompt
            .approve_command
            .contains("agentbox remote-approval-grant"));
        assert!(approval_prompt
            .approve_command
            .contains("--session session-1"));
        assert!(approval_prompt
            .approve_command
            .contains("--worker-session worker-session-1"));
        assert!(approval_prompt.approve_command.contains("approval-status"));
        assert!(approval_prompt
            .claim_boundary
            .contains("interactive remote approval UI is not wired"));
        assert_eq!(response.credentials.len(), 2);
        assert_eq!(response.credentials[0].name, "OPENAI_API_KEY");
        assert_eq!(response.credentials[0].kind, CredentialGrantKind::EnvVar);
        assert_eq!(response.credentials[0].sha256, None);
        assert_eq!(response.credentials[1].name, "openai");
        assert_eq!(response.credentials[1].kind, CredentialGrantKind::FileMount);
        assert_eq!(
            response.credentials[1].guest_path.as_deref(),
            Some("/workspace/.agentbox/credentials/openai")
        );
        let file_credential_hash = "d".repeat(64);
        assert_eq!(
            response.credentials[1].sha256.as_deref(),
            Some(file_credential_hash.as_str())
        );
        assert_eq!(response.credentials[1].bytes, Some(31));
        assert!(response.credentials[1].one_time);
        assert_eq!(response.supervision.boot_count, 1);
        assert_eq!(response.supervision.recovered_sessions, 0);
        assert_eq!(
            response.supervision.persistence,
            WorkerSupervisionPersistence::MemoryOnly
        );
    }

    #[tokio::test]
    async fn lifecycle_events_support_cursor_and_limit() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[78_u8; 32]),
        );
        let state = test_state(config);
        let mut session = WorkerSession::new(
            "session-1".into(),
            std::env::temp_dir(),
            WorkerPolicy::default(),
        );
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::WorkerAllocated,
            Some("allocated".into()),
        );
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::SessionCreated,
            Some("created".into()),
        );
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::CommandStarted,
            Some("started".into()),
        );
        session.record_lifecycle_event(
            RemoteAgentPodLifecycleEvent::CommandFinished,
            Some("finished".into()),
        );
        state
            .sessions
            .lock()
            .await
            .insert("worker-session-1".into(), session);

        let response = lifecycle_events(
            State(state),
            AxumPath("worker-session-1".into()),
            Query(WorkerEvidenceStatusQuery {
                session_id: "session-1".into(),
                after_sequence: Some(2),
                limit: Some(1),
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(response.returned_count, 1);
        assert!(response.has_more);
        assert_eq!(response.next_sequence, 4);
        assert_eq!(response.events[0].sequence, 3);
        assert_eq!(
            response.events[0].event,
            RemoteAgentPodLifecycleEvent::CommandStarted
        );
    }

    #[tokio::test]
    async fn worker_status_reports_supervision_state() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[39_u8; 32]),
        );
        let state = test_state(config);

        let response = worker_status(State(state)).await.0;

        assert_eq!(response.boot_count, 1);
        assert_eq!(response.recovered_sessions, 0);
        assert_eq!(
            response.persistence,
            WorkerSupervisionPersistence::MemoryOnly
        );
        assert!(response.boot_id.starts_with("worker-"));
    }

    #[test]
    fn supervision_state_persists_boot_count_for_state_dir() {
        let state_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-supervision-state-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&state_dir);
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[40_u8; 32]),
        )
        .with_state_dir(&state_dir);

        let first = load_or_initialize_supervision(&config, 0).unwrap();
        let second = load_or_initialize_supervision(&config, 2).unwrap();

        assert_eq!(first.boot_count, 1);
        assert_eq!(second.boot_count, 2);
        assert_eq!(
            second.previous_boot_id.as_deref(),
            Some(first.boot_id.as_str())
        );
        assert_eq!(second.recovered_sessions, 2);
        assert_eq!(second.persistence, WorkerSupervisionPersistence::StateDir);
        assert!(worker_supervision_path(&config).unwrap().exists());
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn upload_evidence_stream_accepts_ordered_chunks_and_seals_hash() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[46_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );

        let first = upload_evidence_stream_chunk(
            State(state.clone()),
            worker_session_path(),
            Json(RemoteAgentPodEvidenceStreamChunkRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                stream_id: "stdout".into(),
                sequence: 0,
                offset: 0,
                chunk_sha256: sha256_hex(b"hello "),
                chunk_bytes: 6,
                chunk_utf8: "hello ".into(),
                final_chunk: false,
                secret_material_included: false,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(first.accepted_sequence, 0);
        assert_eq!(first.accepted_offset, 0);
        assert!(first.stream_sha256.is_none());

        let second = upload_evidence_stream_chunk(
            State(state.clone()),
            worker_session_path(),
            Json(RemoteAgentPodEvidenceStreamChunkRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                stream_id: "stdout".into(),
                sequence: 1,
                offset: 6,
                chunk_sha256: sha256_hex(b"world\n"),
                chunk_bytes: 6,
                chunk_utf8: "world\n".into(),
                final_chunk: true,
                secret_material_included: false,
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(
            second.stream_sha256.as_deref(),
            Some(sha256_hex(b"hello world\n").as_str())
        );
        let sessions = state.sessions.lock().await;
        let stream = sessions
            .get("worker-session-1")
            .unwrap()
            .evidence_streams
            .get("stdout")
            .unwrap();
        assert_eq!(stream.next_sequence, 2);
        assert_eq!(stream.next_offset, 12);
        assert_eq!(stream.received_bytes, 12);
        assert_eq!(stream.chunks, 2);
        assert!(stream.sealed);
    }

    #[tokio::test]
    async fn upload_evidence_stream_rejects_out_of_order_and_sealed_writes() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[47_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let out_of_order = upload_evidence_stream_chunk(
            State(state.clone()),
            worker_session_path(),
            Json(RemoteAgentPodEvidenceStreamChunkRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                stream_id: "stdout".into(),
                sequence: 1,
                offset: 0,
                chunk_sha256: sha256_hex(b"late"),
                chunk_bytes: 4,
                chunk_utf8: "late".into(),
                final_chunk: false,
                secret_material_included: false,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(out_of_order.0, StatusCode::CONFLICT);

        let _ = upload_evidence_stream_chunk(
            State(state.clone()),
            worker_session_path(),
            Json(RemoteAgentPodEvidenceStreamChunkRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                stream_id: "stdout".into(),
                sequence: 0,
                offset: 0,
                chunk_sha256: sha256_hex(b"done"),
                chunk_bytes: 4,
                chunk_utf8: "done".into(),
                final_chunk: true,
                secret_material_included: false,
            }),
        )
        .await
        .unwrap();

        let sealed = upload_evidence_stream_chunk(
            State(state),
            worker_session_path(),
            Json(RemoteAgentPodEvidenceStreamChunkRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                stream_id: "stdout".into(),
                sequence: 1,
                offset: 4,
                chunk_sha256: sha256_hex(b"again"),
                chunk_bytes: 5,
                chunk_utf8: "again".into(),
                final_chunk: false,
                secret_material_included: false,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(sealed.0, StatusCode::CONFLICT);
        assert!(sealed.1 .0.error.contains("already sealed"));
    }

    #[tokio::test]
    async fn evidence_status_rejects_session_id_mismatch() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[39_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );

        let err = evidence_status(
            State(state),
            AxumPath("worker-session-1".into()),
            Query(WorkerEvidenceStatusQuery {
                session_id: "other-session".into(),
                after_sequence: None,
                limit: None,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn upload_evidence_bundle_rejects_hash_mismatch() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[35_u8; 32]),
        )
        .with_state_dir(std::env::temp_dir());
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let request = WorkerEvidenceBundleUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            bundle_sha256: "0".repeat(64),
            bundle_json: "{}".into(),
            secret_material_included: false,
        };

        let err = upload_evidence_bundle(State(state), worker_session_path(), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("hash does not match"));
    }

    #[tokio::test]
    async fn upload_evidence_bundle_rejects_non_envelope_payload() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[40_u8; 32]),
        )
        .with_state_dir(std::env::temp_dir());
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new(
                "session-1".into(),
                std::env::temp_dir(),
                WorkerPolicy::default(),
            ),
        );
        let bundle_json = "{}".to_string();
        let request = WorkerEvidenceBundleUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            bundle_sha256: sha256_hex(bundle_json.as_bytes()),
            bundle_json,
            secret_material_included: false,
        };

        let err = upload_evidence_bundle(State(state), worker_session_path(), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("not valid JSON"));
    }

    #[tokio::test]
    async fn upload_evidence_rejects_unknown_session() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[28_u8; 32]),
        );
        let state = test_state(config);
        let request = RemoteAgentPodEvidenceUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            evidence_mode: RemoteAgentPodEvidenceMode::BundleUpload,
            bundle_sha256: "a".repeat(64),
            derived_from_bundle: false,
            bundle_id: None,
            bundle_root_sha256: None,
            event_count: 7,
            sealed_at: chrono::Utc::now(),
            secret_material_included: false,
        };

        let err = upload_evidence(State(state), worker_session_path(), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert!(err.1 .0.error.contains("has not been created"));
    }

    #[tokio::test]
    async fn destroy_session_rejects_unknown_session() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[29_u8; 32]),
        );
        let state = test_state(config);

        let err = destroy_session(
            State(state),
            worker_session_path(),
            Json(RemoteAgentPodDestroySessionRequest {
                session_id: "session-1".into(),
                worker_session_id: "worker-session-1".into(),
                reason: "test missing".into(),
                kill_switch_required: true,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert!(err.1 .0.error.contains("has not been created"));
    }

    #[tokio::test]
    async fn worker_state_persists_sessions_and_evidence_receipts() {
        let path = state_file("roundtrip");
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[27_u8; 32]),
        )
        .with_state_dir(&path);
        let state = test_state(config.clone());
        let mut session = WorkerSession::new(
            "session-1".into(),
            std::env::temp_dir(),
            WorkerPolicy::default(),
        );
        let sealed_at = chrono::Utc::now();
        session.evidence_receipts.push(WorkerEvidenceReceipt {
            bundle_sha256: "b".repeat(64),
            derived_from_bundle: true,
            bundle_id: Some("bundle-state".into()),
            bundle_root_sha256: Some("b".repeat(64)),
            event_count: 5,
            sealed_at: Some(sealed_at),
        });
        session
            .stored_evidence_bundles
            .push(WorkerStoredEvidenceBundle {
                bundle_sha256: "b".repeat(64),
                stored_bytes: 128,
                storage_path: path.join("evidence/worker-session-1/bundle.json"),
            });
        session.mark_stopped();
        state
            .sessions
            .lock()
            .await
            .insert("worker-session-1".into(), session);

        persist_sessions(&state).await.unwrap();
        let loaded = load_persisted_sessions(&config).unwrap();

        let session = loaded.get("worker-session-1").unwrap();
        assert_eq!(session.session_id, "session-1");
        assert_eq!(session.status, RuntimeStatus::Stopped);
        assert_eq!(session.evidence_receipts.len(), 1);
        assert_eq!(session.evidence_receipts[0].bundle_sha256, "b".repeat(64));
        assert!(session.evidence_receipts[0].derived_from_bundle);
        assert_eq!(
            session.evidence_receipts[0].bundle_id.as_deref(),
            Some("bundle-state")
        );
        assert_eq!(
            session.evidence_receipts[0].bundle_root_sha256,
            Some("b".repeat(64))
        );
        assert_eq!(session.evidence_receipts[0].event_count, 5);
        assert_eq!(session.evidence_receipts[0].sealed_at, Some(sealed_at));
        assert_eq!(session.stored_evidence_bundles.len(), 1);
        assert_eq!(
            session.stored_evidence_bundles[0].bundle_sha256,
            "b".repeat(64)
        );
        assert_eq!(session.stored_evidence_bundles[0].stored_bytes, 128);
        assert!(session.stored_evidence_bundles[0]
            .storage_path
            .ends_with("evidence/worker-session-1/bundle.json"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn create_session_reports_state_persistence_failures() {
        let state_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-state-file-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&state_dir);
        let _ = std::fs::remove_file(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[37_u8; 32]),
        )
        .with_state_dir(&state_dir);
        let state = test_state(config);
        let request = create_session_request(std::env::temp_dir());

        let err = create_session(State(state), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(err.1 .0.error.contains("could not persist session state"));
        let _ = std::fs::remove_dir_all(state_dir);
    }
}
