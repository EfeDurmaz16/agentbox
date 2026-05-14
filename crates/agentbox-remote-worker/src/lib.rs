use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use agentbox_daemon::runtime::providers::remote::{
    Ed25519HandshakeVerifier, RemoteAgentPodCreateSessionRequest,
    RemoteAgentPodCreateSessionResponse, RemoteAgentPodDestroySessionRequest,
    RemoteAgentPodDestroySessionResponse, RemoteAgentPodEvidenceUploadRequest,
    RemoteAgentPodEvidenceUploadResponse, RemoteAgentPodExecRequest, RemoteAgentPodExecResponse,
    RemoteAgentPodHandshakeAck, RemoteAgentPodHandshakeDescriptor, RemoteAgentPodLifecycleEvent,
    RemoteAgentPodWorkspaceBundle, RemoteAgentPodWorkspaceExportResponse,
    RemoteAgentPodWorkspaceFile,
};
use agentbox_daemon::runtime::types::{
    CommandResult, NetworkMode, RuntimeCapability, RuntimeStatus,
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
    sessions: Mutex<HashMap<String, WorkerSession>>,
}

#[derive(Clone)]
struct WorkerSession {
    session_id: String,
    workspace_host_path: PathBuf,
    policy: WorkerPolicy,
    status: RuntimeStatus,
    kill_tx: watch::Sender<bool>,
    evidence_receipts: Vec<WorkerEvidenceReceipt>,
    stored_evidence_bundles: Vec<WorkerStoredEvidenceBundle>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerSessionSnapshot {
    session_id: String,
    worker_session_id: String,
    #[serde(default = "default_worker_workspace")]
    workspace_host_path: PathBuf,
    #[serde(default)]
    policy: WorkerPolicy,
    status: RuntimeStatus,
    evidence_receipts: Vec<WorkerEvidenceReceiptSnapshot>,
    #[serde(default)]
    stored_evidence_bundles: Vec<WorkerStoredEvidenceBundleSnapshot>,
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
}

#[derive(Debug, Clone, Serialize)]
struct WorkerEvidenceStatusResponse {
    session_id: String,
    worker_session_id: String,
    status: RuntimeStatus,
    evidence_receipts: Vec<WorkerEvidenceReceiptSnapshot>,
    stored_evidence_bundles: Vec<WorkerStoredEvidenceBundleSnapshot>,
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
    fn new(session_id: String, workspace_host_path: PathBuf, policy: WorkerPolicy) -> Self {
        let (kill_tx, _kill_rx) = watch::channel(false);
        Self {
            session_id,
            workspace_host_path,
            policy,
            status: RuntimeStatus::Running,
            kill_tx,
            evidence_receipts: Vec::new(),
            stored_evidence_bundles: Vec::new(),
        }
    }

    fn kill_receiver(&self) -> watch::Receiver<bool> {
        self.kill_tx.subscribe()
    }

    fn mark_stopped(&mut self) {
        self.status = RuntimeStatus::Stopped;
        let _ = self.kill_tx.send(true);
    }

    fn from_snapshot(snapshot: WorkerSessionSnapshot) -> Self {
        let (kill_tx, _kill_rx) = watch::channel(matches!(snapshot.status, RuntimeStatus::Stopped));
        Self {
            session_id: snapshot.session_id,
            workspace_host_path: snapshot.workspace_host_path,
            policy: snapshot.policy,
            status: snapshot.status,
            kill_tx,
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
        }
    }

    fn to_snapshot(&self, worker_session_id: String) -> WorkerSessionSnapshot {
        WorkerSessionSnapshot {
            session_id: self.session_id.clone(),
            worker_session_id,
            workspace_host_path: self.workspace_host_path.clone(),
            policy: self.policy.clone(),
            status: self.status.clone(),
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
        }
    }
}

fn default_worker_workspace() -> PathBuf {
    PathBuf::from(".")
}

pub fn router(config: RemoteWorkerConfig) -> Router {
    let sessions = load_persisted_sessions(&config).unwrap_or_default();
    Router::new()
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
            "/sessions/{worker_session_id}/evidence/bundle",
            post(upload_evidence_bundle),
        )
        .route(
            "/sessions/{worker_session_id}/workspace/export",
            get(export_workspace),
        )
        .route(
            "/sessions/{worker_session_id}/destroy",
            post(destroy_session),
        )
        .with_state(Arc::new(RemoteWorkerState {
            config,
            sessions: Mutex::new(sessions),
        }))
}

pub async fn serve(addr: SocketAddr, config: RemoteWorkerConfig) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(config)).await
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
    let workspace_host_path = request.spec.filesystem.workspace_host_path.clone();
    prepare_worker_workspace(&workspace_host_path).await?;
    if let Some(bundle) = request.workspace_bundle.as_ref() {
        materialize_worker_workspace_bundle(&workspace_host_path, bundle).await?;
    }
    let session = WorkerSession::new(
        request.spec.id.clone(),
        workspace_host_path,
        WorkerPolicy::from_spec(&request.spec),
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

fn validate_create_material(
    request: &RemoteAgentPodCreateSessionRequest,
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    if request.spec.credentials.inherit_host_env || !request.spec.credentials.grants.is_empty() {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker refuses credential grants until credential handoff is implemented",
        ));
    }
    Ok(())
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
    Json(request): Json<RemoteAgentPodExecRequest>,
) -> WorkerRouteResult<RemoteAgentPodExecResponse> {
    let started = Instant::now();
    validate_exec_material(&request)?;
    let context = session_exec_context(&state, &request).await?;
    let result = execute_command(request, started, context).await;
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
) -> Result<(), (StatusCode, Json<WorkerError>)> {
    if !request.command.env.is_empty() {
        return Err(worker_error(
            StatusCode::BAD_REQUEST,
            "agentbox remote worker refuses command environment material until credential handoff is implemented",
        ));
    }
    Ok(())
}

struct WorkerExecContext {
    kill_rx: watch::Receiver<bool>,
    workspace_host_path: PathBuf,
    policy: WorkerPolicy,
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
        workspace_host_path: session.workspace_host_path.clone(),
        policy: session.policy.clone(),
    })
}

async fn execute_command(
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
    if let Some(result) = enforce_worker_policy(&request, &context, &working_dir, started) {
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

fn enforce_worker_policy(
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
    Json(request): Json<RemoteAgentPodEvidenceUploadRequest>,
) -> WorkerRouteResult<RemoteAgentPodEvidenceUploadResponse> {
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
    Json(request): Json<WorkerEvidenceBundleUploadRequest>,
) -> WorkerRouteResult<WorkerEvidenceBundleUploadResponse> {
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
        worker_session_id,
        status: session.status.clone(),
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
    drop(sessions);
    persist_sessions(state).await.map_err(worker_state_error)?;
    Ok(receipt)
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
    Json(request): Json<RemoteAgentPodDestroySessionRequest>,
) -> WorkerRouteResult<RemoteAgentPodDestroySessionResponse> {
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
        Ed25519HandshakeVerifier, RemoteAgentPodAuthKind, RemoteAgentPodDestroySessionRequest,
        RemoteAgentPodEvidenceMode, RemoteAgentPodHandshakeVerifier,
        RemoteAgentPodTransportDescriptor, RemoteAgentPodWorkspaceBundle,
    };
    use agentbox_daemon::runtime::types::{
        CredentialGrant, CredentialGrantKind, ExecCommand, MinipodSpec,
    };
    use std::collections::HashMap;

    fn test_state(config: RemoteWorkerConfig) -> Arc<RemoteWorkerState> {
        Arc::new(RemoteWorkerState {
            config,
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

        let response = exec_command(State(state), Json(request)).await.unwrap().0;

        assert_eq!(response.result.exit_code, 0);
        assert_eq!(response.result.stdout, "hello-agentbox");
        assert!(response.result.stderr.is_empty());
        assert!(response
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::EvidenceSealed));
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

        let response = exec_command(State(state), Json(request)).await.unwrap().0;

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

        let err = exec_command(State(state), Json(request)).await.unwrap_err();

        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert!(err.1 .0.error.contains("has not been created"));
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

        let response = exec_command(State(state), Json(request)).await.unwrap().0;

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

        let err = exec_command(State(state), Json(request)).await.unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("credential handoff"));
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

        let response = exec_command(State(state), Json(request)).await.unwrap().0;

        assert_eq!(response.result.exit_code, 126);
        assert!(response.result.stderr.contains("policy denied"));
        assert!(response.result.stderr.contains("unknown.example.com"));
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
    async fn create_session_materializes_workspace_bundle() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[32_u8; 32]),
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
    async fn create_session_rejects_credential_grants() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[33_u8; 32]),
        );
        let state = test_state(config);
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-worker-credential-workspace-{}",
            std::process::id()
        ));
        let mut request = create_session_request(workspace.clone());
        request.spec.credentials.grants.push(CredentialGrant {
            name: "OPENAI_API_KEY".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "OPENAI_API_KEY".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });

        let err = create_session(State(state.clone()), Json(request))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("credential handoff"));
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
        let exec =
            tokio::spawn(async move { exec_command(State(exec_state), Json(request)).await });

        time::sleep(std::time::Duration::from_millis(100)).await;
        let destroy = destroy_session(
            State(state),
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

        let response = upload_evidence(State(state.clone()), Json(request))
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

        let response = upload_evidence_bundle(State(state.clone()), Json(request))
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
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(response.session_id, "session-1");
        assert_eq!(response.worker_session_id, "worker-session-1");
        assert_eq!(response.status, RuntimeStatus::Running);
        assert_eq!(response.evidence_receipts.len(), 1);
        assert_eq!(response.evidence_receipts[0].event_count, 3);
        assert_eq!(
            response.evidence_receipts[0].bundle_id.as_deref(),
            Some("bundle-status")
        );
        assert_eq!(response.stored_evidence_bundles.len(), 1);
        assert_eq!(response.stored_evidence_bundles[0].stored_bytes, 42);
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

        let err = upload_evidence_bundle(State(state), Json(request))
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

        let err = upload_evidence_bundle(State(state), Json(request))
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

        let err = upload_evidence(State(state), Json(request))
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
