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
};
use agentbox_daemon::runtime::types::{CommandResult, RuntimeCapability, RuntimeStatus};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use chrono::Duration;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
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
    status: RuntimeStatus,
    kill_tx: watch::Sender<bool>,
    evidence_receipts: Vec<WorkerEvidenceReceipt>,
}

#[derive(Clone)]
struct WorkerEvidenceReceipt {
    bundle_sha256: String,
    event_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerSessionSnapshot {
    session_id: String,
    worker_session_id: String,
    #[serde(default = "default_worker_workspace")]
    workspace_host_path: PathBuf,
    status: RuntimeStatus,
    evidence_receipts: Vec<WorkerEvidenceReceiptSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerEvidenceReceiptSnapshot {
    bundle_sha256: String,
    event_count: u64,
}

#[derive(Debug, Clone, Serialize)]
struct WorkerError {
    error: String,
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

impl WorkerSession {
    fn new(session_id: String, workspace_host_path: PathBuf) -> Self {
        let (kill_tx, _kill_rx) = watch::channel(false);
        Self {
            session_id,
            workspace_host_path,
            status: RuntimeStatus::Running,
            kill_tx,
            evidence_receipts: Vec::new(),
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
            status: snapshot.status,
            kill_tx,
            evidence_receipts: snapshot
                .evidence_receipts
                .into_iter()
                .map(|receipt| WorkerEvidenceReceipt {
                    bundle_sha256: receipt.bundle_sha256,
                    event_count: receipt.event_count,
                })
                .collect(),
        }
    }

    fn to_snapshot(&self, worker_session_id: String) -> WorkerSessionSnapshot {
        WorkerSessionSnapshot {
            session_id: self.session_id.clone(),
            worker_session_id,
            workspace_host_path: self.workspace_host_path.clone(),
            status: self.status.clone(),
            evidence_receipts: self
                .evidence_receipts
                .iter()
                .map(|receipt| WorkerEvidenceReceiptSnapshot {
                    bundle_sha256: receipt.bundle_sha256.clone(),
                    event_count: receipt.event_count,
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
    let worker_session_id = format!("worker-{}", request.spec.id);
    let workspace_host_path = request.spec.filesystem.workspace_host_path.clone();
    prepare_worker_workspace(&workspace_host_path).await?;
    let session = WorkerSession::new(request.spec.id.clone(), workspace_host_path);
    state
        .sessions
        .lock()
        .await
        .insert(worker_session_id.clone(), session);
    persist_sessions(&state).await;
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

async fn accept_evidence(
    state: &Arc<RemoteWorkerState>,
    request: &RemoteAgentPodEvidenceUploadRequest,
) -> Result<WorkerEvidenceReceipt, (StatusCode, Json<WorkerError>)> {
    request
        .validate()
        .map_err(|err| worker_error(StatusCode::BAD_REQUEST, err.to_string()))?;
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
    let receipt = WorkerEvidenceReceipt {
        bundle_sha256: request.bundle_sha256.clone(),
        event_count: request.event_count,
    };
    session.evidence_receipts.push(receipt.clone());
    drop(sessions);
    persist_sessions(state).await;
    Ok(receipt)
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
    persist_sessions(&state).await;
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

async fn persist_sessions(state: &Arc<RemoteWorkerState>) {
    let Some(path) = worker_state_path(&state.config) else {
        return;
    };
    let snapshots = {
        let sessions = state.sessions.lock().await;
        sessions
            .iter()
            .map(|(worker_session_id, session)| session.to_snapshot(worker_session_id.clone()))
            .collect::<Vec<_>>()
    };
    let Ok(contents) = serde_json::to_string_pretty(&snapshots) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let _ = tokio::fs::write(path, contents).await;
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
        RemoteAgentPodTransportDescriptor,
    };
    use agentbox_daemon::runtime::types::{ExecCommand, MinipodSpec};
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
            WorkerSession::new("session-1".into(), std::env::temp_dir()),
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
            WorkerSession::new("session-1".into(), std::env::temp_dir()),
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
            WorkerSession::new("session-1".into(), workspace),
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
            WorkerSession::new("session-1".into(), std::env::temp_dir()),
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
    async fn destroy_session_kills_running_command() {
        let config = RemoteWorkerConfig::new(
            "worker.local/dev",
            "https://worker.example.com/agentpod/evidence",
            SigningKey::from_bytes(&[24_u8; 32]),
        );
        let state = test_state(config);
        state.sessions.lock().await.insert(
            "worker-session-1".into(),
            WorkerSession::new("session-1".into(), std::env::temp_dir()),
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
            WorkerSession::new("session-1".into(), std::env::temp_dir()),
        );
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

        let response = upload_evidence(State(state.clone()), Json(request))
            .await
            .unwrap()
            .0;

        assert_eq!(response.accepted_event_count, 7);
        let sessions = state.sessions.lock().await;
        let session = sessions.get("worker-session-1").unwrap();
        assert_eq!(session.evidence_receipts.len(), 1);
        assert_eq!(session.evidence_receipts[0].bundle_sha256, "a".repeat(64));
        assert_eq!(session.evidence_receipts[0].event_count, 7);
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
        let mut session = WorkerSession::new("session-1".into(), std::env::temp_dir());
        session.evidence_receipts.push(WorkerEvidenceReceipt {
            bundle_sha256: "b".repeat(64),
            event_count: 5,
        });
        session.mark_stopped();
        state
            .sessions
            .lock()
            .await
            .insert("worker-session-1".into(), session);

        persist_sessions(&state).await;
        let loaded = load_persisted_sessions(&config).unwrap();

        let session = loaded.get("worker-session-1").unwrap();
        assert_eq!(session.session_id, "session-1");
        assert_eq!(session.status, RuntimeStatus::Stopped);
        assert_eq!(session.evidence_receipts.len(), 1);
        assert_eq!(session.evidence_receipts[0].bundle_sha256, "b".repeat(64));
        assert_eq!(session.evidence_receipts[0].event_count, 5);
        let _ = std::fs::remove_file(path);
    }
}
