use std::net::SocketAddr;
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
use axum::routing::post;
use axum::{Json, Router};
use chrono::Duration;
use ed25519_dalek::{Signer, SigningKey};
use tokio::process::Command;
use tokio::time;

#[derive(Clone)]
pub struct RemoteWorkerConfig {
    pub worker_identity: String,
    pub evidence_endpoint: String,
    pub signing_key: SigningKey,
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
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.signing_key.verifying_key().to_bytes())
    }
}

#[derive(Clone)]
struct RemoteWorkerState {
    config: RemoteWorkerConfig,
}

pub fn router(config: RemoteWorkerConfig) -> Router {
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
        .with_state(Arc::new(RemoteWorkerState { config }))
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
    Json(request): Json<RemoteAgentPodCreateSessionRequest>,
) -> Json<RemoteAgentPodCreateSessionResponse> {
    Json(RemoteAgentPodCreateSessionResponse {
        session_id: request.spec.id.clone(),
        worker_session_id: format!("worker-{}", request.spec.id),
        status: RuntimeStatus::Running,
        lifecycle_events: vec![
            RemoteAgentPodLifecycleEvent::WorkerAllocated,
            RemoteAgentPodLifecycleEvent::SessionCreated,
        ],
    })
}

async fn exec_command(
    Json(request): Json<RemoteAgentPodExecRequest>,
) -> Json<RemoteAgentPodExecResponse> {
    let started = Instant::now();
    let result = execute_command(request, started).await;
    Json(RemoteAgentPodExecResponse {
        result,
        lifecycle_events: vec![
            RemoteAgentPodLifecycleEvent::CommandStarted,
            RemoteAgentPodLifecycleEvent::CommandFinished,
            RemoteAgentPodLifecycleEvent::EvidenceSealed,
        ],
    })
}

async fn execute_command(request: RemoteAgentPodExecRequest, started: Instant) -> CommandResult {
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
    if let Some(working_dir) = &request.command.working_dir {
        command.current_dir(working_dir);
    }
    command.kill_on_drop(true);

    let output = if let Some(timeout_seconds) = request.command.timeout_seconds {
        match time::timeout(
            std::time::Duration::from_secs(timeout_seconds),
            command.output(),
        )
        .await
        {
            Ok(output) => output,
            Err(_) => {
                return CommandResult {
                    exit_code: 124,
                    stdout: String::new(),
                    stderr: format!(
                        "agentbox remote worker command timed out after {timeout_seconds}s"
                    ),
                    duration_ms: elapsed_ms(started),
                };
            }
        }
    } else {
        command.output().await
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

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

async fn upload_evidence(
    Json(request): Json<RemoteAgentPodEvidenceUploadRequest>,
) -> Json<RemoteAgentPodEvidenceUploadResponse> {
    Json(RemoteAgentPodEvidenceUploadResponse {
        session_id: request.session_id,
        worker_session_id: request.worker_session_id,
        accepted_bundle_sha256: request.bundle_sha256,
        accepted_event_count: request.event_count,
        lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
    })
}

async fn destroy_session(
    Json(request): Json<RemoteAgentPodDestroySessionRequest>,
) -> Json<RemoteAgentPodDestroySessionResponse> {
    Json(RemoteAgentPodDestroySessionResponse {
        session_id: request.session_id,
        worker_session_id: request.worker_session_id,
        status: RuntimeStatus::Stopped,
        lifecycle_events: vec![
            RemoteAgentPodLifecycleEvent::KillSwitchAck,
            RemoteAgentPodLifecycleEvent::WorkerDestroyed,
        ],
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
        Ed25519HandshakeVerifier, RemoteAgentPodAuthKind, RemoteAgentPodHandshakeVerifier,
    };
    use agentbox_daemon::runtime::types::ExecCommand;
    use std::collections::HashMap;

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

        let Json(ack) = handshake(
            State(Arc::new(RemoteWorkerState { config })),
            Json(descriptor.clone()),
        )
        .await;

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

        let response = exec_command(Json(request)).await.0;

        assert_eq!(response.result.exit_code, 0);
        assert_eq!(response.result.stdout, "hello-agentbox");
        assert!(response.result.stderr.is_empty());
        assert!(response
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::EvidenceSealed));
    }

    #[tokio::test]
    async fn exec_command_rejects_empty_argv() {
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

        let response = exec_command(Json(request)).await.0;

        assert_eq!(response.result.exit_code, 127);
        assert!(response.result.stderr.contains("empty argv"));
    }
}
