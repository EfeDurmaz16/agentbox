use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime::bridge::HostBridgeTransportKind;
use crate::runtime::provider::{
    ProviderFamily, ProviderImplementationStatus, RuntimeError, RuntimeProvider,
};
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteAgentPodAuthKind {
    WorkloadIdentity,
    SignedChallenge,
    MutualTls,
    OperatorSsh,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteAgentPodEvidenceMode {
    AppendOnlyStream,
    BundleUpload,
    LocalPull,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteAgentPodHandshakeResponseField {
    WorkerIdentity,
    WorkerPublicKey,
    SignedChallenge,
    Capabilities,
    EvidenceEndpoint,
    LifecycleAck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodHandshakeDescriptor {
    pub schema_version: i64,
    pub provider: String,
    pub endpoint: String,
    pub auth_kind: RemoteAgentPodAuthKind,
    pub challenge_id: String,
    pub challenge_nonce_sha256: String,
    pub expires_at: DateTime<Utc>,
    pub required_response_fields: Vec<RemoteAgentPodHandshakeResponseField>,
    pub secret_material_included: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodHandshakeAck {
    pub worker_identity: String,
    pub worker_public_key: String,
    pub signed_challenge: String,
    pub capabilities: Vec<RuntimeCapability>,
    pub evidence_endpoint: String,
    pub lifecycle_ack: bool,
    pub secret_material_included: bool,
    pub expires_at: DateTime<Utc>,
}

impl RemoteAgentPodHandshakeAck {
    pub fn validate_for(
        &self,
        descriptor: &RemoteAgentPodHandshakeDescriptor,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeError> {
        if self.worker_identity.trim().is_empty()
            || self.worker_public_key.trim().is_empty()
            || self.signed_challenge.trim().is_empty()
            || self.evidence_endpoint.trim().is_empty()
        {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod handshake ack is missing required identity, signature, or evidence fields"
                    .into(),
            ));
        }
        if self.secret_material_included {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod handshake ack must not include secret material".into(),
            ));
        }
        if !self.lifecycle_ack {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod handshake ack must acknowledge lifecycle contract".into(),
            ));
        }
        if self.expires_at <= now || self.expires_at > descriptor.expires_at {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod handshake ack expiry is invalid".into(),
            ));
        }

        Ok(())
    }
}

impl RemoteAgentPodHandshakeDescriptor {
    pub fn new(
        endpoint: impl Into<String>,
        auth_kind: RemoteAgentPodAuthKind,
        ttl_seconds: i64,
    ) -> Result<Self, RuntimeError> {
        let endpoint = endpoint.into();
        validate_remote_endpoint(&endpoint)?;
        if ttl_seconds <= 0 {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod handshake ttl must be greater than zero".into(),
            ));
        }

        let created_at = Utc::now();
        let mut nonce = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let challenge_nonce_sha256 = sha256_hex(&nonce);
        let challenge_id = format!(
            "agentpod-challenge-{}-{}",
            created_at.timestamp(),
            &challenge_nonce_sha256[..12]
        );

        Ok(Self {
            schema_version: 1,
            provider: "remote-agentpod".to_string(),
            endpoint,
            auth_kind,
            challenge_id,
            challenge_nonce_sha256,
            expires_at: created_at + Duration::seconds(ttl_seconds),
            required_response_fields: vec![
                RemoteAgentPodHandshakeResponseField::WorkerIdentity,
                RemoteAgentPodHandshakeResponseField::WorkerPublicKey,
                RemoteAgentPodHandshakeResponseField::SignedChallenge,
                RemoteAgentPodHandshakeResponseField::Capabilities,
                RemoteAgentPodHandshakeResponseField::EvidenceEndpoint,
                RemoteAgentPodHandshakeResponseField::LifecycleAck,
            ],
            secret_material_included: false,
            created_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteAgentPodLifecycleEvent {
    WorkerAllocated,
    SessionCreated,
    CommandStarted,
    CommandFinished,
    EvidenceSealed,
    KillSwitchAck,
    WorkerDestroyed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodLifecycleDescriptor {
    pub schema_version: i64,
    pub create_timeout_seconds: u64,
    pub command_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub destroy_timeout_seconds: u64,
    pub required_events: Vec<RemoteAgentPodLifecycleEvent>,
    pub kill_switch_required: bool,
}

impl Default for RemoteAgentPodLifecycleDescriptor {
    fn default() -> Self {
        Self {
            schema_version: 1,
            create_timeout_seconds: 120,
            command_timeout_seconds: 3600,
            idle_timeout_seconds: 300,
            destroy_timeout_seconds: 60,
            required_events: vec![
                RemoteAgentPodLifecycleEvent::WorkerAllocated,
                RemoteAgentPodLifecycleEvent::SessionCreated,
                RemoteAgentPodLifecycleEvent::CommandStarted,
                RemoteAgentPodLifecycleEvent::CommandFinished,
                RemoteAgentPodLifecycleEvent::EvidenceSealed,
                RemoteAgentPodLifecycleEvent::KillSwitchAck,
                RemoteAgentPodLifecycleEvent::WorkerDestroyed,
            ],
            kill_switch_required: true,
        }
    }
}

impl RemoteAgentPodLifecycleDescriptor {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema_version <= 0 {
            return Err(RuntimeError::ManifestRejected(
                "remote lifecycle schema version must be greater than zero".into(),
            ));
        }
        if self.create_timeout_seconds == 0
            || self.command_timeout_seconds == 0
            || self.idle_timeout_seconds == 0
            || self.destroy_timeout_seconds == 0
        {
            return Err(RuntimeError::ManifestRejected(
                "remote lifecycle timeouts must be greater than zero".into(),
            ));
        }
        if !self
            .required_events
            .contains(&RemoteAgentPodLifecycleEvent::EvidenceSealed)
        {
            return Err(RuntimeError::ManifestRejected(
                "remote lifecycle descriptor must require sealed evidence".into(),
            ));
        }
        if self.kill_switch_required
            && !self
                .required_events
                .contains(&RemoteAgentPodLifecycleEvent::KillSwitchAck)
        {
            return Err(RuntimeError::ManifestRejected(
                "remote lifecycle descriptor must require kill-switch acknowledgement".into(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodCreateSessionRequest {
    pub transport: RemoteAgentPodTransportDescriptor,
    pub handshake_ack: RemoteAgentPodHandshakeAck,
    pub spec: MinipodSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodCreateSessionResponse {
    pub session_id: String,
    pub worker_session_id: String,
    pub status: RuntimeStatus,
    pub lifecycle_events: Vec<RemoteAgentPodLifecycleEvent>,
}

impl RemoteAgentPodCreateSessionResponse {
    pub fn validate_for(
        &self,
        request: &RemoteAgentPodCreateSessionRequest,
    ) -> Result<(), RuntimeError> {
        if self.session_id != request.spec.id {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod create response session id does not match spec".into(),
            ));
        }
        if self.worker_session_id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod create response must include worker session id".into(),
            ));
        }
        require_lifecycle_events(
            &self.lifecycle_events,
            &[
                RemoteAgentPodLifecycleEvent::WorkerAllocated,
                RemoteAgentPodLifecycleEvent::SessionCreated,
            ],
            "create response",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodExecRequest {
    pub session_id: String,
    pub worker_session_id: String,
    pub command: ExecCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodExecResponse {
    pub result: CommandResult,
    pub lifecycle_events: Vec<RemoteAgentPodLifecycleEvent>,
}

impl RemoteAgentPodExecResponse {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        require_lifecycle_events(
            &self.lifecycle_events,
            &[
                RemoteAgentPodLifecycleEvent::CommandStarted,
                RemoteAgentPodLifecycleEvent::CommandFinished,
                RemoteAgentPodLifecycleEvent::EvidenceSealed,
            ],
            "exec response",
        )
    }
}

#[async_trait]
pub trait RemoteAgentPodTransport: Send + Sync {
    async fn handshake(
        &self,
        descriptor: &RemoteAgentPodHandshakeDescriptor,
    ) -> Result<RemoteAgentPodHandshakeAck, RuntimeError>;

    async fn create_session(
        &self,
        request: RemoteAgentPodCreateSessionRequest,
    ) -> Result<RemoteAgentPodCreateSessionResponse, RuntimeError>;

    async fn exec_command(
        &self,
        request: RemoteAgentPodExecRequest,
    ) -> Result<RemoteAgentPodExecResponse, RuntimeError>;
}

#[derive(Debug, Clone)]
pub struct HttpRemoteAgentPodTransport {
    client: reqwest::Client,
    endpoint: String,
}

impl HttpRemoteAgentPodTransport {
    pub fn new(endpoint: impl Into<String>) -> Result<Self, RuntimeError> {
        let endpoint = endpoint.into();
        validate_remote_endpoint(&endpoint)?;
        if !endpoint.starts_with("https://") {
            return Err(RuntimeError::ManifestRejected(
                "HTTP remote AgentPod transport requires an https:// endpoint".into(),
            ));
        }

        Ok(Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn route(&self, suffix: impl AsRef<str>) -> String {
        format!(
            "{}/{}",
            self.endpoint,
            suffix.as_ref().trim_start_matches('/')
        )
    }
}

#[async_trait]
impl RemoteAgentPodTransport for HttpRemoteAgentPodTransport {
    async fn handshake(
        &self,
        descriptor: &RemoteAgentPodHandshakeDescriptor,
    ) -> Result<RemoteAgentPodHandshakeAck, RuntimeError> {
        let ack = self
            .client
            .post(self.route("handshake"))
            .json(descriptor)
            .send()
            .await
            .map_err(|err| RuntimeError::Unavailable(format!("remote handshake failed: {err}")))?
            .error_for_status()
            .map_err(|err| RuntimeError::Unavailable(format!("remote handshake rejected: {err}")))?
            .json::<RemoteAgentPodHandshakeAck>()
            .await
            .map_err(|err| {
                RuntimeError::ManifestRejected(format!(
                    "remote handshake ack was invalid JSON: {err}"
                ))
            })?;
        ack.validate_for(descriptor, Utc::now())?;
        Ok(ack)
    }

    async fn create_session(
        &self,
        request: RemoteAgentPodCreateSessionRequest,
    ) -> Result<RemoteAgentPodCreateSessionResponse, RuntimeError> {
        let response = self
            .client
            .post(self.route("sessions"))
            .json(&request)
            .send()
            .await
            .map_err(|err| RuntimeError::Unavailable(format!("remote create failed: {err}")))?
            .error_for_status()
            .map_err(|err| RuntimeError::Unavailable(format!("remote create rejected: {err}")))?
            .json::<RemoteAgentPodCreateSessionResponse>()
            .await
            .map_err(|err| {
                RuntimeError::ManifestRejected(format!(
                    "remote create response was invalid JSON: {err}"
                ))
            })?;
        response.validate_for(&request)?;
        Ok(response)
    }

    async fn exec_command(
        &self,
        request: RemoteAgentPodExecRequest,
    ) -> Result<RemoteAgentPodExecResponse, RuntimeError> {
        let response = self
            .client
            .post(self.route(format!("sessions/{}/exec", request.worker_session_id)))
            .json(&request)
            .send()
            .await
            .map_err(|err| RuntimeError::Unavailable(format!("remote exec failed: {err}")))?
            .error_for_status()
            .map_err(|err| RuntimeError::Unavailable(format!("remote exec rejected: {err}")))?
            .json::<RemoteAgentPodExecResponse>()
            .await
            .map_err(|err| {
                RuntimeError::ManifestRejected(format!(
                    "remote exec response was invalid JSON: {err}"
                ))
            })?;
        response.validate()?;
        Ok(response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodTransportDescriptor {
    pub schema_version: i64,
    pub provider: String,
    pub endpoint: String,
    pub auth_kind: RemoteAgentPodAuthKind,
    pub evidence_mode: RemoteAgentPodEvidenceMode,
    pub kill_switch_required: bool,
    pub secret_material_included: bool,
    pub lifecycle: RemoteAgentPodLifecycleDescriptor,
    pub created_at: DateTime<Utc>,
}

impl RemoteAgentPodTransportDescriptor {
    pub fn new(
        endpoint: impl Into<String>,
        auth_kind: RemoteAgentPodAuthKind,
        evidence_mode: RemoteAgentPodEvidenceMode,
    ) -> Result<Self, RuntimeError> {
        let endpoint = endpoint.into();
        validate_remote_endpoint(&endpoint)?;
        let lifecycle = RemoteAgentPodLifecycleDescriptor::default();
        lifecycle.validate()?;
        Ok(Self {
            schema_version: 1,
            provider: "remote-agentpod".to_string(),
            endpoint,
            auth_kind,
            evidence_mode,
            kill_switch_required: true,
            secret_material_included: false,
            lifecycle,
            created_at: Utc::now(),
        })
    }
}

fn validate_remote_endpoint(endpoint: &str) -> Result<(), RuntimeError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(RuntimeError::ManifestRejected(
            "remote AgentPod endpoint must not be empty".into(),
        ));
    }
    if endpoint.contains('@') && !endpoint.starts_with("ssh://") {
        return Err(RuntimeError::ManifestRejected(
            "remote AgentPod endpoint must not embed credentials".into(),
        ));
    }
    if !(endpoint.starts_with("https://") || endpoint.starts_with("ssh://")) {
        return Err(RuntimeError::ManifestRejected(
            "remote AgentPod endpoint must use https:// or ssh://".into(),
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn require_lifecycle_events(
    actual: &[RemoteAgentPodLifecycleEvent],
    required: &[RemoteAgentPodLifecycleEvent],
    context: &str,
) -> Result<(), RuntimeError> {
    for event in required {
        if !actual.contains(event) {
            return Err(RuntimeError::ManifestRejected(format!(
                "remote AgentPod {context} is missing required lifecycle event {event:?}"
            )));
        }
    }
    Ok(())
}

pub struct RemoteAgentPodProvider;

impl RemoteAgentPodProvider {
    fn unavailable(&self) -> RuntimeError {
        RuntimeError::Unavailable(
            "remote-agentpod is a provider descriptor; remote transport, auth, and worker lifecycle are not implemented yet".into(),
        )
    }
}

#[async_trait]
impl RuntimeProvider for RemoteAgentPodProvider {
    fn name(&self) -> &str {
        "remote-agentpod"
    }

    fn platform(&self) -> &str {
        "remote"
    }

    fn family(&self) -> ProviderFamily {
        ProviderFamily::Remote
    }

    fn implementation_status(&self) -> ProviderImplementationStatus {
        ProviderImplementationStatus::DescriptorOnly
    }

    fn capabilities(&self) -> &[RuntimeCapability] {
        &[
            RuntimeCapability::VmIsolation,
            RuntimeCapability::FilesystemPolicy,
            RuntimeCapability::NetworkPolicy,
            RuntimeCapability::CredentialPolicy,
            RuntimeCapability::ApprovalBridge,
            RuntimeCapability::EvidenceExport,
        ]
    }

    fn bridge_transport_kinds(&self) -> &[HostBridgeTransportKind] {
        &[HostBridgeTransportKind::RemoteTunnel]
    }

    async fn is_available(&self) -> bool {
        false
    }

    async fn create(&self, _spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError> {
        Err(self.unavailable())
    }

    async fn exec(
        &self,
        _session_id: &str,
        _command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        Err(self.unavailable())
    }

    async fn status(&self, _session_id: &str) -> Result<RuntimeStatus, RuntimeError> {
        Err(self.unavailable())
    }

    async fn destroy(&self, _session_id: &str) -> Result<(), RuntimeError> {
        Err(self.unavailable())
    }

    async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
        Err(self.unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::providers::conformance::{
        assert_network_enforcement_metadata, assert_provider_metadata,
        assert_unavailable_provider_contract,
    };
    use std::collections::HashMap;

    struct FakeRemoteAgentPodTransport;

    #[async_trait]
    impl RemoteAgentPodTransport for FakeRemoteAgentPodTransport {
        async fn handshake(
            &self,
            descriptor: &RemoteAgentPodHandshakeDescriptor,
        ) -> Result<RemoteAgentPodHandshakeAck, RuntimeError> {
            let ack = RemoteAgentPodHandshakeAck {
                worker_identity: "worker.local/test".into(),
                worker_public_key: "ed25519:test-public-key".into(),
                signed_challenge: format!("signed:{}", descriptor.challenge_id),
                capabilities: vec![
                    RuntimeCapability::ApprovalBridge,
                    RuntimeCapability::EvidenceExport,
                ],
                evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
                lifecycle_ack: true,
                secret_material_included: false,
                expires_at: descriptor.created_at + Duration::seconds(60),
            };
            ack.validate_for(descriptor, descriptor.created_at)?;
            Ok(ack)
        }

        async fn create_session(
            &self,
            request: RemoteAgentPodCreateSessionRequest,
        ) -> Result<RemoteAgentPodCreateSessionResponse, RuntimeError> {
            let response = RemoteAgentPodCreateSessionResponse {
                session_id: request.spec.id.clone(),
                worker_session_id: format!("worker-{}", request.spec.id),
                status: RuntimeStatus::Running,
                lifecycle_events: vec![
                    RemoteAgentPodLifecycleEvent::WorkerAllocated,
                    RemoteAgentPodLifecycleEvent::SessionCreated,
                ],
            };
            response.validate_for(&request)?;
            Ok(response)
        }

        async fn exec_command(
            &self,
            _request: RemoteAgentPodExecRequest,
        ) -> Result<RemoteAgentPodExecResponse, RuntimeError> {
            let response = RemoteAgentPodExecResponse {
                result: CommandResult {
                    exit_code: 0,
                    stdout: "ok\n".into(),
                    stderr: String::new(),
                    duration_ms: 1,
                },
                lifecycle_events: vec![
                    RemoteAgentPodLifecycleEvent::CommandStarted,
                    RemoteAgentPodLifecycleEvent::CommandFinished,
                    RemoteAgentPodLifecycleEvent::EvidenceSealed,
                ],
            };
            response.validate()?;
            Ok(response)
        }
    }

    #[tokio::test]
    async fn remote_agentpod_descriptor_does_not_claim_execution() {
        let provider = RemoteAgentPodProvider;

        assert_provider_metadata(
            &provider,
            "remote-agentpod",
            "remote",
            &[
                RuntimeCapability::VmIsolation,
                RuntimeCapability::ApprovalBridge,
                RuntimeCapability::EvidenceExport,
            ],
        );
        assert_eq!(provider.family(), ProviderFamily::Remote);
        assert_eq!(
            provider.implementation_status(),
            ProviderImplementationStatus::DescriptorOnly
        );
        assert_eq!(
            provider.bridge_transport_kinds(),
            &[HostBridgeTransportKind::RemoteTunnel]
        );
        assert_network_enforcement_metadata(&provider, &[]);
        assert_unavailable_provider_contract(&provider).await;
    }

    #[test]
    fn remote_transport_descriptor_is_secret_free_and_explicit() {
        let descriptor = RemoteAgentPodTransportDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            RemoteAgentPodEvidenceMode::AppendOnlyStream,
        )
        .unwrap();

        assert_eq!(descriptor.schema_version, 1);
        assert_eq!(descriptor.provider, "remote-agentpod");
        assert!(descriptor.kill_switch_required);
        assert!(!descriptor.secret_material_included);
        assert_eq!(descriptor.endpoint, "https://worker.example.com/agentpod");
        assert!(descriptor
            .lifecycle
            .required_events
            .contains(&RemoteAgentPodLifecycleEvent::EvidenceSealed));
        assert!(descriptor
            .lifecycle
            .required_events
            .contains(&RemoteAgentPodLifecycleEvent::KillSwitchAck));
        assert!(descriptor.lifecycle.kill_switch_required);
    }

    #[test]
    fn remote_transport_descriptor_rejects_insecure_or_secret_endpoints() {
        let insecure = RemoteAgentPodTransportDescriptor::new(
            "http://worker.example.com",
            RemoteAgentPodAuthKind::SignedChallenge,
            RemoteAgentPodEvidenceMode::AppendOnlyStream,
        )
        .unwrap_err();
        assert!(insecure.to_string().contains("https:// or ssh://"));

        let secret = RemoteAgentPodTransportDescriptor::new(
            "https://token@worker.example.com",
            RemoteAgentPodAuthKind::SignedChallenge,
            RemoteAgentPodEvidenceMode::AppendOnlyStream,
        )
        .unwrap_err();
        assert!(secret.to_string().contains("must not embed credentials"));
    }

    #[test]
    fn http_remote_transport_builds_stable_routes() {
        let transport =
            HttpRemoteAgentPodTransport::new("https://worker.example.com/agentpod/").unwrap();

        assert_eq!(transport.endpoint(), "https://worker.example.com/agentpod");
        assert_eq!(
            transport.route("/sessions/worker-1/exec"),
            "https://worker.example.com/agentpod/sessions/worker-1/exec"
        );
    }

    #[test]
    fn http_remote_transport_requires_https_endpoint() {
        let ssh = HttpRemoteAgentPodTransport::new("ssh://agentpod@example.com").unwrap_err();

        assert!(ssh.to_string().contains("https://"));
    }

    #[test]
    fn remote_handshake_descriptor_is_secret_free_and_expiring() {
        let descriptor = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();

        assert_eq!(descriptor.schema_version, 1);
        assert_eq!(descriptor.provider, "remote-agentpod");
        assert!(!descriptor.secret_material_included);
        assert_eq!(descriptor.challenge_nonce_sha256.len(), 64);
        assert!(descriptor.expires_at > descriptor.created_at);
        assert!(descriptor
            .required_response_fields
            .contains(&RemoteAgentPodHandshakeResponseField::SignedChallenge));
        assert!(descriptor
            .required_response_fields
            .contains(&RemoteAgentPodHandshakeResponseField::LifecycleAck));
    }

    #[test]
    fn remote_handshake_descriptor_rejects_invalid_ttl() {
        let err = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            0,
        )
        .unwrap_err();

        assert!(err.to_string().contains("ttl"));
    }

    #[test]
    fn remote_handshake_ack_rejects_secret_material_or_missing_lifecycle_ack() {
        let descriptor = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();
        let mut ack = RemoteAgentPodHandshakeAck {
            worker_identity: "worker.local/test".into(),
            worker_public_key: "ed25519:test-public-key".into(),
            signed_challenge: format!("signed:{}", descriptor.challenge_id),
            capabilities: vec![RuntimeCapability::EvidenceExport],
            evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
            lifecycle_ack: false,
            secret_material_included: false,
            expires_at: descriptor.created_at + Duration::seconds(60),
        };

        let lifecycle_err = ack
            .validate_for(&descriptor, descriptor.created_at)
            .unwrap_err();
        assert!(lifecycle_err.to_string().contains("lifecycle"));

        ack.lifecycle_ack = true;
        ack.secret_material_included = true;
        let secret_err = ack
            .validate_for(&descriptor, descriptor.created_at)
            .unwrap_err();
        assert!(secret_err.to_string().contains("secret material"));
    }

    #[test]
    fn remote_create_response_requires_worker_lifecycle_events() {
        let transport = RemoteAgentPodTransportDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            RemoteAgentPodEvidenceMode::AppendOnlyStream,
        )
        .unwrap();
        let handshake = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();
        let handshake_ack = RemoteAgentPodHandshakeAck {
            worker_identity: "worker.local/test".into(),
            worker_public_key: "ed25519:test-public-key".into(),
            signed_challenge: format!("signed:{}", handshake.challenge_id),
            capabilities: vec![RuntimeCapability::EvidenceExport],
            evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
            lifecycle_ack: true,
            secret_material_included: false,
            expires_at: handshake.created_at + Duration::seconds(60),
        };
        let spec = MinipodSpec::for_agent_task("remote-test", std::env::temp_dir());
        let request = RemoteAgentPodCreateSessionRequest {
            transport,
            handshake_ack,
            spec: spec.clone(),
        };
        let response = RemoteAgentPodCreateSessionResponse {
            session_id: spec.id.clone(),
            worker_session_id: "worker-session".into(),
            status: RuntimeStatus::Running,
            lifecycle_events: vec![RemoteAgentPodLifecycleEvent::WorkerAllocated],
        };

        let err = response.validate_for(&request).unwrap_err();

        assert!(err.to_string().contains("SessionCreated"));
    }

    #[test]
    fn remote_exec_response_requires_command_and_evidence_events() {
        let response = RemoteAgentPodExecResponse {
            result: CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: 1,
            },
            lifecycle_events: vec![
                RemoteAgentPodLifecycleEvent::CommandStarted,
                RemoteAgentPodLifecycleEvent::CommandFinished,
            ],
        };

        let err = response.validate().unwrap_err();

        assert!(err.to_string().contains("EvidenceSealed"));
    }

    #[tokio::test]
    async fn fake_remote_transport_proves_contract_without_provider_execution() {
        let transport = RemoteAgentPodTransportDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            RemoteAgentPodEvidenceMode::AppendOnlyStream,
        )
        .unwrap();
        let handshake = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();
        let fake = FakeRemoteAgentPodTransport;
        let handshake_ack = fake.handshake(&handshake).await.unwrap();
        let spec = MinipodSpec::for_agent_task("remote-test", std::env::temp_dir());
        let create = fake
            .create_session(RemoteAgentPodCreateSessionRequest {
                transport,
                handshake_ack,
                spec: spec.clone(),
            })
            .await
            .unwrap();
        let exec = fake
            .exec_command(RemoteAgentPodExecRequest {
                session_id: create.session_id,
                worker_session_id: create.worker_session_id,
                command: ExecCommand {
                    argv: vec!["true".into()],
                    working_dir: None,
                    env: HashMap::new(),
                    timeout_seconds: Some(30),
                },
            })
            .await
            .unwrap();

        assert_eq!(exec.result.exit_code, 0);
        assert!(exec
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::EvidenceSealed));

        let provider = RemoteAgentPodProvider;
        assert_eq!(
            provider.implementation_status(),
            ProviderImplementationStatus::DescriptorOnly
        );
        assert!(!provider.is_available().await);
    }

    #[test]
    fn remote_lifecycle_descriptor_requires_kill_switch_ack() {
        let descriptor = RemoteAgentPodLifecycleDescriptor {
            required_events: vec![
                RemoteAgentPodLifecycleEvent::WorkerAllocated,
                RemoteAgentPodLifecycleEvent::EvidenceSealed,
            ],
            ..RemoteAgentPodLifecycleDescriptor::default()
        };

        let err = descriptor.validate().unwrap_err();

        assert!(err.to_string().contains("kill-switch acknowledgement"));
    }

    #[test]
    fn remote_lifecycle_descriptor_requires_sealed_evidence() {
        let descriptor = RemoteAgentPodLifecycleDescriptor {
            required_events: vec![
                RemoteAgentPodLifecycleEvent::WorkerAllocated,
                RemoteAgentPodLifecycleEvent::KillSwitchAck,
            ],
            ..RemoteAgentPodLifecycleDescriptor::default()
        };

        let err = descriptor.validate().unwrap_err();

        assert!(err.to_string().contains("sealed evidence"));
    }

    #[test]
    fn remote_lifecycle_descriptor_rejects_zero_timeouts() {
        let descriptor = RemoteAgentPodLifecycleDescriptor {
            command_timeout_seconds: 0,
            ..RemoteAgentPodLifecycleDescriptor::default()
        };

        let err = descriptor.validate().unwrap_err();

        assert!(err.to_string().contains("timeouts"));
    }
}
