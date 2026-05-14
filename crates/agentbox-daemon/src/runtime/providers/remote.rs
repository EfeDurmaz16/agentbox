use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use crate::runtime::bridge::HostBridgeTransportKind;
use crate::runtime::provider::{
    ProviderFamily, ProviderImplementationStatus, RuntimeError, RuntimeProvider,
};
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
    SessionEvidenceBundle,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodVerifiedHandshake {
    pub worker_identity: String,
    pub worker_public_key: String,
    pub challenge_id: String,
    pub evidence_endpoint: String,
    pub verified_at: DateTime<Utc>,
    pub verifier: String,
    pub cryptographic_signature_verified: bool,
}

pub trait RemoteAgentPodHandshakeVerifier: Send + Sync {
    fn name(&self) -> &str;

    fn verify(
        &self,
        descriptor: &RemoteAgentPodHandshakeDescriptor,
        ack: &RemoteAgentPodHandshakeAck,
        now: DateTime<Utc>,
    ) -> Result<RemoteAgentPodVerifiedHandshake, RuntimeError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ChallengeBindingHandshakeVerifier;

impl ChallengeBindingHandshakeVerifier {
    pub fn bound_challenge(
        descriptor: &RemoteAgentPodHandshakeDescriptor,
        ack: &RemoteAgentPodHandshakeAck,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{}",
            descriptor.challenge_id,
            descriptor.challenge_nonce_sha256,
            ack.worker_identity,
            ack.worker_public_key
        );
        format!(
            "agentbox-v1:{}:{}",
            descriptor.challenge_id,
            sha256_hex(payload.as_bytes())
        )
    }
}

impl RemoteAgentPodHandshakeVerifier for ChallengeBindingHandshakeVerifier {
    fn name(&self) -> &str {
        "challenge-binding-digest"
    }

    fn verify(
        &self,
        descriptor: &RemoteAgentPodHandshakeDescriptor,
        ack: &RemoteAgentPodHandshakeAck,
        now: DateTime<Utc>,
    ) -> Result<RemoteAgentPodVerifiedHandshake, RuntimeError> {
        ack.validate_for(descriptor, now)?;
        let expected = Self::bound_challenge(descriptor, ack);
        if ack.signed_challenge != expected {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod handshake ack does not match canonical challenge binding".into(),
            ));
        }

        Ok(RemoteAgentPodVerifiedHandshake {
            worker_identity: ack.worker_identity.clone(),
            worker_public_key: ack.worker_public_key.clone(),
            challenge_id: descriptor.challenge_id.clone(),
            evidence_endpoint: ack.evidence_endpoint.clone(),
            verified_at: now,
            verifier: self.name().to_string(),
            cryptographic_signature_verified: false,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519HandshakeVerifier;

impl Ed25519HandshakeVerifier {
    pub fn signing_payload(
        descriptor: &RemoteAgentPodHandshakeDescriptor,
        ack: &RemoteAgentPodHandshakeAck,
    ) -> String {
        format!(
            "agentbox-remote-agentpod-handshake-v1\nchallenge_id={}\nchallenge_nonce_sha256={}\nworker_identity={}\nworker_public_key={}\nevidence_endpoint={}\n",
            descriptor.challenge_id,
            descriptor.challenge_nonce_sha256,
            ack.worker_identity,
            ack.worker_public_key,
            ack.evidence_endpoint
        )
    }

    fn parse_worker_public_key(value: &str) -> Result<VerifyingKey, RuntimeError> {
        let Some(hex_key) = value.strip_prefix("ed25519:") else {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod worker public key must use ed25519:<hex-public-key>".into(),
            ));
        };
        let decoded = decode_hex_exact::<32>(hex_key, "remote AgentPod worker public key")?;
        VerifyingKey::from_bytes(&decoded).map_err(|_| {
            RuntimeError::ManifestRejected("remote AgentPod worker public key is invalid".into())
        })
    }

    fn parse_signed_challenge(value: &str) -> Result<Signature, RuntimeError> {
        let Some(rest) = value.strip_prefix("ed25519:") else {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod signed challenge must use ed25519:<challenge-id>:<hex-signature>"
                    .into(),
            ));
        };
        let Some((_challenge_id, hex_signature)) = rest.split_once(':') else {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod signed challenge must bind the challenge id".into(),
            ));
        };
        let decoded = decode_hex_exact::<64>(hex_signature, "remote AgentPod signed challenge")?;
        Ok(Signature::from_bytes(&decoded))
    }
}

impl RemoteAgentPodHandshakeVerifier for Ed25519HandshakeVerifier {
    fn name(&self) -> &str {
        "ed25519-challenge-signature"
    }

    fn verify(
        &self,
        descriptor: &RemoteAgentPodHandshakeDescriptor,
        ack: &RemoteAgentPodHandshakeAck,
        now: DateTime<Utc>,
    ) -> Result<RemoteAgentPodVerifiedHandshake, RuntimeError> {
        ack.validate_for(descriptor, now)?;
        let verifying_key = Self::parse_worker_public_key(&ack.worker_public_key)?;
        let signature = Self::parse_signed_challenge(&ack.signed_challenge)?;
        let expected_prefix = format!("ed25519:{}:", descriptor.challenge_id);
        if !ack.signed_challenge.starts_with(&expected_prefix) {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod signed challenge does not bind the exact challenge id".into(),
            ));
        }
        let payload = Self::signing_payload(descriptor, ack);
        verifying_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|_| {
                RuntimeError::ManifestRejected(
                    "remote AgentPod signed challenge failed Ed25519 verification".into(),
                )
            })?;

        Ok(RemoteAgentPodVerifiedHandshake {
            worker_identity: ack.worker_identity.clone(),
            worker_public_key: ack.worker_public_key.clone(),
            challenge_id: descriptor.challenge_id.clone(),
            evidence_endpoint: ack.evidence_endpoint.clone(),
            verified_at: now,
            verifier: self.name().to_string(),
            cryptographic_signature_verified: true,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RemoteAgentPodHandshakeVerifierSet;

impl RemoteAgentPodHandshakeVerifierSet {
    pub fn verify(
        &self,
        descriptor: &RemoteAgentPodHandshakeDescriptor,
        ack: &RemoteAgentPodHandshakeAck,
        now: DateTime<Utc>,
    ) -> Result<RemoteAgentPodVerifiedHandshake, RuntimeError> {
        if ack.signed_challenge.starts_with("ed25519:") {
            Ed25519HandshakeVerifier.verify(descriptor, ack, now)
        } else {
            ChallengeBindingHandshakeVerifier.verify(descriptor, ack, now)
        }
    }
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
        if !self.signed_challenge.contains(&descriptor.challenge_id) {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod handshake ack signature must bind the challenge id".into(),
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

fn decode_hex_exact<const N: usize>(value: &str, label: &str) -> Result<[u8; N], RuntimeError> {
    if value.len() != N * 2 {
        return Err(RuntimeError::ManifestRejected(format!(
            "{label} must be {} hex characters",
            N * 2
        )));
    }
    let mut out = [0_u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        let high = decode_hex_nibble(bytes[index * 2], label)?;
        let low = decode_hex_nibble(bytes[index * 2 + 1], label)?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn decode_hex_nibble(value: u8, label: &str) -> Result<u8, RuntimeError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(RuntimeError::ManifestRejected(format!(
            "{label} must contain only hex characters"
        ))),
    }
}

fn validate_sha256_hex(value: &str, label: &str) -> Result<(), RuntimeError> {
    if value.len() == 64 && value.chars().all(|value| value.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(RuntimeError::ManifestRejected(format!(
            "{label} must be a SHA-256 hex digest"
        )))
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_bundle: Option<RemoteAgentPodWorkspaceBundle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodWorkspaceBundle {
    pub schema_version: i64,
    pub root_sha256: String,
    pub files: Vec<RemoteAgentPodWorkspaceFile>,
    pub secret_material_included: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodWorkspaceFile {
    pub path: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: usize,
    pub contents_utf8: String,
}

impl RemoteAgentPodWorkspaceBundle {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema_version != 1 {
            return Err(RuntimeError::ManifestRejected(
                "remote workspace bundle schema version is unsupported".into(),
            ));
        }
        if self.secret_material_included {
            return Err(RuntimeError::ManifestRejected(
                "remote workspace bundle must not include secret material".into(),
            ));
        }
        let computed_root = workspace_bundle_root_sha256(&self.files)?;
        if self.root_sha256 != computed_root {
            return Err(RuntimeError::ManifestRejected(
                "remote workspace bundle root hash does not match file index".into(),
            ));
        }
        for file in &self.files {
            validate_workspace_bundle_file(file)?;
        }
        Ok(())
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodDestroySessionRequest {
    pub session_id: String,
    pub worker_session_id: String,
    pub reason: String,
    pub kill_switch_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodDestroySessionResponse {
    pub session_id: String,
    pub worker_session_id: String,
    pub status: RuntimeStatus,
    pub lifecycle_events: Vec<RemoteAgentPodLifecycleEvent>,
}

impl RemoteAgentPodDestroySessionResponse {
    pub fn validate_for(
        &self,
        request: &RemoteAgentPodDestroySessionRequest,
    ) -> Result<(), RuntimeError> {
        if self.session_id != request.session_id
            || self.worker_session_id != request.worker_session_id
        {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod destroy response session ids do not match request".into(),
            ));
        }
        if !matches!(self.status, RuntimeStatus::Stopped) {
            return Err(RuntimeError::ManifestRejected(
                "remote AgentPod destroy response must report stopped status".into(),
            ));
        }
        let required = if request.kill_switch_required {
            vec![
                RemoteAgentPodLifecycleEvent::KillSwitchAck,
                RemoteAgentPodLifecycleEvent::WorkerDestroyed,
            ]
        } else {
            vec![RemoteAgentPodLifecycleEvent::WorkerDestroyed]
        };
        require_lifecycle_events(&self.lifecycle_events, &required, "destroy response")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodEvidenceUploadRequest {
    pub session_id: String,
    pub worker_session_id: String,
    pub evidence_mode: RemoteAgentPodEvidenceMode,
    pub bundle_sha256: String,
    #[serde(default)]
    pub derived_from_bundle: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_root_sha256: Option<String>,
    pub event_count: u64,
    pub sealed_at: DateTime<Utc>,
    pub secret_material_included: bool,
}

impl RemoteAgentPodEvidenceUploadRequest {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.session_id.trim().is_empty()
            || self.worker_session_id.trim().is_empty()
            || self.bundle_sha256.trim().is_empty()
        {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence upload request must include session ids and bundle hash".into(),
            ));
        }
        if self.bundle_sha256.len() != 64
            || !self
                .bundle_sha256
                .chars()
                .all(|value| value.is_ascii_hexdigit())
        {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence bundle hash must be a SHA-256 hex digest".into(),
            ));
        }
        if let Some(root_hash) = &self.bundle_root_sha256 {
            if root_hash.len() != 64 || !root_hash.chars().all(|value| value.is_ascii_hexdigit()) {
                return Err(RuntimeError::ManifestRejected(
                    "remote evidence bundle root hash must be a SHA-256 hex digest".into(),
                ));
            }
        }
        if self.derived_from_bundle {
            if self
                .bundle_id
                .as_ref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                return Err(RuntimeError::ManifestRejected(
                    "remote evidence derived from a bundle must include a bundle id".into(),
                ));
            }
            if self.bundle_root_sha256.as_deref() != Some(self.bundle_sha256.as_str()) {
                return Err(RuntimeError::ManifestRejected(
                    "remote evidence derived from a bundle must bind bundle_sha256 to bundle_root_sha256"
                        .into(),
                ));
            }
        }
        if self.event_count == 0 {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence upload request must include at least one event".into(),
            ));
        }
        if self.secret_material_included {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence upload request must not include secret material".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodEvidenceUploadResponse {
    pub session_id: String,
    pub worker_session_id: String,
    pub accepted_bundle_sha256: String,
    pub accepted_event_count: u64,
    pub lifecycle_events: Vec<RemoteAgentPodLifecycleEvent>,
}

impl RemoteAgentPodEvidenceUploadResponse {
    pub fn validate_for(
        &self,
        request: &RemoteAgentPodEvidenceUploadRequest,
    ) -> Result<(), RuntimeError> {
        request.validate()?;
        if self.session_id != request.session_id
            || self.worker_session_id != request.worker_session_id
        {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence upload response session ids do not match request".into(),
            ));
        }
        if self.accepted_bundle_sha256 != request.bundle_sha256
            || self.accepted_event_count != request.event_count
        {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence upload response must acknowledge the submitted bundle".into(),
            ));
        }
        require_lifecycle_events(
            &self.lifecycle_events,
            &[RemoteAgentPodLifecycleEvent::EvidenceSealed],
            "evidence upload response",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodEvidenceBundleUploadRequest {
    pub session_id: String,
    pub worker_session_id: String,
    pub bundle_sha256: String,
    pub bundle_json: String,
    pub secret_material_included: bool,
}

impl RemoteAgentPodEvidenceBundleUploadRequest {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.session_id.trim().is_empty()
            || self.worker_session_id.trim().is_empty()
            || self.bundle_sha256.trim().is_empty()
            || self.bundle_json.trim().is_empty()
        {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence bundle upload request must include session ids, bundle hash, and payload".into(),
            ));
        }
        if self.bundle_sha256.len() != 64
            || !self
                .bundle_sha256
                .chars()
                .all(|value| value.is_ascii_hexdigit())
        {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence bundle payload hash must be a SHA-256 hex digest".into(),
            ));
        }
        if sha256_hex(self.bundle_json.as_bytes()) != self.bundle_sha256 {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence bundle payload hash does not match bundle_json".into(),
            ));
        }
        if self.secret_material_included {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence bundle payload must not include secret material".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodEvidenceBundleUploadResponse {
    pub session_id: String,
    pub worker_session_id: String,
    pub stored_bundle_sha256: String,
    pub stored_bytes: u64,
    pub storage_path: String,
    pub lifecycle_events: Vec<RemoteAgentPodLifecycleEvent>,
}

impl RemoteAgentPodEvidenceBundleUploadResponse {
    pub fn validate_for(
        &self,
        request: &RemoteAgentPodEvidenceBundleUploadRequest,
    ) -> Result<(), RuntimeError> {
        request.validate()?;
        if self.session_id != request.session_id
            || self.worker_session_id != request.worker_session_id
        {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence bundle upload response session ids do not match request".into(),
            ));
        }
        if self.stored_bundle_sha256 != request.bundle_sha256 {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence bundle upload response must acknowledge the submitted bundle hash"
                    .into(),
            ));
        }
        if self.stored_bytes == 0 || self.storage_path.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence bundle upload response must include stored byte count and path"
                    .into(),
            ));
        }
        require_lifecycle_events(
            &self.lifecycle_events,
            &[RemoteAgentPodLifecycleEvent::EvidenceSealed],
            "evidence bundle upload response",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RemoteAgentPodEvidenceBundleEnvelope {
    schema_version: i64,
    kind: String,
    session_id: String,
    worker_session_id: String,
    index: RemoteAgentPodEvidenceBundleIndex,
    files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RemoteAgentPodEvidenceBundleIndex {
    schema_version: i64,
    bundle_id: String,
    session_id: String,
    provider: String,
    status: String,
    root_sha256: String,
    generated_at: DateTime<Utc>,
    files: Vec<RemoteAgentPodEvidenceBundleFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RemoteAgentPodEvidenceBundleFile {
    path: String,
    media_type: String,
    sha256: String,
    bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodEvidenceStatusRequest {
    pub session_id: String,
    pub worker_session_id: String,
}

impl RemoteAgentPodEvidenceStatusRequest {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.session_id.trim().is_empty() || self.worker_session_id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence status request must include session ids".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodEvidenceReceiptStatus {
    pub bundle_sha256: String,
    #[serde(default)]
    pub derived_from_bundle: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_root_sha256: Option<String>,
    pub event_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodStoredEvidenceBundleStatus {
    pub bundle_sha256: String,
    pub stored_bytes: u64,
    pub storage_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodEvidenceStatusResponse {
    pub session_id: String,
    pub worker_session_id: String,
    pub status: RuntimeStatus,
    pub evidence_receipts: Vec<RemoteAgentPodEvidenceReceiptStatus>,
    pub stored_evidence_bundles: Vec<RemoteAgentPodStoredEvidenceBundleStatus>,
}

impl RemoteAgentPodEvidenceStatusResponse {
    pub fn validate_for(
        &self,
        request: &RemoteAgentPodEvidenceStatusRequest,
    ) -> Result<(), RuntimeError> {
        request.validate()?;
        if self.session_id != request.session_id
            || self.worker_session_id != request.worker_session_id
        {
            return Err(RuntimeError::ManifestRejected(
                "remote evidence status response session ids do not match request".into(),
            ));
        }
        for receipt in &self.evidence_receipts {
            validate_sha256_hex(
                &receipt.bundle_sha256,
                "remote evidence receipt bundle hash",
            )?;
            if receipt.event_count == 0 {
                return Err(RuntimeError::ManifestRejected(
                    "remote evidence status receipts must include event counts".into(),
                ));
            }
            if let Some(root_hash) = &receipt.bundle_root_sha256 {
                validate_sha256_hex(root_hash, "remote evidence receipt bundle root hash")?;
            }
        }
        for bundle in &self.stored_evidence_bundles {
            validate_sha256_hex(&bundle.bundle_sha256, "remote stored evidence bundle hash")?;
            if bundle.stored_bytes == 0 || bundle.storage_path.trim().is_empty() {
                return Err(RuntimeError::ManifestRejected(
                    "remote stored evidence bundle status must include byte count and path".into(),
                ));
            }
        }
        Ok(())
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

    async fn destroy_session(
        &self,
        request: RemoteAgentPodDestroySessionRequest,
    ) -> Result<RemoteAgentPodDestroySessionResponse, RuntimeError>;

    async fn upload_evidence(
        &self,
        request: RemoteAgentPodEvidenceUploadRequest,
    ) -> Result<RemoteAgentPodEvidenceUploadResponse, RuntimeError>;

    async fn upload_evidence_bundle(
        &self,
        request: RemoteAgentPodEvidenceBundleUploadRequest,
    ) -> Result<RemoteAgentPodEvidenceBundleUploadResponse, RuntimeError>;

    async fn evidence_status(
        &self,
        request: RemoteAgentPodEvidenceStatusRequest,
    ) -> Result<RemoteAgentPodEvidenceStatusResponse, RuntimeError>;
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
        let gated_loopback_http = endpoint.starts_with("http://")
            && remote_loopback_http_enabled()
            && is_loopback_http_endpoint(&endpoint);
        if !(endpoint.starts_with("https://") || gated_loopback_http) {
            return Err(RuntimeError::ManifestRejected(
                "HTTP remote AgentPod transport requires https:// or gated loopback http://".into(),
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
        RemoteAgentPodHandshakeVerifierSet.verify(descriptor, &ack, Utc::now())?;
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

    async fn destroy_session(
        &self,
        request: RemoteAgentPodDestroySessionRequest,
    ) -> Result<RemoteAgentPodDestroySessionResponse, RuntimeError> {
        let response = self
            .client
            .post(self.route(format!("sessions/{}/destroy", request.worker_session_id)))
            .json(&request)
            .send()
            .await
            .map_err(|err| RuntimeError::Unavailable(format!("remote destroy failed: {err}")))?
            .error_for_status()
            .map_err(|err| RuntimeError::Unavailable(format!("remote destroy rejected: {err}")))?
            .json::<RemoteAgentPodDestroySessionResponse>()
            .await
            .map_err(|err| {
                RuntimeError::ManifestRejected(format!(
                    "remote destroy response was invalid JSON: {err}"
                ))
            })?;
        response.validate_for(&request)?;
        Ok(response)
    }

    async fn upload_evidence(
        &self,
        request: RemoteAgentPodEvidenceUploadRequest,
    ) -> Result<RemoteAgentPodEvidenceUploadResponse, RuntimeError> {
        request.validate()?;
        let response = self
            .client
            .post(self.route(format!("sessions/{}/evidence", request.worker_session_id)))
            .json(&request)
            .send()
            .await
            .map_err(|err| {
                RuntimeError::Unavailable(format!("remote evidence upload failed: {err}"))
            })?
            .error_for_status()
            .map_err(|err| {
                RuntimeError::Unavailable(format!("remote evidence upload rejected: {err}"))
            })?
            .json::<RemoteAgentPodEvidenceUploadResponse>()
            .await
            .map_err(|err| {
                RuntimeError::ManifestRejected(format!(
                    "remote evidence upload response was invalid JSON: {err}"
                ))
            })?;
        response.validate_for(&request)?;
        Ok(response)
    }

    async fn upload_evidence_bundle(
        &self,
        request: RemoteAgentPodEvidenceBundleUploadRequest,
    ) -> Result<RemoteAgentPodEvidenceBundleUploadResponse, RuntimeError> {
        request.validate()?;
        let response = self
            .client
            .post(self.route(format!(
                "sessions/{}/evidence/bundle",
                request.worker_session_id
            )))
            .json(&request)
            .send()
            .await
            .map_err(|err| {
                RuntimeError::Unavailable(format!("remote evidence bundle upload failed: {err}"))
            })?
            .error_for_status()
            .map_err(|err| {
                RuntimeError::Unavailable(format!("remote evidence bundle upload rejected: {err}"))
            })?
            .json::<RemoteAgentPodEvidenceBundleUploadResponse>()
            .await
            .map_err(|err| {
                RuntimeError::ManifestRejected(format!(
                    "remote evidence bundle upload response was invalid JSON: {err}"
                ))
            })?;
        response.validate_for(&request)?;
        Ok(response)
    }

    async fn evidence_status(
        &self,
        request: RemoteAgentPodEvidenceStatusRequest,
    ) -> Result<RemoteAgentPodEvidenceStatusResponse, RuntimeError> {
        request.validate()?;
        let response = self
            .client
            .get(self.route(format!(
                "sessions/{}/evidence/status",
                request.worker_session_id
            )))
            .query(&[("session_id", request.session_id.as_str())])
            .send()
            .await
            .map_err(|err| {
                RuntimeError::Unavailable(format!("remote evidence status failed: {err}"))
            })?
            .error_for_status()
            .map_err(|err| {
                RuntimeError::Unavailable(format!("remote evidence status rejected: {err}"))
            })?
            .json::<RemoteAgentPodEvidenceStatusResponse>()
            .await
            .map_err(|err| {
                RuntimeError::ManifestRejected(format!(
                    "remote evidence status response was invalid JSON: {err}"
                ))
            })?;
        response.validate_for(&request)?;
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
    validate_remote_endpoint_with_loopback(endpoint, remote_loopback_http_enabled())
}

fn validate_remote_endpoint_with_loopback(
    endpoint: &str,
    allow_http_loopback: bool,
) -> Result<(), RuntimeError> {
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
    if endpoint.starts_with("http://") && allow_http_loopback && is_loopback_http_endpoint(endpoint)
    {
        return Ok(());
    }
    if !(endpoint.starts_with("https://") || endpoint.starts_with("ssh://")) {
        return Err(RuntimeError::ManifestRejected(
            "remote AgentPod endpoint must use https:// or ssh://".into(),
        ));
    }
    Ok(())
}

fn remote_loopback_http_enabled() -> bool {
    matches!(
        std::env::var("AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

fn remote_workspace_bundle_enabled() -> bool {
    matches!(
        std::env::var(REMOTE_WORKSPACE_BUNDLE_ENV)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

fn is_loopback_http_endpoint(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    if url.scheme() != "http" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn evidence_bundle_root_sha256(files: &[RemoteAgentPodEvidenceBundleFile]) -> String {
    let mut entries = files
        .iter()
        .map(|file| {
            format!(
                "{}\0{}\0{}\0{}",
                file.path, file.sha256, file.bytes, file.media_type
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    sha256_hex(format!("agentbox-evidence-root-v1\n{}", entries.join("\n")).as_bytes())
}

fn workspace_bundle_root_sha256(
    files: &[RemoteAgentPodWorkspaceFile],
) -> Result<String, RuntimeError> {
    let mut entries = Vec::with_capacity(files.len());
    for file in files {
        validate_workspace_bundle_file(file)?;
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

fn build_remote_workspace_bundle(
    root: &Path,
) -> Result<RemoteAgentPodWorkspaceBundle, RuntimeError> {
    let root = root.canonicalize().map_err(|err| {
        RuntimeError::ManifestRejected(format!(
            "remote workspace bundle root {} is not readable: {err}",
            root.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(RuntimeError::ManifestRejected(format!(
            "remote workspace bundle root is not a directory: {}",
            root.display()
        )));
    }
    let mut files = Vec::new();
    let mut total_bytes = 0usize;
    collect_remote_workspace_files(&root, &root, &mut files, &mut total_bytes)?;
    let root_sha256 = workspace_bundle_root_sha256(&files)?;
    let bundle = RemoteAgentPodWorkspaceBundle {
        schema_version: 1,
        root_sha256,
        files,
        secret_material_included: false,
    };
    bundle.validate()?;
    Ok(bundle)
}

fn collect_remote_workspace_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<RemoteAgentPodWorkspaceFile>,
    total_bytes: &mut usize,
) -> Result<(), RuntimeError> {
    let mut entries = fs::read_dir(current)
        .map_err(|err| {
            RuntimeError::ManifestRejected(format!(
                "remote workspace bundle failed to read {}: {err}",
                current.display()
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            RuntimeError::ManifestRejected(format!(
                "remote workspace bundle failed to read directory entry: {err}"
            ))
        })?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|err| {
            RuntimeError::ManifestRejected(format!(
                "remote workspace bundle failed to derive relative path: {err}"
            ))
        })?;
        if should_skip_workspace_bundle_path(relative) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|err| {
            RuntimeError::ManifestRejected(format!(
                "remote workspace bundle failed to inspect {}: {err}",
                path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_remote_workspace_files(root, &path, files, total_bytes)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        if files.len() >= REMOTE_WORKSPACE_BUNDLE_MAX_FILES {
            return Err(RuntimeError::ManifestRejected(format!(
                "remote workspace bundle exceeds file limit of {REMOTE_WORKSPACE_BUNDLE_MAX_FILES}"
            )));
        }
        let bytes: usize = metadata.len().try_into().unwrap_or(usize::MAX);
        if bytes > REMOTE_WORKSPACE_BUNDLE_MAX_FILE_BYTES {
            continue;
        }
        if *total_bytes + bytes > REMOTE_WORKSPACE_BUNDLE_MAX_TOTAL_BYTES {
            return Err(RuntimeError::ManifestRejected(format!(
                "remote workspace bundle exceeds total byte limit of {REMOTE_WORKSPACE_BUNDLE_MAX_TOTAL_BYTES}"
            )));
        }
        let contents = fs::read(&path).map_err(|err| {
            RuntimeError::ManifestRejected(format!(
                "remote workspace bundle failed to read {}: {err}",
                path.display()
            ))
        })?;
        let Ok(contents_utf8) = String::from_utf8(contents) else {
            continue;
        };
        let relative = workspace_bundle_relative_path(relative)?;
        let sha256 = sha256_hex(contents_utf8.as_bytes());
        *total_bytes += contents_utf8.len();
        files.push(RemoteAgentPodWorkspaceFile {
            path: relative,
            media_type: "text/plain; charset=utf-8".to_string(),
            sha256,
            bytes: contents_utf8.len(),
            contents_utf8,
        });
    }
    Ok(())
}

fn workspace_bundle_relative_path(relative: &Path) -> Result<String, RuntimeError> {
    let parts = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => Ok(value.to_string_lossy().to_string()),
            _ => Err(RuntimeError::ManifestRejected(
                "remote workspace bundle file path is unsafe".into(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parts.is_empty() {
        return Err(RuntimeError::ManifestRejected(
            "remote workspace bundle file path is empty".into(),
        ));
    }
    Ok(parts.join("/"))
}

fn should_skip_workspace_bundle_path(relative: &Path) -> bool {
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

fn validate_workspace_bundle_file(file: &RemoteAgentPodWorkspaceFile) -> Result<(), RuntimeError> {
    let candidate = std::path::PathBuf::from(&file.path);
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
        return Err(RuntimeError::ManifestRejected(
            "remote workspace bundle file path is unsafe".into(),
        ));
    }
    if file.media_type.trim().is_empty() {
        return Err(RuntimeError::ManifestRejected(
            "remote workspace bundle file media type cannot be empty".into(),
        ));
    }
    if file.bytes != file.contents_utf8.len()
        || sha256_hex(file.contents_utf8.as_bytes()) != file.sha256
    {
        return Err(RuntimeError::ManifestRejected(
            "remote workspace bundle file bytes or hash do not match contents".into(),
        ));
    }
    Ok(())
}

fn remote_evidence_event_count(bundle: &SessionEvidenceBundle) -> u64 {
    (bundle.lifecycle_events.len()
        + bundle.approvals.len()
        + bundle.commands.len()
        + bundle.boundary_events.len()
        + bundle.credential_events.len())
    .try_into()
    .unwrap_or(u64::MAX)
}

fn remote_worker_working_dir(
    session: &RuntimeSession,
    working_dir: Option<&str>,
) -> Option<String> {
    let working_dir = working_dir?;
    let guest_workspace = session
        .spec
        .filesystem
        .workspace_guest_path
        .trim_end_matches('/');
    if working_dir == guest_workspace {
        return None;
    }
    let guest_prefix = format!("{guest_workspace}/");
    if let Some(relative) = working_dir.strip_prefix(&guest_prefix) {
        let host_workspace = session
            .spec
            .filesystem
            .workspace_host_path
            .to_string_lossy()
            .to_string();
        let host_workspace = host_workspace.trim_end_matches('/');
        return Some(format!("{host_workspace}/{relative}"));
    }
    Some(working_dir.to_string())
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

const REMOTE_AGENTPOD_ENDPOINT_ENV: &str = "AGENTBOX_REMOTE_AGENTPOD_ENDPOINT";
const REMOTE_LABEL_ENDPOINT: &str = "agentbox.remote.endpoint";
const REMOTE_LABEL_WORKER_SESSION_ID: &str = "agentbox.remote.worker_session";
const REMOTE_LABEL_WORKER_IDENTITY: &str = "agentbox.remote.worker_identity";
const REMOTE_LABEL_WORKER_EVIDENCE_ENDPOINT: &str = "agentbox.remote.evidence_endpoint";
const REMOTE_WORKSPACE_BUNDLE_ENV: &str = "AGENTBOX_REMOTE_AGENTPOD_WORKSPACE_BUNDLE";
const REMOTE_WORKSPACE_BUNDLE_MAX_FILES: usize = 512;
const REMOTE_WORKSPACE_BUNDLE_MAX_FILE_BYTES: usize = 512 * 1024;
const REMOTE_WORKSPACE_BUNDLE_MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct RemoteAgentPodProvider {
    endpoint: Option<String>,
    transport: Option<Arc<dyn RemoteAgentPodTransport>>,
}

impl RemoteAgentPodProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_transport(
        endpoint: impl Into<String>,
        transport: Arc<dyn RemoteAgentPodTransport>,
    ) -> Self {
        Self {
            endpoint: Some(endpoint.into()),
            transport: Some(transport),
        }
    }

    fn unavailable(&self) -> RuntimeError {
        RuntimeError::Unavailable(format!(
            "remote-agentpod requires {REMOTE_AGENTPOD_ENDPOINT_ENV}=https://worker.example.com/agentpod"
        ))
    }

    fn configured_endpoint(&self) -> Result<String, RuntimeError> {
        if let Some(endpoint) = &self.endpoint {
            validate_remote_endpoint(endpoint)?;
            return Ok(endpoint.clone());
        }
        let endpoint =
            std::env::var(REMOTE_AGENTPOD_ENDPOINT_ENV).map_err(|_| self.unavailable())?;
        validate_remote_endpoint(&endpoint)?;
        Ok(endpoint)
    }

    fn transport_for(
        &self,
        endpoint: &str,
    ) -> Result<Arc<dyn RemoteAgentPodTransport>, RuntimeError> {
        if let Some(transport) = &self.transport {
            return Ok(transport.clone());
        }
        Ok(Arc::new(HttpRemoteAgentPodTransport::new(endpoint)?))
    }

    fn endpoint_from_session<'a>(
        &self,
        session: &'a RuntimeSession,
    ) -> Result<&'a str, RuntimeError> {
        session
            .spec
            .labels
            .get(REMOTE_LABEL_ENDPOINT)
            .map(String::as_str)
            .ok_or_else(|| {
                RuntimeError::ManifestRejected(
                    "remote AgentPod session is missing worker endpoint metadata".into(),
                )
            })
    }

    fn worker_session_from_session<'a>(
        &self,
        session: &'a RuntimeSession,
    ) -> Result<&'a str, RuntimeError> {
        session
            .spec
            .labels
            .get(REMOTE_LABEL_WORKER_SESSION_ID)
            .map(String::as_str)
            .ok_or_else(|| {
                RuntimeError::ManifestRejected(
                    "remote AgentPod session is missing worker session metadata".into(),
                )
            })
    }

    fn evidence_bundle_upload_requests(
        &self,
        session: &RuntimeSession,
        worker_session_id: &str,
        bundle: &SessionEvidenceBundle,
    ) -> Result<
        (
            RemoteAgentPodEvidenceUploadRequest,
            RemoteAgentPodEvidenceBundleUploadRequest,
        ),
        RuntimeError,
    > {
        let file_specs = [
            (
                "bundle.json",
                "Full redacted AgentPod session evidence bundle",
                serde_json::to_string_pretty(bundle),
            ),
            (
                "manifest.json",
                "Redacted AgentPod session manifest",
                serde_json::to_string_pretty(&bundle.manifest),
            ),
            (
                "replay.json",
                "Metadata-only session replay plan",
                serde_json::to_string_pretty(&bundle.replay),
            ),
            (
                "transcripts.json",
                "Redacted command transcripts",
                serde_json::to_string_pretty(&bundle.transcripts),
            ),
        ];
        let mut files = BTreeMap::new();
        let mut index_files = Vec::with_capacity(file_specs.len());
        for (path, _description, serialized) in file_specs {
            let contents = serialized.map_err(|err| {
                RuntimeError::Internal(format!(
                    "failed to serialize remote AgentPod evidence file {path}: {err}"
                ))
            })?;
            let bytes = contents.len();
            let sha256 = sha256_hex(contents.as_bytes());
            files.insert(path.to_string(), contents);
            index_files.push(RemoteAgentPodEvidenceBundleFile {
                path: path.to_string(),
                media_type: "application/json".to_string(),
                sha256,
                bytes,
            });
        }
        let root_sha256 = evidence_bundle_root_sha256(&index_files);
        let index = RemoteAgentPodEvidenceBundleIndex {
            schema_version: 1,
            bundle_id: bundle.bundle_id.clone(),
            session_id: bundle.session_id.clone(),
            provider: bundle.provider.clone(),
            status: format!("{:?}", bundle.status),
            root_sha256: root_sha256.clone(),
            generated_at: bundle.generated_at,
            files: index_files,
        };
        let envelope = RemoteAgentPodEvidenceBundleEnvelope {
            schema_version: 1,
            kind: "AgentboxEvidenceBundleUpload".to_string(),
            session_id: session.id.clone(),
            worker_session_id: worker_session_id.to_string(),
            index,
            files,
        };
        let bundle_json = serde_json::to_string(&envelope).map_err(|err| {
            RuntimeError::Internal(format!(
                "failed to serialize remote AgentPod evidence upload envelope: {err}"
            ))
        })?;
        let bundle_sha256 = sha256_hex(bundle_json.as_bytes());
        let event_count = remote_evidence_event_count(bundle);
        let receipt = RemoteAgentPodEvidenceUploadRequest {
            session_id: session.id.clone(),
            worker_session_id: worker_session_id.to_string(),
            evidence_mode: RemoteAgentPodEvidenceMode::BundleUpload,
            bundle_sha256: root_sha256.clone(),
            derived_from_bundle: true,
            bundle_id: Some(bundle.bundle_id.clone()),
            bundle_root_sha256: Some(root_sha256),
            event_count,
            sealed_at: bundle.generated_at,
            secret_material_included: false,
        };
        receipt.validate()?;
        let payload = RemoteAgentPodEvidenceBundleUploadRequest {
            session_id: session.id.clone(),
            worker_session_id: worker_session_id.to_string(),
            bundle_sha256,
            bundle_json,
            secret_material_included: false,
        };
        payload.validate()?;
        Ok((receipt, payload))
    }

    fn workspace_bundle_for_spec(
        &self,
        spec: &MinipodSpec,
    ) -> Result<Option<RemoteAgentPodWorkspaceBundle>, RuntimeError> {
        if !remote_workspace_bundle_enabled() {
            return Ok(None);
        }
        build_remote_workspace_bundle(&spec.filesystem.workspace_host_path).map(Some)
    }
}

impl std::fmt::Debug for RemoteAgentPodProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteAgentPodProvider")
            .field("endpoint", &self.endpoint)
            .field("transport", &self.transport.as_ref().map(|_| "<transport>"))
            .finish()
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
        ProviderImplementationStatus::Experimental
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
        self.configured_endpoint().is_ok()
    }

    async fn create(&self, spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError> {
        let endpoint = self.configured_endpoint()?;
        let transport = self.transport_for(&endpoint)?;
        let transport_descriptor = RemoteAgentPodTransportDescriptor::new(
            endpoint.clone(),
            RemoteAgentPodAuthKind::SignedChallenge,
            RemoteAgentPodEvidenceMode::BundleUpload,
        )?;
        let handshake_descriptor = RemoteAgentPodHandshakeDescriptor::new(
            endpoint.clone(),
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )?;
        let handshake_ack = transport.handshake(&handshake_descriptor).await?;
        let workspace_bundle = self.workspace_bundle_for_spec(spec)?;
        let response = transport
            .create_session(RemoteAgentPodCreateSessionRequest {
                transport: transport_descriptor,
                handshake_ack: handshake_ack.clone(),
                spec: spec.clone(),
                workspace_bundle,
            })
            .await?;
        let mut session = RuntimeSession::new(
            spec.name.clone(),
            self.name().to_string(),
            self.platform().to_string(),
            spec.clone(),
        );
        session.status = response.status;
        session
            .spec
            .labels
            .insert(REMOTE_LABEL_ENDPOINT.to_string(), endpoint);
        session.spec.labels.insert(
            REMOTE_LABEL_WORKER_SESSION_ID.to_string(),
            response.worker_session_id,
        );
        session.spec.labels.insert(
            REMOTE_LABEL_WORKER_IDENTITY.to_string(),
            handshake_ack.worker_identity,
        );
        session.spec.labels.insert(
            REMOTE_LABEL_WORKER_EVIDENCE_ENDPOINT.to_string(),
            handshake_ack.evidence_endpoint,
        );
        Ok(session)
    }

    async fn exec(
        &self,
        _session_id: &str,
        _command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        Err(self.unavailable())
    }

    async fn exec_session(
        &self,
        session: &RuntimeSession,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        let endpoint = self.endpoint_from_session(session)?;
        let worker_session_id = self.worker_session_from_session(session)?;
        let transport = self.transport_for(endpoint)?;
        let mut command = command.clone();
        command.working_dir = remote_worker_working_dir(session, command.working_dir.as_deref());
        let response = transport
            .exec_command(RemoteAgentPodExecRequest {
                session_id: session.id.clone(),
                worker_session_id: worker_session_id.to_string(),
                command,
            })
            .await?;
        Ok(response.result)
    }

    async fn status(&self, _session_id: &str) -> Result<RuntimeStatus, RuntimeError> {
        Err(self.unavailable())
    }

    async fn destroy(&self, _session_id: &str) -> Result<(), RuntimeError> {
        Err(self.unavailable())
    }

    async fn destroy_session(&self, session: &RuntimeSession) -> Result<(), RuntimeError> {
        let endpoint = self.endpoint_from_session(session)?;
        let worker_session_id = self.worker_session_from_session(session)?;
        let transport = self.transport_for(endpoint)?;
        transport
            .destroy_session(RemoteAgentPodDestroySessionRequest {
                session_id: session.id.clone(),
                worker_session_id: worker_session_id.to_string(),
                reason: "operator_destroy".into(),
                kill_switch_required: true,
            })
            .await?;
        Ok(())
    }

    async fn seal_evidence_bundle(
        &self,
        session: &RuntimeSession,
        bundle: &SessionEvidenceBundle,
    ) -> Result<(), RuntimeError> {
        let endpoint = self.endpoint_from_session(session)?;
        let worker_session_id = self.worker_session_from_session(session)?;
        let transport = self.transport_for(endpoint)?;
        let (receipt, payload) =
            self.evidence_bundle_upload_requests(session, worker_session_id, bundle)?;
        transport.upload_evidence(receipt).await?;
        transport.upload_evidence_bundle(payload).await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
        Err(self.unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEvent;
    use crate::runtime::providers::conformance::{
        assert_network_enforcement_metadata, assert_provider_metadata,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashMap;

    struct FakeRemoteAgentPodTransport;

    #[async_trait]
    impl RemoteAgentPodTransport for FakeRemoteAgentPodTransport {
        async fn handshake(
            &self,
            descriptor: &RemoteAgentPodHandshakeDescriptor,
        ) -> Result<RemoteAgentPodHandshakeAck, RuntimeError> {
            let mut ack = RemoteAgentPodHandshakeAck {
                worker_identity: "worker.local/test".into(),
                worker_public_key: "ed25519:test-public-key".into(),
                signed_challenge: String::new(),
                capabilities: vec![
                    RuntimeCapability::ApprovalBridge,
                    RuntimeCapability::EvidenceExport,
                ],
                evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
                lifecycle_ack: true,
                secret_material_included: false,
                expires_at: descriptor.created_at + Duration::seconds(60),
            };
            ack.signed_challenge =
                ChallengeBindingHandshakeVerifier::bound_challenge(descriptor, &ack);
            ChallengeBindingHandshakeVerifier.verify(descriptor, &ack, descriptor.created_at)?;
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

        async fn destroy_session(
            &self,
            request: RemoteAgentPodDestroySessionRequest,
        ) -> Result<RemoteAgentPodDestroySessionResponse, RuntimeError> {
            let response = RemoteAgentPodDestroySessionResponse {
                session_id: request.session_id.clone(),
                worker_session_id: request.worker_session_id.clone(),
                status: RuntimeStatus::Stopped,
                lifecycle_events: vec![
                    RemoteAgentPodLifecycleEvent::KillSwitchAck,
                    RemoteAgentPodLifecycleEvent::WorkerDestroyed,
                ],
            };
            response.validate_for(&request)?;
            Ok(response)
        }

        async fn upload_evidence(
            &self,
            request: RemoteAgentPodEvidenceUploadRequest,
        ) -> Result<RemoteAgentPodEvidenceUploadResponse, RuntimeError> {
            let response = RemoteAgentPodEvidenceUploadResponse {
                session_id: request.session_id.clone(),
                worker_session_id: request.worker_session_id.clone(),
                accepted_bundle_sha256: request.bundle_sha256.clone(),
                accepted_event_count: request.event_count,
                lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
            };
            response.validate_for(&request)?;
            Ok(response)
        }

        async fn upload_evidence_bundle(
            &self,
            request: RemoteAgentPodEvidenceBundleUploadRequest,
        ) -> Result<RemoteAgentPodEvidenceBundleUploadResponse, RuntimeError> {
            let response = RemoteAgentPodEvidenceBundleUploadResponse {
                session_id: request.session_id.clone(),
                worker_session_id: request.worker_session_id.clone(),
                stored_bundle_sha256: request.bundle_sha256.clone(),
                stored_bytes: request.bundle_json.len() as u64,
                storage_path: format!(
                    "evidence/{}/{}.json",
                    request.worker_session_id, request.bundle_sha256
                ),
                lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
            };
            response.validate_for(&request)?;
            Ok(response)
        }

        async fn evidence_status(
            &self,
            request: RemoteAgentPodEvidenceStatusRequest,
        ) -> Result<RemoteAgentPodEvidenceStatusResponse, RuntimeError> {
            let response = RemoteAgentPodEvidenceStatusResponse {
                session_id: request.session_id.clone(),
                worker_session_id: request.worker_session_id.clone(),
                status: RuntimeStatus::Running,
                evidence_receipts: vec![RemoteAgentPodEvidenceReceiptStatus {
                    bundle_sha256: "e".repeat(64),
                    derived_from_bundle: false,
                    bundle_id: None,
                    bundle_root_sha256: None,
                    event_count: 4,
                    sealed_at: Some(Utc::now()),
                }],
                stored_evidence_bundles: vec![RemoteAgentPodStoredEvidenceBundleStatus {
                    bundle_sha256: "e".repeat(64),
                    stored_bytes: 128,
                    storage_path: format!(
                        "evidence/{}/{}.json",
                        request.worker_session_id,
                        "e".repeat(64)
                    ),
                }],
            };
            response.validate_for(&request)?;
            Ok(response)
        }
    }

    #[tokio::test]
    async fn remote_agentpod_descriptor_does_not_claim_execution() {
        let provider = RemoteAgentPodProvider {
            endpoint: Some(String::new()),
            transport: None,
        };

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
            ProviderImplementationStatus::Experimental
        );
        assert_eq!(
            provider.bridge_transport_kinds(),
            &[HostBridgeTransportKind::RemoteTunnel]
        );
        assert_network_enforcement_metadata(&provider, &[]);
        assert!(!provider.is_available().await);
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/workspace");
        assert!(provider.create(&spec).await.is_err());
    }

    #[tokio::test]
    async fn remote_agentpod_provider_routes_lifecycle_through_transport() {
        let provider = RemoteAgentPodProvider::with_transport(
            "https://worker.example.com/agentpod",
            Arc::new(FakeRemoteAgentPodTransport),
        );
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/workspace");

        assert!(provider.is_available().await);
        let session = provider.create(&spec).await.unwrap();

        assert_eq!(session.status, RuntimeStatus::Running);
        assert_eq!(
            session.spec.labels.get(REMOTE_LABEL_ENDPOINT),
            Some(&"https://worker.example.com/agentpod".to_string())
        );
        assert_eq!(
            session.spec.labels.get(REMOTE_LABEL_WORKER_SESSION_ID),
            Some(&format!("worker-{}", spec.id))
        );
        assert_eq!(
            session.spec.labels.get(REMOTE_LABEL_WORKER_IDENTITY),
            Some(&"worker.local/test".to_string())
        );

        let command = ExecCommand {
            argv: vec!["printf".into(), "ok".into()],
            working_dir: None,
            env: HashMap::new(),
            timeout_seconds: Some(5),
        };
        let result = provider.exec_session(&session, &command).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "ok\n");

        provider.destroy_session(&session).await.unwrap();
    }

    #[test]
    fn remote_agentpod_evidence_bundle_upload_requests_wrap_session_bundle() {
        let provider = RemoteAgentPodProvider::with_transport(
            "https://worker.example.com/agentpod",
            Arc::new(FakeRemoteAgentPodTransport),
        );
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/workspace");
        spec.labels.insert(
            REMOTE_LABEL_WORKER_SESSION_ID.to_string(),
            "worker-session-1".to_string(),
        );
        let mut session = RuntimeSession::new(
            spec.name.clone(),
            "remote-agentpod".to_string(),
            "remote".to_string(),
            spec,
        );
        session.status = RuntimeStatus::Stopped;
        let event = AuditEvent::new(
            0,
            Some("hermes".to_string()),
            format!("runtime.destroy {}", session.id),
            "/tmp/workspace".to_string(),
            "runtime".to_string(),
            "destroyed".to_string(),
            None,
            None,
        );
        let bundle = SessionEvidenceBundle::from_session_events(&session, &[event]);

        let (receipt, payload) = provider
            .evidence_bundle_upload_requests(&session, "worker-session-1", &bundle)
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&payload.bundle_json).unwrap();

        assert_eq!(receipt.session_id, session.id);
        assert_eq!(receipt.worker_session_id, "worker-session-1");
        assert!(receipt.derived_from_bundle);
        assert_eq!(receipt.bundle_id, Some(bundle.bundle_id.clone()));
        assert_eq!(receipt.event_count, 1);
        assert_eq!(envelope["kind"], "AgentboxEvidenceBundleUpload");
        assert_eq!(envelope["session_id"], session.id);
        assert_eq!(envelope["worker_session_id"], "worker-session-1");
        assert_eq!(envelope["index"]["status"], "Stopped");
        assert!(envelope["files"]["bundle.json"].is_string());
        assert_ne!(payload.bundle_sha256, receipt.bundle_sha256);
    }

    #[test]
    fn remote_worker_working_dir_translates_guest_workspace_paths() {
        let session = RuntimeSession::new(
            "agentbox-test".to_string(),
            "remote-agentpod".to_string(),
            "remote".to_string(),
            MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-workspace"),
        );

        assert_eq!(remote_worker_working_dir(&session, None), None);
        assert_eq!(
            remote_worker_working_dir(&session, Some("/workspace")),
            None
        );
        assert_eq!(
            remote_worker_working_dir(&session, Some("/workspace/project")),
            Some("/tmp/agentbox-workspace/project".to_string())
        );
        assert_eq!(
            remote_worker_working_dir(&session, Some("/tmp/agentbox-workspace")),
            Some("/tmp/agentbox-workspace".to_string())
        );
    }

    #[test]
    fn remote_workspace_bundle_validates_file_hashes_and_paths() {
        let contents = "hello remote workspace\n".to_string();
        let mut file = RemoteAgentPodWorkspaceFile {
            path: "src/main.rs".to_string(),
            media_type: "text/plain".to_string(),
            sha256: sha256_hex(contents.as_bytes()),
            bytes: contents.len(),
            contents_utf8: contents,
        };
        let root_sha256 = workspace_bundle_root_sha256(&[file.clone()]).unwrap();
        let bundle = RemoteAgentPodWorkspaceBundle {
            schema_version: 1,
            root_sha256,
            files: vec![file.clone()],
            secret_material_included: false,
        };
        bundle.validate().unwrap();

        file.path = "../secret".to_string();
        let err = workspace_bundle_root_sha256(&[file]).unwrap_err();
        assert!(err.to_string().contains("unsafe"));
    }

    #[test]
    fn remote_workspace_bundle_builder_skips_secret_and_large_material() {
        let root = std::env::temp_dir().join(format!(
            "agentbox-remote-workspace-bundle-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("target")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join(".env"), "TOKEN=secret\n").unwrap();
        fs::write(root.join("target/build.log"), "generated\n").unwrap();
        fs::write(root.join("binary.bin"), [0, 159, 146, 150]).unwrap();

        let bundle = build_remote_workspace_bundle(&root).unwrap();

        assert_eq!(bundle.schema_version, 1);
        assert!(!bundle.secret_material_included);
        assert_eq!(bundle.files.len(), 1);
        assert_eq!(bundle.files[0].path, "src/main.rs");
        assert_eq!(bundle.files[0].contents_utf8, "fn main() {}\n");
        bundle.validate().unwrap();
        let _ = fs::remove_dir_all(root);
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
    fn remote_endpoint_allows_http_loopback_only_when_explicitly_gated() {
        let loopback = "http://127.0.0.1:63000/agentpod";
        let localhost = "http://localhost:63000/agentpod";
        let external = "http://worker.example.com/agentpod";

        assert!(validate_remote_endpoint_with_loopback(loopback, false).is_err());
        assert!(validate_remote_endpoint_with_loopback(loopback, true).is_ok());
        assert!(validate_remote_endpoint_with_loopback(localhost, true).is_ok());
        assert!(validate_remote_endpoint_with_loopback(external, true).is_err());
        assert!(validate_remote_endpoint_with_loopback(
            "http://token@127.0.0.1:63000/agentpod",
            true
        )
        .is_err());
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
        assert_eq!(
            transport.route("sessions/worker-1/destroy"),
            "https://worker.example.com/agentpod/sessions/worker-1/destroy"
        );
        assert_eq!(
            transport.route("sessions/worker-1/evidence"),
            "https://worker.example.com/agentpod/sessions/worker-1/evidence"
        );
        assert_eq!(
            transport.route("sessions/worker-1/evidence/status"),
            "https://worker.example.com/agentpod/sessions/worker-1/evidence/status"
        );
        assert_eq!(
            transport.route("sessions/worker-1/evidence/bundle"),
            "https://worker.example.com/agentpod/sessions/worker-1/evidence/bundle"
        );
    }

    #[test]
    fn http_remote_transport_requires_https_endpoint() {
        let ssh = HttpRemoteAgentPodTransport::new("ssh://agentpod@example.com").unwrap_err();

        assert!(ssh.to_string().contains("https:// or gated loopback"));
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
    fn remote_handshake_ack_must_bind_challenge_id() {
        let descriptor = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();
        let ack = RemoteAgentPodHandshakeAck {
            worker_identity: "worker.local/test".into(),
            worker_public_key: "ed25519:test-public-key".into(),
            signed_challenge: "signed:other-challenge".into(),
            capabilities: vec![RuntimeCapability::EvidenceExport],
            evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
            lifecycle_ack: true,
            secret_material_included: false,
            expires_at: descriptor.created_at + Duration::seconds(60),
        };

        let err = ack
            .validate_for(&descriptor, descriptor.created_at)
            .unwrap_err();

        assert!(err.to_string().contains("challenge id"));
    }

    #[test]
    fn remote_handshake_verifier_accepts_canonical_binding() {
        let descriptor = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();
        let mut ack = RemoteAgentPodHandshakeAck {
            worker_identity: "worker.local/test".into(),
            worker_public_key: "ed25519:test-public-key".into(),
            signed_challenge: String::new(),
            capabilities: vec![RuntimeCapability::EvidenceExport],
            evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
            lifecycle_ack: true,
            secret_material_included: false,
            expires_at: descriptor.created_at + Duration::seconds(60),
        };
        ack.signed_challenge =
            ChallengeBindingHandshakeVerifier::bound_challenge(&descriptor, &ack);

        let verified = ChallengeBindingHandshakeVerifier
            .verify(&descriptor, &ack, descriptor.created_at)
            .unwrap();

        assert_eq!(verified.worker_identity, ack.worker_identity);
        assert_eq!(verified.challenge_id, descriptor.challenge_id);
        assert_eq!(verified.verifier, "challenge-binding-digest");
        assert!(!verified.cryptographic_signature_verified);
    }

    #[test]
    fn remote_handshake_verifier_rejects_loose_challenge_substring() {
        let descriptor = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();
        let ack = RemoteAgentPodHandshakeAck {
            worker_identity: "worker.local/test".into(),
            worker_public_key: "ed25519:test-public-key".into(),
            signed_challenge: format!("signed:{}", descriptor.challenge_id),
            capabilities: vec![RuntimeCapability::EvidenceExport],
            evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
            lifecycle_ack: true,
            secret_material_included: false,
            expires_at: descriptor.created_at + Duration::seconds(60),
        };

        let err = ChallengeBindingHandshakeVerifier
            .verify(&descriptor, &ack, descriptor.created_at)
            .unwrap_err();

        assert!(err.to_string().contains("canonical challenge binding"));
    }

    #[test]
    fn ed25519_handshake_verifier_accepts_signed_worker_identity() {
        let descriptor = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut ack = RemoteAgentPodHandshakeAck {
            worker_identity: "worker.local/test".into(),
            worker_public_key: format!("ed25519:{}", hex_encode(&verifying_key.to_bytes())),
            signed_challenge: String::new(),
            capabilities: vec![RuntimeCapability::EvidenceExport],
            evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
            lifecycle_ack: true,
            secret_material_included: false,
            expires_at: descriptor.created_at + Duration::seconds(60),
        };
        let payload = Ed25519HandshakeVerifier::signing_payload(&descriptor, &ack);
        let signature = signing_key.sign(payload.as_bytes());
        ack.signed_challenge = format!(
            "ed25519:{}:{}",
            descriptor.challenge_id,
            hex_encode(&signature.to_bytes())
        );

        let verified = Ed25519HandshakeVerifier
            .verify(&descriptor, &ack, descriptor.created_at)
            .unwrap();

        assert_eq!(verified.worker_identity, ack.worker_identity);
        assert_eq!(verified.verifier, "ed25519-challenge-signature");
        assert!(verified.cryptographic_signature_verified);
    }

    #[test]
    fn ed25519_handshake_verifier_rejects_tampered_signature_binding() {
        let descriptor = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut ack = RemoteAgentPodHandshakeAck {
            worker_identity: "worker.local/test".into(),
            worker_public_key: format!("ed25519:{}", hex_encode(&verifying_key.to_bytes())),
            signed_challenge: String::new(),
            capabilities: vec![RuntimeCapability::EvidenceExport],
            evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
            lifecycle_ack: true,
            secret_material_included: false,
            expires_at: descriptor.created_at + Duration::seconds(60),
        };
        let payload = Ed25519HandshakeVerifier::signing_payload(&descriptor, &ack);
        let signature = signing_key.sign(payload.as_bytes());
        ack.signed_challenge = format!(
            "ed25519:{}:{}",
            descriptor.challenge_id,
            hex_encode(&signature.to_bytes())
        );
        ack.evidence_endpoint = "https://worker.example.com/agentpod/other-evidence".into();

        let err = Ed25519HandshakeVerifier
            .verify(&descriptor, &ack, descriptor.created_at)
            .unwrap_err();

        assert!(err.to_string().contains("Ed25519 verification"));
    }

    #[test]
    fn remote_handshake_verifier_set_selects_cryptographic_or_legacy_binding() {
        let descriptor = RemoteAgentPodHandshakeDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            300,
        )
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut signed_ack = RemoteAgentPodHandshakeAck {
            worker_identity: "worker.local/test".into(),
            worker_public_key: format!("ed25519:{}", hex_encode(&verifying_key.to_bytes())),
            signed_challenge: String::new(),
            capabilities: vec![RuntimeCapability::EvidenceExport],
            evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
            lifecycle_ack: true,
            secret_material_included: false,
            expires_at: descriptor.created_at + Duration::seconds(60),
        };
        let payload = Ed25519HandshakeVerifier::signing_payload(&descriptor, &signed_ack);
        let signature = signing_key.sign(payload.as_bytes());
        signed_ack.signed_challenge = format!(
            "ed25519:{}:{}",
            descriptor.challenge_id,
            hex_encode(&signature.to_bytes())
        );

        let signed = RemoteAgentPodHandshakeVerifierSet
            .verify(&descriptor, &signed_ack, descriptor.created_at)
            .unwrap();
        assert!(signed.cryptographic_signature_verified);

        let mut legacy_ack = RemoteAgentPodHandshakeAck {
            worker_identity: "worker.local/test".into(),
            worker_public_key: "ed25519:test-public-key".into(),
            signed_challenge: String::new(),
            capabilities: vec![RuntimeCapability::EvidenceExport],
            evidence_endpoint: "https://worker.example.com/agentpod/evidence".into(),
            lifecycle_ack: true,
            secret_material_included: false,
            expires_at: descriptor.created_at + Duration::seconds(60),
        };
        legacy_ack.signed_challenge =
            ChallengeBindingHandshakeVerifier::bound_challenge(&descriptor, &legacy_ack);

        let legacy = RemoteAgentPodHandshakeVerifierSet
            .verify(&descriptor, &legacy_ack, descriptor.created_at)
            .unwrap();
        assert!(!legacy.cryptographic_signature_verified);
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
            workspace_bundle: None,
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

    #[test]
    fn remote_destroy_response_requires_kill_switch_ack_when_requested() {
        let request = RemoteAgentPodDestroySessionRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            reason: "operator stop".into(),
            kill_switch_required: true,
        };
        let response = RemoteAgentPodDestroySessionResponse {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            status: RuntimeStatus::Stopped,
            lifecycle_events: vec![RemoteAgentPodLifecycleEvent::WorkerDestroyed],
        };

        let err = response.validate_for(&request).unwrap_err();

        assert!(err.to_string().contains("KillSwitchAck"));
    }

    #[test]
    fn remote_destroy_response_requires_stopped_status_and_matching_session() {
        let request = RemoteAgentPodDestroySessionRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            reason: "operator stop".into(),
            kill_switch_required: false,
        };
        let running_response = RemoteAgentPodDestroySessionResponse {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            status: RuntimeStatus::Running,
            lifecycle_events: vec![RemoteAgentPodLifecycleEvent::WorkerDestroyed],
        };
        let mismatched_response = RemoteAgentPodDestroySessionResponse {
            session_id: "session-2".into(),
            worker_session_id: "worker-session-1".into(),
            status: RuntimeStatus::Stopped,
            lifecycle_events: vec![RemoteAgentPodLifecycleEvent::WorkerDestroyed],
        };

        assert!(running_response
            .validate_for(&request)
            .unwrap_err()
            .to_string()
            .contains("stopped"));
        assert!(mismatched_response
            .validate_for(&request)
            .unwrap_err()
            .to_string()
            .contains("session ids"));
    }

    #[test]
    fn remote_evidence_upload_request_rejects_secrets_or_invalid_hashes() {
        let mut request = RemoteAgentPodEvidenceUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            evidence_mode: RemoteAgentPodEvidenceMode::BundleUpload,
            bundle_sha256: "a".repeat(64),
            derived_from_bundle: false,
            bundle_id: None,
            bundle_root_sha256: None,
            event_count: 2,
            sealed_at: Utc::now(),
            secret_material_included: false,
        };

        request.validate().unwrap();

        request.bundle_sha256 = "not-a-sha".into();
        assert!(request
            .validate()
            .unwrap_err()
            .to_string()
            .contains("SHA-256"));

        request.bundle_sha256 = "b".repeat(64);
        request.secret_material_included = true;
        assert!(request
            .validate()
            .unwrap_err()
            .to_string()
            .contains("secret material"));
    }

    #[test]
    fn remote_evidence_upload_request_binds_derived_bundle_root() {
        let mut request = RemoteAgentPodEvidenceUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            evidence_mode: RemoteAgentPodEvidenceMode::BundleUpload,
            bundle_sha256: "f".repeat(64),
            derived_from_bundle: true,
            bundle_id: Some("bundle-1".into()),
            bundle_root_sha256: Some("f".repeat(64)),
            event_count: 2,
            sealed_at: Utc::now(),
            secret_material_included: false,
        };

        request.validate().unwrap();

        request.bundle_root_sha256 = Some("e".repeat(64));
        assert!(request
            .validate()
            .unwrap_err()
            .to_string()
            .contains("bundle_root_sha256"));

        request.bundle_root_sha256 = Some("f".repeat(64));
        request.bundle_id = Some(" ".into());
        assert!(request
            .validate()
            .unwrap_err()
            .to_string()
            .contains("bundle id"));
    }

    #[test]
    fn remote_evidence_upload_response_must_acknowledge_submitted_bundle() {
        let request = RemoteAgentPodEvidenceUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            evidence_mode: RemoteAgentPodEvidenceMode::BundleUpload,
            bundle_sha256: "c".repeat(64),
            derived_from_bundle: false,
            bundle_id: None,
            bundle_root_sha256: None,
            event_count: 3,
            sealed_at: Utc::now(),
            secret_material_included: false,
        };
        let response = RemoteAgentPodEvidenceUploadResponse {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            accepted_bundle_sha256: "d".repeat(64),
            accepted_event_count: 3,
            lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
        };

        let err = response.validate_for(&request).unwrap_err();

        assert!(err.to_string().contains("submitted bundle"));
    }

    #[test]
    fn remote_evidence_bundle_upload_request_binds_payload_hash() {
        let bundle_json = r#"{"session_id":"session-1","events":[]}"#.to_string();
        let mut request = RemoteAgentPodEvidenceBundleUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            bundle_sha256: sha256_hex(bundle_json.as_bytes()),
            bundle_json,
            secret_material_included: false,
        };

        request.validate().unwrap();
        request.bundle_json = "{}".into();
        let err = request.validate().unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn remote_evidence_bundle_upload_response_must_acknowledge_storage() {
        let bundle_json = r#"{"session_id":"session-1","events":[]}"#.to_string();
        let request = RemoteAgentPodEvidenceBundleUploadRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            bundle_sha256: sha256_hex(bundle_json.as_bytes()),
            bundle_json,
            secret_material_included: false,
        };
        let response = RemoteAgentPodEvidenceBundleUploadResponse {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            stored_bundle_sha256: request.bundle_sha256.clone(),
            stored_bytes: 0,
            storage_path: String::new(),
            lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
        };

        let err = response.validate_for(&request).unwrap_err();

        assert!(err.to_string().contains("stored byte count"));
    }

    #[test]
    fn remote_evidence_status_response_validates_receipts_and_storage() {
        let request = RemoteAgentPodEvidenceStatusRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
        };
        let response = RemoteAgentPodEvidenceStatusResponse {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            status: RuntimeStatus::Running,
            evidence_receipts: vec![RemoteAgentPodEvidenceReceiptStatus {
                bundle_sha256: "a".repeat(64),
                derived_from_bundle: true,
                bundle_id: Some("bundle-1".into()),
                bundle_root_sha256: Some("a".repeat(64)),
                event_count: 2,
                sealed_at: Some(Utc::now()),
            }],
            stored_evidence_bundles: vec![RemoteAgentPodStoredEvidenceBundleStatus {
                bundle_sha256: "a".repeat(64),
                stored_bytes: 64,
                storage_path: "evidence/worker-session-1/a.json".into(),
            }],
        };

        response.validate_for(&request).unwrap();
    }

    #[test]
    fn remote_evidence_status_response_rejects_empty_storage_ack() {
        let request = RemoteAgentPodEvidenceStatusRequest {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
        };
        let response = RemoteAgentPodEvidenceStatusResponse {
            session_id: "session-1".into(),
            worker_session_id: "worker-session-1".into(),
            status: RuntimeStatus::Running,
            evidence_receipts: Vec::new(),
            stored_evidence_bundles: vec![RemoteAgentPodStoredEvidenceBundleStatus {
                bundle_sha256: "a".repeat(64),
                stored_bytes: 0,
                storage_path: String::new(),
            }],
        };

        let err = response.validate_for(&request).unwrap_err();

        assert!(err.to_string().contains("byte count"));
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
        let kill_switch_required = transport.kill_switch_required;
        let create = fake
            .create_session(RemoteAgentPodCreateSessionRequest {
                transport,
                handshake_ack,
                spec: spec.clone(),
                workspace_bundle: None,
            })
            .await
            .unwrap();
        let exec = fake
            .exec_command(RemoteAgentPodExecRequest {
                session_id: create.session_id.clone(),
                worker_session_id: create.worker_session_id.clone(),
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
        let destroyed = fake
            .destroy_session(RemoteAgentPodDestroySessionRequest {
                session_id: create.session_id,
                worker_session_id: create.worker_session_id,
                reason: "test teardown".into(),
                kill_switch_required,
            })
            .await
            .unwrap();

        assert_eq!(destroyed.status, RuntimeStatus::Stopped);
        assert!(destroyed
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::KillSwitchAck));
        let evidence = fake
            .upload_evidence(RemoteAgentPodEvidenceUploadRequest {
                session_id: destroyed.session_id,
                worker_session_id: destroyed.worker_session_id,
                evidence_mode: RemoteAgentPodEvidenceMode::BundleUpload,
                bundle_sha256: "e".repeat(64),
                derived_from_bundle: false,
                bundle_id: None,
                bundle_root_sha256: None,
                event_count: 4,
                sealed_at: Utc::now(),
                secret_material_included: false,
            })
            .await
            .unwrap();

        assert_eq!(evidence.accepted_event_count, 4);
        assert!(evidence
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::EvidenceSealed));
        let bundle_json = r#"{"session_id":"session-1","events":[]}"#.to_string();
        let bundle = fake
            .upload_evidence_bundle(RemoteAgentPodEvidenceBundleUploadRequest {
                session_id: evidence.session_id.clone(),
                worker_session_id: evidence.worker_session_id.clone(),
                bundle_sha256: sha256_hex(bundle_json.as_bytes()),
                bundle_json,
                secret_material_included: false,
            })
            .await
            .unwrap();

        assert!(bundle.storage_path.ends_with(".json"));
        assert!(bundle
            .lifecycle_events
            .contains(&RemoteAgentPodLifecycleEvent::EvidenceSealed));
        let status = fake
            .evidence_status(RemoteAgentPodEvidenceStatusRequest {
                session_id: evidence.session_id,
                worker_session_id: evidence.worker_session_id,
            })
            .await
            .unwrap();

        assert_eq!(status.evidence_receipts.len(), 1);
        assert_eq!(status.stored_evidence_bundles.len(), 1);

        let provider = RemoteAgentPodProvider::default();
        assert_eq!(
            provider.implementation_status(),
            ProviderImplementationStatus::Experimental
        );
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
