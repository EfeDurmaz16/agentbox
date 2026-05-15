use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use ulid::Ulid;

use crate::audit::redact_sensitive_text;
use crate::runtime::types::{ApprovalScope, CredentialGrantKind, FileAccessMode};

pub const HOST_BRIDGE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostBridgeTransport {
    UnixSocket { path: PathBuf },
    NamedPipe { path: String },
    Vsock { cid: u32, port: u32 },
    RemoteTunnel { endpoint: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostBridgeTransportKind {
    UnixSocket,
    NamedPipe,
    Vsock,
    RemoteTunnel,
}

impl HostBridgeTransport {
    pub fn kind(&self) -> HostBridgeTransportKind {
        match self {
            Self::UnixSocket { .. } => HostBridgeTransportKind::UnixSocket,
            Self::NamedPipe { .. } => HostBridgeTransportKind::NamedPipe,
            Self::Vsock { .. } => HostBridgeTransportKind::Vsock,
            Self::RemoteTunnel { .. } => HostBridgeTransportKind::RemoteTunnel,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostBridgeDecision {
    Allow,
    Approve,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBridgeEnvelope {
    #[serde(default = "default_host_bridge_schema_version")]
    pub schema_version: u32,
    pub request_id: String,
    pub session_id: String,
    pub provider: String,
    pub transport: HostBridgeTransport,
    pub request: HostBridgeRequest,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
}

impl HostBridgeEnvelope {
    pub fn new(
        session_id: impl Into<String>,
        provider: impl Into<String>,
        transport: HostBridgeTransport,
        request: HostBridgeRequest,
    ) -> Self {
        Self {
            schema_version: HOST_BRIDGE_SCHEMA_VERSION,
            request_id: Ulid::new().to_string(),
            session_id: session_id.into(),
            provider: provider.into(),
            transport,
            request,
            metadata: BTreeMap::new(),
            created_at: Utc::now(),
        }
    }

    pub fn to_evidence_event(&self) -> HostBridgeEvidenceEvent {
        let mut payload =
            serde_json::to_value(&self.request).expect("host bridge request must serialize");
        redact_json_strings(&mut payload);

        HostBridgeEvidenceEvent {
            schema_version: self.schema_version,
            request_id: self.request_id.clone(),
            session_id: self.session_id.clone(),
            provider: self.provider.clone(),
            transport: self.transport.kind(),
            request_kind: self.request.kind(),
            payload,
            redacted: true,
            metadata: self
                .metadata
                .iter()
                .map(|(key, value)| (key.clone(), redact_sensitive_text(value)))
                .collect(),
            created_at: self.created_at,
        }
    }
}

fn default_host_bridge_schema_version() -> u32 {
    HOST_BRIDGE_SCHEMA_VERSION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBridgeEvidenceEvent {
    pub schema_version: u32,
    pub request_id: String,
    pub session_id: String,
    pub provider: String,
    pub transport: HostBridgeTransportKind,
    pub request_kind: HostBridgeRequestKind,
    pub payload: Value,
    pub redacted: bool,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload")]
pub enum HostBridgeRequest {
    CommandMediation(CommandMediationRequest),
    FileGrant(FileGrantRequest),
    CredentialGrant(CredentialGrantRequest),
    NetworkFirstContact(NetworkFirstContactRequest),
    ApprovalResponse(ApprovalResponseRequest),
    EvidenceAppend(EvidenceAppendRequest),
    KillSwitch(KillSwitchRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostBridgeRequestKind {
    CommandMediation,
    FileGrant,
    CredentialGrant,
    NetworkFirstContact,
    ApprovalResponse,
    EvidenceAppend,
    KillSwitch,
}

impl HostBridgeRequest {
    pub fn kind(&self) -> HostBridgeRequestKind {
        match self {
            Self::CommandMediation(_) => HostBridgeRequestKind::CommandMediation,
            Self::FileGrant(_) => HostBridgeRequestKind::FileGrant,
            Self::CredentialGrant(_) => HostBridgeRequestKind::CredentialGrant,
            Self::NetworkFirstContact(_) => HostBridgeRequestKind::NetworkFirstContact,
            Self::ApprovalResponse(_) => HostBridgeRequestKind::ApprovalResponse,
            Self::EvidenceAppend(_) => HostBridgeRequestKind::EvidenceAppend,
            Self::KillSwitch(_) => HostBridgeRequestKind::KillSwitch,
        }
    }
}

fn redact_json_strings(value: &mut Value) {
    match value {
        Value::String(raw) => {
            *raw = redact_sensitive_text(raw);
        }
        Value::Array(values) => {
            for item in values {
                redact_json_strings(item);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                redact_json_strings(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandMediationRequest {
    pub argv: Vec<String>,
    pub cwd: String,
    #[serde(default)]
    pub env_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileGrantRequest {
    pub host_path: PathBuf,
    pub guest_path: String,
    pub access: FileAccessMode,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGrantRequest {
    pub grant_name: String,
    pub kind: CredentialGrantKind,
    pub target: String,
    pub one_time: bool,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkFirstContactRequest {
    pub destination: String,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub classified_risk: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalResponseRequest {
    pub approval_id: String,
    pub scope: ApprovalScope,
    pub decision: HostBridgeDecision,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAppendRequest {
    pub stream: String,
    pub event_ref: String,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchRequest {
    pub reason: String,
    pub requested_by: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_envelope_roundtrips_command_mediation() {
        let envelope = HostBridgeEnvelope::new(
            "01session",
            "agentpod-macos",
            HostBridgeTransport::Vsock { cid: 3, port: 9000 },
            HostBridgeRequest::CommandMediation(CommandMediationRequest {
                argv: vec!["git".into(), "push".into()],
                cwd: "/workspace".into(),
                env_keys: vec!["PATH".into()],
            }),
        );

        let encoded = serde_json::to_string(&envelope).unwrap();
        let decoded: HostBridgeEnvelope = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded.schema_version, HOST_BRIDGE_SCHEMA_VERSION);
        assert_eq!(decoded.session_id, "01session");
        assert_eq!(decoded.transport.kind(), HostBridgeTransportKind::Vsock);
        assert!(matches!(
            decoded.request,
            HostBridgeRequest::CommandMediation(_)
        ));
    }

    #[test]
    fn bridge_models_credential_and_network_requests_without_secret_values() {
        let credential = HostBridgeRequest::CredentialGrant(CredentialGrantRequest {
            grant_name: "openai".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "OPENAI_API_KEY".into(),
            one_time: true,
            requires_approval: true,
        });
        let network = HostBridgeRequest::NetworkFirstContact(NetworkFirstContactRequest {
            destination: "api.openai.com".into(),
            protocol: Some("https".into()),
            port: Some(443),
            classified_risk: Some("public-api".into()),
        });

        assert!(serde_json::to_string(&credential)
            .unwrap()
            .contains("OPENAI_API_KEY"));
        assert!(serde_json::to_string(&network)
            .unwrap()
            .contains("api.openai.com"));
    }

    #[test]
    fn bridge_models_approval_evidence_and_kill_switch_requests() {
        let approval = HostBridgeRequest::ApprovalResponse(ApprovalResponseRequest {
            approval_id: "approval-1".into(),
            scope: ApprovalScope::Session {
                session_id: "01session".into(),
            },
            decision: HostBridgeDecision::Allow,
            reason: "operator approved".into(),
        });
        let evidence = HostBridgeRequest::EvidenceAppend(EvidenceAppendRequest {
            stream: "commands.jsonl".into(),
            event_ref: "audit:01event".into(),
            redacted: true,
        });
        let kill = HostBridgeRequest::KillSwitch(KillSwitchRequest {
            reason: "operator stopped session".into(),
            requested_by: "cli".into(),
        });

        assert!(matches!(approval, HostBridgeRequest::ApprovalResponse(_)));
        assert!(matches!(evidence, HostBridgeRequest::EvidenceAppend(_)));
        assert!(matches!(kill, HostBridgeRequest::KillSwitch(_)));
    }

    #[test]
    fn bridge_evidence_event_redacts_sensitive_payload_strings() {
        let mut envelope = HostBridgeEnvelope::new(
            "01session",
            "direct-host",
            HostBridgeTransport::UnixSocket {
                path: "/tmp/agentbox.sock".into(),
            },
            HostBridgeRequest::CommandMediation(CommandMediationRequest {
                argv: vec![
                    "curl".into(),
                    "--token=sk-test-secret".into(),
                    "https://user:pass@example.com".into(),
                ],
                cwd: "/Users/operator/.ssh/id_rsa".into(),
                env_keys: vec!["OPENAI_API_KEY".into()],
            }),
        );
        envelope.metadata.insert(
            "operator_note".into(),
            "uses AWS_SECRET_ACCESS_KEY=abc".into(),
        );

        let evidence = envelope.to_evidence_event();
        let encoded = serde_json::to_string(&evidence).unwrap();

        assert_eq!(evidence.transport, HostBridgeTransportKind::UnixSocket);
        assert_eq!(
            evidence.request_kind,
            HostBridgeRequestKind::CommandMediation
        );
        assert!(evidence.redacted);
        assert!(encoded.contains("<redacted>"));
        assert!(!encoded.contains("sk-test-secret"));
        assert!(!encoded.contains("user:pass"));
        assert!(!encoded.contains("/Users/operator/.ssh/id_rsa"));
        assert!(!encoded.contains("AWS_SECRET_ACCESS_KEY=abc"));
    }
}
