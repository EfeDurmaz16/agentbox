use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use ulid::Ulid;

use crate::runtime::types::{ApprovalScope, CredentialGrantKind, FileAccessMode};

pub const HOST_BRIDGE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostBridgeTransport {
    UnixSocket { path: PathBuf },
    NamedPipe { path: String },
    Vsock { cid: u32, port: u32 },
    RemoteTunnel { endpoint: String },
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
}

fn default_host_bridge_schema_version() -> u32 {
    HOST_BRIDGE_SCHEMA_VERSION
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
}
