use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::runtime::types::ApprovalSignature;
use crate::runtime::types::{CredentialGrant, CredentialGrantKind, RuntimeSession};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FidesCredentialAuthorityRequest {
    pub schema_version: i64,
    pub action: String,
    pub session_id: String,
    pub agent_name: String,
    pub provider: String,
    pub platform: String,
    pub grant_name: String,
    pub grant_kind: CredentialGrantKind,
    pub grant_target: String,
    pub one_time: bool,
    pub requires_approval: bool,
    pub evidence_refs: Vec<String>,
}

impl FidesCredentialAuthorityRequest {
    pub fn from_session_grant(
        session: &RuntimeSession,
        grant: &CredentialGrant,
        evidence_refs: Vec<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            action: "agentbox.credential_grant.authorize".to_string(),
            session_id: session.id.clone(),
            agent_name: session.spec.agent.name.clone(),
            provider: session.provider.clone(),
            platform: session.platform.clone(),
            grant_name: grant.name.clone(),
            grant_kind: grant.kind.clone(),
            grant_target: grant.target.clone(),
            one_time: grant.one_time,
            requires_approval: grant.requires_approval,
            evidence_refs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FidesCredentialAuthorityDecision {
    Allow,
    Deny { reason: String },
    RequiresExternalAuthority { reason: String },
}

pub trait FidesCredentialAuthorityHook: Send + Sync {
    fn evaluate_credential_grant(
        &self,
        request: &FidesCredentialAuthorityRequest,
    ) -> FidesCredentialAuthorityDecision;
}

pub struct NoopFidesCredentialAuthorityHook;

impl FidesCredentialAuthorityHook for NoopFidesCredentialAuthorityHook {
    fn evaluate_credential_grant(
        &self,
        _request: &FidesCredentialAuthorityRequest,
    ) -> FidesCredentialAuthorityDecision {
        FidesCredentialAuthorityDecision::RequiresExternalAuthority {
            reason: "FIDES runtime is not configured".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FidesSignedActionDraft {
    pub schema_version: i64,
    pub action_id: String,
    pub action_type: String,
    pub actor: String,
    pub subject: String,
    pub decision: String,
    pub evidence_refs: Vec<String>,
    pub signature: Option<ApprovalSignature>,
}

impl FidesSignedActionDraft {
    pub fn from_audit_event(session: &RuntimeSession, event: &AuditEvent) -> Self {
        Self {
            schema_version: 1,
            action_id: event.id.clone(),
            action_type: format!("agentbox.{}", event.bucket),
            actor: session.spec.agent.name.clone(),
            subject: session.id.clone(),
            decision: event.decision.clone(),
            evidence_refs: event.event_hash.iter().cloned().collect(),
            signature: None,
        }
    }

    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    pub fn requires_signature(&self) -> bool {
        self.signature.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEvent;
    use crate::runtime::types::{FilesystemPolicy, MinipodSpec, RuntimeSession, RuntimeStatus};
    use chrono::Utc;

    fn session_with_grant() -> (RuntimeSession, CredentialGrant) {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let grant = CredentialGrant {
            name: "openai".into(),
            kind: CredentialGrantKind::FileMount,
            target: "/tmp/agentbox-openai-key".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        };
        spec.filesystem = FilesystemPolicy::workspace("/tmp/agentbox-work");
        let session = RuntimeSession {
            id: "01agentboxsession".into(),
            name: spec.name.clone(),
            provider: "agentpod-linux".into(),
            platform: "linux".into(),
            status: RuntimeStatus::Running,
            spec,
            approval_grants: vec![],
            transcripts: vec![],
            started_at: Utc::now(),
            stopped_at: None,
        };

        (session, grant)
    }

    #[test]
    fn fides_credential_authority_request_carries_grant_boundary() {
        let (session, grant) = session_with_grant();

        let request = FidesCredentialAuthorityRequest::from_session_grant(
            &session,
            &grant,
            vec!["audit-event-1".into()],
        );

        assert_eq!(request.schema_version, 1);
        assert_eq!(request.action, "agentbox.credential_grant.authorize");
        assert_eq!(request.session_id, session.id);
        assert_eq!(request.agent_name, "hermes");
        assert_eq!(request.grant_name, "openai");
        assert!(matches!(request.grant_kind, CredentialGrantKind::FileMount));
        assert!(request.one_time);
        assert!(request.requires_approval);
        assert_eq!(request.evidence_refs, vec!["audit-event-1"]);
    }

    #[test]
    fn noop_fides_hook_never_claims_authority() {
        let (session, grant) = session_with_grant();
        let request = FidesCredentialAuthorityRequest::from_session_grant(&session, &grant, vec![]);
        let hook = NoopFidesCredentialAuthorityHook;

        let decision = hook.evaluate_credential_grant(&request);

        assert!(matches!(
            decision,
            FidesCredentialAuthorityDecision::RequiresExternalAuthority { .. }
        ));
    }

    #[test]
    fn fides_signed_action_draft_maps_audit_decisions_without_fake_signature() {
        let (session, _) = session_with_grant();
        let mut event = AuditEvent::new(
            0,
            Some("hermes".into()),
            format!("runtime.exec {} git push", session.id),
            "/tmp/agentbox-work".into(),
            "approval".into(),
            "grant:grant-git-push:exit_code:0".into(),
            None,
            Some("agentpod-linux".into()),
        );
        event.event_hash = Some("event-hash-1".into());

        let draft = FidesSignedActionDraft::from_audit_event(&session, &event);

        assert_eq!(draft.schema_version, 1);
        assert_eq!(draft.action_id, event.id);
        assert_eq!(draft.action_type, "agentbox.approval");
        assert_eq!(draft.actor, "hermes");
        assert_eq!(draft.subject, session.id);
        assert_eq!(draft.evidence_refs, vec!["event-hash-1"]);
        assert!(!draft.is_signed());
        assert!(draft.requires_signature());
    }
}
