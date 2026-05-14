use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
