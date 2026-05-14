use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::runtime::types::RuntimeSession;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgitLineageKind {
    Command,
    Approval,
    Boundary,
    Credential,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgitEvidenceLineageRecord {
    pub schema_version: i64,
    pub session_id: String,
    pub agent_name: String,
    pub provider: String,
    pub workspace: String,
    pub audit_event_id: String,
    pub lineage_kind: AgitLineageKind,
    pub action: String,
    pub decision: String,
    pub evidence_hash: Option<String>,
    pub previous_evidence_hash: Option<String>,
    pub commit_id: Option<String>,
    pub workspace_diff_ref: Option<String>,
}

impl AgitEvidenceLineageRecord {
    pub fn from_audit_event(session: &RuntimeSession, event: &AuditEvent) -> Self {
        Self {
            schema_version: 1,
            session_id: session.id.clone(),
            agent_name: session.spec.agent.name.clone(),
            provider: session.provider.clone(),
            workspace: session
                .spec
                .filesystem
                .workspace_host_path
                .display()
                .to_string(),
            audit_event_id: event.id.clone(),
            lineage_kind: lineage_kind_for_bucket(&event.bucket),
            action: event.command.clone(),
            decision: event.decision.clone(),
            evidence_hash: event.event_hash.clone(),
            previous_evidence_hash: event.prev_hash.clone(),
            commit_id: None,
            workspace_diff_ref: None,
        }
    }

    pub fn attach_commit(mut self, commit_id: impl Into<String>) -> Self {
        self.commit_id = Some(commit_id.into());
        self
    }

    pub fn attach_workspace_diff(mut self, diff_ref: impl Into<String>) -> Self {
        self.workspace_diff_ref = Some(diff_ref.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgitEvidencePublishDecision {
    Published { record_id: String },
    RequiresExternalAdapter { reason: String },
}

pub trait AgitEvidencePublisher: Send + Sync {
    fn publish_lineage(&self, record: &AgitEvidenceLineageRecord) -> AgitEvidencePublishDecision;
}

pub struct NoopAgitEvidencePublisher;

impl AgitEvidencePublisher for NoopAgitEvidencePublisher {
    fn publish_lineage(&self, _record: &AgitEvidenceLineageRecord) -> AgitEvidencePublishDecision {
        AgitEvidencePublishDecision::RequiresExternalAdapter {
            reason: "agit runtime is not configured".to_string(),
        }
    }
}

fn lineage_kind_for_bucket(bucket: &str) -> AgitLineageKind {
    match bucket {
        "allow" | "block" => AgitLineageKind::Command,
        "approve" | "approval" => AgitLineageKind::Approval,
        "credential" => AgitLineageKind::Credential,
        "runtime" => AgitLineageKind::Runtime,
        _ => AgitLineageKind::Boundary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::{FilesystemPolicy, MinipodSpec, RuntimeSession, RuntimeStatus};
    use chrono::Utc;

    fn session() -> RuntimeSession {
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.filesystem = FilesystemPolicy::workspace("/tmp/agentbox-work");
        RuntimeSession {
            id: "01agentboxsession".into(),
            name: spec.name.clone(),
            provider: "agentpod-linux".into(),
            platform: "linux".into(),
            status: RuntimeStatus::Running,
            spec,
            approval_grants: vec![],
            started_at: Utc::now(),
            stopped_at: None,
        }
    }

    #[test]
    fn agit_lineage_record_maps_audit_event_without_claiming_commit() {
        let session = session();
        let mut event = AuditEvent::new(
            0,
            Some("openclaw".into()),
            format!("runtime.exec {} cargo test", session.id),
            "/tmp/agentbox-work".into(),
            "runtime".into(),
            "allow:exit_code:0".into(),
            None,
            Some("agentpod-linux".into()),
        );
        event.prev_hash = Some("previous-hash".into());
        event.event_hash = Some("event-hash".into());

        let record = AgitEvidenceLineageRecord::from_audit_event(&session, &event);

        assert_eq!(record.schema_version, 1);
        assert_eq!(record.session_id, session.id);
        assert_eq!(record.agent_name, "openclaw");
        assert_eq!(record.provider, "agentpod-linux");
        assert_eq!(record.workspace, "/tmp/agentbox-work");
        assert_eq!(record.audit_event_id, event.id);
        assert_eq!(record.lineage_kind, AgitLineageKind::Runtime);
        assert_eq!(record.evidence_hash.as_deref(), Some("event-hash"));
        assert_eq!(
            record.previous_evidence_hash.as_deref(),
            Some("previous-hash")
        );
        assert_eq!(record.commit_id, None);
        assert_eq!(record.workspace_diff_ref, None);
    }

    #[test]
    fn agit_lineage_record_can_attach_external_commit_and_diff_refs() {
        let session = session();
        let mut event = AuditEvent::new(
            0,
            Some("openclaw".into()),
            format!("runtime.exec {} git diff", session.id),
            "/tmp/agentbox-work".into(),
            "allow".into(),
            "allow:exit_code:0".into(),
            None,
            Some("agentpod-linux".into()),
        );
        event.event_hash = Some("event-hash".into());

        let record = AgitEvidenceLineageRecord::from_audit_event(&session, &event)
            .attach_commit("agit-commit-1")
            .attach_workspace_diff("diff-snapshot-1");

        assert_eq!(record.lineage_kind, AgitLineageKind::Command);
        assert_eq!(record.commit_id.as_deref(), Some("agit-commit-1"));
        assert_eq!(
            record.workspace_diff_ref.as_deref(),
            Some("diff-snapshot-1")
        );
    }

    #[test]
    fn noop_agit_publisher_never_claims_live_integration() {
        let session = session();
        let event = AuditEvent::new(
            0,
            Some("openclaw".into()),
            format!("runtime.exec {} git status", session.id),
            "/tmp/agentbox-work".into(),
            "allow".into(),
            "allow:exit_code:0".into(),
            None,
            Some("agentpod-linux".into()),
        );
        let record = AgitEvidenceLineageRecord::from_audit_event(&session, &event);
        let publisher = NoopAgitEvidencePublisher;

        let decision = publisher.publish_lineage(&record);

        assert!(matches!(
            decision,
            AgitEvidencePublishDecision::RequiresExternalAdapter { .. }
        ));
    }
}
