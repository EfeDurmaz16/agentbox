use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::AuditEvent;
use crate::runtime::types::RuntimeSession;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgitEvidenceAdapterDescriptor {
    pub schema_version: i64,
    pub integration: String,
    pub descriptor_kind: String,
    pub status: String,
    pub live_support: bool,
    pub requires_external_adapter: bool,
    pub supported_refs: Vec<String>,
    pub claim_boundary: String,
    pub verification_command: String,
}

impl Default for AgitEvidenceAdapterDescriptor {
    fn default() -> Self {
        Self {
            schema_version: 1,
            integration: "agit".to_string(),
            descriptor_kind: "workspace-diff-evidence-boundary".to_string(),
            status: "external-adapter-required".to_string(),
            live_support: false,
            requires_external_adapter: true,
            supported_refs: vec![
                "audit-event".to_string(),
                "commit-id".to_string(),
                "workspace-diff-ref".to_string(),
                "patch-sha256".to_string(),
            ],
            claim_boundary:
                "Agentbox can reference workspace diff snapshots for AGIT lineage, but it does not publish commits or lineage records without an external AGIT adapter."
                    .to_string(),
            verification_command: "cargo test --locked -p agentbox-daemon agit".to_string(),
        }
    }
}

pub fn agit_evidence_adapter_descriptor() -> AgitEvidenceAdapterDescriptor {
    AgitEvidenceAdapterDescriptor::default()
}

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
pub struct AgitWorkspaceDiffEvidenceRef {
    pub schema_version: i64,
    pub snapshot_id: String,
    pub session_id: String,
    pub workspace: String,
    pub patch_ref: String,
    pub patch_sha256: String,
    pub patch_bytes: usize,
    pub evidence_hash: String,
    pub live_support: bool,
    pub requires_external_adapter: bool,
}

impl AgitWorkspaceDiffEvidenceRef {
    pub fn from_patch(
        session: &RuntimeSession,
        snapshot_id: impl Into<String>,
        patch_ref: impl Into<String>,
        patch: &str,
        evidence_hash: impl Into<String>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(patch.as_bytes());
        Self {
            schema_version: 1,
            snapshot_id: snapshot_id.into(),
            session_id: session.id.clone(),
            workspace: session
                .spec
                .filesystem
                .workspace_host_path
                .display()
                .to_string(),
            patch_ref: patch_ref.into(),
            patch_sha256: format!("sha256:{:x}", hasher.finalize()),
            patch_bytes: patch.len(),
            evidence_hash: evidence_hash.into(),
            live_support: false,
            requires_external_adapter: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgitEvidencePublishDecision {
    Published { record_id: String },
    RequiresExternalAdapter { reason: String },
}

pub trait AgitEvidencePublisher: Send + Sync {
    fn descriptor(&self) -> AgitEvidenceAdapterDescriptor {
        agit_evidence_adapter_descriptor()
    }

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
            transcripts: vec![],
            started_at: Utc::now(),
            stopped_at: None,
        }
    }

    #[test]
    fn agit_descriptor_never_claims_live_publication() {
        let descriptor = agit_evidence_adapter_descriptor();

        assert_eq!(descriptor.schema_version, 1);
        assert_eq!(descriptor.integration, "agit");
        assert_eq!(descriptor.status, "external-adapter-required");
        assert!(!descriptor.live_support);
        assert!(descriptor.requires_external_adapter);
        assert!(descriptor
            .supported_refs
            .contains(&"workspace-diff-ref".to_string()));
        assert!(descriptor
            .claim_boundary
            .contains("does not publish commits"));
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
    fn agit_workspace_diff_ref_can_point_to_local_patch_without_service() {
        let session = session();
        let diff_ref = AgitWorkspaceDiffEvidenceRef::from_patch(
            &session,
            "diff-snapshot-1",
            "workspace-diff.patch",
            "diff --git a/README.md b/README.md\n+agentbox\n",
            "event-hash-1",
        );

        assert_eq!(diff_ref.schema_version, 1);
        assert_eq!(diff_ref.session_id, session.id);
        assert_eq!(diff_ref.workspace, "/tmp/agentbox-work");
        assert_eq!(diff_ref.patch_ref, "workspace-diff.patch");
        assert_eq!(
            diff_ref.patch_sha256,
            "sha256:ad233596931db62e18f5f3ed86c79e740d975bd498384af244cff2fcf779cf7e"
        );
        assert_eq!(diff_ref.patch_bytes, 45);
        assert_eq!(diff_ref.evidence_hash, "event-hash-1");
        assert!(!diff_ref.live_support);
        assert!(diff_ref.requires_external_adapter);
    }

    #[test]
    fn agit_workspace_diff_fixture_contains_patch_hash_boundary() {
        let diff_ref: AgitWorkspaceDiffEvidenceRef =
            serde_json::from_str(include_str!("../../fixtures/agit-workspace-diff-ref.json"))
                .unwrap();

        assert_eq!(diff_ref.snapshot_id, "diff-snapshot-1");
        assert_eq!(diff_ref.patch_ref, "workspace-diff.patch");
        assert_eq!(diff_ref.patch_bytes, 45);
        assert_eq!(
            diff_ref.patch_sha256,
            "sha256:ad233596931db62e18f5f3ed86c79e740d975bd498384af244cff2fcf779cf7e"
        );
        assert_eq!(diff_ref.evidence_hash, "event-hash-1");
        assert!(!diff_ref.live_support);
        assert!(diff_ref.requires_external_adapter);
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

        let descriptor = publisher.descriptor();
        let decision = publisher.publish_lineage(&record);

        assert!(!descriptor.live_support);
        assert!(descriptor.requires_external_adapter);
        assert!(matches!(
            decision,
            AgitEvidencePublishDecision::RequiresExternalAdapter { .. }
        ));
    }
}
