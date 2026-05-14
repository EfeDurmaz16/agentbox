use std::sync::Arc;

use chrono::Utc;

use crate::audit::{AuditEvent, AuditStore};
use crate::runtime::policy::validate_minipod_spec;
use crate::runtime::provider::{RuntimeError, RuntimeProvider};
use crate::runtime::session::RuntimeSessionStore;
use crate::runtime::types::{
    ApprovalGrant, CommandResult, ExecCommand, MinipodSpec, RuntimeSession, RuntimeStatus,
};

pub struct RuntimeManager {
    provider: Arc<dyn RuntimeProvider>,
    sessions: RuntimeSessionStore,
    audit: AuditStore,
}

impl RuntimeManager {
    pub fn new(
        provider: Arc<dyn RuntimeProvider>,
        sessions: RuntimeSessionStore,
        audit: AuditStore,
    ) -> Self {
        Self {
            provider,
            sessions,
            audit,
        }
    }

    pub async fn create(&self, spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError> {
        if let Err(error) = validate_minipod_spec(spec) {
            self.audit_manifest_rejection(spec, &error)?;
            return Err(error);
        }

        if !self.provider.is_available().await {
            return Err(RuntimeError::Unavailable(self.provider.name().to_string()));
        }

        if self
            .sessions
            .get(&spec.id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .is_some()
        {
            return Err(RuntimeError::AlreadyExists(spec.id.clone()));
        }

        let mut session = self.provider.create(spec).await?;
        if matches!(session.status, RuntimeStatus::Creating) {
            session.status = RuntimeStatus::Running;
        }

        self.sessions
            .upsert(session.clone())
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;
        self.audit_runtime_event("runtime.create", &session, "runtime", "created", None, None)?;

        Ok(session)
    }

    pub async fn exec(
        &self,
        session_id: &str,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        let session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;

        let result = self.provider.exec(session_id, command).await?;
        let command_text = format!("runtime.exec {} {}", session_id, command.argv.join(" "));
        let decision = format!("exit_code:{}", result.exit_code);

        self.audit_runtime_event(
            &command_text,
            &session,
            "runtime",
            &decision,
            None,
            Some(self.provider.name().to_string()),
        )?;

        Ok(result)
    }

    pub async fn refresh_status(&self, session_id: &str) -> Result<RuntimeSession, RuntimeError> {
        let mut session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;

        session.status = self.provider.status(session_id).await?;
        if matches!(
            session.status,
            RuntimeStatus::Stopped | RuntimeStatus::Failed(_)
        ) {
            session.stopped_at = Some(Utc::now());
        }

        self.sessions
            .upsert(session.clone())
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;

        Ok(session)
    }

    pub async fn destroy(&self, session_id: &str) -> Result<(), RuntimeError> {
        let mut session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;

        self.provider.destroy(session_id).await?;
        session.status = RuntimeStatus::Stopped;
        session.stopped_at = Some(Utc::now());

        self.audit_runtime_event(
            "runtime.destroy",
            &session,
            "runtime",
            "destroyed",
            None,
            Some(self.provider.name().to_string()),
        )?;
        self.sessions
            .remove(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;

        Ok(())
    }

    pub fn add_session_approval_grant(
        &self,
        session_id: &str,
        grant: ApprovalGrant,
    ) -> Result<ApprovalGrant, RuntimeError> {
        let mut session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        let grant = grant.bound_to_session(session_id);
        if let Some(scope_session_id) = grant.session_scope_id() {
            if scope_session_id != session_id {
                return Err(RuntimeError::ManifestRejected(format!(
                    "approval grant {} is scoped to another session",
                    grant.id
                )));
            }
        }

        session.approval_grants.push(grant.clone());
        self.sessions
            .upsert(session.clone())
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;
        self.audit_runtime_event(
            "runtime.approval_grant",
            &session,
            "approval",
            &format!("grant_added:{}", grant.id),
            None,
            Some(self.provider.name().to_string()),
        )?;

        Ok(grant)
    }

    pub fn session_approval_grants(
        &self,
        session_id: &str,
    ) -> Result<Vec<ApprovalGrant>, RuntimeError> {
        let session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;

        Ok(session.approval_grants)
    }

    pub fn list_sessions(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
        self.sessions
            .list()
            .map_err(|e| RuntimeError::Internal(e.to_string()))
    }

    fn audit_runtime_event(
        &self,
        command: &str,
        session: &RuntimeSession,
        bucket: &str,
        decision: &str,
        user_response_ms: Option<i64>,
        parent_process: Option<String>,
    ) -> Result<(), RuntimeError> {
        let event = AuditEvent::new(
            0,
            Some(session.spec.agent.name.clone()),
            format!("{command} {}", session.id),
            session
                .spec
                .filesystem
                .workspace_host_path
                .display()
                .to_string(),
            bucket.to_string(),
            decision.to_string(),
            user_response_ms,
            parent_process,
        );

        self.audit
            .log_event(&event)
            .map_err(|e| RuntimeError::Internal(e.to_string()))
    }

    fn audit_manifest_rejection(
        &self,
        spec: &MinipodSpec,
        error: &RuntimeError,
    ) -> Result<(), RuntimeError> {
        let event = AuditEvent::new(
            0,
            Some(spec.agent.name.clone()),
            format!("runtime.validate {}", spec.id),
            spec.filesystem.workspace_host_path.display().to_string(),
            "filesystem".to_string(),
            format!("rejected:{error}"),
            None,
            Some(self.provider.name().to_string()),
        );

        self.audit
            .log_event(&event)
            .map_err(|e| RuntimeError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::fs;

    use crate::runtime::types::{ApprovalScope, RuntimeCapability};

    struct MockProvider;

    #[async_trait]
    impl RuntimeProvider for MockProvider {
        fn name(&self) -> &str {
            "native-mock"
        }

        fn platform(&self) -> &str {
            "test"
        }

        fn capabilities(&self) -> &[RuntimeCapability] {
            &[
                RuntimeCapability::FilesystemPolicy,
                RuntimeCapability::EvidenceExport,
            ]
        }

        async fn is_available(&self) -> bool {
            true
        }

        async fn create(&self, spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError> {
            Ok(RuntimeSession::new(
                spec.name.clone(),
                self.name().to_string(),
                self.platform().to_string(),
                spec.clone(),
            ))
        }

        async fn exec(
            &self,
            _session_id: &str,
            command: &ExecCommand,
        ) -> Result<CommandResult, RuntimeError> {
            Ok(CommandResult {
                exit_code: 0,
                stdout: command.argv.join(" "),
                stderr: String::new(),
                duration_ms: 3,
            })
        }

        async fn status(&self, _session_id: &str) -> Result<RuntimeStatus, RuntimeError> {
            Ok(RuntimeStatus::Running)
        }

        async fn destroy(&self, _session_id: &str) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
            Ok(vec![])
        }
    }

    fn session_store(name: &str) -> RuntimeSessionStore {
        let path = std::env::temp_dir().join(format!(
            "agentbox-runtime-manager-{}-{name}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        RuntimeSessionStore::new(path)
    }

    fn manager(name: &str) -> RuntimeManager {
        RuntimeManager::new(
            Arc::new(MockProvider),
            session_store(name),
            AuditStore::in_memory().unwrap(),
        )
    }

    #[tokio::test]
    async fn create_persists_session_and_audit_event() {
        let manager = manager("create");
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");

        let session = manager.create(&spec).await.unwrap();

        assert_eq!(session.id, spec.id);
        assert_eq!(session.provider, "native-mock");
        assert!(matches!(session.status, RuntimeStatus::Running));
        assert_eq!(manager.list_sessions().unwrap().len(), 1);

        let audit = manager.audit.recent(1).unwrap();
        assert_eq!(audit[0].bucket, "runtime");
        assert_eq!(audit[0].decision, "created");
        assert!(audit[0].event_hash.is_some());
    }

    #[tokio::test]
    async fn exec_requires_existing_session_and_records_evidence() {
        let manager = manager("exec");
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["echo".to_string(), "hello".to_string()],
            working_dir: None,
            env: Default::default(),
            timeout_seconds: None,
        };

        let result = manager.exec(&session.id, &command).await.unwrap();

        assert_eq!(result.stdout, "echo hello");
        let audit = manager.audit.recent(2).unwrap();
        assert_eq!(audit[0].decision, "exit_code:0");
        assert!(audit[0].command.contains("runtime.exec"));
        assert_eq!(audit[0].prev_hash, audit[1].event_hash);
    }

    #[tokio::test]
    async fn destroy_removes_session_and_records_evidence() {
        let manager = manager("destroy");
        let spec = MinipodSpec::for_agent_task("aspendos", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();

        manager.destroy(&session.id).await.unwrap();

        assert!(manager.list_sessions().unwrap().is_empty());
        let audit = manager.audit.recent(1).unwrap();
        assert_eq!(audit[0].decision, "destroyed");
        assert!(audit[0].command.contains("runtime.destroy"));
    }

    #[tokio::test]
    async fn rejected_manifest_records_filesystem_evidence() {
        let manager = manager("manifest-rejection");
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.credentials.inherit_host_env = true;

        let err = manager.create(&spec).await.unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
        let audit = manager.audit.recent(1).unwrap();
        assert_eq!(audit[0].bucket, "filesystem");
        assert!(audit[0].decision.contains("rejected:"));
        assert!(audit[0].command.contains("runtime.validate"));
        assert!(audit[0].event_hash.is_some());
    }

    #[tokio::test]
    async fn session_approval_grants_persist_with_session() {
        let manager = manager("session-approvals");
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();
        let grant = ApprovalGrant {
            id: "grant-session".into(),
            scope: ApprovalScope::Session {
                session_id: String::new(),
            },
            reason: "operator approved this session".into(),
            expires_at: None,
        };

        let saved = manager
            .add_session_approval_grant(&session.id, grant)
            .unwrap();
        let grants = manager.session_approval_grants(&session.id).unwrap();

        assert_eq!(saved.session_scope_id(), Some(session.id.as_str()));
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, "grant-session");
        let audit = manager.audit.recent(1).unwrap();
        assert_eq!(audit[0].bucket, "approval");
        assert_eq!(audit[0].decision, "grant_added:grant-session");
    }

    #[tokio::test]
    async fn destroy_expires_session_approval_grants() {
        let manager = manager("session-approval-destroy");
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();
        manager
            .add_session_approval_grant(
                &session.id,
                ApprovalGrant {
                    id: "grant-session".into(),
                    scope: ApprovalScope::Session {
                        session_id: session.id.clone(),
                    },
                    reason: "operator approved this session".into(),
                    expires_at: None,
                },
            )
            .unwrap();

        manager.destroy(&session.id).await.unwrap();

        assert!(matches!(
            manager.session_approval_grants(&session.id),
            Err(RuntimeError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn rejects_session_approval_grant_for_another_session() {
        let manager = manager("session-approval-mismatch");
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();

        let err = manager
            .add_session_approval_grant(
                &session.id,
                ApprovalGrant {
                    id: "grant-session".into(),
                    scope: ApprovalScope::Session {
                        session_id: "another-session".into(),
                    },
                    reason: "operator approved another session".into(),
                    expires_at: None,
                },
            )
            .unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }
}
