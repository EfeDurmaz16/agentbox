use std::sync::Arc;

use agentbox_policy::classify::{self, Bucket, Classification, PolicyConfig, PolicyNetworkMode};
use chrono::Utc;

use crate::audit::{AuditEvent, AuditStore};
use crate::runtime::approval::{
    command_context_for_session, consume_once_grant, grant_matches_command,
};
use crate::runtime::policy::validate_minipod_spec;
use crate::runtime::provider::{RuntimeError, RuntimeProvider};
use crate::runtime::session::RuntimeSessionStore;
use crate::runtime::types::{
    ApprovalGrant, CommandResult, CommandTranscript, CredentialGrant, CredentialGrantKind,
    ExecCommand, MinipodSpec, RuntimeSession, RuntimeStatus,
};
use crate::runtime::workspace::{
    WorkspaceDiffSnapshot, WorkspaceDiffSnapshotter, WorkspaceProjectionApplier,
    WorkspaceProjectionApply, WorkspaceProjectionCommit, WorkspaceProjectionCommitter,
    WorkspaceProjectionDiscard, WorkspaceProjectionDiscarder,
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
        let mut session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        if !matches!(session.status, RuntimeStatus::Running) {
            return Err(RuntimeError::PolicyDenied(format!(
                "cannot exec in session {session_id} with status {:?}",
                session.status
            )));
        }

        let expired_credentials_removed = self.expire_credential_grants(&mut session)?;
        let grant_count_before = session.approval_grants.len();
        let grant_id = self.enforce_exec_policy(&mut session, command)?;
        if expired_credentials_removed
            || grant_id.is_some()
            || session.approval_grants.len() != grant_count_before
        {
            self.sessions
                .upsert(session.clone())
                .map_err(|e| RuntimeError::Internal(e.to_string()))?;
        }

        let mut hydrated_command = command.clone();
        let consumed_credentials = hydrate_env_credential_grants(&session, &mut hydrated_command)?;

        let result = self
            .provider
            .exec_session(&session, &hydrated_command)
            .await?;
        for grant in &consumed_credentials {
            session.spec.credentials.grants.retain(|existing| {
                !(existing.name == grant.name
                    && existing.kind == grant.kind
                    && existing.target == grant.target)
            });
            self.audit_credential_revocation(&session, grant, "one_time_exec")?;
        }
        session
            .transcripts
            .push(CommandTranscript::from_command_result(
                session_id.to_string(),
                &hydrated_command,
                &result,
            ));
        self.sessions
            .upsert(session.clone())
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;
        let command_text = format!("runtime.exec {} {}", session_id, command.argv.join(" "));
        let decision = grant_id
            .map(|grant_id| format!("grant:{grant_id}:exit_code:{}", result.exit_code))
            .unwrap_or_else(|| format!("exit_code:{}", result.exit_code));

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

        self.provider.destroy_session(&session).await?;
        session.status = RuntimeStatus::Stopped;
        session.stopped_at = Some(Utc::now());
        session.approval_grants.clear();

        self.audit_credential_revocations(&session)?;
        self.audit_runtime_event(
            "runtime.destroy",
            &session,
            "runtime",
            "destroyed",
            None,
            Some(self.provider.name().to_string()),
        )?;
        self.sessions
            .upsert(session)
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
        if grant.is_expired_at(Utc::now()) {
            return Err(RuntimeError::ManifestRejected(format!(
                "approval grant {} is already expired",
                grant.id
            )));
        }
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

        let now = Utc::now();
        Ok(session
            .approval_grants
            .into_iter()
            .filter(|grant| !grant.is_expired_at(now))
            .collect())
    }

    pub fn list_credential_grants(
        &self,
        session_id: &str,
    ) -> Result<Vec<CredentialGrant>, RuntimeError> {
        let mut session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        if self.expire_credential_grants(&mut session)? {
            self.sessions
                .upsert(session.clone())
                .map_err(|e| RuntimeError::Internal(e.to_string()))?;
        }

        Ok(session.spec.credentials.grants.clone())
    }

    pub fn revoke_credential_grant(
        &self,
        session_id: &str,
        grant_name: &str,
    ) -> Result<Option<CredentialGrant>, RuntimeError> {
        let mut session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;

        let Some(index) = session
            .spec
            .credentials
            .grants
            .iter()
            .position(|grant| grant.name == grant_name)
        else {
            return Ok(None);
        };

        let grant = session.spec.credentials.grants.remove(index);
        self.audit_credential_revocation(&session, &grant, "operator")?;
        self.sessions
            .upsert(session)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;

        Ok(Some(grant))
    }

    pub fn list_sessions(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
        self.sessions
            .list()
            .map_err(|e| RuntimeError::Internal(e.to_string()))
    }

    pub fn capture_workspace_diff(
        &self,
        session_id: &str,
    ) -> Result<WorkspaceDiffSnapshot, RuntimeError> {
        let session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        let snapshot = WorkspaceDiffSnapshotter::capture(&session);

        if snapshot.available {
            let changed_files = snapshot.changed_files.len();
            self.audit_runtime_event(
                &format!("workspace.diff_snapshot {}", snapshot.snapshot_id),
                &session,
                "workspace",
                &format!("changed_files:{changed_files}"),
                None,
                Some(self.provider.name().to_string()),
            )?;
        }

        Ok(snapshot)
    }

    pub fn discard_workspace_projection(
        &self,
        session_id: &str,
    ) -> Result<Option<WorkspaceProjectionDiscard>, RuntimeError> {
        let session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        let discard = WorkspaceProjectionDiscarder::discard(&session)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;

        if let Some(discard) = &discard {
            self.audit_runtime_event(
                "workspace.projection_discard",
                &session,
                "workspace",
                &format!("discarded:{}", discard.projected_host_path.display()),
                None,
                Some(self.provider.name().to_string()),
            )?;
        }

        Ok(discard)
    }

    pub fn apply_workspace_projection(
        &self,
        session_id: &str,
    ) -> Result<Option<WorkspaceProjectionApply>, RuntimeError> {
        let session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        let apply = WorkspaceProjectionApplier::apply(&session)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;

        if let Some(apply) = &apply {
            self.audit_runtime_event(
                "workspace.projection_apply",
                &session,
                "workspace",
                &format!(
                    "applied:{}:bytes:{}",
                    apply.lower_host_path.display(),
                    apply.patch_bytes
                ),
                None,
                Some(self.provider.name().to_string()),
            )?;
        }

        Ok(apply)
    }

    pub fn commit_workspace_projection(
        &self,
        session_id: &str,
        message: &str,
    ) -> Result<Option<WorkspaceProjectionCommit>, RuntimeError> {
        let session = self
            .sessions
            .get(session_id)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        let commit = WorkspaceProjectionCommitter::commit(&session, message)
            .map_err(|e| RuntimeError::Internal(e.to_string()))?;

        if let Some(commit) = &commit {
            self.audit_runtime_event(
                "workspace.projection_commit",
                &session,
                "workspace",
                &format!(
                    "committed:{}:{}",
                    commit.commit_hash,
                    commit.apply.lower_host_path.display()
                ),
                None,
                Some(self.provider.name().to_string()),
            )?;
        }

        Ok(commit)
    }

    fn enforce_exec_policy(
        &self,
        session: &mut RuntimeSession,
        command: &ExecCommand,
    ) -> Result<Option<String>, RuntimeError> {
        if command.argv.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "exec command cannot be empty".into(),
            ));
        }
        let now = Utc::now();
        session
            .approval_grants
            .retain(|grant| !grant.is_expired_at(now));

        let ctx = command_context_for_session(session, command);
        let classification = classify::classify(
            &ctx,
            &PolicyConfig {
                workspace: command
                    .working_dir
                    .clone()
                    .or_else(|| Some(session.spec.filesystem.workspace_guest_path.clone())),
                allowed_domains: session.spec.network.allowed_domains.clone(),
                denied_domains: session.spec.network.denied_domains.clone(),
                allow_localhost: session.spec.network.allow_localhost,
                network_mode: policy_network_mode(&session.spec.network.mode),
                always_allow: vec![],
                always_block: vec![],
            },
        );

        match classification.bucket {
            Bucket::Allow => {
                self.audit_network_boundary_if_needed(
                    session,
                    command,
                    &classification,
                    "allowed",
                )?;
                Ok(None)
            }
            Bucket::Block => {
                self.audit_network_boundary_if_needed(
                    session,
                    command,
                    &classification,
                    "blocked",
                )?;
                Err(RuntimeError::PolicyDenied(format!(
                    "blocked by runtime policy: {}",
                    classification.reason
                )))
            }
            Bucket::Approve => {
                let grant_id = match session
                    .approval_grants
                    .iter()
                    .find(|grant| grant_matches_command(grant, session, command))
                    .map(|grant| grant.id.clone())
                {
                    Some(grant_id) => grant_id,
                    None => {
                        self.audit_network_boundary_if_needed(
                            session,
                            command,
                            &classification,
                            "approval_required",
                        )?;
                        return Err(RuntimeError::PolicyDenied(format!(
                            "approval required by runtime policy: {}",
                            classification.reason
                        )));
                    }
                };
                consume_once_grant(&mut session.approval_grants, &grant_id);
                self.audit_network_boundary_if_needed(
                    session,
                    command,
                    &classification,
                    &format!("approved:{grant_id}"),
                )?;
                Ok(Some(grant_id))
            }
        }
    }

    fn audit_network_boundary_if_needed(
        &self,
        session: &RuntimeSession,
        command: &ExecCommand,
        classification: &Classification,
        decision: &str,
    ) -> Result<(), RuntimeError> {
        if !is_network_http_command(command) {
            return Ok(());
        }

        self.audit_runtime_event(
            &format!("network.boundary {}", command.argv.join(" ")),
            session,
            "network",
            &format!("{decision}:{}", classification.reason),
            None,
            Some(self.provider.name().to_string()),
        )
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

    fn expire_credential_grants(&self, session: &mut RuntimeSession) -> Result<bool, RuntimeError> {
        let now = Utc::now();
        let mut retained = Vec::with_capacity(session.spec.credentials.grants.len());
        let mut expired = Vec::new();

        for grant in session.spec.credentials.grants.drain(..) {
            if grant.is_expired_at(now) {
                expired.push(grant);
            } else {
                retained.push(grant);
            }
        }

        session.spec.credentials.grants = retained;

        for grant in &expired {
            self.audit_credential_revocation(session, grant, "expired")?;
        }

        Ok(!expired.is_empty())
    }

    fn audit_credential_revocations(&self, session: &RuntimeSession) -> Result<(), RuntimeError> {
        for grant in session
            .spec
            .credentials
            .grants
            .iter()
            .filter(|grant| grant.one_time)
        {
            self.audit_credential_revocation(session, grant, "one_time")?;
        }

        Ok(())
    }

    fn audit_credential_revocation(
        &self,
        session: &RuntimeSession,
        grant: &CredentialGrant,
        reason: &str,
    ) -> Result<(), RuntimeError> {
        let event = AuditEvent::new(
            0,
            Some(session.spec.agent.name.clone()),
            format!("credential.revoke {} {}", grant.name, session.id),
            session
                .spec
                .filesystem
                .workspace_host_path
                .display()
                .to_string(),
            "credential".to_string(),
            format!("revoked:{reason}:{:?}", grant.kind),
            None,
            Some(self.provider.name().to_string()),
        );
        self.audit
            .log_event(&event)
            .map_err(|e| RuntimeError::Internal(e.to_string()))
    }
}

fn is_network_http_command(command: &ExecCommand) -> bool {
    matches!(
        command.argv.first().map(String::as_str),
        Some("curl" | "wget")
    ) && command.argv.iter().skip(1).any(|arg| {
        let lower = arg.to_ascii_lowercase();
        lower.starts_with("http://") || lower.starts_with("https://")
    })
}

fn hydrate_env_credential_grants(
    session: &RuntimeSession,
    command: &mut ExecCommand,
) -> Result<Vec<CredentialGrant>, RuntimeError> {
    let mut consumed = Vec::new();
    for grant in session
        .spec
        .credentials
        .grants
        .iter()
        .filter(|grant| matches!(grant.kind, CredentialGrantKind::EnvVar))
    {
        let value = std::env::var(&grant.target).map_err(|_| {
            RuntimeError::PolicyDenied(format!(
                "credential env grant `{}` references missing host env var `{}`",
                grant.name, grant.target
            ))
        })?;
        command.env.insert(grant.name.clone(), value);
        if grant.one_time {
            consumed.push(grant.clone());
        }
    }
    Ok(consumed)
}

fn policy_network_mode(mode: &crate::runtime::types::NetworkMode) -> PolicyNetworkMode {
    match mode {
        crate::runtime::types::NetworkMode::None => PolicyNetworkMode::None,
        crate::runtime::types::NetworkMode::DenyByDefault => PolicyNetworkMode::DenyByDefault,
        crate::runtime::types::NetworkMode::AllowListed => PolicyNetworkMode::AllowListed,
        crate::runtime::types::NetworkMode::ApprovalOnFirstContact => {
            PolicyNetworkMode::ApprovalOnFirstContact
        }
        crate::runtime::types::NetworkMode::OpenWithGuardrails => {
            PolicyNetworkMode::OpenWithGuardrails
        }
        crate::runtime::types::NetworkMode::Host => PolicyNetworkMode::Host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::fs;
    use std::future::Future;

    use crate::runtime::types::{
        ApprovalScope, CredentialGrant, CredentialGrantKind, RuntimeCapability,
    };

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
            let stdout = if command.argv.first().map(String::as_str) == Some("printenv") {
                command
                    .argv
                    .get(1)
                    .and_then(|key| command.env.get(key))
                    .cloned()
                    .unwrap_or_default()
            } else {
                command.argv.join(" ")
            };
            Ok(CommandResult {
                exit_code: 0,
                stdout,
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

    async fn temp_env_var<F, Fut>(key: &str, value: Option<&str>, body: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        let previous = std::env::var(key).ok();
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }

        body().await;

        match previous {
            Some(previous) => std::env::set_var(key, previous),
            None => std::env::remove_var(key),
        }
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
    async fn exec_persists_redacted_command_transcript() {
        let manager = manager("exec-transcript");
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["echo".to_string(), "sk-test-secret".to_string()],
            working_dir: Some("/tmp/project/.env".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        manager.exec(&session.id, &command).await.unwrap();

        let saved = manager
            .sessions
            .get(&session.id)
            .unwrap()
            .expect("session should remain persisted");
        assert_eq!(saved.transcripts.len(), 1);
        let transcript = &saved.transcripts[0];
        let json = serde_json::to_string(transcript).unwrap();
        assert_eq!(transcript.session_id, session.id);
        assert_eq!(transcript.exit_code, 0);
        assert_eq!(transcript.duration_ms, 3);
        assert!(json.contains("<redacted>"));
        assert!(!json.contains("sk-test-secret"));
        assert!(!json.contains("/tmp/project/.env"));
    }

    #[tokio::test]
    async fn exec_injects_only_explicit_env_credential_grants() {
        let manager = manager("exec-env-credential");
        temp_env_var("AGENTBOX_TEST_SECRET", Some("sk-test-secret"), || async {
            let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
            spec.credentials.grants.push(CredentialGrant {
                name: "OPENAI_API_KEY".into(),
                kind: CredentialGrantKind::EnvVar,
                target: "AGENTBOX_TEST_SECRET".into(),
                one_time: true,
                requires_approval: true,
                expires_at: None,
            });
            let session = manager.create(&spec).await.unwrap();
            let command = ExecCommand {
                argv: vec!["printenv".into(), "OPENAI_API_KEY".into()],
                working_dir: Some("/workspace".into()),
                env: Default::default(),
                timeout_seconds: None,
            };

            let result = manager.exec(&session.id, &command).await.unwrap();

            assert_eq!(result.stdout, "sk-test-secret");
            let saved = manager
                .sessions
                .get(&session.id)
                .unwrap()
                .expect("session should remain persisted");
            let transcript = saved.transcripts.last().unwrap();
            let json = serde_json::to_string(transcript).unwrap();
            assert!(json.contains("<redacted>"));
            assert!(!json.contains("sk-test-secret"));
            assert!(
                saved.spec.credentials.grants.is_empty(),
                "one-time env grants should be consumed after exposure"
            );
            let audit = manager.audit.recent(4).unwrap();
            assert!(audit.iter().any(|event| event.bucket == "credential"
                && event.command.contains("credential.revoke OPENAI_API_KEY")
                && event.decision.contains("one_time_exec")));
        })
        .await;
    }

    #[tokio::test]
    async fn exec_does_not_reuse_consumed_one_time_env_credential_grants() {
        let manager = manager("exec-env-credential-once");
        temp_env_var(
            "AGENTBOX_TEST_ONCE_SECRET",
            Some("sk-test-secret"),
            || async {
                let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
                spec.credentials.grants.push(CredentialGrant {
                    name: "OPENAI_API_KEY".into(),
                    kind: CredentialGrantKind::EnvVar,
                    target: "AGENTBOX_TEST_ONCE_SECRET".into(),
                    one_time: true,
                    requires_approval: true,
                    expires_at: None,
                });
                let session = manager.create(&spec).await.unwrap();
                let command = ExecCommand {
                    argv: vec!["printenv".into(), "OPENAI_API_KEY".into()],
                    working_dir: Some("/workspace".into()),
                    env: Default::default(),
                    timeout_seconds: None,
                };

                let first = manager.exec(&session.id, &command).await.unwrap();
                let second = manager.exec(&session.id, &command).await.unwrap();

                assert_eq!(first.stdout, "sk-test-secret");
                assert_eq!(second.stdout, "");
            },
        )
        .await;
    }

    #[tokio::test]
    async fn exec_rejects_missing_env_credential_grant_target() {
        let manager = manager("exec-env-credential-missing");
        temp_env_var("AGENTBOX_MISSING_TEST_SECRET", None, || async {
            let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
            spec.credentials.grants.push(CredentialGrant {
                name: "OPENAI_API_KEY".into(),
                kind: CredentialGrantKind::EnvVar,
                target: "AGENTBOX_MISSING_TEST_SECRET".into(),
                one_time: true,
                requires_approval: true,
                expires_at: None,
            });
            let session = manager.create(&spec).await.unwrap();
            let command = ExecCommand {
                argv: vec!["printenv".into(), "OPENAI_API_KEY".into()],
                working_dir: Some("/workspace".into()),
                env: Default::default(),
                timeout_seconds: None,
            };

            let err = manager.exec(&session.id, &command).await.unwrap_err();

            assert!(matches!(err, RuntimeError::PolicyDenied(_)));
            assert!(err.to_string().contains("missing host env var"));
        })
        .await;
    }

    #[tokio::test]
    async fn list_credential_grants_returns_session_manifest_grants() {
        let manager = manager("credential-list");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.credentials.grants.push(CredentialGrant {
            name: "OPENAI_API_KEY".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "AGENTBOX_TEST_SECRET".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });
        let session = manager.create(&spec).await.unwrap();

        let grants = manager.list_credential_grants(&session.id).unwrap();

        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].name, "OPENAI_API_KEY");
        assert!(matches!(grants[0].kind, CredentialGrantKind::EnvVar));
    }

    #[tokio::test]
    async fn list_credential_grants_expires_stale_grants_with_evidence() {
        let manager = manager("credential-list-expired");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.credentials.grants.push(CredentialGrant {
            name: "OPENAI_API_KEY".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "AGENTBOX_TEST_SECRET".into(),
            one_time: false,
            requires_approval: true,
            expires_at: Some(Utc::now() - chrono::Duration::seconds(1)),
        });
        let session = manager.create(&spec).await.unwrap();

        let grants = manager.list_credential_grants(&session.id).unwrap();

        assert!(grants.is_empty());
        let saved = manager
            .sessions
            .get(&session.id)
            .unwrap()
            .expect("session should remain persisted");
        assert!(saved.spec.credentials.grants.is_empty());
        let audit = manager.audit.recent(4).unwrap();
        assert!(audit.iter().any(|event| event.bucket == "credential"
            && event.command.contains("credential.revoke OPENAI_API_KEY")
            && event.decision.contains("expired")));
    }

    #[tokio::test]
    async fn exec_does_not_inject_expired_env_credential_grants() {
        let manager = manager("exec-env-credential-expired");
        temp_env_var(
            "AGENTBOX_EXPIRED_SECRET",
            Some("sk-test-secret"),
            || async {
                let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
                spec.credentials.grants.push(CredentialGrant {
                    name: "OPENAI_API_KEY".into(),
                    kind: CredentialGrantKind::EnvVar,
                    target: "AGENTBOX_EXPIRED_SECRET".into(),
                    one_time: false,
                    requires_approval: true,
                    expires_at: Some(Utc::now() - chrono::Duration::seconds(1)),
                });
                let session = manager.create(&spec).await.unwrap();
                let command = ExecCommand {
                    argv: vec!["printenv".into(), "OPENAI_API_KEY".into()],
                    working_dir: Some("/workspace".into()),
                    env: Default::default(),
                    timeout_seconds: None,
                };

                let result = manager.exec(&session.id, &command).await.unwrap();

                assert_eq!(result.stdout, "");
                let saved = manager
                    .sessions
                    .get(&session.id)
                    .unwrap()
                    .expect("session should remain persisted");
                assert!(saved.spec.credentials.grants.is_empty());
            },
        )
        .await;
    }

    #[tokio::test]
    async fn revoke_credential_grant_removes_grant_and_records_evidence() {
        let manager = manager("credential-revoke");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.credentials.grants.push(CredentialGrant {
            name: "OPENAI_API_KEY".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "AGENTBOX_TEST_SECRET".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });
        let session = manager.create(&spec).await.unwrap();

        let revoked = manager
            .revoke_credential_grant(&session.id, "OPENAI_API_KEY")
            .unwrap()
            .expect("grant should be revoked");

        assert_eq!(revoked.name, "OPENAI_API_KEY");
        assert!(manager
            .list_credential_grants(&session.id)
            .unwrap()
            .is_empty());
        let audit = manager.audit.recent(4).unwrap();
        assert_eq!(audit[0].bucket, "credential");
        assert!(audit[0]
            .command
            .contains("credential.revoke OPENAI_API_KEY"));
        assert!(audit[0].decision.contains("revoked:operator"));
    }

    #[tokio::test]
    async fn revoke_credential_grant_returns_none_for_unknown_grant() {
        let manager = manager("credential-revoke-missing");
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();

        let revoked = manager
            .revoke_credential_grant(&session.id, "OPENAI_API_KEY")
            .unwrap();

        assert!(revoked.is_none());
        assert_eq!(manager.audit.recent(4).unwrap()[0].bucket, "runtime");
    }

    #[tokio::test]
    async fn exec_requires_matching_grant_for_approve_bucket() {
        let manager = manager("exec-approval-missing");
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["git".into(), "push".into(), "origin".into(), "main".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
    }

    #[tokio::test]
    async fn exec_uses_matching_command_scope_grant() {
        let manager = manager("exec-command-grant");
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();
        manager
            .add_session_approval_grant(
                &session.id,
                ApprovalGrant {
                    id: "grant-git-push".into(),
                    scope: ApprovalScope::Command {
                        binary: "git".into(),
                        args_prefix: vec!["push".into()],
                    },
                    reason: "operator approved git push for this session".into(),
                    expires_at: None,
                },
            )
            .unwrap();
        let command = ExecCommand {
            argv: vec!["git".into(), "push".into(), "origin".into(), "main".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let result = manager.exec(&session.id, &command).await.unwrap();

        assert_eq!(result.stdout, "git push origin main");
        let audit = manager.audit.recent(1).unwrap();
        assert!(audit[0].decision.contains("grant:grant-git-push"));
    }

    #[tokio::test]
    async fn exec_consumes_once_grant() {
        let manager = manager("exec-once-grant");
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();
        manager
            .add_session_approval_grant(
                &session.id,
                ApprovalGrant {
                    id: "grant-once".into(),
                    scope: ApprovalScope::Once,
                    reason: "operator approved one risky command".into(),
                    expires_at: None,
                },
            )
            .unwrap();
        let command = ExecCommand {
            argv: vec!["git".into(), "push".into(), "origin".into(), "main".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        manager.exec(&session.id, &command).await.unwrap();

        assert!(manager
            .session_approval_grants(&session.id)
            .unwrap()
            .is_empty());
        let err = manager.exec(&session.id, &command).await.unwrap_err();
        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
    }

    #[tokio::test]
    async fn exec_grants_do_not_bypass_block_bucket() {
        let manager = manager("exec-block");
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();
        manager
            .add_session_approval_grant(
                &session.id,
                ApprovalGrant {
                    id: "grant-once".into(),
                    scope: ApprovalScope::Once,
                    reason: "operator approved one risky command".into(),
                    expires_at: None,
                },
            )
            .unwrap();
        let command = ExecCommand {
            argv: vec!["rm".into(), "-rf".into(), "/".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        assert_eq!(
            manager.session_approval_grants(&session.id).unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn exec_denies_network_denylist_before_grants() {
        let manager = manager("exec-network-denylist");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.denied_domains = vec!["metadata.google.internal".into()];
        let session = manager.create(&spec).await.unwrap();
        manager
            .add_session_approval_grant(
                &session.id,
                ApprovalGrant {
                    id: "grant-domain".into(),
                    scope: ApprovalScope::Domain {
                        domain: "metadata.google.internal".into(),
                    },
                    reason: "operator approval should not bypass denylist".into(),
                    expires_at: None,
                },
            )
            .unwrap();
        let command = ExecCommand {
            argv: vec![
                "curl".into(),
                "https://metadata.google.internal/computeMetadata/v1".into(),
            ],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        assert_eq!(
            manager.session_approval_grants(&session.id).unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn exec_allows_localhost_when_minipod_policy_allows_it() {
        let manager = manager("exec-localhost-allow");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.allow_localhost = true;
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["curl".into(), "http://localhost:3000/health".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let result = manager.exec(&session.id, &command).await.unwrap();

        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn exec_blocks_localhost_when_minipod_policy_disables_it() {
        let manager = manager("exec-localhost-block");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.allow_localhost = false;
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["curl".into(), "http://127.0.0.1:3000/health".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        assert!(err
            .to_string()
            .contains("localhost service access disabled"));
    }

    #[tokio::test]
    async fn exec_records_network_boundary_evidence_for_allowed_http() {
        let manager = manager("exec-network-allow-evidence");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.allowed_domains = vec!["api.openai.com".into()];
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["curl".into(), "https://api.openai.com/v1/models".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        manager.exec(&session.id, &command).await.unwrap();

        let audit = manager.audit.recent(3).unwrap();
        assert_eq!(audit[1].bucket, "network");
        assert!(audit[1].command.contains("network.boundary"));
        assert!(audit[1].decision.contains("allowed:"));
        assert_eq!(audit[0].bucket, "runtime");
        assert_eq!(audit[0].prev_hash, audit[1].event_hash);
    }

    #[tokio::test]
    async fn exec_records_network_boundary_evidence_for_blocked_http() {
        let manager = manager("exec-network-block-evidence");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.denied_domains = vec!["metadata.google.internal".into()];
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec![
                "curl".into(),
                "https://metadata.google.internal/computeMetadata/v1".into(),
            ],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        let audit = manager.audit.recent(2).unwrap();
        assert_eq!(audit[0].bucket, "network");
        assert!(audit[0].decision.contains("blocked:"));
        assert!(audit[0].decision.contains("denylist"));
    }

    #[tokio::test]
    async fn exec_records_network_boundary_evidence_for_required_approval() {
        let manager = manager("exec-network-approval-evidence");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.mode = crate::runtime::types::NetworkMode::ApprovalOnFirstContact;
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["curl".into(), "https://unknown.example.test".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        let audit = manager.audit.recent(2).unwrap();
        assert_eq!(audit[0].bucket, "network");
        assert!(audit[0].decision.contains("approval_required:"));
    }

    #[tokio::test]
    async fn exec_blocks_unknown_http_in_deny_by_default_mode() {
        let manager = manager("exec-network-deny-by-default");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.mode = crate::runtime::types::NetworkMode::DenyByDefault;
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["curl".into(), "https://unknown.example.test".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        let audit = manager.audit.recent(2).unwrap();
        assert_eq!(audit[0].bucket, "network");
        assert!(audit[0].decision.contains("blocked:"));
        assert!(audit[0].decision.contains("denies external HTTP"));
    }

    #[tokio::test]
    async fn exec_blocks_allowlisted_http_in_deny_by_default_mode() {
        let manager = manager("exec-network-deny-by-default-allowlisted");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.mode = crate::runtime::types::NetworkMode::DenyByDefault;
        spec.network.allowed_domains = vec!["api.github.com".into()];
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["curl".into(), "https://api.github.com/repos".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        let audit = manager.audit.recent(2).unwrap();
        assert_eq!(audit[0].bucket, "network");
        assert!(audit[0].decision.contains("blocked:"));
        assert!(audit[0].decision.contains("denies external HTTP"));
    }

    #[tokio::test]
    async fn exec_blocks_unknown_http_in_allowlisted_mode() {
        let manager = manager("exec-network-allowlisted-unknown");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.mode = crate::runtime::types::NetworkMode::AllowListed;
        spec.network.allowed_domains = vec!["api.github.com".into()];
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["curl".into(), "https://unknown.example.test".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        let audit = manager.audit.recent(2).unwrap();
        assert_eq!(audit[0].bucket, "network");
        assert!(audit[0].decision.contains("blocked:"));
        assert!(audit[0].decision.contains("allowlisted network mode"));
    }

    #[tokio::test]
    async fn exec_allows_unknown_http_in_open_with_guardrails_mode() {
        let manager = manager("exec-network-open-guardrails");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.network.mode = crate::runtime::types::NetworkMode::OpenWithGuardrails;
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["curl".into(), "https://unknown.example.test".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let result = manager.exec(&session.id, &command).await.unwrap();

        assert_eq!(result.exit_code, 0);
        let audit = manager.audit.recent(3).unwrap();
        assert_eq!(audit[1].bucket, "network");
        assert!(audit[1].decision.contains("allowed:"));
        assert!(audit[1].decision.contains("guardrail audit"));
    }

    #[tokio::test]
    async fn destroy_retains_stopped_session_and_records_evidence() {
        let manager = manager("destroy");
        let spec = MinipodSpec::for_agent_task("aspendos", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();

        manager.destroy(&session.id).await.unwrap();

        let sessions = manager.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(matches!(sessions[0].status, RuntimeStatus::Stopped));
        assert!(sessions[0].stopped_at.is_some());
        let audit = manager.audit.recent(1).unwrap();
        assert_eq!(audit[0].decision, "destroyed");
        assert!(audit[0].command.contains("runtime.destroy"));
    }

    #[tokio::test]
    async fn exec_rejects_stopped_sessions_before_provider_dispatch() {
        let manager = manager("exec-stopped");
        let spec = MinipodSpec::for_agent_task("aspendos", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();
        manager.destroy(&session.id).await.unwrap();

        let err = manager
            .exec(
                &session.id,
                &ExecCommand {
                    argv: vec!["echo".into(), "after-stop".into()],
                    working_dir: None,
                    env: Default::default(),
                    timeout_seconds: None,
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        assert!(err.to_string().contains("Stopped"));
        let saved = manager
            .sessions
            .get(&session.id)
            .unwrap()
            .expect("stopped session remains available for evidence");
        assert!(saved.transcripts.is_empty());
    }

    #[tokio::test]
    async fn capture_workspace_diff_records_snapshot_evidence_for_git_workspaces() {
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-manager-workspace-snapshot-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).unwrap();
        run_git(&workspace, &["init"]);
        run_git(
            &workspace,
            &["config", "user.email", "agentbox@example.test"],
        );
        run_git(&workspace, &["config", "user.name", "Agentbox Test"]);
        fs::write(workspace.join("README.md"), "hello\n").unwrap();
        run_git(&workspace, &["add", "README.md"]);
        run_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "hello\nchanged\n").unwrap();

        let manager = manager("workspace-diff-snapshot");
        let spec = MinipodSpec::for_agent_task("openclaw", &workspace);
        let session = manager.create(&spec).await.unwrap();

        let snapshot = manager.capture_workspace_diff(&session.id).unwrap();

        assert!(snapshot.available);
        assert!(snapshot.has_changes());
        assert!(snapshot.changed_files.contains(&"README.md".to_string()));
        let audit = manager.audit.recent(1).unwrap();
        assert_eq!(audit[0].bucket, "workspace");
        assert!(audit[0].command.contains("workspace.diff_snapshot"));
        assert_eq!(audit[0].decision, "changed_files:1");

        let _ = fs::remove_dir_all(&workspace);
    }

    #[tokio::test]
    async fn discard_workspace_projection_records_workspace_evidence() {
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-manager-discard-workspace-{}",
            std::process::id()
        ));
        let overlay = std::env::temp_dir().join(format!(
            "agentbox-manager-discard-overlay-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("README.md"), "lower\n").unwrap();
        let manager = manager("workspace-discard");
        let mut spec = MinipodSpec::for_agent_task("openclaw", &workspace);
        spec.workspace_mode = crate::runtime::types::AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_write_policy =
            crate::runtime::types::WorkspaceWritePolicy::WritableOverlay;
        spec.filesystem.workspace_overlay =
            crate::runtime::types::WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));
        crate::runtime::workspace::WorkspaceProjectionMaterializer::materialize(&mut spec)
            .unwrap()
            .expect("workspace projection should be prepared");
        let session = manager.create(&spec).await.unwrap();

        let discard = manager
            .discard_workspace_projection(&session.id)
            .unwrap()
            .expect("projection should exist");

        assert!(!discard.projected_host_path.exists());
        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).unwrap(),
            "lower\n"
        );
        let audit = manager.audit.recent(1).unwrap();
        assert_eq!(audit[0].bucket, "workspace");
        assert!(audit[0].command.contains("workspace.projection_discard"));
        assert!(audit[0].decision.contains("discarded:"));

        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[tokio::test]
    async fn apply_workspace_projection_records_workspace_evidence() {
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-manager-apply-workspace-{}",
            std::process::id()
        ));
        let overlay = std::env::temp_dir().join(format!(
            "agentbox-manager-apply-overlay-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        run_git(&workspace, &["init"]);
        run_git(
            &workspace,
            &["config", "user.email", "agentbox@example.test"],
        );
        run_git(&workspace, &["config", "user.name", "Agentbox Test"]);
        fs::write(workspace.join("README.md"), "lower\n").unwrap();
        run_git(&workspace, &["add", "README.md"]);
        run_git(&workspace, &["commit", "-m", "initial"]);
        let manager = manager("workspace-apply");
        let mut spec = MinipodSpec::for_agent_task("openclaw", &workspace);
        spec.workspace_mode = crate::runtime::types::AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_write_policy =
            crate::runtime::types::WorkspaceWritePolicy::WritableOverlay;
        spec.filesystem.workspace_overlay =
            crate::runtime::types::WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));
        let projection =
            crate::runtime::workspace::WorkspaceProjectionMaterializer::materialize(&mut spec)
                .unwrap()
                .expect("workspace projection should be prepared");
        fs::write(
            projection.projected_host_path.join("README.md"),
            "lower\napplied\n",
        )
        .unwrap();
        let session = manager.create(&spec).await.unwrap();

        let apply = manager
            .apply_workspace_projection(&session.id)
            .unwrap()
            .expect("projection should apply");

        assert!(apply.patch_bytes > 0);
        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).unwrap(),
            "lower\napplied\n"
        );
        let audit = manager.audit.recent(1).unwrap();
        assert_eq!(audit[0].bucket, "workspace");
        assert!(audit[0].command.contains("workspace.projection_apply"));
        assert!(audit[0].decision.contains("applied:"));

        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[tokio::test]
    async fn commit_workspace_projection_records_workspace_evidence() {
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-manager-commit-workspace-{}",
            std::process::id()
        ));
        let overlay = std::env::temp_dir().join(format!(
            "agentbox-manager-commit-overlay-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        run_git(&workspace, &["init"]);
        run_git(
            &workspace,
            &["config", "user.email", "agentbox@example.test"],
        );
        run_git(&workspace, &["config", "user.name", "Agentbox Test"]);
        fs::write(workspace.join("README.md"), "lower\n").unwrap();
        run_git(&workspace, &["add", "README.md"]);
        run_git(&workspace, &["commit", "-m", "initial"]);
        let manager = manager("workspace-commit");
        let mut spec = MinipodSpec::for_agent_task("openclaw", &workspace);
        spec.workspace_mode = crate::runtime::types::AgentPodWorkspaceMode::CommitGated;
        spec.filesystem.workspace_write_policy =
            crate::runtime::types::WorkspaceWritePolicy::WritableOverlay;
        spec.filesystem.workspace_overlay =
            crate::runtime::types::WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));
        let projection =
            crate::runtime::workspace::WorkspaceProjectionMaterializer::materialize(&mut spec)
                .unwrap()
                .expect("workspace projection should be prepared");
        fs::write(
            projection.projected_host_path.join("README.md"),
            "lower\ncommitted\n",
        )
        .unwrap();
        let session = manager.create(&spec).await.unwrap();

        let commit = manager
            .commit_workspace_projection(&session.id, "agentbox review output")
            .unwrap()
            .expect("projection should commit");

        assert!(!commit.commit_hash.is_empty());
        let audit = manager.audit.recent(1).unwrap();
        assert_eq!(audit[0].bucket, "workspace");
        assert!(audit[0].command.contains("workspace.projection_commit"));
        assert!(audit[0].decision.contains(&commit.commit_hash));

        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[tokio::test]
    async fn destroy_records_one_time_credential_revocation_events() {
        let manager = manager("destroy-credential-revoke");
        let mut spec = MinipodSpec::for_agent_task("aspendos", "/tmp/agentbox-work");
        spec.credentials.grants.push(CredentialGrant {
            name: "openai".into(),
            kind: CredentialGrantKind::FileMount,
            target: "/tmp/agentbox-openai-key".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });
        let session = manager.create(&spec).await.unwrap();

        manager.destroy(&session.id).await.unwrap();

        let audit = manager.audit.recent(3).unwrap();
        assert_eq!(audit[0].bucket, "runtime");
        assert_eq!(audit[0].decision, "destroyed");
        assert_eq!(audit[1].bucket, "credential");
        assert!(audit[1].command.contains("credential.revoke openai"));
        assert!(audit[1].decision.contains("revoked:one_time:FileMount"));
        assert_eq!(audit[0].prev_hash, audit[1].event_hash);
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

        assert!(manager
            .session_approval_grants(&session.id)
            .unwrap()
            .is_empty());
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

    #[tokio::test]
    async fn rejects_already_expired_session_approval_grant() {
        let manager = manager("session-approval-expired-add");
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let session = manager.create(&spec).await.unwrap();

        let err = manager
            .add_session_approval_grant(
                &session.id,
                ApprovalGrant {
                    id: "grant-expired".into(),
                    scope: ApprovalScope::Session {
                        session_id: session.id.clone(),
                    },
                    reason: "expired approval".into(),
                    expires_at: Some(Utc::now() - chrono::Duration::seconds(1)),
                },
            )
            .unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }

    #[tokio::test]
    async fn expired_approval_grants_do_not_authorize_exec() {
        let manager = manager("exec-expired-grant");
        let mut spec = MinipodSpec::for_agent_task("openclaw", "/tmp/agentbox-work");
        spec.approvals.push(ApprovalGrant {
            id: "expired-git-push".into(),
            scope: ApprovalScope::Command {
                binary: "git".into(),
                args_prefix: vec!["push".into()],
            },
            reason: "expired git push approval".into(),
            expires_at: Some(Utc::now() - chrono::Duration::seconds(1)),
        });
        let session = manager.create(&spec).await.unwrap();
        let command = ExecCommand {
            argv: vec!["git".into(), "push".into(), "origin".into(), "main".into()],
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = manager.exec(&session.id, &command).await.unwrap_err();

        assert!(matches!(err, RuntimeError::PolicyDenied(_)));
        assert!(manager
            .session_approval_grants(&session.id)
            .unwrap()
            .is_empty());
    }

    fn run_git(workspace: &std::path::Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
