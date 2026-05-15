use std::time::Instant;

use async_trait::async_trait;
use tokio::process::Command;

use crate::runtime::bridge::HostBridgeTransportKind;
use crate::runtime::provider::{
    ProviderFamily, ProviderImplementationStatus, RuntimeError, RuntimeProvider,
};
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
};

pub struct DirectHostRuntimeProvider;

impl DirectHostRuntimeProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DirectHostRuntimeProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RuntimeProvider for DirectHostRuntimeProvider {
    fn name(&self) -> &str {
        "direct-host"
    }

    fn platform(&self) -> &str {
        std::env::consts::OS
    }

    fn family(&self) -> ProviderFamily {
        ProviderFamily::DirectHost
    }

    fn implementation_status(&self) -> ProviderImplementationStatus {
        ProviderImplementationStatus::Shipped
    }

    fn capabilities(&self) -> &[RuntimeCapability] {
        &[
            RuntimeCapability::FilesystemPolicy,
            RuntimeCapability::CredentialPolicy,
            RuntimeCapability::ApprovalBridge,
            RuntimeCapability::EvidenceExport,
        ]
    }

    fn bridge_transport_kinds(&self) -> &[HostBridgeTransportKind] {
        &[HostBridgeTransportKind::UnixSocket]
    }

    fn boundary_primitives(&self) -> Vec<&'static str> {
        vec!["path-shim", "daemon-policy", "sqlite-audit"]
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
        run_direct_command(command, None).await
    }

    async fn exec_session(
        &self,
        session: &RuntimeSession,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        run_direct_command(command, Some(session)).await
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

async fn run_direct_command(
    command: &ExecCommand,
    session: Option<&RuntimeSession>,
) -> Result<CommandResult, RuntimeError> {
    let Some(program) = command.argv.first() else {
        return Err(RuntimeError::ManifestRejected(
            "direct-host command cannot be empty".into(),
        ));
    };

    let mut process = Command::new(program);
    process.args(command.argv.iter().skip(1));
    process.envs(
        command
            .env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    if let Some(working_dir) = direct_working_dir(command, session) {
        process.current_dir(working_dir);
    }

    let start = Instant::now();
    let output = if let Some(timeout_seconds) = command.timeout_seconds {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_seconds),
            process.output(),
        )
        .await
        .map_err(|_| RuntimeError::Internal("direct-host command timed out".into()))?
    } else {
        process.output().await
    }
    .map_err(|error| RuntimeError::Internal(format!("direct-host exec failed: {error}")))?;

    Ok(CommandResult {
        exit_code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

fn direct_working_dir(
    command: &ExecCommand,
    session: Option<&RuntimeSession>,
) -> Option<std::path::PathBuf> {
    let requested = command.working_dir.as_deref()?;
    let session = session?;
    if requested == session.spec.filesystem.workspace_guest_path {
        return Some(session.spec.filesystem.workspace_host_path.clone());
    }
    Some(std::path::PathBuf::from(requested))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::MinipodSpec;
    use std::collections::HashMap;

    #[tokio::test]
    async fn direct_host_provider_runs_argv_in_workspace_without_shell() {
        let workspace =
            std::env::temp_dir().join(format!("agentbox-direct-host-test-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        let spec = MinipodSpec::for_agent_task("direct", &workspace);
        let provider = DirectHostRuntimeProvider::new();
        let session = provider.create(&spec).await.unwrap();
        let result = provider
            .exec_session(
                &session,
                &ExecCommand {
                    argv: vec!["pwd".into()],
                    working_dir: Some("/workspace".into()),
                    env: HashMap::new(),
                    timeout_seconds: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(
            result.stdout.trim(),
            std::fs::canonicalize(&workspace).unwrap().to_string_lossy()
        );
        std::fs::remove_dir_all(&workspace).ok();
    }

    #[tokio::test]
    async fn direct_host_provider_rejects_empty_commands() {
        let provider = DirectHostRuntimeProvider::new();
        let err = provider
            .exec(
                "session",
                &ExecCommand {
                    argv: vec![],
                    working_dir: None,
                    env: HashMap::new(),
                    timeout_seconds: None,
                },
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("cannot be empty"));
    }
}
