use async_trait::async_trait;
use thiserror::Error;

use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
};

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("session not found: {0}")]
    NotFound(String),

    #[error("session already exists: {0}")]
    AlreadyExists(String),

    #[error("provider unavailable: {0}")]
    Unavailable(String),

    #[error("manifest rejected: {0}")]
    ManifestRejected(String),

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("exec failed: {0}")]
    ExecFailed(String),

    #[error("timeout after {0}s")]
    Timeout(u64),

    #[error("internal error: {0}")]
    Internal(String),
}

#[async_trait]
pub trait RuntimeProvider: Send + Sync {
    fn name(&self) -> &str;

    fn platform(&self) -> &str;

    fn capabilities(&self) -> &[RuntimeCapability];

    async fn is_available(&self) -> bool;

    async fn create(&self, spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError>;

    async fn exec(
        &self,
        session_id: &str,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError>;

    async fn status(&self, session_id: &str) -> Result<RuntimeStatus, RuntimeError>;

    async fn destroy(&self, session_id: &str) -> Result<(), RuntimeError>;

    async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider {
        capabilities: Vec<RuntimeCapability>,
    }

    #[async_trait]
    impl RuntimeProvider for MockProvider {
        fn name(&self) -> &str {
            "mock"
        }

        fn platform(&self) -> &str {
            "test"
        }

        fn capabilities(&self) -> &[RuntimeCapability] {
            &self.capabilities
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
                duration_ms: 1,
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

    #[tokio::test]
    async fn provider_reports_capabilities() {
        let provider = MockProvider {
            capabilities: vec![
                RuntimeCapability::ContainerIsolation,
                RuntimeCapability::FilesystemPolicy,
            ],
        };

        assert!(provider.is_available().await);
        assert_eq!(provider.name(), "mock");
        assert_eq!(provider.platform(), "test");
        assert_eq!(provider.capabilities().len(), 2);
    }

    #[tokio::test]
    async fn provider_can_create_session_from_spec() {
        let provider = MockProvider {
            capabilities: vec![RuntimeCapability::ContainerIsolation],
        };
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/workspace");

        let session = provider.create(&spec).await.unwrap();

        assert_eq!(session.name, spec.name);
        assert_eq!(session.provider, "mock");
        assert_eq!(session.platform, "test");
        assert!(matches!(session.status, RuntimeStatus::Creating));
    }
}
