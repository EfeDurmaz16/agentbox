use async_trait::async_trait;
use thiserror::Error;

use crate::runtime::bridge::{HostBridgeHealth, HostBridgeTransportKind};
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, NetworkEnforcementCapability, RuntimeCapability,
    RuntimeSession, RuntimeStatus, SessionEvidenceBundle,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFamily {
    DirectHost,
    NativeSandbox,
    VmBacked,
    Remote,
    Compatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderImplementationStatus {
    Shipped,
    Experimental,
    PrototypePrimitive,
    DescriptorOnly,
    Planned,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryPrimitiveStatus {
    pub primitive: &'static str,
    pub status: ProviderImplementationStatus,
    pub active: bool,
    pub requires_gate: Option<&'static str>,
    pub enforcement_scope: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeErrorKind {
    NotFound,
    AlreadyExists,
    Unavailable,
    ManifestRejected,
    PolicyDenied,
    ExecFailed,
    Timeout,
    Internal,
}

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

impl RuntimeError {
    pub fn kind(&self) -> RuntimeErrorKind {
        match self {
            Self::NotFound(_) => RuntimeErrorKind::NotFound,
            Self::AlreadyExists(_) => RuntimeErrorKind::AlreadyExists,
            Self::Unavailable(_) => RuntimeErrorKind::Unavailable,
            Self::ManifestRejected(_) => RuntimeErrorKind::ManifestRejected,
            Self::PolicyDenied(_) => RuntimeErrorKind::PolicyDenied,
            Self::ExecFailed(_) => RuntimeErrorKind::ExecFailed,
            Self::Timeout(_) => RuntimeErrorKind::Timeout,
            Self::Internal(_) => RuntimeErrorKind::Internal,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            RuntimeErrorKind::Unavailable
                | RuntimeErrorKind::ExecFailed
                | RuntimeErrorKind::Timeout
        )
    }

    pub fn is_user_actionable(&self) -> bool {
        matches!(
            self.kind(),
            RuntimeErrorKind::Unavailable
                | RuntimeErrorKind::ManifestRejected
                | RuntimeErrorKind::PolicyDenied
                | RuntimeErrorKind::Timeout
        )
    }
}

#[async_trait]
pub trait RuntimeProvider: Send + Sync {
    fn name(&self) -> &str;

    fn platform(&self) -> &str;

    fn family(&self) -> ProviderFamily {
        ProviderFamily::Compatibility
    }

    fn implementation_status(&self) -> ProviderImplementationStatus {
        ProviderImplementationStatus::Experimental
    }

    fn capabilities(&self) -> &[RuntimeCapability];

    fn network_enforcement_capabilities(&self) -> &[NetworkEnforcementCapability] {
        &[]
    }

    fn bridge_transport_kinds(&self) -> &[HostBridgeTransportKind] {
        &[]
    }

    fn boundary_primitives(&self) -> Vec<&'static str> {
        vec![]
    }

    fn boundary_primitive_statuses(&self) -> Vec<BoundaryPrimitiveStatus> {
        self.boundary_primitives()
            .into_iter()
            .map(|primitive| BoundaryPrimitiveStatus {
                primitive,
                status: self.implementation_status(),
                active: false,
                requires_gate: None,
                enforcement_scope: "metadata only",
            })
            .collect()
    }

    fn bridge_health(&self) -> HostBridgeHealth {
        let provider_active = matches!(
            self.implementation_status(),
            ProviderImplementationStatus::Shipped
                | ProviderImplementationStatus::Experimental
                | ProviderImplementationStatus::PrototypePrimitive
        );
        HostBridgeHealth::from_runtime_metadata(
            self.name(),
            self.bridge_transport_kinds(),
            self.capabilities(),
            self.network_enforcement_capabilities(),
            provider_active,
        )
    }

    async fn is_available(&self) -> bool;

    async fn create(&self, spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError>;

    async fn exec(
        &self,
        session_id: &str,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError>;

    async fn exec_session(
        &self,
        session: &RuntimeSession,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        self.exec(&session.id, command).await
    }

    async fn status(&self, session_id: &str) -> Result<RuntimeStatus, RuntimeError>;

    async fn status_session(
        &self,
        session: &RuntimeSession,
    ) -> Result<RuntimeStatus, RuntimeError> {
        self.status(&session.id).await
    }

    async fn destroy(&self, session_id: &str) -> Result<(), RuntimeError>;

    async fn destroy_session(&self, session: &RuntimeSession) -> Result<(), RuntimeError> {
        self.destroy(&session.id).await
    }

    async fn seal_evidence_bundle(
        &self,
        _session: &RuntimeSession,
        _bundle: &SessionEvidenceBundle,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider {
        capabilities: Vec<RuntimeCapability>,
        network_enforcement_capabilities: Vec<NetworkEnforcementCapability>,
        boundary_primitives: Vec<&'static str>,
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

        fn network_enforcement_capabilities(&self) -> &[NetworkEnforcementCapability] {
            &self.network_enforcement_capabilities
        }

        fn boundary_primitives(&self) -> Vec<&'static str> {
            self.boundary_primitives.clone()
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
            network_enforcement_capabilities: vec![
                NetworkEnforcementCapability::ContainerNetworkMode,
                NetworkEnforcementCapability::DomainDenylist,
            ],
            boundary_primitives: vec![],
        };

        assert!(provider.is_available().await);
        assert_eq!(provider.name(), "mock");
        assert_eq!(provider.platform(), "test");
        assert_eq!(provider.capabilities().len(), 2);
        assert_eq!(provider.network_enforcement_capabilities().len(), 2);
    }

    #[tokio::test]
    async fn provider_can_create_session_from_spec() {
        let provider = MockProvider {
            capabilities: vec![RuntimeCapability::ContainerIsolation],
            network_enforcement_capabilities: vec![],
            boundary_primitives: vec![],
        };
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/workspace");

        let session = provider.create(&spec).await.unwrap();

        assert_eq!(session.name, spec.name);
        assert_eq!(session.provider, "mock");
        assert_eq!(session.platform, "test");
        assert!(matches!(session.status, RuntimeStatus::Creating));
    }

    #[test]
    fn runtime_errors_expose_stable_taxonomy() {
        let cases = [
            (
                RuntimeError::NotFound("missing".into()),
                RuntimeErrorKind::NotFound,
                false,
                false,
            ),
            (
                RuntimeError::AlreadyExists("session".into()),
                RuntimeErrorKind::AlreadyExists,
                false,
                false,
            ),
            (
                RuntimeError::Unavailable("agentpod-linux".into()),
                RuntimeErrorKind::Unavailable,
                true,
                true,
            ),
            (
                RuntimeError::ManifestRejected("host network".into()),
                RuntimeErrorKind::ManifestRejected,
                false,
                true,
            ),
            (
                RuntimeError::PolicyDenied("credential read".into()),
                RuntimeErrorKind::PolicyDenied,
                false,
                true,
            ),
            (
                RuntimeError::ExecFailed("exit 1".into()),
                RuntimeErrorKind::ExecFailed,
                true,
                false,
            ),
            (
                RuntimeError::Timeout(30),
                RuntimeErrorKind::Timeout,
                true,
                true,
            ),
            (
                RuntimeError::Internal("sqlite".into()),
                RuntimeErrorKind::Internal,
                false,
                false,
            ),
        ];

        for (error, kind, retryable, user_actionable) in cases {
            assert_eq!(error.kind(), kind);
            assert_eq!(error.is_retryable(), retryable, "{error:?}");
            assert_eq!(error.is_user_actionable(), user_actionable, "{error:?}");
        }
    }

    #[test]
    fn provider_truth_metadata_has_stable_debug_labels() {
        assert_eq!(format!("{:?}", ProviderFamily::DirectHost), "DirectHost");
        assert_eq!(
            format!("{:?}", ProviderImplementationStatus::DescriptorOnly),
            "DescriptorOnly"
        );
    }

    #[test]
    fn boundary_primitive_status_defaults_to_metadata_only() {
        let provider = MockProvider {
            capabilities: vec![RuntimeCapability::ContainerIsolation],
            network_enforcement_capabilities: vec![],
            boundary_primitives: vec!["mock-primitive"],
        };

        assert_eq!(
            provider.boundary_primitive_statuses(),
            vec![BoundaryPrimitiveStatus {
                primitive: "mock-primitive",
                status: ProviderImplementationStatus::Experimental,
                active: false,
                requires_gate: None,
                enforcement_scope: "metadata only",
            }]
        );
    }
}
