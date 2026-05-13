use async_trait::async_trait;

use crate::runtime::provider::{RuntimeError, RuntimeProvider};
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeProviderKind {
    MacOs,
    Linux,
    Windows,
}

impl NativeProviderKind {
    pub fn current_platform_candidate() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Linux
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::MacOs => "native-macos",
            Self::Linux => "native-linux",
            Self::Windows => "native-windows",
        }
    }

    fn platform(&self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Linux => "linux",
            Self::Windows => "windows",
        }
    }

    fn capabilities(&self) -> &'static [RuntimeCapability] {
        match self {
            Self::MacOs => &[
                RuntimeCapability::VmIsolation,
                RuntimeCapability::EndpointSecurity,
                RuntimeCapability::FilesystemPolicy,
                RuntimeCapability::NetworkPolicy,
                RuntimeCapability::CredentialPolicy,
                RuntimeCapability::ApprovalBridge,
                RuntimeCapability::EvidenceExport,
            ],
            Self::Linux => &[
                RuntimeCapability::NativeNamespaces,
                RuntimeCapability::FilesystemPolicy,
                RuntimeCapability::NetworkPolicy,
                RuntimeCapability::CredentialPolicy,
                RuntimeCapability::ApprovalBridge,
                RuntimeCapability::EvidenceExport,
            ],
            Self::Windows => &[
                RuntimeCapability::WindowsJobObjects,
                RuntimeCapability::AppContainer,
                RuntimeCapability::FilesystemPolicy,
                RuntimeCapability::NetworkPolicy,
                RuntimeCapability::CredentialPolicy,
                RuntimeCapability::ApprovalBridge,
                RuntimeCapability::EvidenceExport,
            ],
        }
    }
}

pub struct NativeProvider {
    kind: NativeProviderKind,
}

impl NativeProvider {
    pub fn new(kind: NativeProviderKind) -> Self {
        Self { kind }
    }

    pub fn current_platform_candidate() -> Self {
        Self::new(NativeProviderKind::current_platform_candidate())
    }

    fn unavailable(&self) -> RuntimeError {
        RuntimeError::Unavailable(format!(
            "{} is a provider descriptor; enforcement is not implemented yet",
            self.name()
        ))
    }
}

#[async_trait]
impl RuntimeProvider for NativeProvider {
    fn name(&self) -> &str {
        self.kind.name()
    }

    fn platform(&self) -> &str {
        self.kind.platform()
    }

    fn capabilities(&self) -> &[RuntimeCapability] {
        self.kind.capabilities()
    }

    async fn is_available(&self) -> bool {
        false
    }

    async fn create(&self, _spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError> {
        Err(self.unavailable())
    }

    async fn exec(
        &self,
        _session_id: &str,
        _command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        Err(self.unavailable())
    }

    async fn status(&self, _session_id: &str) -> Result<RuntimeStatus, RuntimeError> {
        Err(self.unavailable())
    }

    async fn destroy(&self, _session_id: &str) -> Result<(), RuntimeError> {
        Err(self.unavailable())
    }

    async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
        Err(self.unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_provider_names_are_explicit() {
        assert_eq!(
            NativeProvider::new(NativeProviderKind::MacOs).name(),
            "native-macos"
        );
        assert_eq!(
            NativeProvider::new(NativeProviderKind::Linux).name(),
            "native-linux"
        );
        assert_eq!(
            NativeProvider::new(NativeProviderKind::Windows).name(),
            "native-windows"
        );
    }

    #[test]
    fn native_provider_describes_planned_capabilities() {
        let macos = NativeProvider::new(NativeProviderKind::MacOs);

        assert_eq!(macos.platform(), "macos");
        assert!(macos
            .capabilities()
            .contains(&RuntimeCapability::EndpointSecurity));
        assert!(macos
            .capabilities()
            .contains(&RuntimeCapability::EvidenceExport));
    }

    #[tokio::test]
    async fn native_provider_is_not_available_until_enforcement_lands() {
        let provider = NativeProvider::new(NativeProviderKind::Linux);
        let spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");

        assert!(!provider.is_available().await);
        let err = provider.create(&spec).await.unwrap_err();

        assert!(err.to_string().contains("not implemented yet"));
    }
}
