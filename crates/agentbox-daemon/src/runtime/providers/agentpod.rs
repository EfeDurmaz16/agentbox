use async_trait::async_trait;

use crate::runtime::provider::{RuntimeError, RuntimeProvider};
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPodProviderKind {
    MacOs,
    Linux,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPodPrimitive {
    AppleVirtualization,
    EndpointSecurity,
    NetworkExtension,
    UserNamespaces,
    MountNamespaces,
    PidNamespaces,
    CgroupsV2,
    Landlock,
    Seccomp,
    EBpf,
    Nftables,
    JobObjects,
    AppContainer,
    Wfp,
    Etw,
}

impl AgentPodProviderKind {
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
            Self::MacOs => "agentpod-macos",
            Self::Linux => "agentpod-linux",
            Self::Windows => "agentpod-windows",
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

    fn planned_primitives(&self) -> &'static [AgentPodPrimitive] {
        match self {
            Self::MacOs => &[
                AgentPodPrimitive::AppleVirtualization,
                AgentPodPrimitive::EndpointSecurity,
                AgentPodPrimitive::NetworkExtension,
            ],
            Self::Linux => &[
                AgentPodPrimitive::UserNamespaces,
                AgentPodPrimitive::MountNamespaces,
                AgentPodPrimitive::PidNamespaces,
                AgentPodPrimitive::CgroupsV2,
                AgentPodPrimitive::Landlock,
                AgentPodPrimitive::Seccomp,
                AgentPodPrimitive::EBpf,
                AgentPodPrimitive::Nftables,
            ],
            Self::Windows => &[
                AgentPodPrimitive::JobObjects,
                AgentPodPrimitive::AppContainer,
                AgentPodPrimitive::Wfp,
                AgentPodPrimitive::Etw,
            ],
        }
    }
}

pub struct AgentPodProvider {
    kind: AgentPodProviderKind,
}

impl AgentPodProvider {
    pub fn new(kind: AgentPodProviderKind) -> Self {
        Self { kind }
    }

    pub fn current_platform_candidate() -> Self {
        Self::new(AgentPodProviderKind::current_platform_candidate())
    }

    pub fn planned_primitives(&self) -> &[AgentPodPrimitive] {
        self.kind.planned_primitives()
    }

    fn unavailable(&self) -> RuntimeError {
        RuntimeError::Unavailable(format!(
            "{} is a provider descriptor; enforcement is not implemented yet",
            self.name()
        ))
    }
}

#[async_trait]
impl RuntimeProvider for AgentPodProvider {
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
    use crate::runtime::providers::conformance::{
        assert_network_enforcement_metadata, assert_provider_metadata,
        assert_unavailable_provider_contract,
    };

    #[test]
    fn agentpod_provider_names_are_explicit() {
        assert_eq!(
            AgentPodProvider::new(AgentPodProviderKind::MacOs).name(),
            "agentpod-macos"
        );
        assert_eq!(
            AgentPodProvider::new(AgentPodProviderKind::Linux).name(),
            "agentpod-linux"
        );
        assert_eq!(
            AgentPodProvider::new(AgentPodProviderKind::Windows).name(),
            "agentpod-windows"
        );
    }

    #[test]
    fn agentpod_provider_describes_planned_capabilities() {
        let macos = AgentPodProvider::new(AgentPodProviderKind::MacOs);

        assert_provider_metadata(
            &macos,
            "agentpod-macos",
            "macos",
            &[
                RuntimeCapability::EndpointSecurity,
                RuntimeCapability::EvidenceExport,
            ],
        );
        assert!(
            macos.network_enforcement_capabilities().is_empty(),
            "unavailable AgentPod descriptors must not claim active network enforcement"
        );
        assert_network_enforcement_metadata(&macos, &[]);
    }

    #[tokio::test]
    async fn agentpod_provider_is_not_available_until_enforcement_lands() {
        let provider = AgentPodProvider::new(AgentPodProviderKind::Linux);

        assert_provider_metadata(
            &provider,
            "agentpod-linux",
            "linux",
            &[
                RuntimeCapability::NativeNamespaces,
                RuntimeCapability::FilesystemPolicy,
                RuntimeCapability::EvidenceExport,
            ],
        );
        assert_unavailable_provider_contract(&provider).await;
        assert!(
            provider.network_enforcement_capabilities().is_empty(),
            "unavailable AgentPod descriptors must not claim active network enforcement"
        );
    }

    #[test]
    fn linux_agentpod_scaffold_names_kernel_primitives_without_claiming_execution() {
        let provider = AgentPodProvider::new(AgentPodProviderKind::Linux);

        assert_eq!(provider.name(), "agentpod-linux");
        assert!(!provider.planned_primitives().is_empty());
        assert!(provider
            .planned_primitives()
            .contains(&AgentPodPrimitive::UserNamespaces));
        assert!(provider
            .planned_primitives()
            .contains(&AgentPodPrimitive::CgroupsV2));
        assert!(provider
            .planned_primitives()
            .contains(&AgentPodPrimitive::Landlock));
        assert!(provider
            .planned_primitives()
            .contains(&AgentPodPrimitive::Seccomp));
        assert!(provider
            .planned_primitives()
            .contains(&AgentPodPrimitive::EBpf));
    }
}
