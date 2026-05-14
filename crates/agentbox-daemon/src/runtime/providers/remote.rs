use async_trait::async_trait;

use crate::runtime::bridge::HostBridgeTransportKind;
use crate::runtime::provider::{
    ProviderFamily, ProviderImplementationStatus, RuntimeError, RuntimeProvider,
};
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
};

pub struct RemoteAgentPodProvider;

impl RemoteAgentPodProvider {
    fn unavailable(&self) -> RuntimeError {
        RuntimeError::Unavailable(
            "remote-agentpod is a provider descriptor; remote transport, auth, and worker lifecycle are not implemented yet".into(),
        )
    }
}

#[async_trait]
impl RuntimeProvider for RemoteAgentPodProvider {
    fn name(&self) -> &str {
        "remote-agentpod"
    }

    fn platform(&self) -> &str {
        "remote"
    }

    fn family(&self) -> ProviderFamily {
        ProviderFamily::Remote
    }

    fn implementation_status(&self) -> ProviderImplementationStatus {
        ProviderImplementationStatus::DescriptorOnly
    }

    fn capabilities(&self) -> &[RuntimeCapability] {
        &[
            RuntimeCapability::VmIsolation,
            RuntimeCapability::FilesystemPolicy,
            RuntimeCapability::NetworkPolicy,
            RuntimeCapability::CredentialPolicy,
            RuntimeCapability::ApprovalBridge,
            RuntimeCapability::EvidenceExport,
        ]
    }

    fn bridge_transport_kinds(&self) -> &[HostBridgeTransportKind] {
        &[HostBridgeTransportKind::RemoteTunnel]
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

    #[tokio::test]
    async fn remote_agentpod_descriptor_does_not_claim_execution() {
        let provider = RemoteAgentPodProvider;

        assert_provider_metadata(
            &provider,
            "remote-agentpod",
            "remote",
            &[
                RuntimeCapability::VmIsolation,
                RuntimeCapability::ApprovalBridge,
                RuntimeCapability::EvidenceExport,
            ],
        );
        assert_eq!(provider.family(), ProviderFamily::Remote);
        assert_eq!(
            provider.implementation_status(),
            ProviderImplementationStatus::DescriptorOnly
        );
        assert_eq!(
            provider.bridge_transport_kinds(),
            &[HostBridgeTransportKind::RemoteTunnel]
        );
        assert_network_enforcement_metadata(&provider, &[]);
        assert_unavailable_provider_contract(&provider).await;
    }
}
