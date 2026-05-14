use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::runtime::bridge::HostBridgeTransportKind;
use crate::runtime::provider::{
    ProviderFamily, ProviderImplementationStatus, RuntimeError, RuntimeProvider,
};
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteAgentPodAuthKind {
    WorkloadIdentity,
    SignedChallenge,
    MutualTls,
    OperatorSsh,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteAgentPodEvidenceMode {
    AppendOnlyStream,
    BundleUpload,
    LocalPull,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAgentPodTransportDescriptor {
    pub schema_version: i64,
    pub provider: String,
    pub endpoint: String,
    pub auth_kind: RemoteAgentPodAuthKind,
    pub evidence_mode: RemoteAgentPodEvidenceMode,
    pub kill_switch_required: bool,
    pub secret_material_included: bool,
    pub created_at: DateTime<Utc>,
}

impl RemoteAgentPodTransportDescriptor {
    pub fn new(
        endpoint: impl Into<String>,
        auth_kind: RemoteAgentPodAuthKind,
        evidence_mode: RemoteAgentPodEvidenceMode,
    ) -> Result<Self, RuntimeError> {
        let endpoint = endpoint.into();
        validate_remote_endpoint(&endpoint)?;
        Ok(Self {
            schema_version: 1,
            provider: "remote-agentpod".to_string(),
            endpoint,
            auth_kind,
            evidence_mode,
            kill_switch_required: true,
            secret_material_included: false,
            created_at: Utc::now(),
        })
    }
}

fn validate_remote_endpoint(endpoint: &str) -> Result<(), RuntimeError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(RuntimeError::ManifestRejected(
            "remote AgentPod endpoint must not be empty".into(),
        ));
    }
    if endpoint.contains('@') && !endpoint.starts_with("ssh://") {
        return Err(RuntimeError::ManifestRejected(
            "remote AgentPod endpoint must not embed credentials".into(),
        ));
    }
    if !(endpoint.starts_with("https://") || endpoint.starts_with("ssh://")) {
        return Err(RuntimeError::ManifestRejected(
            "remote AgentPod endpoint must use https:// or ssh://".into(),
        ));
    }
    Ok(())
}

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

    #[test]
    fn remote_transport_descriptor_is_secret_free_and_explicit() {
        let descriptor = RemoteAgentPodTransportDescriptor::new(
            "https://worker.example.com/agentpod",
            RemoteAgentPodAuthKind::SignedChallenge,
            RemoteAgentPodEvidenceMode::AppendOnlyStream,
        )
        .unwrap();

        assert_eq!(descriptor.schema_version, 1);
        assert_eq!(descriptor.provider, "remote-agentpod");
        assert!(descriptor.kill_switch_required);
        assert!(!descriptor.secret_material_included);
        assert_eq!(descriptor.endpoint, "https://worker.example.com/agentpod");
    }

    #[test]
    fn remote_transport_descriptor_rejects_insecure_or_secret_endpoints() {
        let insecure = RemoteAgentPodTransportDescriptor::new(
            "http://worker.example.com",
            RemoteAgentPodAuthKind::SignedChallenge,
            RemoteAgentPodEvidenceMode::AppendOnlyStream,
        )
        .unwrap_err();
        assert!(insecure.to_string().contains("https:// or ssh://"));

        let secret = RemoteAgentPodTransportDescriptor::new(
            "https://token@worker.example.com",
            RemoteAgentPodAuthKind::SignedChallenge,
            RemoteAgentPodEvidenceMode::AppendOnlyStream,
        )
        .unwrap_err();
        assert!(secret.to_string().contains("must not embed credentials"));
    }
}
