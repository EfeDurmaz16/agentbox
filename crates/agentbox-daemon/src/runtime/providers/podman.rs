use std::collections::HashMap;

use async_trait::async_trait;

use crate::pod::podman::PodmanProvider;
use crate::pod::provider::{PodError, PodProvider};
use crate::pod::types::{
    ContainerRole, ContainerSpec, ExecRequest, MountKind as PodMountKind, MountSpec,
    NetworkMode as PodNetworkMode, NetworkPolicy as PodNetworkPolicy, PodSession, PodSpec,
    PodStatus, ReadinessProbe, ResourceLimits,
};
use crate::runtime::provider::{
    ProviderFamily, ProviderImplementationStatus, RuntimeError, RuntimeProvider,
};
use crate::runtime::types::{
    CommandResult, CredentialGrantKind, ExecCommand, MinipodSpec, MountKind, MountMode,
    NetworkMode, RuntimeCapability, RuntimeSession, RuntimeStatus,
};

pub struct PodmanRuntimeProvider {
    provider: PodmanProvider,
}

impl PodmanRuntimeProvider {
    pub fn new(agentbox_socket: String, shim_binary: String) -> Self {
        Self {
            provider: PodmanProvider::new(agentbox_socket, shim_binary),
        }
    }
}

#[async_trait]
impl RuntimeProvider for PodmanRuntimeProvider {
    fn name(&self) -> &str {
        "podman"
    }

    fn platform(&self) -> &str {
        "linux-vm"
    }

    fn family(&self) -> ProviderFamily {
        ProviderFamily::Compatibility
    }

    fn implementation_status(&self) -> ProviderImplementationStatus {
        ProviderImplementationStatus::Experimental
    }

    fn capabilities(&self) -> &[RuntimeCapability] {
        &[
            RuntimeCapability::ContainerIsolation,
            RuntimeCapability::VmIsolation,
            RuntimeCapability::FilesystemPolicy,
            RuntimeCapability::ApprovalBridge,
            RuntimeCapability::EvidenceExport,
        ]
    }

    async fn is_available(&self) -> bool {
        self.provider.is_available().await
    }

    async fn create(&self, spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError> {
        let pod_spec = minipod_to_pod_spec(spec);
        let session = self
            .provider
            .create(&spec.id, &pod_spec)
            .await
            .map_err(runtime_error)?;
        Ok(pod_session_to_runtime_session(session, spec.clone()))
    }

    async fn exec(
        &self,
        session_id: &str,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        let req = ExecRequest {
            command: command.argv.clone(),
            working_dir: command.working_dir.clone(),
            env: command.env.clone(),
            timeout_seconds: command.timeout_seconds,
        };
        let result = self
            .provider
            .exec(session_id, &req)
            .await
            .map_err(runtime_error)?;
        Ok(CommandResult {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            duration_ms: result.duration_ms,
        })
    }

    async fn status(&self, session_id: &str) -> Result<RuntimeStatus, RuntimeError> {
        self.provider
            .status(session_id)
            .await
            .map(pod_status_to_runtime_status)
            .map_err(runtime_error)
    }

    async fn destroy(&self, session_id: &str) -> Result<(), RuntimeError> {
        self.provider
            .destroy(session_id)
            .await
            .map_err(runtime_error)
    }

    async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
        self.provider
            .list()
            .await
            .map(|sessions| {
                sessions
                    .into_iter()
                    .map(|session| {
                        let spec = pod_session_to_minipod_spec(&session);
                        pod_session_to_runtime_session(session, spec)
                    })
                    .collect()
            })
            .map_err(runtime_error)
    }
}

fn minipod_to_pod_spec(spec: &MinipodSpec) -> PodSpec {
    let mut labels = spec.labels.clone();
    labels.insert("agentbox.session".to_string(), spec.id.clone());
    labels.insert("agentbox.agent".to_string(), spec.agent.name.clone());

    let mut mounts = vec![MountSpec {
        host_path: spec.filesystem.workspace_host_path.clone(),
        container_path: spec.filesystem.workspace_guest_path.clone(),
        read_only: false,
        kind: PodMountKind::Workspace,
        one_time: false,
    }];
    mounts.extend(spec.filesystem.mounts.iter().map(|mount| MountSpec {
        host_path: mount.host_path.clone(),
        container_path: mount.guest_path.clone(),
        read_only: matches!(mount.mode, MountMode::ReadOnly),
        kind: pod_mount_kind(&mount.kind),
        one_time: is_one_time_credential_mount(spec, mount),
    }));

    let mut containers = vec![ContainerSpec {
        name: "workspace".to_string(),
        image: workspace_image(spec),
        command: Some(spec.agent.command.clone()),
        env: HashMap::new(),
        ports: vec![],
        role: ContainerRole::Workspace,
        readiness: None,
    }];

    containers.extend(spec.services.iter().map(|service| ContainerSpec {
        name: service.name.clone(),
        image: service.image.clone(),
        command: None,
        env: service.env.clone(),
        ports: vec![],
        role: ContainerRole::Sidecar,
        readiness: service.readiness.as_ref().map(|probe| ReadinessProbe {
            command: probe.command.clone(),
            interval_ms: probe.interval_ms,
            timeout_ms: probe.timeout_ms,
        }),
    }));

    PodSpec {
        name: spec.name.clone(),
        containers,
        network: PodNetworkPolicy {
            mode: match spec.network.mode {
                NetworkMode::None => PodNetworkMode::None,
                NetworkMode::Host => PodNetworkMode::Host,
                NetworkMode::DenyByDefault
                | NetworkMode::AllowListed
                | NetworkMode::ApprovalOnFirstContact
                | NetworkMode::OpenWithGuardrails => PodNetworkMode::Restricted,
            },
            allow_domains: spec.network.allowed_domains.clone(),
        },
        resources: ResourceLimits {
            memory_bytes: spec.resources.memory_bytes,
            cpu_shares: spec.resources.cpu_shares,
        },
        mounts,
        env: HashMap::new(),
        timeout_seconds: spec.resources.timeout_seconds,
        labels,
    }
}

fn pod_mount_kind(kind: &MountKind) -> PodMountKind {
    match kind {
        MountKind::Workspace => PodMountKind::Workspace,
        MountKind::WorkspaceOverlay => PodMountKind::WorkspaceOverlay,
        MountKind::ReadOnlyHost => PodMountKind::ReadOnlyHost,
        MountKind::Credential => PodMountKind::Credential,
        MountKind::SystemBridge => PodMountKind::SystemBridge,
        MountKind::ServiceData => PodMountKind::ServiceData,
        MountKind::Custom(value) => PodMountKind::Custom(value.clone()),
    }
}

fn is_one_time_credential_mount(
    spec: &MinipodSpec,
    mount: &crate::runtime::types::MountRule,
) -> bool {
    matches!(mount.kind, MountKind::Credential)
        && spec.credentials.grants.iter().any(|grant| {
            matches!(grant.kind, CredentialGrantKind::FileMount)
                && grant.one_time
                && grant.target == mount.host_path.display().to_string()
        })
}

fn workspace_image(spec: &MinipodSpec) -> String {
    spec.labels
        .get("agentbox.runtime_image")
        .cloned()
        .unwrap_or_else(|| "ubuntu:24.04".to_string())
}

fn pod_session_to_runtime_session(session: PodSession, spec: MinipodSpec) -> RuntimeSession {
    let approval_grants = spec
        .approvals
        .iter()
        .cloned()
        .map(|grant| grant.bound_to_session(&session.id))
        .collect();
    RuntimeSession {
        id: session.id,
        name: spec.name.clone(),
        provider: session.provider,
        platform: "linux-vm".to_string(),
        status: pod_status_to_runtime_status(session.status),
        spec,
        approval_grants,
        transcripts: vec![],
        started_at: session.created_at,
        stopped_at: None,
    }
}

fn pod_session_to_minipod_spec(session: &PodSession) -> MinipodSpec {
    let workspace = session
        .spec
        .mounts
        .iter()
        .find(|mount| mount.container_path == "/workspace")
        .map(|mount| mount.host_path.clone())
        .unwrap_or_else(|| ".".into());
    let mut spec = MinipodSpec::for_agent_task(
        session
            .spec
            .labels
            .get("agentbox.agent")
            .cloned()
            .unwrap_or_else(|| "agent".to_string()),
        workspace,
    );
    spec.id = session.id.clone();
    spec.name = session.spec.name.clone();
    spec.labels = session.spec.labels.clone();
    spec
}

fn pod_status_to_runtime_status(status: PodStatus) -> RuntimeStatus {
    match status {
        PodStatus::Creating => RuntimeStatus::Creating,
        PodStatus::Running => RuntimeStatus::Running,
        PodStatus::Paused => RuntimeStatus::Paused,
        PodStatus::Stopped => RuntimeStatus::Stopped,
        PodStatus::Failed(reason) => RuntimeStatus::Failed(reason),
    }
}

fn runtime_error(error: PodError) -> RuntimeError {
    match error {
        PodError::NotFound(id) => RuntimeError::NotFound(id),
        PodError::AlreadyExists(id) => RuntimeError::AlreadyExists(id),
        PodError::Unavailable(reason) => RuntimeError::Unavailable(reason),
        PodError::PolicyDenied(reason) => RuntimeError::PolicyDenied(reason),
        PodError::ExecFailed(reason) => RuntimeError::ExecFailed(reason),
        PodError::Timeout(seconds) => RuntimeError::Timeout(seconds),
        PodError::ImagePullFailed(reason) | PodError::Internal(reason) => {
            RuntimeError::Internal(reason)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::providers::conformance::{
        assert_network_enforcement_metadata, assert_provider_metadata,
    };

    #[test]
    fn podman_provider_matches_runtime_provider_metadata() {
        let provider = PodmanRuntimeProvider::new(
            "/tmp/agentbox.sock".to_string(),
            "/tmp/agentbox-shim".to_string(),
        );

        assert_provider_metadata(
            &provider,
            "podman",
            "linux-vm",
            &[
                RuntimeCapability::ContainerIsolation,
                RuntimeCapability::VmIsolation,
                RuntimeCapability::FilesystemPolicy,
                RuntimeCapability::ApprovalBridge,
                RuntimeCapability::EvidenceExport,
            ],
        );
        assert!(
            provider.network_enforcement_capabilities().is_empty(),
            "podman compatibility adapter must not claim domain or packet enforcement"
        );
        assert_network_enforcement_metadata(&provider, &[]);
        assert_eq!(provider.family(), ProviderFamily::Compatibility);
        assert_eq!(
            provider.implementation_status(),
            ProviderImplementationStatus::Experimental
        );
    }

    #[test]
    fn converts_minipod_spec_to_pod_spec() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/workspace");
        spec.network.allowed_domains = vec!["api.openai.com".to_string()];
        spec.labels.insert("purpose".into(), "test".into());

        let pod_spec = minipod_to_pod_spec(&spec);

        assert_eq!(pod_spec.name, spec.name);
        assert_eq!(pod_spec.containers[0].name, "workspace");
        assert_eq!(pod_spec.containers[0].image, "ubuntu:24.04");
        assert_eq!(
            pod_spec.containers[0].command,
            Some(vec!["hermes".to_string()])
        );
        assert_eq!(pod_spec.mounts[0].container_path, "/workspace");
        assert_eq!(pod_spec.network.allow_domains, vec!["api.openai.com"]);
        assert_eq!(pod_spec.labels.get("agentbox.session"), Some(&spec.id));
        assert_eq!(pod_spec.labels.get("purpose"), Some(&"test".to_string()));
    }

    #[test]
    fn converts_one_time_credential_mounts_to_pod_mount_metadata() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/workspace");
        spec.filesystem
            .mounts
            .push(crate::runtime::types::MountRule {
                host_path: "/tmp/agentbox-openai-key".into(),
                guest_path: "/run/agentbox/credentials/openai".into(),
                mode: MountMode::ReadOnly,
                kind: MountKind::Credential,
            });
        spec.credentials
            .grants
            .push(crate::runtime::types::CredentialGrant {
                name: "openai".into(),
                kind: CredentialGrantKind::FileMount,
                target: "/tmp/agentbox-openai-key".into(),
                one_time: true,
                requires_approval: true,
            });

        let pod_spec = minipod_to_pod_spec(&spec);
        let credential_mount = pod_spec
            .mounts
            .iter()
            .find(|mount| mount.container_path == "/run/agentbox/credentials/openai")
            .expect("credential mount should be present");

        assert!(matches!(credential_mount.kind, PodMountKind::Credential));
        assert!(credential_mount.read_only);
        assert!(credential_mount.one_time);
    }

    #[test]
    fn converts_sidecar_readiness_to_pod_container_metadata() {
        let mut spec = MinipodSpec::for_agent_task("node", "/tmp/workspace");
        spec.services.push(crate::runtime::types::ServiceSpec {
            name: "postgres".into(),
            image: "postgres:16-alpine".into(),
            env: HashMap::new(),
            readiness: Some(crate::runtime::types::ServiceReadinessProbe {
                command: vec!["pg_isready".into(), "-U".into(), "postgres".into()],
                interval_ms: 250,
                timeout_ms: 10_000,
            }),
        });

        let pod_spec = minipod_to_pod_spec(&spec);
        let sidecar = pod_spec
            .containers
            .iter()
            .find(|container| matches!(container.role, ContainerRole::Sidecar))
            .expect("sidecar should be present");
        let readiness = sidecar
            .readiness
            .as_ref()
            .expect("sidecar readiness should be present");

        assert_eq!(readiness.command, vec!["pg_isready", "-U", "postgres"]);
        assert_eq!(readiness.interval_ms, 250);
        assert_eq!(readiness.timeout_ms, 10_000);
    }

    #[test]
    fn runtime_image_label_selects_workspace_image() {
        let mut spec = MinipodSpec::for_agent_task("node", "/tmp/workspace");
        spec.labels.insert(
            "agentbox.runtime_image".to_string(),
            "node:22-bookworm".to_string(),
        );

        let pod_spec = minipod_to_pod_spec(&spec);

        assert_eq!(pod_spec.containers[0].image, "node:22-bookworm");
    }

    #[test]
    fn converts_pod_status_to_runtime_status() {
        assert!(matches!(
            pod_status_to_runtime_status(PodStatus::Running),
            RuntimeStatus::Running
        ));
        assert!(matches!(
            pod_status_to_runtime_status(PodStatus::Failed("boom".into())),
            RuntimeStatus::Failed(reason) if reason == "boom"
        ));
    }

    #[test]
    fn maps_pod_errors_to_runtime_errors() {
        assert!(matches!(
            runtime_error(PodError::NotFound("abc".into())),
            RuntimeError::NotFound(id) if id == "abc"
        ));
        assert!(matches!(
            runtime_error(PodError::Timeout(5)),
            RuntimeError::Timeout(5)
        ));
    }
}
