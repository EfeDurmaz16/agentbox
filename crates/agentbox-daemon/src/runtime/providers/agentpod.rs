use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::runtime::bridge::HostBridgeTransportKind;
use crate::runtime::provider::{
    BoundaryPrimitiveStatus, ProviderFamily, ProviderImplementationStatus, RuntimeError,
    RuntimeProvider,
};
use crate::runtime::providers::linux::{
    linux_native_execution_enabled, LinuxAgentPodPrototypeExecutor,
};
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
    NoNewPrivs,
    CgroupsV2,
    Landlock,
    Seccomp,
    EBpf,
    Nftables,
    JobObjects,
    AppContainer,
    Wfp,
    Etw,
    WindowsSandbox,
    HyperV,
}

impl AgentPodPrimitive {
    pub fn label(&self) -> &'static str {
        match self {
            Self::AppleVirtualization => "apple-virtualization",
            Self::EndpointSecurity => "endpoint-security",
            Self::NetworkExtension => "network-extension",
            Self::UserNamespaces => "user-namespaces",
            Self::MountNamespaces => "mount-namespaces",
            Self::PidNamespaces => "pid-namespaces",
            Self::NoNewPrivs => "no-new-privs",
            Self::CgroupsV2 => "cgroups-v2",
            Self::Landlock => "landlock",
            Self::Seccomp => "seccomp",
            Self::EBpf => "ebpf",
            Self::Nftables => "nftables",
            Self::JobObjects => "job-objects",
            Self::AppContainer => "appcontainer",
            Self::Wfp => "wfp",
            Self::Etw => "etw",
            Self::WindowsSandbox => "windows-sandbox",
            Self::HyperV => "hyper-v",
        }
    }
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
                AgentPodPrimitive::NoNewPrivs,
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
                AgentPodPrimitive::WindowsSandbox,
                AgentPodPrimitive::HyperV,
            ],
        }
    }

    fn bridge_transport_kinds(&self) -> &'static [HostBridgeTransportKind] {
        match self {
            Self::MacOs => &[
                HostBridgeTransportKind::UnixSocket,
                HostBridgeTransportKind::Vsock,
            ],
            Self::Linux => &[HostBridgeTransportKind::UnixSocket],
            Self::Windows => &[HostBridgeTransportKind::NamedPipe],
        }
    }
}

pub struct AgentPodProvider {
    kind: AgentPodProviderKind,
    sessions: Arc<Mutex<HashMap<String, RuntimeSession>>>,
}

impl AgentPodProvider {
    pub fn new(kind: AgentPodProviderKind) -> Self {
        Self {
            kind,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
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

    fn linux_prototype_available(&self) -> bool {
        matches!(self.kind, AgentPodProviderKind::Linux)
            && cfg!(target_os = "linux")
            && linux_native_execution_enabled()
    }

    fn linux_prototype_unavailable(&self) -> RuntimeError {
        RuntimeError::Unavailable(
            "agentpod-linux prototype execution requires Linux and AGENTBOX_LINUX_NATIVE=1".into(),
        )
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

    fn family(&self) -> ProviderFamily {
        match self.kind {
            AgentPodProviderKind::MacOs => ProviderFamily::VmBacked,
            AgentPodProviderKind::Linux => ProviderFamily::NativeSandbox,
            AgentPodProviderKind::Windows => ProviderFamily::NativeSandbox,
        }
    }

    fn implementation_status(&self) -> ProviderImplementationStatus {
        match self.kind {
            AgentPodProviderKind::Linux => ProviderImplementationStatus::PrototypePrimitive,
            AgentPodProviderKind::MacOs | AgentPodProviderKind::Windows => {
                ProviderImplementationStatus::DescriptorOnly
            }
        }
    }

    fn capabilities(&self) -> &[RuntimeCapability] {
        self.kind.capabilities()
    }

    fn bridge_transport_kinds(&self) -> &[HostBridgeTransportKind] {
        self.kind.bridge_transport_kinds()
    }

    fn boundary_primitives(&self) -> Vec<&'static str> {
        self.planned_primitives()
            .iter()
            .map(AgentPodPrimitive::label)
            .collect()
    }

    fn boundary_primitive_statuses(&self) -> Vec<BoundaryPrimitiveStatus> {
        if matches!(self.kind, AgentPodProviderKind::Linux) {
            return self
                .planned_primitives()
                .iter()
                .map(|primitive| {
                    let enforcement_scope = match primitive {
                        AgentPodPrimitive::UserNamespaces => {
                            "gated unshare user namespace composition; not a complete sandbox"
                        }
                        AgentPodPrimitive::MountNamespaces => {
                            "gated unshare mount namespace composition with runner-managed bind mounts and prototype overlayfs workspace apply"
                        }
                        AgentPodPrimitive::PidNamespaces => {
                            "gated unshare PID namespace composition; process supervision remains prototype"
                        }
                        AgentPodPrimitive::NoNewPrivs => {
                            "gated PR_SET_NO_NEW_PRIVS child process flag before exec"
                        }
                        AgentPodPrimitive::CgroupsV2 => {
                            "gated cgroup v2 resource file writes, process attach, and cleanup"
                        }
                        AgentPodPrimitive::Landlock => {
                            "gated prototype Landlock write-oriented path-beneath ruleset loader before exec"
                        }
                        AgentPodPrimitive::Seccomp => {
                            "gated prototype BPF seccomp loader for supported syscall deny rules; not a complete libseccomp profile loader"
                        }
                        AgentPodPrimitive::EBpf => {
                            "eBPF observability descriptor only; probe loading is not wired"
                        }
                        AgentPodPrimitive::Nftables => {
                            "nftables egress descriptor only; packet/domain enforcement is not wired"
                        }
                        _ => "not part of the Linux AgentPod provider",
                    };
                    BoundaryPrimitiveStatus {
                        primitive: primitive.label(),
                        status: ProviderImplementationStatus::PrototypePrimitive,
                        active: false,
                        requires_gate: Some("AGENTBOX_LINUX_NATIVE=1"),
                        enforcement_scope,
                    }
                })
                .collect();
        }

        let (status, requires_gate, enforcement_scope) = match self.kind {
            AgentPodProviderKind::MacOs => (
                ProviderImplementationStatus::DescriptorOnly,
                Some("AGENTBOX_MACOS_NATIVE=1"),
                "plan compiler only; VM runner, system extension, and network extension are not wired",
            ),
            AgentPodProviderKind::Windows => (
                ProviderImplementationStatus::DescriptorOnly,
                Some("AGENTBOX_WINDOWS_NATIVE=1"),
                "plan compiler only; Job Object/AppContainer/WFP/ETW execution is not wired",
            ),
            AgentPodProviderKind::Linux => unreachable!("Linux handled above"),
        };

        self.planned_primitives()
            .iter()
            .map(|primitive| BoundaryPrimitiveStatus {
                primitive: primitive.label(),
                status,
                active: false,
                requires_gate,
                enforcement_scope,
            })
            .collect()
    }

    async fn is_available(&self) -> bool {
        self.linux_prototype_available()
    }

    async fn create(&self, spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError> {
        if !self.linux_prototype_available() {
            return Err(match self.kind {
                AgentPodProviderKind::Linux => self.linux_prototype_unavailable(),
                AgentPodProviderKind::MacOs | AgentPodProviderKind::Windows => self.unavailable(),
            });
        }

        let mut session = RuntimeSession::new(
            spec.name.clone(),
            self.name().to_string(),
            self.platform().to_string(),
            spec.clone(),
        );
        session.status = RuntimeStatus::Running;

        self.sessions
            .lock()
            .map_err(|_| RuntimeError::Internal("agentpod-linux session lock poisoned".into()))?
            .insert(session.id.clone(), session.clone());

        Ok(session)
    }

    async fn exec(
        &self,
        session_id: &str,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        if !self.linux_prototype_available() {
            return Err(match self.kind {
                AgentPodProviderKind::Linux => self.linux_prototype_unavailable(),
                AgentPodProviderKind::MacOs | AgentPodProviderKind::Windows => self.unavailable(),
            });
        }

        let session = self
            .sessions
            .lock()
            .map_err(|_| RuntimeError::Internal("agentpod-linux session lock poisoned".into()))?
            .get(session_id)
            .cloned()
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        if !matches!(session.status, RuntimeStatus::Running) {
            return Err(RuntimeError::PolicyDenied(format!(
                "cannot exec in {} session {session_id} with status {:?}",
                self.name(),
                session.status
            )));
        }
        let mut command = command.clone();
        if command.working_dir.as_deref() == Some(&session.spec.filesystem.workspace_guest_path) {
            command.working_dir = Some(
                session
                    .spec
                    .filesystem
                    .workspace_host_path
                    .display()
                    .to_string(),
            );
        }

        LinuxAgentPodPrototypeExecutor::execute(&session.spec, &command)
    }

    async fn status(&self, session_id: &str) -> Result<RuntimeStatus, RuntimeError> {
        if !self.linux_prototype_available() {
            return Err(match self.kind {
                AgentPodProviderKind::Linux => self.linux_prototype_unavailable(),
                AgentPodProviderKind::MacOs | AgentPodProviderKind::Windows => self.unavailable(),
            });
        }

        self.sessions
            .lock()
            .map_err(|_| RuntimeError::Internal("agentpod-linux session lock poisoned".into()))?
            .get(session_id)
            .map(|session| session.status.clone())
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))
    }

    async fn destroy(&self, session_id: &str) -> Result<(), RuntimeError> {
        if !self.linux_prototype_available() {
            return Err(match self.kind {
                AgentPodProviderKind::Linux => self.linux_prototype_unavailable(),
                AgentPodProviderKind::MacOs | AgentPodProviderKind::Windows => self.unavailable(),
            });
        }

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| RuntimeError::Internal("agentpod-linux session lock poisoned".into()))?;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        session.status = RuntimeStatus::Stopped;
        session.stopped_at = Some(chrono::Utc::now());
        Ok(())
    }

    async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
        if !self.linux_prototype_available() {
            return Err(match self.kind {
                AgentPodProviderKind::Linux => self.linux_prototype_unavailable(),
                AgentPodProviderKind::MacOs | AgentPodProviderKind::Windows => self.unavailable(),
            });
        }

        Ok(self
            .sessions
            .lock()
            .map_err(|_| RuntimeError::Internal("agentpod-linux session lock poisoned".into()))?
            .values()
            .cloned()
            .collect())
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
        assert!(macos
            .bridge_transport_kinds()
            .contains(&HostBridgeTransportKind::Vsock));
        assert_eq!(
            macos.boundary_primitives(),
            vec![
                "apple-virtualization",
                "endpoint-security",
                "network-extension"
            ]
        );
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
        assert_eq!(provider.family(), ProviderFamily::NativeSandbox);
        assert_eq!(
            provider.implementation_status(),
            ProviderImplementationStatus::PrototypePrimitive
        );
        assert!(
            provider.network_enforcement_capabilities().is_empty(),
            "unavailable AgentPod descriptors must not claim active network enforcement"
        );
        assert!(provider.boundary_primitives().contains(&"user-namespaces"));
        assert!(provider.boundary_primitives().contains(&"seccomp"));

        let windows = AgentPodProvider::new(AgentPodProviderKind::Windows);
        assert_provider_metadata(
            &windows,
            "agentpod-windows",
            "windows",
            &[
                RuntimeCapability::WindowsJobObjects,
                RuntimeCapability::AppContainer,
                RuntimeCapability::FilesystemPolicy,
                RuntimeCapability::NetworkPolicy,
                RuntimeCapability::CredentialPolicy,
                RuntimeCapability::ApprovalBridge,
                RuntimeCapability::EvidenceExport,
            ],
        );
        assert_eq!(windows.family(), ProviderFamily::NativeSandbox);
        assert_eq!(
            windows.implementation_status(),
            ProviderImplementationStatus::DescriptorOnly
        );
        assert!(
            windows.network_enforcement_capabilities().is_empty(),
            "Windows descriptor must not claim active WFP enforcement"
        );
        assert_network_enforcement_metadata(&windows, &[]);
        assert_eq!(
            windows.bridge_transport_kinds(),
            &[HostBridgeTransportKind::NamedPipe]
        );
        assert!(windows.boundary_primitives().contains(&"job-objects"));
        assert!(windows.boundary_primitives().contains(&"appcontainer"));
        assert!(windows.boundary_primitives().contains(&"wfp"));
        assert!(windows.boundary_primitives().contains(&"etw"));
        assert!(windows.boundary_primitives().contains(&"windows-sandbox"));
        assert!(windows.boundary_primitives().contains(&"hyper-v"));
    }

    #[tokio::test]
    async fn windows_agentpod_provider_remains_descriptor_only() {
        let provider = AgentPodProvider::new(AgentPodProviderKind::Windows);

        assert_unavailable_provider_contract(&provider).await;
        assert!(provider
            .boundary_primitive_statuses()
            .iter()
            .all(|status| !status.active
                && status.requires_gate == Some("AGENTBOX_WINDOWS_NATIVE=1")
                && status.enforcement_scope.contains("execution is not wired")));
    }

    #[tokio::test]
    async fn linux_agentpod_provider_refuses_without_native_gate() {
        if std::env::var("AGENTBOX_LINUX_NATIVE").is_ok() {
            return;
        }
        let provider = AgentPodProvider::new(AgentPodProviderKind::Linux);
        let spec = MinipodSpec::for_agent_task("linux-test", std::env::temp_dir());

        assert!(!provider.is_available().await);
        let err = provider.create(&spec).await.unwrap_err();

        assert!(err.to_string().contains("AGENTBOX_LINUX_NATIVE"));
    }

    #[tokio::test]
    async fn linux_agentpod_provider_lifecycle_is_gated_to_native_hosts() {
        if !(cfg!(target_os = "linux")
            && matches!(std::env::var("AGENTBOX_LINUX_NATIVE").as_deref(), Ok("1")))
        {
            return;
        }
        let provider = AgentPodProvider::new(AgentPodProviderKind::Linux);
        let spec = MinipodSpec::for_agent_task("linux-test", std::env::temp_dir());

        let session = provider.create(&spec).await.unwrap();

        assert_eq!(session.provider, "agentpod-linux");
        assert_eq!(
            provider.status(&session.id).await.unwrap(),
            RuntimeStatus::Running
        );
        provider.destroy(&session.id).await.unwrap();
        assert_eq!(
            provider.status(&session.id).await.unwrap(),
            RuntimeStatus::Stopped
        );
        let exec_err = provider
            .exec(
                &session.id,
                &ExecCommand {
                    argv: vec!["true".into()],
                    working_dir: None,
                    env: HashMap::new(),
                    timeout_seconds: Some(5),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(exec_err, RuntimeError::PolicyDenied(_)));
        assert!(provider.destroy("missing-session").await.is_err());
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
            .contains(&AgentPodPrimitive::NoNewPrivs));
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

        let primitive_statuses = provider.boundary_primitive_statuses();
        let cgroups = primitive_statuses
            .iter()
            .find(|status| status.primitive == "cgroups-v2")
            .unwrap();
        assert!(cgroups.enforcement_scope.contains("process attach"));
        assert!(cgroups.enforcement_scope.contains("cleanup"));

        let no_new_privs = primitive_statuses
            .iter()
            .find(|status| status.primitive == "no-new-privs")
            .unwrap();
        assert!(no_new_privs
            .enforcement_scope
            .contains("PR_SET_NO_NEW_PRIVS"));

        let seccomp = primitive_statuses
            .iter()
            .find(|status| status.primitive == "seccomp")
            .unwrap();
        assert!(seccomp.enforcement_scope.contains("BPF seccomp loader"));
        assert!(seccomp
            .enforcement_scope
            .contains("not a complete libseccomp"));

        let landlock = primitive_statuses
            .iter()
            .find(|status| status.primitive == "landlock")
            .unwrap();
        assert!(landlock.enforcement_scope.contains("ruleset loader"));

        let nftables = primitive_statuses
            .iter()
            .find(|status| status.primitive == "nftables")
            .unwrap();
        assert!(nftables
            .enforcement_scope
            .contains("packet/domain enforcement is not wired"));
    }
}
