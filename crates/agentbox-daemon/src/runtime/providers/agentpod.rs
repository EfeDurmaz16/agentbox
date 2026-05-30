use async_trait::async_trait;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::sync::{Arc, Mutex};

use agentbox_agentpod::{PROVIDER_LINUX, PROVIDER_MACOS, PROVIDER_WINDOWS};

use crate::runtime::bridge::HostBridgeTransportKind;
use crate::runtime::provider::{
    BoundaryPrimitiveStatus, ProviderFamily, ProviderImplementationStatus, RuntimeError,
    RuntimeProvider,
};
#[cfg(target_os = "linux")]
use crate::runtime::providers::linux::linux_cgroup_v2_root;
use crate::runtime::providers::linux::{
    linux_native_execution_enabled, LinuxAgentPodPrototypeExecutor,
};
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, RuntimeCapability, RuntimeSession, RuntimeStatus,
};

const MACOS_PROVIDER_MISSING_PREREQUISITES: &str = "agentpod-macos is unavailable until Apple Virtualization VM lifecycle, signed Endpoint Security system extension, Network Extension lifecycle, and live allow/deny evidence tests are wired; AGENTBOX_MACOS_NATIVE=1 only enables native-plan/runner request experiments, and AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1 only enables a gated Apple Virtualization boot prototype when kernel/initrd artifacts and entitlement prerequisites are present; neither gate enables provider execution";
const MACOS_PROVIDER_REQUIRED_GATE: &str =
    "Apple Virtualization boot lifecycle + signed Endpoint Security + Network Extension + live allow/deny tests";

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
            Self::MacOs => PROVIDER_MACOS,
            Self::Linux => PROVIDER_LINUX,
            Self::Windows => PROVIDER_WINDOWS,
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

    fn provider_unavailable(&self) -> RuntimeError {
        match self.kind {
            AgentPodProviderKind::Linux => self.linux_prototype_unavailable(),
            AgentPodProviderKind::MacOs => {
                RuntimeError::Unavailable(MACOS_PROVIDER_MISSING_PREREQUISITES.to_string())
            }
            AgentPodProviderKind::Windows => self.unavailable(),
        }
    }

    fn linux_prototype_available(&self) -> bool {
        matches!(self.kind, AgentPodProviderKind::Linux)
            && linux_prototype_available_for(
                linux_native_execution_enabled(),
                cfg!(target_os = "linux"),
                linux_prototype_host_prerequisites_ready(),
            )
    }

    fn gated_invocation_available(&self) -> bool {
        self.linux_prototype_available()
    }

    fn linux_prototype_unavailable(&self) -> RuntimeError {
        RuntimeError::Unavailable(
            "agentpod-linux prototype execution requires Linux and AGENTBOX_LINUX_NATIVE=1 plus host prerequisites: unshare, user namespaces, and a cgroups v2 root".into(),
        )
    }
}

fn linux_prototype_available_for(
    native_gate_enabled: bool,
    target_is_linux: bool,
    host_prerequisites_ready: bool,
) -> bool {
    native_gate_enabled && target_is_linux && host_prerequisites_ready
}

fn linux_prototype_host_prerequisites_ready() -> bool {
    linux_unshare_available() && linux_user_namespace_ready() && linux_cgroup_v2_root_ready()
}

#[cfg(target_os = "linux")]
fn linux_unshare_available() -> bool {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|path| path.join("unshare"))
                .find(|path| path.is_file())
        })
        .is_some()
}

#[cfg(not(target_os = "linux"))]
fn linux_unshare_available() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn linux_user_namespace_ready() -> bool {
    Path::new("/proc/self/ns/user").exists()
}

#[cfg(not(target_os = "linux"))]
fn linux_user_namespace_ready() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn linux_cgroup_v2_root_ready() -> bool {
    let root = linux_cgroup_v2_root();
    if std::env::var_os("AGENTBOX_LINUX_CGROUP_ROOT").is_some() {
        return root.is_dir();
    }
    root.join("cgroup.controllers").is_file()
}

#[cfg(not(target_os = "linux"))]
fn linux_cgroup_v2_root_ready() -> bool {
    false
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
                            "gated prototype ABI-aware Landlock path-beneath ruleset loader before exec for supported read/write/create/remove/execute plus host-supported refer/truncate rights, with explicit runtime support paths"
                        }
                        AgentPodPrimitive::Seccomp => {
                            "gated prototype BPF seccomp loader for supported generated/imported syscall deny rules plus coarse connect-deny network guard; not a complete libseccomp profile loader or packet/domain firewall"
                        }
                        AgentPodPrimitive::EBpf => {
                            "eBPF observability descriptor only; probe loading is not wired"
                        }
                        AgentPodPrimitive::Nftables => {
                            "gated nftables table lifecycle skeleton behind AGENTBOX_LINUX_NFTABLES=1; packet/domain enforcement is not wired"
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
                Some(MACOS_PROVIDER_REQUIRED_GATE),
                "plan compiler and runner request contract only; Apple Virtualization boot is gated separately by AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1, but provider execution, signed Endpoint Security system extension, Network Extension lifecycle, and live allow/deny evidence tests are not wired",
            ),
            AgentPodProviderKind::Windows => (
                ProviderImplementationStatus::DescriptorOnly,
                Some("live Windows lifecycle/enforcement gates"),
                "plan compiler only; Job Object create/close smoke is gated separately by AGENTBOX_WINDOWS_JOB_OBJECT=1, but provider execution is not wired and process assignment, cleanup, AppContainer/WFP/ETW execution, and live limit enforcement are not wired",
            ),
            AgentPodProviderKind::Linux => unreachable!("Linux handled above"),
        };

        self.planned_primitives()
            .iter()
            .map(|primitive| {
                if matches!(self.kind, AgentPodProviderKind::MacOs)
                    && matches!(primitive, AgentPodPrimitive::AppleVirtualization)
                {
                    return BoundaryPrimitiveStatus {
                        primitive: primitive.label(),
                        status: ProviderImplementationStatus::PrototypePrimitive,
                        active: false,
                        requires_gate: Some("AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1 + AGENTBOX_MACOS_VM_KERNEL_IMAGE + AGENTBOX_MACOS_VM_INITRD_IMAGE + com.apple.security.virtualization"),
                        enforcement_scope: "gated VZLinuxBootLoader/VZVirtualMachineConfiguration validation and short-lived VZVirtualMachine.start prototype; provider execution, host bridge evidence, and cleanup proof are not wired",
                    };
                }

                BoundaryPrimitiveStatus {
                    primitive: primitive.label(),
                    status,
                    active: false,
                    requires_gate,
                    enforcement_scope,
                }
            })
            .collect()
    }

    async fn is_available(&self) -> bool {
        self.gated_invocation_available()
    }

    async fn create(&self, spec: &MinipodSpec) -> Result<RuntimeSession, RuntimeError> {
        if !self.gated_invocation_available() {
            return Err(self.provider_unavailable());
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
            .map_err(|_| RuntimeError::Internal("agentpod session lock poisoned".into()))?
            .insert(session.id.clone(), session.clone());

        Ok(session)
    }

    async fn exec(
        &self,
        session_id: &str,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        if !self.gated_invocation_available() {
            return Err(self.provider_unavailable());
        }

        let session = self
            .sessions
            .lock()
            .map_err(|_| RuntimeError::Internal("agentpod session lock poisoned".into()))?
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

        match self.kind {
            AgentPodProviderKind::Linux => {
                LinuxAgentPodPrototypeExecutor::execute(&session.spec, &command)
            }
            AgentPodProviderKind::MacOs => Err(self.provider_unavailable()),
            AgentPodProviderKind::Windows => Err(self.unavailable()),
        }
    }

    async fn status(&self, session_id: &str) -> Result<RuntimeStatus, RuntimeError> {
        if !self.gated_invocation_available() {
            return Err(self.provider_unavailable());
        }

        self.sessions
            .lock()
            .map_err(|_| RuntimeError::Internal("agentpod session lock poisoned".into()))?
            .get(session_id)
            .map(|session| session.status.clone())
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))
    }

    async fn destroy(&self, session_id: &str) -> Result<(), RuntimeError> {
        if !self.gated_invocation_available() {
            return Err(self.provider_unavailable());
        }

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| RuntimeError::Internal("agentpod session lock poisoned".into()))?;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| RuntimeError::NotFound(session_id.to_string()))?;
        session.status = RuntimeStatus::Stopped;
        session.stopped_at = Some(chrono::Utc::now());
        Ok(())
    }

    async fn list(&self) -> Result<Vec<RuntimeSession>, RuntimeError> {
        if !self.gated_invocation_available() {
            return Err(self.provider_unavailable());
        }

        Ok(self
            .sessions
            .lock()
            .map_err(|_| RuntimeError::Internal("agentpod session lock poisoned".into()))?
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
        assert_eq!(
            provider.implementation_status(),
            ProviderImplementationStatus::DescriptorOnly
        );
        assert!(!provider.is_available().await);

        let statuses = provider.boundary_primitive_statuses();
        assert_eq!(statuses.len(), provider.boundary_primitives().len());
        for status in statuses {
            assert_eq!(status.status, ProviderImplementationStatus::DescriptorOnly);
            assert!(!status.active);
            assert_eq!(
                status.requires_gate,
                Some("live Windows lifecycle/enforcement gates")
            );
            assert!(status.enforcement_scope.contains("execution is not wired"));
            assert!(status.enforcement_scope.contains("process assignment"));
            assert!(status.enforcement_scope.contains("cleanup"));
            assert!(status.enforcement_scope.contains("live limit enforcement"));
            assert!(status
                .enforcement_scope
                .contains("AppContainer/WFP/ETW execution"));
        }
    }

    #[tokio::test]
    async fn macos_agentpod_provider_remains_unavailable_until_vm_lifecycle_exists() {
        let previous_gate = std::env::var_os("AGENTBOX_MACOS_NATIVE");
        std::env::set_var("AGENTBOX_MACOS_NATIVE", "1");

        let provider = AgentPodProvider::new(AgentPodProviderKind::MacOs);
        let spec = MinipodSpec::for_agent_task("macos-test", std::env::temp_dir());

        assert!(!provider.is_available().await);
        let err = provider.create(&spec).await.unwrap_err();

        match previous_gate {
            Some(value) => std::env::set_var("AGENTBOX_MACOS_NATIVE", value),
            None => std::env::remove_var("AGENTBOX_MACOS_NATIVE"),
        }

        let err = err.to_string();
        assert!(err.contains("agentpod-macos"));
        assert!(err.contains("Apple Virtualization VM lifecycle"));
        assert!(err.contains("signed Endpoint Security"));
        assert!(err.contains("Network Extension lifecycle"));
        assert!(err.contains("live allow/deny evidence tests"));
        assert!(err.contains("AGENTBOX_MACOS_NATIVE=1 only enables native-plan/runner request"));
        assert!(err.contains("AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1"));
        assert!(err.contains("neither gate enables provider execution"));

        let statuses = provider.boundary_primitive_statuses();
        assert!(statuses.iter().all(|status| !status.active));
        let apple_virtualization = statuses
            .iter()
            .find(|status| status.primitive == "apple-virtualization")
            .unwrap();
        assert_eq!(
            apple_virtualization.status,
            ProviderImplementationStatus::PrototypePrimitive
        );
        assert!(apple_virtualization
            .requires_gate
            .unwrap()
            .contains("AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1"));
        assert!(apple_virtualization
            .enforcement_scope
            .contains("VZVirtualMachine.start"));
        assert!(statuses
            .iter()
            .filter(|status| status.primitive != "apple-virtualization")
            .all(|status| {
                status.status == ProviderImplementationStatus::DescriptorOnly
                    && status.requires_gate == Some(MACOS_PROVIDER_REQUIRED_GATE)
                    && status
                        .enforcement_scope
                        .contains("live allow/deny evidence tests")
            }));
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

    #[test]
    fn linux_prototype_availability_requires_gate_target_and_host_prereqs() {
        assert!(!linux_prototype_available_for(false, true, true));
        assert!(!linux_prototype_available_for(true, false, true));
        assert!(!linux_prototype_available_for(true, true, false));
        assert!(linux_prototype_available_for(true, true, true));
    }

    #[tokio::test]
    async fn linux_agentpod_provider_lifecycle_is_gated_to_native_hosts() {
        if !(cfg!(target_os = "linux")
            && matches!(std::env::var("AGENTBOX_LINUX_NATIVE").as_deref(), Ok("1"))
            && linux_prototype_host_prerequisites_ready())
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
