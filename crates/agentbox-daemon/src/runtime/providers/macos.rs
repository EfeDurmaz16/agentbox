use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::config;
use crate::runtime::bridge::{
    CommandMediationRequest, FileGrantRequest, HostBridgeDecision, HostBridgeRequest,
    HostBridgeTransportKind, NetworkFirstContactRequest,
};
use crate::runtime::provider::RuntimeError;
use crate::runtime::types::{
    CommandResult, ExecCommand, FileAccessMode, MinipodSpec, MountKind, MountMode, NetworkMode,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsVirtualizationCellPlan {
    pub schema_version: i64,
    pub bundle_id: String,
    pub guest_os: String,
    pub cpu_count: u32,
    pub memory_bytes: u64,
    pub workspace_host_path: String,
    pub workspace_guest_path: String,
    pub cell_config: MacOsVmCellConfigPlan,
    pub storage_layout: MacOsVmCellStorageLayout,
    pub shared_directories: Vec<MacOsSharedDirectoryPlan>,
    pub host_bridge: MacOsHostBridgePlan,
    pub requires_apple_virtualization: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsVmCellConfigPlan {
    pub workspace_mount: MacOsWorkspaceMountPlan,
    pub credential_channels: Vec<MacOsCredentialChannelPlan>,
    pub bridge_socket_guest_path: String,
    pub evidence_spool_guest_path: String,
    pub shutdown_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsVmCellStorageLayout {
    pub schema_version: i64,
    pub cell_root_host_path: String,
    pub config_json_host_path: String,
    pub disk_image_host_path: String,
    pub auxiliary_storage_host_path: String,
    pub workspace_mount_host_path: String,
    pub credential_channel_host_path: String,
    pub evidence_spool_host_path: String,
    pub cleanup_policy: MacOsVmCellCleanupPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsVmCellCleanupPolicy {
    pub remove_runner_request_after_invocation: bool,
    pub destroy_cell_root_after_stop: bool,
    pub seal_evidence_before_cleanup: bool,
    pub retain_disk_image_on_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsWorkspaceMountPlan {
    pub host_path: String,
    pub guest_path: String,
    pub writable: bool,
    pub review_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsCredentialChannelPlan {
    pub name: String,
    pub kind: crate::runtime::types::CredentialGrantKind,
    pub target: String,
    pub delivery: String,
    pub guest_path: Option<String>,
    pub requires_approval: bool,
    pub one_time: bool,
    pub scope: MacOsCredentialGrantScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub recipient: MacOsCredentialRecipient,
    pub audit: MacOsCredentialAuditMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsCredentialGrantScope {
    pub session_id: String,
    pub grant_name: String,
    pub kind: crate::runtime::types::CredentialGrantKind,
    pub target_ref: String,
    pub delivery: String,
    pub guest_path: Option<String>,
    pub one_time: bool,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsCredentialRecipient {
    pub provider: String,
    pub session_id: String,
    pub vm_bundle_id: String,
    pub cell_safe_id: String,
    pub guest_workspace_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsCredentialAuditMetadata {
    pub grant_event_type: String,
    pub revoke_event_type: String,
    pub evidence_stream: String,
    pub evidence_ref_prefix: String,
    pub redacted: bool,
    pub secret_values_forbidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsSharedDirectoryPlan {
    pub host_path: String,
    pub guest_path: String,
    pub read_only: bool,
    pub kind: MountKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsHostBridgePlan {
    pub transport: HostBridgeTransportKind,
    pub guest_socket_path: String,
    pub policy_endpoint: String,
    pub evidence_endpoint: String,
}

impl MacOsVirtualizationCellPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Result<Self, RuntimeError> {
        if spec.id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS AgentPod session id cannot be empty".into(),
            ));
        }
        if spec.resources.memory_bytes == 0 {
            return Err(RuntimeError::ManifestRejected(
                "macOS AgentPod VM memory limit cannot be zero".into(),
            ));
        }
        if spec.filesystem.workspace_host_path.as_os_str().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS AgentPod workspace host path cannot be empty".into(),
            ));
        }

        let mut shared_directories = vec![MacOsSharedDirectoryPlan {
            host_path: spec.filesystem.workspace_host_path.display().to_string(),
            guest_path: spec.filesystem.workspace_guest_path.clone(),
            read_only: false,
            kind: MountKind::Workspace,
        }];
        shared_directories.extend(spec.filesystem.mounts.iter().map(|mount| {
            MacOsSharedDirectoryPlan {
                host_path: mount.host_path.display().to_string(),
                guest_path: mount.guest_path.clone(),
                read_only: matches!(mount.mode, MountMode::ReadOnly),
                kind: mount.kind.clone(),
            }
        }));

        let workspace_mount = MacOsWorkspaceMountPlan {
            host_path: spec.filesystem.workspace_host_path.display().to_string(),
            guest_path: spec.filesystem.workspace_guest_path.clone(),
            writable: true,
            review_required: !matches!(
                spec.workspace_mode,
                crate::runtime::types::AgentPodWorkspaceMode::Direct
            ),
        };
        let credential_channels = spec
            .credentials
            .grants
            .iter()
            .map(|grant| macos_credential_channel_plan(spec, grant))
            .collect();
        let bridge_socket_guest_path = "/run/agentbox/bridge.sock".to_string();

        let storage_layout = MacOsVmCellStorageLayout::from_minipod_spec(spec);

        Ok(Self {
            schema_version: 1,
            bundle_id: format!("dev.agentbox.agentpod.{}", spec.id),
            guest_os: "linux".into(),
            cpu_count: cpu_shares_to_vcpu(spec.resources.cpu_shares),
            memory_bytes: spec.resources.memory_bytes,
            workspace_host_path: spec.filesystem.workspace_host_path.display().to_string(),
            workspace_guest_path: spec.filesystem.workspace_guest_path.clone(),
            cell_config: MacOsVmCellConfigPlan {
                workspace_mount,
                credential_channels,
                bridge_socket_guest_path: bridge_socket_guest_path.clone(),
                evidence_spool_guest_path: "/var/lib/agentbox/evidence".into(),
                shutdown_policy: "destroy-vm-cell-and-seal-evidence".into(),
            },
            storage_layout,
            shared_directories,
            host_bridge: MacOsHostBridgePlan {
                transport: HostBridgeTransportKind::Vsock,
                guest_socket_path: bridge_socket_guest_path,
                policy_endpoint: "agentbox.policy.v1.Decide".into(),
                evidence_endpoint: "agentbox.evidence.v1.Append".into(),
            },
            requires_apple_virtualization: true,
        })
    }
}

impl MacOsVmCellStorageLayout {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
        let cell_root = config::config_dir()
            .join("agentpods")
            .join("macos")
            .join(macos_agentpod_cell_safe_id(&spec.id));
        Self {
            schema_version: 1,
            cell_root_host_path: path_to_string(&cell_root),
            config_json_host_path: path_to_string(&cell_root.join("config").join("cell.json")),
            disk_image_host_path: path_to_string(&cell_root.join("disk").join("rootfs.img")),
            auxiliary_storage_host_path: path_to_string(&cell_root.join("disk").join("aux.img")),
            workspace_mount_host_path: path_to_string(&spec.filesystem.workspace_host_path),
            credential_channel_host_path: path_to_string(&cell_root.join("credentials")),
            evidence_spool_host_path: path_to_string(&cell_root.join("evidence")),
            cleanup_policy: MacOsVmCellCleanupPolicy {
                remove_runner_request_after_invocation: true,
                destroy_cell_root_after_stop: true,
                seal_evidence_before_cleanup: true,
                retain_disk_image_on_failure: true,
            },
        }
    }
}

fn path_to_string(path: &std::path::Path) -> String {
    path.display().to_string()
}

fn macos_agentpod_cell_safe_id(session_id: &str) -> String {
    let safe_session_id: String = session_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let safe_session_id = safe_session_id.trim_matches('_');
    if safe_session_id.is_empty() {
        "session".into()
    } else {
        safe_session_id.into()
    }
}

fn macos_credential_delivery(kind: &crate::runtime::types::CredentialGrantKind) -> &'static str {
    match kind {
        crate::runtime::types::CredentialGrantKind::EnvVar => "host-bridge-env-injection",
        crate::runtime::types::CredentialGrantKind::FileMount => "read-only-shared-directory",
        crate::runtime::types::CredentialGrantKind::Socket => "host-bridge-socket-proxy",
        crate::runtime::types::CredentialGrantKind::ProviderToken => {
            "broker-mediated-provider-token"
        }
    }
}

fn macos_credential_channel_plan(
    spec: &MinipodSpec,
    grant: &crate::runtime::types::CredentialGrant,
) -> MacOsCredentialChannelPlan {
    let delivery = macos_credential_delivery(&grant.kind).to_string();
    let guest_path = macos_credential_guest_path(&grant.kind, &grant.name);
    MacOsCredentialChannelPlan {
        name: grant.name.clone(),
        kind: grant.kind.clone(),
        target: grant.target.clone(),
        delivery: delivery.clone(),
        guest_path: guest_path.clone(),
        requires_approval: grant.requires_approval,
        one_time: grant.one_time,
        scope: MacOsCredentialGrantScope {
            session_id: spec.id.clone(),
            grant_name: grant.name.clone(),
            kind: grant.kind.clone(),
            target_ref: grant.target.clone(),
            delivery,
            guest_path,
            one_time: grant.one_time,
            requires_approval: grant.requires_approval,
        },
        expires_at: grant.expires_at,
        recipient: MacOsCredentialRecipient {
            provider: "agentpod-macos".into(),
            session_id: spec.id.clone(),
            vm_bundle_id: format!("dev.agentbox.agentpod.{}", spec.id),
            cell_safe_id: macos_agentpod_cell_safe_id(&spec.id),
            guest_workspace_path: spec.filesystem.workspace_guest_path.clone(),
        },
        audit: MacOsCredentialAuditMetadata {
            grant_event_type: "agentbox.credential.grant.requested".into(),
            revoke_event_type: "agentbox.credential.grant.revoked".into(),
            evidence_stream: format!("agentpod-macos/{}/credentials", spec.id),
            evidence_ref_prefix: format!("agentpod-macos:{}:credential:{}", spec.id, grant.name),
            redacted: true,
            secret_values_forbidden: true,
        },
    }
}

fn macos_credential_guest_path(
    kind: &crate::runtime::types::CredentialGrantKind,
    name: &str,
) -> Option<String> {
    match kind {
        crate::runtime::types::CredentialGrantKind::FileMount => {
            Some(format!("/run/agentbox/credentials/{name}"))
        }
        crate::runtime::types::CredentialGrantKind::Socket => {
            Some(format!("/run/agentbox/sockets/{name}.sock"))
        }
        crate::runtime::types::CredentialGrantKind::EnvVar
        | crate::runtime::types::CredentialGrantKind::ProviderToken => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsEndpointSecurityPlan {
    pub schema_version: i64,
    pub subscribe_events: Vec<String>,
    pub protected_paths: Vec<MacOsProtectedPathPlan>,
    pub deny_home_by_default: bool,
    pub requires_system_extension: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsProtectedPathPlan {
    pub path: String,
    pub reason: String,
}

impl MacOsEndpointSecurityPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
        Self {
            schema_version: 1,
            subscribe_events: vec![
                "ES_EVENT_TYPE_AUTH_EXEC".into(),
                "ES_EVENT_TYPE_AUTH_OPEN".into(),
                "ES_EVENT_TYPE_AUTH_CREATE".into(),
                "ES_EVENT_TYPE_AUTH_RENAME".into(),
                "ES_EVENT_TYPE_AUTH_UNLINK".into(),
            ],
            protected_paths: spec
                .filesystem
                .protected_paths
                .iter()
                .map(|path| MacOsProtectedPathPlan {
                    path: path.path.display().to_string(),
                    reason: path.reason.clone(),
                })
                .collect(),
            deny_home_by_default: spec.filesystem.deny_home_by_default,
            requires_system_extension: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsNetworkExtensionPlan {
    pub schema_version: i64,
    pub mode: NetworkMode,
    pub allowed_domains: Vec<String>,
    pub denied_domains: Vec<String>,
    pub allow_localhost: bool,
    pub requires_network_extension: bool,
}

impl MacOsNetworkExtensionPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
        Self {
            schema_version: 1,
            mode: spec.network.mode.clone(),
            allowed_domains: spec.network.allowed_domains.clone(),
            denied_domains: spec.network.denied_domains.clone(),
            allow_localhost: spec.network.allow_localhost,
            requires_network_extension: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsEvidenceObserverPlan {
    pub schema_version: i64,
    pub session_id: String,
    pub correlation: MacOsEvidenceCorrelationPlan,
    pub event_schema: Vec<MacOsEvidenceEventSchema>,
    pub enforcement: MacOsEvidenceEnforcementMode,
    pub evidence_claim: String,
    pub requires_endpoint_security: bool,
    pub requires_network_extension: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsEvidenceCorrelationPlan {
    pub preferred_key: String,
    pub vm_bundle_id: String,
    pub process_id_fallback: bool,
    pub manifest_label_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsEvidenceEventSchema {
    pub event_type: String,
    pub source: String,
    pub evidence_use: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacOsEvidenceEnforcementMode {
    ObservedOnly,
}

impl MacOsEvidenceObserverPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
        let mut manifest_label_keys: Vec<String> = spec.labels.keys().cloned().collect();
        manifest_label_keys.sort();
        Self {
            schema_version: 1,
            session_id: spec.id.clone(),
            correlation: MacOsEvidenceCorrelationPlan {
                preferred_key: "vm_bundle_id".into(),
                vm_bundle_id: format!("dev.agentbox.agentpod.{}", spec.id),
                process_id_fallback: true,
                manifest_label_keys,
            },
            event_schema: vec![
                MacOsEvidenceEventSchema {
                    event_type: "macos.process.exec".into(),
                    source: "EndpointSecurity:AUTH_EXEC".into(),
                    evidence_use: "command lineage, argv, and signing identity evidence".into(),
                },
                MacOsEvidenceEventSchema {
                    event_type: "macos.file.open".into(),
                    source: "EndpointSecurity:AUTH_OPEN".into(),
                    evidence_use: "protected path read/write intent evidence".into(),
                },
                MacOsEvidenceEventSchema {
                    event_type: "macos.network.flow".into(),
                    source: "NetworkExtension:outbound-flow".into(),
                    evidence_use: "destination metadata for network boundary evidence".into(),
                },
                MacOsEvidenceEventSchema {
                    event_type: "agentbox.provider.lifecycle".into(),
                    source: "AgentboxHostBridge".into(),
                    evidence_use: "VM lifecycle and host bridge decision evidence".into(),
                },
            ],
            enforcement: MacOsEvidenceEnforcementMode::ObservedOnly,
            evidence_claim:
                "macOS evidence observer descriptor only; observed events are not enforcement proof"
                    .into(),
            requires_endpoint_security: true,
            requires_network_extension: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsNativePrerequisiteCheck {
    pub name: String,
    pub status: String,
    pub required: bool,
    pub probe: String,
    pub claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsAgentPodRunnerPhase {
    pub name: String,
    pub status: String,
    pub claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsAgentPodExecutionPlan {
    pub schema_version: i64,
    pub provider: String,
    pub session_id: String,
    pub command_argv: Vec<String>,
    pub virtualization: MacOsVirtualizationCellPlan,
    pub endpoint_security: MacOsEndpointSecurityPlan,
    pub network_extension: MacOsNetworkExtensionPlan,
    pub evidence_observer: MacOsEvidenceObserverPlan,
    pub prerequisite_checks: Vec<MacOsNativePrerequisiteCheck>,
    pub runner_phases: Vec<MacOsAgentPodRunnerPhase>,
    pub required_entitlements: Vec<String>,
    pub live_env_var: String,
    pub live_execution_enabled: bool,
    pub requires_macos: bool,
    pub security_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsAgentPodRunnerRequest {
    pub schema_version: i64,
    pub session_id: String,
    pub command_argv: Vec<String>,
    pub working_dir: Option<String>,
    pub boot_request: MacOsVmCellBootRequest,
    pub virtualization: MacOsVirtualizationCellPlan,
    pub endpoint_security: MacOsEndpointSecurityPlan,
    pub network_extension: MacOsNetworkExtensionPlan,
    pub evidence_observer: MacOsEvidenceObserverPlan,
    pub prerequisite_checks: Vec<MacOsNativePrerequisiteCheck>,
    pub runner_phases: Vec<MacOsAgentPodRunnerPhase>,
    pub required_entitlements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsVmCellBootRequest {
    pub schema_version: i64,
    pub session_id: String,
    pub bundle_id: String,
    pub guest_os: String,
    pub cpu_count: u32,
    pub memory_bytes: u64,
    pub command_argv: Vec<String>,
    pub working_dir: String,
    pub storage_layout: MacOsVmCellStorageLayout,
    pub workspace_mount: MacOsWorkspaceMountPlan,
    pub shared_directories: Vec<MacOsSharedDirectoryPlan>,
    pub bridge_socket_guest_path: String,
    pub evidence_spool_guest_path: String,
    pub required_entitlements: Vec<String>,
    pub claim_boundary: String,
}

impl MacOsVmCellBootRequest {
    pub fn from_execution_plan(plan: &MacOsAgentPodExecutionPlan, command: &ExecCommand) -> Self {
        Self {
            schema_version: 1,
            session_id: plan.session_id.clone(),
            bundle_id: plan.virtualization.bundle_id.clone(),
            guest_os: plan.virtualization.guest_os.clone(),
            cpu_count: plan.virtualization.cpu_count,
            memory_bytes: plan.virtualization.memory_bytes,
            command_argv: plan.command_argv.clone(),
            working_dir: command
                .working_dir
                .clone()
                .unwrap_or_else(|| plan.virtualization.workspace_guest_path.clone()),
            storage_layout: plan.virtualization.storage_layout.clone(),
            workspace_mount: plan.virtualization.cell_config.workspace_mount.clone(),
            shared_directories: plan.virtualization.shared_directories.clone(),
            bridge_socket_guest_path: plan
                .virtualization
                .cell_config
                .bridge_socket_guest_path
                .clone(),
            evidence_spool_guest_path: plan
                .virtualization
                .cell_config
                .evidence_spool_guest_path
                .clone(),
            required_entitlements: plan.required_entitlements.clone(),
            claim_boundary:
                "boot request contract only; Apple Virtualization lifecycle is not wired".into(),
        }
    }

    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema_version != 1 {
            return Err(RuntimeError::ManifestRejected(
                "macOS VM cell boot request schema_version must be 1".into(),
            ));
        }
        if self.session_id.trim().is_empty() || self.bundle_id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS VM cell boot request must include session and bundle ids".into(),
            ));
        }
        if self.guest_os.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS VM cell boot request guest OS cannot be empty".into(),
            ));
        }
        if self.cpu_count == 0 || self.memory_bytes == 0 {
            return Err(RuntimeError::ManifestRejected(
                "macOS VM cell boot request must include positive CPU and memory limits".into(),
            ));
        }
        if self.command_argv.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS VM cell boot request command argv cannot be empty".into(),
            ));
        }
        if self.working_dir.trim().is_empty()
            || self.workspace_mount.host_path.trim().is_empty()
            || self.workspace_mount.guest_path.trim().is_empty()
            || self.bridge_socket_guest_path.trim().is_empty()
            || self.evidence_spool_guest_path.trim().is_empty()
        {
            return Err(RuntimeError::ManifestRejected(
                "macOS VM cell boot request paths cannot be empty".into(),
            ));
        }
        if !self
            .required_entitlements
            .iter()
            .any(|entitlement| entitlement == "com.apple.security.virtualization")
        {
            return Err(RuntimeError::ManifestRejected(
                "macOS VM cell boot request must require Apple Virtualization entitlement".into(),
            ));
        }
        if !self.claim_boundary.contains("not wired") {
            return Err(RuntimeError::ManifestRejected(
                "macOS VM cell boot request must keep an explicit non-execution claim boundary"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl MacOsAgentPodRunnerRequest {
    pub fn from_execution_plan(plan: &MacOsAgentPodExecutionPlan, command: &ExecCommand) -> Self {
        Self {
            schema_version: 1,
            session_id: plan.session_id.clone(),
            command_argv: plan.command_argv.clone(),
            working_dir: command
                .working_dir
                .clone()
                .or_else(|| Some(plan.virtualization.workspace_guest_path.clone())),
            boot_request: MacOsVmCellBootRequest::from_execution_plan(plan, command),
            virtualization: plan.virtualization.clone(),
            endpoint_security: plan.endpoint_security.clone(),
            network_extension: plan.network_extension.clone(),
            evidence_observer: plan.evidence_observer.clone(),
            prerequisite_checks: plan.prerequisite_checks.clone(),
            runner_phases: plan.runner_phases.clone(),
            required_entitlements: plan.required_entitlements.clone(),
        }
    }
}

impl MacOsAgentPodExecutionPlan {
    pub fn from_minipod_spec(
        spec: &MinipodSpec,
        command: &ExecCommand,
    ) -> Result<Self, RuntimeError> {
        if command.argv.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS AgentPod execution command cannot be empty".into(),
            ));
        }

        Ok(Self {
            schema_version: 1,
            provider: "agentpod-macos".into(),
            session_id: spec.id.clone(),
            command_argv: command.argv.clone(),
            virtualization: MacOsVirtualizationCellPlan::from_minipod_spec(spec)?,
            endpoint_security: MacOsEndpointSecurityPlan::from_minipod_spec(spec),
            network_extension: MacOsNetworkExtensionPlan::from_minipod_spec(spec),
            evidence_observer: MacOsEvidenceObserverPlan::from_minipod_spec(spec),
            prerequisite_checks: macos_native_prerequisite_checks(),
            runner_phases: macos_agentpod_runner_phases(),
            required_entitlements: vec![
                "com.apple.security.virtualization".into(),
                "com.apple.developer.endpoint-security.client".into(),
                "com.apple.developer.networking.networkextension".into(),
            ],
            live_env_var: "AGENTBOX_MACOS_NATIVE".into(),
            live_execution_enabled: macos_native_execution_enabled(),
            requires_macos: true,
            security_claim: "VM cell plan plus host ES/NE enforcement plan; execution is not wired"
                .into(),
        })
    }

    pub fn runnable_on_current_host(&self) -> bool {
        cfg!(target_os = "macos") && self.live_execution_enabled
    }
}

fn macos_native_prerequisite_checks() -> Vec<MacOsNativePrerequisiteCheck> {
    vec![
        MacOsNativePrerequisiteCheck {
            name: "apple-virtualization-framework".into(),
            status: "host-probe-required".into(),
            required: true,
            probe: "test -d /System/Library/Frameworks/Virtualization.framework".into(),
            claim: "host can load Apple Virtualization.framework for VM-cell lifecycle".into(),
        },
        MacOsNativePrerequisiteCheck {
            name: "virtualization-entitlement".into(),
            status: "signing-required".into(),
            required: true,
            probe: "codesign -d --entitlements :- <agentbox-macos-runner>".into(),
            claim: "runner binary is signed with com.apple.security.virtualization".into(),
        },
        MacOsNativePrerequisiteCheck {
            name: "vm-runner-binary".into(),
            status: "planned".into(),
            required: true,
            probe: "agentbox-macos-vm-runner --version".into(),
            claim: "dedicated VM runner exists and owns Apple Virtualization lifecycle".into(),
        },
        MacOsNativePrerequisiteCheck {
            name: "endpoint-security-system-extension".into(),
            status: "planned".into(),
            required: true,
            probe: "systemextensionsctl list | rg dev.agentbox.endpoint-security".into(),
            claim: "signed Endpoint Security system extension is installed and user-approved"
                .into(),
        },
        MacOsNativePrerequisiteCheck {
            name: "network-extension".into(),
            status: "planned".into(),
            required: true,
            probe: "systemextensionsctl list | rg dev.agentbox.network-extension".into(),
            claim: "signed Network Extension is installed and can mediate outbound flows".into(),
        },
    ]
}

fn macos_agentpod_runner_phases() -> Vec<MacOsAgentPodRunnerPhase> {
    vec![
        MacOsAgentPodRunnerPhase {
            name: "compile-vm-cell-config".into(),
            status: "descriptor".into(),
            claim: "emit secret-free VM cell, workspace mount, bridge socket, and evidence spool descriptors".into(),
        },
        MacOsAgentPodRunnerPhase {
            name: "start-virtualization-vm".into(),
            status: "planned".into(),
            claim: "boot a short-lived Apple Virtualization VM cell for the AgentPod session".into(),
        },
        MacOsAgentPodRunnerPhase {
            name: "attach-host-bridge".into(),
            status: "planned".into(),
            claim: "connect guest policy and evidence traffic to the Agentbox host bridge".into(),
        },
        MacOsAgentPodRunnerPhase {
            name: "attach-endpoint-security".into(),
            status: "planned".into(),
            claim: "correlate host exec/file authorization events with the VM cell and policy bridge".into(),
        },
        MacOsAgentPodRunnerPhase {
            name: "attach-network-extension".into(),
            status: "planned".into(),
            claim: "mediate outbound flow first contact through the host bridge before allow/deny".into(),
        },
        MacOsAgentPodRunnerPhase {
            name: "exec-command".into(),
            status: "planned".into(),
            claim: "execute argv inside the VM cell only after bridge and evidence channels are ready".into(),
        },
    ]
}

pub fn macos_native_execution_enabled() -> bool {
    matches!(std::env::var("AGENTBOX_MACOS_NATIVE").as_deref(), Ok("1"))
}

pub struct MacOsAgentPodPrototypeExecutor;

impl MacOsAgentPodPrototypeExecutor {
    pub fn execute(
        spec: &MinipodSpec,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        let plan = MacOsAgentPodExecutionPlan::from_minipod_spec(spec, command)?;
        if !plan.live_execution_enabled {
            return Err(RuntimeError::Unavailable(
                "macOS AgentPod VM runner invocation requires AGENTBOX_MACOS_NATIVE=1".into(),
            ));
        }
        Self::execute_plan(&plan, command)
    }

    #[cfg(target_os = "macos")]
    fn execute_plan(
        plan: &MacOsAgentPodExecutionPlan,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        if !plan.runnable_on_current_host() {
            return Err(RuntimeError::Unavailable(
                "macOS AgentPod VM runner invocation is not runnable on this host".into(),
            ));
        }

        let runner_binary = macos_agentpod_vm_runner_binary()?;
        let request_file = write_macos_agentpod_runner_request(plan, command)?;
        let output = std::process::Command::new(&runner_binary)
            .arg("--request")
            .arg(request_file.path())
            .output()
            .map_err(|err| {
                RuntimeError::ExecFailed(format!(
                    "failed to invoke macOS AgentPod VM runner {}: {err}",
                    runner_binary.display()
                ))
            })?;

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !output.status.success() {
            return Err(RuntimeError::Unavailable(format!(
                "macOS AgentPod VM runner contract invoked but VM execution is unavailable: {stderr}"
            )));
        }

        Err(RuntimeError::Unavailable(
            "macOS AgentPod VM runner returned success before VM execution support is implemented"
                .into(),
        ))
    }

    #[cfg(not(target_os = "macos"))]
    fn execute_plan(
        _plan: &MacOsAgentPodExecutionPlan,
        _command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        Err(RuntimeError::Unavailable(
            "macOS AgentPod VM runner invocation is only available on macOS".into(),
        ))
    }
}

#[cfg(target_os = "macos")]
struct MacOsAgentPodRunnerRequestFile {
    path: std::path::PathBuf,
}

#[cfg(target_os = "macos")]
impl MacOsAgentPodRunnerRequestFile {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacOsAgentPodRunnerRequestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(target_os = "macos")]
fn macos_agentpod_vm_runner_binary() -> Result<std::path::PathBuf, RuntimeError> {
    if let Some(path) = std::env::var_os("AGENTBOX_MACOS_VM_RUNNER") {
        let path = std::path::PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        return Err(RuntimeError::Unavailable(format!(
            "AGENTBOX_MACOS_VM_RUNNER does not exist: {}",
            path.display()
        )));
    }

    let current = std::env::current_exe().map_err(|err| {
        RuntimeError::ExecFailed(format!("failed to locate current executable: {err}"))
    })?;
    let sibling = current.with_file_name("agentbox-macos-vm-runner");
    if sibling.exists() {
        return Ok(sibling);
    }

    Err(RuntimeError::Unavailable(format!(
        "agentbox-macos-vm-runner binary not found next to {}; set AGENTBOX_MACOS_VM_RUNNER",
        current.display()
    )))
}

#[cfg(target_os = "macos")]
fn write_macos_agentpod_runner_request(
    plan: &MacOsAgentPodExecutionPlan,
    command: &ExecCommand,
) -> Result<MacOsAgentPodRunnerRequestFile, RuntimeError> {
    let request = MacOsAgentPodRunnerRequest::from_execution_plan(plan, command);
    let dir = std::env::temp_dir().join("agentbox-macos-vm-runner");
    std::fs::create_dir_all(&dir).map_err(|err| {
        RuntimeError::ExecFailed(format!(
            "failed to create macOS VM runner request dir {}: {err}",
            dir.display()
        ))
    })?;
    let path = dir.join(macos_agentpod_runner_request_filename(&plan.session_id));
    let file = std::fs::File::create(&path).map_err(|err| {
        RuntimeError::ExecFailed(format!(
            "failed to create macOS VM runner request {}: {err}",
            path.display()
        ))
    })?;
    serde_json::to_writer(file, &request).map_err(|err| {
        let _ = std::fs::remove_file(&path);
        RuntimeError::ExecFailed(format!(
            "failed to serialize macOS VM runner request {}: {err}",
            path.display()
        ))
    })?;
    Ok(MacOsAgentPodRunnerRequestFile { path })
}

#[cfg(any(test, target_os = "macos"))]
fn macos_agentpod_runner_request_filename(session_id: &str) -> String {
    static REQUEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let safe_session_id: String = session_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let safe_session_id = safe_session_id.trim_matches('_');
    let safe_session_id = if safe_session_id.is_empty() {
        "session"
    } else {
        safe_session_id
    };
    let count = REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{safe_session_id}-{}-{count}.json", ulid::Ulid::new())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacOsNetworkFlowDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsNetworkExtensionFlowRequest {
    pub schema_version: i64,
    pub session_id: String,
    pub flow_id: String,
    pub direction: MacOsNetworkFlowDirection,
    pub destination_host: String,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub process: MacOsEndpointSecuritySubject,
    pub observed_at: DateTime<Utc>,
}

impl MacOsNetworkExtensionFlowRequest {
    pub fn outbound(
        session_id: impl Into<String>,
        flow_id: impl Into<String>,
        destination_host: impl Into<String>,
        protocol: Option<String>,
        port: Option<u16>,
        process: MacOsEndpointSecuritySubject,
    ) -> Result<Self, RuntimeError> {
        let session_id = session_id.into();
        if session_id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS Network Extension flow session id cannot be empty".into(),
            ));
        }
        let flow_id = flow_id.into();
        if flow_id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS Network Extension flow id cannot be empty".into(),
            ));
        }
        let destination_host = destination_host.into();
        if destination_host.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS Network Extension destination host cannot be empty".into(),
            ));
        }

        Ok(Self {
            schema_version: 1,
            session_id,
            flow_id,
            direction: MacOsNetworkFlowDirection::Outbound,
            destination_host,
            protocol,
            port,
            process,
            observed_at: Utc::now(),
        })
    }

    pub fn to_host_bridge_request(&self) -> Result<HostBridgeRequest, RuntimeError> {
        if !matches!(self.direction, MacOsNetworkFlowDirection::Outbound) {
            return Err(RuntimeError::ManifestRejected(
                "macOS Network Extension bridge request only supports outbound flows".into(),
            ));
        }
        Ok(HostBridgeRequest::NetworkFirstContact(
            NetworkFirstContactRequest {
                destination: self.destination_host.clone(),
                protocol: self.protocol.clone(),
                port: self.port,
                classified_risk: Some(format!("macos-ne-flow:{}", self.flow_id)),
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacOsEndpointSecurityEventKind {
    Exec,
    Open,
    Create,
    Rename,
    Unlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacOsFileAccess {
    Read,
    Write,
    Execute,
    Create,
    Delete,
    Rename,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsEndpointSecuritySubject {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub executable_path: String,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
}

impl MacOsEndpointSecuritySubject {
    pub fn unsigned(pid: u32, executable_path: impl Into<String>) -> Self {
        Self {
            pid,
            ppid: None,
            executable_path: executable_path.into(),
            signing_id: None,
            team_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsEndpointSecurityAuthorizationRequest {
    pub schema_version: i64,
    pub session_id: String,
    pub event_id: String,
    pub event_kind: MacOsEndpointSecurityEventKind,
    pub subject: MacOsEndpointSecuritySubject,
    pub command_argv: Vec<String>,
    pub target_path: Option<String>,
    pub target_new_path: Option<String>,
    pub requested_access: Vec<MacOsFileAccess>,
    pub observed_at: DateTime<Utc>,
}

impl MacOsEndpointSecurityAuthorizationRequest {
    pub fn exec(
        session_id: impl Into<String>,
        event_id: impl Into<String>,
        subject: MacOsEndpointSecuritySubject,
        command_argv: Vec<String>,
    ) -> Result<Self, RuntimeError> {
        if command_argv.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS Endpoint Security exec request cannot have empty argv".into(),
            ));
        }
        let target_path = command_argv.first().cloned();
        Self::new(
            session_id,
            event_id,
            MacOsEndpointSecurityEventKind::Exec,
            subject,
            command_argv,
            target_path,
            None,
            vec![MacOsFileAccess::Execute],
        )
    }

    pub fn file(
        session_id: impl Into<String>,
        event_id: impl Into<String>,
        event_kind: MacOsEndpointSecurityEventKind,
        subject: MacOsEndpointSecuritySubject,
        target_path: impl Into<String>,
        requested_access: Vec<MacOsFileAccess>,
    ) -> Result<Self, RuntimeError> {
        Self::new(
            session_id,
            event_id,
            event_kind,
            subject,
            vec![],
            Some(target_path.into()),
            None,
            requested_access,
        )
    }

    pub fn to_host_bridge_request(&self) -> Result<HostBridgeRequest, RuntimeError> {
        match self.event_kind {
            MacOsEndpointSecurityEventKind::Exec => {
                if self.command_argv.is_empty() {
                    return Err(RuntimeError::ManifestRejected(
                        "macOS Endpoint Security exec bridge request cannot have empty argv".into(),
                    ));
                }
                Ok(HostBridgeRequest::CommandMediation(
                    CommandMediationRequest {
                        argv: self.command_argv.clone(),
                        cwd: "/".into(),
                        env_keys: vec![],
                    },
                ))
            }
            MacOsEndpointSecurityEventKind::Open
            | MacOsEndpointSecurityEventKind::Create
            | MacOsEndpointSecurityEventKind::Rename
            | MacOsEndpointSecurityEventKind::Unlink => {
                let Some(target_path) = self.target_path.as_ref() else {
                    return Err(RuntimeError::ManifestRejected(
                        "macOS Endpoint Security file bridge request target path is missing".into(),
                    ));
                };
                Ok(HostBridgeRequest::FileGrant(FileGrantRequest {
                    host_path: PathBuf::from(target_path),
                    guest_path: target_path.clone(),
                    access: macos_access_to_file_access_mode(&self.requested_access),
                    reason: format!(
                        "macOS Endpoint Security {:?} event {}",
                        self.event_kind, self.event_id
                    ),
                }))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        session_id: impl Into<String>,
        event_id: impl Into<String>,
        event_kind: MacOsEndpointSecurityEventKind,
        subject: MacOsEndpointSecuritySubject,
        command_argv: Vec<String>,
        target_path: Option<String>,
        target_new_path: Option<String>,
        requested_access: Vec<MacOsFileAccess>,
    ) -> Result<Self, RuntimeError> {
        let session_id = session_id.into();
        if session_id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS Endpoint Security request session id cannot be empty".into(),
            ));
        }
        let event_id = event_id.into();
        if event_id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "macOS Endpoint Security request event id cannot be empty".into(),
            ));
        }
        if !matches!(event_kind, MacOsEndpointSecurityEventKind::Exec)
            && target_path.as_deref().unwrap_or_default().trim().is_empty()
        {
            return Err(RuntimeError::ManifestRejected(
                "macOS Endpoint Security file request target path cannot be empty".into(),
            ));
        }
        if !matches!(event_kind, MacOsEndpointSecurityEventKind::Exec)
            && requested_access.is_empty()
        {
            return Err(RuntimeError::ManifestRejected(
                "macOS Endpoint Security file request access cannot be empty".into(),
            ));
        }

        Ok(Self {
            schema_version: 1,
            session_id,
            event_id,
            event_kind,
            subject,
            command_argv,
            target_path,
            target_new_path,
            requested_access,
            observed_at: Utc::now(),
        })
    }
}

fn macos_access_to_file_access_mode(access: &[MacOsFileAccess]) -> FileAccessMode {
    let reads = access
        .iter()
        .any(|item| matches!(item, MacOsFileAccess::Read | MacOsFileAccess::Execute));
    let writes = access.iter().any(|item| {
        matches!(
            item,
            MacOsFileAccess::Write
                | MacOsFileAccess::Create
                | MacOsFileAccess::Delete
                | MacOsFileAccess::Rename
        )
    });

    match (reads, writes) {
        (true, true) => FileAccessMode::ReadWrite,
        (true, false) => FileAccessMode::Read,
        (false, true) | (false, false) => FileAccessMode::Write,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsEndpointSecurityAuthorizationDecision {
    pub schema_version: i64,
    pub request_event_id: String,
    pub decision: HostBridgeDecision,
    pub reason: String,
    pub evidence_ref: Option<String>,
    pub decided_at: DateTime<Utc>,
}

impl MacOsEndpointSecurityAuthorizationDecision {
    pub fn new(
        request: &MacOsEndpointSecurityAuthorizationRequest,
        decision: HostBridgeDecision,
        reason: impl Into<String>,
        evidence_ref: Option<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            request_event_id: request.event_id.clone(),
            decision,
            reason: reason.into(),
            evidence_ref,
            decided_at: Utc::now(),
        }
    }
}

fn cpu_shares_to_vcpu(cpu_shares: u32) -> u32 {
    let vcpus = (cpu_shares.max(1) as u64).div_ceil(2048);
    vcpus.clamp(1, 8) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::{CredentialGrant, CredentialGrantKind, MountRule, ResourcePolicy};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn command(argv: &[&str]) -> ExecCommand {
        ExecCommand {
            argv: argv.iter().map(|arg| arg.to_string()).collect(),
            working_dir: None,
            env: HashMap::new(),
            timeout_seconds: None,
        }
    }

    #[test]
    fn virtualization_plan_maps_agentpod_manifest_to_vm_cell() {
        let mut spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        spec.resources = ResourcePolicy {
            memory_bytes: 2_147_483_648,
            cpu_shares: 4096,
            timeout_seconds: Some(30),
        };
        spec.filesystem.mounts.push(MountRule {
            host_path: PathBuf::from("/tmp/agentbox-ro"),
            guest_path: "/ro".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::ReadOnlyHost,
        });
        spec.credentials.grants.push(CredentialGrant {
            name: "AWS_PROFILE".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "AWS_PROFILE".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });
        spec.credentials.grants.push(CredentialGrant {
            name: "deploy_key".into(),
            kind: CredentialGrantKind::FileMount,
            target: "/tmp/deploy-key".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });

        let plan = MacOsVirtualizationCellPlan::from_minipod_spec(&spec).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.bundle_id, format!("dev.agentbox.agentpod.{}", spec.id));
        assert_eq!(plan.guest_os, "linux");
        assert_eq!(plan.cpu_count, 2);
        assert_eq!(plan.memory_bytes, 2_147_483_648);
        assert_eq!(plan.workspace_guest_path, "/workspace");
        assert_eq!(plan.host_bridge.transport, HostBridgeTransportKind::Vsock);
        assert_eq!(
            plan.cell_config.workspace_mount.host_path,
            "/tmp/agentbox-work"
        );
        assert_eq!(
            plan.cell_config.bridge_socket_guest_path,
            plan.host_bridge.guest_socket_path
        );
        assert_eq!(
            plan.cell_config.evidence_spool_guest_path,
            "/var/lib/agentbox/evidence"
        );
        let safe_id = macos_agentpod_cell_safe_id(&spec.id);
        assert!(plan
            .storage_layout
            .cell_root_host_path
            .ends_with(&format!(".agentbox/agentpods/macos/{safe_id}")));
        assert!(plan
            .storage_layout
            .config_json_host_path
            .ends_with(&format!(
                ".agentbox/agentpods/macos/{safe_id}/config/cell.json"
            )));
        assert!(plan.storage_layout.disk_image_host_path.ends_with(&format!(
            ".agentbox/agentpods/macos/{safe_id}/disk/rootfs.img"
        )));
        assert_eq!(
            plan.storage_layout.workspace_mount_host_path,
            "/tmp/agentbox-work"
        );
        assert!(plan
            .storage_layout
            .credential_channel_host_path
            .ends_with(&format!(".agentbox/agentpods/macos/{safe_id}/credentials")));
        assert!(plan
            .storage_layout
            .evidence_spool_host_path
            .ends_with(&format!(".agentbox/agentpods/macos/{safe_id}/evidence")));
        assert!(
            plan.storage_layout
                .cleanup_policy
                .remove_runner_request_after_invocation
        );
        assert!(
            plan.storage_layout
                .cleanup_policy
                .seal_evidence_before_cleanup
        );
        assert_eq!(plan.cell_config.credential_channels.len(), 2);
        assert!(plan.cell_config.credential_channels.iter().any(|channel| {
            channel.name == "AWS_PROFILE"
                && channel.delivery == "host-bridge-env-injection"
                && channel.guest_path.is_none()
        }));
        assert!(plan.cell_config.credential_channels.iter().any(|channel| {
            channel.name == "deploy_key"
                && channel.delivery == "read-only-shared-directory"
                && channel.guest_path.as_deref() == Some("/run/agentbox/credentials/deploy_key")
        }));
        assert!(plan.requires_apple_virtualization);
        assert_eq!(plan.shared_directories.len(), 2);
        assert!(!plan.shared_directories[0].read_only);
        assert!(plan.shared_directories[1].read_only);
    }

    #[test]
    fn macos_vm_cell_storage_safe_id_normalizes_session_paths() {
        let safe = macos_agentpod_cell_safe_id("../session/with spaces");

        assert_eq!(safe, "session_with_spaces");
        assert!(!safe.contains('/'));
        assert!(!safe.contains(' '));
    }

    #[test]
    fn macos_execution_plan_composes_vm_host_enforcement_and_network() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let plan =
            MacOsAgentPodExecutionPlan::from_minipod_spec(&spec, &command(&["/bin/true"])).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.provider, "agentpod-macos");
        assert_eq!(plan.session_id, spec.id);
        assert_eq!(plan.command_argv, vec!["/bin/true"]);
        assert_eq!(plan.live_env_var, "AGENTBOX_MACOS_NATIVE");
        assert!(plan.requires_macos);
        assert!(plan.prerequisite_checks.iter().any(|check| {
            check.name == "vm-runner-binary"
                && check.required
                && check.status == "planned"
                && check.probe.contains("agentbox-macos-vm-runner")
        }));
        assert_eq!(
            plan.runner_phases
                .iter()
                .map(|phase| (phase.name.as_str(), phase.status.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("compile-vm-cell-config", "descriptor"),
                ("start-virtualization-vm", "planned"),
                ("attach-host-bridge", "planned"),
                ("attach-endpoint-security", "planned"),
                ("attach-network-extension", "planned"),
                ("exec-command", "planned"),
            ]
        );
        assert!(plan
            .required_entitlements
            .contains(&"com.apple.security.virtualization".into()));
        assert!(plan.endpoint_security.requires_system_extension);
        assert!(plan.network_extension.requires_network_extension);
        assert_eq!(
            plan.evidence_observer.enforcement,
            MacOsEvidenceEnforcementMode::ObservedOnly
        );
        assert!(plan
            .evidence_observer
            .event_schema
            .iter()
            .any(|event| event.event_type == "macos.network.flow"));
        assert!(plan.security_claim.contains("execution is not wired"));
    }

    #[test]
    fn macos_credential_channel_contract_carries_scope_expiry_recipient_and_audit_metadata() {
        let mut spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        let expires_at = DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        spec.credentials.grants.push(CredentialGrant {
            name: "OPENAI_API_KEY".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "OPENAI_API_KEY".into(),
            one_time: true,
            requires_approval: true,
            expires_at: Some(expires_at),
        });

        let plan = MacOsVirtualizationCellPlan::from_minipod_spec(&spec).unwrap();
        let channel = plan
            .cell_config
            .credential_channels
            .iter()
            .find(|channel| channel.name == "OPENAI_API_KEY")
            .unwrap();

        assert_eq!(channel.scope.session_id, spec.id);
        assert_eq!(channel.scope.grant_name, "OPENAI_API_KEY");
        assert_eq!(channel.scope.kind, CredentialGrantKind::EnvVar);
        assert_eq!(channel.scope.target_ref, "OPENAI_API_KEY");
        assert_eq!(channel.expires_at, Some(expires_at));
        assert_eq!(channel.recipient.session_id, spec.id);
        assert_eq!(
            channel.recipient.vm_bundle_id,
            format!("dev.agentbox.agentpod.{}", spec.id)
        );
        assert_eq!(
            channel.recipient.cell_safe_id,
            macos_agentpod_cell_safe_id(&spec.id)
        );
        assert_eq!(channel.recipient.guest_workspace_path, "/workspace");
        assert_eq!(
            channel.audit.grant_event_type,
            "agentbox.credential.grant.requested"
        );
        assert_eq!(
            channel.audit.evidence_stream,
            format!("agentpod-macos/{}/credentials", spec.id)
        );
        assert!(channel.audit.redacted);
        assert!(channel.audit.secret_values_forbidden);
        let encoded = serde_json::to_string(channel).unwrap();
        assert!(!encoded.contains("sk-live-secret-value"));
    }

    #[test]
    fn macos_provider_execution_contract_remains_unavailable_without_native_runner() {
        let previous_gate = std::env::var_os("AGENTBOX_MACOS_NATIVE");
        std::env::remove_var("AGENTBOX_MACOS_NATIVE");
        let spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");

        let err =
            MacOsAgentPodPrototypeExecutor::execute(&spec, &command(&["/bin/true"])).unwrap_err();

        match previous_gate {
            Some(value) => std::env::set_var("AGENTBOX_MACOS_NATIVE", value),
            None => std::env::remove_var("AGENTBOX_MACOS_NATIVE"),
        }

        assert!(err.to_string().contains("requires AGENTBOX_MACOS_NATIVE=1"));
    }

    #[test]
    fn macos_runner_request_is_derived_from_execution_plan() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let exec = command(&["/bin/true"]);
        let plan = MacOsAgentPodExecutionPlan::from_minipod_spec(&spec, &exec).unwrap();

        let request = MacOsAgentPodRunnerRequest::from_execution_plan(&plan, &exec);

        assert_eq!(request.schema_version, 1);
        assert_eq!(request.session_id, spec.id);
        assert_eq!(request.command_argv, vec!["/bin/true"]);
        assert_eq!(request.working_dir.as_deref(), Some("/workspace"));
        assert_eq!(request.boot_request.session_id, request.session_id);
        assert_eq!(request.boot_request.command_argv, request.command_argv);
        assert_eq!(
            request.boot_request.claim_boundary,
            "boot request contract only; Apple Virtualization lifecycle is not wired"
        );
        request.boot_request.validate().unwrap();
        assert_eq!(request.virtualization, plan.virtualization);
        assert_eq!(request.endpoint_security, plan.endpoint_security);
        assert_eq!(request.network_extension, plan.network_extension);
        assert_eq!(request.evidence_observer, plan.evidence_observer);
        assert_eq!(request.prerequisite_checks, plan.prerequisite_checks);
        assert_eq!(request.runner_phases, plan.runner_phases);
        assert_eq!(request.required_entitlements, plan.required_entitlements);
    }

    #[test]
    fn macos_vm_cell_boot_request_preserves_honest_boot_boundary() {
        let spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        let exec = ExecCommand {
            argv: vec!["/usr/bin/python3".into(), "-c".into(), "print(1)".into()],
            working_dir: Some("/workspace/project".into()),
            env: HashMap::new(),
            timeout_seconds: Some(30),
        };
        let plan = MacOsAgentPodExecutionPlan::from_minipod_spec(&spec, &exec).unwrap();

        let boot_request = MacOsVmCellBootRequest::from_execution_plan(&plan, &exec);

        assert_eq!(boot_request.schema_version, 1);
        assert_eq!(boot_request.session_id, spec.id);
        assert_eq!(boot_request.bundle_id, plan.virtualization.bundle_id);
        assert_eq!(boot_request.guest_os, "linux");
        assert_eq!(boot_request.command_argv, exec.argv);
        assert_eq!(boot_request.working_dir, "/workspace/project");
        assert_eq!(
            boot_request.workspace_mount.guest_path,
            spec.filesystem.workspace_guest_path
        );
        assert_eq!(
            boot_request.bridge_socket_guest_path,
            "/run/agentbox/bridge.sock"
        );
        assert!(boot_request
            .required_entitlements
            .contains(&"com.apple.security.virtualization".into()));
        assert!(boot_request.claim_boundary.contains("not wired"));
        boot_request.validate().unwrap();
    }

    #[test]
    fn macos_vm_cell_boot_request_rejects_fake_execution_claims() {
        let spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        let exec = command(&["/bin/true"]);
        let plan = MacOsAgentPodExecutionPlan::from_minipod_spec(&spec, &exec).unwrap();
        let mut boot_request = MacOsVmCellBootRequest::from_execution_plan(&plan, &exec);
        boot_request.claim_boundary = "booted and enforced".into();

        let err = boot_request.validate().unwrap_err();

        assert!(err.to_string().contains("claim boundary"));
    }

    #[test]
    fn macos_vm_cell_boot_request_fixture_remains_valid() {
        let fixture = include_str!("../../../fixtures/macos-vm-cell-boot-request.json");
        let request: MacOsVmCellBootRequest = serde_json::from_str(fixture).unwrap();

        request.validate().unwrap();

        assert_eq!(request.session_id, "fixture-session");
        assert_eq!(request.bundle_id, "dev.agentbox.agentpod.fixture-session");
        assert_eq!(request.command_argv[0], "/usr/bin/python3");
        assert_eq!(request.workspace_mount.guest_path, "/workspace");
        assert_eq!(request.shared_directories.len(), 1);
        assert!(
            request
                .storage_layout
                .cleanup_policy
                .seal_evidence_before_cleanup
        );
        assert!(request.claim_boundary.contains("not wired"));
    }

    #[test]
    fn macos_runner_request_filename_is_path_safe_and_unique() {
        let first = macos_agentpod_runner_request_filename("../session/with spaces");
        let second = macos_agentpod_runner_request_filename("../session/with spaces");

        assert!(first.ends_with(".json"));
        assert!(first.starts_with("session_with_spaces-"));
        assert!(!first.contains('/'));
        assert!(!first.contains(' '));
        assert_ne!(first, second);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vm_runner_invocation_writes_request_and_preserves_unavailable_claim() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "agentbox-macos-vm-runner-test-{}-{}",
            std::process::id(),
            ulid::Ulid::new()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let runner = dir.join("fake-macos-vm-runner");
        let marker = dir.join("runner-argv.txt");
        let request_marker = dir.join("runner-request-path.txt");
        let mut file = std::fs::File::create(&runner).unwrap();
        writeln!(
            file,
            "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s\\n' \"$2\" > '{}'\necho fake vm unavailable >&2\nexit 125",
            marker.display(),
            request_marker.display()
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&runner).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&runner, permissions).unwrap();

        let spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        let exec = command(&["/bin/true"]);
        let previous_gate = std::env::var_os("AGENTBOX_MACOS_NATIVE");
        let previous_runner = std::env::var_os("AGENTBOX_MACOS_VM_RUNNER");
        std::env::set_var("AGENTBOX_MACOS_NATIVE", "1");
        std::env::set_var("AGENTBOX_MACOS_VM_RUNNER", &runner);

        let err = MacOsAgentPodPrototypeExecutor::execute(&spec, &exec).unwrap_err();

        match previous_gate {
            Some(value) => std::env::set_var("AGENTBOX_MACOS_NATIVE", value),
            None => std::env::remove_var("AGENTBOX_MACOS_NATIVE"),
        }
        match previous_runner {
            Some(value) => std::env::set_var("AGENTBOX_MACOS_VM_RUNNER", value),
            None => std::env::remove_var("AGENTBOX_MACOS_VM_RUNNER"),
        }

        assert!(err.to_string().contains("contract invoked"));
        assert!(err.to_string().contains("fake vm unavailable"));
        let argv = std::fs::read_to_string(marker).unwrap();
        assert!(argv.contains("--request"));
        let request_path = std::fs::read_to_string(request_marker).unwrap();
        let request_path = std::path::Path::new(request_path.trim());
        assert!(!request_path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn macos_evidence_observer_plan_carries_session_correlation_and_event_schema() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.labels
            .insert("policy.bundle".into(), "research-default".into());

        let plan = MacOsEvidenceObserverPlan::from_minipod_spec(&spec);

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.session_id, spec.id);
        assert_eq!(plan.correlation.preferred_key, "vm_bundle_id");
        assert_eq!(
            plan.correlation.vm_bundle_id,
            format!("dev.agentbox.agentpod.{}", spec.id)
        );
        assert!(plan.correlation.process_id_fallback);
        assert!(plan
            .correlation
            .manifest_label_keys
            .contains(&"policy.bundle".to_string()));
        assert_eq!(plan.enforcement, MacOsEvidenceEnforcementMode::ObservedOnly);
        assert!(plan
            .event_schema
            .iter()
            .any(|event| event.event_type == "macos.process.exec"));
        assert!(plan
            .event_schema
            .iter()
            .any(|event| event.source == "NetworkExtension:outbound-flow"));
        assert!(plan.requires_endpoint_security);
        assert!(plan.requires_network_extension);
        assert!(plan.evidence_claim.contains("not enforcement proof"));
    }

    #[test]
    fn macos_execution_plan_rejects_empty_commands() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");

        let err = MacOsAgentPodExecutionPlan::from_minipod_spec(&spec, &command(&[])).unwrap_err();

        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn macos_execution_plan_is_not_live_without_explicit_env_gate() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let plan =
            MacOsAgentPodExecutionPlan::from_minipod_spec(&spec, &command(&["/bin/true"])).unwrap();

        if std::env::var("AGENTBOX_MACOS_NATIVE").is_err() {
            assert!(!plan.live_execution_enabled);
            assert!(!plan.runnable_on_current_host());
        }
    }

    #[test]
    fn endpoint_security_exec_request_models_policy_authorization() {
        let subject = MacOsEndpointSecuritySubject {
            pid: 42,
            ppid: Some(1),
            executable_path: "/usr/bin/git".into(),
            signing_id: Some("com.apple.git".into()),
            team_id: Some("APPLE".into()),
        };

        let request = MacOsEndpointSecurityAuthorizationRequest::exec(
            "session-1",
            "event-1",
            subject,
            vec!["/usr/bin/git".into(), "push".into()],
        )
        .unwrap();
        let decision = MacOsEndpointSecurityAuthorizationDecision::new(
            &request,
            HostBridgeDecision::Approve,
            "git push requires operator approval",
            Some("audit:1".into()),
        );

        assert_eq!(request.schema_version, 1);
        assert_eq!(request.event_kind, MacOsEndpointSecurityEventKind::Exec);
        assert_eq!(request.target_path.as_deref(), Some("/usr/bin/git"));
        assert_eq!(request.requested_access, vec![MacOsFileAccess::Execute]);
        assert_eq!(decision.request_event_id, "event-1");
        assert_eq!(decision.decision, HostBridgeDecision::Approve);
        assert_eq!(decision.evidence_ref.as_deref(), Some("audit:1"));
    }

    #[test]
    fn endpoint_security_file_request_models_protected_path_access() {
        let request = MacOsEndpointSecurityAuthorizationRequest::file(
            "session-1",
            "event-2",
            MacOsEndpointSecurityEventKind::Open,
            MacOsEndpointSecuritySubject::unsigned(43, "/usr/bin/python3"),
            "/Users/efe/.ssh/id_ed25519",
            vec![MacOsFileAccess::Read],
        )
        .unwrap();

        assert_eq!(request.schema_version, 1);
        assert_eq!(request.command_argv, Vec::<String>::new());
        assert_eq!(
            request.target_path.as_deref(),
            Some("/Users/efe/.ssh/id_ed25519")
        );
        assert_eq!(request.requested_access, vec![MacOsFileAccess::Read]);
    }

    #[test]
    fn endpoint_security_exec_request_maps_to_host_bridge_command() {
        let request = MacOsEndpointSecurityAuthorizationRequest::exec(
            "session-1",
            "event-bridge-1",
            MacOsEndpointSecuritySubject::unsigned(45, "/usr/bin/git"),
            vec!["/usr/bin/git".into(), "status".into()],
        )
        .unwrap();

        let bridge = request.to_host_bridge_request().unwrap();

        match bridge {
            HostBridgeRequest::CommandMediation(command) => {
                assert_eq!(command.argv, vec!["/usr/bin/git", "status"]);
                assert_eq!(command.cwd, "/");
                assert!(command.env_keys.is_empty());
            }
            other => panic!("unexpected bridge request: {other:?}"),
        }
    }

    #[test]
    fn endpoint_security_file_request_maps_to_host_bridge_file_grant() {
        let request = MacOsEndpointSecurityAuthorizationRequest::file(
            "session-1",
            "event-bridge-2",
            MacOsEndpointSecurityEventKind::Create,
            MacOsEndpointSecuritySubject::unsigned(46, "/usr/bin/python3"),
            "/Users/efe/project/output.txt",
            vec![MacOsFileAccess::Create, MacOsFileAccess::Write],
        )
        .unwrap();

        let bridge = request.to_host_bridge_request().unwrap();

        match bridge {
            HostBridgeRequest::FileGrant(file) => {
                assert_eq!(
                    file.host_path,
                    PathBuf::from("/Users/efe/project/output.txt")
                );
                assert_eq!(file.guest_path, "/Users/efe/project/output.txt");
                assert_eq!(file.access, FileAccessMode::Write);
                assert!(file.reason.contains("event-bridge-2"));
            }
            other => panic!("unexpected bridge request: {other:?}"),
        }
    }

    #[test]
    fn endpoint_security_requests_reject_empty_boundaries() {
        let subject = MacOsEndpointSecuritySubject::unsigned(44, "/usr/bin/python3");

        let exec_err = MacOsEndpointSecurityAuthorizationRequest::exec(
            "session-1",
            "event-3",
            subject.clone(),
            vec![],
        )
        .unwrap_err();
        let file_err = MacOsEndpointSecurityAuthorizationRequest::file(
            "session-1",
            "event-4",
            MacOsEndpointSecurityEventKind::Open,
            subject,
            "",
            vec![MacOsFileAccess::Read],
        )
        .unwrap_err();

        assert!(exec_err.to_string().contains("empty argv"));
        assert!(file_err.to_string().contains("target path"));
    }

    #[test]
    fn network_extension_flow_maps_to_host_bridge_first_contact() {
        let flow = MacOsNetworkExtensionFlowRequest::outbound(
            "session-1",
            "flow-1",
            "api.openai.com",
            Some("https".into()),
            Some(443),
            MacOsEndpointSecuritySubject::unsigned(47, "/usr/bin/curl"),
        )
        .unwrap();

        let bridge = flow.to_host_bridge_request().unwrap();

        match bridge {
            HostBridgeRequest::NetworkFirstContact(network) => {
                assert_eq!(network.destination, "api.openai.com");
                assert_eq!(network.protocol.as_deref(), Some("https"));
                assert_eq!(network.port, Some(443));
                assert_eq!(
                    network.classified_risk.as_deref(),
                    Some("macos-ne-flow:flow-1")
                );
            }
            other => panic!("unexpected bridge request: {other:?}"),
        }
    }

    #[test]
    fn network_extension_flow_rejects_empty_destination() {
        let err = MacOsNetworkExtensionFlowRequest::outbound(
            "session-1",
            "flow-2",
            "",
            Some("https".into()),
            Some(443),
            MacOsEndpointSecuritySubject::unsigned(48, "/usr/bin/curl"),
        )
        .unwrap_err();

        assert!(err.to_string().contains("destination host"));
    }
}
