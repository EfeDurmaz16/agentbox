use serde::{Deserialize, Serialize};

use agentbox_agentpod::{
    skipped_primitives_for_provider, AgentPodEnforcementStatus, PROVIDER_WINDOWS,
    RUNNER_PHASE_STATUS_DESCRIPTOR, RUNNER_PHASE_STATUS_PLANNED,
};

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::{
    AgentPodNativeReceiptSummary, AgentPodRunnerPhaseReceipt, CredentialGrantKind, ExecCommand,
    MinipodSpec, MountKind, MountMode, NetworkMode, WorkspaceOverlayMode, WorkspaceWritePolicy,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsJobObjectPlan {
    pub schema_version: i64,
    pub job_name: String,
    #[serde(default)]
    pub live_smoke: WindowsJobObjectLiveSmokePlan,
    pub kill_on_close: bool,
    pub memory_limit_bytes: u64,
    pub cpu_rate_weight: u32,
    pub process_limit: Option<u32>,
    pub timeout_seconds: Option<u64>,
    pub timeout_action: String,
    pub resource_claim: String,
    pub requires_windows: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsJobObjectLiveSmokePlan {
    pub schema_version: i64,
    pub env_var: String,
    pub enabled: bool,
    pub lifecycle_steps: Vec<String>,
    pub lifecycle_claim: String,
}

impl Default for WindowsJobObjectLiveSmokePlan {
    fn default() -> Self {
        Self::descriptor()
    }
}

impl WindowsJobObjectPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Result<Self, RuntimeError> {
        if spec.id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "Windows Job Object session id cannot be empty".into(),
            ));
        }
        if spec.resources.memory_bytes == 0 {
            return Err(RuntimeError::ManifestRejected(
                "Windows Job Object memory limit cannot be zero".into(),
            ));
        }

        Ok(Self {
            schema_version: 1,
            job_name: format!("agentbox-{}", spec.id),
            live_smoke: WindowsJobObjectLiveSmokePlan::descriptor(),
            kill_on_close: true,
            memory_limit_bytes: spec.resources.memory_bytes,
            cpu_rate_weight: cpu_shares_to_job_weight(spec.resources.cpu_shares),
            process_limit: Some(default_process_limit_for_risk(&spec.risk)),
            timeout_seconds: spec.resources.timeout_seconds,
            timeout_action: "terminate-job-and-seal-timeout-evidence".into(),
            resource_claim:
                "planned Job Object resource contract; live Win32 apply proof is not wired".into(),
            requires_windows: true,
        })
    }

    pub fn limit_writes(&self) -> Vec<WindowsJobObjectLimit> {
        let mut limits = vec![
            WindowsJobObjectLimit {
                name: "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE".into(),
                value: self.kill_on_close.to_string(),
            },
            WindowsJobObjectLimit {
                name: "JOB_OBJECT_LIMIT_PROCESS_MEMORY".into(),
                value: self.memory_limit_bytes.to_string(),
            },
            WindowsJobObjectLimit {
                name: "JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED".into(),
                value: self.cpu_rate_weight.to_string(),
            },
        ];

        if let Some(process_limit) = self.process_limit {
            limits.push(WindowsJobObjectLimit {
                name: "JOB_OBJECT_LIMIT_ACTIVE_PROCESS".into(),
                value: process_limit.to_string(),
            });
        }
        if let Some(timeout_seconds) = self.timeout_seconds {
            limits.push(WindowsJobObjectLimit {
                name: "AGENTBOX_WALL_CLOCK_TIMEOUT_SECONDS".into(),
                value: timeout_seconds.to_string(),
            });
        }

        limits
    }
}

impl WindowsJobObjectLiveSmokePlan {
    fn descriptor() -> Self {
        Self {
            schema_version: 1,
            env_var: "AGENTBOX_WINDOWS_JOB_OBJECT".into(),
            enabled: windows_job_object_live_smoke_enabled(),
            lifecycle_steps: vec![
                "CreateJobObjectW".into(),
                "CloseHandle".into(),
                "no process assignment or resource enforcement proof".into(),
            ],
            lifecycle_claim:
                "gated Job Object create/close smoke skeleton only; process assignment and limit enforcement are not proven"
                    .into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsJobObjectLimit {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAppContainerPlan {
    pub schema_version: i64,
    pub package_family_name: String,
    pub workspace_host_path: String,
    pub workspace_guest_path: String,
    pub workspace_mode: String,
    pub workspace_write_policy: WorkspaceWritePolicy,
    pub workspace_boundary: WindowsWorkspaceBoundaryPlan,
    pub mounts: Vec<WindowsMountPlan>,
    pub protected_paths: Vec<String>,
    pub protected_path_rules: Vec<WindowsProtectedPathPlan>,
    pub deny_home_by_default: bool,
    pub requires_profile_creation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsWorkspaceBoundaryPlan {
    pub access_model: String,
    pub overlay_mode: WorkspaceOverlayMode,
    pub upper_host_path: Option<String>,
    pub work_host_path: Option<String>,
    pub guest_path: String,
    pub review_required: bool,
    pub commit_required: bool,
    pub discard_on_destroy: bool,
    pub enforcement_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsMountPlan {
    pub host_path: String,
    pub guest_path: String,
    pub read_only: bool,
    pub kind: MountKind,
    pub acl_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProtectedPathPlan {
    pub path: String,
    pub class: crate::runtime::types::SensitivePathClass,
    pub reason: String,
    pub default_access: String,
}

impl WindowsAppContainerPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Result<Self, RuntimeError> {
        if spec.filesystem.workspace_host_path.as_os_str().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "Windows AppContainer workspace host path cannot be empty".into(),
            ));
        }

        Ok(Self {
            schema_version: 1,
            package_family_name: format!("Agentbox.AgentPod.{}", spec.id),
            workspace_host_path: spec.filesystem.workspace_host_path.display().to_string(),
            workspace_guest_path: spec.filesystem.workspace_guest_path.clone(),
            workspace_mode: spec.workspace_mode.label().to_string(),
            workspace_write_policy: spec.filesystem.workspace_write_policy.clone(),
            workspace_boundary: WindowsWorkspaceBoundaryPlan {
                access_model: if matches!(
                    spec.filesystem.workspace_write_policy,
                    WorkspaceWritePolicy::WritableOverlay
                ) {
                    "workspace-overlay-review".into()
                } else {
                    "direct-workspace-acl".into()
                },
                overlay_mode: spec.filesystem.workspace_overlay.mode.clone(),
                upper_host_path: spec
                    .filesystem
                    .workspace_overlay
                    .upper_host_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                work_host_path: spec
                    .filesystem
                    .workspace_overlay
                    .work_host_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                guest_path: spec.filesystem.workspace_overlay.guest_path.clone(),
                review_required: matches!(
                    spec.workspace_mode,
                    crate::runtime::types::AgentPodWorkspaceMode::OverlayReview
                        | crate::runtime::types::AgentPodWorkspaceMode::CommitGated
                ),
                commit_required: matches!(
                    spec.workspace_mode,
                    crate::runtime::types::AgentPodWorkspaceMode::CommitGated
                ),
                discard_on_destroy: matches!(
                    spec.workspace_mode,
                    crate::runtime::types::AgentPodWorkspaceMode::Ephemeral
                ),
                enforcement_claim:
                    "planned AppContainer/ACL workspace boundary; live ACL proof is not wired"
                        .into(),
            },
            mounts: spec
                .filesystem
                .mounts
                .iter()
                .map(|mount| WindowsMountPlan {
                    host_path: mount.host_path.display().to_string(),
                    guest_path: mount.guest_path.clone(),
                    read_only: matches!(mount.mode, MountMode::ReadOnly),
                    kind: mount.kind.clone(),
                    acl_claim: if matches!(mount.mode, MountMode::ReadOnly) {
                        "planned read-only ACL or mapped-folder permission".into()
                    } else {
                        "planned explicit read-write capability".into()
                    },
                })
                .collect(),
            protected_paths: spec
                .filesystem
                .protected_paths
                .iter()
                .map(|path| path.path.display().to_string())
                .collect(),
            protected_path_rules: spec
                .filesystem
                .protected_paths
                .iter()
                .map(|path| WindowsProtectedPathPlan {
                    path: path.path.display().to_string(),
                    class: path.class.clone(),
                    reason: path.reason.clone(),
                    default_access: "deny-without-explicit-grant".into(),
                })
                .collect(),
            deny_home_by_default: spec.filesystem.deny_home_by_default,
            requires_profile_creation: true,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsWfpBoundaryPlan {
    pub schema_version: i64,
    pub mode: NetworkMode,
    pub default_policy: WindowsWfpDefaultPolicy,
    pub allowed_domains: Vec<String>,
    pub denied_domains: Vec<String>,
    pub allow_localhost: bool,
    pub planned_rules: Vec<WindowsWfpRulePlan>,
    pub evidence_events: Vec<String>,
    pub domain_rules_require_resolver: bool,
    pub enforcement_claim: String,
    pub requires_wfp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsWfpDefaultPolicy {
    Block,
    PermitWithGuardrails,
    RequireApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsWfpRulePlan {
    pub action: WindowsWfpRuleAction,
    pub layer: String,
    pub selector: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsWfpRuleAction {
    Permit,
    Block,
    ApprovalRequired,
    Observe,
}

impl WindowsWfpBoundaryPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
        let mut planned_rules = Vec::new();
        if spec.network.allow_localhost {
            planned_rules.push(WindowsWfpRulePlan {
                action: WindowsWfpRuleAction::Permit,
                layer: "ALE_AUTH_CONNECT".into(),
                selector: "loopback:127.0.0.0/8,::1".into(),
                reason: "manifest allows loopback service access".into(),
            });
        } else {
            planned_rules.push(WindowsWfpRulePlan {
                action: WindowsWfpRuleAction::Block,
                layer: "ALE_AUTH_CONNECT".into(),
                selector: "loopback:127.0.0.0/8,::1".into(),
                reason: "manifest disables loopback service access".into(),
            });
        }
        planned_rules.push(WindowsWfpRulePlan {
            action: WindowsWfpRuleAction::ApprovalRequired,
            layer: "ALE_AUTH_CONNECT".into(),
            selector: "private-lan:10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7".into(),
            reason: "private/LAN destinations require explicit mediation".into(),
        });
        for domain in &spec.network.denied_domains {
            planned_rules.push(WindowsWfpRulePlan {
                action: WindowsWfpRuleAction::Block,
                layer: "ALE_AUTH_CONNECT".into(),
                selector: format!("domain:{domain}"),
                reason: "manifest domain denylist; requires resolver or callout mapping".into(),
            });
        }
        for domain in &spec.network.allowed_domains {
            planned_rules.push(WindowsWfpRulePlan {
                action: WindowsWfpRuleAction::Permit,
                layer: "ALE_AUTH_CONNECT".into(),
                selector: format!("domain:{domain}"),
                reason: "manifest domain allowlist; requires resolver or callout mapping".into(),
            });
        }

        let default_policy = match spec.network.mode {
            NetworkMode::None | NetworkMode::DenyByDefault | NetworkMode::AllowListed => {
                WindowsWfpDefaultPolicy::Block
            }
            NetworkMode::ApprovalOnFirstContact => WindowsWfpDefaultPolicy::RequireApproval,
            NetworkMode::OpenWithGuardrails | NetworkMode::Host => {
                WindowsWfpDefaultPolicy::PermitWithGuardrails
            }
        };

        Self {
            schema_version: 1,
            mode: spec.network.mode.clone(),
            default_policy,
            allowed_domains: spec.network.allowed_domains.clone(),
            denied_domains: spec.network.denied_domains.clone(),
            allow_localhost: spec.network.allow_localhost,
            planned_rules,
            evidence_events: vec![
                "windows.wfp.flow.permit".into(),
                "windows.wfp.flow.block".into(),
                "windows.wfp.flow.approval_required".into(),
            ],
            domain_rules_require_resolver: true,
            enforcement_claim: "WFP policy descriptor only; no packet/domain denial proof is wired"
                .into(),
            requires_wfp: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsEtwObserverPlan {
    pub schema_version: i64,
    pub provider_name: String,
    pub session_name: String,
    pub event_kinds: Vec<String>,
    pub correlation: WindowsEtwCorrelationPlan,
    pub event_schema: Vec<WindowsEtwEventSchema>,
    pub evidence_export: WindowsEtwEvidenceExportPlan,
    pub enforcement: WindowsEtwEnforcementMode,
    pub evidence_claim: String,
    pub requires_etw: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsEtwCorrelationPlan {
    pub preferred_key: String,
    pub job_name: String,
    pub process_id_fallback: bool,
    pub manifest_label_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsEtwEventSchema {
    pub event_type: String,
    pub provider: String,
    pub evidence_use: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsEtwEvidenceExportPlan {
    pub spool_guest_path: String,
    pub bundle_files: Vec<String>,
    pub redaction_policy: WindowsEtwRedactionPlan,
    pub hash_chain_algorithm: String,
    pub bundle_root_algorithm: String,
    pub export_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsEtwRedactionPlan {
    pub marker: String,
    pub redact_command_env: bool,
    pub redact_credential_paths: bool,
    pub max_event_payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsEtwEnforcementMode {
    ObservedOnly,
}

impl WindowsEtwObserverPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
        let mut manifest_label_keys: Vec<String> = spec.labels.keys().cloned().collect();
        manifest_label_keys.sort();
        Self {
            schema_version: 1,
            provider_name: "Agentbox-AgentPod".into(),
            session_name: format!("agentbox-agentpod-{}", spec.id),
            event_kinds: vec![
                "process.start".into(),
                "process.exit".into(),
                "job.assign".into(),
                "job.terminate".into(),
                "network.connect".into(),
                "provider.lifecycle".into(),
            ],
            correlation: WindowsEtwCorrelationPlan {
                preferred_key: "job_name".into(),
                job_name: format!("agentbox-{}", spec.id),
                process_id_fallback: true,
                manifest_label_keys,
            },
            event_schema: vec![
                WindowsEtwEventSchema {
                    event_type: "windows.process.start".into(),
                    provider: "Microsoft-Windows-Kernel-Process".into(),
                    evidence_use: "process lineage and executable path evidence".into(),
                },
                WindowsEtwEventSchema {
                    event_type: "windows.process.exit".into(),
                    provider: "Microsoft-Windows-Kernel-Process".into(),
                    evidence_use: "process lifetime and exit correlation".into(),
                },
                WindowsEtwEventSchema {
                    event_type: "windows.network.connect".into(),
                    provider: "Microsoft-Windows-WFP".into(),
                    evidence_use: "flow metadata for network boundary evidence".into(),
                },
                WindowsEtwEventSchema {
                    event_type: "agentbox.provider.lifecycle".into(),
                    provider: "Agentbox-AgentPod".into(),
                    evidence_use: "provider lifecycle and kill-switch acknowledgement evidence"
                        .into(),
                },
            ],
            evidence_export: WindowsEtwEvidenceExportPlan {
                spool_guest_path: r"C:\ProgramData\Agentbox\Evidence\etw".into(),
                bundle_files: vec![
                    "windows-etw-events.jsonl".into(),
                    "windows-etw-manifest.json".into(),
                    "windows-etw-redaction.json".into(),
                ],
                redaction_policy: WindowsEtwRedactionPlan {
                    marker: "<redacted>".into(),
                    redact_command_env: true,
                    redact_credential_paths: true,
                    max_event_payload_bytes: 16 * 1024,
                },
                hash_chain_algorithm: "sha256-prev-hash-event-hash".into(),
                bundle_root_algorithm: "agentbox-evidence-bundle-root-v1".into(),
                export_claim: "planned ETW export bundle; live ETW capture/export is not wired"
                    .into(),
            },
            enforcement: WindowsEtwEnforcementMode::ObservedOnly,
            evidence_claim:
                "ETW observer descriptor only; observed events are not enforcement proof".into(),
            requires_etw: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsVmBoundaryPlan {
    pub schema_version: i64,
    pub candidate_backends: Vec<String>,
    pub required_for_risk: Vec<String>,
    pub cell_config: WindowsVmCellConfigPlan,
    pub execution_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsVmCellConfigPlan {
    pub workspace_mount: WindowsVmWorkspaceMountPlan,
    pub credential_channels: Vec<WindowsVmCredentialChannelPlan>,
    pub host_bridge: WindowsVmHostBridgePlan,
    pub evidence_spool_guest_path: String,
    pub shutdown_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsVmWorkspaceMountPlan {
    pub host_path: String,
    pub guest_path: String,
    pub writable: bool,
    pub review_required: bool,
    pub transport: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsVmCredentialChannelPlan {
    pub name: String,
    pub kind: CredentialGrantKind,
    pub target: String,
    pub delivery: String,
    pub guest_path: Option<String>,
    pub requires_approval: bool,
    pub one_time: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsVmHostBridgePlan {
    pub transport: String,
    pub host_pipe_name: String,
    pub guest_endpoint: String,
    pub policy_endpoint: String,
    pub evidence_endpoint: String,
}

impl WindowsVmBoundaryPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
        let credential_channels = spec
            .credentials
            .grants
            .iter()
            .map(|grant| WindowsVmCredentialChannelPlan {
                name: grant.name.clone(),
                kind: grant.kind.clone(),
                target: grant.target.clone(),
                delivery: windows_vm_credential_delivery(&grant.kind).to_string(),
                guest_path: windows_vm_credential_guest_path(&grant.kind, &grant.name),
                requires_approval: grant.requires_approval,
                one_time: grant.one_time,
            })
            .collect();

        Self {
            schema_version: 1,
            candidate_backends: vec!["windows-sandbox".into(), "hyper-v".into()],
            required_for_risk: if matches!(
                spec.risk,
                crate::runtime::types::AgentPodRiskLevel::High
                    | crate::runtime::types::AgentPodRiskLevel::VeryHigh
            ) {
                vec![spec.risk.label().to_string()]
            } else {
                vec![]
            },
            cell_config: WindowsVmCellConfigPlan {
                workspace_mount: WindowsVmWorkspaceMountPlan {
                    host_path: spec.filesystem.workspace_host_path.display().to_string(),
                    guest_path: spec.filesystem.workspace_guest_path.clone(),
                    writable: true,
                    review_required: !matches!(
                        spec.workspace_mode,
                        crate::runtime::types::AgentPodWorkspaceMode::Direct
                    ),
                    transport: "sandbox-mapped-folder-or-hyper-v-plan9".into(),
                },
                credential_channels,
                host_bridge: WindowsVmHostBridgePlan {
                    transport: "hyper-v-socket-or-named-pipe".into(),
                    host_pipe_name: format!(r"\\.\pipe\agentbox-agentpod-{}", spec.id),
                    guest_endpoint: r"\\.\pipe\agentbox-bridge".into(),
                    policy_endpoint: "agentbox.policy.v1.Decide".into(),
                    evidence_endpoint: "agentbox.evidence.v1.Append".into(),
                },
                evidence_spool_guest_path: r"C:\ProgramData\Agentbox\Evidence".into(),
                shutdown_policy: "terminate-vm-cell-and-seal-evidence".into(),
            },
            execution_claim: "planned higher-strength boundary; lifecycle is not wired".into(),
        }
    }
}

fn windows_vm_credential_delivery(kind: &CredentialGrantKind) -> &'static str {
    match kind {
        CredentialGrantKind::EnvVar => "host-bridge-env-injection",
        CredentialGrantKind::FileMount => "read-only-mapped-file",
        CredentialGrantKind::Socket => "host-bridge-named-pipe-proxy",
        CredentialGrantKind::ProviderToken => "broker-mediated-provider-token",
    }
}

fn windows_vm_credential_guest_path(kind: &CredentialGrantKind, name: &str) -> Option<String> {
    match kind {
        CredentialGrantKind::FileMount => {
            Some(format!(r"C:\ProgramData\Agentbox\Credentials\{name}"))
        }
        CredentialGrantKind::Socket => Some(format!(r"\\.\pipe\agentbox-credential-{name}")),
        CredentialGrantKind::EnvVar | CredentialGrantKind::ProviderToken => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAgentPodExecutionPlan {
    pub schema_version: i64,
    pub provider: String,
    pub session_id: String,
    pub command_argv: Vec<String>,
    pub job_object: WindowsJobObjectPlan,
    pub app_container: WindowsAppContainerPlan,
    pub wfp: WindowsWfpBoundaryPlan,
    pub etw: WindowsEtwObserverPlan,
    pub vm_boundary: WindowsVmBoundaryPlan,
    pub native_receipt: AgentPodNativeReceiptSummary,
    pub live_env_var: String,
    pub live_execution_enabled: bool,
    pub requires_windows: bool,
    pub security_claim: String,
}

impl WindowsAgentPodExecutionPlan {
    pub fn from_minipod_spec(
        spec: &MinipodSpec,
        command: &ExecCommand,
    ) -> Result<Self, RuntimeError> {
        if command.argv.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "Windows AgentPod execution command cannot be empty".into(),
            ));
        }
        let job_object = WindowsJobObjectPlan::from_minipod_spec(spec)?;
        let app_container = WindowsAppContainerPlan::from_minipod_spec(spec)?;
        let wfp = WindowsWfpBoundaryPlan::from_minipod_spec(spec);
        let etw = WindowsEtwObserverPlan::from_minipod_spec(spec);
        let vm_boundary = WindowsVmBoundaryPlan::from_minipod_spec(spec);
        let native_receipt = windows_native_receipt_descriptor(
            &job_object,
            &app_container,
            &wfp,
            &etw,
            &vm_boundary,
        );

        Ok(Self {
            schema_version: 1,
            provider: "agentpod-windows".into(),
            session_id: spec.id.clone(),
            command_argv: command.argv.clone(),
            job_object,
            app_container,
            wfp,
            etw,
            vm_boundary,
            native_receipt,
            live_env_var: "AGENTBOX_WINDOWS_NATIVE".into(),
            live_execution_enabled: windows_native_execution_enabled(),
            requires_windows: true,
            security_claim:
                "Job Object/AppContainer/WFP/ETW/VM boundary plan; execution is not wired".into(),
        })
    }

    pub fn runnable_on_current_host(&self) -> bool {
        cfg!(target_os = "windows") && self.live_execution_enabled
    }
}

fn windows_native_receipt_descriptor(
    job_object: &WindowsJobObjectPlan,
    app_container: &WindowsAppContainerPlan,
    wfp: &WindowsWfpBoundaryPlan,
    etw: &WindowsEtwObserverPlan,
    vm_boundary: &WindowsVmBoundaryPlan,
) -> AgentPodNativeReceiptSummary {
    let runner_phases = vec![
        AgentPodRunnerPhaseReceipt {
            phase: "apply-job-object".into(),
            status: RUNNER_PHASE_STATUS_DESCRIPTOR.into(),
            event_name: "windows.job_object.apply".into(),
            evidence_ref: Some(job_object.timeout_action.clone()),
        },
        AgentPodRunnerPhaseReceipt {
            phase: "apply-app-container".into(),
            status: RUNNER_PHASE_STATUS_DESCRIPTOR.into(),
            event_name: "windows.app_container.apply".into(),
            evidence_ref: Some(app_container.workspace_boundary.access_model.clone()),
        },
        AgentPodRunnerPhaseReceipt {
            phase: "apply-wfp".into(),
            status: RUNNER_PHASE_STATUS_DESCRIPTOR.into(),
            event_name: "windows.wfp.policy.apply".into(),
            evidence_ref: Some(wfp.evidence_events.join(",")),
        },
        AgentPodRunnerPhaseReceipt {
            phase: "attach-etw".into(),
            status: RUNNER_PHASE_STATUS_DESCRIPTOR.into(),
            event_name: "windows.etw.observer.attach".into(),
            evidence_ref: Some(etw.evidence_export.bundle_files.join(",")),
        },
        AgentPodRunnerPhaseReceipt {
            phase: "boot-vm-boundary".into(),
            status: RUNNER_PHASE_STATUS_PLANNED.into(),
            event_name: "windows.vm_boundary.boot".into(),
            evidence_ref: Some(vm_boundary.candidate_backends.join(",")),
        },
    ];
    let mut evidence_refs = Vec::new();
    evidence_refs.extend(wfp.evidence_events.clone());
    evidence_refs.extend(etw.evidence_export.bundle_files.clone());
    evidence_refs.push(vm_boundary.cell_config.evidence_spool_guest_path.clone());

    AgentPodNativeReceiptSummary {
        schema_version: 1,
        provider: PROVIDER_WINDOWS.into(),
        enforcement_status: AgentPodEnforcementStatus::DescriptorOnlyOrUnobserved
            .as_str()
            .into(),
        runner_phases,
        enforced_phases: vec![],
        skipped_planned_primitives: skipped_primitives_for_provider(PROVIDER_WINDOWS),
        evidence_refs,
    }
}

pub fn windows_native_execution_enabled() -> bool {
    // Keep descriptor-only until the provider has a real process lifecycle,
    // assignment, cleanup, and enforcement gate. The Job Object smoke only
    // proves create/close, not runnable execution.
    false
}

pub fn windows_job_object_live_smoke_enabled() -> bool {
    matches!(
        std::env::var("AGENTBOX_WINDOWS_JOB_OBJECT").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

pub struct WindowsJobObjectController;

impl WindowsJobObjectController {
    pub fn plan(spec: &MinipodSpec) -> Result<WindowsJobObjectPlan, RuntimeError> {
        WindowsJobObjectPlan::from_minipod_spec(spec)
    }

    #[cfg(target_os = "windows")]
    pub fn apply(
        _plan: &WindowsJobObjectPlan,
        _pid: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Windows Job Object control is modeled but not wired to Win32 APIs yet".into())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn apply(
        _plan: &WindowsJobObjectPlan,
        _pid: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Windows Job Objects are only available on Windows".into())
    }
}

fn cpu_shares_to_job_weight(cpu_shares: u32) -> u32 {
    let weight = ((cpu_shares.max(1) as u64 * 9) / 262_144).max(1);
    weight.min(9) as u32
}

fn default_process_limit_for_risk(risk: &crate::runtime::types::AgentPodRiskLevel) -> u32 {
    match risk {
        crate::runtime::types::AgentPodRiskLevel::Low => 256,
        crate::runtime::types::AgentPodRiskLevel::Medium => 128,
        crate::runtime::types::AgentPodRiskLevel::High => 64,
        crate::runtime::types::AgentPodRiskLevel::VeryHigh => 32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::{
        CredentialGrant, MountRule, ResourcePolicy, WorkspaceOverlayPolicy,
    };

    #[test]
    fn job_object_plan_maps_minipod_resources() {
        let mut spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
        spec.resources = ResourcePolicy {
            memory_bytes: 536_870_912,
            cpu_shares: 2048,
            timeout_seconds: Some(30),
        };

        let plan = WindowsJobObjectController::plan(&spec).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.job_name, format!("agentbox-{}", spec.id));
        assert_eq!(plan.live_smoke.env_var, "AGENTBOX_WINDOWS_JOB_OBJECT");
        assert!(!plan.live_smoke.enabled);
        assert!(plan
            .live_smoke
            .lifecycle_claim
            .contains("process assignment and limit enforcement are not proven"));
        assert!(plan.kill_on_close);
        assert_eq!(plan.memory_limit_bytes, 536_870_912);
        assert_eq!(plan.cpu_rate_weight, 1);
        assert_eq!(plan.process_limit, Some(128));
        assert_eq!(plan.timeout_seconds, Some(30));
        assert_eq!(
            plan.timeout_action,
            "terminate-job-and-seal-timeout-evidence"
        );
        assert!(plan.resource_claim.contains("live Win32 apply proof"));
        assert!(plan.requires_windows);
        assert_eq!(
            plan.limit_writes(),
            vec![
                WindowsJobObjectLimit {
                    name: "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE".into(),
                    value: "true".into(),
                },
                WindowsJobObjectLimit {
                    name: "JOB_OBJECT_LIMIT_PROCESS_MEMORY".into(),
                    value: "536870912".into(),
                },
                WindowsJobObjectLimit {
                    name: "JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED".into(),
                    value: "1".into(),
                },
                WindowsJobObjectLimit {
                    name: "JOB_OBJECT_LIMIT_ACTIVE_PROCESS".into(),
                    value: "128".into(),
                },
                WindowsJobObjectLimit {
                    name: "AGENTBOX_WALL_CLOCK_TIMEOUT_SECONDS".into(),
                    value: "30".into(),
                },
            ]
        );
    }

    #[test]
    fn job_object_live_smoke_descriptor_models_create_close_only() {
        let spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");

        let plan = WindowsJobObjectController::plan(&spec).unwrap();

        assert_eq!(plan.live_smoke.schema_version, 1);
        assert_eq!(
            plan.live_smoke.lifecycle_steps,
            vec![
                "CreateJobObjectW".to_string(),
                "CloseHandle".to_string(),
                "no process assignment or resource enforcement proof".to_string(),
            ]
        );
        assert!(plan
            .live_smoke
            .lifecycle_claim
            .contains("create/close smoke skeleton only"));
        assert!(plan
            .live_smoke
            .lifecycle_claim
            .contains("limit enforcement are not proven"));
    }

    #[test]
    fn job_object_plan_rejects_invalid_limits() {
        let mut spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
        spec.resources.memory_bytes = 0;

        let err = WindowsJobObjectController::plan(&spec).unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }

    #[test]
    fn agentpod_execution_plan_composes_windows_native_boundaries() {
        let mut spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
        spec.workspace_mode = crate::runtime::types::AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_write_policy = WorkspaceWritePolicy::WritableOverlay;
        spec.filesystem.workspace_overlay = WorkspaceOverlayPolicy::review_required(Some(
            "C:\\agentbox\\.agentbox\\overlay".into(),
        ));
        spec.filesystem.mounts.push(MountRule {
            host_path: "C:\\agentbox\\readonly".into(),
            guest_path: "/mnt/readonly".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::ReadOnlyHost,
        });
        spec.credentials.grants.push(CredentialGrant {
            name: "OPENAI_API_KEY".into(),
            kind: CredentialGrantKind::EnvVar,
            target: "OPENAI_API_KEY".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });
        spec.credentials.grants.push(CredentialGrant {
            name: "deploy_token".into(),
            kind: CredentialGrantKind::FileMount,
            target: "C:\\agentbox\\secrets\\deploy-token".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });
        let command = ExecCommand {
            argv: vec!["codex".into(), "exec".into()],
            working_dir: Some("C:\\agentbox\\work".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let plan = WindowsAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.provider, "agentpod-windows");
        assert_eq!(plan.session_id, spec.id);
        assert_eq!(plan.command_argv, vec!["codex", "exec"]);
        assert_eq!(plan.live_env_var, "AGENTBOX_WINDOWS_NATIVE");
        assert!(plan.requires_windows);
        assert!(!plan.live_execution_enabled);
        assert!(!windows_native_execution_enabled());
        assert!(plan.security_claim.contains("execution is not wired"));
        assert!(plan.job_object.kill_on_close);
        assert_eq!(plan.job_object.process_limit, Some(128));
        assert_eq!(
            plan.job_object.live_smoke.env_var,
            "AGENTBOX_WINDOWS_JOB_OBJECT"
        );
        assert!(plan
            .job_object
            .resource_claim
            .contains("live Win32 apply proof"));
        assert!(plan.app_container.requires_profile_creation);
        assert_eq!(plan.app_container.workspace_mode, "overlay-review");
        assert_eq!(
            plan.app_container.workspace_write_policy,
            WorkspaceWritePolicy::WritableOverlay
        );
        assert_eq!(
            plan.app_container.workspace_boundary.access_model,
            "workspace-overlay-review"
        );
        assert_eq!(
            plan.app_container.workspace_boundary.overlay_mode,
            WorkspaceOverlayMode::ReviewRequired
        );
        assert!(plan.app_container.workspace_boundary.review_required);
        assert!(!plan.app_container.workspace_boundary.commit_required);
        assert!(!plan.app_container.workspace_boundary.discard_on_destroy);
        assert!(plan
            .app_container
            .workspace_boundary
            .enforcement_claim
            .contains("live ACL proof is not wired"));
        assert_eq!(plan.app_container.mounts.len(), 1);
        assert!(plan.app_container.mounts.iter().any(|mount| {
            mount.host_path == "C:\\agentbox\\readonly"
                && mount.guest_path == "/mnt/readonly"
                && mount.read_only
                && mount.kind == MountKind::ReadOnlyHost
        }));
        assert_eq!(
            plan.app_container.protected_paths.len(),
            plan.app_container.protected_path_rules.len()
        );
        assert!(plan
            .app_container
            .protected_path_rules
            .iter()
            .all(|rule| rule.default_access == "deny-without-explicit-grant"));
        assert!(plan.wfp.requires_wfp);
        assert_eq!(
            plan.wfp.default_policy,
            WindowsWfpDefaultPolicy::PermitWithGuardrails
        );
        assert!(plan.wfp.domain_rules_require_resolver);
        assert!(plan
            .wfp
            .planned_rules
            .iter()
            .any(|rule| rule.action == WindowsWfpRuleAction::ApprovalRequired
                && rule.selector.contains("private-lan")));
        assert!(plan
            .wfp
            .planned_rules
            .iter()
            .any(|rule| rule.action == WindowsWfpRuleAction::Block
                && rule.selector.contains("169.254.169.254")));
        assert!(plan
            .wfp
            .evidence_events
            .contains(&"windows.wfp.flow.block".to_string()));
        assert!(plan
            .wfp
            .enforcement_claim
            .contains("no packet/domain denial proof"));
        assert!(plan.etw.requires_etw);
        assert!(plan.etw.event_kinds.contains(&"process.start".into()));
        assert_eq!(plan.etw.correlation.preferred_key, "job_name");
        assert_eq!(
            plan.etw.correlation.job_name,
            format!("agentbox-{}", spec.id)
        );
        assert_eq!(
            plan.etw.enforcement,
            WindowsEtwEnforcementMode::ObservedOnly
        );
        assert!(plan
            .etw
            .event_schema
            .iter()
            .any(|event| event.event_type == "windows.network.connect"));
        assert_eq!(
            plan.etw.evidence_export.spool_guest_path,
            r"C:\ProgramData\Agentbox\Evidence\etw"
        );
        assert!(plan
            .etw
            .evidence_export
            .bundle_files
            .contains(&"windows-etw-events.jsonl".to_string()));
        assert!(plan.etw.evidence_export.redaction_policy.redact_command_env);
        assert_eq!(
            plan.etw.evidence_export.hash_chain_algorithm,
            "sha256-prev-hash-event-hash"
        );
        assert!(plan
            .etw
            .evidence_export
            .export_claim
            .contains("live ETW capture/export is not wired"));
        assert!(plan.etw.evidence_claim.contains("not enforcement proof"));
        assert_eq!(
            plan.vm_boundary.candidate_backends,
            vec!["windows-sandbox".to_string(), "hyper-v".to_string()]
        );
        assert_eq!(
            plan.vm_boundary.cell_config.workspace_mount.host_path,
            "C:\\agentbox\\work"
        );
        assert_eq!(
            plan.vm_boundary.cell_config.workspace_mount.guest_path,
            "/workspace"
        );
        assert!(plan.vm_boundary.cell_config.workspace_mount.writable);
        assert!(plan.vm_boundary.cell_config.workspace_mount.review_required);
        assert_eq!(
            plan.vm_boundary.cell_config.host_bridge.policy_endpoint,
            "agentbox.policy.v1.Decide"
        );
        assert!(plan
            .vm_boundary
            .cell_config
            .host_bridge
            .host_pipe_name
            .contains(&spec.id));
        assert_eq!(
            plan.vm_boundary.cell_config.evidence_spool_guest_path,
            r"C:\ProgramData\Agentbox\Evidence"
        );
        assert_eq!(plan.native_receipt.schema_version, 1);
        assert_eq!(plan.native_receipt.provider, "agentpod-windows");
        assert_eq!(
            plan.native_receipt.enforcement_status,
            "descriptor-only-or-unobserved"
        );
        assert!(plan.native_receipt.enforced_phases.is_empty());
        assert!(plan.native_receipt.runner_phases.iter().any(|phase| {
            phase.phase == "apply-wfp"
                && phase.status == "descriptor"
                && phase.event_name == "windows.wfp.policy.apply"
        }));
        assert!(plan.native_receipt.runner_phases.iter().any(|phase| {
            phase.phase == "boot-vm-boundary"
                && phase.status == "planned"
                && phase.event_name == "windows.vm_boundary.boot"
        }));
        assert!(plan
            .native_receipt
            .evidence_refs
            .contains(&"windows-etw-events.jsonl".to_string()));
        assert!(plan
            .native_receipt
            .evidence_refs
            .contains(&"windows.wfp.flow.block".to_string()));
        assert!(plan
            .native_receipt
            .skipped_planned_primitives
            .contains(&"live WFP packet/domain enforcement".to_string()));
        assert!(plan
            .native_receipt
            .skipped_planned_primitives
            .contains(&"live ETW capture/export".to_string()));
        assert_eq!(plan.vm_boundary.cell_config.credential_channels.len(), 2);
        assert!(plan
            .vm_boundary
            .cell_config
            .credential_channels
            .iter()
            .any(|channel| channel.name == "OPENAI_API_KEY"
                && channel.delivery == "host-bridge-env-injection"
                && channel.guest_path.is_none()
                && channel.requires_approval
                && channel.one_time));
        assert!(plan
            .vm_boundary
            .cell_config
            .credential_channels
            .iter()
            .any(|channel| channel.name == "deploy_token"
                && channel.delivery == "read-only-mapped-file"
                && channel.guest_path.as_deref()
                    == Some(r"C:\ProgramData\Agentbox\Credentials\deploy_token")));
        assert!(!plan.runnable_on_current_host());
    }

    #[test]
    fn windows_native_gate_does_not_claim_runnable_execution() {
        let previous = std::env::var("AGENTBOX_WINDOWS_NATIVE").ok();
        std::env::set_var("AGENTBOX_WINDOWS_NATIVE", "1");

        let spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
        let command = ExecCommand {
            argv: vec!["powershell.exe".into(), "-NoProfile".into()],
            working_dir: Some("C:\\agentbox\\work".into()),
            env: Default::default(),
            timeout_seconds: None,
        };
        let plan = WindowsAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();

        assert_eq!(plan.live_env_var, "AGENTBOX_WINDOWS_NATIVE");
        assert!(!windows_native_execution_enabled());
        assert!(!plan.live_execution_enabled);
        assert!(!plan.runnable_on_current_host());
        assert!(plan.security_claim.contains("execution is not wired"));
        assert!(plan.native_receipt.enforced_phases.is_empty());

        match previous {
            Some(value) => std::env::set_var("AGENTBOX_WINDOWS_NATIVE", value),
            None => std::env::remove_var("AGENTBOX_WINDOWS_NATIVE"),
        }
    }

    #[test]
    fn windows_native_receipt_descriptor_uses_agentpod_vocabulary_without_live_claim() {
        let spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
        let command = ExecCommand {
            argv: vec!["powershell.exe".into(), "-NoProfile".into()],
            working_dir: Some("C:\\agentbox\\work".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let plan = WindowsAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();
        let receipt = plan.native_receipt;

        assert_eq!(receipt.provider, "agentpod-windows");
        assert_eq!(receipt.enforcement_status, "descriptor-only-or-unobserved");
        assert!(receipt.enforced_phases.is_empty());
        assert_eq!(receipt.runner_phases.len(), 5);
        assert!(receipt
            .runner_phases
            .iter()
            .all(|phase| phase.status == "descriptor" || phase.status == "planned"));
        assert!(receipt
            .skipped_planned_primitives
            .iter()
            .all(|primitive| primitive.starts_with("live ")));
    }

    #[test]
    fn etw_observer_plan_carries_session_correlation_and_evidence_schema() {
        let mut spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
        spec.labels
            .insert("policy.bundle".into(), "deploy-default".into());

        let plan = WindowsEtwObserverPlan::from_minipod_spec(&spec);

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.provider_name, "Agentbox-AgentPod");
        assert_eq!(plan.session_name, format!("agentbox-agentpod-{}", spec.id));
        assert_eq!(plan.correlation.preferred_key, "job_name");
        assert!(plan
            .correlation
            .manifest_label_keys
            .contains(&"policy.bundle".to_string()));
        assert_eq!(plan.enforcement, WindowsEtwEnforcementMode::ObservedOnly);
        assert!(plan.event_schema.iter().any(|event| {
            event.event_type == "windows.process.start"
                && event.provider == "Microsoft-Windows-Kernel-Process"
        }));
        assert!(plan.event_schema.iter().any(|event| {
            event.event_type == "agentbox.provider.lifecycle"
                && event.provider == "Agentbox-AgentPod"
        }));
        assert!(plan
            .evidence_export
            .bundle_files
            .contains(&"windows-etw-manifest.json".to_string()));
        assert_eq!(plan.evidence_export.redaction_policy.marker, "<redacted>");
        assert_eq!(
            plan.evidence_export.bundle_root_algorithm,
            "agentbox-evidence-bundle-root-v1"
        );
        assert!(plan.requires_etw);
        assert!(plan.evidence_claim.contains("descriptor only"));
    }

    #[test]
    fn agentpod_execution_plan_rejects_empty_commands() {
        let spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
        let command = ExecCommand {
            argv: vec![],
            working_dir: Some("C:\\agentbox\\work".into()),
            env: Default::default(),
            timeout_seconds: None,
        };

        let err = WindowsAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap_err();

        assert!(err.to_string().contains("cannot be empty"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn job_object_apply_is_explicitly_windows_only() {
        let spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
        let plan = WindowsJobObjectController::plan(&spec).unwrap();

        let err = WindowsJobObjectController::apply(&plan, 1).unwrap_err();

        assert!(err.to_string().contains("only available on Windows"));
    }
}
