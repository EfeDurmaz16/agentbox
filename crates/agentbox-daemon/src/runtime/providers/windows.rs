use serde::{Deserialize, Serialize};

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::{ExecCommand, MinipodSpec, NetworkMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsJobObjectPlan {
    pub schema_version: i64,
    pub job_name: String,
    pub kill_on_close: bool,
    pub memory_limit_bytes: u64,
    pub cpu_rate_weight: u32,
    pub process_limit: Option<u32>,
    pub requires_windows: bool,
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
            kill_on_close: true,
            memory_limit_bytes: spec.resources.memory_bytes,
            cpu_rate_weight: cpu_shares_to_job_weight(spec.resources.cpu_shares),
            process_limit: None,
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

        limits
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
    pub protected_paths: Vec<String>,
    pub deny_home_by_default: bool,
    pub requires_profile_creation: bool,
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
            protected_paths: spec
                .filesystem
                .protected_paths
                .iter()
                .map(|path| path.path.display().to_string())
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
    pub allowed_domains: Vec<String>,
    pub denied_domains: Vec<String>,
    pub allow_localhost: bool,
    pub enforcement_claim: String,
    pub requires_wfp: bool,
}

impl WindowsWfpBoundaryPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
        Self {
            schema_version: 1,
            mode: spec.network.mode.clone(),
            allowed_domains: spec.network.allowed_domains.clone(),
            denied_domains: spec.network.denied_domains.clone(),
            allow_localhost: spec.network.allow_localhost,
            enforcement_claim: "planned WFP observability/enforcement; no packet denial proof yet"
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
    pub execution_claim: String,
}

impl WindowsVmBoundaryPlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
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
            execution_claim: "planned higher-strength boundary; lifecycle is not wired".into(),
        }
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

        Ok(Self {
            schema_version: 1,
            provider: "agentpod-windows".into(),
            session_id: spec.id.clone(),
            command_argv: command.argv.clone(),
            job_object: WindowsJobObjectPlan::from_minipod_spec(spec)?,
            app_container: WindowsAppContainerPlan::from_minipod_spec(spec)?,
            wfp: WindowsWfpBoundaryPlan::from_minipod_spec(spec),
            etw: WindowsEtwObserverPlan::from_minipod_spec(spec),
            vm_boundary: WindowsVmBoundaryPlan::from_minipod_spec(spec),
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

pub fn windows_native_execution_enabled() -> bool {
    matches!(
        std::env::var("AGENTBOX_WINDOWS_NATIVE").as_deref(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::ResourcePolicy;

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
        assert!(plan.kill_on_close);
        assert_eq!(plan.memory_limit_bytes, 536_870_912);
        assert_eq!(plan.cpu_rate_weight, 1);
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
            ]
        );
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
        let spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
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
        assert!(plan.security_claim.contains("execution is not wired"));
        assert!(plan.job_object.kill_on_close);
        assert!(plan.app_container.requires_profile_creation);
        assert!(plan.wfp.requires_wfp);
        assert!(plan
            .wfp
            .enforcement_claim
            .contains("no packet denial proof"));
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
        assert!(plan.etw.evidence_claim.contains("not enforcement proof"));
        assert_eq!(
            plan.vm_boundary.candidate_backends,
            vec!["windows-sandbox".to_string(), "hyper-v".to_string()]
        );
        assert!(!plan.runnable_on_current_host());
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
