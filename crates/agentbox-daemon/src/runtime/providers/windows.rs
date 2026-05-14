use serde::{Deserialize, Serialize};

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::MinipodSpec;

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

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn job_object_apply_is_explicitly_windows_only() {
        let spec = MinipodSpec::for_agent_task("codex", "C:\\agentbox\\work");
        let plan = WindowsJobObjectController::plan(&spec).unwrap();

        let err = WindowsJobObjectController::apply(&plan, 1).unwrap_err();

        assert!(err.to_string().contains("only available on Windows"));
    }
}
