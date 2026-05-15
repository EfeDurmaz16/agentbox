use serde::{Deserialize, Serialize};

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, MountMode, NetworkMode, ResourcePolicy, SeccompAction,
    SeccompProfile,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxUserNamespacePlan {
    pub schema_version: i64,
    pub command_argv: Vec<String>,
    pub map_root_user: bool,
    pub deny_setgroups: bool,
    pub uid_map: String,
    pub gid_map: String,
    pub requires_linux: bool,
}

impl LinuxUserNamespacePlan {
    pub fn rootless(command: &ExecCommand) -> Self {
        Self {
            schema_version: 1,
            command_argv: command.argv.clone(),
            map_root_user: true,
            deny_setgroups: true,
            uid_map: "0 current-user 1".to_string(),
            gid_map: "0 current-group 1".to_string(),
            requires_linux: true,
        }
    }
}

pub struct LinuxUserNamespaceLauncher;

impl LinuxUserNamespaceLauncher {
    pub fn plan(command: &ExecCommand) -> Result<LinuxUserNamespacePlan, RuntimeError> {
        if command.argv.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "user namespace launcher command cannot be empty".into(),
            ));
        }

        Ok(LinuxUserNamespacePlan::rootless(command))
    }

    #[cfg(target_os = "linux")]
    pub fn spawn(
        command: &ExecCommand,
    ) -> Result<std::process::Child, Box<dyn std::error::Error + Send + Sync>> {
        let plan = Self::plan(command)?;
        let mut child = std::process::Command::new("unshare");
        child
            .arg("--user")
            .arg("--map-root-user")
            .arg("--setgroups=deny")
            .arg("--")
            .args(&plan.command_argv);

        if let Some(working_dir) = &command.working_dir {
            child.current_dir(working_dir);
        }
        for (key, value) in &command.env {
            child.env(key, value);
        }

        Ok(child.spawn()?)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn spawn(
        _command: &ExecCommand,
    ) -> Result<std::process::Child, Box<dyn std::error::Error + Send + Sync>> {
        Err("Linux user namespaces are only available on Linux".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxMountNamespacePlan {
    pub schema_version: i64,
    pub workspace_host_path: String,
    pub workspace_guest_path: String,
    pub read_only_mounts: Vec<LinuxMountNamespaceMount>,
    pub propagation: String,
    pub requires_linux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxMountNamespaceMount {
    pub host_path: String,
    pub guest_path: String,
    pub read_only: bool,
}

impl LinuxMountNamespacePlan {
    pub fn from_minipod_spec(spec: &MinipodSpec) -> Self {
        let read_only_mounts = spec
            .filesystem
            .mounts
            .iter()
            .map(|mount| LinuxMountNamespaceMount {
                host_path: mount.host_path.display().to_string(),
                guest_path: mount.guest_path.clone(),
                read_only: matches!(mount.mode, MountMode::ReadOnly),
            })
            .collect();

        Self {
            schema_version: 1,
            workspace_host_path: spec.filesystem.workspace_host_path.display().to_string(),
            workspace_guest_path: spec.filesystem.workspace_guest_path.clone(),
            read_only_mounts,
            propagation: "private".to_string(),
            requires_linux: true,
        }
    }
}

pub struct LinuxMountNamespaceLauncher;

impl LinuxMountNamespaceLauncher {
    pub fn plan(spec: &MinipodSpec) -> Result<LinuxMountNamespacePlan, RuntimeError> {
        if spec.filesystem.workspace_guest_path.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "mount namespace workspace guest path cannot be empty".into(),
            ));
        }

        Ok(LinuxMountNamespacePlan::from_minipod_spec(spec))
    }

    pub fn command_args(plan: &LinuxMountNamespacePlan, command: &ExecCommand) -> Vec<String> {
        let mut args = vec![
            "--mount".to_string(),
            "--propagation".to_string(),
            plan.propagation.clone(),
            "--".to_string(),
        ];
        args.extend(command.argv.clone());
        args
    }

    #[cfg(target_os = "linux")]
    pub fn spawn(
        spec: &MinipodSpec,
        command: &ExecCommand,
    ) -> Result<std::process::Child, Box<dyn std::error::Error + Send + Sync>> {
        if command.argv.is_empty() {
            return Err("mount namespace launcher command cannot be empty".into());
        }
        let plan = Self::plan(spec)?;
        let mut child = std::process::Command::new("unshare");
        child.args(Self::command_args(&plan, command));

        if let Some(working_dir) = &command.working_dir {
            child.current_dir(working_dir);
        }
        for (key, value) in &command.env {
            child.env(key, value);
        }

        Ok(child.spawn()?)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn spawn(
        _spec: &MinipodSpec,
        _command: &ExecCommand,
    ) -> Result<std::process::Child, Box<dyn std::error::Error + Send + Sync>> {
        Err("Linux mount namespaces are only available on Linux".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxPidNamespacePlan {
    pub schema_version: i64,
    pub command_argv: Vec<String>,
    pub fork_init: bool,
    pub mount_proc: bool,
    pub kill_signal: String,
    pub requires_linux: bool,
}

impl LinuxPidNamespacePlan {
    pub fn isolated(command: &ExecCommand) -> Self {
        Self {
            schema_version: 1,
            command_argv: command.argv.clone(),
            fork_init: true,
            mount_proc: true,
            kill_signal: "TERM".to_string(),
            requires_linux: true,
        }
    }
}

pub struct LinuxPidNamespaceLauncher;

impl LinuxPidNamespaceLauncher {
    pub fn plan(command: &ExecCommand) -> Result<LinuxPidNamespacePlan, RuntimeError> {
        if command.argv.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "pid namespace launcher command cannot be empty".into(),
            ));
        }

        Ok(LinuxPidNamespacePlan::isolated(command))
    }

    pub fn command_args(plan: &LinuxPidNamespacePlan) -> Vec<String> {
        let mut args = vec![
            "--pid".to_string(),
            "--fork".to_string(),
            "--mount-proc".to_string(),
            "--".to_string(),
        ];
        args.extend(plan.command_argv.clone());
        args
    }

    #[cfg(target_os = "linux")]
    pub fn spawn(
        command: &ExecCommand,
    ) -> Result<std::process::Child, Box<dyn std::error::Error + Send + Sync>> {
        let plan = Self::plan(command)?;
        let mut child = std::process::Command::new("unshare");
        child.args(Self::command_args(&plan));

        if let Some(working_dir) = &command.working_dir {
            child.current_dir(working_dir);
        }
        for (key, value) in &command.env {
            child.env(key, value);
        }

        Ok(child.spawn()?)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn spawn(
        _command: &ExecCommand,
    ) -> Result<std::process::Child, Box<dyn std::error::Error + Send + Sync>> {
        Err("Linux PID namespaces are only available on Linux".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxCgroupV2Plan {
    pub schema_version: i64,
    pub cgroup_name: String,
    pub memory_max: String,
    pub cpu_weight: u32,
    pub pids_max: Option<u32>,
    pub requires_linux: bool,
}

impl LinuxCgroupV2Plan {
    pub fn from_resources(session_id: &str, resources: &ResourcePolicy) -> Self {
        Self {
            schema_version: 1,
            cgroup_name: format!("agentbox-{session_id}"),
            memory_max: resources.memory_bytes.to_string(),
            cpu_weight: cpu_shares_to_cgroup_weight(resources.cpu_shares),
            pids_max: None,
            requires_linux: true,
        }
    }

    pub fn writes(&self) -> Vec<LinuxCgroupV2Write> {
        let mut writes = vec![
            LinuxCgroupV2Write {
                file: "memory.max".into(),
                value: self.memory_max.clone(),
            },
            LinuxCgroupV2Write {
                file: "cpu.weight".into(),
                value: self.cpu_weight.to_string(),
            },
        ];

        if let Some(pids_max) = self.pids_max {
            writes.push(LinuxCgroupV2Write {
                file: "pids.max".into(),
                value: pids_max.to_string(),
            });
        }

        writes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxCgroupV2Write {
    pub file: String,
    pub value: String,
}

pub struct LinuxCgroupV2Limiter;

impl LinuxCgroupV2Limiter {
    pub fn plan(
        session_id: &str,
        resources: &ResourcePolicy,
    ) -> Result<LinuxCgroupV2Plan, RuntimeError> {
        if session_id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "cgroup v2 session id cannot be empty".into(),
            ));
        }
        if resources.memory_bytes == 0 {
            return Err(RuntimeError::ManifestRejected(
                "cgroup v2 memory limit cannot be zero".into(),
            ));
        }

        Ok(LinuxCgroupV2Plan::from_resources(session_id, resources))
    }

    #[cfg(target_os = "linux")]
    pub fn apply(
        root: &std::path::Path,
        plan: &LinuxCgroupV2Plan,
        pid: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cgroup_dir = root.join(&plan.cgroup_name);
        std::fs::create_dir_all(&cgroup_dir)?;
        for write in plan.writes() {
            std::fs::write(cgroup_dir.join(write.file), write.value)?;
        }
        std::fs::write(cgroup_dir.join("cgroup.procs"), pid.to_string())?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(
        _root: &std::path::Path,
        _plan: &LinuxCgroupV2Plan,
        _pid: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Linux cgroups v2 are only available on Linux".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSeccompPlan {
    pub schema_version: i64,
    pub enabled: bool,
    pub default_action: SeccompAction,
    pub syscall_rules: Vec<LinuxSeccompRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oci_profile: Option<LinuxSeccompOciProfile>,
    pub requires_loader: bool,
    pub requires_linux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSeccompRule {
    pub syscall: String,
    pub action: SeccompAction,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxSeccompOciProfile {
    pub default_action: String,
    pub architectures: Vec<String>,
    pub syscalls: Vec<LinuxSeccompOciSyscall>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxSeccompOciSyscall {
    pub names: Vec<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno_ret: Option<i32>,
    pub comment: String,
}

impl LinuxSeccompPlan {
    pub fn from_profile(profile: &SeccompProfile) -> Self {
        Self {
            schema_version: 1,
            enabled: profile.enabled,
            default_action: profile.default_action.clone(),
            syscall_rules: profile
                .rules
                .iter()
                .map(|rule| LinuxSeccompRule {
                    syscall: rule.syscall.clone(),
                    action: rule.action.clone(),
                    reason: rule.reason.clone(),
                })
                .collect(),
            oci_profile: profile.enabled.then(|| LinuxSeccompOciProfile {
                default_action: seccomp_action_to_oci(&profile.default_action).0,
                architectures: vec![current_seccomp_architecture().to_string()],
                syscalls: profile
                    .rules
                    .iter()
                    .map(|rule| {
                        let (action, errno_ret) = seccomp_action_to_oci(&rule.action);
                        LinuxSeccompOciSyscall {
                            names: vec![rule.syscall.clone()],
                            action,
                            errno_ret,
                            comment: rule.reason.clone(),
                        }
                    })
                    .collect(),
            }),
            requires_loader: profile.enabled,
            requires_linux: true,
        }
    }
}

fn seccomp_action_to_oci(action: &SeccompAction) -> (String, Option<i32>) {
    match action {
        SeccompAction::Allow => ("SCMP_ACT_ALLOW".into(), None),
        SeccompAction::Errno(errno) => ("SCMP_ACT_ERRNO".into(), Some(*errno)),
        SeccompAction::KillProcess => ("SCMP_ACT_KILL_PROCESS".into(), None),
        SeccompAction::Log => ("SCMP_ACT_LOG".into(), None),
    }
}

fn current_seccomp_architecture() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "SCMP_ARCH_X86_64"
    } else if cfg!(target_arch = "aarch64") {
        "SCMP_ARCH_AARCH64"
    } else if cfg!(target_arch = "arm") {
        "SCMP_ARCH_ARM"
    } else if cfg!(target_arch = "x86") {
        "SCMP_ARCH_X86"
    } else {
        "SCMP_ARCH_NATIVE"
    }
}

pub struct LinuxSeccompProfileLoader;

impl LinuxSeccompProfileLoader {
    pub fn plan(profile: &SeccompProfile) -> Result<LinuxSeccompPlan, RuntimeError> {
        if profile.enabled && profile.rules.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "enabled seccomp profile must contain at least one syscall rule".into(),
            ));
        }

        Ok(LinuxSeccompPlan::from_profile(profile))
    }

    #[cfg(target_os = "linux")]
    pub fn apply(_plan: &LinuxSeccompPlan) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("seccomp profile loading is modeled but not wired to a Linux loader yet".into())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(_plan: &LinuxSeccompPlan) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Linux seccomp profiles are only available on Linux".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxLandlockPlan {
    pub schema_version: i64,
    pub ruleset_name: String,
    pub rules: Vec<LinuxLandlockRule>,
    pub default_deny: bool,
    pub requires_loader: bool,
    pub requires_linux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxLandlockRule {
    pub path: String,
    pub access: Vec<LinuxLandlockAccess>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinuxLandlockAccess {
    ReadFile,
    ReadDir,
    WriteFile,
    MakeDir,
    RemoveFile,
    RemoveDir,
    Execute,
}

pub struct LinuxLandlockRuleset;

impl LinuxLandlockRuleset {
    pub fn plan(spec: &MinipodSpec) -> Result<LinuxLandlockPlan, RuntimeError> {
        if spec.filesystem.workspace_host_path.as_os_str().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "landlock workspace path cannot be empty".into(),
            ));
        }

        let mut rules = vec![LinuxLandlockRule {
            path: spec.filesystem.workspace_host_path.display().to_string(),
            access: vec![
                LinuxLandlockAccess::ReadFile,
                LinuxLandlockAccess::ReadDir,
                LinuxLandlockAccess::WriteFile,
                LinuxLandlockAccess::MakeDir,
                LinuxLandlockAccess::RemoveFile,
                LinuxLandlockAccess::RemoveDir,
                LinuxLandlockAccess::Execute,
            ],
            reason: "task workspace is the writable execution boundary".into(),
        }];

        for mount in &spec.filesystem.mounts {
            let mut access = vec![
                LinuxLandlockAccess::ReadFile,
                LinuxLandlockAccess::ReadDir,
                LinuxLandlockAccess::Execute,
            ];
            if matches!(mount.mode, MountMode::ReadWrite) {
                access.extend([
                    LinuxLandlockAccess::WriteFile,
                    LinuxLandlockAccess::MakeDir,
                    LinuxLandlockAccess::RemoveFile,
                    LinuxLandlockAccess::RemoveDir,
                ]);
            }
            rules.push(LinuxLandlockRule {
                path: mount.host_path.display().to_string(),
                access,
                reason: format!("explicit {:?} mount", mount.kind),
            });
        }

        Ok(LinuxLandlockPlan {
            schema_version: 1,
            ruleset_name: format!("agentbox-{}", spec.id),
            rules,
            default_deny: true,
            requires_loader: true,
            requires_linux: true,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn apply(
        _plan: &LinuxLandlockPlan,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Landlock rules are modeled but not wired to a Linux loader yet".into())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(
        _plan: &LinuxLandlockPlan,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Linux Landlock is only available on Linux".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxNftablesPlan {
    pub schema_version: i64,
    pub table_name: String,
    pub chain_name: String,
    pub mode: NetworkMode,
    pub default_policy: LinuxNftablesDefaultPolicy,
    pub allow_localhost: bool,
    pub allowed_domains: Vec<String>,
    pub denied_domains: Vec<String>,
    pub planned_rules: Vec<LinuxNftablesRulePlan>,
    pub domain_rules_require_resolver: bool,
    pub requires_nftables: bool,
    pub requires_linux: bool,
    pub enforcement_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinuxNftablesDefaultPolicy {
    Drop,
    AcceptWithGuardrails,
    RequireApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxNftablesRulePlan {
    pub action: LinuxNftablesRuleAction,
    pub selector: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinuxNftablesRuleAction {
    Accept,
    Drop,
    ApprovalRequired,
    Observe,
}

pub struct LinuxNftablesPolicyDescriptor;

impl LinuxNftablesPolicyDescriptor {
    pub fn plan(spec: &MinipodSpec) -> Result<LinuxNftablesPlan, RuntimeError> {
        if spec.id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "nftables policy session id cannot be empty".into(),
            ));
        }

        let mut planned_rules = Vec::new();
        if spec.network.allow_localhost {
            planned_rules.push(LinuxNftablesRulePlan {
                action: LinuxNftablesRuleAction::Accept,
                selector: "ip daddr 127.0.0.0/8; ip6 daddr ::1".into(),
                reason: "manifest allows loopback service access".into(),
            });
        } else {
            planned_rules.push(LinuxNftablesRulePlan {
                action: LinuxNftablesRuleAction::Drop,
                selector: "ip daddr 127.0.0.0/8; ip6 daddr ::1".into(),
                reason: "manifest disables loopback service access".into(),
            });
        }
        for domain in &spec.network.denied_domains {
            planned_rules.push(LinuxNftablesRulePlan {
                action: LinuxNftablesRuleAction::Drop,
                selector: format!("domain:{domain}"),
                reason: "manifest domain denylist; requires resolver/ipset compilation".into(),
            });
        }
        for domain in &spec.network.allowed_domains {
            planned_rules.push(LinuxNftablesRulePlan {
                action: LinuxNftablesRuleAction::Accept,
                selector: format!("domain:{domain}"),
                reason: "manifest domain allowlist; requires resolver/ipset compilation".into(),
            });
        }

        let default_policy = match spec.network.mode {
            NetworkMode::None | NetworkMode::DenyByDefault | NetworkMode::AllowListed => {
                LinuxNftablesDefaultPolicy::Drop
            }
            NetworkMode::ApprovalOnFirstContact => LinuxNftablesDefaultPolicy::RequireApproval,
            NetworkMode::OpenWithGuardrails | NetworkMode::Host => {
                LinuxNftablesDefaultPolicy::AcceptWithGuardrails
            }
        };

        Ok(LinuxNftablesPlan {
            schema_version: 1,
            table_name: format!("agentbox_{}", sanitize_nft_name(&spec.id)),
            chain_name: "agentpod_egress".into(),
            mode: spec.network.mode.clone(),
            default_policy,
            allow_localhost: spec.network.allow_localhost,
            allowed_domains: spec.network.allowed_domains.clone(),
            denied_domains: spec.network.denied_domains.clone(),
            planned_rules,
            domain_rules_require_resolver: true,
            requires_nftables: true,
            requires_linux: true,
            enforcement_claim:
                "nftables policy descriptor only; no packet/domain denial proof is wired".into(),
        })
    }
}

fn sanitize_nft_name(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        "session".into()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxIsolationBenchmarkPlan {
    pub schema_version: i64,
    pub iterations: u32,
    pub command_argv: Vec<String>,
    pub layers: Vec<LinuxIsolationBenchmarkLayer>,
    pub live_env_var: String,
    pub requires_linux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxIsolationBenchmarkLayer {
    pub name: String,
    pub argv: Vec<String>,
    pub expected_boundary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxAgentPodExecutionPlan {
    pub schema_version: i64,
    pub provider: String,
    pub session_id: String,
    pub command_argv: Vec<String>,
    pub composed_argv: Vec<String>,
    pub user_namespace: LinuxUserNamespacePlan,
    pub mount_namespace: LinuxMountNamespacePlan,
    pub pid_namespace: LinuxPidNamespacePlan,
    pub cgroup: LinuxCgroupV2Plan,
    pub seccomp: LinuxSeccompPlan,
    pub landlock: LinuxLandlockPlan,
    pub nftables: LinuxNftablesPlan,
    pub live_env_var: String,
    pub live_execution_enabled: bool,
    pub requires_linux: bool,
    pub security_claim: String,
}

impl LinuxAgentPodExecutionPlan {
    pub fn from_minipod_spec(
        spec: &MinipodSpec,
        command: &ExecCommand,
    ) -> Result<Self, RuntimeError> {
        if command.argv.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "Linux AgentPod execution command cannot be empty".into(),
            ));
        }

        let user_namespace = LinuxUserNamespaceLauncher::plan(command)?;
        let mount_namespace = LinuxMountNamespaceLauncher::plan(spec)?;
        let pid_namespace = LinuxPidNamespaceLauncher::plan(command)?;
        let cgroup = LinuxCgroupV2Limiter::plan(&spec.id, &spec.resources)?;
        let seccomp = LinuxSeccompProfileLoader::plan(&spec.seccomp)?;
        let landlock = LinuxLandlockRuleset::plan(spec)?;
        let nftables = LinuxNftablesPolicyDescriptor::plan(spec)?;

        let mut composed_argv = vec![
            "unshare".to_string(),
            "--user".to_string(),
            "--map-root-user".to_string(),
            "--setgroups=deny".to_string(),
            "--mount".to_string(),
            "--propagation".to_string(),
            mount_namespace.propagation.clone(),
        ];
        composed_argv.extend(LinuxPidNamespaceLauncher::command_args(&pid_namespace));

        Ok(Self {
            schema_version: 1,
            provider: "agentpod-linux".into(),
            session_id: spec.id.clone(),
            command_argv: command.argv.clone(),
            composed_argv,
            user_namespace,
            mount_namespace,
            pid_namespace,
            cgroup,
            seccomp,
            landlock,
            nftables,
            live_env_var: "AGENTBOX_LINUX_NATIVE".into(),
            live_execution_enabled: linux_native_execution_enabled(),
            requires_linux: true,
            security_claim: "prototype namespace/resource execution plan; not a complete sandbox"
                .into(),
        })
    }

    pub fn runnable_on_current_host(&self) -> bool {
        cfg!(target_os = "linux") && self.live_execution_enabled
    }
}

pub struct LinuxAgentPodPrototypeExecutor;

impl LinuxAgentPodPrototypeExecutor {
    pub fn execute(
        spec: &MinipodSpec,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(spec, command)?;
        if !plan.live_execution_enabled {
            return Err(RuntimeError::Unavailable(
                "Linux AgentPod prototype execution requires AGENTBOX_LINUX_NATIVE=1".into(),
            ));
        }

        Self::execute_plan(&plan, command)
    }

    #[cfg(target_os = "linux")]
    fn execute_plan(
        plan: &LinuxAgentPodExecutionPlan,
        command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        if !plan.runnable_on_current_host() {
            return Err(RuntimeError::Unavailable(
                "Linux AgentPod prototype execution is not runnable on this host".into(),
            ));
        }

        let (binary, args) = plan.composed_argv.split_first().ok_or_else(|| {
            RuntimeError::ManifestRejected("Linux AgentPod execution argv cannot be empty".into())
        })?;
        let start = std::time::Instant::now();
        let mut process = std::process::Command::new(binary);
        process.args(args);
        if let Some(working_dir) = &command.working_dir {
            process.current_dir(working_dir);
        }
        for (key, value) in &command.env {
            process.env(key, value);
        }

        let output = process.output().map_err(|err| {
            RuntimeError::ExecFailed(format!("Linux AgentPod prototype exec failed: {err}"))
        })?;

        Ok(CommandResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration_ms: start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn execute_plan(
        _plan: &LinuxAgentPodExecutionPlan,
        _command: &ExecCommand,
    ) -> Result<CommandResult, RuntimeError> {
        Err(RuntimeError::Unavailable(
            "Linux AgentPod prototype execution is only available on Linux".into(),
        ))
    }
}

impl LinuxIsolationBenchmarkPlan {
    pub fn from_minipod_spec(
        spec: &MinipodSpec,
        command: &ExecCommand,
        iterations: u32,
    ) -> Result<Self, RuntimeError> {
        if iterations == 0 {
            return Err(RuntimeError::ManifestRejected(
                "Linux isolation benchmark iterations cannot be zero".into(),
            ));
        }
        if command.argv.is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "Linux isolation benchmark command cannot be empty".into(),
            ));
        }

        let user = LinuxUserNamespaceLauncher::plan(command)?;
        let mount = LinuxMountNamespaceLauncher::plan(spec)?;
        let pid = LinuxPidNamespaceLauncher::plan(command)?;
        let cgroup = LinuxCgroupV2Limiter::plan(&spec.id, &spec.resources)?;
        let seccomp = LinuxSeccompProfileLoader::plan(&spec.seccomp)?;
        let landlock = LinuxLandlockRuleset::plan(spec)?;
        let nftables = LinuxNftablesPolicyDescriptor::plan(spec)?;

        let mut user_mount_pid = vec![
            "unshare".to_string(),
            "--user".to_string(),
            "--map-root-user".to_string(),
            "--setgroups=deny".to_string(),
            "--mount".to_string(),
            "--propagation".to_string(),
            mount.propagation.clone(),
        ];
        user_mount_pid.extend(LinuxPidNamespaceLauncher::command_args(&pid));

        Ok(Self {
            schema_version: 1,
            iterations,
            command_argv: command.argv.clone(),
            layers: vec![
                LinuxIsolationBenchmarkLayer {
                    name: "direct".into(),
                    argv: command.argv.clone(),
                    expected_boundary: "baseline host process startup".into(),
                },
                LinuxIsolationBenchmarkLayer {
                    name: "userns".into(),
                    argv: prefixed_unshare_args(
                        &["--user", "--map-root-user", "--setgroups=deny", "--"],
                        &user.command_argv,
                    ),
                    expected_boundary: "rootless user namespace".into(),
                },
                LinuxIsolationBenchmarkLayer {
                    name: "mntns".into(),
                    argv: prefixed_command(
                        "unshare",
                        LinuxMountNamespaceLauncher::command_args(&mount, command),
                    ),
                    expected_boundary: "private mount namespace metadata boundary".into(),
                },
                LinuxIsolationBenchmarkLayer {
                    name: "pidns".into(),
                    argv: prefixed_command(
                        "unshare",
                        LinuxPidNamespaceLauncher::command_args(&pid),
                    ),
                    expected_boundary: "forked PID namespace with proc mount".into(),
                },
                LinuxIsolationBenchmarkLayer {
                    name: "user-mount-pid".into(),
                    argv: user_mount_pid,
                    expected_boundary: "combined rootless namespace startup path".into(),
                },
                LinuxIsolationBenchmarkLayer {
                    name: "cgroup-plan".into(),
                    argv: cgroup
                        .writes()
                        .into_iter()
                        .map(|write| format!("{}={}", write.file, write.value))
                        .collect(),
                    expected_boundary: "cgroups v2 resource write plan only".into(),
                },
                LinuxIsolationBenchmarkLayer {
                    name: "seccomp-plan".into(),
                    argv: seccomp
                        .syscall_rules
                        .iter()
                        .map(|rule| rule.syscall.clone())
                        .collect(),
                    expected_boundary: "seccomp loader plan only".into(),
                },
                LinuxIsolationBenchmarkLayer {
                    name: "landlock-plan".into(),
                    argv: landlock
                        .rules
                        .iter()
                        .map(|rule| rule.path.clone())
                        .collect(),
                    expected_boundary: "Landlock ruleset plan only".into(),
                },
                LinuxIsolationBenchmarkLayer {
                    name: "nftables-plan".into(),
                    argv: nftables
                        .planned_rules
                        .iter()
                        .map(|rule| rule.selector.clone())
                        .collect(),
                    expected_boundary: "nftables egress policy descriptor only".into(),
                },
            ],
            live_env_var: "AGENTBOX_LINUX_BENCHMARK".into(),
            requires_linux: true,
        })
    }
}

fn prefixed_unshare_args(prefix: &[&str], command_argv: &[String]) -> Vec<String> {
    let mut argv = vec!["unshare".to_string()];
    argv.extend(prefix.iter().map(|value| (*value).to_string()));
    argv.extend(command_argv.iter().cloned());
    argv
}

fn prefixed_command(binary: &str, args: Vec<String>) -> Vec<String> {
    let mut argv = vec![binary.to_string()];
    argv.extend(args);
    argv
}

pub fn linux_native_execution_enabled() -> bool {
    matches!(
        std::env::var("AGENTBOX_LINUX_NATIVE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn cpu_shares_to_cgroup_weight(cpu_shares: u32) -> u32 {
    let weight = ((cpu_shares.max(2) as u64 * 10_000) / 262_144).max(1);
    weight.min(10_000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::{MountKind, MountRule};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn command(argv: &[&str]) -> ExecCommand {
        ExecCommand {
            argv: argv.iter().map(|value| value.to_string()).collect(),
            working_dir: Some("/workspace".into()),
            env: HashMap::from([("AGENTBOX_TEST".into(), "1".into())]),
            timeout_seconds: None,
        }
    }

    #[test]
    fn user_namespace_plan_is_rootless_and_linux_scoped() {
        let command = command(&["/bin/echo", "hello"]);

        let plan = LinuxUserNamespaceLauncher::plan(&command).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.command_argv, vec!["/bin/echo", "hello"]);
        assert!(plan.map_root_user);
        assert!(plan.deny_setgroups);
        assert!(plan.requires_linux);
        assert_eq!(plan.uid_map, "0 current-user 1");
        assert_eq!(plan.gid_map, "0 current-group 1");
    }

    #[test]
    fn user_namespace_plan_rejects_empty_commands() {
        let err = LinuxUserNamespaceLauncher::plan(&command(&[])).unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn user_namespace_spawn_is_explicitly_linux_only() {
        let err = LinuxUserNamespaceLauncher::spawn(&command(&["/bin/echo", "hello"])).unwrap_err();

        assert!(err.to_string().contains("only available on Linux"));
    }

    #[test]
    fn mount_namespace_plan_maps_workspace_and_read_only_mounts() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.filesystem.workspace_guest_path = "/workspace".into();
        spec.filesystem.mounts.push(MountRule {
            host_path: PathBuf::from("/tmp/agentbox-fixtures"),
            guest_path: "/fixtures".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::ReadOnlyHost,
        });

        let plan = LinuxMountNamespaceLauncher::plan(&spec).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.workspace_host_path, "/tmp/agentbox-work");
        assert_eq!(plan.workspace_guest_path, "/workspace");
        assert_eq!(plan.propagation, "private");
        assert!(plan.requires_linux);
        assert_eq!(plan.read_only_mounts.len(), 1);
        assert_eq!(plan.read_only_mounts[0].guest_path, "/fixtures");
        assert!(plan.read_only_mounts[0].read_only);
    }

    #[test]
    fn mount_namespace_command_args_wrap_command_with_unshare_mount() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let plan = LinuxMountNamespaceLauncher::plan(&spec).unwrap();

        let args = LinuxMountNamespaceLauncher::command_args(&plan, &command(&["/bin/true"]));

        assert_eq!(
            args,
            vec!["--mount", "--propagation", "private", "--", "/bin/true"]
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn mount_namespace_spawn_is_explicitly_linux_only() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let err = LinuxMountNamespaceLauncher::spawn(&spec, &command(&["/bin/true"])).unwrap_err();

        assert!(err.to_string().contains("only available on Linux"));
    }

    #[test]
    fn pid_namespace_plan_is_forked_and_proc_scoped() {
        let command = command(&["/bin/sleep", "1"]);

        let plan = LinuxPidNamespaceLauncher::plan(&command).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.command_argv, vec!["/bin/sleep", "1"]);
        assert!(plan.fork_init);
        assert!(plan.mount_proc);
        assert_eq!(plan.kill_signal, "TERM");
        assert!(plan.requires_linux);
    }

    #[test]
    fn pid_namespace_command_args_wrap_command_with_unshare_pid() {
        let plan = LinuxPidNamespaceLauncher::plan(&command(&["/bin/true"])).unwrap();

        let args = LinuxPidNamespaceLauncher::command_args(&plan);

        assert_eq!(
            args,
            vec!["--pid", "--fork", "--mount-proc", "--", "/bin/true"]
        );
    }

    #[test]
    fn pid_namespace_plan_rejects_empty_commands() {
        let err = LinuxPidNamespaceLauncher::plan(&command(&[])).unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn pid_namespace_spawn_is_explicitly_linux_only() {
        let err = LinuxPidNamespaceLauncher::spawn(&command(&["/bin/true"])).unwrap_err();

        assert!(err.to_string().contains("only available on Linux"));
    }

    #[test]
    fn cgroup_v2_plan_maps_resource_limits_to_filesystem_writes() {
        let resources = ResourcePolicy {
            memory_bytes: 536_870_912,
            cpu_shares: 2048,
            timeout_seconds: Some(30),
        };

        let plan = LinuxCgroupV2Limiter::plan("01agentboxsession", &resources).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.cgroup_name, "agentbox-01agentboxsession");
        assert_eq!(plan.memory_max, "536870912");
        assert_eq!(plan.cpu_weight, 78);
        assert!(plan.requires_linux);
        assert_eq!(
            plan.writes(),
            vec![
                LinuxCgroupV2Write {
                    file: "memory.max".into(),
                    value: "536870912".into(),
                },
                LinuxCgroupV2Write {
                    file: "cpu.weight".into(),
                    value: "78".into(),
                },
            ]
        );
    }

    #[test]
    fn cgroup_v2_plan_rejects_invalid_limits() {
        let resources = ResourcePolicy {
            memory_bytes: 0,
            ..ResourcePolicy::default()
        };

        let err = LinuxCgroupV2Limiter::plan("01agentboxsession", &resources).unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn cgroup_v2_apply_is_explicitly_linux_only() {
        let plan =
            LinuxCgroupV2Limiter::plan("01agentboxsession", &ResourcePolicy::default()).unwrap();
        let err = LinuxCgroupV2Limiter::apply(std::path::Path::new("/sys/fs/cgroup"), &plan, 1)
            .unwrap_err();

        assert!(err.to_string().contains("only available on Linux"));
    }

    #[test]
    fn seccomp_plan_preserves_disabled_default_without_claiming_loader() {
        let profile = SeccompProfile::default();

        let plan = LinuxSeccompProfileLoader::plan(&profile).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert!(!plan.enabled);
        assert_eq!(plan.default_action, SeccompAction::Allow);
        assert!(plan.syscall_rules.is_empty());
        assert!(plan.oci_profile.is_none());
        assert!(!plan.requires_loader);
        assert!(plan.requires_linux);
    }

    #[test]
    fn seccomp_plan_maps_targeted_syscall_rules() {
        let profile = SeccompProfile::deny_syscalls(
            &["ptrace", "bpf"],
            "debugging and kernel instrumentation require explicit support",
        );

        let plan = LinuxSeccompProfileLoader::plan(&profile).unwrap();

        assert!(plan.enabled);
        assert!(plan.requires_loader);
        assert_eq!(plan.syscall_rules.len(), 2);
        assert_eq!(plan.syscall_rules[0].syscall, "ptrace");
        assert_eq!(
            plan.syscall_rules[0].action,
            SeccompAction::Errno(libc::EPERM)
        );
        let oci_profile = plan.oci_profile.as_ref().unwrap();
        assert_eq!(oci_profile.default_action, "SCMP_ACT_ALLOW");
        assert!(!oci_profile.architectures.is_empty());
        assert_eq!(oci_profile.syscalls[0].names, vec!["ptrace"]);
        assert_eq!(oci_profile.syscalls[0].action, "SCMP_ACT_ERRNO");
        assert_eq!(oci_profile.syscalls[0].errno_ret, Some(libc::EPERM));
        assert!(oci_profile.syscalls[0].comment.contains("debugging"));
        let oci_json = serde_json::to_value(oci_profile).unwrap();
        assert_eq!(oci_json["defaultAction"], "SCMP_ACT_ALLOW");
        assert_eq!(oci_json["syscalls"][0]["errnoRet"], libc::EPERM);
        assert!(oci_json.get("default_action").is_none());
    }

    #[test]
    fn seccomp_plan_rejects_enabled_empty_profiles() {
        let profile = SeccompProfile {
            enabled: true,
            ..SeccompProfile::default()
        };

        let err = LinuxSeccompProfileLoader::plan(&profile).unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn seccomp_apply_is_explicitly_linux_only() {
        let plan = LinuxSeccompProfileLoader::plan(&SeccompProfile::default()).unwrap();
        let err = LinuxSeccompProfileLoader::apply(&plan).unwrap_err();

        assert!(err.to_string().contains("only available on Linux"));
    }

    #[test]
    fn landlock_plan_allows_workspace_and_explicit_mounts_only() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.filesystem.mounts.push(MountRule {
            host_path: PathBuf::from("/tmp/agentbox-fixtures"),
            guest_path: "/fixtures".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::ReadOnlyHost,
        });

        let plan = LinuxLandlockRuleset::plan(&spec).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert!(plan.default_deny);
        assert!(plan.requires_loader);
        assert_eq!(plan.rules.len(), 2);
        assert_eq!(plan.rules[0].path, "/tmp/agentbox-work");
        assert!(plan.rules[0]
            .access
            .contains(&LinuxLandlockAccess::WriteFile));
        assert_eq!(plan.rules[1].path, "/tmp/agentbox-fixtures");
        assert!(plan.rules[1]
            .access
            .contains(&LinuxLandlockAccess::ReadFile));
        assert!(!plan.rules[1]
            .access
            .contains(&LinuxLandlockAccess::WriteFile));
    }

    #[test]
    fn landlock_plan_rejects_empty_workspace() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.filesystem.workspace_host_path = PathBuf::new();

        let err = LinuxLandlockRuleset::plan(&spec).unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }

    #[test]
    fn nftables_plan_describes_domain_and_loopback_policy_without_claiming_enforcement() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.id = "agentpod.test/session-1".into();
        spec.network.mode = NetworkMode::AllowListed;
        spec.network.allow_localhost = false;
        spec.network.allowed_domains = vec!["api.openai.com".into()];
        spec.network.denied_domains = vec!["metadata.google.internal".into()];

        let plan = LinuxNftablesPolicyDescriptor::plan(&spec).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.table_name, "agentbox_agentpod_test_session_1");
        assert_eq!(plan.chain_name, "agentpod_egress");
        assert_eq!(plan.default_policy, LinuxNftablesDefaultPolicy::Drop);
        assert!(!plan.allow_localhost);
        assert!(plan.domain_rules_require_resolver);
        assert!(plan.requires_nftables);
        assert!(plan.requires_linux);
        assert!(plan.enforcement_claim.contains("descriptor only"));
        assert!(plan.planned_rules.iter().any(|rule| {
            rule.action == LinuxNftablesRuleAction::Drop && rule.selector.contains("127.0.0.0/8")
        }));
        assert!(plan.planned_rules.iter().any(|rule| {
            rule.action == LinuxNftablesRuleAction::Drop
                && rule.selector == "domain:metadata.google.internal"
        }));
        assert!(plan.planned_rules.iter().any(|rule| {
            rule.action == LinuxNftablesRuleAction::Accept
                && rule.selector == "domain:api.openai.com"
        }));
    }

    #[test]
    fn nftables_plan_rejects_empty_session_ids() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.id = " ".into();

        let err = LinuxNftablesPolicyDescriptor::plan(&spec).unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn landlock_apply_is_explicitly_linux_only() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let plan = LinuxLandlockRuleset::plan(&spec).unwrap();
        let err = LinuxLandlockRuleset::apply(&plan).unwrap_err();

        assert!(err.to_string().contains("only available on Linux"));
    }

    #[test]
    fn rootless_execution_plan_composes_linux_kernel_boundaries() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.filesystem.mounts.push(MountRule {
            host_path: PathBuf::from("/tmp/agentbox-fixtures"),
            guest_path: "/fixtures".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::ReadOnlyHost,
        });
        spec.seccomp = SeccompProfile::deny_syscalls(
            &["ptrace", "bpf"],
            "debugging and kernel instrumentation require explicit support",
        );
        let command = command(&["/bin/true"]);

        let user = LinuxUserNamespaceLauncher::plan(&command).unwrap();
        let mount = LinuxMountNamespaceLauncher::plan(&spec).unwrap();
        let pid = LinuxPidNamespaceLauncher::plan(&command).unwrap();
        let cgroup = LinuxCgroupV2Limiter::plan(&spec.id, &spec.resources).unwrap();
        let seccomp = LinuxSeccompProfileLoader::plan(&spec.seccomp).unwrap();
        let landlock = LinuxLandlockRuleset::plan(&spec).unwrap();

        assert!(user.map_root_user);
        assert!(user.deny_setgroups);
        assert_eq!(mount.propagation, "private");
        assert!(pid.fork_init);
        assert!(pid.mount_proc);
        assert_eq!(cgroup.cgroup_name, format!("agentbox-{}", spec.id));
        assert!(seccomp.requires_loader);
        assert!(landlock.default_deny);
        assert!(landlock.requires_loader);
        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();
        assert_eq!(plan.nftables.chain_name, "agentpod_egress");
        assert!(plan.nftables.requires_nftables);
    }

    #[test]
    fn rootless_execution_live_path_is_not_claimed_by_default() {
        let live_enabled = matches!(
            std::env::var("AGENTBOX_LINUX_LIVE_TESTS").as_deref(),
            Ok("1")
        );
        if live_enabled && !linux_live_tests_can_run_here() {
            panic!("live rootless execution can only run on Linux");
        }
    }

    fn linux_live_tests_can_run_here() -> bool {
        cfg!(target_os = "linux")
    }

    #[test]
    fn isolation_benchmark_plan_lists_measured_and_planned_boundaries() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.filesystem.mounts.push(MountRule {
            host_path: PathBuf::from("/tmp/agentbox-fixtures"),
            guest_path: "/fixtures".into(),
            mode: MountMode::ReadOnly,
            kind: MountKind::ReadOnlyHost,
        });
        spec.seccomp = SeccompProfile::deny_syscalls(
            &["ptrace", "bpf"],
            "debugging and kernel instrumentation require explicit support",
        );

        let plan =
            LinuxIsolationBenchmarkPlan::from_minipod_spec(&spec, &command(&["/bin/true"]), 25)
                .unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.iterations, 25);
        assert_eq!(plan.live_env_var, "AGENTBOX_LINUX_BENCHMARK");
        assert!(plan.requires_linux);
        assert_eq!(
            plan.layers
                .iter()
                .map(|layer| layer.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "direct",
                "userns",
                "mntns",
                "pidns",
                "user-mount-pid",
                "cgroup-plan",
                "seccomp-plan",
                "landlock-plan",
                "nftables-plan",
            ]
        );
        assert_eq!(
            plan.layers[1].argv,
            vec![
                "unshare",
                "--user",
                "--map-root-user",
                "--setgroups=deny",
                "--",
                "/bin/true"
            ]
        );
        assert!(plan.layers[4].argv.contains(&"--pid".to_string()));
        assert!(plan.layers[5]
            .expected_boundary
            .contains("resource write plan only"));
        assert_eq!(plan.layers[6].argv, vec!["ptrace", "bpf"]);
        assert!(plan.layers[8]
            .argv
            .iter()
            .any(|arg| arg.contains("domain:")));
    }

    #[test]
    fn agentpod_execution_plan_composes_linux_native_boundaries() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let command = command(&["/bin/true"]);

        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.provider, "agentpod-linux");
        assert_eq!(plan.session_id, spec.id);
        assert_eq!(plan.command_argv, vec!["/bin/true"]);
        assert_eq!(plan.live_env_var, "AGENTBOX_LINUX_NATIVE");
        assert!(plan.requires_linux);
        assert!(plan.composed_argv.starts_with(&[
            "unshare".into(),
            "--user".into(),
            "--map-root-user".into(),
            "--setgroups=deny".into(),
            "--mount".into(),
        ]));
        assert!(plan
            .composed_argv
            .windows(2)
            .any(|window| window == ["--pid", "--fork"]));
        assert!(plan.security_claim.contains("prototype"));
        assert_eq!(plan.cgroup.cgroup_name, format!("agentbox-{}", spec.id));
        assert!(plan.landlock.default_deny);
        assert!(!plan.seccomp.requires_loader);
    }

    #[test]
    fn agentpod_execution_plan_rejects_empty_commands() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");

        let err = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command(&[])).unwrap_err();

        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn agentpod_execution_plan_is_not_live_without_explicit_env_gate() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let command = command(&["/bin/true"]);

        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();

        if std::env::var("AGENTBOX_LINUX_NATIVE").is_err() {
            assert!(!plan.live_execution_enabled);
            assert!(!plan.runnable_on_current_host());
        }
    }

    #[test]
    fn prototype_executor_refuses_without_native_env_gate() {
        if std::env::var("AGENTBOX_LINUX_NATIVE").is_ok() {
            return;
        }
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let command = command(&["/bin/true"]);

        let err = LinuxAgentPodPrototypeExecutor::execute(&spec, &command).unwrap_err();

        assert!(err.to_string().contains("AGENTBOX_LINUX_NATIVE"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn prototype_executor_plan_is_linux_only_on_non_linux_hosts() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let command = command(&["/bin/true"]);
        let mut plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();
        plan.live_execution_enabled = true;

        let err = LinuxAgentPodPrototypeExecutor::execute_plan(&plan, &command).unwrap_err();

        assert!(err.to_string().contains("only available on Linux"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prototype_executor_live_smoke_runs_only_when_enabled() {
        if !matches!(std::env::var("AGENTBOX_LINUX_NATIVE").as_deref(), Ok("1")) {
            return;
        }
        let spec = MinipodSpec::for_agent_task("hermes", std::env::temp_dir());
        let command = command(&["/bin/true"]);

        let result = LinuxAgentPodPrototypeExecutor::execute(&spec, &command).unwrap();

        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn isolation_benchmark_plan_rejects_empty_inputs() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");

        let zero_iters =
            LinuxIsolationBenchmarkPlan::from_minipod_spec(&spec, &command(&["/bin/true"]), 0)
                .unwrap_err();
        let empty_command =
            LinuxIsolationBenchmarkPlan::from_minipod_spec(&spec, &command(&[]), 1).unwrap_err();

        assert!(matches!(zero_iters, RuntimeError::ManifestRejected(_)));
        assert!(matches!(empty_command, RuntimeError::ManifestRejected(_)));
    }
}
