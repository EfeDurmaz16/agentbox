use serde::{Deserialize, Serialize};

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::{
    ExecCommand, MinipodSpec, MountMode, ResourcePolicy, SeccompAction, SeccompProfile,
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
    pub requires_loader: bool,
    pub requires_linux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSeccompRule {
    pub syscall: String,
    pub action: SeccompAction,
    pub reason: String,
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
            requires_loader: profile.enabled,
            requires_linux: true,
        }
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
}
