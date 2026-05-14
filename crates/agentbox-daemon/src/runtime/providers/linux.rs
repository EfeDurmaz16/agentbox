use serde::{Deserialize, Serialize};

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::{ExecCommand, MinipodSpec, MountMode};

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
}
