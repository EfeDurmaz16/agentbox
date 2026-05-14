use serde::{Deserialize, Serialize};

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::ExecCommand;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
}
