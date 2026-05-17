use serde::{Deserialize, Serialize};

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::{
    CommandResult, ExecCommand, MinipodSpec, MountMode, NetworkMode, ResourcePolicy, SeccompAction,
    SeccompProfile, WorkspaceOverlayMode,
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
    pub workspace_bind_mount_wired: bool,
    pub workspace_mount_claim: String,
    pub overlayfs: Option<LinuxOverlayFsWorkspacePlan>,
    pub read_only_mounts: Vec<LinuxMountNamespaceMount>,
    pub propagation: String,
    pub requires_linux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxOverlayFsWorkspacePlan {
    pub lower_host_path: String,
    pub upper_host_path: String,
    pub work_host_path: String,
    pub merged_guest_path: String,
    pub mode: WorkspaceOverlayMode,
    pub review_required: bool,
    pub requires_overlayfs: bool,
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

        let overlayfs = spec
            .filesystem
            .workspace_overlay
            .is_enabled()
            .then(|| {
                let overlay = &spec.filesystem.workspace_overlay;
                Some(LinuxOverlayFsWorkspacePlan {
                    lower_host_path: spec.filesystem.workspace_host_path.display().to_string(),
                    upper_host_path: overlay.upper_host_path.as_ref()?.display().to_string(),
                    work_host_path: overlay.work_host_path.as_ref()?.display().to_string(),
                    merged_guest_path: overlay.guest_path.clone(),
                    mode: overlay.mode.clone(),
                    review_required: matches!(overlay.mode, WorkspaceOverlayMode::ReviewRequired),
                    requires_overlayfs: true,
                })
            })
            .flatten();

        let (workspace_bind_mount_wired, workspace_mount_claim) = if overlayfs.is_some() {
            (
                true,
                "agentbox-linux-runner mounts the review workspace with overlayfs inside the mount namespace before applying Landlock/seccomp"
                    .to_string(),
            )
        } else {
            (
                true,
                "agentbox-linux-runner bind-mounts the host workspace inside the mount namespace before applying Landlock/seccomp"
                    .to_string(),
            )
        };

        Self {
            schema_version: 1,
            workspace_host_path: spec.filesystem.workspace_host_path.display().to_string(),
            workspace_guest_path: spec.filesystem.workspace_guest_path.clone(),
            workspace_bind_mount_wired,
            workspace_mount_claim,
            overlayfs,
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

    #[cfg(target_os = "linux")]
    pub fn cleanup(
        root: &std::path::Path,
        plan: &LinuxCgroupV2Plan,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cgroup_dir = root.join(&plan.cgroup_name);
        for write in plan.writes() {
            let _ = std::fs::remove_file(cgroup_dir.join(write.file));
        }
        let _ = std::fs::remove_file(cgroup_dir.join("cgroup.procs"));
        match std::fs::remove_dir(&cgroup_dir) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(
        _root: &std::path::Path,
        _plan: &LinuxCgroupV2Plan,
        _pid: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Linux cgroups v2 are only available on Linux".into())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn cleanup(
        _root: &std::path::Path,
        _plan: &LinuxCgroupV2Plan,
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
    #[serde(default)]
    pub import_descriptor: LinuxSeccompProfileImportDescriptor,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSeccompProfileImportDescriptor {
    pub schema_version: i64,
    pub supported_formats: Vec<String>,
    pub generated_oci_profile: bool,
    pub import_enabled: bool,
    pub loader_scope: String,
    pub claim_boundary: String,
}

impl Default for LinuxSeccompProfileImportDescriptor {
    fn default() -> Self {
        Self::for_generated_profile(false)
    }
}

impl LinuxSeccompPlan {
    pub fn from_profile(profile: &SeccompProfile) -> Self {
        let enabled = profile.enabled;
        let oci_profile = enabled.then(|| LinuxSeccompOciProfile {
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
        });
        Self {
            schema_version: 1,
            enabled,
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
            import_descriptor: LinuxSeccompProfileImportDescriptor::for_generated_profile(
                oci_profile.is_some(),
            ),
            oci_profile,
            requires_loader: enabled,
            requires_linux: true,
        }
    }
}

impl LinuxSeccompProfileImportDescriptor {
    fn for_generated_profile(generated_oci_profile: bool) -> Self {
        Self {
            schema_version: 1,
            supported_formats: vec!["oci-seccomp-v1-json".into(), "libseccomp-json".into()],
            generated_oci_profile,
            import_enabled: false,
            loader_scope: "prototype BPF loader accepts explicit syscall deny rules generated by Agentbox".into(),
            claim_boundary: "external OCI/libseccomp profile import is described but not accepted or applied yet".into(),
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
    pub fn apply(plan: &LinuxSeccompPlan) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(filter) = compile_linux_seccomp_filter(plan)? else {
            return Ok(());
        };
        install_linux_seccomp_filter(&filter)?;
        Ok(())
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
    pub path_policy: LinuxLandlockPathPolicyPlan,
    pub handled_access_mask: u64,
    pub default_deny: bool,
    pub requires_loader: bool,
    pub requires_linux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxLandlockRule {
    pub path: String,
    pub access: Vec<LinuxLandlockAccess>,
    pub reason: String,
    pub access_mask: u64,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxLandlockPathPolicyPlan {
    pub schema_version: i64,
    pub access_classes: Vec<LinuxLandlockAccessClassPlan>,
    pub current_loader_scope: String,
    pub claim_boundary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxLandlockAccessClassPlan {
    pub class: String,
    pub planned: bool,
    pub enforced_by_prototype_loader: bool,
    pub access: Vec<LinuxLandlockAccess>,
    pub reason: String,
}

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;

const LANDLOCK_ABI_V1_FS_ACCESS_MASK: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG;
const LANDLOCK_PROTOTYPE_HANDLED_FS_ACCESS_MASK: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG;

impl LinuxLandlockAccess {
    fn access_mask(&self) -> u64 {
        match self {
            Self::Execute => LANDLOCK_ACCESS_FS_EXECUTE,
            Self::WriteFile => LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG,
            Self::ReadFile => LANDLOCK_ACCESS_FS_READ_FILE,
            Self::ReadDir => LANDLOCK_ACCESS_FS_READ_DIR,
            Self::RemoveDir => LANDLOCK_ACCESS_FS_REMOVE_DIR,
            Self::RemoveFile => LANDLOCK_ACCESS_FS_REMOVE_FILE,
            Self::MakeDir => LANDLOCK_ACCESS_FS_MAKE_DIR,
        }
    }
}

impl LinuxLandlockPathPolicyPlan {
    pub fn prototype_loader_scope() -> Self {
        Self {
            schema_version: 1,
            access_classes: vec![
                LinuxLandlockAccessClassPlan {
                    class: "read".into(),
                    planned: true,
                    enforced_by_prototype_loader: false,
                    access: vec![LinuxLandlockAccess::ReadFile, LinuxLandlockAccess::ReadDir],
                    reason: "planned read path policy; prototype loader does not yet handle read access".into(),
                },
                LinuxLandlockAccessClassPlan {
                    class: "execute".into(),
                    planned: true,
                    enforced_by_prototype_loader: false,
                    access: vec![LinuxLandlockAccess::Execute],
                    reason: "planned execute path policy; prototype loader must run after launcher sequencing before handling execute access".into(),
                },
                LinuxLandlockAccessClassPlan {
                    class: "write".into(),
                    planned: true,
                    enforced_by_prototype_loader: true,
                    access: vec![LinuxLandlockAccess::WriteFile],
                    reason: "prototype loader handles write-file path-beneath access".into(),
                },
                LinuxLandlockAccessClassPlan {
                    class: "create".into(),
                    planned: true,
                    enforced_by_prototype_loader: true,
                    access: vec![LinuxLandlockAccess::MakeDir],
                    reason: "prototype loader handles create access covered by ABI v1 make-dir and make-reg bits".into(),
                },
                LinuxLandlockAccessClassPlan {
                    class: "remove".into(),
                    planned: true,
                    enforced_by_prototype_loader: true,
                    access: vec![
                        LinuxLandlockAccess::RemoveFile,
                        LinuxLandlockAccess::RemoveDir,
                    ],
                    reason: "prototype loader handles remove-file and remove-dir path-beneath access".into(),
                },
            ],
            current_loader_scope: "write/create/remove path-beneath denial only".into(),
            claim_boundary: "read and execute path policy are planned but not enforced by the prototype loader".into(),
        }
    }
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
            access_mask: 0,
        }];
        if let Some(rule) = rules.first_mut() {
            rule.access_mask = landlock_access_mask(&rule.access);
        }

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
                access_mask: landlock_access_mask(&access),
                access,
                reason: format!("explicit {:?} mount", mount.kind),
            });
        }

        Ok(LinuxLandlockPlan {
            schema_version: 1,
            ruleset_name: format!("agentbox-{}", spec.id),
            path_policy: LinuxLandlockPathPolicyPlan::prototype_loader_scope(),
            handled_access_mask: landlock_handled_access_mask(&rules),
            rules,
            default_deny: true,
            requires_loader: true,
            requires_linux: true,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn apply(plan: &LinuxLandlockPlan) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(ruleset) = prepare_linux_landlock_ruleset(plan)? else {
            return Ok(());
        };
        let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        restrict_self_with_landlock(&ruleset)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(
        _plan: &LinuxLandlockPlan,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Linux Landlock is only available on Linux".into())
    }
}

fn landlock_access_mask(access: &[LinuxLandlockAccess]) -> u64 {
    access
        .iter()
        .fold(0, |mask, access| mask | access.access_mask())
        & LANDLOCK_ABI_V1_FS_ACCESS_MASK
}

fn landlock_handled_access_mask(rules: &[LinuxLandlockRule]) -> u64 {
    rules.iter().fold(0, |mask, rule| mask | rule.access_mask)
        & LANDLOCK_PROTOTYPE_HANDLED_FS_ACCESS_MASK
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttrV1 {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[cfg(target_os = "linux")]
struct LinuxLandlockPreparedRuleset {
    ruleset: std::fs::File,
}

#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

#[cfg(target_os = "linux")]
fn prepare_linux_landlock_ruleset(
    plan: &LinuxLandlockPlan,
) -> Result<Option<LinuxLandlockPreparedRuleset>, Box<dyn std::error::Error + Send + Sync>> {
    use std::os::fd::{AsRawFd, FromRawFd};

    if plan.handled_access_mask == 0 {
        return Ok(None);
    }
    let abi = linux_landlock_abi_version()?;
    if abi < 1 {
        return Err("Linux Landlock ABI version 1 or newer is required".into());
    }

    let attr = LandlockRulesetAttrV1 {
        handled_access_fs: plan.handled_access_mask,
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttrV1,
            std::mem::size_of::<LandlockRulesetAttrV1>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    set_fd_cloexec(ruleset_fd as i32)?;
    let ruleset = unsafe { std::fs::File::from_raw_fd(ruleset_fd as i32) };

    for rule in &plan.rules {
        let allowed_access = rule.access_mask & plan.handled_access_mask;
        if allowed_access == 0 {
            continue;
        }
        let path = std::ffi::CString::new(rule.path.as_str())?;
        let path_fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if path_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let path_file = unsafe { std::fs::File::from_raw_fd(path_fd) };
        let path_beneath = LandlockPathBeneathAttr {
            allowed_access,
            parent_fd: path_file.as_raw_fd(),
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &path_beneath as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    Ok(Some(LinuxLandlockPreparedRuleset { ruleset }))
}

#[cfg(target_os = "linux")]
fn restrict_self_with_landlock(
    ruleset: &LinuxLandlockPreparedRuleset,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::fd::AsRawFd;

    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset.ruleset.as_raw_fd(),
            0u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(target_os = "linux")]
fn linux_landlock_abi_version() -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi >= 0 {
        Ok(abi)
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(target_os = "linux")]
fn set_fd_cloexec(fd: i32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxNftablesPlan {
    pub schema_version: i64,
    pub table_name: String,
    pub chain_name: String,
    #[serde(default)]
    pub live_gate: LinuxNftablesLiveGatePlan,
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
pub struct LinuxNftablesLiveGatePlan {
    pub schema_version: i64,
    pub env_var: String,
    pub enabled: bool,
    pub table_family: String,
    pub table_name: String,
    pub transaction: Vec<String>,
    pub lifecycle_claim: String,
}

impl Default for LinuxNftablesLiveGatePlan {
    fn default() -> Self {
        Self::for_table("agentbox_unset")
    }
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

impl LinuxNftablesLiveGatePlan {
    fn for_table(table_name: &str) -> Self {
        Self {
            schema_version: 1,
            env_var: "AGENTBOX_LINUX_NFTABLES".into(),
            enabled: linux_nftables_live_gate_enabled(),
            table_family: "inet".into(),
            table_name: table_name.into(),
            transaction: vec![
                format!("nft add table inet {table_name}"),
                format!("nft list table inet {table_name}"),
                format!("nft delete table inet {table_name}"),
            ],
            lifecycle_claim:
                "gated nftables table create/list/delete skeleton only; no egress hook or packet/domain enforcement is wired"
                    .into(),
        }
    }
}

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

        let table_name = format!("agentbox_{}", sanitize_nft_name(&spec.id));

        Ok(LinuxNftablesPlan {
            schema_version: 1,
            table_name: table_name.clone(),
            chain_name: "agentpod_egress".into(),
            live_gate: LinuxNftablesLiveGatePlan::for_table(&table_name),
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

fn linux_nftables_live_gate_enabled() -> bool {
    matches!(std::env::var("AGENTBOX_LINUX_NFTABLES").as_deref(), Ok("1"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxEbpfObservabilityPlan {
    pub schema_version: i64,
    pub session_id: String,
    pub provider: String,
    pub correlation: LinuxEbpfCorrelationPlan,
    pub event_sources: Vec<LinuxEbpfEventSourcePlan>,
    pub required_capabilities: Vec<String>,
    pub required_maps: Vec<String>,
    pub enforcement: LinuxEbpfEnforcementMode,
    pub requires_loader: bool,
    pub requires_linux: bool,
    pub evidence_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxEbpfCorrelationPlan {
    pub preferred_key: String,
    pub cgroup_path: String,
    pub pid_fallback: bool,
    pub manifest_label_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxEbpfEventSourcePlan {
    pub event_type: String,
    pub source: String,
    pub evidence_use: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinuxEbpfEnforcementMode {
    ObservedOnly,
}

pub struct LinuxEbpfObserverDescriptor;

impl LinuxEbpfObserverDescriptor {
    pub fn plan(spec: &MinipodSpec) -> Result<LinuxEbpfObservabilityPlan, RuntimeError> {
        if spec.id.trim().is_empty() {
            return Err(RuntimeError::ManifestRejected(
                "eBPF observer session id cannot be empty".into(),
            ));
        }

        Ok(LinuxEbpfObservabilityPlan {
            schema_version: 1,
            session_id: spec.id.clone(),
            provider: "agentpod-linux".into(),
            correlation: LinuxEbpfCorrelationPlan {
                preferred_key: "cgroup_path".into(),
                cgroup_path: format!("/sys/fs/cgroup/agentbox-{}", spec.id),
                pid_fallback: true,
                manifest_label_keys: sorted_label_keys(spec),
            },
            event_sources: vec![
                LinuxEbpfEventSourcePlan {
                    event_type: "linux.process.exec".into(),
                    source: "tracepoint:sched:sched_process_exec".into(),
                    evidence_use: "command lineage and binary path evidence".into(),
                },
                LinuxEbpfEventSourcePlan {
                    event_type: "linux.process.exit".into(),
                    source: "tracepoint:sched:sched_process_exit".into(),
                    evidence_use: "process lifetime and exit correlation".into(),
                },
                LinuxEbpfEventSourcePlan {
                    event_type: "linux.network.connect".into(),
                    source: "cgroup/connect observer".into(),
                    evidence_use: "destination metadata for network boundary evidence".into(),
                },
            ],
            required_capabilities: vec!["CAP_BPF".into(), "CAP_PERFMON".into()],
            required_maps: vec![
                "agentbox_session_correlation".into(),
                "agentbox_event_counters".into(),
            ],
            enforcement: LinuxEbpfEnforcementMode::ObservedOnly,
            requires_loader: true,
            requires_linux: true,
            evidence_claim:
                "eBPF observer descriptor only; observed events are not enforcement proof".into(),
        })
    }
}

fn sorted_label_keys(spec: &MinipodSpec) -> Vec<String> {
    let mut keys: Vec<String> = spec.labels.keys().cloned().collect();
    keys.sort();
    keys
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
    pub runner_phases: Vec<LinuxAgentPodRunnerPhase>,
    pub user_namespace: LinuxUserNamespacePlan,
    pub mount_namespace: LinuxMountNamespacePlan,
    pub pid_namespace: LinuxPidNamespacePlan,
    pub cgroup: LinuxCgroupV2Plan,
    pub seccomp: LinuxSeccompPlan,
    pub landlock: LinuxLandlockPlan,
    pub nftables: LinuxNftablesPlan,
    pub ebpf: LinuxEbpfObservabilityPlan,
    pub cgroup_root: String,
    pub live_env_var: String,
    pub live_execution_enabled: bool,
    pub requires_linux: bool,
    pub security_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxAgentPodRunnerPhase {
    pub name: String,
    pub status: String,
    pub evidence_event: String,
    pub claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxAgentPodRunnerPhaseEvidence {
    pub schema_version: u32,
    pub provider: String,
    pub session_id: String,
    pub phase: String,
    pub status: String,
    pub event_name: String,
    pub claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxAgentPodRunnerRequest {
    pub mount_namespace: LinuxMountNamespacePlan,
    pub seccomp: LinuxSeccompPlan,
    pub landlock: LinuxLandlockPlan,
    pub command_argv: Vec<String>,
    pub working_dir: Option<String>,
}

impl LinuxAgentPodRunnerRequest {
    pub fn from_execution_plan(plan: &LinuxAgentPodExecutionPlan, command: &ExecCommand) -> Self {
        Self {
            mount_namespace: plan.mount_namespace.clone(),
            seccomp: plan.seccomp.clone(),
            landlock: plan.landlock.clone(),
            command_argv: command.argv.clone(),
            working_dir: command.working_dir.clone(),
        }
    }
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
        let mut cgroup = LinuxCgroupV2Limiter::plan(&spec.id, &spec.resources)?;
        cgroup.pids_max = linux_pids_max_from_spec(spec)?;
        let seccomp = LinuxSeccompProfileLoader::plan(&spec.seccomp)?;
        let landlock = LinuxLandlockRuleset::plan(spec)?;
        let nftables = LinuxNftablesPolicyDescriptor::plan(spec)?;
        let ebpf = LinuxEbpfObserverDescriptor::plan(spec)?;

        let composed_argv = linux_agentpod_unshare_prefix(&mount_namespace, &pid_namespace);

        Ok(Self {
            schema_version: 1,
            provider: "agentpod-linux".into(),
            session_id: spec.id.clone(),
            command_argv: command.argv.clone(),
            composed_argv,
            runner_phases: linux_agentpod_runner_phases(
                &mount_namespace,
                &seccomp,
                &landlock,
                &nftables,
            ),
            user_namespace,
            mount_namespace,
            pid_namespace,
            cgroup,
            seccomp,
            landlock,
            nftables,
            ebpf,
            cgroup_root: linux_cgroup_v2_root().display().to_string(),
            live_env_var: "AGENTBOX_LINUX_NATIVE".into(),
            live_execution_enabled: linux_native_execution_enabled(),
            requires_linux: true,
            security_claim:
                "prototype namespace/resource execution with runner-managed workspace mount and cgroup v2 process attach; not a complete sandbox"
                    .into(),
        })
    }

    pub fn runnable_on_current_host(&self) -> bool {
        cfg!(target_os = "linux") && self.live_execution_enabled
    }

    pub fn runner_phase_evidence(&self) -> Vec<LinuxAgentPodRunnerPhaseEvidence> {
        self.runner_phases
            .iter()
            .map(|phase| LinuxAgentPodRunnerPhaseEvidence {
                schema_version: 1,
                provider: self.provider.clone(),
                session_id: self.session_id.clone(),
                phase: phase.name.clone(),
                status: phase.status.clone(),
                event_name: phase.evidence_event.clone(),
                claim: phase.claim.clone(),
            })
            .collect()
    }
}

fn linux_agentpod_unshare_prefix(
    mount_namespace: &LinuxMountNamespacePlan,
    pid_namespace: &LinuxPidNamespacePlan,
) -> Vec<String> {
    let mut argv = vec![
        "unshare".to_string(),
        "--user".to_string(),
        "--map-root-user".to_string(),
        "--setgroups=deny".to_string(),
        "--mount".to_string(),
        "--propagation".to_string(),
        mount_namespace.propagation.clone(),
    ];
    argv.extend(LinuxPidNamespaceLauncher::command_args(pid_namespace));
    argv
}

fn linux_agentpod_runner_phases(
    mount_namespace: &LinuxMountNamespacePlan,
    seccomp: &LinuxSeccompPlan,
    landlock: &LinuxLandlockPlan,
    nftables: &LinuxNftablesPlan,
) -> Vec<LinuxAgentPodRunnerPhase> {
    vec![
        LinuxAgentPodRunnerPhase {
            name: "enter-user-mount-pid-namespaces".into(),
            status: "prototype".into(),
            evidence_event: "agentpod.linux.runner.namespaces.entered".into(),
            claim: format!(
                "unshare user, mount, and PID namespaces with {} propagation",
                mount_namespace.propagation
            ),
        },
        LinuxAgentPodRunnerPhase {
            name: "bind-workspace".into(),
            status: if mount_namespace.workspace_bind_mount_wired {
                "prototype"
            } else {
                "planned"
            }
            .into(),
            evidence_event: "agentpod.linux.runner.workspace.mounted".into(),
            claim: mount_namespace.workspace_mount_claim.clone(),
        },
        LinuxAgentPodRunnerPhase {
            name: "apply-overlayfs".into(),
            status: if mount_namespace.overlayfs.is_some() {
                "prototype"
            } else {
                "inactive"
            }
            .into(),
            evidence_event: "agentpod.linux.runner.overlayfs.applied".into(),
            claim: if let Some(overlayfs) = &mount_namespace.overlayfs {
                format!(
                    "mount overlayfs lower={} upper={} work={} merged={}",
                    overlayfs.lower_host_path,
                    overlayfs.upper_host_path,
                    overlayfs.work_host_path,
                    overlayfs.merged_guest_path
                )
            } else {
                "no workspace overlay requested".into()
            },
        },
        LinuxAgentPodRunnerPhase {
            name: "apply-landlock".into(),
            status: "prototype".into(),
            evidence_event: "agentpod.linux.runner.landlock.applied".into(),
            claim: format!(
                "apply handled filesystem access mask {} after no-new-privs",
                landlock.handled_access_mask
            ),
        },
        LinuxAgentPodRunnerPhase {
            name: "apply-seccomp".into(),
            status: if seccomp.requires_loader {
                "prototype"
            } else {
                "inactive"
            }
            .into(),
            evidence_event: "agentpod.linux.runner.seccomp.applied".into(),
            claim: if seccomp.requires_loader {
                "install supported BPF syscall deny filter after no-new-privs".into()
            } else {
                "no syscall deny filter requested".into()
            },
        },
        LinuxAgentPodRunnerPhase {
            name: "apply-nftables".into(),
            status: if nftables.live_gate.enabled {
                "gated-skeleton"
            } else {
                "inactive"
            }
            .into(),
            evidence_event: "agentpod.linux.runner.nftables.skeleton.applied".into(),
            claim: nftables.live_gate.lifecycle_claim.clone(),
        },
        LinuxAgentPodRunnerPhase {
            name: "exec-command".into(),
            status: "prototype".into(),
            evidence_event: "agentpod.linux.runner.command.executed".into(),
            claim: "execute direct argv without shell wrapping and collect output".into(),
        },
    ]
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

        let runner_binary = linux_agentpod_runner_binary()?;
        let request_file = write_linux_agentpod_runner_request(plan, command)?;
        let mut runner_argv = plan.composed_argv.clone();
        runner_argv.extend([
            runner_binary.display().to_string(),
            "--request".to_string(),
            request_file.path().display().to_string(),
        ]);
        let (binary, args) = runner_argv.split_first().ok_or_else(|| {
            RuntimeError::ManifestRejected("Linux AgentPod runner argv cannot be empty".into())
        })?;
        let start = std::time::Instant::now();
        let mut process = std::process::Command::new(binary);
        process.args(args);
        process
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (key, value) in &command.env {
            process.env(key, value);
        }

        let mut child = process.spawn().map_err(|err| {
            RuntimeError::ExecFailed(format!("Linux AgentPod prototype exec failed: {err}"))
        })?;
        let pid = child.id();
        let cgroup_root = std::path::Path::new(&plan.cgroup_root);
        if let Err(err) = LinuxCgroupV2Limiter::apply(cgroup_root, &plan.cgroup, pid) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RuntimeError::ExecFailed(format!(
                "Linux AgentPod cgroup v2 attach failed at {}: {err}",
                cgroup_root.display()
            )));
        }
        let output_result = wait_for_child_output(child, command.timeout_seconds);
        LinuxCgroupV2Limiter::cleanup(cgroup_root, &plan.cgroup).map_err(|err| {
            RuntimeError::ExecFailed(format!(
                "Linux AgentPod cgroup v2 cleanup failed at {}: {err}",
                cgroup_root.display()
            ))
        })?;
        let output = output_result?;

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

#[cfg(target_os = "linux")]
struct LinuxAgentPodRunnerRequestFile {
    path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl LinuxAgentPodRunnerRequestFile {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxAgentPodRunnerRequestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(target_os = "linux")]
fn linux_agentpod_runner_binary() -> Result<std::path::PathBuf, RuntimeError> {
    if let Some(path) = std::env::var_os("AGENTBOX_LINUX_RUNNER") {
        let path = std::path::PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        return Err(RuntimeError::Unavailable(format!(
            "AGENTBOX_LINUX_RUNNER points to missing binary: {}",
            path.display()
        )));
    }

    let current = std::env::current_exe().map_err(|err| {
        RuntimeError::ExecFailed(format!("failed to locate current executable: {err}"))
    })?;
    let sibling = current.with_file_name("agentbox-linux-runner");
    if sibling.exists() {
        return Ok(sibling);
    }

    Err(RuntimeError::Unavailable(format!(
        "agentbox-linux-runner binary not found next to {}; set AGENTBOX_LINUX_RUNNER",
        current.display()
    )))
}

#[cfg(target_os = "linux")]
fn write_linux_agentpod_runner_request(
    plan: &LinuxAgentPodExecutionPlan,
    command: &ExecCommand,
) -> Result<LinuxAgentPodRunnerRequestFile, RuntimeError> {
    let request = LinuxAgentPodRunnerRequest::from_execution_plan(plan, command);
    let dir = std::env::temp_dir().join("agentbox-linux-runner");
    std::fs::create_dir_all(&dir).map_err(|err| {
        RuntimeError::ExecFailed(format!(
            "failed to create Linux runner request dir {}: {err}",
            dir.display()
        ))
    })?;
    let path = dir.join(linux_agentpod_runner_request_filename(&plan.session_id));
    let file = std::fs::File::create(&path).map_err(|err| {
        RuntimeError::ExecFailed(format!(
            "failed to create Linux runner request {}: {err}",
            path.display()
        ))
    })?;
    serde_json::to_writer(file, &request).map_err(|err| {
        let _ = std::fs::remove_file(&path);
        RuntimeError::ExecFailed(format!(
            "failed to serialize Linux runner request {}: {err}",
            path.display()
        ))
    })?;
    Ok(LinuxAgentPodRunnerRequestFile { path })
}

#[cfg(any(test, target_os = "linux"))]
fn linux_agentpod_runner_request_filename(session_id: &str) -> String {
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
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    format!(
        "{}-{}-{}-{}.json",
        safe_session_id,
        std::process::id(),
        nonce,
        counter
    )
}

#[cfg(test)]
fn linux_agentpod_host_working_dir(
    plan: &LinuxAgentPodExecutionPlan,
    command: &ExecCommand,
) -> Option<std::path::PathBuf> {
    let working_dir = command.working_dir.as_ref()?;
    let guest_workspace = plan
        .mount_namespace
        .workspace_guest_path
        .trim_end_matches('/');
    if guest_workspace.is_empty() {
        return Some(std::path::PathBuf::from(working_dir));
    }

    if working_dir == guest_workspace {
        return Some(std::path::PathBuf::from(
            &plan.mount_namespace.workspace_host_path,
        ));
    }

    if let Some(relative) = working_dir
        .strip_prefix(guest_workspace)
        .and_then(|value| value.strip_prefix('/'))
    {
        return Some(
            std::path::Path::new(&plan.mount_namespace.workspace_host_path).join(relative),
        );
    }

    Some(std::path::PathBuf::from(working_dir))
}

#[cfg(all(test, target_os = "linux"))]
fn configure_linux_child_security(
    command: &mut std::process::Command,
    seccomp: Option<&LinuxSeccompPlan>,
    landlock: Option<&LinuxLandlockPlan>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::process::CommandExt;

    let child_security = LinuxPreparedChildSecurity::prepare(seccomp, landlock)?;

    // SAFETY: pre_exec runs after fork and before exec in the child. The closure only
    // calls prctl syscalls and constructs an io::Error from errno on failure, then
    // returns to std::process for exec/error handling.
    unsafe {
        command.pre_exec(move || child_security.apply_in_child());
    }

    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
struct LinuxPreparedChildSecurity {
    seccomp_filter: Option<Vec<libc::sock_filter>>,
    landlock_ruleset: Option<LinuxLandlockPreparedRuleset>,
}

#[cfg(all(test, target_os = "linux"))]
impl LinuxPreparedChildSecurity {
    fn prepare(
        seccomp: Option<&LinuxSeccompPlan>,
        landlock: Option<&LinuxLandlockPlan>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let seccomp_filter = seccomp
            .map(compile_linux_seccomp_filter)
            .transpose()
            .map(Option::flatten)?;
        let landlock_ruleset = landlock
            .map(prepare_linux_landlock_ruleset)
            .transpose()
            .map(Option::flatten)?;

        Ok(Self {
            seccomp_filter,
            landlock_ruleset,
        })
    }

    fn apply_in_child(&self) -> std::io::Result<()> {
        let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if let Some(ruleset) = &self.landlock_ruleset {
            restrict_self_with_landlock(ruleset).map_err(|_| std::io::Error::last_os_error())?;
        }
        if let Some(filter) = &self.seccomp_filter {
            install_linux_seccomp_filter(filter).map_err(|_| std::io::Error::last_os_error())?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn compile_linux_seccomp_filter(
    plan: &LinuxSeccompPlan,
) -> Result<Option<Vec<libc::sock_filter>>, Box<dyn std::error::Error + Send + Sync>> {
    if !plan.enabled {
        return Ok(None);
    }

    let audit_arch = linux_seccomp_audit_arch()
        .ok_or("seccomp BPF loader does not support this CPU architecture")?;
    let mut filter = vec![
        bpf_stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 4),
        bpf_jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            audit_arch,
            1,
            0,
        ),
        bpf_stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
        bpf_stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0),
    ];
    for rule in &plan.syscall_rules {
        let syscall = linux_syscall_number(&rule.syscall).ok_or_else(|| {
            format!(
                "seccomp syscall '{}' is not supported by the prototype BPF loader",
                rule.syscall
            )
        })?;
        filter.push(bpf_jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            syscall,
            0,
            1,
        ));
        filter.push(bpf_stmt(
            libc::BPF_RET | libc::BPF_K,
            seccomp_action_to_bpf(&rule.action)?,
        ));
    }
    filter.push(bpf_stmt(
        libc::BPF_RET | libc::BPF_K,
        seccomp_action_to_bpf(&plan.default_action)?,
    ));

    Ok(Some(filter))
}

#[cfg(target_os = "linux")]
fn bpf_stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(target_os = "linux")]
fn bpf_jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

#[cfg(target_os = "linux")]
fn install_linux_seccomp_filter(
    filter: &[libc::sock_filter],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut program = libc::sock_fprog {
        len: filter
            .len()
            .try_into()
            .map_err(|_| "seccomp filter is too large")?,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program as *mut libc::sock_fprog,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(target_os = "linux")]
fn seccomp_action_to_bpf(
    action: &SeccompAction,
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    match action {
        SeccompAction::Allow => Ok(libc::SECCOMP_RET_ALLOW),
        SeccompAction::Errno(errno) => Ok(libc::SECCOMP_RET_ERRNO | (*errno as u32 & 0x0000ffff)),
        SeccompAction::KillProcess => Ok(libc::SECCOMP_RET_KILL_PROCESS),
        SeccompAction::Log => Ok(libc::SECCOMP_RET_LOG),
    }
}

#[cfg(target_os = "linux")]
fn linux_syscall_number(syscall: &str) -> Option<u32> {
    match syscall {
        "bpf" => Some(libc::SYS_bpf as u32),
        "clone" => Some(libc::SYS_clone as u32),
        "clone3" => Some(libc::SYS_clone3 as u32),
        "kill" => Some(libc::SYS_kill as u32),
        "ptrace" => Some(libc::SYS_ptrace as u32),
        "unshare" => Some(libc::SYS_unshare as u32),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn linux_seccomp_audit_arch() -> Option<u32> {
    if cfg!(target_arch = "x86_64") {
        Some(0xc000003e)
    } else if cfg!(target_arch = "aarch64") {
        Some(0xc00000b7)
    } else {
        None
    }
}

fn linux_pids_max_from_spec(spec: &MinipodSpec) -> Result<Option<u32>, RuntimeError> {
    let Some(raw) = spec.labels.get("agentbox.resources.pids_max") else {
        return Ok(None);
    };
    let value = raw.parse::<u32>().map_err(|_| {
        RuntimeError::ManifestRejected("agentbox.resources.pids_max must be a u32".into())
    })?;
    if value == 0 {
        return Err(RuntimeError::ManifestRejected(
            "agentbox.resources.pids_max cannot be zero".into(),
        ));
    }
    Ok(Some(value))
}

#[cfg(target_os = "linux")]
fn wait_for_child_output(
    mut child: std::process::Child,
    timeout_seconds: Option<u64>,
) -> Result<std::process::Output, RuntimeError> {
    use std::io::Read;

    let mut stdout = child.stdout.take().ok_or_else(|| {
        RuntimeError::Internal("Linux AgentPod child stdout pipe was not captured".into())
    })?;
    let mut stderr = child.stderr.take().ok_or_else(|| {
        RuntimeError::Internal("Linux AgentPod child stderr pipe was not captured".into())
    })?;
    let stdout_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        stdout.read_to_end(&mut buffer).map(|_| buffer)
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        stderr.read_to_end(&mut buffer).map(|_| buffer)
    });

    let deadline = timeout_seconds
        .map(|seconds| std::time::Instant::now() + std::time::Duration::from_secs(seconds));
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|err| {
            RuntimeError::ExecFailed(format!("Linux AgentPod prototype wait failed: {err}"))
        })? {
            break status;
        }
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(RuntimeError::Timeout(timeout_seconds.unwrap_or_default()));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| RuntimeError::Internal("Linux AgentPod stdout reader panicked".into()))?
        .map_err(|err| {
            RuntimeError::ExecFailed(format!("Linux AgentPod stdout capture failed: {err}"))
        })?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| RuntimeError::Internal("Linux AgentPod stderr reader panicked".into()))?
        .map_err(|err| {
            RuntimeError::ExecFailed(format!("Linux AgentPod stderr capture failed: {err}"))
        })?;

    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
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
        let ebpf = LinuxEbpfObserverDescriptor::plan(spec)?;

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
                LinuxIsolationBenchmarkLayer {
                    name: "ebpf-observer-plan".into(),
                    argv: ebpf
                        .event_sources
                        .iter()
                        .map(|source| source.event_type.clone())
                        .collect(),
                    expected_boundary: "eBPF observability descriptor only".into(),
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

pub fn linux_cgroup_v2_root() -> std::path::PathBuf {
    std::env::var_os("AGENTBOX_LINUX_CGROUP_ROOT")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/sys/fs/cgroup"))
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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_child_output_waiter_captures_stdout_and_stderr() {
        let child = std::process::Command::new("sh")
            .arg("-c")
            .arg("printf out; printf err >&2")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let output = wait_for_child_output(child, Some(5)).unwrap();

        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "out");
        assert_eq!(String::from_utf8_lossy(&output.stderr), "err");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_child_output_waiter_kills_process_on_timeout() {
        let child = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 2")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let err = wait_for_child_output(child, Some(0)).unwrap_err();

        assert!(matches!(err, RuntimeError::Timeout(0)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_child_security_sets_no_new_privs() {
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg("awk '/NoNewPrivs/ { print $2 }' /proc/self/status")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        configure_linux_child_security(&mut command, None, None).unwrap();

        let child = command.spawn().unwrap();
        let output = wait_for_child_output(child, Some(5)).unwrap();

        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_seccomp_filter_blocks_supported_syscall_in_child() {
        let profile = SeccompProfile::deny_syscalls(&["kill"], "test syscall denial");
        let plan = LinuxSeccompProfileLoader::plan(&profile).unwrap();
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg("kill -0 $$; printf 'kill_status:%s\\n' \"$?\"")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        configure_linux_child_security(&mut command, Some(&plan), None).unwrap();

        let child = command.spawn().unwrap();
        let output = wait_for_child_output(child, Some(5)).unwrap();

        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("kill_status:1"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_landlock_filter_denies_child_writes_outside_workspace() {
        if let Err(err) = linux_landlock_abi_version() {
            eprintln!("skipping Landlock child proof: {err}");
            return;
        }

        let root = std::env::temp_dir().join(format!(
            "agentbox-landlock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let spec = MinipodSpec::for_agent_task("hermes", &workspace);
        let plan = LinuxLandlockRuleset::plan(&spec).unwrap();
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg("printf ok > \"$WORKSPACE/allowed\"; printf no > \"$OUTSIDE/denied\"")
            .env("WORKSPACE", &workspace)
            .env("OUTSIDE", &outside)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        configure_linux_child_security(&mut command, None, Some(&plan)).unwrap();

        let child = command.spawn().unwrap();
        let output = wait_for_child_output(child, Some(5)).unwrap();

        assert!(!output.status.success());
        assert_eq!(
            std::fs::read_to_string(workspace.join("allowed")).unwrap(),
            "ok"
        );
        assert!(!outside.join("denied").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_filter_rejects_unsupported_syscall_names_before_spawn() {
        let profile = SeccompProfile::deny_syscalls(&["definitely_not_a_syscall"], "test");
        let plan = LinuxSeccompProfileLoader::plan(&profile).unwrap();
        let mut command = std::process::Command::new("true");

        let err = configure_linux_child_security(&mut command, Some(&plan), None).unwrap_err();

        assert!(err.to_string().contains("not supported"));
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
        assert!(plan.workspace_bind_mount_wired);
        assert!(plan.workspace_mount_claim.contains("agentbox-linux-runner"));
        assert_eq!(plan.propagation, "private");
        assert!(plan.requires_linux);
        assert_eq!(plan.read_only_mounts.len(), 1);
        assert_eq!(plan.read_only_mounts[0].guest_path, "/fixtures");
        assert!(plan.read_only_mounts[0].read_only);
    }

    #[test]
    fn mount_namespace_plan_carries_overlayfs_workspace_metadata() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.filesystem.workspace_overlay =
            crate::runtime::types::WorkspaceOverlayPolicy::review_required(Some(PathBuf::from(
                "/tmp/agentbox-overlay",
            )));

        let plan = LinuxMountNamespaceLauncher::plan(&spec).unwrap();
        let overlayfs = plan.overlayfs.expect("overlayfs plan should be present");

        assert_eq!(overlayfs.lower_host_path, "/tmp/agentbox-work");
        assert_eq!(overlayfs.upper_host_path, "/tmp/agentbox-overlay/upper");
        assert_eq!(overlayfs.work_host_path, "/tmp/agentbox-overlay/work");
        assert_eq!(overlayfs.merged_guest_path, "/workspace");
        assert_eq!(overlayfs.mode, WorkspaceOverlayMode::ReviewRequired);
        assert!(overlayfs.review_required);
        assert!(overlayfs.requires_overlayfs);
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
    fn agentpod_execution_plan_maps_pids_max_label_to_cgroup_limit() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.labels
            .insert("agentbox.resources.pids_max".into(), "64".into());
        let command = command(&["/bin/true"]);

        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();

        assert_eq!(plan.cgroup.pids_max, Some(64));
        assert!(plan
            .cgroup
            .writes()
            .iter()
            .any(|write| { write.file == "pids.max" && write.value == "64" }));
    }

    #[test]
    fn agentpod_execution_plan_rejects_invalid_pids_max_label() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.labels
            .insert("agentbox.resources.pids_max".into(), "not-a-number".into());
        let command = command(&["/bin/true"]);

        let err = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
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

        let err = LinuxCgroupV2Limiter::cleanup(std::path::Path::new("/sys/fs/cgroup"), &plan)
            .unwrap_err();

        assert!(err.to_string().contains("only available on Linux"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_v2_apply_writes_limits_and_process_membership() {
        let root = std::env::temp_dir().join(format!(
            "agentbox-cgroup-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let plan =
            LinuxCgroupV2Limiter::plan("01agentboxsession", &ResourcePolicy::default()).unwrap();

        LinuxCgroupV2Limiter::apply(&root, &plan, 12345).unwrap();

        let cgroup_dir = root.join(&plan.cgroup_name);
        assert_eq!(
            std::fs::read_to_string(cgroup_dir.join("memory.max")).unwrap(),
            plan.memory_max
        );
        assert_eq!(
            std::fs::read_to_string(cgroup_dir.join("cpu.weight")).unwrap(),
            plan.cpu_weight.to_string()
        );
        assert_eq!(
            std::fs::read_to_string(cgroup_dir.join("cgroup.procs")).unwrap(),
            "12345"
        );

        LinuxCgroupV2Limiter::cleanup(&root, &plan).unwrap();

        assert!(!cgroup_dir.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_v2_cleanup_tolerates_missing_cgroups() {
        let root = std::env::temp_dir().join(format!(
            "agentbox-cgroup-missing-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let plan =
            LinuxCgroupV2Limiter::plan("01agentboxsession", &ResourcePolicy::default()).unwrap();

        LinuxCgroupV2Limiter::cleanup(&root, &plan).unwrap();
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
        assert_eq!(plan.import_descriptor.schema_version, 1);
        assert!(!plan.import_descriptor.generated_oci_profile);
        assert!(!plan.import_descriptor.import_enabled);
        assert!(plan
            .import_descriptor
            .claim_boundary
            .contains("not accepted or applied yet"));
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
    fn seccomp_import_descriptor_models_external_profile_boundary() {
        let profile = SeccompProfile::deny_syscalls(&["kill"], "block signal fanout");

        let plan = LinuxSeccompProfileLoader::plan(&profile).unwrap();

        assert!(plan.import_descriptor.generated_oci_profile);
        assert!(!plan.import_descriptor.import_enabled);
        assert!(plan
            .import_descriptor
            .supported_formats
            .contains(&"oci-seccomp-v1-json".to_string()));
        assert!(plan
            .import_descriptor
            .supported_formats
            .contains(&"libseccomp-json".to_string()));
        assert!(plan
            .import_descriptor
            .loader_scope
            .contains("explicit syscall deny rules"));
        assert!(plan
            .import_descriptor
            .claim_boundary
            .contains("external OCI/libseccomp profile import"));
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
        assert_eq!(
            plan.rules[0].access_mask & LANDLOCK_ACCESS_FS_WRITE_FILE,
            LANDLOCK_ACCESS_FS_WRITE_FILE
        );
        assert_eq!(
            plan.rules[0].access_mask & LANDLOCK_ACCESS_FS_MAKE_REG,
            LANDLOCK_ACCESS_FS_MAKE_REG
        );
        assert_eq!(plan.rules[1].path, "/tmp/agentbox-fixtures");
        assert!(plan.rules[1]
            .access
            .contains(&LinuxLandlockAccess::ReadFile));
        assert!(!plan.rules[1]
            .access
            .contains(&LinuxLandlockAccess::WriteFile));
        assert_eq!(
            plan.handled_access_mask,
            LANDLOCK_PROTOTYPE_HANDLED_FS_ACCESS_MASK
        );
        assert_eq!(
            plan.handled_access_mask & LANDLOCK_ACCESS_FS_EXECUTE,
            0,
            "prototype loader must not handle exec until it can run after the launcher starts"
        );
    }

    #[test]
    fn landlock_path_policy_plan_separates_read_execute_from_loader_scope() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");

        let plan = LinuxLandlockRuleset::plan(&spec).unwrap();

        assert_eq!(plan.path_policy.schema_version, 1);
        assert!(plan
            .path_policy
            .claim_boundary
            .contains("not enforced by the prototype loader"));
        assert_eq!(
            plan.path_policy.current_loader_scope,
            "write/create/remove path-beneath denial only"
        );

        let read = plan
            .path_policy
            .access_classes
            .iter()
            .find(|class| class.class == "read")
            .unwrap();
        assert!(read.planned);
        assert!(!read.enforced_by_prototype_loader);
        assert!(read.access.contains(&LinuxLandlockAccess::ReadFile));
        assert!(read.access.contains(&LinuxLandlockAccess::ReadDir));

        let execute = plan
            .path_policy
            .access_classes
            .iter()
            .find(|class| class.class == "execute")
            .unwrap();
        assert!(execute.planned);
        assert!(!execute.enforced_by_prototype_loader);
        assert!(execute.access.contains(&LinuxLandlockAccess::Execute));
        assert_eq!(
            plan.handled_access_mask & LANDLOCK_ACCESS_FS_EXECUTE,
            0,
            "execute is planned but still outside the prototype loader scope"
        );

        for enforced_class in ["write", "create", "remove"] {
            let class = plan
                .path_policy
                .access_classes
                .iter()
                .find(|class| class.class == enforced_class)
                .unwrap();
            assert!(class.planned);
            assert!(class.enforced_by_prototype_loader);
        }
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
        assert_eq!(plan.live_gate.env_var, "AGENTBOX_LINUX_NFTABLES");
        assert_eq!(plan.live_gate.table_family, "inet");
        assert_eq!(plan.live_gate.table_name, plan.table_name);
        assert!(plan
            .live_gate
            .lifecycle_claim
            .contains("no egress hook or packet/domain enforcement"));
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
    fn nftables_live_gate_transaction_is_scoped_to_agentbox_table() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.id = "agentpod.test/session-1".into();

        let plan = LinuxNftablesPolicyDescriptor::plan(&spec).unwrap();

        assert_eq!(plan.live_gate.schema_version, 1);
        assert_eq!(plan.live_gate.env_var, "AGENTBOX_LINUX_NFTABLES");
        assert!(!plan.live_gate.enabled);
        assert_eq!(
            plan.live_gate.transaction,
            vec![
                "nft add table inet agentbox_agentpod_test_session_1".to_string(),
                "nft list table inet agentbox_agentpod_test_session_1".to_string(),
                "nft delete table inet agentbox_agentpod_test_session_1".to_string(),
            ]
        );
        assert!(plan
            .live_gate
            .transaction
            .iter()
            .all(|command| command.contains("agentbox_agentpod_test_session_1")));
        assert!(plan
            .live_gate
            .lifecycle_claim
            .contains("table create/list/delete skeleton only"));
    }

    #[test]
    fn nftables_plan_preserves_default_guardrail_denies_and_localhost_allowance() {
        let spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");

        let plan = LinuxNftablesPolicyDescriptor::plan(&spec).unwrap();

        assert_eq!(
            plan.default_policy,
            LinuxNftablesDefaultPolicy::AcceptWithGuardrails
        );
        assert!(plan.allow_localhost);
        assert!(plan.domain_rules_require_resolver);
        assert_eq!(plan.denied_domains, spec.network.denied_domains);
        assert!(plan.planned_rules.iter().any(|rule| {
            rule.action == LinuxNftablesRuleAction::Accept
                && rule.selector.contains("127.0.0.0/8")
                && rule.reason.contains("allows loopback")
        }));
        for metadata_endpoint in [
            "169.254.169.254",
            "metadata.google.internal",
            "fd00:ec2::254",
        ] {
            assert!(plan.planned_rules.iter().any(|rule| {
                rule.action == LinuxNftablesRuleAction::Drop
                    && rule.selector == format!("domain:{metadata_endpoint}")
                    && rule.reason.contains("requires resolver")
            }));
        }
        assert!(plan.enforcement_claim.contains("descriptor only"));
        assert!(plan
            .enforcement_claim
            .contains("no packet/domain denial proof"));
    }

    #[test]
    fn nftables_plan_requires_resolver_for_domain_allow_and_deny_rules() {
        let mut spec = MinipodSpec::for_agent_task("deploy", "/tmp/agentbox-work");
        spec.network.mode = NetworkMode::DenyByDefault;
        spec.network.allowed_domains = vec!["api.github.com".into(), "registry.npmjs.org".into()];
        spec.network.denied_domains = vec!["169.254.169.254".into()];

        let plan = LinuxNftablesPolicyDescriptor::plan(&spec).unwrap();

        assert_eq!(plan.default_policy, LinuxNftablesDefaultPolicy::Drop);
        let domain_rules: Vec<_> = plan
            .planned_rules
            .iter()
            .filter(|rule| rule.selector.starts_with("domain:"))
            .collect();
        assert_eq!(domain_rules.len(), 3);
        assert!(domain_rules
            .iter()
            .all(|rule| rule.reason.contains("requires resolver/ipset compilation")));
        assert!(domain_rules.iter().any(|rule| {
            rule.action == LinuxNftablesRuleAction::Accept
                && rule.selector == "domain:api.github.com"
        }));
        assert!(domain_rules.iter().any(|rule| {
            rule.action == LinuxNftablesRuleAction::Drop
                && rule.selector == "domain:169.254.169.254"
        }));
    }

    #[test]
    fn nftables_plan_models_approval_mode_without_live_packet_claim() {
        let mut spec = MinipodSpec::for_agent_task("browser", "/tmp/agentbox-work");
        spec.network.mode = NetworkMode::ApprovalOnFirstContact;
        spec.network.allow_localhost = false;

        let plan = LinuxNftablesPolicyDescriptor::plan(&spec).unwrap();

        assert_eq!(
            plan.default_policy,
            LinuxNftablesDefaultPolicy::RequireApproval
        );
        assert!(!plan.allow_localhost);
        assert!(plan.planned_rules.iter().any(|rule| {
            rule.action == LinuxNftablesRuleAction::Drop
                && rule.selector.contains("127.0.0.0/8")
                && rule.reason.contains("disables loopback")
        }));
        assert!(plan.requires_nftables);
        assert!(plan.requires_linux);
        assert!(plan
            .enforcement_claim
            .contains("no packet/domain denial proof"));
    }

    #[test]
    fn nftables_plan_rejects_empty_session_ids() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.id = " ".into();

        let err = LinuxNftablesPolicyDescriptor::plan(&spec).unwrap_err();

        assert!(matches!(err, RuntimeError::ManifestRejected(_)));
    }

    #[test]
    fn ebpf_observer_plan_models_observed_only_evidence_sources() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.labels
            .insert("policy.bundle".into(), "research-default".into());

        let plan = LinuxEbpfObserverDescriptor::plan(&spec).unwrap();

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.provider, "agentpod-linux");
        assert_eq!(plan.session_id, spec.id);
        assert_eq!(plan.correlation.preferred_key, "cgroup_path");
        assert!(plan.correlation.cgroup_path.contains("agentbox-"));
        assert!(plan.correlation.pid_fallback);
        assert!(plan
            .correlation
            .manifest_label_keys
            .contains(&"policy.bundle".to_string()));
        assert!(plan
            .event_sources
            .iter()
            .any(|source| source.event_type == "linux.process.exec"));
        assert!(plan
            .event_sources
            .iter()
            .any(|source| source.event_type == "linux.network.connect"));
        assert!(plan.required_capabilities.contains(&"CAP_BPF".into()));
        assert_eq!(plan.enforcement, LinuxEbpfEnforcementMode::ObservedOnly);
        assert!(plan.requires_loader);
        assert!(plan.evidence_claim.contains("not enforcement proof"));
    }

    #[test]
    fn ebpf_observer_plan_rejects_empty_session_ids() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.id = " ".into();

        let err = LinuxEbpfObserverDescriptor::plan(&spec).unwrap_err();

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
        assert_eq!(plan.nftables.live_gate.env_var, "AGENTBOX_LINUX_NFTABLES");
        assert!(plan.runner_phases.iter().any(|phase| {
            phase.name == "apply-nftables"
                && phase.evidence_event == "agentpod.linux.runner.nftables.skeleton.applied"
                && phase.claim.contains("no egress hook")
        }));
        assert_eq!(
            plan.ebpf.enforcement,
            LinuxEbpfEnforcementMode::ObservedOnly
        );
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
                "ebpf-observer-plan",
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
        assert!(plan.layers[9].argv.contains(&"linux.process.exec".into()));
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
        assert_eq!(
            plan.runner_phases
                .iter()
                .map(|phase| (phase.name.as_str(), phase.status.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("enter-user-mount-pid-namespaces", "prototype"),
                ("bind-workspace", "prototype"),
                ("apply-overlayfs", "inactive"),
                ("apply-landlock", "prototype"),
                ("apply-seccomp", "inactive"),
                ("apply-nftables", "inactive"),
                ("exec-command", "prototype"),
            ]
        );
        assert_eq!(plan.live_env_var, "AGENTBOX_LINUX_NATIVE");
        assert!(!plan.cgroup_root.is_empty());
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
        assert!(plan.security_claim.contains("cgroup v2 process attach"));
        assert!(plan
            .security_claim
            .contains("runner-managed workspace mount"));
        assert_eq!(plan.cgroup.cgroup_name, format!("agentbox-{}", spec.id));
        assert!(plan.landlock.default_deny);
        assert!(!plan.seccomp.requires_loader);
    }

    #[test]
    fn agentpod_execution_plan_wires_linux_overlayfs_phase() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.filesystem.workspace_overlay =
            crate::runtime::types::WorkspaceOverlayPolicy::review_required(Some(
                "/tmp/agentbox-overlay/session-1".into(),
            ));
        let command = command(&["/bin/true"]);

        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();

        let overlayfs = plan.mount_namespace.overlayfs.as_ref().unwrap();
        assert_eq!(overlayfs.lower_host_path, "/tmp/agentbox-work");
        assert_eq!(
            overlayfs.upper_host_path,
            "/tmp/agentbox-overlay/session-1/upper"
        );
        assert_eq!(
            overlayfs.work_host_path,
            "/tmp/agentbox-overlay/session-1/work"
        );
        assert_eq!(overlayfs.merged_guest_path, "/workspace");
        assert!(overlayfs.review_required);
        assert!(plan
            .mount_namespace
            .workspace_mount_claim
            .contains("overlayfs"));
        assert!(plan.runner_phases.iter().any(|phase| {
            phase.name == "apply-overlayfs"
                && phase.status == "prototype"
                && phase
                    .claim
                    .contains("upper=/tmp/agentbox-overlay/session-1/upper")
        }));
    }

    #[test]
    fn runner_phase_evidence_events_match_plan_phases() {
        let mut spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        spec.seccomp =
            crate::runtime::types::SeccompProfile::deny_syscalls(&["kill"], "block signal fanout");
        let command = command(&["/bin/true"]);

        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();
        let events = plan.runner_phase_evidence();

        assert_eq!(events.len(), plan.runner_phases.len());
        assert_eq!(events[0].schema_version, 1);
        assert_eq!(events[0].provider, "agentpod-linux");
        assert_eq!(events[0].session_id, spec.id);
        assert_eq!(events[0].phase, "enter-user-mount-pid-namespaces");
        assert_eq!(
            events[0].event_name,
            "agentpod.linux.runner.namespaces.entered"
        );
        assert!(events.iter().any(|event| {
            event.phase == "apply-seccomp"
                && event.status == "prototype"
                && event.event_name == "agentpod.linux.runner.seccomp.applied"
        }));
        assert!(events
            .iter()
            .all(|event| event.event_name.starts_with("agentpod.linux.runner.")));
    }

    #[test]
    fn agentpod_executor_maps_guest_workspace_working_dir_to_host_path() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let mut command = command(&["/bin/true"]);
        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();

        assert_eq!(
            linux_agentpod_host_working_dir(&plan, &command).unwrap(),
            PathBuf::from("/tmp/agentbox-work")
        );

        command.working_dir = Some("/workspace/src".into());
        assert_eq!(
            linux_agentpod_host_working_dir(&plan, &command).unwrap(),
            PathBuf::from("/tmp/agentbox-work/src")
        );

        command.working_dir = Some("/var/tmp".into());
        assert_eq!(
            linux_agentpod_host_working_dir(&plan, &command).unwrap(),
            PathBuf::from("/var/tmp")
        );
    }

    #[test]
    fn agentpod_runner_request_is_derived_from_execution_plan() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let command = command(&["/bin/true"]);
        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();

        let request = LinuxAgentPodRunnerRequest::from_execution_plan(&plan, &command);

        assert_eq!(request.command_argv, vec!["/bin/true"]);
        assert_eq!(request.working_dir, Some("/workspace".into()));
        assert_eq!(request.mount_namespace, plan.mount_namespace);
        assert_eq!(request.seccomp, plan.seccomp);
        assert_eq!(request.landlock, plan.landlock);
    }

    #[test]
    fn agentpod_runner_request_filename_is_path_safe_and_unique() {
        let first = linux_agentpod_runner_request_filename("../session/with spaces");
        let second = linux_agentpod_runner_request_filename("../session/with spaces");

        assert!(first.ends_with(".json"));
        assert!(first.starts_with("session_with_spaces-"));
        assert!(!first.contains('/'));
        assert!(!first.contains(' '));
        assert_ne!(first, second);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn agentpod_runner_request_file_is_removed_on_drop() {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        let command = command(&["/bin/true"]);
        let plan = LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();

        let path = {
            let request_file = write_linux_agentpod_runner_request(&plan, &command).unwrap();
            let path = request_file.path().to_path_buf();
            assert!(path.exists());
            path
        };

        assert!(!path.exists());
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
