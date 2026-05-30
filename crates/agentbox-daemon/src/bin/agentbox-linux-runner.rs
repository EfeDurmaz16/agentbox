use agentbox_daemon::runtime::providers::linux::{
    LinuxAgentPodRunnerRequest, LinuxLandlockPlan, LinuxLandlockRule, LinuxLandlockRuleset,
    LinuxMountNamespaceMount, LinuxMountNamespacePlan, LinuxOverlayFsWorkspacePlan,
    LinuxSeccompProfileLoader,
};
use agentbox_daemon::runtime::types::{AgentPodWorkspaceMode, WorkspaceOverlayMode};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(err) = run() {
        eprintln!("agentbox-linux-runner: {err}");
        std::process::exit(125);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(request_path) = parse_request_path()? else {
        print_usage();
        return Ok(());
    };
    let request = read_request(&request_path)?;
    validate_request(&request)?;

    apply_mounts(&request.mount_namespace)?;
    let landlock = landlock_with_guest_workspace_alias(&request);
    LinuxLandlockRuleset::apply(&landlock)?;
    LinuxSeccompProfileLoader::apply(&request.seccomp)?;
    exec_request(request)
}

fn parse_request_path() -> Result<Option<PathBuf>, Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (Some(flag), None, None) if flag == "--help" || flag == "-h" => Ok(None),
        (Some(flag), Some(path), None) if flag == "--request" => Ok(Some(PathBuf::from(path))),
        _ => Err("usage: agentbox-linux-runner --request <request.json>".into()),
    }
}

fn print_usage() {
    println!("agentbox-linux-runner --request <request.json>");
    println!("  Linux-only helper for AgentPod namespace mount setup and final exec.");
}

fn read_request(
    path: &Path,
) -> Result<LinuxAgentPodRunnerRequest, Box<dyn std::error::Error + Send + Sync>> {
    let file = std::fs::File::open(path)?;
    Ok(serde_json::from_reader(file)?)
}

fn validate_request(
    request: &LinuxAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if request.command_argv.is_empty() {
        return Err("runner command argv cannot be empty".into());
    }
    if request
        .mount_namespace
        .workspace_host_path
        .trim()
        .is_empty()
    {
        return Err("runner workspace host path cannot be empty".into());
    }
    if request
        .mount_namespace
        .workspace_guest_path
        .trim()
        .is_empty()
    {
        return Err("runner workspace guest path cannot be empty".into());
    }
    validate_workspace_mode(&request.mount_namespace)?;
    validate_read_only_mounts(&request.mount_namespace.read_only_mounts)?;
    Ok(())
}

fn validate_workspace_mode(
    plan: &LinuxMountNamespacePlan,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match (&plan.workspace_mode, &plan.overlayfs) {
        (AgentPodWorkspaceMode::Direct, None) => Ok(()),
        (AgentPodWorkspaceMode::Direct, Some(_)) => {
            Err("runner direct workspace mode must not include overlayfs".into())
        }
        (AgentPodWorkspaceMode::OverlayReview, Some(overlayfs)) => {
            validate_overlayfs(overlayfs)?;
            if overlayfs.mode != WorkspaceOverlayMode::ReviewRequired || !overlayfs.review_required
            {
                return Err(
                    "runner overlay-review workspace mode requires review overlayfs".into(),
                );
            }
            Ok(())
        }
        (AgentPodWorkspaceMode::OverlayReview, None) => {
            Err("runner overlay-review workspace mode requires overlayfs".into())
        }
        (AgentPodWorkspaceMode::Ephemeral, Some(overlayfs)) => {
            validate_overlayfs(overlayfs)?;
            if overlayfs.mode != WorkspaceOverlayMode::DiscardOnDestroy || overlayfs.review_required
            {
                return Err("runner ephemeral workspace mode requires discard overlayfs".into());
            }
            Ok(())
        }
        (AgentPodWorkspaceMode::Ephemeral, None) => {
            Err("runner ephemeral workspace mode requires overlayfs".into())
        }
        (AgentPodWorkspaceMode::CommitGated, _) => {
            Err("runner commit-gated workspace mode is not supported yet".into())
        }
    }
}

fn validate_read_only_mounts(
    mounts: &[LinuxMountNamespaceMount],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for mount in mounts {
        if mount.host_path.trim().is_empty() {
            return Err("runner read-only mount host path cannot be empty".into());
        }
        if mount.guest_path.trim().is_empty() {
            return Err("runner read-only mount guest path cannot be empty".into());
        }
        if !mount.read_only {
            return Err("runner read-only mount request must be read-only".into());
        }
    }
    Ok(())
}

fn validate_overlayfs(
    overlayfs: &LinuxOverlayFsWorkspacePlan,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if overlayfs.lower_host_path.trim().is_empty() {
        return Err("runner overlayfs lower path cannot be empty".into());
    }
    if overlayfs.upper_host_path.trim().is_empty() {
        return Err("runner overlayfs upper path cannot be empty".into());
    }
    if overlayfs.work_host_path.trim().is_empty() {
        return Err("runner overlayfs work path cannot be empty".into());
    }
    if overlayfs.merged_guest_path.trim().is_empty() {
        return Err("runner overlayfs merged guest path cannot be empty".into());
    }
    if overlayfs.upper_host_path == overlayfs.work_host_path {
        return Err("runner overlayfs upper and work paths must differ".into());
    }
    Ok(())
}

fn landlock_with_guest_workspace_alias(request: &LinuxAgentPodRunnerRequest) -> LinuxLandlockPlan {
    let mut plan = request.landlock.clone();
    append_landlock_alias_rule(
        &mut plan,
        &request.mount_namespace.workspace_host_path,
        &request.mount_namespace.workspace_guest_path,
        "guest workspace bind-mount alias",
    );
    for mount in &request.mount_namespace.read_only_mounts {
        append_landlock_alias_rule(
            &mut plan,
            &mount.host_path,
            &mount.guest_path,
            "guest read-only bind-mount alias",
        );
    }
    plan
}

fn append_landlock_alias_rule(
    plan: &mut LinuxLandlockPlan,
    source_path: &str,
    alias_path: &str,
    reason: &str,
) {
    if source_path == alias_path {
        return;
    }
    if let Some(source_rule) = plan
        .rules
        .iter()
        .find(|rule| rule.path == source_path)
        .cloned()
    {
        plan.rules.push(LinuxLandlockRule {
            path: alias_path.to_string(),
            reason: reason.to_string(),
            optional: false,
            ..source_rule
        });
    }
}

#[cfg(target_os = "linux")]
fn apply_mounts(
    plan: &LinuxMountNamespacePlan,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(overlayfs) = &plan.overlayfs {
        mount_overlay_workspace(overlayfs)?;
    } else {
        bind_mount(
            Path::new(&plan.workspace_host_path),
            Path::new(&plan.workspace_guest_path),
            false,
        )?;
    }
    for mount in &plan.read_only_mounts {
        bind_mount(
            Path::new(&mount.host_path),
            Path::new(&mount.guest_path),
            mount.read_only,
        )?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_mounts(
    _plan: &LinuxMountNamespacePlan,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("agentbox-linux-runner is only available on Linux".into())
}

#[cfg(target_os = "linux")]
fn mount_overlay_workspace(
    overlayfs: &LinuxOverlayFsWorkspacePlan,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::ffi::OsStrExt;

    std::fs::create_dir_all(&overlayfs.upper_host_path)?;
    std::fs::create_dir_all(&overlayfs.work_host_path)?;
    std::fs::create_dir_all(&overlayfs.merged_guest_path)?;

    let target = std::ffi::CString::new(
        Path::new(&overlayfs.merged_guest_path)
            .as_os_str()
            .as_bytes(),
    )?;
    let fstype = std::ffi::CString::new("overlay")?;
    let options = std::ffi::CString::new(overlay_mount_options(overlayfs))?;
    let result = unsafe {
        libc::mount(
            fstype.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            options.as_ptr().cast::<libc::c_void>(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn overlay_mount_options(overlayfs: &LinuxOverlayFsWorkspacePlan) -> String {
    format!(
        "lowerdir={},upperdir={},workdir={}",
        overlayfs.lower_host_path, overlayfs.upper_host_path, overlayfs.work_host_path
    )
}

#[cfg(target_os = "linux")]
fn bind_mount(
    source: &Path,
    target: &Path,
    read_only: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::ffi::OsStrExt;

    std::fs::create_dir_all(target)?;
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let target = std::ffi::CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null::<libc::c_char>(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null::<libc::c_void>(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    if read_only {
        let result = unsafe {
            libc::mount(
                std::ptr::null::<libc::c_char>(),
                target.as_ptr(),
                std::ptr::null::<libc::c_char>(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
                std::ptr::null::<libc::c_void>(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn exec_request(
    request: LinuxAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::process::CommandExt;

    let working_dir = request
        .working_dir
        .unwrap_or(request.mount_namespace.workspace_guest_path);
    let mut command = std::process::Command::new(&request.command_argv[0]);
    command.args(&request.command_argv[1..]);
    command.current_dir(working_dir);
    Err(command.exec().into())
}

#[cfg(not(target_os = "linux"))]
fn exec_request(
    _request: LinuxAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("agentbox-linux-runner exec is only available on Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentbox_daemon::runtime::providers::linux::{
        LinuxLandlockAccess, LinuxLandlockPathPolicyPlan, LinuxMountNamespaceBoundaryPlan,
        LinuxMountNamespaceMount, LinuxOverlayFsWorkspacePlan, LinuxSeccompProfileImportDescriptor,
        LinuxUserNamespacePlan,
    };
    use agentbox_daemon::runtime::types::AgentPodWorkspaceMode;

    fn request() -> LinuxAgentPodRunnerRequest {
        LinuxAgentPodRunnerRequest {
            user_namespace: LinuxUserNamespacePlan {
                schema_version: 1,
                command_argv: vec!["/bin/true".into()],
                map_root_user: true,
                deny_setgroups: true,
                uid_map: "0 current-user 1".into(),
                gid_map: "0 current-group 1".into(),
                requires_linux: true,
            },
            mount_namespace: LinuxMountNamespacePlan {
                schema_version: 1,
                workspace_mode: AgentPodWorkspaceMode::Direct,
                workspace_host_path: "/tmp/agentbox-work".into(),
                workspace_guest_path: "/workspace".into(),
                workspace_bind_mount_wired: true,
                workspace_mount_claim: "test".into(),
                overlayfs: None,
                read_only_mounts: Vec::<LinuxMountNamespaceMount>::new(),
                propagation: "private".into(),
                boundary: LinuxMountNamespaceBoundaryPlan::runner_managed(),
                requires_linux: true,
            },
            seccomp: agentbox_daemon::runtime::providers::linux::LinuxSeccompPlan {
                schema_version: 1,
                enabled: false,
                default_action: agentbox_daemon::runtime::types::SeccompAction::Allow,
                syscall_rules: Vec::new(),
                denied_syscall_fixture: None,
                import_descriptor: LinuxSeccompProfileImportDescriptor {
                    schema_version: 1,
                    supported_formats: vec!["oci-seccomp-v1-json".into()],
                    generated_oci_profile: false,
                    import_enabled: false,
                    loader_scope: "test".into(),
                    claim_boundary: "test".into(),
                },
                oci_profile: None,
                requires_loader: false,
                requires_linux: true,
            },
            landlock: agentbox_daemon::runtime::providers::linux::LinuxLandlockPlan {
                schema_version: 1,
                ruleset_name: "test".into(),
                abi: agentbox_daemon::runtime::providers::linux::LinuxLandlockAbiPlan {
                    schema_version: 1,
                    host_abi_version: None,
                    effective_abi_version: 1,
                    supported_access: vec![LinuxLandlockAccess::WriteFile],
                    unsupported_access: Vec::new(),
                    supported_access_mask: 1,
                    claim_boundary: "test".into(),
                },
                rules: vec![LinuxLandlockRule {
                    path: "/tmp/agentbox-work".into(),
                    access: vec![LinuxLandlockAccess::WriteFile],
                    reason: "workspace".into(),
                    access_mask: 1,
                    optional: false,
                }],
                path_policy: LinuxLandlockPathPolicyPlan::runner_loader_scope(),
                handled_access_mask: 1,
                default_deny: true,
                requires_loader: true,
                requires_linux: true,
            },
            command_argv: vec!["/bin/true".into()],
            working_dir: Some("/workspace".into()),
        }
    }

    #[test]
    fn landlock_alias_adds_guest_workspace_rule() {
        let request = request();

        let plan = landlock_with_guest_workspace_alias(&request);

        assert!(plan.rules.iter().any(|rule| {
            rule.path == "/workspace" && rule.reason == "guest workspace bind-mount alias"
        }));
    }

    #[test]
    fn landlock_alias_adds_guest_read_only_mount_rules() {
        let mut request = request();
        request
            .mount_namespace
            .read_only_mounts
            .push(LinuxMountNamespaceMount {
                host_path: "/tmp/agentbox-fixtures".into(),
                guest_path: "/fixtures".into(),
                read_only: true,
            });
        request.landlock.rules.push(LinuxLandlockRule {
            path: "/tmp/agentbox-fixtures".into(),
            access: vec![LinuxLandlockAccess::ReadFile],
            reason: "fixtures".into(),
            access_mask: 4,
            optional: false,
        });

        let plan = landlock_with_guest_workspace_alias(&request);

        assert!(plan.rules.iter().any(|rule| {
            rule.path == "/fixtures" && rule.reason == "guest read-only bind-mount alias"
        }));
    }

    #[test]
    fn validates_overlayfs_workspace_request() {
        let mut request = request();
        request.mount_namespace.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        request.mount_namespace.overlayfs = Some(LinuxOverlayFsWorkspacePlan {
            lower_host_path: "/tmp/agentbox-work".into(),
            upper_host_path: "/tmp/agentbox-overlay/upper".into(),
            work_host_path: "/tmp/agentbox-overlay/work".into(),
            merged_guest_path: "/workspace".into(),
            mode: agentbox_daemon::runtime::types::WorkspaceOverlayMode::ReviewRequired,
            review_required: true,
            requires_overlayfs: true,
        });

        validate_request(&request).unwrap();
        assert_eq!(
            overlay_mount_options(request.mount_namespace.overlayfs.as_ref().unwrap()),
            "lowerdir=/tmp/agentbox-work,upperdir=/tmp/agentbox-overlay/upper,workdir=/tmp/agentbox-overlay/work"
        );
    }

    #[test]
    fn validates_ephemeral_overlay_workspace_request() {
        let mut request = request();
        request.mount_namespace.workspace_mode = AgentPodWorkspaceMode::Ephemeral;
        request.mount_namespace.overlayfs = Some(LinuxOverlayFsWorkspacePlan {
            lower_host_path: "/tmp/agentbox-work".into(),
            upper_host_path: "/tmp/agentbox-ephemeral/upper".into(),
            work_host_path: "/tmp/agentbox-ephemeral/work".into(),
            merged_guest_path: "/workspace".into(),
            mode: agentbox_daemon::runtime::types::WorkspaceOverlayMode::DiscardOnDestroy,
            review_required: false,
            requires_overlayfs: true,
        });

        validate_request(&request).unwrap();
    }

    #[test]
    fn rejects_direct_workspace_request_with_overlayfs() {
        let mut request = request();
        request.mount_namespace.overlayfs = Some(LinuxOverlayFsWorkspacePlan {
            lower_host_path: "/tmp/agentbox-work".into(),
            upper_host_path: "/tmp/agentbox-overlay/upper".into(),
            work_host_path: "/tmp/agentbox-overlay/work".into(),
            merged_guest_path: "/workspace".into(),
            mode: agentbox_daemon::runtime::types::WorkspaceOverlayMode::ReviewRequired,
            review_required: true,
            requires_overlayfs: true,
        });

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("direct workspace mode"));
        assert!(err.to_string().contains("must not include overlayfs"));
    }

    #[test]
    fn rejects_read_only_mount_request_with_empty_guest_path() {
        let mut request = request();
        request
            .mount_namespace
            .read_only_mounts
            .push(LinuxMountNamespaceMount {
                host_path: "/tmp/fixtures".into(),
                guest_path: " ".into(),
                read_only: true,
            });

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("read-only mount guest path"));
    }

    #[test]
    fn rejects_overlayfs_request_with_same_upper_and_work_paths() {
        let mut request = request();
        request.mount_namespace.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        request.mount_namespace.overlayfs = Some(LinuxOverlayFsWorkspacePlan {
            lower_host_path: "/tmp/agentbox-work".into(),
            upper_host_path: "/tmp/agentbox-overlay/same".into(),
            work_host_path: "/tmp/agentbox-overlay/same".into(),
            merged_guest_path: "/workspace".into(),
            mode: agentbox_daemon::runtime::types::WorkspaceOverlayMode::ReviewRequired,
            review_required: true,
            requires_overlayfs: true,
        });

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("upper and work paths must differ"));
    }
}
