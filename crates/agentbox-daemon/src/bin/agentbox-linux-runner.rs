use agentbox_daemon::runtime::providers::linux::{
    LinuxAgentPodRunnerRequest, LinuxLandlockRuleset, LinuxMountNamespacePlan,
    LinuxSeccompProfileLoader,
};
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
    LinuxLandlockRuleset::apply(&request.landlock)?;
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
    if request.mount_namespace.overlayfs.is_some() {
        return Err("runner overlayfs workspace mounts are not wired yet".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_mounts(
    plan: &LinuxMountNamespacePlan,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    bind_mount(
        Path::new(&plan.workspace_host_path),
        Path::new(&plan.workspace_guest_path),
        false,
    )?;
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
