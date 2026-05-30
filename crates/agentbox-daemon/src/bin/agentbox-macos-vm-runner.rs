use agentbox_daemon::runtime::providers::macos::MacOsAgentPodRunnerRequest;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(err) = run() {
        eprintln!("agentbox-macos-vm-runner: {err}");
        std::process::exit(125);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let request_path = match parse_args()? {
        RunnerArgs::Help => {
            print_usage();
            return Ok(());
        }
        RunnerArgs::Version => {
            println!("agentbox-macos-vm-runner {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        RunnerArgs::Request(path) => path,
    };
    let request = read_request(&request_path)?;
    validate_request(&request)?;
    Err(
        "macOS AgentPod VM runner contract is valid, but Apple Virtualization execution is not wired yet"
            .into(),
    )
}

enum RunnerArgs {
    Help,
    Version,
    Request(PathBuf),
}

fn parse_args() -> Result<RunnerArgs, Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (Some(flag), None, None) if flag == "--help" || flag == "-h" => Ok(RunnerArgs::Help),
        (Some(flag), None, None) if flag == "--version" || flag == "-V" => Ok(RunnerArgs::Version),
        (Some(flag), Some(path), None) if flag == "--request" => {
            Ok(RunnerArgs::Request(PathBuf::from(path)))
        }
        _ => Err("usage: agentbox-macos-vm-runner --request <request.json>".into()),
    }
}

fn print_usage() {
    println!("agentbox-macos-vm-runner --request <request.json>");
    println!("  Contract-only macOS AgentPod VM runner.");
    println!(
        "  Validates VM request JSON and refuses execution until Apple Virtualization is wired."
    );
}

fn read_request(
    path: &Path,
) -> Result<MacOsAgentPodRunnerRequest, Box<dyn std::error::Error + Send + Sync>> {
    let file = std::fs::File::open(path)?;
    Ok(serde_json::from_reader(file)?)
}

fn validate_request(
    request: &MacOsAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if request.schema_version != 1 {
        return Err("macOS VM runner request schema_version must be 1".into());
    }
    validate_nested_schema_versions(request)?;
    if request.session_id.trim().is_empty() {
        return Err("macOS VM runner request session id cannot be empty".into());
    }
    if request.command_argv.is_empty() {
        return Err("macOS VM runner request command argv cannot be empty".into());
    }
    if request.command_argv[0].trim().is_empty() {
        return Err("macOS VM runner request command argv[0] cannot be empty".into());
    }
    if request.virtualization.workspace_host_path.trim().is_empty() {
        return Err("macOS VM runner request workspace host path cannot be empty".into());
    }
    validate_host_path(
        "macOS VM runner request workspace host path",
        &request.virtualization.workspace_host_path,
    )?;
    if request
        .virtualization
        .workspace_guest_path
        .trim()
        .is_empty()
    {
        return Err("macOS VM runner request workspace guest path cannot be empty".into());
    }
    validate_guest_path(
        "macOS VM runner request workspace guest path",
        &request.virtualization.workspace_guest_path,
    )?;
    if request
        .virtualization
        .host_bridge
        .guest_socket_path
        .trim()
        .is_empty()
    {
        return Err("macOS VM runner request bridge socket path cannot be empty".into());
    }
    validate_guest_path(
        "macOS VM runner request bridge socket path",
        &request.virtualization.host_bridge.guest_socket_path,
    )?;
    validate_virtualization_paths(request)?;
    if !request
        .runner_phases
        .iter()
        .any(|phase| phase.name == "start-virtualization-vm")
    {
        return Err("macOS VM runner request must include start-virtualization-vm phase".into());
    }
    if !request
        .required_entitlements
        .iter()
        .any(|entitlement| entitlement == "com.apple.security.virtualization")
    {
        return Err("macOS VM runner request must require Apple Virtualization entitlement".into());
    }
    request.boot_request.validate()?;
    if request.boot_request.session_id != request.session_id {
        return Err("macOS VM runner boot request session id must match request".into());
    }
    if request.boot_request.command_argv != request.command_argv {
        return Err("macOS VM runner boot request command argv must match request".into());
    }
    validate_boot_request_references(request)?;
    Ok(())
}

fn validate_nested_schema_versions(
    request: &MacOsAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if request.virtualization.schema_version != 1 {
        return Err("macOS VM runner virtualization schema_version must be 1".into());
    }
    if request.virtualization.storage_layout.schema_version != 1 {
        return Err("macOS VM runner cell storage schema_version must be 1".into());
    }
    if request.endpoint_security.schema_version != 1 {
        return Err("macOS VM runner Endpoint Security schema_version must be 1".into());
    }
    if request.network_extension.schema_version != 1 {
        return Err("macOS VM runner Network Extension schema_version must be 1".into());
    }
    if request.evidence_observer.schema_version != 1 {
        return Err("macOS VM runner evidence observer schema_version must be 1".into());
    }
    Ok(())
}

fn validate_virtualization_paths(
    request: &MacOsAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let virtualization = &request.virtualization;
    let storage = &virtualization.storage_layout;
    let workspace_mount = &virtualization.cell_config.workspace_mount;

    if workspace_mount.host_path != virtualization.workspace_host_path {
        return Err(
            "macOS VM runner request workspace mount host path must match workspace host path"
                .into(),
        );
    }
    if workspace_mount.guest_path != virtualization.workspace_guest_path {
        return Err(
            "macOS VM runner request workspace mount guest path must match workspace guest path"
                .into(),
        );
    }
    if virtualization.cell_config.bridge_socket_guest_path
        != virtualization.host_bridge.guest_socket_path
    {
        return Err(
            "macOS VM runner request bridge socket path must match cell config bridge socket path"
                .into(),
        );
    }

    validate_cell_path(
        "macOS VM runner request cell root host path",
        &storage.cell_root_host_path,
    )?;
    validate_cell_path(
        "macOS VM runner request cell config host path",
        &storage.config_json_host_path,
    )?;
    validate_cell_path(
        "macOS VM runner request disk image host path",
        &storage.disk_image_host_path,
    )?;
    validate_cell_path(
        "macOS VM runner request auxiliary storage host path",
        &storage.auxiliary_storage_host_path,
    )?;
    validate_cell_path(
        "macOS VM runner request credential channel host path",
        &storage.credential_channel_host_path,
    )?;
    validate_cell_path(
        "macOS VM runner request evidence spool host path",
        &storage.evidence_spool_host_path,
    )?;
    validate_host_path(
        "macOS VM runner request workspace mount host path",
        &storage.workspace_mount_host_path,
    )?;
    if storage.workspace_mount_host_path != virtualization.workspace_host_path {
        return Err(
            "macOS VM runner request storage workspace mount path must match workspace host path"
                .into(),
        );
    }

    for directory in &virtualization.shared_directories {
        validate_host_path(
            "macOS VM runner request shared directory host path",
            &directory.host_path,
        )?;
        validate_guest_path(
            "macOS VM runner request shared directory guest path",
            &directory.guest_path,
        )?;
    }

    Ok(())
}

fn validate_boot_request_references(
    request: &MacOsAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let boot = &request.boot_request;
    let virtualization = &request.virtualization;

    if boot.bundle_id != virtualization.bundle_id {
        return Err("macOS VM runner boot request bundle id must match virtualization plan".into());
    }
    if boot.guest_os != virtualization.guest_os {
        return Err("macOS VM runner boot request guest OS must match virtualization plan".into());
    }
    if boot.cpu_count != virtualization.cpu_count
        || boot.memory_bytes != virtualization.memory_bytes
    {
        return Err("macOS VM runner boot request resources must match virtualization plan".into());
    }
    if boot.storage_layout != virtualization.storage_layout {
        return Err(
            "macOS VM runner boot request storage layout must match virtualization plan".into(),
        );
    }
    if boot.workspace_mount != virtualization.cell_config.workspace_mount {
        return Err(
            "macOS VM runner boot request workspace mount must match virtualization plan".into(),
        );
    }
    if boot.shared_directories != virtualization.shared_directories {
        return Err(
            "macOS VM runner boot request shared directories must match virtualization plan".into(),
        );
    }
    if boot.bridge_socket_guest_path != virtualization.cell_config.bridge_socket_guest_path {
        return Err(
            "macOS VM runner boot request bridge socket path must match virtualization plan".into(),
        );
    }
    if boot.evidence_spool_guest_path != virtualization.cell_config.evidence_spool_guest_path {
        return Err(
            "macOS VM runner boot request evidence spool path must match virtualization plan"
                .into(),
        );
    }
    if boot.required_entitlements != request.required_entitlements {
        return Err("macOS VM runner boot request entitlements must match request".into());
    }

    Ok(())
}

fn validate_cell_path(
    label: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    validate_host_path(label, path)
}

fn validate_host_path(
    label: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    validate_absolute_path(label, path)
}

fn validate_guest_path(
    label: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    validate_absolute_path(label, path)
}

fn validate_absolute_path(
    label: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} cannot be empty").into());
    }
    let path = Path::new(trimmed);
    if !path.is_absolute() {
        return Err(format!("{label} must be absolute").into());
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("{label} cannot contain parent directory traversal").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentbox_daemon::runtime::providers::macos::MacOsAgentPodExecutionPlan;
    use agentbox_daemon::runtime::types::{ExecCommand, MinipodSpec};
    use std::collections::HashMap;

    fn request() -> MacOsAgentPodRunnerRequest {
        let spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        let command = ExecCommand {
            argv: vec!["/bin/true".into()],
            working_dir: Some("/workspace".into()),
            env: HashMap::new(),
            timeout_seconds: None,
        };
        let plan = MacOsAgentPodExecutionPlan::from_minipod_spec(&spec, &command).unwrap();
        MacOsAgentPodRunnerRequest::from_execution_plan(&plan, &command)
    }

    #[test]
    fn validates_complete_contract_request() {
        validate_request(&request()).unwrap();
    }

    #[test]
    fn rejects_empty_command_request() {
        let mut request = request();
        request.command_argv.clear();

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("command argv"));
    }

    #[test]
    fn rejects_malformed_schema_version() {
        let mut request = request();
        request.schema_version = 2;

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn rejects_malformed_nested_schema_version() {
        let mut request = request();
        request.virtualization.storage_layout.schema_version = 2;

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("cell storage schema_version"));
    }

    #[test]
    fn rejects_request_without_vm_phase() {
        let mut request = request();
        request
            .runner_phases
            .retain(|phase| phase.name != "start-virtualization-vm");

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("start-virtualization-vm"));
    }

    #[test]
    fn rejects_request_without_virtualization_entitlement() {
        let mut request = request();
        request
            .required_entitlements
            .retain(|entitlement| entitlement != "com.apple.security.virtualization");
        request.boot_request.required_entitlements = request.required_entitlements.clone();

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("Virtualization entitlement"));
    }

    #[test]
    fn rejects_mismatched_boot_request_contract() {
        let mut request = request();
        request.boot_request.command_argv = vec!["/bin/false".into()];

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("boot request command argv"));
    }

    #[test]
    fn rejects_unsafe_workspace_paths() {
        let mut request = request();
        request.virtualization.workspace_host_path = "../agentbox-work".into();
        request.virtualization.cell_config.workspace_mount.host_path = "../agentbox-work".into();

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("workspace host path"));
    }

    #[test]
    fn rejects_unsafe_cell_paths() {
        let mut request = request();
        request.virtualization.storage_layout.disk_image_host_path =
            "/tmp/agentbox-cell/../outside/rootfs.img".into();

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("disk image host path"));
    }

    #[test]
    fn rejects_unsafe_bridge_path() {
        let mut request = request();
        request.virtualization.host_bridge.guest_socket_path = "bridge.sock".into();
        request.virtualization.cell_config.bridge_socket_guest_path = "bridge.sock".into();
        request.boot_request.bridge_socket_guest_path = "bridge.sock".into();

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("bridge socket path"));
    }

    #[test]
    fn rejects_mismatched_boot_request_references() {
        let mut request = request();
        request.boot_request.bundle_id = "dev.agentbox.agentpod.other".into();

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("boot request bundle id"));
    }
}
