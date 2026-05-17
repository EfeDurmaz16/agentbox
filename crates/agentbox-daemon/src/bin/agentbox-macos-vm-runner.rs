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
    if request.session_id.trim().is_empty() {
        return Err("macOS VM runner request session id cannot be empty".into());
    }
    if request.command_argv.is_empty() {
        return Err("macOS VM runner request command argv cannot be empty".into());
    }
    if request.virtualization.workspace_host_path.trim().is_empty() {
        return Err("macOS VM runner request workspace host path cannot be empty".into());
    }
    if request
        .virtualization
        .workspace_guest_path
        .trim()
        .is_empty()
    {
        return Err("macOS VM runner request workspace guest path cannot be empty".into());
    }
    if request
        .virtualization
        .host_bridge
        .guest_socket_path
        .trim()
        .is_empty()
    {
        return Err("macOS VM runner request bridge socket path cannot be empty".into());
    }
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
    fn rejects_request_without_vm_phase() {
        let mut request = request();
        request
            .runner_phases
            .retain(|phase| phase.name != "start-virtualization-vm");

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("start-virtualization-vm"));
    }

    #[test]
    fn rejects_mismatched_boot_request_contract() {
        let mut request = request();
        request.boot_request.command_argv = vec!["/bin/false".into()];

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("boot request command argv"));
    }
}
