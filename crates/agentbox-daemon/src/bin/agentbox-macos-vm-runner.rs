use agentbox_daemon::runtime::providers::macos::MacOsAgentPodRunnerRequest;
use serde::Serialize;
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
    if macos_boot_prototype_enabled() {
        return run_boot_prototype(&request);
    }
    Err(
        "macOS AgentPod VM runner contract is valid, but AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1 is required before the Apple Virtualization boot prototype can run"
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
    println!("  Gated macOS AgentPod VM runner.");
    println!(
        "  Validates VM request JSON; AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1 enables the Apple Virtualization boot prototype."
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
    if let Some(path) = &request.boot_request.linux_boot.kernel_image_host_path {
        validate_host_path("macOS VM runner Linux kernel image path", path)?;
    }
    if let Some(path) = &request.boot_request.linux_boot.initial_ramdisk_host_path {
        validate_host_path("macOS VM runner Linux initial RAM disk path", path)?;
    }
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
    if boot.linux_boot != virtualization.linux_boot {
        return Err(
            "macOS VM runner boot request Linux boot plan must match virtualization plan".into(),
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

#[derive(Debug, Serialize)]
struct MacOsVmBootPrototypeReport {
    schema_version: i64,
    provider: &'static str,
    session_id: String,
    status: &'static str,
    reason_code: Option<&'static str>,
    reason: Option<String>,
    gate_env_var: &'static str,
    apple_requirements: Vec<&'static str>,
    checks: Vec<MacOsVmBootPrototypeCheck>,
    next_steps: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MacOsVmBootPrototypeCheck {
    name: &'static str,
    required: bool,
    status: &'static str,
    detail: String,
}

fn macos_boot_prototype_enabled() -> bool {
    matches!(
        std::env::var("AGENTBOX_MACOS_VM_BOOT_PROTOTYPE").as_deref(),
        Ok("1")
    )
}

fn run_boot_prototype(
    request: &MacOsAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut report = evaluate_boot_prototype_prerequisites(request);
    if report.status != "ready" {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Err(format!(
            "macOS AgentPod VM boot prototype blocked: {}: {}",
            report.reason_code.unwrap_or("unknown"),
            report
                .reason
                .as_deref()
                .unwrap_or("unknown prerequisite failure")
        )
        .into());
    }

    match attempt_apple_virtualization_boot(request) {
        Ok(()) => {
            report.status = "booted";
            report.reason_code = None;
            report.reason = None;
            report.next_steps = vec![
                "wire VM lifecycle evidence into the Agentbox host bridge".into(),
                "add stop/cleanup evidence before enabling agentpod-macos provider execution"
                    .into(),
            ];
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Err(err) => {
            report.status = "blocked";
            report.reason_code = Some("apple_virtualization_start_failed");
            report.reason = Some(err.to_string());
            report.checks.push(boot_check(
                "apple-virtualization-start",
                true,
                "failed",
                err.to_string(),
            ));
            println!("{}", serde_json::to_string_pretty(&report)?);
            Err(format!("macOS AgentPod VM boot prototype failed: {err}").into())
        }
    }
}

fn evaluate_boot_prototype_prerequisites(
    request: &MacOsAgentPodRunnerRequest,
) -> MacOsVmBootPrototypeReport {
    let mut checks = Vec::new();
    checks.push(boot_check(
        "host-os",
        true,
        if cfg!(target_os = "macos") {
            "ok"
        } else {
            "missing"
        },
        if cfg!(target_os = "macos") {
            "running on macOS".into()
        } else {
            "Apple Virtualization boot requires macOS".into()
        },
    ));
    checks.push(path_check(
        "virtualization-framework",
        true,
        Path::new("/System/Library/Frameworks/Virtualization.framework"),
    ));

    let kernel_path = request
        .boot_request
        .linux_boot
        .kernel_image_host_path
        .as_deref();
    let initrd_path = request
        .boot_request
        .linux_boot
        .initial_ramdisk_host_path
        .as_deref();
    checks.push(optional_path_check(
        "linux-kernel-image",
        true,
        kernel_path,
        "set AGENTBOX_MACOS_VM_KERNEL_IMAGE to a host-architecture Linux kernel image",
    ));
    checks.push(optional_path_check(
        "linux-initial-ramdisk",
        true,
        initrd_path,
        "set AGENTBOX_MACOS_VM_INITRD_IMAGE to a matching Linux initial RAM disk image",
    ));
    checks.push(command_check(
        "swiftc",
        true,
        &["xcrun", "--find", "swiftc"],
        "Swift compiler is required for the gated Apple Virtualization boot helper",
    ));
    checks.push(command_check(
        "codesign",
        true,
        &["/usr/bin/codesign", "--version"],
        "codesign is required to attach com.apple.security.virtualization to the boot helper",
    ));

    let first_failure = checks
        .iter()
        .find(|check| check.required && check.status != "ok");
    let (status, reason_code, reason, next_steps) = match first_failure {
        Some(check) => (
            "blocked",
            Some(check.name),
            Some(check.detail.clone()),
            vec![
                "provide AGENTBOX_MACOS_VM_KERNEL_IMAGE and AGENTBOX_MACOS_VM_INITRD_IMAGE".into(),
                "run on macOS with Apple Virtualization support".into(),
                "allow the boot helper to be ad-hoc signed with com.apple.security.virtualization"
                    .into(),
            ],
        ),
        None => (
            "ready",
            None,
            None,
            vec![
                "attempt VZVirtualMachineConfiguration.validate() and VZVirtualMachine.start()"
                    .into(),
            ],
        ),
    };

    MacOsVmBootPrototypeReport {
        schema_version: 1,
        provider: "agentpod-macos",
        session_id: request.session_id.clone(),
        status,
        reason_code,
        reason,
        gate_env_var: "AGENTBOX_MACOS_VM_BOOT_PROTOTYPE",
        apple_requirements: vec![
            "VZVirtualMachine.isSupported must be true on the host",
            "the executable that uses Virtualization must carry com.apple.security.virtualization",
            "VZVirtualMachineConfiguration must include a bootLoader and pass validate()",
            "Linux guests use VZLinuxBootLoader with a kernelURL and initialRamdiskURL",
            "VZVirtualMachine.start(completionHandler:) starts the VM asynchronously",
        ],
        checks,
        next_steps,
    }
}

fn boot_check(
    name: &'static str,
    required: bool,
    status: &'static str,
    detail: String,
) -> MacOsVmBootPrototypeCheck {
    MacOsVmBootPrototypeCheck {
        name,
        required,
        status,
        detail,
    }
}

fn path_check(name: &'static str, required: bool, path: &Path) -> MacOsVmBootPrototypeCheck {
    if path.exists() {
        boot_check(name, required, "ok", path.display().to_string())
    } else {
        boot_check(
            name,
            required,
            "missing",
            format!("missing {}", path.display()),
        )
    }
}

fn optional_path_check(
    name: &'static str,
    required: bool,
    path: Option<&str>,
    missing_detail: &str,
) -> MacOsVmBootPrototypeCheck {
    match path {
        Some(path) => path_check(name, required, Path::new(path)),
        None => boot_check(name, required, "missing", missing_detail.into()),
    }
}

fn command_check(
    name: &'static str,
    required: bool,
    command: &[&str],
    missing_detail: &str,
) -> MacOsVmBootPrototypeCheck {
    let Some((binary, args)) = command.split_first() else {
        return boot_check(name, required, "missing", missing_detail.into());
    };
    match std::process::Command::new(binary).args(args).output() {
        Ok(output) if output.status.success() => boot_check(
            name,
            required,
            "ok",
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ),
        Ok(output) => {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            boot_check(
                name,
                required,
                "missing",
                if detail.is_empty() {
                    missing_detail.into()
                } else {
                    detail
                },
            )
        }
        Err(err) => boot_check(
            name,
            required,
            "missing",
            format!("{missing_detail}: {err}"),
        ),
    }
}

#[cfg(target_os = "macos")]
fn attempt_apple_virtualization_boot(
    request: &MacOsAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let temp_root = std::env::temp_dir().join(format!(
        "agentbox-macos-vm-boot-prototype-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&temp_root)?;
    let helper_source = temp_root.join("AgentboxMacOsVmBootPrototype.swift");
    let helper_binary = temp_root.join("agentbox-macos-vm-boot-prototype");
    let entitlements = temp_root.join("agentbox-macos-vm-boot-prototype.entitlements");
    std::fs::write(&helper_source, MACOS_VM_BOOT_PROTOTYPE_SWIFT)?;
    std::fs::write(&entitlements, MACOS_VM_BOOT_PROTOTYPE_ENTITLEMENTS)?;

    let swiftc = find_swiftc()?;
    let compile = std::process::Command::new(swiftc)
        .arg(&helper_source)
        .arg("-framework")
        .arg("Virtualization")
        .arg("-o")
        .arg(&helper_binary)
        .output()?;
    if !compile.status.success() {
        return Err(format!(
            "swiftc failed: {}",
            String::from_utf8_lossy(&compile.stderr).trim()
        )
        .into());
    }

    let codesign = std::process::Command::new("/usr/bin/codesign")
        .arg("--force")
        .arg("--sign")
        .arg("-")
        .arg("--entitlements")
        .arg(&entitlements)
        .arg(&helper_binary)
        .output()?;
    if !codesign.status.success() {
        return Err(format!(
            "codesign failed: {}",
            String::from_utf8_lossy(&codesign.stderr).trim()
        )
        .into());
    }

    let kernel = request
        .boot_request
        .linux_boot
        .kernel_image_host_path
        .as_deref()
        .ok_or("missing kernel image after prerequisite evaluation")?;
    let initrd = request
        .boot_request
        .linux_boot
        .initial_ramdisk_host_path
        .as_deref()
        .ok_or("missing initial RAM disk after prerequisite evaluation")?;
    let timeout = std::env::var("AGENTBOX_MACOS_VM_BOOT_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15);
    let command_line = request
        .boot_request
        .linux_boot
        .kernel_command_line
        .join(" ");

    let run = std::process::Command::new(&helper_binary)
        .arg(kernel)
        .arg(initrd)
        .arg(request.boot_request.cpu_count.to_string())
        .arg(request.boot_request.memory_bytes.to_string())
        .arg(command_line)
        .arg(timeout.to_string())
        .output()?;
    let _ = std::fs::remove_dir_all(&temp_root);
    if run.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&run.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&run.stdout).trim().to_string();
    Err(if stderr.is_empty() { stdout } else { stderr }.into())
}

#[cfg(not(target_os = "macos"))]
fn attempt_apple_virtualization_boot(
    _request: &MacOsAgentPodRunnerRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("Apple Virtualization boot can only run on macOS".into())
}

#[cfg(target_os = "macos")]
fn find_swiftc() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let output = std::process::Command::new("xcrun")
        .arg("--find")
        .arg("swiftc")
        .output()?;
    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    Err("swiftc not found through xcrun".into())
}

#[cfg(target_os = "macos")]
const MACOS_VM_BOOT_PROTOTYPE_ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.virtualization</key>
  <true/>
</dict>
</plist>
"#;

#[cfg(target_os = "macos")]
const MACOS_VM_BOOT_PROTOTYPE_SWIFT: &str = r#"
import Foundation
import Virtualization

enum AgentboxBootError: Error, CustomStringConvertible {
    case unsupportedHost
    case timedOut
    case invalidArguments
    case startFailed(String)

    var description: String {
        switch self {
        case .unsupportedHost:
            return "VZVirtualMachine.isSupported is false on this host"
        case .timedOut:
            return "VZVirtualMachine.start(completionHandler:) timed out"
        case .invalidArguments:
            return "usage: helper <kernel> <initrd> <cpu> <memory_bytes> <command_line> <timeout_seconds>"
        case .startFailed(let message):
            return message
        }
    }
}

func run() throws {
    let args = CommandLine.arguments
    guard args.count == 7,
          let cpuCount = Int(args[3]),
          let memorySize = UInt64(args[4]),
          let timeoutSeconds = Int(args[6]) else {
        throw AgentboxBootError.invalidArguments
    }

    guard VZVirtualMachine.isSupported else {
        throw AgentboxBootError.unsupportedHost
    }

    let configuration = VZVirtualMachineConfiguration()
    configuration.cpuCount = cpuCount
    configuration.memorySize = memorySize

    let bootLoader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: args[1]))
    bootLoader.initialRamdiskURL = URL(fileURLWithPath: args[2])
    bootLoader.commandLine = args[5]
    configuration.bootLoader = bootLoader

    let console = VZVirtioConsoleDeviceSerialPortConfiguration()
    let input = FileHandle(forReadingAtPath: "/dev/null")!
    let output = FileHandle(forWritingAtPath: "/dev/null")!
    console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: input, fileHandleForWriting: output)
    configuration.serialPorts = [console]
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

    try configuration.validate()

    let virtualMachine = VZVirtualMachine(configuration: configuration)
    let semaphore = DispatchSemaphore(value: 0)
    var startError: Error?
    virtualMachine.start { result in
        switch result {
        case .success:
            break
        case .failure(let error):
            startError = error
        }
        semaphore.signal()
    }

    if semaphore.wait(timeout: .now() + .seconds(timeoutSeconds)) == .timedOut {
        throw AgentboxBootError.timedOut
    }
    if let startError {
        throw AgentboxBootError.startFailed(String(describing: startError))
    }

    if virtualMachine.canRequestStop {
        try? virtualMachine.requestStop()
    }
    if virtualMachine.canStop {
        let stopSemaphore = DispatchSemaphore(value: 0)
        virtualMachine.stop { _ in
            stopSemaphore.signal()
        }
        _ = stopSemaphore.wait(timeout: .now() + .seconds(5))
    }
}

do {
    try run()
    print("started")
} catch {
    FileHandle.standardError.write(Data(String(describing: error).utf8))
    exit(125)
}
"#;

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

    #[test]
    fn rejects_mismatched_linux_boot_plan_references() {
        let mut request = request();
        request.boot_request.linux_boot.boot_loader = "VZEFIBootLoader".into();

        let err = validate_request(&request).unwrap_err();

        assert!(err.to_string().contains("Linux boot plan"));
    }

    #[test]
    fn boot_prototype_report_blocks_without_host_prerequisites() {
        let request = request();

        let report = evaluate_boot_prototype_prerequisites(&request);

        assert_eq!(report.schema_version, 1);
        assert_eq!(report.provider, "agentpod-macos");
        assert_eq!(report.status, "blocked");
        assert!(report.reason_code.is_some());
        assert!(report
            .apple_requirements
            .iter()
            .any(|requirement| requirement.contains("VZVirtualMachineConfiguration")));
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "linux-kernel-image" && check.required));
    }
}
