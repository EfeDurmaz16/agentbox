use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::time::sleep;
use tracing::{debug, info};

use crate::pod::provider::{PodError, PodProvider};
use crate::pod::types::*;

/// Commands that the agentbox shim intercepts inside the pod.
const SHIMMED_COMMANDS: &[&str] = &[
    "rm", "git", "ssh", "curl", "wget", "psql", "mysql", "chmod", "kill", "scp", "sendmail",
];

/// PodmanProvider manages pods via the `podman` CLI.
///
/// Key features:
/// - Mounts the host agentbox daemon socket into pods at `/run/agentbox.sock`
/// - Copies the agentbox-shim binary and creates symlinks for dangerous commands
/// - Uses podman pods to group workspace + sidecar containers
pub struct PodmanProvider {
    /// Path to the host's agentbox daemon socket.
    agentbox_socket: String,
    /// Path to the compiled agentbox-shim binary.
    shim_binary: String,
    /// Active pod sessions indexed by pod id.
    sessions: Mutex<HashMap<String, PodSession>>,
}

impl PodmanProvider {
    pub fn new(agentbox_socket: String, shim_binary: String) -> Self {
        Self {
            agentbox_socket,
            shim_binary,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Construct the pod name from an agentbox session id.
    fn pod_name(id: &str) -> String {
        format!("sb-{}", id)
    }

    /// Construct a container name within a pod.
    fn container_name(id: &str, role: &str) -> String {
        format!("sb-{}-{}", id, role)
    }

    /// Run a podman command and return stdout on success.
    async fn run_podman(args: &[&str]) -> Result<String, PodError> {
        debug!("podman {}", args.join(" "));

        let output = Command::new("podman")
            .args(args)
            .output()
            .await
            .map_err(|e| PodError::Unavailable(format!("failed to run podman: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(PodError::Internal(format!(
                "podman {} failed: {}",
                args.first().unwrap_or(&""),
                stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Create the podman pod itself (the network namespace grouping).
    async fn create_pod(&self, id: &str, spec: &PodSpec) -> Result<(), PodError> {
        let pod_name = Self::pod_name(id);
        let mut args = vec![
            "pod".to_string(),
            "create".to_string(),
            "--name".to_string(),
            pod_name,
            "--label".to_string(),
            "agentbox=true".to_string(),
        ];

        // Add user-defined labels
        for (k, v) in &spec.labels {
            args.push("--label".to_string());
            args.push(format!("{}={}", k, v));
        }

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        Self::run_podman(&arg_refs).await?;
        Ok(())
    }

    /// Start the workspace container with mounts for agentbox socket and shim binary.
    async fn start_workspace(
        &self,
        id: &str,
        container: &ContainerSpec,
        spec: &PodSpec,
    ) -> Result<(), PodError> {
        let shim_binary = resolve_linux_guest_shim(&self.shim_binary)?;

        let pod_name = Self::pod_name(id);
        let container_name = Self::container_name(id, "workspace");

        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--pod".to_string(),
            pod_name,
            "--name".to_string(),
            container_name,
        ];

        // Mount host agentbox socket into the pod
        args.push("-v".to_string());
        args.push(format!("{}:/run/agentbox.sock:ro", self.agentbox_socket));

        // Mount the shim binary into the pod
        args.push("-v".to_string());
        args.push(format!(
            "{}:/usr/local/bin/agentbox-shim:ro",
            shim_binary.display()
        ));

        // Mount user-specified volumes (workspace, etc.)
        for mount in &spec.mounts {
            args.push("-v".to_string());
            let ro = if mount.read_only { ":ro" } else { ":rw" };
            args.push(format!(
                "{}:{}{}",
                mount.host_path.display(),
                mount.container_path,
                ro
            ));
        }

        // Resource limits
        let mem_mb = spec.resources.memory_bytes / (1024 * 1024);
        args.push("--memory".to_string());
        args.push(format!("{}m", mem_mb));

        let cpus = spec.resources.cpu_shares as f64 / 1024.0;
        args.push("--cpus".to_string());
        args.push(format!("{:.1}", cpus));

        // Environment variables (merged: spec-level + container-level)
        for (k, v) in &spec.env {
            args.push("-e".to_string());
            args.push(format!("{}={}", k, v));
        }
        for (k, v) in &container.env {
            args.push("-e".to_string());
            args.push(format!("{}={}", k, v));
        }

        // Image + command
        args.push(container.image.clone());
        match &container.command {
            Some(cmd) => args.extend(cmd.iter().cloned()),
            None => {
                args.push("sleep".to_string());
                args.push("infinity".to_string());
            }
        }

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        Self::run_podman(&arg_refs).await?;

        // Set up shim symlinks inside the container
        self.setup_shims(id).await?;

        Ok(())
    }

    /// Start a sidecar container within the pod.
    async fn start_sidecar(&self, id: &str, container: &ContainerSpec) -> Result<(), PodError> {
        let pod_name = Self::pod_name(id);
        let container_name = Self::container_name(id, &container.name);

        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--pod".to_string(),
            pod_name,
            "--name".to_string(),
            container_name,
        ];

        for (k, v) in &container.env {
            args.push("-e".to_string());
            args.push(format!("{}={}", k, v));
        }

        args.push(container.image.clone());
        if let Some(cmd) = &container.command {
            args.extend(cmd.iter().cloned());
        }

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        Self::run_podman(&arg_refs).await?;

        Ok(())
    }

    async fn wait_for_sidecar_readiness(
        &self,
        id: &str,
        container: &ContainerSpec,
    ) -> Result<(), PodError> {
        let Some(probe) = &container.readiness else {
            return Ok(());
        };
        if probe.command.is_empty() {
            return Err(PodError::Internal(format!(
                "sidecar {} readiness command cannot be empty",
                container.name
            )));
        }

        let container_name = Self::container_name(id, &container.name);
        let interval = Duration::from_millis(probe.interval_ms.max(100));
        let timeout = Duration::from_millis(probe.timeout_ms.max(probe.interval_ms.max(100)));
        let started = Instant::now();

        loop {
            let mut args = vec!["exec".to_string(), container_name.clone()];
            args.extend(probe.command.iter().cloned());
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            if Self::run_podman(&arg_refs).await.is_ok() {
                return Ok(());
            }
            if started.elapsed() >= timeout {
                return Err(PodError::Internal(format!(
                    "sidecar {} readiness probe timed out after {}ms",
                    container.name, probe.timeout_ms
                )));
            }
            sleep(interval).await;
        }
    }

    /// Create shim symlinks inside the workspace container so that dangerous
    /// commands route through agentbox-shim.
    async fn setup_shims(&self, id: &str) -> Result<(), PodError> {
        let ws = Self::container_name(id, "workspace");

        // Create symlinks for all shimmed commands
        let symlink_cmds: Vec<String> = SHIMMED_COMMANDS
            .iter()
            .map(|cmd| format!("ln -sf /usr/local/bin/agentbox-shim /usr/local/bin/{}", cmd))
            .collect();
        let script = symlink_cmds.join(" && ");

        Self::run_podman(&["exec", &ws, "sh", "-c", &script]).await?;

        // Set up the socket link so the shim can find the daemon
        Self::run_podman(&[
            "exec",
            &ws,
            "sh",
            "-c",
            "mkdir -p /root/.agentbox && ln -sf /run/agentbox.sock /root/.agentbox/agentbox.sock",
        ])
        .await?;

        info!(id, "shim symlinks installed in workspace container");
        Ok(())
    }

    /// Parse `podman pod ls --format json` output into PodSessions.
    fn parse_pod_list(json_str: &str) -> Result<Vec<PodSession>, PodError> {
        // podman pod ls --format json returns a JSON array
        let pods: Vec<serde_json::Value> = serde_json::from_str(json_str)
            .map_err(|e| PodError::Internal(format!("failed to parse pod list: {}", e)))?;

        let mut sessions = Vec::new();
        for pod in pods {
            let name = pod["Name"].as_str().unwrap_or("");
            // Only include agentbox pods (sb-{id} naming)
            let id = match name.strip_prefix("sb-") {
                Some(id) => id.to_string(),
                None => continue,
            };

            let status_str = pod["Status"].as_str().unwrap_or("unknown");
            let status = match status_str {
                "Running" => PodStatus::Running,
                "Created" => PodStatus::Creating,
                "Paused" => PodStatus::Paused,
                "Stopped" | "Exited" | "Dead" => PodStatus::Stopped,
                other => PodStatus::Failed(other.to_string()),
            };

            sessions.push(PodSession {
                id: id.clone(),
                spec: PodSpec {
                    name: name.to_string(),
                    containers: vec![],
                    network: NetworkPolicy::default(),
                    resources: ResourceLimits::default(),
                    mounts: vec![],
                    env: HashMap::new(),
                    timeout_seconds: None,
                    labels: HashMap::new(),
                },
                status,
                created_at: chrono::Utc::now(),
                provider: "podman".to_string(),
            });
        }

        Ok(sessions)
    }
}

#[async_trait::async_trait]
impl PodProvider for PodmanProvider {
    fn name(&self) -> &str {
        "podman"
    }

    async fn is_available(&self) -> bool {
        Self::run_podman(&["info", "--format", "json"])
            .await
            .is_ok()
    }

    async fn create(&self, id: &str, spec: &PodSpec) -> Result<PodSession, PodError> {
        // Check for duplicate
        {
            let sessions = self.sessions.lock().unwrap();
            if sessions.contains_key(id) {
                return Err(PodError::AlreadyExists(id.to_string()));
            }
        }

        info!(id, "creating pod");

        // 1. Create the pod
        self.create_pod(id, spec).await?;

        // 2. Start sidecars first and wait for readiness before workspace agent startup.
        for container in &spec.containers {
            if matches!(container.role, ContainerRole::Sidecar) {
                self.start_sidecar(id, container).await?;
                self.wait_for_sidecar_readiness(id, container).await?;
            }
        }
        for container in &spec.containers {
            if matches!(container.role, ContainerRole::Workspace) {
                self.start_workspace(id, container, spec).await?;
            }
        }

        let session = PodSession {
            id: id.to_string(),
            spec: spec.clone(),
            status: PodStatus::Running,
            created_at: chrono::Utc::now(),
            provider: "podman".to_string(),
        };

        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.insert(id.to_string(), session.clone());
        }

        info!(id, "pod created and running");
        Ok(session)
    }

    async fn exec(&self, id: &str, req: &ExecRequest) -> Result<ExecResult, PodError> {
        // Verify pod exists
        {
            let sessions = self.sessions.lock().unwrap();
            if !sessions.contains_key(id) {
                return Err(PodError::NotFound(id.to_string()));
            }
        }

        let ws = Self::container_name(id, "workspace");
        let start = Instant::now();

        let mut args = vec!["exec".to_string()];

        // Working directory
        if let Some(dir) = &req.working_dir {
            args.push("-w".to_string());
            args.push(dir.clone());
        }

        // Environment overrides
        for (k, v) in &req.env {
            args.push("-e".to_string());
            args.push(format!("{}={}", k, v));
        }

        args.push(ws);
        args.extend(req.command.iter().cloned());

        debug!(id, cmd = ?req.command, "executing in pod");

        let output = if let Some(timeout_secs) = req.timeout_seconds {
            let duration = std::time::Duration::from_secs(timeout_secs);
            tokio::time::timeout(duration, async {
                let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                Command::new("podman").args(&arg_refs).output().await
            })
            .await
            .map_err(|_| PodError::Timeout(timeout_secs))?
            .map_err(|e| PodError::ExecFailed(format!("failed to run podman exec: {}", e)))?
        } else {
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            Command::new("podman")
                .args(&arg_refs)
                .output()
                .await
                .map_err(|e| PodError::ExecFailed(format!("failed to run podman exec: {}", e)))?
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration_ms,
        })
    }

    async fn status(&self, id: &str) -> Result<PodStatus, PodError> {
        let pod_name = Self::pod_name(id);
        let output =
            Self::run_podman(&["pod", "inspect", &pod_name, "--format", "{{.State}}"]).await;

        match output {
            Ok(state) => {
                let state = state.trim();
                match state {
                    "Running" => Ok(PodStatus::Running),
                    "Created" => Ok(PodStatus::Creating),
                    "Paused" => Ok(PodStatus::Paused),
                    "Stopped" | "Exited" | "Dead" => Ok(PodStatus::Stopped),
                    other => Ok(PodStatus::Failed(other.to_string())),
                }
            }
            Err(_) => Err(PodError::NotFound(id.to_string())),
        }
    }

    async fn destroy(&self, id: &str) -> Result<(), PodError> {
        let pod_name = Self::pod_name(id);
        info!(id, "destroying pod");

        // Force-remove the pod and all its containers
        Self::run_podman(&["pod", "rm", "-f", &pod_name]).await?;

        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.remove(id);
        }

        info!(id, "pod destroyed");
        Ok(())
    }

    async fn list(&self) -> Result<Vec<PodSession>, PodError> {
        let output = Self::run_podman(&[
            "pod",
            "ls",
            "--format",
            "json",
            "--filter",
            "label=agentbox=true",
        ])
        .await?;

        Self::parse_pod_list(&output)
    }
}

fn resolve_linux_guest_shim(configured_path: &str) -> Result<PathBuf, PodError> {
    let configured = PathBuf::from(configured_path);
    for candidate in linux_guest_shim_candidates(&configured) {
        if is_linux_elf(&candidate) {
            return Ok(candidate);
        }
    }

    validate_linux_guest_shim(&configured)?;
    Ok(configured)
}

fn linux_guest_shim_candidates(configured_path: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("AGENTBOX_LINUX_SHIM") {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(configured_path.to_path_buf());
    candidates.push(configured_path.with_extension("linux"));

    if let Some(target_dir) = infer_target_dir(configured_path) {
        for triple in [
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
        ] {
            for profile in ["debug", "release"] {
                candidates.push(target_dir.join(triple).join(profile).join("agentbox-shim"));
            }
        }
    }

    candidates
}

fn infer_target_dir(configured_path: &Path) -> Option<PathBuf> {
    let mut current = configured_path.parent();
    while let Some(dir) = current {
        if dir.file_name().is_some_and(|name| name == "target") {
            return Some(dir.to_path_buf());
        }
        current = dir.parent();
    }
    None
}

fn is_linux_elf(path: &Path) -> bool {
    fs::read(path)
        .map(|magic| magic.starts_with(b"\x7fELF"))
        .unwrap_or(false)
}

fn validate_linux_guest_shim(path: &Path) -> Result<(), PodError> {
    let magic = fs::read(path)
        .map_err(|e| PodError::Unavailable(format!("agentbox-shim not readable: {e}")))?;
    if magic.starts_with(b"\x7fELF") {
        return Ok(());
    }
    if is_macho_magic(&magic) {
        return Err(PodError::Unavailable(
            "Podman compatibility runs Linux containers; the configured agentbox-shim is a macOS Mach-O binary and cannot execute in the minipod. Provide a Linux-compatible agentbox-shim artifact for shim bridge proof.".into(),
        ));
    }
    Err(PodError::Unavailable(
        "configured agentbox-shim is not a Linux ELF binary; set AGENTBOX_LINUX_SHIM or build a Linux-targeted agentbox-shim artifact".into(),
    ))
}

fn is_macho_magic(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some([0xfe, 0xed, 0xfa, 0xce])
            | Some([0xce, 0xfa, 0xed, 0xfe])
            | Some([0xfe, 0xed, 0xfa, 0xcf])
            | Some([0xcf, 0xfa, 0xed, 0xfe])
            | Some([0xca, 0xfe, 0xba, 0xbe])
            | Some([0xbe, 0xba, 0xfe, 0xca])
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn test_provider() -> PodmanProvider {
        PodmanProvider::new(
            "/tmp/test-agentbox.sock".to_string(),
            "/tmp/test-agentbox-shim".to_string(),
        )
    }

    fn test_spec() -> PodSpec {
        PodSpec {
            name: "test-pod".to_string(),
            containers: vec![
                ContainerSpec {
                    name: "workspace".to_string(),
                    image: "node:22-slim".to_string(),
                    command: None,
                    env: HashMap::new(),
                    ports: vec![],
                    role: ContainerRole::Workspace,
                    readiness: None,
                },
                ContainerSpec {
                    name: "postgres".to_string(),
                    image: "postgres:16-alpine".to_string(),
                    command: None,
                    env: HashMap::from([("POSTGRES_PASSWORD".to_string(), "test".to_string())]),
                    ports: vec![PortMapping {
                        container_port: 5432,
                        host_port: None,
                        protocol: "tcp".to_string(),
                    }],
                    role: ContainerRole::Sidecar,
                    readiness: Some(ReadinessProbe {
                        command: vec!["pg_isready".into(), "-U".into(), "postgres".into()],
                        interval_ms: 500,
                        timeout_ms: 30_000,
                    }),
                },
            ],
            network: NetworkPolicy::default(),
            resources: ResourceLimits::default(),
            mounts: vec![MountSpec {
                host_path: PathBuf::from("/home/user/project"),
                container_path: "/workspace".to_string(),
                read_only: false,
                kind: MountKind::Workspace,
                one_time: false,
            }],
            env: HashMap::from([("NODE_ENV".to_string(), "development".to_string())]),
            timeout_seconds: Some(300),
            labels: HashMap::from([("project".to_string(), "myapp".to_string())]),
        }
    }

    #[test]
    fn test_pod_name() {
        assert_eq!(PodmanProvider::pod_name("abc123"), "sb-abc123");
    }

    #[test]
    fn test_container_name() {
        assert_eq!(
            PodmanProvider::container_name("abc123", "workspace"),
            "sb-abc123-workspace"
        );
        assert_eq!(
            PodmanProvider::container_name("abc123", "postgres"),
            "sb-abc123-postgres"
        );
    }

    #[test]
    fn test_provider_name() {
        let provider = test_provider();
        assert_eq!(provider.name(), "podman");
    }

    #[test]
    fn test_shimmed_commands_not_empty() {
        assert!(!SHIMMED_COMMANDS.is_empty());
        assert!(SHIMMED_COMMANDS.contains(&"rm"));
        assert!(SHIMMED_COMMANDS.contains(&"git"));
        assert!(SHIMMED_COMMANDS.contains(&"ssh"));
        assert!(SHIMMED_COMMANDS.contains(&"psql"));
    }

    #[test]
    fn linux_guest_shim_accepts_elf_binary() {
        let path = std::env::temp_dir().join(format!("agentbox-shim-elf-{}", std::process::id()));
        fs::write(&path, b"\x7fELFdemo").unwrap();

        validate_linux_guest_shim(&path).unwrap();

        let _ = fs::remove_file(path);
    }

    #[test]
    fn linux_guest_shim_rejects_macos_macho_binary() {
        let path = std::env::temp_dir().join(format!("agentbox-shim-macho-{}", std::process::id()));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(&[0xcf, 0xfa, 0xed, 0xfe, 0x00]).unwrap();

        let error = validate_linux_guest_shim(&path).unwrap_err();

        assert!(error.to_string().contains("Mach-O"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn linux_guest_shim_resolves_sidecar_linux_artifact() {
        let base =
            std::env::temp_dir().join(format!("agentbox-shim-resolve-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let configured = base.join("agentbox-shim");
        let linux_artifact = configured.with_extension("linux");
        fs::write(&configured, [0xcf, 0xfa, 0xed, 0xfe, 0x00]).unwrap();
        fs::write(&linux_artifact, b"\x7fELFdemo").unwrap();

        let resolved = resolve_linux_guest_shim(&configured.to_string_lossy()).unwrap();

        assert_eq!(resolved, linux_artifact);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn test_parse_pod_list_empty() {
        let result = PodmanProvider::parse_pod_list("[]").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_pod_list_with_pods() {
        let json = r#"[
            {"Name": "sb-abc123", "Status": "Running"},
            {"Name": "sb-def456", "Status": "Stopped"},
            {"Name": "other-pod", "Status": "Running"}
        ]"#;
        let result = PodmanProvider::parse_pod_list(json).unwrap();
        // "other-pod" should be filtered out (no sb- prefix)
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "abc123");
        assert!(matches!(result[0].status, PodStatus::Running));
        assert_eq!(result[1].id, "def456");
        assert!(matches!(result[1].status, PodStatus::Stopped));
    }

    #[test]
    fn test_parse_pod_list_invalid_json() {
        let result = PodmanProvider::parse_pod_list("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_session_detected() {
        let provider = test_provider();
        let spec = test_spec();

        // Insert a session manually
        {
            let mut sessions = provider.sessions.lock().unwrap();
            sessions.insert(
                "test-id".to_string(),
                PodSession {
                    id: "test-id".to_string(),
                    spec: spec.clone(),
                    status: PodStatus::Running,
                    created_at: chrono::Utc::now(),
                    provider: "podman".to_string(),
                },
            );
        }

        // Verify it's tracked
        let sessions = provider.sessions.lock().unwrap();
        assert!(sessions.contains_key("test-id"));
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn test_resource_limits_to_args() {
        // Verify the memory/cpu calculation logic
        let spec = test_spec();
        let mem_mb = spec.resources.memory_bytes / (1024 * 1024);
        assert_eq!(mem_mb, 1024); // 1 GiB = 1024 MiB

        let cpus = spec.resources.cpu_shares as f64 / 1024.0;
        assert!((cpus - 2.0).abs() < f64::EPSILON); // 2048 shares = 2.0 cpus
    }
}
