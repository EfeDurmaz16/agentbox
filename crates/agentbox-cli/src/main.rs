use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use agentbox_policy::classify::{
    Bucket, Classification, CommandContext, PolicyConfig, PolicyNetworkMode,
};
use chrono::{NaiveDateTime, Utc};
use clap::{Parser, Subcommand};
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "agentbox",
    about = "Local governed minipods for autonomous agents",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon in background
    Start,
    /// Initialize local config, directories, and command shims
    Setup,
    /// Stop the daemon
    Stop,
    /// Show daemon status
    Status,
    /// Run local readiness checks for daemon, shims, policy, audit, and minipods
    Doctor,
    /// Query audit log
    Audit {
        /// Number of events to show
        #[arg(long, default_value_t = 20)]
        limit: usize,

        /// Filter by bucket (allow, approve, block)
        #[arg(long)]
        bucket: Option<String>,

        /// Live tail mode (re-query every 2s)
        #[arg(long)]
        tail: bool,
    },
    /// Set up shims for dangerous commands
    Install,
    /// Add domain to network allowlist
    Allow {
        /// Domain to allow (e.g. api.example.com)
        domain: String,
    },
    /// Explain network policy for a URL without making the request
    NetworkExplain {
        /// URL to classify, e.g. https://api.example.com/v1
        url: String,

        /// Network policy mode: deny-by-default, allowlisted, first-contact, open-with-guardrails
        #[arg(long = "mode", default_value = "open-with-guardrails")]
        mode: String,

        /// Network domain allowed without first-contact approval
        #[arg(long = "allow-domain")]
        allow_domains: Vec<String>,

        /// Network domain blocked by policy
        #[arg(long = "deny-domain")]
        deny_domains: Vec<String>,

        /// Disable localhost/loopback service access
        #[arg(long = "deny-localhost")]
        deny_localhost: bool,
    },
    /// Add a session-scoped first-contact network domain grant
    NetworkGrant {
        /// AgentPod session id
        session_id: String,

        /// Domain to grant for this session
        domain: String,

        /// Optional grant reason
        #[arg(long, default_value = "operator approved first-contact domain")]
        reason: String,
    },
    /// List credential grants for an AgentPod session
    Credentials {
        /// AgentPod session id
        session_id: String,

        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Revoke a credential grant from an AgentPod session
    CredentialRevoke {
        /// AgentPod session id
        session_id: String,

        /// Credential grant name to revoke
        name: String,
    },
    /// Run a command inside an isolated Agentbox minipod
    Run {
        /// Command to run (e.g., "openclaw start" or "npm test")
        command: Vec<String>,

        /// Runtime image (node, python, rust, go, ruby)
        #[arg(long)]
        runtime: Option<String>,

        /// Agent policy profile (general, coding, research, deploy, or custom)
        #[arg(long = "agent-profile", default_value = "general")]
        agent_profile: String,

        /// AgentPod task risk: low, medium, high, very-high
        #[arg(long = "risk", default_value = "medium")]
        risk: String,

        /// Runtime provider: auto, podman, agentpod-macos, agentpod-linux, agentpod-windows
        #[arg(long = "provider", default_value = "auto")]
        provider: String,

        /// Print the AgentPod run plan without starting a backend
        #[arg(long = "plan")]
        plan: bool,

        /// Add a service sidecar (postgres, redis, mysql, mongo)
        #[arg(long = "with", num_args = 1..)]
        services: Vec<String>,

        /// Mount current directory into the minipod workspace (default: true)
        #[arg(long, default_value = "true")]
        mount_cwd: bool,

        /// Workspace write mode: direct, overlay-review, ephemeral, commit-gated
        #[arg(long = "workspace-mode")]
        workspace_mode: Option<String>,

        /// Enable a writable workspace overlay rooted at this host directory
        #[arg(long = "workspace-overlay-dir")]
        workspace_overlay_dir: Option<PathBuf>,

        /// Resource limit: memory in MB (default: 1024)
        #[arg(long, default_value = "1024")]
        memory: u64,

        /// Add a read-only host mount as host_path:guest_path
        #[arg(long = "mount-ro")]
        read_only_mounts: Vec<String>,

        /// Add an explicit credential file grant as name=host_path:guest_path
        #[arg(long = "credential-file")]
        credential_files: Vec<String>,

        /// Add an explicit environment credential grant as name=ENV_VAR
        #[arg(long = "credential-env")]
        credential_env: Vec<String>,

        /// Add an explicit socket credential grant as name=/path/to/socket
        #[arg(long = "credential-socket")]
        credential_sockets: Vec<String>,

        /// Add an explicit provider token grant as name=provider:token-id
        #[arg(long = "credential-token")]
        credential_tokens: Vec<String>,

        /// Expire newly added credential grants after this many seconds
        #[arg(long = "credential-ttl-seconds")]
        credential_ttl_seconds: Option<i64>,

        /// Load a task-scoped policy bundle JSON file
        #[arg(long = "policy-bundle")]
        policy_bundles: Vec<PathBuf>,

        /// Network domain allowed without first-contact approval
        #[arg(long = "allow-domain")]
        allow_domains: Vec<String>,

        /// Network policy mode: deny-by-default, allowlisted, first-contact, open-with-guardrails
        #[arg(long = "network-mode")]
        network_mode: Option<String>,

        /// Network domain blocked for this minipod task
        #[arg(long = "deny-domain")]
        deny_domains: Vec<String>,

        /// Disable localhost/loopback service access for this minipod task
        #[arg(long = "deny-localhost")]
        deny_localhost: bool,
    },
    /// Stop and remove a minipod
    StopPod {
        /// Minipod session id; legacy sb-* backend ids are still accepted
        pod_id: String,
    },
    /// List running minipods
    Pods,
    /// Explain the last blocked or denied action
    Why,
    /// Show current policy posture (allow/approve/block rules)
    Policy,
    /// Simulate the policy decision for a command without executing it
    PolicySimulate {
        /// Command to classify; use `--` before the command if it has flags
        command: Vec<String>,
    },
    /// Explain the policy decision for a command without executing it
    PolicyExplain {
        /// Command to explain; use `--` before the command if it has flags
        command: Vec<String>,
    },
    /// Rich audit log viewer with timeline formatting
    History {
        /// Show all events (not just today)
        #[arg(long)]
        all: bool,

        /// Filter by bucket (allow, approve, block)
        #[arg(long)]
        bucket: Option<String>,

        /// Output as JSON (for piping)
        #[arg(long)]
        json: bool,
    },
    /// Export tamper-evident audit events as JSONL
    Evidence {
        /// Number of events to export
        #[arg(long, default_value_t = 100)]
        limit: usize,

        /// Verify the audit hash chain instead of exporting rows
        #[arg(long)]
        verify: bool,

        /// Export a session-scoped evidence bundle with redacted command transcripts
        #[arg(long)]
        session: Option<String>,

        /// Export only session credential grants/events as JSONL
        #[arg(long)]
        credentials: bool,

        /// Export only network boundary audit events as JSONL
        #[arg(long)]
        network: bool,
    },
    /// Generate a governed minipod manifest for an agent task
    MinipodSpec {
        /// Agent command/name, e.g. openclaw, hermes, codex, aspendos
        agent: String,

        /// Workspace directory exposed to the minipod
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Agent policy profile (general, coding, research, deploy, or custom)
        #[arg(long = "agent-profile", default_value = "general")]
        agent_profile: String,

        /// AgentPod task risk: low, medium, high, very-high
        #[arg(long = "risk", default_value = "medium")]
        risk: String,

        /// Runtime provider hint: auto, podman, agentpod-macos, agentpod-linux, agentpod-windows
        #[arg(long = "provider", default_value = "auto")]
        provider: String,

        /// Network domain allowed without first-contact approval
        #[arg(long = "allow-domain")]
        allow_domains: Vec<String>,

        /// Network policy mode: deny-by-default, allowlisted, first-contact, open-with-guardrails
        #[arg(long = "network-mode")]
        network_mode: Option<String>,

        /// Network domain blocked for this minipod task
        #[arg(long = "deny-domain")]
        deny_domains: Vec<String>,

        /// Disable localhost/loopback service access in the generated manifest
        #[arg(long = "deny-localhost")]
        deny_localhost: bool,

        /// Workspace write mode: direct, overlay-review, ephemeral, commit-gated
        #[arg(long = "workspace-mode")]
        workspace_mode: Option<String>,

        /// Add a read-only host mount as host_path:guest_path
        #[arg(long = "mount-ro")]
        read_only_mounts: Vec<String>,

        /// Add an explicit credential file grant as name=host_path:guest_path
        #[arg(long = "credential-file")]
        credential_files: Vec<String>,

        /// Add an explicit environment credential grant as name=ENV_VAR
        #[arg(long = "credential-env")]
        credential_env: Vec<String>,

        /// Add an explicit socket credential grant as name=/path/to/socket
        #[arg(long = "credential-socket")]
        credential_sockets: Vec<String>,

        /// Add an explicit provider token grant as name=provider:token-id
        #[arg(long = "credential-token")]
        credential_tokens: Vec<String>,

        /// Expire newly added credential grants after this many seconds
        #[arg(long = "credential-ttl-seconds")]
        credential_ttl_seconds: Option<i64>,

        /// Load a task-scoped policy bundle JSON file
        #[arg(long = "policy-bundle")]
        policy_bundles: Vec<PathBuf>,

        /// Enable a review-required writable workspace overlay rooted at this host directory
        #[arg(long = "workspace-overlay-dir")]
        workspace_overlay_dir: Option<PathBuf>,
    },
    /// List runtime providers and their current implementation status
    Providers {
        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Generate a secret-free remote AgentPod transport descriptor
    RemoteDescriptor {
        /// Remote worker endpoint, e.g. https://worker.example.com/agentpod or ssh://agentpod@host
        #[arg(long)]
        endpoint: String,

        /// Auth model: signed-challenge, workload-identity, mtls, operator-ssh
        #[arg(long = "auth", default_value = "signed-challenge")]
        auth: String,

        /// Evidence mode: append-only-stream, bundle-upload, local-pull
        #[arg(long = "evidence", default_value = "append-only-stream")]
        evidence: String,
    },
    /// Generate a secret-free remote AgentPod handshake challenge descriptor
    RemoteHandshake {
        /// Remote worker endpoint, e.g. https://worker.example.com/agentpod or ssh://agentpod@host
        #[arg(long)]
        endpoint: String,

        /// Auth model: signed-challenge, workload-identity, mtls, operator-ssh
        #[arg(long = "auth", default_value = "signed-challenge")]
        auth: String,

        /// Challenge expiry in seconds
        #[arg(long = "ttl-seconds", default_value_t = 300)]
        ttl_seconds: i64,
    },
    /// Inspect persisted minipod session metadata
    MinipodInspect {
        /// Session id to inspect; omit to list all persisted sessions
        session_id: Option<String>,

        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Review workspace output for an AgentPod session
    Review {
        /// Session id to review
        session_id: String,

        /// Emit JSON
        #[arg(long)]
        json: bool,

        /// Emit only the workspace patch
        #[arg(long)]
        patch: bool,
    },
    /// Discard projected workspace output for an AgentPod session
    ReviewDiscard {
        /// Session id whose projected review workspace should be discarded
        session_id: String,
    },
    /// Apply projected workspace output to the lower workspace
    ReviewApply {
        /// Session id whose projected review workspace should be applied
        session_id: String,
    },
    /// Apply projected workspace output and commit it in the lower workspace
    ReviewCommit {
        /// Session id whose projected review workspace should be committed
        session_id: String,

        /// Commit message for the lower workspace
        #[arg(short = 'm', long = "message")]
        message: String,
    },
    /// Show logs for a minipod session backed by the compatibility backend
    MinipodLogs {
        /// Minipod session id; legacy sb-* backend ids are still accepted
        session_id: String,

        /// Follow logs
        #[arg(long)]
        follow: bool,

        /// Number of trailing lines to show
        #[arg(long)]
        tail: Option<usize>,
    },
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn agentbox_dir() -> PathBuf {
    dirs::home_dir()
        .expect("cannot determine home directory")
        .join(".agentbox")
}

fn pid_path() -> PathBuf {
    agentbox_dir().join("agentbox.pid")
}

fn socket_path() -> PathBuf {
    agentbox_dir().join("agentbox.sock")
}

fn config_path() -> PathBuf {
    agentbox_dir().join("config.toml")
}

fn audit_db_path() -> PathBuf {
    agentbox_dir().join("audit.db")
}

fn shims_dir() -> PathBuf {
    agentbox_dir().join("shims")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ensure_dir(p: &PathBuf) {
    if !p.exists() {
        fs::create_dir_all(p).expect("failed to create directory");
    }
}

/// Read PID from the pid file. Returns None if file missing or unreadable.
fn read_pid() -> Option<u32> {
    fs::read_to_string(pid_path())
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Check if a process with the given PID is alive.
fn process_alive(pid: u32) -> bool {
    // signal 0 checks existence without sending a real signal
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn cleanup_stale_daemon_files() {
    if let Some(pid) = read_pid() {
        if !process_alive(pid) {
            let _ = fs::remove_file(pid_path());
            let _ = fs::remove_file(socket_path());
        }
    }
}

/// Locate the agentbox-daemon binary.
/// Looks next to the current executable first, then falls back to PATH.
fn find_daemon_binary() -> Option<PathBuf> {
    // Same directory as this binary
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap().join("agentbox-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    // Fall back: assume it's on PATH
    which_in_path("agentbox-daemon")
}

fn which_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full = dir.join(name);
            if full.is_file() {
                Some(full)
            } else {
                None
            }
        })
    })
}

/// Locate the agentbox-shim binary.
fn find_shim_binary() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap().join("agentbox-shim");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    which_in_path("agentbox-shim")
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[allow(clippy::zombie_processes)]
fn cmd_start() {
    ensure_dir(&agentbox_dir());

    // Check if already running
    if let Some(pid) = read_pid() {
        if process_alive(pid) {
            eprintln!("daemon already running (PID: {})", pid);
            std::process::exit(1);
        } else {
            cleanup_stale_daemon_files();
            eprintln!("cleaned stale daemon pid/socket files");
        }
    }

    let daemon = find_daemon_binary().unwrap_or_else(|| {
        eprintln!("error: agentbox-daemon binary not found");
        eprintln!("hint: run `cargo build -p agentbox-daemon` first");
        std::process::exit(1);
    });

    let child = Command::new(&daemon)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("failed to start daemon: {}", e);
            std::process::exit(1);
        });

    let pid = child.id();

    // Write PID file
    fs::write(pid_path(), pid.to_string()).expect("failed to write pid file");

    println!("daemon started (PID: {})", pid);
}

fn cmd_setup() {
    use agentbox_daemon::config;

    ensure_dir(&agentbox_dir());
    let config = config::load().unwrap_or_else(|e| {
        eprintln!("error: failed to initialize Agentbox config: {}", e);
        std::process::exit(1);
    });

    println!("Agentbox setup");
    println!("{}", "-".repeat(64));
    println!("config:  {}", config_path().display());
    println!("audit:   {}", config.db_path);
    println!("socket:  {}", config.socket_path);
    println!();
    cmd_install();
    println!();
    println!("Next:");
    println!("  export PATH=\"{}:$PATH\"", shims_dir().display());
    println!("  agentbox start");
    println!("  agentbox doctor");
}

fn cmd_stop() {
    let pid = match read_pid() {
        Some(pid) if process_alive(pid) => pid,
        Some(_) => {
            // Stale PID file
            let _ = fs::remove_file(pid_path());
            eprintln!("daemon not running (stale pid file cleaned)");
            std::process::exit(1);
        }
        None => {
            eprintln!("daemon not running (no pid file)");
            std::process::exit(1);
        }
    };

    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }

    // Wait briefly for process to exit
    for _ in 0..20 {
        if !process_alive(pid) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = fs::remove_file(pid_path());
    println!("daemon stopped");
}

fn cmd_status() {
    let pid = read_pid();
    let running = pid.is_some_and(process_alive);

    if running {
        let pid = pid.unwrap();
        println!("status:  running");
        println!("pid:     {}", pid);
    } else if let Some(pid) = pid {
        println!("status:  stopped (stale pid file)");
        println!("pid:     {} (not running)", pid);
        println!("hint:    run `agentbox start` to clean stale daemon files");
    } else {
        println!("status:  stopped");
    }

    let sock = socket_path();
    println!("socket:  {}", sock.display());

    // Read ntfy topic from config if available
    let topic = fs::read_to_string(config_path())
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .and_then(|t| {
            t.get("ntfy")
                .and_then(|v| v.as_table())
                .and_then(|nt| nt.get("topic"))
                .and_then(|v| v.as_str().map(String::from))
        })
        .unwrap_or_else(|| "(not configured)".into());
    println!("ntfy:    {}", topic);

    // List active shims
    let shims = shims_dir();
    if shims.exists() {
        let mut names: Vec<String> = fs::read_dir(&shims)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let path = e.path();
                if path.is_symlink() || path.is_file() {
                    Some(e.file_name().to_string_lossy().into_owned())
                } else {
                    None
                }
            })
            .collect();
        names.sort();
        if names.is_empty() {
            println!("shims:   (none)");
        } else {
            println!("shims:   {} active", names.len());
            for name in &names {
                println!("         - {}", name);
            }
        }
    } else {
        println!("shims:   (not installed, run `agentbox install`)");
    }
}

fn cmd_doctor() {
    let mut checks = Vec::new();

    checks.push(doctor_check(
        "agentbox directory",
        agentbox_dir().is_dir(),
        format!("{}", agentbox_dir().display()),
        "run `agentbox start` or `agentbox install` to initialize ~/.agentbox",
    ));

    let config_ok = fs::read_to_string(config_path())
        .ok()
        .and_then(|s| toml::from_str::<toml::Table>(&s).ok())
        .is_some();
    checks.push(doctor_check(
        "config file",
        config_ok,
        format!("{}", config_path().display()),
        "start the daemon once to generate config.toml",
    ));

    let pid = read_pid();
    let daemon_running = pid.is_some_and(process_alive);
    checks.push(doctor_check(
        "daemon process",
        daemon_running,
        match pid {
            Some(pid) if daemon_running => format!("pid {pid}"),
            Some(pid) => format!("stale pid {pid}"),
            None => "no pid file".to_string(),
        },
        "run `agentbox start`",
    ));

    checks.push(doctor_check(
        "daemon socket",
        socket_path().exists(),
        format!("{}", socket_path().display()),
        "run `agentbox start`; remove stale pid/socket files if the daemon crashed",
    ));

    checks.push(doctor_check(
        "agentbox-daemon binary",
        find_daemon_binary().is_some(),
        find_daemon_binary()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "not found".to_string()),
        "run `cargo build --release` or put agentbox-daemon on PATH",
    ));

    checks.push(doctor_check(
        "agentbox-shim binary",
        find_shim_binary().is_some(),
        find_shim_binary()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "not found".to_string()),
        "run `cargo build --release` or put agentbox-shim on PATH",
    ));

    let shim_count = installed_shim_count();
    checks.push(doctor_check(
        "installed shims",
        shim_count >= 20,
        format!("{shim_count} shims in {}", shims_dir().display()),
        "run `agentbox install`",
    ));

    checks.push(doctor_check(
        "shim PATH priority",
        shims_first_in_path(),
        std::env::var("PATH").unwrap_or_default(),
        "prepend `export PATH=\"$HOME/.agentbox/shims:$PATH\"` to your shell profile",
    ));

    let audit_status = audit_event_count()
        .map(|count| format!("{count} events"))
        .unwrap_or_else(|| "audit db missing or unreadable".to_string());
    checks.push(doctor_check(
        "audit database",
        audit_event_count().is_some(),
        audit_status,
        "start the daemon and run one intercepted command",
    ));

    let podman_available = Command::new("podman")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    checks.push(doctor_check(
        "podman provider",
        podman_available,
        podman_version().unwrap_or_else(|| "not found".to_string()),
        "install Podman; on macOS also run `podman machine init && podman machine start`",
    ));
    if cfg!(target_os = "macos") {
        let machine = podman_machine_status();
        checks.push(doctor_check(
            "podman machine",
            machine.ok,
            machine.detail,
            machine.fix,
        ));
    }

    println!("Agentbox doctor");
    println!("{}", "-".repeat(64));

    let mut failed = 0;
    for check in &checks {
        let marker = if check.ok { "ok" } else { "fail" };
        println!("{:<6} {:<24} {}", marker, check.name, check.detail);
        if !check.ok {
            println!("       fix: {}", check.fix);
            failed += 1;
        }
    }

    println!("{}", "-".repeat(64));
    println!("summary: {} ok, {} failed", checks.len() - failed, failed);

    if failed > 0 {
        std::process::exit(1);
    }
}

struct DoctorCheck {
    name: &'static str,
    ok: bool,
    detail: String,
    fix: &'static str,
}

fn doctor_check(name: &'static str, ok: bool, detail: String, fix: &'static str) -> DoctorCheck {
    DoctorCheck {
        name,
        ok,
        detail,
        fix,
    }
}

fn installed_shim_count() -> usize {
    fs::read_dir(shims_dir())
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            path.is_symlink() || path.is_file()
        })
        .count()
}

fn shims_first_in_path() -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    let Some(first) = std::env::split_paths(&paths).next() else {
        return false;
    };
    first == shims_dir()
}

fn audit_event_count() -> Option<i64> {
    let db_path = audit_db_path();
    if !db_path.exists() {
        return None;
    }

    Connection::open(db_path)
        .ok()?
        .query_row("SELECT COUNT(*) FROM audit_log", [], |row| {
            row.get::<_, i64>(0)
        })
        .ok()
}

fn podman_version() -> Option<String> {
    let output = Command::new("podman").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

struct PodmanMachineDoctor {
    ok: bool,
    detail: String,
    fix: &'static str,
}

fn podman_machine_status() -> PodmanMachineDoctor {
    let output = match Command::new("podman").args(["machine", "inspect"]).output() {
        Ok(output) => output,
        Err(_) => {
            return PodmanMachineDoctor {
                ok: false,
                detail: "podman not found".to_string(),
                fix: "install Podman, then run `podman machine init && podman machine start`",
            };
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let fix = if stderr.contains("no machine") || stderr.contains("not exist") {
            "run `podman machine init && podman machine start`"
        } else {
            "run `podman machine inspect` for details, then start or recreate the machine"
        };
        return PodmanMachineDoctor {
            ok: false,
            detail: stderr.trim().to_string(),
            fix,
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let running = stdout.contains("\"State\": \"running\"") || stdout.contains("\"Running\": true");
    PodmanMachineDoctor {
        ok: running,
        detail: if running {
            "running".to_string()
        } else {
            "installed but stopped".to_string()
        },
        fix: "run `podman machine start`",
    }
}

fn cmd_audit(limit: usize, bucket: Option<String>, tail: bool) {
    let db_path = audit_db_path();
    if !db_path.exists() {
        eprintln!("no audit log found at {}", db_path.display());
        eprintln!("hint: start the daemon first with `agentbox start`");
        std::process::exit(1);
    }

    if tail {
        // Live tail: re-query every 2 seconds
        let mut last_id: i64 = 0;
        print_audit_header();
        loop {
            last_id = print_audit_events(&db_path, limit, &bucket, Some(last_id));
            io::stdout().flush().ok();
            thread::sleep(Duration::from_secs(2));
        }
    } else {
        print_audit_header();
        print_audit_events(&db_path, limit, &bucket, None);
        println!();
        println!("Tip: use `agentbox history` for a richer timeline view");
    }
}

fn print_audit_header() {
    println!("{:<14} {:<9} {:<10} COMMAND", "TIME", "BUCKET", "DECISION");
}

/// Query and print audit events. Returns the max rowid seen (for tail mode).
fn print_audit_events(
    db_path: &PathBuf,
    limit: usize,
    bucket: &Option<String>,
    after_id: Option<i64>,
) -> i64 {
    let conn = Connection::open(db_path).expect("failed to open audit db");

    let mut sql =
        String::from("SELECT rowid, timestamp, bucket, decision, command FROM audit_log WHERE 1=1");

    if let Some(ref b) = bucket {
        sql.push_str(&format!(" AND bucket = '{}'", b));
    }
    if let Some(id) = after_id {
        sql.push_str(&format!(" AND rowid > {}", id));
    }
    sql.push_str(&format!(" ORDER BY rowid DESC LIMIT {}", limit));

    let mut stmt = conn.prepare(&sql).expect("failed to prepare query");

    let mut max_id: i64 = after_id.unwrap_or(0);

    let rows = stmt
        .query_map([], |row| {
            let rowid: i64 = row.get(0)?;
            let timestamp: String = row.get(1)?;
            let bucket: String = row.get(2)?;
            let decision: String = row.get(3)?;
            let command: String = row.get(4)?;
            Ok((rowid, timestamp, bucket, decision, command))
        })
        .expect("failed to query audit log");

    let mut events: Vec<_> = rows.filter_map(|r| r.ok()).collect();
    // Reverse so oldest prints first (we queried DESC for LIMIT)
    events.reverse();

    for (rowid, timestamp, bucket, decision, command) in &events {
        if *rowid > max_id {
            max_id = *rowid;
        }
        // Extract just the time portion if possible
        let time_display = if timestamp.len() >= 19 {
            &timestamp[11..19]
        } else {
            timestamp.as_str()
        };
        let command = agentbox_daemon::audit::redact_sensitive_text(command);
        println!(
            "{:<14} {:<9} {:<10} {}",
            time_display, bucket, decision, command
        );
    }

    max_id
}

fn cmd_install() {
    let shims = shims_dir();
    ensure_dir(&shims);

    let shim_binary = find_shim_binary().unwrap_or_else(|| {
        eprintln!("error: agentbox-shim binary not found");
        eprintln!("hint: run `cargo build -p agentbox-shim` first");
        std::process::exit(1);
    });

    let commands = [
        "rm",
        "git",
        "ssh",
        "scp",
        "curl",
        "wget",
        "psql",
        "mysql",
        "sqlite3",
        "npm",
        "cargo",
        "gem",
        "pip",
        "gh",
        "osascript",
        "chmod",
        "kill",
        "killall",
        "docker",
        "kubectl",
        "cat",
        "head",
        "tail",
        "dd",
        "mkfs",
        "diskutil",
        "csrutil",
        "spctl",
    ];

    let mut created = 0;
    let mut skipped = 0;

    for cmd in &commands {
        let link_path = shims.join(cmd);
        if link_path.exists() || link_path.is_symlink() {
            // Remove old symlink to ensure it points to current shim
            let _ = fs::remove_file(&link_path);
        }
        match std::os::unix::fs::symlink(&shim_binary, &link_path) {
            Ok(()) => created += 1,
            Err(e) => {
                eprintln!("warning: failed to create shim for {}: {}", cmd, e);
                skipped += 1;
            }
        }
    }

    println!("installed {} shims ({} skipped)", created, skipped);
    println!();
    println!("Add this to your shell profile (~/.zshrc or ~/.bashrc):");
    println!();
    println!("  export PATH=\"{}:$PATH\"", shims.display());
    println!();
    println!("Then restart your shell or run:");
    println!();
    println!("  source ~/.zshrc");
}

struct RunOptions {
    command: Vec<String>,
    runtime: Option<String>,
    agent_profile: String,
    risk: String,
    provider: String,
    plan: bool,
    services: Vec<String>,
    mount_cwd: bool,
    workspace_mode: Option<String>,
    workspace_overlay_dir: Option<PathBuf>,
    memory: u64,
    read_only_mounts: Vec<String>,
    credential_files: Vec<String>,
    credential_env: Vec<String>,
    credential_sockets: Vec<String>,
    credential_tokens: Vec<String>,
    credential_ttl_seconds: Option<i64>,
    policy_bundles: Vec<PathBuf>,
    allow_domains: Vec<String>,
    network_mode: Option<String>,
    deny_domains: Vec<String>,
    deny_localhost: bool,
}

async fn cmd_run(options: RunOptions) {
    use agentbox_daemon::audit::AuditStore;
    use agentbox_daemon::config;
    use agentbox_daemon::pod::machine::MachineManager;
    use agentbox_daemon::runtime::manager::RuntimeManager;
    use agentbox_daemon::runtime::registry::{ProviderSelectionRequest, RuntimeProviderRegistry};
    use agentbox_daemon::runtime::session::RuntimeSessionStore;
    use agentbox_daemon::runtime::types::{ExecCommand, MinipodSpec, NetworkMode, ResourcePolicy};
    use agentbox_daemon::runtime::workspace::WorkspaceProjectionMaterializer;

    let risk = parse_agentpod_risk(&options.risk);
    let provider_hint = parse_provider_hint(&options.provider);

    // 1. Resolve provider selection before touching any backend.
    let agentbox_sock = socket_path().to_string_lossy().to_string();
    let shim_binary = find_shim_binary()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| {
            eprintln!("warning: agentbox-shim binary not found, shim injection will be skipped");
            eprintln!("hint: run `cargo build -p agentbox-shim` first");
            String::new()
        });

    let config = config::load().unwrap_or_else(|e| {
        eprintln!("Error: failed to load Agentbox config: {}", e);
        std::process::exit(1);
    });
    let registry = RuntimeProviderRegistry::with_local_providers(agentbox_sock, shim_binary);
    let selection = registry
        .explain_selection(&ProviderSelectionRequest {
            preferred_provider: provider_hint.clone(),
            risk: risk.clone(),
        })
        .unwrap_or_else(|e| {
            eprintln!("Error: failed to select runtime provider: {}", e);
            std::process::exit(1);
        });
    // 2. Build governed AgentPod manifest.
    let workspace = if options.mount_cwd {
        std::env::current_dir().unwrap_or_else(|e| {
            eprintln!("Error: failed to determine current directory: {}", e);
            std::process::exit(1);
        })
    } else {
        std::env::temp_dir()
    };
    let agent_name = options
        .command
        .first()
        .cloned()
        .or_else(|| options.runtime.clone())
        .unwrap_or_else(|| "agent".to_string());
    let mut spec =
        MinipodSpec::for_agent_task_with_profile(agent_name, workspace, options.agent_profile);
    spec.risk = risk;
    spec.labels
        .insert("agentbox.risk".to_string(), spec.risk.label().to_string());
    spec.labels.insert(
        "agentbox.provider.selected".to_string(),
        selection.selected_provider.clone(),
    );
    spec.labels.insert(
        "agentbox.provider.selection_reason".to_string(),
        selection.reason.clone(),
    );
    apply_workspace_mode(
        &mut spec,
        options.workspace_mode.as_deref(),
        options.workspace_overlay_dir,
    );
    spec.agent.command = if options.command.is_empty() {
        vec!["sleep".to_string(), "infinity".to_string()]
    } else {
        options.command.clone()
    };
    spec.resources = ResourcePolicy {
        memory_bytes: options.memory * 1024 * 1024,
        ..ResourcePolicy::default()
    };
    if let Some(runtime) = options.runtime.as_deref() {
        spec.labels
            .insert("agentbox.runtime".to_string(), runtime.to_string());
        spec.labels.insert(
            "agentbox.runtime_image".to_string(),
            runtime_image(runtime).to_string(),
        );
    }
    spec.services = options
        .services
        .iter()
        .filter_map(|service| service_spec(service))
        .collect();
    for bundle_path in options.policy_bundles {
        let bundle = load_task_policy_bundle(&bundle_path);
        bundle.apply_to_minipod(&mut spec);
    }
    for mount in options.read_only_mounts {
        spec.filesystem.mounts.push(parse_read_only_mount(&mount));
    }
    for grant in options.credential_files {
        let (mount, credential_grant) = parse_credential_file_grant(&grant);
        spec.filesystem.mounts.push(mount);
        spec.credentials.grants.push(credential_grant);
    }
    for grant in options.credential_env {
        spec.credentials
            .grants
            .push(parse_simple_credential_grant(&grant, "env"));
    }
    for grant in options.credential_sockets {
        spec.credentials
            .grants
            .push(parse_simple_credential_grant(&grant, "socket"));
    }
    for grant in options.credential_tokens {
        spec.credentials
            .grants
            .push(parse_simple_credential_grant(&grant, "token"));
    }
    apply_credential_ttl(&mut spec, options.credential_ttl_seconds);
    if !options.allow_domains.is_empty() {
        spec.network.mode = NetworkMode::AllowListed;
        spec.network.allowed_domains = options.allow_domains;
    }
    if let Some(mode) = options.network_mode {
        spec.network.mode = parse_network_mode(&mode);
    }
    if !options.deny_domains.is_empty() {
        spec.network.denied_domains = options.deny_domains;
    }
    if options.deny_localhost {
        spec.network.allow_localhost = false;
    }

    if options.plan {
        println!(
            "{}",
            serde_json::to_string_pretty(&spec).expect("failed to serialize AgentPod run plan")
        );
        return;
    }

    if selection.selected_provider != "podman" {
        eprintln!(
            "Error: provider `{}` is not runnable in this build yet.",
            selection.selected_provider
        );
        eprintln!("reason: {}", selection.reason);
        eprintln!("hint: use `--provider podman` for the current compatibility backend");
        std::process::exit(1);
    }

    // 3. Check whether the current compatibility backend is available.
    match Command::new("podman").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let ver = String::from_utf8_lossy(&output.stdout);
            eprintln!("Using {}", ver.trim());
        }
        _ => {
            eprintln!("Error: no runnable AgentPod backend is available yet.");
            eprintln!("The current compatibility backend requires Podman:");
            eprintln!(
                "  macOS: brew install podman && podman machine init && podman machine start"
            );
            eprintln!("  Linux: https://podman.io/docs/installation");
            std::process::exit(1);
        }
    }

    // 4. On macOS, ensure the compatibility backend VM is running.
    let machine = MachineManager::new();
    if machine.needs_vm() {
        eprintln!("Checking AgentPod compatibility VM...");
        if let Err(e) = machine.ensure_ready().await {
            eprintln!("Error: failed to start podman machine: {}", e);
            std::process::exit(1);
        }
    }

    let workspace_projection = WorkspaceProjectionMaterializer::materialize(&mut spec)
        .unwrap_or_else(|e| {
            eprintln!("Error: failed to prepare workspace projection: {}", e);
            std::process::exit(1);
        });

    let provider = registry
        .get(&selection.selected_provider)
        .unwrap_or_else(|e| {
            eprintln!(
                "Error: failed to resolve compatibility runtime provider: {}",
                e
            );
            std::process::exit(1);
        });
    let manager = RuntimeManager::new(
        provider,
        RuntimeSessionStore::new(config.session_store_path.clone()),
        AuditStore::new(&config.db_path).unwrap_or_else(|e| {
            eprintln!("Error: failed to open audit store: {}", e);
            std::process::exit(1);
        }),
    );

    // 5. Print progress and create minipod through RuntimeManager
    let ws_image = spec
        .labels
        .get("agentbox.runtime_image")
        .cloned()
        .unwrap_or_else(|| "ubuntu:24.04".to_string());
    println!("Creating governed minipod {}...", spec.name);
    println!("  Risk: {}", spec.risk.label());
    println!("  Workspace mode: {}", spec.workspace_mode.label());
    println!("  Provider: {}", selection.selected_provider);
    println!("  Selection: {}", selection.reason);
    println!("  Image: {}", ws_image);
    if let Some(projection) = &workspace_projection {
        println!("  Review lower: {}", projection.lower_host_path.display());
        println!(
            "  Review workspace: {}",
            projection.projected_host_path.display()
        );
    }

    if !spec.services.is_empty() {
        let sidecars: Vec<String> = spec
            .services
            .iter()
            .map(|service| format!("{} ({})", service.name, service.image))
            .collect();
        println!("  Sidecars: {}", sidecars.join(", "));
    }

    println!(
        "  Mount: {} -> {} (rw)",
        spec.filesystem.workspace_host_path.display(),
        spec.filesystem.workspace_guest_path
    );
    for mount in &spec.filesystem.mounts {
        let ro = if matches!(
            mount.mode,
            agentbox_daemon::runtime::types::MountMode::ReadOnly
        ) {
            " (ro)"
        } else {
            " (rw)"
        };
        println!(
            "  Mount: {} -> {}{}",
            mount.host_path.display(),
            mount.guest_path,
            ro
        );
    }

    println!("  Agentbox: socket + shims injected");

    let session = match manager.create(&spec).await {
        Ok(session) => {
            println!("Minipod {} created and running.", session.name);
            session
        }
        Err(e) => {
            eprintln!("Error: failed to create minipod: {}", e);
            std::process::exit(1);
        }
    };

    // 6. If command was provided, run it
    if !options.command.is_empty() {
        println!();
        println!("Running: {}", options.command.join(" "));
        println!("--- output ---");

        let exec_req = ExecCommand {
            argv: options.command.clone(),
            working_dir: Some("/workspace".to_string()),
            env: HashMap::new(),
            timeout_seconds: None,
        };

        match manager.exec(&session.id, &exec_req).await {
            Ok(result) => {
                if !result.stdout.is_empty() {
                    print!("{}", result.stdout);
                }
                if !result.stderr.is_empty() {
                    eprint!("{}", result.stderr);
                }
                println!("--- exit code: {} ---", result.exit_code);

                // Cleanup prompt
                eprint!("Destroy minipod {}? [Y/n] ", session.name);
                io::stderr().flush().ok();
                let mut input = String::new();
                if io::stdin().read_line(&mut input).is_ok() {
                    let answer = input.trim().to_lowercase();
                    if answer.is_empty() || answer == "y" || answer == "yes" {
                        if let Err(e) = manager.destroy(&session.id).await {
                            eprintln!("Warning: failed to destroy minipod: {}", e);
                        } else {
                            println!("Minipod {} destroyed.", session.name);
                        }
                    } else {
                        println!("Minipod {} left running.", session.name);
                    }
                }

                if result.exit_code != 0 {
                    std::process::exit(result.exit_code);
                }
            }
            Err(e) => {
                eprintln!("Error: failed to run command: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // 7. No command: print interactive instructions
        println!();
        println!("Minipod session running.");
        println!("  Session id: {}", session.id);
        println!("  Backend container: sb-{}-workspace", session.id);
        println!(
            "  Debug shell: podman exec -it sb-{}-workspace bash",
            session.id
        );
        println!();
        println!("Stop with:");
        println!("  agentbox stop-pod {}", session.id);
    }
}

fn runtime_image(runtime: &str) -> &'static str {
    match runtime {
        "node" => "node:22-bookworm",
        "python" => "python:3.12-slim",
        "rust" => "rust:1.82-slim",
        "go" => "golang:1.23-bookworm",
        "ruby" => "ruby:3.3-slim",
        _ => "ubuntu:24.04",
    }
}

fn service_spec(service: &str) -> Option<agentbox_daemon::runtime::types::ServiceSpec> {
    use agentbox_daemon::runtime::types::{ServiceReadinessProbe, ServiceSpec};

    let (image, readiness) = match service {
        "postgres" => (
            "postgres:16-alpine",
            Some(ServiceReadinessProbe::command(vec![
                "pg_isready".into(),
                "-U".into(),
                "postgres".into(),
            ])),
        ),
        "redis" => (
            "redis:7-alpine",
            Some(ServiceReadinessProbe::command(vec![
                "redis-cli".into(),
                "ping".into(),
            ])),
        ),
        "mysql" => (
            "mysql:8",
            Some(ServiceReadinessProbe::command(vec![
                "mysqladmin".into(),
                "ping".into(),
                "-h".into(),
                "127.0.0.1".into(),
            ])),
        ),
        "mongo" => (
            "mongo:7",
            Some(ServiceReadinessProbe::command(vec![
                "mongosh".into(),
                "--quiet".into(),
                "--eval".into(),
                "db.runCommand({ ping: 1 }).ok".into(),
            ])),
        ),
        _ => return None,
    };

    Some(ServiceSpec {
        name: service.to_string(),
        image: image.to_string(),
        env: HashMap::new(),
        readiness,
    })
}

async fn cmd_stop_pod(pod_id: String) {
    let raw_id = pod_id.strip_prefix("sb-").unwrap_or(&pod_id);

    if stop_runtime_session(raw_id).await {
        return;
    }

    stop_legacy_podman_pod(raw_id);
}

async fn stop_runtime_session(session_id: &str) -> bool {
    use agentbox_daemon::audit::AuditStore;
    use agentbox_daemon::config;
    use agentbox_daemon::runtime::manager::RuntimeManager;
    use agentbox_daemon::runtime::registry::RuntimeProviderRegistry;
    use agentbox_daemon::runtime::session::RuntimeSessionStore;

    let config = config::load().unwrap_or_else(|e| {
        eprintln!("error: failed to load Agentbox config: {}", e);
        std::process::exit(1);
    });
    let store = RuntimeSessionStore::new(config.session_store_path.clone());
    let session = store.get(session_id).unwrap_or_else(|e| {
        eprintln!("error: failed to read runtime session store: {}", e);
        std::process::exit(1);
    });
    let Some(session) = session else {
        return false;
    };

    let registry = RuntimeProviderRegistry::with_local_providers(
        socket_path().to_string_lossy().into_owned(),
        find_shim_binary()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
    );
    let provider = registry.get(&session.provider).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to resolve session provider `{}` for stop: {}",
            session.provider, e
        );
        std::process::exit(1);
    });
    let manager = RuntimeManager::new(
        provider,
        RuntimeSessionStore::new(config.session_store_path),
        AuditStore::new(&config.db_path).unwrap_or_else(|e| {
            eprintln!("error: failed to open audit store: {}", e);
            std::process::exit(1);
        }),
    );

    eprintln!("Stopping AgentPod session {}...", session.id);
    manager.destroy(&session.id).await.unwrap_or_else(|e| {
        eprintln!(
            "error: failed to stop AgentPod session {}: {}",
            session.id, e
        );
        std::process::exit(1);
    });
    println!("AgentPod session {} stopped.", session.id);
    true
}

fn stop_legacy_podman_pod(raw_id: &str) {
    let pod_name = format!("sb-{}", raw_id);

    eprintln!("Stopping legacy pod {}...", pod_name);
    match Command::new("podman")
        .args(["pod", "rm", "-f", &pod_name])
        .output()
    {
        Ok(o) if o.status.success() => {
            println!("Minipod {} removed.", pod_name);
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!(
                "Error: failed to remove pod {}: {}",
                pod_name,
                stderr.trim()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: podman not found or failed: {}", e);
            std::process::exit(1);
        }
    }
}

async fn cmd_pods() {
    use agentbox_daemon::config;
    use agentbox_daemon::runtime::session::RuntimeSessionStore;

    let config = config::load().unwrap_or_else(|e| {
        eprintln!("error: failed to load Agentbox config: {}", e);
        std::process::exit(1);
    });
    let store = RuntimeSessionStore::new(config.session_store_path);
    let sessions = store.list().unwrap_or_else(|e| {
        eprintln!("error: failed to read runtime session store: {}", e);
        std::process::exit(1);
    });

    if sessions.is_empty() {
        println!("No persisted AgentPod sessions.");
        return;
    }

    println!(
        "{:<28} {:<18} {:<12} {:<10} {:<12} AGENT",
        "SESSION", "NAME", "PROVIDER", "STATUS", "RISK"
    );
    println!("{}", "-".repeat(104));

    for session in &sessions {
        println!(
            "{:<28} {:<18} {:<12} {:<10} {:<12} {}",
            session.id,
            session.name,
            session.provider,
            format!("{:?}", session.status),
            session.spec.risk.label(),
            session.spec.agent.name
        );
    }
}

fn cmd_allow(domain: String) {
    ensure_dir(&agentbox_dir());

    let cfg_path = config_path();

    let mut config: toml::Table = if cfg_path.exists() {
        let content = fs::read_to_string(&cfg_path).expect("failed to read config.toml");
        content.parse().expect("failed to parse config.toml")
    } else {
        toml::Table::new()
    };

    // Get or create top-level allowed_domains array. Older development builds
    // used a nested [network] table; the daemon config is flat now.
    let domains = config
        .entry("allowed_domains")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .expect("allowed_domains should be an array");

    // Check for duplicates
    let already_exists = domains.iter().any(|v| v.as_str() == Some(&domain));
    if already_exists {
        println!("{} is already in the allowlist", domain);
        return;
    }

    domains.push(toml::Value::String(domain.clone()));

    let serialized = toml::to_string_pretty(&config).expect("failed to serialize config");
    fs::write(&cfg_path, serialized).expect("failed to write config.toml");

    println!("added {} to allowlist", domain);
}

fn cmd_network_explain(
    url: String,
    mode: String,
    allow_domains: Vec<String>,
    deny_domains: Vec<String>,
    deny_localhost: bool,
) {
    let network_mode = parse_policy_network_mode(&mode);
    let cwd = std::env::current_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string());
    let ctx = CommandContext {
        binary: "curl".to_string(),
        args: vec![url.clone()],
        cwd,
        parent_process: Some("agentbox-cli".to_string()),
        pid: std::process::id(),
    };
    let classification = agentbox_policy::classify::classify(
        &ctx,
        &PolicyConfig {
            workspace: None,
            allowed_domains: allow_domains,
            denied_domains: deny_domains,
            allow_localhost: !deny_localhost,
            network_mode,
            always_allow: vec![],
            always_block: vec![],
        },
    );
    let decision = match classification.bucket {
        Bucket::Allow => "allowed",
        Bucket::Approve => "approval required",
        Bucket::Block => "blocked",
    };

    println!("Network explain");
    println!("{}", "-".repeat(64));
    println!("url:      {}", url);
    println!("mode:     {}", format_policy_network_mode(network_mode));
    println!("bucket:   {}", bucket_name(classification.bucket));
    println!("decision: {}", decision);
    println!("reason:   {}", classification.reason);
    println!("scope:    command mediation only; no packet filtering is claimed");
    if let Some(summary) = classification.notification_summary {
        println!("prompt:   {}", summary);
    }
}

fn cmd_network_grant(session_id: String, domain: String, reason: String) {
    use agentbox_daemon::runtime::types::{ApprovalGrant, ApprovalScope};

    let (manager, _session) = runtime_manager_for_session(&session_id, "network grant");
    let domain = normalize_domain_or_exit(&domain);
    let grant = ApprovalGrant {
        id: format!(
            "grant-domain-{}",
            ulid::Ulid::new().to_string().to_lowercase()
        ),
        scope: ApprovalScope::Domain {
            domain: domain.clone(),
        },
        reason,
        expires_at: None,
    };
    let grant = manager
        .add_session_approval_grant(&session_id, grant)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to add network domain grant: {}", e);
            std::process::exit(1);
        });

    println!("Added session network grant.");
    println!("session: {}", session_id);
    println!("grant:   {}", grant.id);
    println!("domain:  {}", domain);
}

fn cmd_credentials(session_id: String, json: bool) {
    let (manager, session) = runtime_manager_for_session(&session_id, "credentials");
    let grants = manager
        .list_credential_grants(&session_id)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to list credential grants: {}", e);
            std::process::exit(1);
        });

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&grants).expect("failed to serialize credential grants")
        );
        return;
    }

    println!("AgentPod credential grants");
    println!("{}", "-".repeat(88));
    println!("session:  {}", session.id);
    println!("provider: {}", session.provider);
    if grants.is_empty() {
        println!("grants:   none");
        return;
    }

    println!("{:<24} {:<16} {:<9} TARGET", "NAME", "KIND", "ONE-TIME");
    println!("{}", "-".repeat(88));
    for grant in grants {
        println!(
            "{:<24} {:<16} {:<9} {}",
            grant.name,
            format!("{:?}", grant.kind),
            if grant.one_time { "yes" } else { "no" },
            grant.target
        );
    }
}

fn cmd_credential_revoke(session_id: String, name: String) {
    let (manager, _session) = runtime_manager_for_session(&session_id, "credential revoke");
    let revoked = manager
        .revoke_credential_grant(&session_id, &name)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to revoke credential grant: {}", e);
            std::process::exit(1);
        });

    let Some(grant) = revoked else {
        eprintln!(
            "error: credential grant `{}` not found in session {}",
            name, session_id
        );
        std::process::exit(1);
    };

    println!("Revoked credential grant.");
    println!("session: {}", session_id);
    println!("name:    {}", grant.name);
    println!("kind:    {:?}", grant.kind);
    println!("target:  {}", grant.target);
}

fn normalize_domain_or_exit(raw: &str) -> String {
    let domain = raw
        .trim()
        .trim_end_matches('.')
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if domain.is_empty() || domain.chars().any(char::is_whitespace) || domain.contains("://") {
        eprintln!("error: invalid domain `{}`", raw);
        std::process::exit(2);
    }
    domain
}

fn parse_policy_network_mode(raw: &str) -> PolicyNetworkMode {
    match raw.trim().to_ascii_lowercase().as_str() {
        "none" => PolicyNetworkMode::None,
        "deny" | "deny-by-default" | "deny_by_default" => PolicyNetworkMode::DenyByDefault,
        "allowlist" | "allowlisted" | "allow-listed" => PolicyNetworkMode::AllowListed,
        "first-contact" | "first_contact" | "approval-on-first-contact" => {
            PolicyNetworkMode::ApprovalOnFirstContact
        }
        "open" | "open-with-guardrails" | "open_with_guardrails" => {
            PolicyNetworkMode::OpenWithGuardrails
        }
        "host" => PolicyNetworkMode::Host,
        other => {
            eprintln!("error: invalid network mode `{}`", other);
            eprintln!(
                "hint: expected deny-by-default, allowlisted, first-contact, open-with-guardrails, none, or host"
            );
            std::process::exit(2);
        }
    }
}

fn format_policy_network_mode(mode: PolicyNetworkMode) -> &'static str {
    match mode {
        PolicyNetworkMode::None => "none",
        PolicyNetworkMode::DenyByDefault => "deny-by-default",
        PolicyNetworkMode::AllowListed => "allowlisted",
        PolicyNetworkMode::ApprovalOnFirstContact => "first-contact",
        PolicyNetworkMode::OpenWithGuardrails => "open-with-guardrails",
        PolicyNetworkMode::Host => "host",
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn cmd_why() {
    let db_path = audit_db_path();
    if !db_path.exists() {
        eprintln!("no audit log found at {}", db_path.display());
        eprintln!("hint: start the daemon first with `agentbox start`");
        std::process::exit(1);
    }

    let conn = Connection::open(&db_path).expect("failed to open audit db");

    let result = conn.query_row(
        "SELECT timestamp, command, bucket, decision, user_response_ms, cwd
         FROM audit_log
         WHERE decision != 'allowed'
         ORDER BY timestamp DESC
         LIMIT 1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, String>(5)?,
            ))
        },
    );

    match result {
        Ok((timestamp, command, bucket, decision, response_ms, cwd)) => {
            let ago = format_time_ago(&timestamp);
            let command = agentbox_daemon::audit::redact_sensitive_text(&command);
            let cwd = agentbox_daemon::audit::redact_sensitive_text(&cwd);

            println!();
            println!("Last intercepted action ({}):", ago);
            println!("  Command:  {}", command);
            println!("  Bucket:   {}", bucket);
            println!("  Decision: {}", format_decision(&decision, response_ms));
            println!("  Dir:      {}", cwd);
            println!("  Reason:   {}", explain_reason(&command, &bucket));
            println!();
            println!("Why: {}", explain_why(&command, &bucket, &decision));
            println!();

            // Suggest override
            let binary = command.split_whitespace().next().unwrap_or(&command);
            println!("To always allow this command in this repo:");
            println!("  agentbox allow-command \"{}\" --in {}", binary, cwd);
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            println!("No blocked or denied actions found in the audit log.");
            println!("All intercepted commands have been allowed so far.");
        }
        Err(e) => {
            eprintln!("failed to query audit log: {}", e);
            std::process::exit(1);
        }
    }
}

fn format_time_ago(timestamp: &str) -> String {
    let ts = if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(timestamp) {
        dt.with_timezone(&Utc)
    } else if let Ok(dt) = NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S") {
        dt.and_utc()
    } else {
        return timestamp.to_string();
    };

    let now = Utc::now();
    let diff = now.signed_duration_since(ts);

    if diff.num_seconds() < 60 {
        "just now".to_string()
    } else if diff.num_minutes() < 60 {
        let m = diff.num_minutes();
        format!("{} minute{} ago", m, if m == 1 { "" } else { "s" })
    } else if diff.num_hours() < 24 {
        let h = diff.num_hours();
        format!("{} hour{} ago", h, if h == 1 { "" } else { "s" })
    } else {
        let d = diff.num_days();
        format!("{} day{} ago", d, if d == 1 { "" } else { "s" })
    }
}

fn format_decision(decision: &str, response_ms: Option<i64>) -> String {
    match decision {
        "denied" => {
            if let Some(ms) = response_ms {
                format!("denied (user tapped Deny, {:.1}s)", ms as f64 / 1000.0)
            } else {
                "denied (user tapped Deny)".to_string()
            }
        }
        "blocked" => "blocked (instant deny)".to_string(),
        "timed_out" => "denied (timed out, no response)".to_string(),
        "approved" => {
            if let Some(ms) = response_ms {
                format!("approved ({:.1}s)", ms as f64 / 1000.0)
            } else {
                "approved".to_string()
            }
        }
        other => other.to_string(),
    }
}

fn explain_reason(command: &str, bucket: &str) -> String {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let binary = parts.first().copied().unwrap_or("");

    match (binary, bucket) {
        ("git", "approve") => {
            if command.contains("--force") || command.contains("-f") {
                "git push to remote -- force push detected".to_string()
            } else {
                "git push to remote repository".to_string()
            }
        }
        ("rm", "block") => "rm -rf targeting root or home directory".to_string(),
        ("rm", "approve") => "rm targeting files outside workspace".to_string(),
        ("ssh", _) | ("scp", _) => format!("{} to remote host", binary),
        ("psql", _) | ("mysql", _) | ("sqlite3", _) => "database client invocation".to_string(),
        ("curl", _) | ("wget", _) => "network egress to unknown domain".to_string(),
        ("npm", _) | ("cargo", _) | ("gem", _) if command.contains("publish") => {
            "package publish".to_string()
        }
        ("chmod", _) | ("chown", _) => "file permission/ownership change".to_string(),
        ("kill", _) | ("killall", _) | ("pkill", _) => "process termination".to_string(),
        ("docker", _) | ("podman", _) => "container mutation".to_string(),
        ("kubectl", _) | ("helm", _) => "cluster mutation".to_string(),
        ("dd", _) => "raw disk/device write tool".to_string(),
        ("mkfs", _) | ("diskutil", _) => "disk format/erase command".to_string(),
        ("csrutil", _) | ("spctl", _) => "system security settings modification".to_string(),
        ("cat", _) | ("head", _) | ("tail", _) => "reading sensitive/credential file".to_string(),
        ("osascript", _) => "AppleScript execution".to_string(),
        ("gh", _) => "visible GitHub operation".to_string(),
        _ => format!("{} -- classified as {}", binary, bucket),
    }
}

fn explain_why(command: &str, bucket: &str, decision: &str) -> String {
    let binary = command.split_whitespace().next().unwrap_or("");

    let risk = match binary {
        "git" if command.contains("push") => {
            if command.contains("--force") || command.contains("-f") {
                "Force pushing rewrites remote history and can destroy\n     teammates' work."
            } else {
                "Pushing code to a remote repository makes changes visible\n     to others and potentially deploys code."
            }
        }
        "rm" if bucket == "block" => {
            "Recursively deleting root or home directory would destroy\n     your entire system or all personal files."
        }
        "rm" => {
            "Deleting files outside the current project could affect\n     other work or system stability."
        }
        "ssh" | "scp" => {
            "Remote access can execute commands on other machines\n     or transfer sensitive data."
        }
        "psql" | "mysql" | "sqlite3" => {
            "Database operations can modify or destroy data\n     that may be difficult or impossible to recover."
        }
        "curl" | "wget" => {
            "Network requests can exfiltrate data or interact\n     with external services in unexpected ways."
        }
        "dd" => "dd writes raw data directly to devices and can\n     overwrite entire disks without warning.",
        "chmod" | "chown" => {
            "Changing file permissions can expose sensitive files\n     or lock you out of your own system."
        }
        "kill" | "killall" => {
            "Terminating processes can interrupt critical services\n     or cause data loss."
        }
        "docker" | "podman" => {
            "Container mutations can affect running services\n     or expose host resources."
        }
        "kubectl" | "helm" => {
            "Cluster mutations can affect production workloads\n     and potentially cause outages."
        }
        _ => "This action was classified as potentially dangerous\n     based on Agentbox's default policy rules.",
    };

    let action = match decision {
        "blocked" => "Agentbox blocked this action immediately.",
        "denied" => "Agentbox required phone approval,\n     which was denied.",
        "timed_out" => {
            "Agentbox required phone approval,\n     but no response was received within the timeout."
        }
        _ => "Agentbox intercepted this action.",
    };

    format!("{}\n     {}", risk, action)
}

fn cmd_policy() {
    println!();
    println!("BLOCK (instant deny, no notification):");
    println!("  rm -rf / or ~    mkfs    diskutil erase    csrutil/spctl    dd");
    println!("  git push --force to main/master");
    println!();
    println!("APPROVE (phone notification required):");
    println!("  git push         ssh/scp           curl/wget (unknown domains)");
    println!("  psql/mysql       sqlite3           npm/cargo/gem publish");
    println!("  chmod/chown      kill/killall      docker (mutations)");
    println!("  kubectl (mutations)  gh pr/issue   osascript");
    println!("  cat .env/.ssh/.aws");
    println!();
    println!("ALLOW (pass through, <50ms):");
    println!("  Everything else -- ls, cat, git commit, npm install, cargo build...");
    println!();

    // Read config for overrides
    let cfg = fs::read_to_string(config_path())
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok());

    // Allowed domains
    let domains: Vec<String> = cfg
        .as_ref()
        .and_then(|t| t.get("allowed_domains"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Always-allow overrides
    let always_allow: Vec<String> = cfg
        .as_ref()
        .and_then(|t| t.get("always_allow"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Always-block overrides
    let always_block: Vec<String> = cfg
        .as_ref()
        .and_then(|t| t.get("always_block"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    println!("OVERRIDES:");
    if domains.is_empty() {
        println!("  Allowed domains: (none)");
    } else {
        println!("  Allowed domains: {}", domains.join(", "));
    }
    if always_allow.is_empty() {
        println!("  Always allow:    (none)");
    } else {
        println!("  Always allow:    {}", always_allow.join(", "));
    }
    if always_block.is_empty() {
        println!("  Always block:    (none)");
    } else {
        println!("  Always block:    {}", always_block.join(", "));
    }

    println!();

    // Audit event count
    let db_path = audit_db_path();
    let event_count = if db_path.exists() {
        Connection::open(&db_path)
            .ok()
            .and_then(|c| {
                c.query_row("SELECT COUNT(*) FROM audit_log", [], |row| {
                    row.get::<_, i64>(0)
                })
                .ok()
            })
            .unwrap_or(0)
    } else {
        0
    };

    println!("Config: {}", config_path().display());
    println!(
        "Audit:  {} ({} events)",
        audit_db_path().display(),
        event_count
    );
}

fn cmd_policy_simulate(command: Vec<String>) {
    let (command_text, classification) = classify_cli_command(command);

    println!("Command: {}", command_text);
    println!("Bucket:  {}", bucket_name(classification.bucket));
    println!("Reason:  {}", classification.reason);
    if let Some(summary) = classification.notification_summary {
        println!("Notify:  {}", summary);
    }
}

fn cmd_policy_explain(command: Vec<String>) {
    let (command_text, classification) = classify_cli_command(command);
    let bucket = bucket_name(classification.bucket);
    let decision = match classification.bucket {
        Bucket::Allow => "allowed",
        Bucket::Approve => "needs approval",
        Bucket::Block => "blocked",
    };

    println!("Command:  {}", command_text);
    println!("Bucket:   {}", bucket);
    println!("Decision: {}", decision);
    println!("Reason:   {}", classification.reason);
    println!();
    println!(
        "Why: {}",
        explain_why(
            &command_text,
            bucket,
            simulated_decision_key(classification.bucket)
        )
    );
    if let Some(summary) = classification.notification_summary {
        println!();
        println!("Approval prompt: {}", summary);
    }
}

fn classify_cli_command(command: Vec<String>) -> (String, Classification) {
    if command.is_empty() {
        eprintln!("error: command is required");
        eprintln!("hint: agentbox policy-simulate -- git push origin main");
        std::process::exit(2);
    }

    let binary = command[0].clone();
    let args = command[1..].to_vec();
    let cwd = std::env::current_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string());
    let config = agentbox_daemon::config::load()
        .map(|config| config.to_policy_config())
        .unwrap_or_default();
    let ctx = CommandContext {
        binary,
        args,
        cwd,
        parent_process: Some("agentbox-cli".to_string()),
        pid: std::process::id(),
    };

    let command_text = format_command_text(&ctx.binary, &ctx.args);
    let classification = agentbox_policy::classify::classify(&ctx, &config);
    (command_text, classification)
}

fn format_command_text(binary: &str, args: &[String]) -> String {
    if args.is_empty() {
        binary.to_string()
    } else {
        format!("{} {}", binary, args.join(" "))
    }
}

fn bucket_name(bucket: Bucket) -> &'static str {
    match bucket {
        Bucket::Allow => "allow",
        Bucket::Approve => "approve",
        Bucket::Block => "block",
    }
}

fn simulated_decision_key(bucket: Bucket) -> &'static str {
    match bucket {
        Bucket::Allow => "allowed",
        Bucket::Approve => "approved",
        Bucket::Block => "blocked",
    }
}

fn cmd_history(show_all: bool, bucket_filter: Option<String>, json_output: bool) {
    let db_path = audit_db_path();
    if !db_path.exists() {
        eprintln!("no audit log found at {}", db_path.display());
        eprintln!("hint: start the daemon first with `agentbox start`");
        std::process::exit(1);
    }

    let conn = Connection::open(&db_path).expect("failed to open audit db");

    // Build query
    let today_str = Utc::now().format("%Y-%m-%d").to_string();
    let mut sql = String::from(
        "SELECT timestamp, bucket, decision, command, user_response_ms
         FROM audit_log WHERE 1=1",
    );

    if !show_all {
        sql.push_str(&format!(" AND timestamp LIKE '{}%'", today_str));
    }
    if let Some(ref b) = bucket_filter {
        sql.push_str(&format!(" AND bucket = '{}'", b));
    }
    sql.push_str(" ORDER BY timestamp ASC");

    let mut stmt = conn.prepare(&sql).expect("failed to prepare query");

    struct HistoryRow {
        timestamp: String,
        bucket: String,
        decision: String,
        command: String,
        user_response_ms: Option<i64>,
    }

    let rows = stmt
        .query_map([], |row| {
            Ok(HistoryRow {
                timestamp: row.get(0)?,
                bucket: row.get(1)?,
                decision: row.get(2)?,
                command: row.get(3)?,
                user_response_ms: row.get(4)?,
            })
        })
        .expect("failed to query audit log");

    let events: Vec<HistoryRow> = rows.filter_map(|r| r.ok()).collect();

    if json_output {
        println!("[");
        for (i, event) in events.iter().enumerate() {
            let comma = if i < events.len() - 1 { "," } else { "" };
            let response_ms = event
                .user_response_ms
                .map(|ms| ms.to_string())
                .unwrap_or_else(|| "null".to_string());
            println!(
                "  {{\"timestamp\":\"{}\",\"bucket\":\"{}\",\"decision\":\"{}\",\"command\":\"{}\",\"user_response_ms\":{}}}{}",
                event.timestamp,
                event.bucket,
                event.decision,
                agentbox_daemon::audit::redact_sensitive_text(&event.command)
                    .replace('\\', "\\\\")
                    .replace('"', "\\\""),
                response_ms,
                comma
            );
        }
        println!("]");
        return;
    }

    if events.is_empty() {
        if show_all {
            println!("No events in the audit log.");
        } else {
            println!("No events today. Use --all to see all history.");
        }
        return;
    }

    // Group by date, print timeline
    let mut current_date = String::new();
    let mut total: usize = 0;
    let mut allowed: usize = 0;
    let mut approved: usize = 0;
    let mut blocked: usize = 0;
    let mut approval_times: Vec<f64> = Vec::new();

    for event in &events {
        let date = if event.timestamp.len() >= 10 {
            &event.timestamp[..10]
        } else {
            &event.timestamp
        };

        if date != current_date {
            if !current_date.is_empty() {
                println!();
            }
            current_date = date.to_string();
            let label = if date == today_str {
                "Today".to_string()
            } else {
                date.to_string()
            };
            println!("{}", label);
            println!("{}", "\u{2501}".repeat(50));
        }

        let time_display = if event.timestamp.len() >= 16 {
            &event.timestamp[11..16]
        } else {
            &event.timestamp
        };

        let bucket_label = match event.bucket.as_str() {
            "allow" => "ALLOW  ",
            "approve" => "APPROVE",
            "block" => "BLOCK  ",
            _ => "       ",
        };

        let command = agentbox_daemon::audit::redact_sensitive_text(&event.command);
        let cmd_display = if command.len() > 40 {
            format!("{}...", &command[..37])
        } else {
            command
        };

        let suffix = match event.bucket.as_str() {
            "block" => " \u{26d4} instant deny".to_string(),
            "approve" => {
                let time_part = event
                    .user_response_ms
                    .map(|ms| format!("{:.1}s", ms as f64 / 1000.0))
                    .unwrap_or_default();
                match event.decision.as_str() {
                    "approved" => {
                        if time_part.is_empty() {
                            " -> approved".to_string()
                        } else {
                            format!(" -> approved ({})", time_part)
                        }
                    }
                    "denied" => " -> denied (user)".to_string(),
                    "timed_out" => " -> denied (timeout)".to_string(),
                    _ => String::new(),
                }
            }
            _ => String::new(),
        };

        println!(
            "{}  {}  {:<40}{}",
            time_display, bucket_label, cmd_display, suffix
        );

        // Update stats
        total += 1;
        match event.bucket.as_str() {
            "allow" => allowed += 1,
            "approve" => {
                approved += 1;
                if let Some(ms) = event.user_response_ms {
                    approval_times.push(ms as f64);
                }
            }
            "block" => blocked += 1,
            _ => {}
        }
    }

    // Print stats
    println!();
    println!(
        "Stats: {} total | {} allowed | {} approved | {} blocked",
        total, allowed, approved, blocked
    );
    if !approval_times.is_empty() {
        let avg: f64 = approval_times.iter().sum::<f64>() / approval_times.len() as f64;
        println!("Avg approval time: {:.1}s", avg / 1000.0);
    }
}

fn cmd_evidence(
    limit: usize,
    verify: bool,
    session: Option<String>,
    credentials: bool,
    network: bool,
) {
    let db_path = audit_db_path();
    if !db_path.exists() {
        eprintln!("no audit log found at {}", db_path.display());
        eprintln!("hint: start the daemon first with `agentbox start`");
        std::process::exit(1);
    }

    if verify {
        let store = agentbox_daemon::audit::AuditStore::new(&db_path.to_string_lossy())
            .unwrap_or_else(|e| {
                eprintln!("failed to open audit store: {}", e);
                std::process::exit(1);
            });
        let verification = store.verify_hash_chain().unwrap_or_else(|e| {
            eprintln!("failed to verify audit hash chain: {}", e);
            std::process::exit(1);
        });

        if verification.valid {
            println!(
                "evidence hash chain: valid ({} events checked)",
                verification.checked_events
            );
            return;
        }

        eprintln!(
            "evidence hash chain: invalid ({} events checked, {} violations)",
            verification.checked_events,
            verification.violations.len()
        );
        for violation in verification.violations {
            eprintln!("- {}: {}", violation.event_id, violation.reason);
        }
        std::process::exit(1);
    }

    if credentials && session.is_none() {
        eprintln!("error: --credentials requires --session <id>");
        std::process::exit(1);
    }
    if network && session.is_some() {
        eprintln!("error: --network currently exports global network evidence; omit --session");
        std::process::exit(1);
    }
    if network && credentials {
        eprintln!("error: --network and --credentials cannot be combined");
        std::process::exit(1);
    }

    if let Some(session_id) = session {
        if credentials {
            cmd_session_credentials_evidence(&db_path, &session_id, limit);
        } else {
            cmd_session_evidence_bundle(&db_path, &session_id, limit);
        }
        return;
    }

    if network {
        cmd_bucket_evidence_jsonl(&db_path, "network", limit);
        return;
    }

    cmd_all_evidence_jsonl(&db_path, limit);
}

fn cmd_all_evidence_jsonl(db_path: &PathBuf, limit: usize) {
    let conn = Connection::open(&db_path).expect("failed to open audit db");
    ensure_evidence_columns(&conn);
    let mut stmt = conn
        .prepare(
            "SELECT id, schema_version, timestamp, agent_pid, agent_name, command, cwd,
                    bucket, decision, user_response_ms, parent_process, prev_hash, event_hash
             FROM audit_log
             ORDER BY timestamp ASC
             LIMIT ?1",
        )
        .expect("failed to prepare evidence query");

    let rows = stmt
        .query_map([limit as i64], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "schema_version": row.get::<_, i64>(1)?,
                "timestamp": row.get::<_, String>(2)?,
                "agent_pid": row.get::<_, i64>(3)?,
                "agent_name": row.get::<_, Option<String>>(4)?,
                "command": agentbox_daemon::audit::redact_sensitive_text(&row.get::<_, String>(5)?),
                "cwd": agentbox_daemon::audit::redact_sensitive_text(&row.get::<_, String>(6)?),
                "bucket": row.get::<_, String>(7)?,
                "decision": row.get::<_, String>(8)?,
                "user_response_ms": row.get::<_, Option<i64>>(9)?,
                "parent_process": row.get::<_, Option<String>>(10)?.map(|value| agentbox_daemon::audit::redact_sensitive_text(&value)),
                "prev_hash": row.get::<_, Option<String>>(11)?,
                "event_hash": row.get::<_, Option<String>>(12)?,
            }))
        })
        .expect("failed to query evidence");

    for row in rows {
        match row {
            Ok(value) => println!("{}", value),
            Err(e) => {
                eprintln!("failed to read evidence row: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn cmd_bucket_evidence_jsonl(db_path: &PathBuf, bucket: &str, limit: usize) {
    let conn = Connection::open(db_path).expect("failed to open audit db");
    ensure_evidence_columns(&conn);
    let mut stmt = conn
        .prepare(
            "SELECT id, schema_version, timestamp, agent_pid, agent_name, command, cwd,
                    bucket, decision, user_response_ms, parent_process, prev_hash, event_hash
             FROM audit_log
             WHERE bucket = ?1
             ORDER BY timestamp ASC
             LIMIT ?2",
        )
        .expect("failed to prepare filtered evidence query");

    let rows = stmt
        .query_map((bucket, limit as i64), |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "schema_version": row.get::<_, i64>(1)?,
                "timestamp": row.get::<_, String>(2)?,
                "agent_pid": row.get::<_, i64>(3)?,
                "agent_name": row.get::<_, Option<String>>(4)?,
                "command": agentbox_daemon::audit::redact_sensitive_text(&row.get::<_, String>(5)?),
                "cwd": agentbox_daemon::audit::redact_sensitive_text(&row.get::<_, String>(6)?),
                "bucket": row.get::<_, String>(7)?,
                "decision": row.get::<_, String>(8)?,
                "user_response_ms": row.get::<_, Option<i64>>(9)?,
                "parent_process": row.get::<_, Option<String>>(10)?.map(|value| agentbox_daemon::audit::redact_sensitive_text(&value)),
                "prev_hash": row.get::<_, Option<String>>(11)?,
                "event_hash": row.get::<_, Option<String>>(12)?,
            }))
        })
        .expect("failed to query filtered evidence");

    for row in rows {
        match row {
            Ok(value) => println!("{}", value),
            Err(e) => {
                eprintln!("failed to read evidence row: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn cmd_session_evidence_bundle(db_path: &PathBuf, session_id: &str, limit: usize) {
    let bundle = load_session_evidence_bundle(db_path, session_id, limit);
    println!(
        "{}",
        serde_json::to_string(&bundle).expect("failed to serialize session bundle")
    );
}

fn cmd_session_credentials_evidence(db_path: &PathBuf, session_id: &str, limit: usize) {
    let bundle = load_session_evidence_bundle(db_path, session_id, limit);
    for grant in bundle.credential_grants {
        println!(
            "{}",
            serde_json::json!({
                "type": "credential_grant",
                "session_id": session_id,
                "grant": grant,
            })
        );
    }
    for event in bundle.credential_events {
        println!(
            "{}",
            serde_json::json!({
                "type": "credential_event",
                "session_id": session_id,
                "event": event,
            })
        );
    }
}

fn load_session_evidence_bundle(
    db_path: &PathBuf,
    session_id: &str,
    limit: usize,
) -> agentbox_daemon::runtime::types::SessionEvidenceBundle {
    use agentbox_daemon::audit::AuditEvent;
    use agentbox_daemon::config;
    use agentbox_daemon::runtime::session::RuntimeSessionStore;
    use agentbox_daemon::runtime::types::SessionEvidenceBundle;

    let config = config::load().unwrap_or_else(|e| {
        eprintln!("error: failed to load Agentbox config: {}", e);
        std::process::exit(1);
    });
    let store = RuntimeSessionStore::new(config.session_store_path);
    let session = store.get(session_id).unwrap_or_else(|e| {
        eprintln!("error: failed to read runtime session store: {}", e);
        std::process::exit(1);
    });
    let Some(session) = session else {
        eprintln!("error: minipod session not found: {}", session_id);
        eprintln!("hint: session bundle export currently requires a persisted active session");
        std::process::exit(1);
    };

    let conn = Connection::open(db_path).expect("failed to open audit db");
    ensure_evidence_columns(&conn);
    let mut stmt = conn
        .prepare(
            "SELECT id, schema_version, timestamp, agent_pid, agent_name, command, cwd,
                    bucket, decision, user_response_ms, parent_process, prev_hash, event_hash
             FROM audit_log
             WHERE command LIKE ?1 OR agent_name = ?2
             ORDER BY timestamp ASC
             LIMIT ?3",
        )
        .expect("failed to prepare session evidence query");
    let pattern = format!("%{}%", session.id);
    let rows = stmt
        .query_map((&pattern, &session.spec.agent.name, limit as i64), |row| {
            Ok(AuditEvent {
                id: row.get(0)?,
                schema_version: row.get(1)?,
                timestamp: row.get(2)?,
                agent_pid: row.get(3)?,
                agent_name: row.get(4)?,
                command: agentbox_daemon::audit::redact_sensitive_text(&row.get::<_, String>(5)?),
                cwd: agentbox_daemon::audit::redact_sensitive_text(&row.get::<_, String>(6)?),
                bucket: row.get(7)?,
                decision: row.get(8)?,
                user_response_ms: row.get(9)?,
                parent_process: row
                    .get::<_, Option<String>>(10)?
                    .map(|value| agentbox_daemon::audit::redact_sensitive_text(&value)),
                prev_hash: row.get(11)?,
                event_hash: row.get(12)?,
            })
        })
        .expect("failed to query session evidence");

    let events = rows.collect::<Result<Vec<_>, _>>().unwrap_or_else(|e| {
        eprintln!("failed to read session evidence row: {}", e);
        std::process::exit(1);
    });
    SessionEvidenceBundle::from_session_events(&session, &events)
}

struct MinipodSpecOptions {
    agent: String,
    workspace: Option<PathBuf>,
    agent_profile: String,
    risk: String,
    provider: String,
    allow_domains: Vec<String>,
    read_only_mounts: Vec<String>,
    credential_files: Vec<String>,
    credential_env: Vec<String>,
    credential_sockets: Vec<String>,
    credential_tokens: Vec<String>,
    credential_ttl_seconds: Option<i64>,
    policy_bundles: Vec<PathBuf>,
    network_mode: Option<String>,
    deny_domains: Vec<String>,
    deny_localhost: bool,
    workspace_mode: Option<String>,
    workspace_overlay_dir: Option<PathBuf>,
}

fn cmd_minipod_spec(options: MinipodSpecOptions) {
    use agentbox_daemon::runtime::policy::validate_minipod_spec;
    use agentbox_daemon::runtime::registry::{ProviderSelectionRequest, RuntimeProviderRegistry};
    use agentbox_daemon::runtime::types::{MinipodSpec, NetworkMode};

    let workspace = options.workspace.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| {
            eprintln!("error: failed to determine current directory");
            std::process::exit(1);
        })
    });
    let mut spec =
        MinipodSpec::for_agent_task_with_profile(options.agent, workspace, options.agent_profile);
    spec.risk = parse_agentpod_risk(&options.risk);
    spec.labels
        .insert("agentbox.risk".to_string(), spec.risk.label().to_string());

    let registry = RuntimeProviderRegistry::with_local_providers(String::new(), String::new());
    let selection = registry
        .explain_selection(&ProviderSelectionRequest {
            preferred_provider: parse_provider_hint(&options.provider),
            risk: spec.risk.clone(),
        })
        .unwrap_or_else(|e| {
            eprintln!("error: failed to select provider: {}", e);
            std::process::exit(1);
        });
    spec.labels.insert(
        "agentbox.provider.selected".to_string(),
        selection.selected_provider,
    );
    spec.labels.insert(
        "agentbox.provider.selection_reason".to_string(),
        selection.reason,
    );

    for bundle_path in options.policy_bundles {
        let bundle = load_task_policy_bundle(&bundle_path);
        bundle.apply_to_minipod(&mut spec);
    }
    for mount in options.read_only_mounts {
        spec.filesystem.mounts.push(parse_read_only_mount(&mount));
    }
    for grant in options.credential_files {
        let (mount, credential_grant) = parse_credential_file_grant(&grant);
        spec.filesystem.mounts.push(mount);
        spec.credentials.grants.push(credential_grant);
    }
    for grant in options.credential_env {
        spec.credentials
            .grants
            .push(parse_simple_credential_grant(&grant, "env"));
    }
    for grant in options.credential_sockets {
        spec.credentials
            .grants
            .push(parse_simple_credential_grant(&grant, "socket"));
    }
    for grant in options.credential_tokens {
        spec.credentials
            .grants
            .push(parse_simple_credential_grant(&grant, "token"));
    }
    apply_credential_ttl(&mut spec, options.credential_ttl_seconds);
    apply_workspace_mode(
        &mut spec,
        options.workspace_mode.as_deref(),
        options.workspace_overlay_dir,
    );
    if !options.allow_domains.is_empty() {
        spec.network.mode = NetworkMode::AllowListed;
        spec.network.allowed_domains = options.allow_domains;
    }
    if let Some(mode) = options.network_mode {
        spec.network.mode = parse_network_mode(&mode);
    }
    if !options.deny_domains.is_empty() {
        spec.network.denied_domains = options.deny_domains;
    }
    if options.deny_localhost {
        spec.network.allow_localhost = false;
    }

    if let Err(e) = validate_minipod_spec(&spec) {
        eprintln!("error: generated minipod manifest is invalid: {}", e);
        std::process::exit(1);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&spec).expect("failed to serialize minipod manifest")
    );
}

fn parse_read_only_mount(raw: &str) -> agentbox_daemon::runtime::types::MountRule {
    use agentbox_daemon::runtime::types::{MountKind, MountMode, MountRule};

    let Some((host_path, guest_path)) = raw.split_once(':') else {
        eprintln!("error: invalid --mount-ro value `{}`", raw);
        eprintln!("hint: expected host_path:guest_path");
        std::process::exit(1);
    };
    if host_path.trim().is_empty() || guest_path.trim().is_empty() {
        eprintln!("error: invalid --mount-ro value `{}`", raw);
        eprintln!("hint: host_path and guest_path must both be non-empty");
        std::process::exit(1);
    }

    MountRule {
        host_path: PathBuf::from(host_path),
        guest_path: guest_path.to_string(),
        mode: MountMode::ReadOnly,
        kind: MountKind::ReadOnlyHost,
    }
}

fn parse_network_mode(raw: &str) -> agentbox_daemon::runtime::types::NetworkMode {
    use agentbox_daemon::runtime::types::NetworkMode;

    match raw.trim().to_ascii_lowercase().as_str() {
        "deny" | "deny-by-default" | "deny_by_default" => NetworkMode::DenyByDefault,
        "allowlist" | "allowlisted" | "allow-listed" => NetworkMode::AllowListed,
        "first-contact" | "first_contact" | "approval-on-first-contact" => {
            NetworkMode::ApprovalOnFirstContact
        }
        "open-with-guardrails" | "open_with_guardrails" | "guardrails" => {
            NetworkMode::OpenWithGuardrails
        }
        other => {
            eprintln!("error: invalid --network-mode value `{}`", other);
            eprintln!(
                "hint: expected deny-by-default, allowlisted, first-contact, or open-with-guardrails"
            );
            std::process::exit(1);
        }
    }
}

fn parse_agentpod_risk(raw: &str) -> agentbox_daemon::runtime::types::AgentPodRiskLevel {
    use agentbox_daemon::runtime::types::AgentPodRiskLevel;

    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => AgentPodRiskLevel::Low,
        "medium" | "med" => AgentPodRiskLevel::Medium,
        "high" => AgentPodRiskLevel::High,
        "very-high" | "very_high" | "veryhigh" | "critical" => AgentPodRiskLevel::VeryHigh,
        other => {
            eprintln!("error: invalid --risk value `{}`", other);
            eprintln!("hint: expected low, medium, high, or very-high");
            std::process::exit(1);
        }
    }
}

fn parse_provider_hint(raw: &str) -> Option<String> {
    let provider = raw.trim();
    if provider.is_empty() || provider.eq_ignore_ascii_case("auto") {
        None
    } else {
        Some(provider.to_string())
    }
}

fn apply_workspace_mode(
    spec: &mut agentbox_daemon::runtime::types::MinipodSpec,
    raw_mode: Option<&str>,
    overlay_dir: Option<PathBuf>,
) {
    use agentbox_daemon::runtime::types::{
        AgentPodWorkspaceMode, WorkspaceOverlayMode, WorkspaceOverlayPolicy,
    };

    let mut mode = raw_mode
        .map(parse_workspace_mode)
        .unwrap_or(AgentPodWorkspaceMode::Direct);
    if overlay_dir.is_some() && mode == AgentPodWorkspaceMode::Direct {
        mode = AgentPodWorkspaceMode::OverlayReview;
    }

    spec.workspace_mode = mode.clone();
    spec.labels.insert(
        "agentbox.workspace_mode".to_string(),
        spec.workspace_mode.label().to_string(),
    );
    spec.filesystem.workspace_write_policy = mode.write_policy();

    if mode == AgentPodWorkspaceMode::Direct {
        spec.filesystem.workspace_overlay = WorkspaceOverlayPolicy::default();
        return;
    }

    let overlay_base = overlay_dir.unwrap_or_else(|| {
        agentbox_dir()
            .join("overlays")
            .join(spec.id.clone())
            .join(mode.label())
    });
    let mut overlay = WorkspaceOverlayPolicy::review_required(Some(overlay_base));
    if mode == AgentPodWorkspaceMode::Ephemeral {
        overlay.mode = WorkspaceOverlayMode::DiscardOnDestroy;
    }
    spec.filesystem.workspace_overlay = overlay;
}

fn parse_workspace_mode(raw: &str) -> agentbox_daemon::runtime::types::AgentPodWorkspaceMode {
    use agentbox_daemon::runtime::types::AgentPodWorkspaceMode;

    match raw.trim().to_ascii_lowercase().as_str() {
        "direct" => AgentPodWorkspaceMode::Direct,
        "overlay-review" | "overlay_review" | "overlay" | "review" => {
            AgentPodWorkspaceMode::OverlayReview
        }
        "ephemeral" | "discard" => AgentPodWorkspaceMode::Ephemeral,
        "commit-gated" | "commit_gated" | "commit" => AgentPodWorkspaceMode::CommitGated,
        other => {
            eprintln!("error: invalid --workspace-mode value `{}`", other);
            eprintln!("hint: expected direct, overlay-review, ephemeral, or commit-gated");
            std::process::exit(1);
        }
    }
}

fn load_task_policy_bundle(
    path: &std::path::Path,
) -> agentbox_daemon::runtime::types::TaskPolicyBundle {
    agentbox_daemon::runtime::policy::load_task_policy_bundle(path).unwrap_or_else(|e| {
        eprintln!("error: failed to load task policy bundle: {}", e);
        std::process::exit(1);
    })
}

fn parse_credential_file_grant(
    raw: &str,
) -> (
    agentbox_daemon::runtime::types::MountRule,
    agentbox_daemon::runtime::types::CredentialGrant,
) {
    use agentbox_daemon::runtime::types::{
        CredentialGrant, CredentialGrantKind, MountKind, MountMode, MountRule,
    };

    let Some((name, paths)) = raw.split_once('=') else {
        eprintln!("error: invalid --credential-file value `{}`", raw);
        eprintln!("hint: expected name=host_path:guest_path");
        std::process::exit(1);
    };
    let Some((host_path, guest_path)) = paths.split_once(':') else {
        eprintln!("error: invalid --credential-file value `{}`", raw);
        eprintln!("hint: expected name=host_path:guest_path");
        std::process::exit(1);
    };
    if name.trim().is_empty() || host_path.trim().is_empty() || guest_path.trim().is_empty() {
        eprintln!("error: invalid --credential-file value `{}`", raw);
        eprintln!("hint: name, host_path, and guest_path must all be non-empty");
        std::process::exit(1);
    }
    if host_path.ends_with('/') || PathBuf::from(host_path).is_dir() {
        eprintln!("error: --credential-file must point to a single credential file");
        eprintln!("hint: do not grant whole credential directories");
        std::process::exit(1);
    }

    let host_path = PathBuf::from(host_path);
    (
        MountRule {
            host_path: host_path.clone(),
            guest_path: guest_path.to_string(),
            mode: MountMode::ReadOnly,
            kind: MountKind::Credential,
        },
        CredentialGrant {
            name: name.to_string(),
            kind: CredentialGrantKind::FileMount,
            target: host_path.display().to_string(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        },
    )
}

fn parse_simple_credential_grant(
    raw: &str,
    kind: &str,
) -> agentbox_daemon::runtime::types::CredentialGrant {
    use agentbox_daemon::runtime::types::{CredentialGrant, CredentialGrantKind};

    let Some((name, target)) = raw.split_once('=') else {
        eprintln!("error: invalid --credential-{kind} value `{}`", raw);
        eprintln!("hint: expected name=target");
        std::process::exit(1);
    };
    if name.trim().is_empty() || target.trim().is_empty() {
        eprintln!("error: invalid --credential-{kind} value `{}`", raw);
        eprintln!("hint: name and target must be non-empty");
        std::process::exit(1);
    }

    let grant_kind = match kind {
        "env" => CredentialGrantKind::EnvVar,
        "socket" => CredentialGrantKind::Socket,
        "token" => CredentialGrantKind::ProviderToken,
        _ => unreachable!("unsupported credential grant kind"),
    };

    CredentialGrant {
        name: name.to_string(),
        kind: grant_kind,
        target: target.to_string(),
        one_time: true,
        requires_approval: true,
        expires_at: None,
    }
}

fn apply_credential_ttl(
    spec: &mut agentbox_daemon::runtime::types::MinipodSpec,
    ttl_seconds: Option<i64>,
) {
    let Some(ttl_seconds) = ttl_seconds else {
        return;
    };
    if ttl_seconds <= 0 {
        eprintln!("error: --credential-ttl-seconds must be greater than zero");
        std::process::exit(1);
    }

    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl_seconds);
    for grant in &mut spec.credentials.grants {
        if grant.expires_at.is_none() {
            grant.expires_at = Some(expires_at);
        }
    }
}

fn cmd_providers(json: bool) {
    use agentbox_daemon::runtime::registry::RuntimeProviderRegistry;

    let mut rows = vec![serde_json::json!({
        "provider": "direct-host",
        "family": "direct-host",
        "platform": std::env::consts::OS,
        "status": "shipped",
        "bridge": "unix-socket",
        "network": "command-mediation",
        "capabilities": ["shim", "policy", "approval", "audit"],
    })];

    let registry = RuntimeProviderRegistry::with_local_providers(
        socket_path().to_string_lossy().into_owned(),
        find_shim_binary()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
    );
    for name in registry.names() {
        let provider = registry
            .get(name)
            .expect("provider name came from registry");
        if provider.name() == "podman" {
            continue;
        }
        rows.push(serde_json::json!({
            "provider": provider.name(),
            "family": format_provider_family(provider.family()),
            "platform": provider.platform(),
            "status": format_provider_status(provider.implementation_status()),
            "bridge": format_bridge_transports(provider.bridge_transport_kinds()),
            "network": format_network_enforcement(provider.network_enforcement_capabilities()),
            "capabilities": provider
                .capabilities()
                .iter()
                .map(|capability| format!("{capability:?}"))
                .collect::<Vec<_>>(),
        }));
    }

    let podman_status = if Command::new("podman")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
    {
        "experimental"
    } else {
        "unavailable"
    };
    rows.push(serde_json::json!({
        "provider": "podman",
        "family": "compat",
        "platform": "linux-vm",
        "status": podman_status,
        "bridge": "unix-socket",
        "network": "none",
        "capabilities": ["container isolation", "shim bridge"],
    }));

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).expect("failed to serialize providers")
        );
        return;
    }

    println!(
        "{:<18} {:<14} {:<10} {:<18} {:<18} {:<24} CAPABILITIES",
        "PROVIDER", "FAMILY", "PLATFORM", "STATUS", "BRIDGE", "NETWORK"
    );
    println!("{}", "-".repeat(152));
    println!(
        "{:<18} {:<14} {:<10} {:<18} {:<18} {:<24} shim, policy, approval, audit",
        "direct-host",
        "direct-host",
        std::env::consts::OS,
        "shipped",
        "unix-socket",
        "command-mediation"
    );
    for name in registry.names() {
        let provider = registry
            .get(name)
            .expect("provider name came from registry");
        if provider.name() == "podman" {
            continue;
        }
        let capabilities = provider
            .capabilities()
            .iter()
            .map(|capability| format!("{capability:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{:<18} {:<14} {:<10} {:<18} {:<18} {:<24} {}",
            provider.name(),
            format_provider_family(provider.family()),
            provider.platform(),
            format_provider_status(provider.implementation_status()),
            format_bridge_transports(provider.bridge_transport_kinds()),
            format_network_enforcement(provider.network_enforcement_capabilities()),
            capabilities
        );
    }

    println!(
        "{:<18} {:<14} {:<10} {:<18} {:<18} {:<24} container isolation, shim bridge",
        "podman", "compat", "linux-vm", podman_status, "unix-socket", "none"
    );
}

fn cmd_remote_descriptor(endpoint: String, auth: String, evidence: String) {
    use agentbox_daemon::runtime::providers::remote::RemoteAgentPodTransportDescriptor;

    let descriptor = RemoteAgentPodTransportDescriptor::new(
        endpoint,
        parse_remote_auth_kind(&auth),
        parse_remote_evidence_mode(&evidence),
    )
    .unwrap_or_else(|e| {
        eprintln!("error: failed to build remote AgentPod descriptor: {}", e);
        std::process::exit(1);
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&descriptor)
            .expect("failed to serialize remote AgentPod descriptor")
    );
}

fn cmd_remote_handshake(endpoint: String, auth: String, ttl_seconds: i64) {
    use agentbox_daemon::runtime::providers::remote::RemoteAgentPodHandshakeDescriptor;

    let descriptor = RemoteAgentPodHandshakeDescriptor::new(
        endpoint,
        parse_remote_auth_kind(&auth),
        ttl_seconds,
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod handshake descriptor: {}",
            e
        );
        std::process::exit(1);
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&descriptor)
            .expect("failed to serialize remote AgentPod handshake descriptor")
    );
}

fn parse_remote_auth_kind(
    raw: &str,
) -> agentbox_daemon::runtime::providers::remote::RemoteAgentPodAuthKind {
    use agentbox_daemon::runtime::providers::remote::RemoteAgentPodAuthKind;

    match raw.trim().to_ascii_lowercase().as_str() {
        "signed-challenge" | "signed_challenge" => RemoteAgentPodAuthKind::SignedChallenge,
        "workload-identity" | "workload_identity" => RemoteAgentPodAuthKind::WorkloadIdentity,
        "mtls" | "mutual-tls" | "mutual_tls" => RemoteAgentPodAuthKind::MutualTls,
        "operator-ssh" | "operator_ssh" | "ssh" => RemoteAgentPodAuthKind::OperatorSsh,
        other => {
            eprintln!("error: invalid --auth value `{}`", other);
            eprintln!("hint: expected signed-challenge, workload-identity, mtls, or operator-ssh");
            std::process::exit(1);
        }
    }
}

fn parse_remote_evidence_mode(
    raw: &str,
) -> agentbox_daemon::runtime::providers::remote::RemoteAgentPodEvidenceMode {
    use agentbox_daemon::runtime::providers::remote::RemoteAgentPodEvidenceMode;

    match raw.trim().to_ascii_lowercase().as_str() {
        "append-only-stream" | "append_only_stream" | "stream" => {
            RemoteAgentPodEvidenceMode::AppendOnlyStream
        }
        "bundle-upload" | "bundle_upload" | "upload" => RemoteAgentPodEvidenceMode::BundleUpload,
        "local-pull" | "local_pull" | "pull" => RemoteAgentPodEvidenceMode::LocalPull,
        other => {
            eprintln!("error: invalid --evidence value `{}`", other);
            eprintln!("hint: expected append-only-stream, bundle-upload, or local-pull");
            std::process::exit(1);
        }
    }
}

fn format_provider_family(
    family: agentbox_daemon::runtime::provider::ProviderFamily,
) -> &'static str {
    use agentbox_daemon::runtime::provider::ProviderFamily;

    match family {
        ProviderFamily::DirectHost => "direct-host",
        ProviderFamily::NativeSandbox => "native",
        ProviderFamily::VmBacked => "vm-backed",
        ProviderFamily::Remote => "remote",
        ProviderFamily::Compatibility => "compat",
    }
}

fn format_provider_status(
    status: agentbox_daemon::runtime::provider::ProviderImplementationStatus,
) -> &'static str {
    use agentbox_daemon::runtime::provider::ProviderImplementationStatus;

    match status {
        ProviderImplementationStatus::Shipped => "shipped",
        ProviderImplementationStatus::Experimental => "experimental",
        ProviderImplementationStatus::PrototypePrimitive => "prototype",
        ProviderImplementationStatus::DescriptorOnly => "descriptor-only",
        ProviderImplementationStatus::Planned => "planned",
        ProviderImplementationStatus::Unavailable => "unavailable",
    }
}

fn format_network_enforcement(
    capabilities: &[agentbox_daemon::runtime::types::NetworkEnforcementCapability],
) -> String {
    if capabilities.is_empty() {
        return "none".to_string();
    }

    capabilities
        .iter()
        .map(|capability| format!("{capability:?}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_bridge_transports(
    transports: &[agentbox_daemon::runtime::bridge::HostBridgeTransportKind],
) -> String {
    use agentbox_daemon::runtime::bridge::HostBridgeTransportKind;

    if transports.is_empty() {
        return "none".to_string();
    }

    transports
        .iter()
        .map(|transport| match transport {
            HostBridgeTransportKind::UnixSocket => "unix-socket",
            HostBridgeTransportKind::NamedPipe => "named-pipe",
            HostBridgeTransportKind::Vsock => "vsock",
            HostBridgeTransportKind::RemoteTunnel => "remote-tunnel",
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn cmd_minipod_inspect(session_id: Option<String>, json: bool) {
    use agentbox_daemon::config;
    use agentbox_daemon::runtime::session::RuntimeSessionStore;

    let config = config::load().unwrap_or_else(|e| {
        eprintln!("error: failed to load Agentbox config: {}", e);
        std::process::exit(1);
    });
    let store = RuntimeSessionStore::new(config.session_store_path);

    if let Some(session_id) = session_id {
        let session = store.get(&session_id).unwrap_or_else(|e| {
            eprintln!("error: failed to read runtime session store: {}", e);
            std::process::exit(1);
        });
        let Some(session) = session else {
            eprintln!("error: minipod session not found: {}", session_id);
            std::process::exit(1);
        };

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&session).expect("failed to serialize session")
            );
        } else {
            print_minipod_session(&session);
        }
        return;
    }

    let sessions = store.list().unwrap_or_else(|e| {
        eprintln!("error: failed to read runtime session store: {}", e);
        std::process::exit(1);
    });

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&sessions).expect("failed to serialize sessions")
        );
        return;
    }

    if sessions.is_empty() {
        println!("No persisted minipod sessions.");
        return;
    }

    println!(
        "{:<28} {:<18} {:<12} {:<10} AGENT",
        "SESSION", "NAME", "PROVIDER", "STATUS"
    );
    println!("{}", "-".repeat(88));
    for session in &sessions {
        println!(
            "{:<28} {:<18} {:<12} {:<10} {}",
            session.id,
            session.name,
            session.provider,
            format!("{:?}", session.status),
            session.spec.agent.name
        );
    }
}

fn cmd_review(session_id: String, json: bool, patch: bool) {
    use agentbox_daemon::audit::AuditStore;
    use agentbox_daemon::config;
    use agentbox_daemon::runtime::manager::RuntimeManager;
    use agentbox_daemon::runtime::registry::RuntimeProviderRegistry;
    use agentbox_daemon::runtime::session::RuntimeSessionStore;

    let config = config::load().unwrap_or_else(|e| {
        eprintln!("error: failed to load Agentbox config: {}", e);
        std::process::exit(1);
    });
    let store = RuntimeSessionStore::new(config.session_store_path.clone());
    let session = store.get(&session_id).unwrap_or_else(|e| {
        eprintln!("error: failed to read runtime session store: {}", e);
        std::process::exit(1);
    });
    let Some(session) = session else {
        eprintln!("error: AgentPod session not found: {}", session_id);
        std::process::exit(1);
    };
    let registry = RuntimeProviderRegistry::with_local_providers(
        socket_path().to_string_lossy().into_owned(),
        find_shim_binary()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
    );
    let provider = registry.get(&session.provider).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to resolve session provider `{}` for review: {}",
            session.provider, e
        );
        std::process::exit(1);
    });
    let manager = RuntimeManager::new(
        provider,
        RuntimeSessionStore::new(config.session_store_path),
        AuditStore::new(&config.db_path).unwrap_or_else(|e| {
            eprintln!("error: failed to open audit store: {}", e);
            std::process::exit(1);
        }),
    );
    let snapshot = manager
        .capture_workspace_diff(&session_id)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to capture workspace review: {}", e);
            std::process::exit(1);
        });

    if patch {
        if !snapshot.available {
            eprintln!(
                "error: workspace diff unavailable ({})",
                snapshot
                    .reason
                    .clone()
                    .unwrap_or_else(|| "unknown reason".to_string())
            );
            std::process::exit(1);
        }
        if let Some(diff_patch) = snapshot.diff_patch.as_deref() {
            println!("{}", diff_patch);
        }
        return;
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&snapshot).expect("failed to serialize workspace review")
        );
        return;
    }

    println!("AgentPod review");
    println!("{}", "-".repeat(64));
    println!("session:   {}", session.id);
    println!("provider:  {}", session.provider);
    println!("risk:      {}", session.spec.risk.label());
    println!("workspace: {}", snapshot.workspace);
    println!("mode:      {}", session.spec.workspace_mode.label());
    if !snapshot.available {
        println!(
            "diff:      unavailable ({})",
            snapshot
                .reason
                .unwrap_or_else(|| "unknown reason".to_string())
        );
        return;
    }
    println!(
        "git head:  {}",
        snapshot.git_head.unwrap_or_else(|| "(unknown)".into())
    );
    println!(
        "diff:      {}",
        snapshot
            .diff_shortstat
            .clone()
            .unwrap_or_else(|| "no unstaged diff".to_string())
    );
    println!(
        "patch:     {}",
        if snapshot.diff_patch.is_some() {
            "available via --patch"
        } else {
            "none"
        }
    );
    if snapshot.changed_files.is_empty() {
        println!("files:     no workspace changes");
    } else {
        println!("files:");
        for file in &snapshot.changed_files {
            println!("  - {}", file);
        }
    }
}

fn cmd_review_discard(session_id: String) {
    let (manager, _session) = runtime_manager_for_session(&session_id, "discard");
    let discard = manager
        .discard_workspace_projection(&session_id)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to discard workspace projection: {}", e);
            std::process::exit(1);
        });

    let Some(discard) = discard else {
        println!(
            "No projected review workspace recorded for session {}.",
            session_id
        );
        return;
    };

    println!("Discarded projected workspace output.");
    println!("session:   {}", session_id);
    println!("projected: {}", discard.projected_host_path.display());
    if let Some(work) = discard.work_host_path {
        println!("work:      {}", work.display());
    }
    if let Some(lower) = discard.lower_host_path {
        println!("lower:     {} (left untouched)", lower.display());
    }
}

fn cmd_review_apply(session_id: String) {
    let (manager, _session) = runtime_manager_for_session(&session_id, "apply");
    let apply = manager
        .apply_workspace_projection(&session_id)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to apply workspace projection: {}", e);
            std::process::exit(1);
        });

    let Some(apply) = apply else {
        println!(
            "No projected workspace patch recorded for session {}.",
            session_id
        );
        return;
    };

    println!("Applied projected workspace output.");
    println!("session:   {}", session_id);
    println!("lower:     {}", apply.lower_host_path.display());
    println!("projected: {}", apply.projected_host_path.display());
    println!("patch:     {} bytes", apply.patch_bytes);
    println!("note:      projected workspace was kept; run review-discard to remove it");
}

fn cmd_review_commit(session_id: String, message: String) {
    let (manager, _session) = runtime_manager_for_session(&session_id, "commit");
    let commit = manager
        .commit_workspace_projection(&session_id, &message)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to commit workspace projection: {}", e);
            std::process::exit(1);
        });

    let Some(commit) = commit else {
        println!(
            "No projected workspace patch recorded for session {}.",
            session_id
        );
        return;
    };

    println!("Committed projected workspace output.");
    println!("session:   {}", session_id);
    println!("lower:     {}", commit.apply.lower_host_path.display());
    println!("commit:    {}", commit.commit_hash);
    println!("message:   {}", commit.message);
    println!("note:      projected workspace was kept; run review-discard to remove it");
}

fn runtime_manager_for_session(
    session_id: &str,
    action: &str,
) -> (
    agentbox_daemon::runtime::manager::RuntimeManager,
    agentbox_daemon::runtime::types::RuntimeSession,
) {
    use agentbox_daemon::audit::AuditStore;
    use agentbox_daemon::config;
    use agentbox_daemon::runtime::manager::RuntimeManager;
    use agentbox_daemon::runtime::registry::RuntimeProviderRegistry;
    use agentbox_daemon::runtime::session::RuntimeSessionStore;

    let config = config::load().unwrap_or_else(|e| {
        eprintln!("error: failed to load Agentbox config: {}", e);
        std::process::exit(1);
    });
    let store = RuntimeSessionStore::new(config.session_store_path.clone());
    let session = store.get(session_id).unwrap_or_else(|e| {
        eprintln!("error: failed to read runtime session store: {}", e);
        std::process::exit(1);
    });
    let Some(session) = session else {
        eprintln!("error: AgentPod session not found: {}", session_id);
        std::process::exit(1);
    };
    let registry = RuntimeProviderRegistry::with_local_providers(
        socket_path().to_string_lossy().into_owned(),
        find_shim_binary()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
    );
    let provider = registry.get(&session.provider).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to resolve session provider `{}` for {}: {}",
            session.provider, action, e
        );
        std::process::exit(1);
    });
    let manager = RuntimeManager::new(
        provider,
        RuntimeSessionStore::new(config.session_store_path),
        AuditStore::new(&config.db_path).unwrap_or_else(|e| {
            eprintln!("error: failed to open audit store: {}", e);
            std::process::exit(1);
        }),
    );
    (manager, session)
}

fn print_minipod_session(session: &agentbox_daemon::runtime::types::RuntimeSession) {
    println!("session:   {}", session.id);
    println!("name:      {}", session.name);
    println!("provider:  {}", session.provider);
    println!("platform:  {}", session.platform);
    println!("status:    {:?}", session.status);
    println!("agent:     {}", session.spec.agent.name);
    println!(
        "workspace: {} -> {}",
        session.spec.filesystem.workspace_host_path.display(),
        session.spec.filesystem.workspace_guest_path
    );
    println!("network:   {:?}", session.spec.network.mode);
    if session.spec.network.allowed_domains.is_empty() {
        println!("domains:   (none)");
    } else {
        println!(
            "domains:   {}",
            session.spec.network.allowed_domains.join(", ")
        );
    }
    println!("started:   {}", session.started_at.to_rfc3339());
    if let Some(stopped_at) = session.stopped_at {
        println!("stopped:   {}", stopped_at.to_rfc3339());
    }
}

fn cmd_minipod_logs(session_id: String, follow: bool, tail: Option<usize>) {
    let raw_id = session_id.strip_prefix("sb-").unwrap_or(&session_id);
    let container = format!("sb-{}-workspace", raw_id);
    let mut args = vec!["logs".to_string()];
    if follow {
        args.push("--follow".to_string());
    }
    if let Some(tail) = tail {
        args.push("--tail".to_string());
        args.push(tail.to_string());
    }
    args.push(container.clone());

    let status = Command::new("podman")
        .args(&args)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to run podman logs: {}", e);
            eprintln!("hint: minipod logs currently require the Podman-backed runtime");
            std::process::exit(1);
        });

    if !status.success() {
        eprintln!("error: podman logs failed for {}", container);
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn ensure_evidence_columns(conn: &Connection) {
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(audit_log)")
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
        })
        .unwrap_or_default();

    if !columns.iter().any(|c| c == "schema_version") {
        let _ = conn.execute_batch(
            "ALTER TABLE audit_log ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;",
        );
    }
    if !columns.iter().any(|c| c == "prev_hash") {
        let _ = conn.execute_batch("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;");
    }
    if !columns.iter().any(|c| c == "event_hash") {
        let _ = conn.execute_batch("ALTER TABLE audit_log ADD COLUMN event_hash TEXT;");
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start => cmd_start(),
        Commands::Setup => cmd_setup(),
        Commands::Stop => cmd_stop(),
        Commands::Status => cmd_status(),
        Commands::Doctor => cmd_doctor(),
        Commands::Audit {
            limit,
            bucket,
            tail,
        } => cmd_audit(limit, bucket, tail),
        Commands::Install => cmd_install(),
        Commands::Allow { domain } => cmd_allow(domain),
        Commands::NetworkExplain {
            url,
            mode,
            allow_domains,
            deny_domains,
            deny_localhost,
        } => cmd_network_explain(url, mode, allow_domains, deny_domains, deny_localhost),
        Commands::NetworkGrant {
            session_id,
            domain,
            reason,
        } => cmd_network_grant(session_id, domain, reason),
        Commands::Credentials { session_id, json } => cmd_credentials(session_id, json),
        Commands::CredentialRevoke { session_id, name } => cmd_credential_revoke(session_id, name),
        Commands::Run {
            command,
            runtime,
            agent_profile,
            risk,
            provider,
            plan,
            services,
            mount_cwd,
            workspace_mode,
            workspace_overlay_dir,
            memory,
            read_only_mounts,
            credential_files,
            credential_env,
            credential_sockets,
            credential_tokens,
            credential_ttl_seconds,
            policy_bundles,
            allow_domains,
            network_mode,
            deny_domains,
            deny_localhost,
        } => {
            cmd_run(RunOptions {
                command,
                runtime,
                agent_profile,
                risk,
                provider,
                plan,
                services,
                mount_cwd,
                workspace_mode,
                workspace_overlay_dir,
                memory,
                read_only_mounts,
                credential_files,
                credential_env,
                credential_sockets,
                credential_tokens,
                credential_ttl_seconds,
                policy_bundles,
                allow_domains,
                network_mode,
                deny_domains,
                deny_localhost,
            })
            .await
        }
        Commands::StopPod { pod_id } => cmd_stop_pod(pod_id).await,
        Commands::Pods => cmd_pods().await,
        Commands::Why => cmd_why(),
        Commands::Policy => cmd_policy(),
        Commands::PolicySimulate { command } => cmd_policy_simulate(command),
        Commands::PolicyExplain { command } => cmd_policy_explain(command),
        Commands::History { all, bucket, json } => cmd_history(all, bucket, json),
        Commands::Evidence {
            limit,
            verify,
            session,
            credentials,
            network,
        } => cmd_evidence(limit, verify, session, credentials, network),
        Commands::MinipodSpec {
            agent,
            workspace,
            agent_profile,
            risk,
            provider,
            allow_domains,
            network_mode,
            read_only_mounts,
            credential_files,
            credential_env,
            credential_sockets,
            credential_tokens,
            credential_ttl_seconds,
            policy_bundles,
            workspace_mode,
            workspace_overlay_dir,
            deny_domains,
            deny_localhost,
        } => cmd_minipod_spec(MinipodSpecOptions {
            agent,
            workspace,
            agent_profile,
            risk,
            provider,
            allow_domains,
            read_only_mounts,
            credential_files,
            credential_env,
            credential_sockets,
            credential_tokens,
            credential_ttl_seconds,
            policy_bundles,
            network_mode,
            deny_domains,
            deny_localhost,
            workspace_mode,
            workspace_overlay_dir,
        }),
        Commands::Providers { json } => cmd_providers(json),
        Commands::RemoteDescriptor {
            endpoint,
            auth,
            evidence,
        } => cmd_remote_descriptor(endpoint, auth, evidence),
        Commands::RemoteHandshake {
            endpoint,
            auth,
            ttl_seconds,
        } => cmd_remote_handshake(endpoint, auth, ttl_seconds),
        Commands::MinipodInspect { session_id, json } => cmd_minipod_inspect(session_id, json),
        Commands::Review {
            session_id,
            json,
            patch,
        } => cmd_review(session_id, json, patch),
        Commands::ReviewDiscard { session_id } => cmd_review_discard(session_id),
        Commands::ReviewApply { session_id } => cmd_review_apply(session_id),
        Commands::ReviewCommit {
            session_id,
            message,
        } => cmd_review_commit(session_id, message),
        Commands::MinipodLogs {
            session_id,
            follow,
            tail,
        } => cmd_minipod_logs(session_id, follow, tail),
    }
}
