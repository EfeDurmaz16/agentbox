use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use agentbox_policy::classify::{
    Bucket, Classification, CommandContext, PolicyConfig, PolicyNetworkMode,
};
use chrono::{NaiveDateTime, Utc};
use clap::{Parser, Subcommand};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REMOTE_LABEL_ENDPOINT: &str = "agentbox.remote.endpoint";
const REMOTE_LABEL_WORKER_SESSION: &str = "agentbox.remote.worker_session";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReviewJsonOutput {
    #[serde(flatten)]
    snapshot: agentbox_daemon::runtime::workspace::WorkspaceDiffSnapshot,
    action_plan: ReviewActionPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReviewActionPlan {
    schema_version: i64,
    session_id: String,
    actions: Vec<ReviewAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReviewAction {
    key: &'static str,
    id: &'static str,
    label: &'static str,
    command: String,
    mutates_workspace: bool,
    requires_message: bool,
    description: &'static str,
}

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
    /// Remove stale daemon pid and socket files
    Clean,
    /// Initialize local config, directories, and command shims
    Setup {
        /// Emit JSON
        #[arg(long)]
        json: bool,

        /// Print a guided setup wizard with ordered next steps
        #[arg(long)]
        wizard: bool,

        /// Show what setup would do without changing host state
        #[arg(long)]
        dry_run: bool,

        /// Limit setup actions to one provider: direct-host, podman, agentpod-macos, agentpod-linux, agentpod-windows, or remote-agentpod
        #[arg(long)]
        provider: Option<String>,

        /// Remote AgentPod worker endpoint to include in setup guidance
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Stop the daemon
    Stop,
    /// Show daemon status
    Status,
    /// Run local readiness checks for daemon, shims, policy, audit, and minipods
    Doctor {
        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Print the next local setup actions without changing the host
    SetupPlan {
        /// Emit JSON
        #[arg(long)]
        json: bool,

        /// Limit setup actions to one provider: direct-host, podman, agentpod-macos, agentpod-linux, agentpod-windows, or remote-agentpod
        #[arg(long)]
        provider: Option<String>,
    },
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

        /// Runtime provider: auto, podman, agentpod-macos, agentpod-linux, agentpod-windows, remote-agentpod
        #[arg(long = "provider", default_value = "auto")]
        provider: String,

        /// Print the AgentPod run plan without starting a backend
        #[arg(long = "plan")]
        plan: bool,

        /// Emit machine-readable JSON for session/run output
        #[arg(long)]
        json: bool,

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
    /// List persisted AgentPod sessions
    Pods {
        /// Emit JSON
        #[arg(long)]
        json: bool,

        /// Refresh the session list until interrupted
        #[arg(long)]
        watch: bool,

        /// Watch refresh interval in seconds
        #[arg(long = "interval-seconds", default_value_t = 2)]
        interval_seconds: u64,

        /// Filter by provider
        #[arg(long)]
        provider: Option<String>,

        /// Filter by status substring, e.g. running, stopped, failed
        #[arg(long)]
        status: Option<String>,
    },
    /// List persisted AgentPod sessions
    Sessions {
        /// Emit JSON
        #[arg(long)]
        json: bool,

        /// Refresh the session list until interrupted
        #[arg(long)]
        watch: bool,

        /// Watch refresh interval in seconds
        #[arg(long = "interval-seconds", default_value_t = 2)]
        interval_seconds: u64,

        /// Filter by provider
        #[arg(long)]
        provider: Option<String>,

        /// Filter by status substring, e.g. running, stopped, failed
        #[arg(long)]
        status: Option<String>,
    },
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

        /// Write a session evidence bundle directory instead of printing JSON
        #[arg(long = "bundle")]
        bundle_dir: Option<PathBuf>,
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
    /// Inspect provider host-bridge capability health without starting a session
    BridgeHealth {
        /// Emit JSON
        #[arg(long)]
        json: bool,

        /// Limit health output to one provider
        #[arg(long)]
        provider: Option<String>,
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
    /// Generate remote AgentPod evidence upload metadata without uploading it
    RemoteEvidence {
        /// Agentbox session id
        #[arg(long = "session")]
        session_id: String,

        /// Worker-side session id
        #[arg(long = "worker-session")]
        worker_session_id: String,

        /// Evidence mode: append-only-stream, bundle-upload, local-pull
        #[arg(long = "evidence", default_value = "bundle-upload")]
        evidence: String,

        /// SHA-256 hex digest of the sealed evidence bundle
        #[arg(long = "bundle-sha256")]
        bundle_sha256: Option<String>,

        /// Number of evidence events in the sealed bundle
        #[arg(long = "event-count")]
        event_count: Option<u64>,

        /// Read bundle root hash and event count from a verified evidence bundle directory
        #[arg(long = "bundle-dir")]
        bundle_dir: Option<PathBuf>,
    },
    /// Query a remote AgentPod worker for accepted evidence state
    RemoteEvidenceStatus {
        /// Remote worker endpoint, e.g. https://worker.example.com/agentpod; omitted values are read from the local session when possible
        #[arg(long)]
        endpoint: Option<String>,

        /// Agentbox session id
        #[arg(long = "session")]
        session_id: String,

        /// Worker-side session id; omitted values are read from the local session when possible
        #[arg(long = "worker-session")]
        worker_session_id: Option<String>,
    },
    /// Upload a verified evidence bundle directory to a remote AgentPod worker
    RemoteEvidenceUpload {
        /// Remote worker endpoint, e.g. https://worker.example.com/agentpod; omitted values are read from the local session when possible
        #[arg(long)]
        endpoint: Option<String>,

        /// Agentbox session id
        #[arg(long = "session")]
        session_id: String,

        /// Worker-side session id; omitted values are read from the local session when possible
        #[arg(long = "worker-session")]
        worker_session_id: Option<String>,

        /// Verified evidence bundle directory produced by `agentbox evidence --bundle`
        #[arg(long = "bundle-dir")]
        bundle_dir: PathBuf,
    },
    /// Upload UTF-8 evidence stream chunks to a remote AgentPod worker
    RemoteEvidenceStream {
        /// Remote worker endpoint, e.g. https://worker.example.com/agentpod; omitted values are read from the local session when possible
        #[arg(long)]
        endpoint: Option<String>,

        /// Agentbox session id
        #[arg(long = "session")]
        session_id: String,

        /// Worker-side session id; omitted values are read from the local session when possible
        #[arg(long = "worker-session")]
        worker_session_id: Option<String>,

        /// Evidence stream id, e.g. stdout, stderr, events
        #[arg(long = "stream", default_value = "stdout")]
        stream_id: String,

        /// UTF-8 file to stream
        #[arg(long = "file")]
        file: PathBuf,

        /// Maximum bytes per chunk
        #[arg(long = "chunk-bytes", default_value_t = 65536)]
        chunk_bytes: usize,
    },
    /// Grant a pending remote AgentPod command approval
    RemoteApprovalGrant {
        /// Remote worker endpoint, e.g. https://worker.example.com/agentpod; omitted values are read from the local session when possible
        #[arg(long)]
        endpoint: Option<String>,

        /// Agentbox session id
        #[arg(long = "session")]
        session_id: String,

        /// Worker-side session id; omitted values are read from the local session when possible
        #[arg(long = "worker-session")]
        worker_session_id: Option<String>,

        /// Pending approval request id from remote-evidence-status
        #[arg(long = "request")]
        request_id: String,

        /// Optional grant reason
        #[arg(long, default_value = "operator approved pending remote command")]
        reason: String,

        /// Optional grant expiry in seconds
        #[arg(long = "ttl-seconds")]
        ttl_seconds: Option<i64>,
    },
    /// Export a remote AgentPod worker workspace into a local review directory
    RemoteWorkspaceExport {
        /// Remote worker endpoint, e.g. https://worker.example.com/agentpod; omitted values are read from the local session when possible
        #[arg(long)]
        endpoint: Option<String>,

        /// Agentbox session id
        #[arg(long = "session")]
        session_id: String,

        /// Worker-side session id; omitted values are read from the local session when possible
        #[arg(long = "worker-session")]
        worker_session_id: Option<String>,

        /// Local directory where exported workspace files should be written
        #[arg(long = "output-dir")]
        output_dir: PathBuf,

        /// Allow writing into an existing empty output directory
        #[arg(long)]
        force: bool,

        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Apply a pulled remote AgentPod workspace export to a local workspace
    RemoteWorkspaceApply {
        /// Directory produced by `agentbox remote-workspace-export`
        #[arg(long = "export-dir")]
        export_dir: PathBuf,

        /// Local workspace directory to write into
        #[arg(long)]
        workspace: PathBuf,

        /// Preview files and conflicts without writing
        #[arg(long)]
        dry_run: bool,

        /// Overwrite existing target files
        #[arg(long)]
        force: bool,

        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Generate a native provider execution plan without running it
    NativePlan {
        /// Native provider: auto, agentpod-linux, agentpod-macos, or agentpod-windows
        #[arg(long = "provider", default_value = "auto")]
        provider: String,

        /// Workspace directory for the AgentPod plan
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Agent policy profile (general, coding, research, deploy, or custom)
        #[arg(long = "agent-profile", default_value = "general")]
        agent_profile: String,

        /// AgentPod task risk: low, medium, high, very-high
        #[arg(long = "risk", default_value = "medium")]
        risk: String,

        /// Command to plan; use `--` before command flags
        command: Vec<String>,
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

        /// Print a keyboard-style review command menu after the summary
        #[arg(long)]
        tui: bool,
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

fn stale_daemon_files_present() -> bool {
    read_pid().is_some_and(|pid| !process_alive(pid))
        || (socket_path().exists() && read_pid().is_none())
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

fn cmd_clean() {
    let stale = stale_daemon_files_present();
    cleanup_stale_daemon_files();
    if socket_path().exists() && read_pid().is_none() {
        let _ = fs::remove_file(socket_path());
    }
    if stale {
        println!("cleaned stale daemon pid/socket files");
    } else {
        println!("no stale daemon pid/socket files found");
    }
}

fn cmd_setup(
    json: bool,
    wizard: bool,
    dry_run: bool,
    provider: Option<String>,
    endpoint: Option<String>,
) {
    use agentbox_daemon::config;

    let provider_filter = provider.as_deref().map(normalize_setup_provider_filter);
    let remote_endpoint = setup_remote_endpoint(provider_filter.as_deref(), endpoint.as_deref());
    let mut actions = Vec::new();
    let mut config_summary = None;
    let mut shim_summary = None;

    if dry_run {
        actions.push(SetupAction {
            name: "initialize config".to_string(),
            status: "planned".to_string(),
            detail: format!("create or validate {}", config_path().display()),
        });
        if setup_should_install_shims(provider_filter.as_deref()) {
            actions.push(SetupAction {
                name: "install shims".to_string(),
                status: "planned".to_string(),
                detail: format!("link guarded commands into {}", shims_dir().display()),
            });
        }
    } else {
        ensure_dir(&agentbox_dir());
        let config = config::load().unwrap_or_else(|e| {
            eprintln!("error: failed to initialize Agentbox config: {}", e);
            std::process::exit(1);
        });
        config_summary = Some(SetupConfigSummary {
            config_path: config_path().display().to_string(),
            db_path: config.db_path.clone(),
            socket_path: config.socket_path.clone(),
        });
        actions.push(SetupAction {
            name: "initialize config".to_string(),
            status: "completed".to_string(),
            detail: format!("created or validated {}", config_path().display()),
        });

        if setup_should_install_shims(provider_filter.as_deref()) {
            let install = install_shims().unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
            actions.push(SetupAction {
                name: "install shims".to_string(),
                status: "completed".to_string(),
                detail: format!(
                    "installed {} guarded command shims into {}",
                    install.created,
                    install.shims_dir.display()
                ),
            });
            shim_summary = Some(install.into_summary());
        } else {
            actions.push(SetupAction {
                name: "install shims".to_string(),
                status: "skipped".to_string(),
                detail: "provider setup does not require direct-host command shims".to_string(),
            });
        }
    }

    let report = build_doctor_report();
    let plan = setup_plan_from_doctor(&report, provider_filter.as_deref());
    let operator_commands = setup_operator_commands(
        &plan,
        provider_filter.as_deref(),
        remote_endpoint.as_deref(),
    );
    let wizard_steps = setup_wizard_steps(
        &plan,
        &operator_commands,
        provider_filter.as_deref(),
        dry_run,
        remote_endpoint.as_deref(),
    );
    let setup_report = SetupReport {
        schema_version: 1,
        platform: std::env::consts::OS.to_string(),
        provider: provider_filter.clone(),
        dry_run,
        wizard,
        actions,
        config: config_summary,
        shims: shim_summary,
        remote_endpoint,
        operator_commands,
        setup_plan: plan,
        wizard_steps,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&setup_report).expect("failed to serialize setup report")
        );
        return;
    }

    println!("Agentbox setup");
    println!("{}", "-".repeat(64));
    if let Some(provider) = &setup_report.provider {
        println!("provider: {}", provider);
    }
    if setup_report.dry_run {
        println!("mode:     dry-run");
    }
    if setup_report.wizard {
        println!("wizard:   guided");
    }
    if let Some(config) = &setup_report.config {
        println!("config:   {}", config.config_path);
        println!("audit:    {}", config.db_path);
        println!("socket:   {}", config.socket_path);
    } else {
        println!("config:   {}", config_path().display());
    }
    if let Some(endpoint) = &setup_report.remote_endpoint {
        println!("endpoint: {endpoint}");
    }
    println!();
    for action in &setup_report.actions {
        println!("{}: {}", action.status, action.detail);
    }
    if !setup_report.operator_commands.is_empty() {
        println!();
        println!("Operator commands:");
        for command in &setup_report.operator_commands {
            println!("  {command}");
        }
    }
    if setup_report.wizard {
        println!();
        println!("Wizard:");
        for step in &setup_report.wizard_steps {
            println!("  {}. [{}] {}", step.step, step.status, step.title);
            println!("     {}", step.detail);
            if let Some(command) = &step.command {
                println!("     command: {command}");
            }
        }
    }
    println!();
    println!("Next:");
    println!("  export PATH=\"{}:$PATH\"", shims_dir().display());
    println!("  agentbox start");
    println!("  agentbox doctor");
    if setup_report.setup_plan.failed > 0 {
        println!("  agentbox setup-plan");
    }
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
    if let Some(socket_state) = daemon_socket_status_line(sock.exists(), running) {
        println!("socket state: {}", socket_state);
        if !running {
            println!("hint:    run `agentbox clean && agentbox start`");
        }
    }

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

fn daemon_socket_status_line(socket_exists: bool, daemon_running: bool) -> Option<&'static str> {
    match (socket_exists, daemon_running) {
        (true, true) => Some("ready"),
        (true, false) => Some("stale socket file"),
        (false, true) => Some("missing while daemon appears to be running"),
        (false, false) => None,
    }
}

fn cmd_doctor(json: bool) {
    let report = build_doctor_report();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("failed to serialize doctor report")
        );
        if report.required_failed > 0 {
            std::process::exit(1);
        }
        return;
    }

    println!("Agentbox doctor");
    println!("{}", "-".repeat(64));

    for check in &report.checks {
        let marker = match (check.ok, check.required) {
            (true, _) => "ok",
            (false, true) => "fail",
            (false, false) => "warn",
        };
        println!(
            "{:<6} {:<24} {:<8} {}",
            marker, check.name, check.severity, check.detail
        );
        if !check.ok {
            println!("       fix: {}", check.fix);
        }
    }

    println!("{}", "-".repeat(64));
    println!(
        "summary: {} ok, {} required failed, {} advisory failed",
        report.ok, report.required_failed, report.advisory_failed
    );

    if report.required_failed > 0 {
        std::process::exit(1);
    }
}

fn cmd_setup_plan(json: bool, provider: Option<String>) {
    let report = build_doctor_report();
    let plan = setup_plan_from_doctor(&report, provider.as_deref());

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan).expect("failed to serialize setup plan")
        );
        return;
    }

    println!("Agentbox setup plan");
    println!("{}", "-".repeat(64));
    if let Some(provider) = &plan.provider {
        println!("provider:  {provider}");
    }
    println!(
        "readiness: {} ok, {} required failed, {} advisory failed",
        plan.ok, plan.required_failed, plan.advisory_failed
    );
    if let Some(command) = &plan.next_command {
        println!("next:      {command}");
    } else {
        println!("next:      no required setup action");
    }
    println!("{}", "-".repeat(64));

    if plan.steps.is_empty() {
        println!("All required setup checks passed.");
        if plan.advisory_failed > 0 {
            println!("Advisory provider prerequisites are still listed in `agentbox doctor`.");
        }
        return;
    }

    for (index, step) in plan.steps.iter().enumerate() {
        println!("{}. [{}] {}", index + 1, step.severity, step.title);
        println!("   check:  {}", step.check);
        println!("   detail: {}", step.detail);
        println!("   action: {}", step.action);
        if let Some(command) = &step.command {
            println!("   run:    {command}");
        }
    }
}

fn build_doctor_report() -> DoctorReport {
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

    checks.push(daemon_socket_doctor_check(
        socket_path().exists(),
        daemon_running,
        format!("{}", socket_path().display()),
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
    checks.extend(remote_agentpod_doctor_checks());
    if cfg!(target_os = "macos") {
        let machine = podman_machine_status();
        checks.push(doctor_check(
            "podman machine",
            machine.ok,
            machine.detail,
            machine.fix,
        ));
        checks.extend(macos_native_doctor_checks());
    }
    if cfg!(target_os = "linux") {
        checks.extend(linux_native_doctor_checks());
    }
    if cfg!(target_os = "windows") {
        checks.extend(windows_native_doctor_checks());
    }

    doctor_report(checks)
}

#[derive(Serialize)]
struct DoctorReport {
    schema_version: i64,
    platform: String,
    ok: usize,
    failed: usize,
    required_failed: usize,
    advisory_failed: usize,
    checks: Vec<DoctorCheck>,
}

fn doctor_report(checks: Vec<DoctorCheck>) -> DoctorReport {
    let failed = checks.iter().filter(|check| !check.ok).count();
    let required_failed = checks
        .iter()
        .filter(|check| !check.ok && check.required)
        .count();
    let advisory_failed = failed - required_failed;
    DoctorReport {
        schema_version: 1,
        platform: std::env::consts::OS.to_string(),
        ok: checks.len() - failed,
        failed,
        required_failed,
        advisory_failed,
        checks,
    }
}

#[derive(Clone, Serialize)]
struct DoctorCheck {
    name: &'static str,
    ok: bool,
    severity: &'static str,
    required: bool,
    release_blocker: bool,
    detail: String,
    fix: &'static str,
}

fn doctor_check(name: &'static str, ok: bool, detail: String, fix: &'static str) -> DoctorCheck {
    DoctorCheck {
        name,
        ok,
        severity: "required",
        required: true,
        release_blocker: !ok,
        detail,
        fix,
    }
}

fn daemon_socket_doctor_check(
    socket_exists: bool,
    daemon_running: bool,
    socket_path: String,
) -> DoctorCheck {
    match (socket_exists, daemon_running) {
        (true, true) => doctor_check("daemon socket", true, socket_path, "none"),
        (true, false) => doctor_check(
            "daemon socket",
            false,
            format!("stale socket at {socket_path}; daemon process is not running"),
            "run `agentbox clean` or remove the stale socket, then run `agentbox start`",
        ),
        (false, true) => doctor_check(
            "daemon socket",
            false,
            format!("missing socket at {socket_path}; daemon process appears to be running"),
            "run `agentbox restart` to recreate the daemon socket",
        ),
        (false, false) => doctor_check(
            "daemon socket",
            false,
            format!("missing socket at {socket_path}"),
            "run `agentbox start`",
        ),
    }
}

fn doctor_advisory_check(
    name: &'static str,
    ok: bool,
    detail: String,
    fix: &'static str,
) -> DoctorCheck {
    DoctorCheck {
        name,
        ok,
        severity: "advisory",
        required: false,
        release_blocker: false,
        detail,
        fix,
    }
}

#[derive(Serialize)]
struct SetupPlan {
    schema_version: i64,
    platform: String,
    provider: Option<String>,
    ok: usize,
    failed: usize,
    required_failed: usize,
    advisory_failed: usize,
    ready_for_required_setup: bool,
    next_command: Option<String>,
    steps: Vec<SetupPlanStep>,
}

#[derive(Serialize)]
struct SetupPlanStep {
    check: String,
    title: String,
    severity: String,
    required: bool,
    release_blocker: bool,
    detail: String,
    action: String,
    command: Option<String>,
}

#[derive(Serialize)]
struct SetupReport {
    schema_version: i64,
    platform: String,
    provider: Option<String>,
    dry_run: bool,
    wizard: bool,
    actions: Vec<SetupAction>,
    config: Option<SetupConfigSummary>,
    shims: Option<SetupShimSummary>,
    remote_endpoint: Option<String>,
    operator_commands: Vec<String>,
    setup_plan: SetupPlan,
    wizard_steps: Vec<SetupWizardStep>,
}

#[derive(Serialize)]
struct SetupAction {
    name: String,
    status: String,
    detail: String,
}

#[derive(Serialize)]
struct SetupConfigSummary {
    config_path: String,
    db_path: String,
    socket_path: String,
}

#[derive(Serialize)]
struct SetupShimSummary {
    shims_dir: String,
    shim_binary: String,
    created: usize,
    skipped: usize,
}

#[derive(Serialize)]
struct SetupWizardStep {
    step: usize,
    title: String,
    status: String,
    detail: String,
    command: Option<String>,
}

fn setup_plan_from_doctor(report: &DoctorReport, provider: Option<&str>) -> SetupPlan {
    let provider_filter = provider.map(normalize_setup_provider_filter);
    let checks = if let Some(provider_filter) = provider_filter.as_deref() {
        if provider_filter == "all" {
            report.checks.clone()
        } else {
            filter_doctor_checks_for_provider(&report.checks, provider_filter)
        }
    } else {
        report.checks.clone()
    };
    let filtered_report = doctor_report(checks);
    let mut steps = filtered_report
        .checks
        .iter()
        .filter(|check| !check.ok)
        .map(setup_plan_step_from_check)
        .collect::<Vec<_>>();
    steps.sort_by_key(|step| (!step.required, step.check.clone()));
    let next_command = steps
        .iter()
        .find(|step| step.required)
        .and_then(|step| step.command.clone());

    SetupPlan {
        schema_version: 1,
        platform: report.platform.clone(),
        provider: provider_filter,
        ok: filtered_report.ok,
        failed: filtered_report.failed,
        required_failed: filtered_report.required_failed,
        advisory_failed: filtered_report.advisory_failed,
        ready_for_required_setup: filtered_report.required_failed == 0,
        next_command,
        steps,
    }
}

fn setup_should_install_shims(provider: Option<&str>) -> bool {
    matches!(provider, None | Some("all") | Some("direct-host"))
}

fn setup_remote_endpoint(provider: Option<&str>, endpoint: Option<&str>) -> Option<String> {
    let endpoint = endpoint?.trim();
    if !matches!(provider, Some("remote-agentpod")) {
        eprintln!("error: --endpoint is only valid with --provider remote-agentpod");
        std::process::exit(2);
    }
    let loopback_allowed = std::env::var("AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let (ok, detail) = remote_agentpod_endpoint_status(endpoint, loopback_allowed);
    if !ok {
        eprintln!("error: invalid remote AgentPod endpoint: {detail}");
        std::process::exit(2);
    }
    Some(endpoint.to_string())
}

fn setup_operator_commands(
    plan: &SetupPlan,
    provider: Option<&str>,
    remote_endpoint: Option<&str>,
) -> Vec<String> {
    let mut commands = plan
        .steps
        .iter()
        .filter_map(|step| step.command.clone())
        .collect::<Vec<_>>();
    commands.push(match provider.unwrap_or("all") {
        "all" => "agentbox bridge-health".to_string(),
        provider => format!("agentbox bridge-health --provider {provider}"),
    });
    if let Some(endpoint) = remote_endpoint {
        commands
            .retain(|command| !command.starts_with("export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT="));
        commands.push(format!(
            "export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT={endpoint}"
        ));
        commands.push(format!("agentbox remote-handshake --endpoint {endpoint}"));
    }
    commands.sort();
    commands.dedup();
    commands
}

fn setup_wizard_steps(
    plan: &SetupPlan,
    operator_commands: &[String],
    provider: Option<&str>,
    dry_run: bool,
    remote_endpoint: Option<&str>,
) -> Vec<SetupWizardStep> {
    let provider = provider.unwrap_or("all");
    let mut steps = Vec::new();
    push_setup_wizard_step(
        &mut steps,
        "Prepare Agentbox binaries",
        if setup_plan_has_check(plan, "agentbox-daemon binary")
            || setup_plan_has_check(plan, "agentbox-shim binary")
        {
            "required"
        } else {
            "ready"
        },
        "Build the CLI, daemon, and shim before installing or starting local governance.",
        Some("cargo build --release"),
    );

    if matches!(provider, "all" | "direct-host") {
        push_setup_wizard_step(
            &mut steps,
            "Install local command shims",
            if setup_plan_has_check(plan, "installed shims") {
                "required"
            } else if dry_run {
                "planned"
            } else {
                "ready"
            },
            "Create guarded command links in ~/.agentbox/shims without silently editing shell startup files.",
            Some("agentbox setup --provider direct-host"),
        );
        push_setup_wizard_step(
            &mut steps,
            "Put Agentbox first on PATH",
            if setup_plan_has_check(plan, "shim PATH priority") {
                "required"
            } else {
                "ready"
            },
            "Export the shim directory first so terminal agents hit the policy boundary before host commands.",
            Some("export PATH=\"$HOME/.agentbox/shims:$PATH\""),
        );
        push_setup_wizard_step(
            &mut steps,
            "Start the local daemon",
            if setup_plan_has_check(plan, "daemon process")
                || setup_plan_has_check(plan, "daemon socket")
            {
                "required"
            } else {
                "ready"
            },
            "Run the local policy, approval, and audit daemon used by the shims and direct-host provider.",
            Some("agentbox start"),
        );
    }

    if matches!(provider, "all" | "podman") {
        push_setup_wizard_step(
            &mut steps,
            "Prepare Podman compatibility provider",
            if setup_plan_has_check(plan, "podman provider")
                || setup_plan_has_check(plan, "podman machine")
            {
                "optional"
            } else {
                "ready"
            },
            "Install and start Podman only if you want the compatibility backend; this is not native AgentPod execution.",
            Some("podman machine init && podman machine start"),
        );
    }

    if matches!(provider, "all" | "remote-agentpod") {
        let command = remote_endpoint
            .map(|endpoint| format!("export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT={endpoint}"))
            .or_else(|| {
                operator_commands
                    .iter()
                    .find(|command| {
                        command.starts_with("export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=")
                    })
                    .cloned()
            })
            .unwrap_or_else(|| {
                "export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://worker.example.com/agentpod"
                    .to_string()
            });
        push_setup_wizard_step(
            &mut steps,
            "Attach a remote AgentPod worker",
            if setup_plan_has_check(plan, "remote-agentpod endpoint") {
                "optional"
            } else {
                "ready"
            },
            "Configure a HTTPS worker endpoint before using remote-agentpod; loopback HTTP requires the explicit dev gate.",
            Some(command),
        );
    }

    if matches!(
        provider,
        "all" | "agentpod-macos" | "agentpod-linux" | "agentpod-windows"
    ) {
        let native_command = match provider {
            "agentpod-linux" => "agentbox native-plan --provider agentpod-linux -- <cmd>",
            "agentpod-windows" => "agentbox native-plan --provider agentpod-windows -- <cmd>",
            _ => "agentbox native-plan --provider agentpod-macos -- <cmd>",
        };
        push_setup_wizard_step(
            &mut steps,
            "Inspect native AgentPod plan",
            "prototype",
            "Native providers are descriptor/prototype surfaces until platform-specific execution and denial tests land.",
            Some(native_command),
        );
    }

    push_setup_wizard_step(
        &mut steps,
        "Inspect provider bridge readiness",
        "info",
        "Check which provider bridge capabilities are active, supported, gated, or metadata-only before running autonomous work.",
        Some(match provider {
            "all" => "agentbox bridge-health".to_string(),
            provider => format!("agentbox bridge-health --provider {provider}"),
        }),
    );

    push_setup_wizard_step(
        &mut steps,
        "Verify readiness",
        if plan.required_failed == 0 {
            "ready"
        } else {
            "required"
        },
        "Run doctor after each setup step; required failures block the shipped direct-host path and advisory failures track optional providers.",
        Some("agentbox doctor"),
    );

    steps
}

fn setup_plan_has_check(plan: &SetupPlan, check_name: &str) -> bool {
    plan.steps.iter().any(|step| step.check == check_name)
}

fn push_setup_wizard_step(
    steps: &mut Vec<SetupWizardStep>,
    title: &str,
    status: &str,
    detail: &str,
    command: Option<impl Into<String>>,
) {
    steps.push(SetupWizardStep {
        step: steps.len() + 1,
        title: title.to_string(),
        status: status.to_string(),
        detail: detail.to_string(),
        command: command.map(Into::into),
    });
}

fn normalize_setup_provider_filter(provider: &str) -> String {
    let provider = provider.trim().to_ascii_lowercase();
    match provider.as_str() {
        "" | "auto" | "all" => "all".to_string(),
        "direct" | "host" | "direct-host" => "direct-host".to_string(),
        "podman" | "compat" => "podman".to_string(),
        "remote" | "remote-agentpod" => "remote-agentpod".to_string(),
        "macos" | "agentpod-macos" => "agentpod-macos".to_string(),
        "linux" | "agentpod-linux" => "agentpod-linux".to_string(),
        "windows" | "agentpod-windows" => "agentpod-windows".to_string(),
        other => {
            eprintln!("error: unsupported --provider value `{}`", other);
            eprintln!(
                "hint: expected direct-host, podman, agentpod-macos, agentpod-linux, agentpod-windows, or remote-agentpod"
            );
            std::process::exit(1);
        }
    }
}

fn filter_doctor_checks_for_provider(checks: &[DoctorCheck], provider: &str) -> Vec<DoctorCheck> {
    let names = setup_provider_check_names(provider);
    checks
        .iter()
        .filter(|check| names.contains(&check.name))
        .cloned()
        .collect()
}

fn setup_provider_check_names(provider: &str) -> &'static [&'static str] {
    match provider {
        "all" => &[],
        "direct-host" => &[
            "agentbox directory",
            "config file",
            "daemon process",
            "daemon socket",
            "agentbox-daemon binary",
            "agentbox-shim binary",
            "installed shims",
            "shim PATH priority",
            "audit database",
        ],
        "podman" => &["podman provider", "podman machine"],
        "remote-agentpod" => &["remote-agentpod endpoint"],
        "agentpod-macos" => &[
            "macOS native plan",
            "Apple Virtualization",
            "Endpoint Security entitlement",
            "Network Extension entitlement",
        ],
        "agentpod-linux" => &[
            "Linux native plan",
            "Linux user namespace",
            "Linux cgroups v2",
            "Linux seccomp",
            "Linux Landlock ABI",
        ],
        "agentpod-windows" => &[
            "Windows native plan",
            "Windows Job Objects",
            "Windows AppContainer",
            "Windows WFP",
            "Windows ETW",
            "Windows VM boundary",
        ],
        _ => &[],
    }
}

fn setup_plan_step_from_check(check: &DoctorCheck) -> SetupPlanStep {
    SetupPlanStep {
        check: check.name.to_string(),
        title: setup_step_title(check.name).to_string(),
        severity: check.severity.to_string(),
        required: check.required,
        release_blocker: check.release_blocker,
        detail: check.detail.clone(),
        action: check.fix.to_string(),
        command: setup_command_for_doctor_check(check),
    }
}

fn setup_command_for_doctor_check(check: &DoctorCheck) -> Option<String> {
    if check.name == "daemon socket" && check.detail.contains("stale socket") {
        return Some("agentbox clean && agentbox start".to_string());
    }
    setup_command_for_check(check.name).map(str::to_string)
}

fn setup_step_title(check_name: &str) -> &'static str {
    match check_name {
        "agentbox directory" | "config file" => "Initialize Agentbox local state",
        "daemon process" | "daemon socket" => "Start the Agentbox daemon",
        "agentbox-daemon binary" | "agentbox-shim binary" => "Build Agentbox binaries",
        "installed shims" => "Install command shims",
        "shim PATH priority" => "Put Agentbox shims first in PATH",
        "audit database" => "Create audit state",
        "podman provider" => "Install the compatibility provider",
        "podman machine" => "Start the Podman machine",
        "remote-agentpod endpoint" => "Configure a remote AgentPod worker",
        "macOS native plan" | "Linux native plan" | "Windows native plan" => {
            "Inspect native AgentPod plan"
        }
        "Apple Virtualization" => "Enable VM-backed macOS planning prerequisites",
        "Endpoint Security entitlement" => "Prepare macOS Endpoint Security signing",
        "Network Extension entitlement" => "Prepare macOS Network Extension signing",
        "Linux user namespace" => "Enable Linux user namespaces",
        "Linux cgroups v2" => "Enable Linux cgroups v2",
        "Linux seccomp" => "Enable Linux seccomp",
        "Linux Landlock ABI" => "Enable Linux Landlock",
        "Windows Job Objects" => "Wire Windows Job Object containment",
        "Windows AppContainer" => "Model Windows AppContainer authority",
        "Windows WFP" => "Model Windows network filtering",
        "Windows ETW" => "Model Windows event evidence",
        "Windows VM boundary" => "Plan Windows VM-backed AgentPods",
        _ => "Resolve readiness check",
    }
}

fn setup_command_for_check(check_name: &str) -> Option<&'static str> {
    match check_name {
        "agentbox directory" | "config file" | "daemon process" | "daemon socket"
        | "audit database" => Some("agentbox start"),
        "agentbox-daemon binary" | "agentbox-shim binary" => Some("cargo build --release"),
        "installed shims" => Some("agentbox install"),
        "shim PATH priority" => Some("export PATH=\"$HOME/.agentbox/shims:$PATH\""),
        "podman machine" => Some("podman machine init && podman machine start"),
        "remote-agentpod endpoint" => {
            Some("export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://worker.example.com/agentpod")
        }
        "macOS native plan" => Some("agentbox native-plan --provider agentpod-macos -- <cmd>"),
        "Linux native plan" => Some("agentbox native-plan --provider agentpod-linux -- <cmd>"),
        "Windows native plan" => Some("agentbox native-plan --provider agentpod-windows -- <cmd>"),
        _ => None,
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

fn remote_agentpod_doctor_checks() -> Vec<DoctorCheck> {
    let endpoint = std::env::var("AGENTBOX_REMOTE_AGENTPOD_ENDPOINT").unwrap_or_default();
    let loopback_allowed = remote_agentpod_loopback_http_allowed();
    let (ok, detail) = remote_agentpod_endpoint_status(&endpoint, loopback_allowed);

    vec![doctor_advisory_check(
        "remote-agentpod endpoint",
        ok,
        detail,
        "set AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://worker.example.com/agentpod; use AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 only for local worker smoke tests",
    )]
}

fn remote_agentpod_loopback_http_allowed() -> bool {
    matches!(
        std::env::var("AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

fn remote_agentpod_endpoint_status(endpoint: &str, allow_http_loopback: bool) -> (bool, String) {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return (
            false,
            "AGENTBOX_REMOTE_AGENTPOD_ENDPOINT is not set".to_string(),
        );
    }
    if endpoint.contains('@') && !endpoint.starts_with("ssh://") {
        return (
            false,
            "endpoint must not embed credentials outside ssh://".to_string(),
        );
    }
    if endpoint.starts_with("http://") {
        if allow_http_loopback && is_remote_loopback_http_endpoint(endpoint) {
            return (true, format!("{endpoint} (loopback HTTP dev mode)"));
        }
        return (
            false,
            "http:// is allowed only for loopback workers with AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1".to_string(),
        );
    }
    if endpoint.starts_with("https://") || endpoint.starts_with("ssh://") {
        return (true, endpoint.to_string());
    }
    (false, "endpoint must use https:// or ssh://".to_string())
}

fn is_remote_loopback_http_endpoint(endpoint: &str) -> bool {
    let Some(authority) = endpoint.strip_prefix("http://") else {
        return false;
    };
    let host = authority
        .split('/')
        .next()
        .unwrap_or_default()
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = if host.starts_with('[') {
        host.split(']').next().unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or_default()
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
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

fn macos_native_doctor_checks() -> Vec<DoctorCheck> {
    let virtualization_framework =
        Path::new("/System/Library/Frameworks/Virtualization.framework").exists();
    vec![
        doctor_advisory_check(
            "macOS native plan",
            true,
            "compiler available; provider execution remains unavailable".to_string(),
            "no action needed for planning; native execution still needs runner wiring",
        ),
        doctor_advisory_check(
            "Apple Virtualization",
            virtualization_framework,
            "/System/Library/Frameworks/Virtualization.framework".to_string(),
            "use macOS 11+ with Apple Virtualization framework available",
        ),
        doctor_advisory_check(
            "Endpoint Security entitlement",
            current_executable_has_entitlement("com.apple.developer.endpoint-security.client"),
            current_executable_entitlement_detail("com.apple.developer.endpoint-security.client"),
            "sign the future system extension with the Endpoint Security entitlement",
        ),
        doctor_advisory_check(
            "Network Extension entitlement",
            current_executable_has_entitlement("com.apple.developer.networking.networkextension"),
            current_executable_entitlement_detail(
                "com.apple.developer.networking.networkextension",
            ),
            "sign the future network extension with the required Network Extension entitlement",
        ),
    ]
}

fn linux_native_doctor_checks() -> Vec<DoctorCheck> {
    vec![
        doctor_advisory_check(
            "Linux native plan",
            true,
            "compiler available; gated prototype execution requires AGENTBOX_LINUX_NATIVE=1"
                .to_string(),
            "inspect with `agentbox native-plan --provider agentpod-linux -- <cmd>`",
        ),
        doctor_advisory_check(
            "Linux user namespace",
            linux_user_namespace_available(),
            linux_user_namespace_detail(),
            "enable unprivileged user namespaces or run on a kernel/distribution that supports them",
        ),
        doctor_advisory_check(
            "Linux cgroups v2",
            Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            "/sys/fs/cgroup/cgroup.controllers".to_string(),
            "boot with cgroup v2 enabled",
        ),
        doctor_advisory_check(
            "Linux seccomp",
            Path::new("/proc/sys/kernel/seccomp/actions_avail").exists(),
            fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")
                .map(|contents| contents.trim().to_string())
                .unwrap_or_else(|_| "seccomp actions file not readable".to_string()),
            "use a kernel with seccomp enabled",
        ),
        doctor_advisory_check(
            "Linux Landlock ABI",
            linux_landlock_abi_version().is_some(),
            linux_landlock_abi_version()
                .map(|version| format!("ABI version {version}"))
                .unwrap_or_else(|| "not available or blocked by kernel policy".to_string()),
            "use Linux 5.13+ with Landlock enabled",
        ),
    ]
}

fn linux_user_namespace_available() -> bool {
    Path::new("/proc/self/ns/user").exists()
        && fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            .map(|value| value.trim() != "0")
            .unwrap_or(true)
}

fn linux_user_namespace_detail() -> String {
    let ns = if Path::new("/proc/self/ns/user").exists() {
        "present"
    } else {
        "missing"
    };
    let clone = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|value| format!("unprivileged_userns_clone={}", value.trim()))
        .unwrap_or_else(|_| "unprivileged_userns_clone=unknown".to_string());
    format!("namespace={ns}; {clone}")
}

#[cfg(target_os = "linux")]
fn linux_landlock_abi_version() -> Option<i64> {
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32,
        )
    };
    (abi >= 0).then_some(abi)
}

#[cfg(not(target_os = "linux"))]
fn linux_landlock_abi_version() -> Option<i64> {
    None
}

fn windows_native_doctor_checks() -> Vec<DoctorCheck> {
    vec![
        doctor_advisory_check(
            "Windows native plan",
            true,
            "Job Object plan compiler available; provider execution remains unavailable"
                .to_string(),
            "inspect docs/windows-native-provider.md before enabling Windows execution",
        ),
        doctor_advisory_check(
            "Windows Job Objects",
            true,
            "plan/controller modeled; Win32 apply path is not wired".to_string(),
            "wire and live-test Job Object process containment before enabling execution",
        ),
        doctor_advisory_check(
            "Windows AppContainer",
            false,
            "planned authority boundary; descriptor and live tests are not implemented".to_string(),
            "add AppContainer descriptor plus Windows live containment tests",
        ),
        doctor_advisory_check(
            "Windows WFP",
            false,
            "planned network boundary; no packet/domain denial proof yet".to_string(),
            "add WFP integration only with live network denial tests",
        ),
        doctor_advisory_check(
            "Windows ETW",
            false,
            "planned evidence boundary; event capture is not wired".to_string(),
            "add ETW session/event capture linked to Agentbox session ids",
        ),
        doctor_advisory_check(
            "Windows VM boundary",
            false,
            "Windows Sandbox/Hyper-V remain planned for higher-risk cells".to_string(),
            "add a VM-backed provider only after lifecycle and evidence proof",
        ),
    ]
}

fn current_executable_has_entitlement(entitlement: &str) -> bool {
    current_executable_entitlements()
        .as_deref()
        .is_some_and(|entitlements| entitlements_contain_key(entitlements, entitlement))
}

fn current_executable_entitlement_detail(entitlement: &str) -> String {
    match current_executable_entitlements() {
        Some(entitlements) if entitlements_contain_key(&entitlements, entitlement) => {
            format!("{entitlement} present on current executable")
        }
        Some(_) => format!("{entitlement} not present on current executable"),
        None => "codesign entitlements unavailable for current executable".to_string(),
    }
}

fn current_executable_entitlements() -> Option<String> {
    let executable = std::env::current_exe().ok()?;
    let output = Command::new("codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(executable)
        .output()
        .ok()?;
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    if combined.trim().is_empty() {
        None
    } else {
        Some(combined)
    }
}

fn entitlements_contain_key(entitlements: &str, entitlement: &str) -> bool {
    entitlements.contains(&format!("<key>{entitlement}</key>"))
        || entitlements
            .lines()
            .any(|line| line.trim() == entitlement || line.trim().starts_with(entitlement))
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

struct ShimInstallReport {
    shims_dir: PathBuf,
    shim_binary: PathBuf,
    created: usize,
    skipped: usize,
}

impl ShimInstallReport {
    fn into_summary(self) -> SetupShimSummary {
        SetupShimSummary {
            shims_dir: self.shims_dir.display().to_string(),
            shim_binary: self.shim_binary.display().to_string(),
            created: self.created,
            skipped: self.skipped,
        }
    }
}

fn install_shims() -> Result<ShimInstallReport, String> {
    let shims = shims_dir();
    ensure_dir(&shims);

    let shim_binary = find_shim_binary().ok_or_else(|| {
        "error: agentbox-shim binary not found\nhint: run `cargo build -p agentbox-shim` first"
            .to_string()
    })?;

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

    Ok(ShimInstallReport {
        shims_dir: shims,
        shim_binary,
        created,
        skipped,
    })
}

fn cmd_install() {
    let report = install_shims().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    println!(
        "installed {} shims ({} skipped)",
        report.created, report.skipped
    );
    println!();
    println!("Add this to your shell profile (~/.zshrc or ~/.bashrc):");
    println!();
    println!("  export PATH=\"{}:$PATH\"", report.shims_dir.display());
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
    json: bool,
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

#[derive(Serialize)]
struct RunPlanPreview {
    schema_version: i64,
    command: Vec<String>,
    selected_provider: RunPlanProvider,
    candidates: Vec<RunPlanCandidate>,
    manifest: agentbox_daemon::runtime::types::MinipodSpec,
    backend_actions: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct RunPlanProvider {
    name: String,
    family: String,
    platform: String,
    status: String,
    selection_reason: String,
    bridge_transports: Vec<String>,
    boundary_primitives: Vec<String>,
    boundary_primitive_statuses: Vec<RunPlanBoundaryPrimitiveStatus>,
    capabilities: Vec<String>,
    network_enforcement: Vec<String>,
    availability_check: String,
}

#[derive(Serialize)]
struct RunPlanBoundaryPrimitiveStatus {
    primitive: String,
    status: String,
    active: bool,
    requires_gate: Option<String>,
    enforcement_scope: String,
}

#[derive(Serialize)]
struct RunPlanCandidate {
    name: String,
    family: String,
    status: String,
}

#[derive(Serialize)]
struct RunJsonOutput {
    schema_version: i64,
    session: agentbox_daemon::runtime::types::RuntimeSession,
    command_result: Option<agentbox_daemon::runtime::types::CommandResult>,
    destroyed: bool,
    cleanup_error: Option<String>,
    cleanup_command: Option<String>,
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
    let workspace_mode_risk = spec.risk.clone();
    apply_workspace_mode(
        &mut spec,
        &workspace_mode_risk,
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
        let selected_provider = registry
            .get(&selection.selected_provider)
            .unwrap_or_else(|e| {
                eprintln!("Error: failed to resolve runtime provider: {}", e);
                std::process::exit(1);
            });
        let mut backend_actions = vec![
            "validate AgentPod manifest".to_string(),
            "materialize workspace projection when requested".to_string(),
            "create runtime session through selected provider".to_string(),
            "execute command through RuntimeManager policy checks".to_string(),
            "record hash-chained runtime evidence".to_string(),
        ];
        if selection.selected_provider == "podman" {
            backend_actions.insert(
                0,
                "check Podman availability and start compatibility VM if required".to_string(),
            );
        }

        let mut warnings = vec![
            "plan output does not start a backend, create a session, hydrate credentials, or run the command"
                .to_string(),
        ];
        if selection.selected_provider != "podman" {
            warnings.push(format!(
                "{} is not generally runnable in this build; execution may require a platform gate or future provider wiring",
                selection.selected_provider
            ));
        }
        if !selected_provider
            .network_enforcement_capabilities()
            .is_empty()
        {
            warnings.push("provider reports active network enforcement metadata".to_string());
        } else {
            warnings.push(
                "network policy is command-mediated unless the selected provider reports enforcement"
                    .to_string(),
            );
        }

        let preview = RunPlanPreview {
            schema_version: 1,
            command: spec.agent.command.clone(),
            selected_provider: RunPlanProvider {
                name: selected_provider.name().to_string(),
                family: format!("{:?}", selected_provider.family()),
                platform: selected_provider.platform().to_string(),
                status: format!("{:?}", selected_provider.implementation_status()),
                selection_reason: selection.reason.clone(),
                bridge_transports: selected_provider
                    .bridge_transport_kinds()
                    .iter()
                    .map(|transport| format!("{transport:?}"))
                    .collect(),
                boundary_primitives: selected_provider
                    .boundary_primitives()
                    .iter()
                    .map(|primitive| (*primitive).to_string())
                    .collect(),
                boundary_primitive_statuses: selected_provider
                    .boundary_primitive_statuses()
                    .into_iter()
                    .map(|primitive| RunPlanBoundaryPrimitiveStatus {
                        primitive: primitive.primitive.to_string(),
                        status: format_provider_status(primitive.status).to_string(),
                        active: primitive.active,
                        requires_gate: primitive.requires_gate.map(str::to_string),
                        enforcement_scope: primitive.enforcement_scope.to_string(),
                    })
                    .collect(),
                capabilities: selected_provider
                    .capabilities()
                    .iter()
                    .map(|capability| format!("{capability:?}"))
                    .collect(),
                network_enforcement: selected_provider
                    .network_enforcement_capabilities()
                    .iter()
                    .map(|capability| format!("{capability:?}"))
                    .collect(),
                availability_check: "not performed by --plan".to_string(),
            },
            candidates: selection
                .candidates
                .iter()
                .map(|candidate| RunPlanCandidate {
                    name: candidate.name.clone(),
                    family: candidate.family.clone(),
                    status: candidate.status.clone(),
                })
                .collect(),
            manifest: spec,
            backend_actions,
            warnings,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&preview).expect("failed to serialize AgentPod run plan")
        );
        return;
    }

    if selection.selected_provider != "podman" {
        let selected_provider = registry
            .get(&selection.selected_provider)
            .unwrap_or_else(|e| {
                eprintln!("Error: failed to resolve runtime provider: {}", e);
                std::process::exit(1);
            });
        if selection.selected_provider == "agentpod-linux" && selected_provider.is_available().await
        {
            eprintln!(
                "warning: using gated agentpod-linux prototype execution; this is not a complete sandbox"
            );
        } else if selection.selected_provider == "remote-agentpod"
            && selected_provider.is_available().await
        {
            eprintln!(
                "warning: using experimental remote-agentpod execution; worker-side sandboxing is not complete"
            );
        } else {
            eprintln!(
                "Error: provider `{}` is not runnable in this build yet.",
                selection.selected_provider
            );
            eprintln!("reason: {}", selection.reason);
            if selection.selected_provider == "agentpod-linux" {
                eprintln!(
                "hint: inspect the native prototype plan with `agentbox native-plan --provider agentpod-linux -- <cmd>`"
            );
                eprintln!(
                "hint: Linux prototype execution runs through `agentbox run` only on Linux with AGENTBOX_LINUX_NATIVE=1"
            );
            } else if selection.selected_provider == "remote-agentpod" {
                eprintln!(
                    "hint: set AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://... for a production worker"
                );
                eprintln!(
                    "hint: loopback HTTP workers require AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1"
                );
            } else {
                eprintln!("hint: use `--provider podman` for the current compatibility backend");
            }
            std::process::exit(1);
        }
    }

    if selection.selected_provider == "podman" {
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
    if !options.json {
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

        if selection.selected_provider == "podman" {
            println!("  Agentbox: socket + shims injected");
        } else {
            println!("  Agentbox: native prototype executor");
        }
    }

    let session = match manager.create(&spec).await {
        Ok(session) => {
            if !options.json {
                println!("Minipod {} created and running.", session.name);
            }
            session
        }
        Err(e) => {
            eprintln!("Error: failed to create minipod: {}", e);
            std::process::exit(1);
        }
    };

    // 6. If command was provided, run it
    if !options.command.is_empty() {
        if !options.json {
            println!();
            println!("Running: {}", options.command.join(" "));
            println!("--- output ---");
        }

        let exec_req = ExecCommand {
            argv: options.command.clone(),
            working_dir: Some("/workspace".to_string()),
            env: HashMap::new(),
            timeout_seconds: None,
        };

        match manager.exec(&session.id, &exec_req).await {
            Ok(result) => {
                if options.json {
                    let cleanup_error = manager
                        .destroy(&session.id)
                        .await
                        .err()
                        .map(|e| e.to_string());
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&RunJsonOutput {
                            schema_version: 1,
                            session: session.clone(),
                            command_result: Some(result.clone()),
                            destroyed: cleanup_error.is_none(),
                            cleanup_error,
                            cleanup_command: Some(format!("agentbox stop-pod {}", session.id)),
                        })
                        .expect("failed to serialize run JSON output")
                    );
                } else {
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
        if options.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&RunJsonOutput {
                    schema_version: 1,
                    session: session.clone(),
                    command_result: None,
                    destroyed: false,
                    cleanup_error: None,
                    cleanup_command: Some(format!("agentbox stop-pod {}", session.id)),
                })
                .expect("failed to serialize run JSON output")
            );
            return;
        }
        // 7. No command: print interactive instructions
        println!();
        println!("Minipod session running.");
        println!("  Session id: {}", session.id);
        if selection.selected_provider == "podman" {
            println!("  Backend container: sb-{}-workspace", session.id);
            println!(
                "  Debug shell: podman exec -it sb-{}-workspace bash",
                session.id
            );
        }
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

async fn cmd_pods(
    json: bool,
    watch: bool,
    interval_seconds: u64,
    provider: Option<String>,
    status: Option<String>,
) {
    use agentbox_daemon::config;
    use agentbox_daemon::runtime::session::RuntimeSessionStore;

    if watch && json {
        eprintln!("error: --watch cannot be combined with --json");
        std::process::exit(2);
    }
    if watch && interval_seconds == 0 {
        eprintln!("error: --interval-seconds must be greater than zero");
        std::process::exit(2);
    }

    let config = config::load().unwrap_or_else(|e| {
        eprintln!("error: failed to load Agentbox config: {}", e);
        std::process::exit(1);
    });
    let store = RuntimeSessionStore::new(config.session_store_path);

    loop {
        let sessions = store.list().unwrap_or_else(|e| {
            eprintln!("error: failed to read runtime session store: {}", e);
            std::process::exit(1);
        });
        let sessions = filter_pod_sessions(sessions, provider.as_deref(), status.as_deref());

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&sessions).expect("failed to serialize sessions")
            );
            return;
        }

        print_pod_sessions(&sessions);
        if !watch {
            return;
        }
        thread::sleep(Duration::from_secs(interval_seconds));
        println!();
    }
}

fn print_pod_sessions(sessions: &[agentbox_daemon::runtime::types::RuntimeSession]) {
    if sessions.is_empty() {
        println!("No persisted AgentPod sessions.");
        return;
    }
    println!(
        "{:<28} {:<18} {:<12} {:<10} {:<12} AGENT",
        "SESSION", "NAME", "PROVIDER", "STATUS", "RISK"
    );
    println!("{}", "-".repeat(104));

    for session in sessions {
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

fn filter_pod_sessions(
    sessions: Vec<agentbox_daemon::runtime::types::RuntimeSession>,
    provider: Option<&str>,
    status: Option<&str>,
) -> Vec<agentbox_daemon::runtime::types::RuntimeSession> {
    let provider = provider.map(|value| value.trim().to_ascii_lowercase());
    let status = status.map(|value| value.trim().to_ascii_lowercase());
    sessions
        .into_iter()
        .filter(|session| {
            provider
                .as_deref()
                .is_none_or(|provider| session.provider.to_ascii_lowercase() == provider)
        })
        .filter(|session| {
            status.as_deref().is_none_or(|status| {
                format!("{:?}", session.status)
                    .to_ascii_lowercase()
                    .contains(status)
            })
        })
        .collect()
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

fn evidence_legacy_skip_suffix(skipped_legacy_events: usize) -> String {
    if skipped_legacy_events == 0 {
        String::new()
    } else {
        format!(", {skipped_legacy_events} legacy events skipped")
    }
}

fn cmd_evidence(
    limit: usize,
    verify: bool,
    session: Option<String>,
    credentials: bool,
    network: bool,
    bundle_dir: Option<PathBuf>,
) {
    if bundle_dir.is_some() && (credentials || network) {
        eprintln!("error: --bundle cannot be combined with --credentials or --network");
        std::process::exit(1);
    }
    if let Some(bundle_dir) = bundle_dir.as_deref() {
        if verify {
            cmd_verify_evidence_bundle_dir(bundle_dir);
            return;
        }
    }

    let db_path = audit_db_path();
    if !db_path.exists() {
        eprintln!("no audit log found at {}", db_path.display());
        eprintln!("hint: start the daemon first with `agentbox start`");
        std::process::exit(1);
    }

    if let Some(bundle_dir) = bundle_dir {
        let Some(session_id) = session else {
            eprintln!("error: --bundle requires --session <id>");
            std::process::exit(1);
        };
        cmd_session_evidence_bundle_dir(&db_path, &session_id, limit, &bundle_dir);
        return;
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
                "evidence hash chain: valid ({} events checked{})",
                verification.checked_events,
                evidence_legacy_skip_suffix(verification.skipped_legacy_events)
            );
            return;
        }

        eprintln!(
            "evidence hash chain: invalid ({} events checked{}, {} violations)",
            verification.checked_events,
            evidence_legacy_skip_suffix(verification.skipped_legacy_events),
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
    let conn = Connection::open(db_path).expect("failed to open audit db");
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

fn cmd_session_evidence_bundle_dir(
    db_path: &PathBuf,
    session_id: &str,
    limit: usize,
    output_dir: &Path,
) {
    let bundle = load_session_evidence_bundle(db_path, session_id, limit);
    write_session_evidence_bundle_dir(&bundle, output_dir).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to write evidence bundle to {}: {}",
            output_dir.display(),
            e
        );
        std::process::exit(1);
    });
    println!(
        "wrote evidence bundle {} to {}",
        bundle.bundle_id,
        output_dir.display()
    );
}

#[derive(Debug, Serialize, Deserialize)]
struct EvidenceBundleIndex {
    schema_version: i64,
    bundle_id: String,
    session_id: String,
    provider: String,
    status: String,
    root_sha256: String,
    generated_at: chrono::DateTime<Utc>,
    files: Vec<EvidenceBundleFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EvidenceBundleFile {
    path: String,
    media_type: String,
    description: String,
    sha256: String,
    bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct RemoteWorkspaceExportManifest {
    schema_version: i64,
    session_id: String,
    worker_session_id: String,
    status: String,
    output_dir: String,
    manifest_path: String,
    root_sha256: String,
    file_count: usize,
    total_bytes: usize,
    files: Vec<RemoteWorkspaceExportFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RemoteWorkspaceExportFile {
    path: String,
    media_type: String,
    sha256: String,
    bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct RemoteWorkspaceApplyReport {
    schema_version: i64,
    session_id: String,
    worker_session_id: String,
    export_dir: String,
    workspace: String,
    dry_run: bool,
    force: bool,
    applied_files: usize,
    skipped_files: usize,
    unchanged_files: usize,
    conflict_files: usize,
    total_bytes: usize,
    files: Vec<RemoteWorkspaceApplyFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RemoteWorkspaceApplyFile {
    path: String,
    bytes: usize,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_sha256: Option<String>,
    action: String,
}

fn write_session_evidence_bundle_dir(
    bundle: &agentbox_daemon::runtime::types::SessionEvidenceBundle,
    output_dir: &Path,
) -> io::Result<()> {
    fs::create_dir_all(output_dir)?;
    let files = vec![
        write_bundle_json_file(
            output_dir,
            "bundle.json",
            "Full redacted AgentPod session evidence bundle",
            bundle,
        )?,
        write_bundle_json_file(
            output_dir,
            "manifest.json",
            "AgentPod manifest captured for this session",
            &bundle.manifest,
        )?,
        write_bundle_json_file(
            output_dir,
            "replay.json",
            "Metadata-only replay plan and limitations",
            &bundle.replay,
        )?,
        write_bundle_json_file(
            output_dir,
            "transcripts.json",
            "Redacted command transcripts captured by RuntimeManager",
            &bundle.transcripts,
        )?,
        write_bundle_json_file(
            output_dir,
            "integrations.json",
            "Descriptor-only FIDES, AGIT, and OAPS integration metadata",
            &bundle.integration_descriptors,
        )?,
    ];

    let index = EvidenceBundleIndex {
        schema_version: 1,
        bundle_id: bundle.bundle_id.clone(),
        session_id: bundle.session_id.clone(),
        provider: bundle.provider.clone(),
        status: format!("{:?}", bundle.status),
        root_sha256: evidence_bundle_root_sha256(&files),
        generated_at: bundle.generated_at,
        files,
    };
    fs::write(
        output_dir.join("index.json"),
        serde_json::to_vec_pretty(&index).expect("failed to serialize evidence bundle index"),
    )?;
    Ok(())
}

fn write_bundle_json_file<T: Serialize>(
    output_dir: &Path,
    path: &str,
    description: &str,
    value: &T,
) -> io::Result<EvidenceBundleFile> {
    let bytes = serde_json::to_vec_pretty(value).expect("failed to serialize evidence bundle file");
    fs::write(output_dir.join(path), &bytes)?;
    Ok(EvidenceBundleFile {
        path: path.to_string(),
        media_type: "application/json".to_string(),
        description: description.to_string(),
        sha256: sha256_hex(&bytes),
        bytes: bytes.len(),
    })
}

fn cmd_verify_evidence_bundle_dir(bundle_dir: &Path) {
    match verify_evidence_bundle_dir(bundle_dir) {
        Ok(verified_files) => {
            println!(
                "evidence bundle: valid ({} files checked) at {}",
                verified_files,
                bundle_dir.display()
            );
        }
        Err(e) => {
            eprintln!(
                "evidence bundle: invalid at {}: {}",
                bundle_dir.display(),
                e
            );
            std::process::exit(1);
        }
    }
}

fn verify_evidence_bundle_dir(bundle_dir: &Path) -> Result<usize, String> {
    let index = read_evidence_bundle_index(bundle_dir)?;
    if index.schema_version != 1 {
        return Err(format!(
            "unsupported evidence bundle index schema version {}",
            index.schema_version
        ));
    }
    if index.files.is_empty() {
        return Err("evidence bundle index does not list any files".to_string());
    }
    let actual_root_sha256 = evidence_bundle_root_sha256(&index.files);
    if index.root_sha256 != actual_root_sha256 {
        return Err(format!(
            "bundle root sha256 mismatch: expected {}, got {}",
            index.root_sha256, actual_root_sha256
        ));
    }

    for file in &index.files {
        let relative_path = safe_bundle_relative_path(&file.path)?;
        let path = bundle_dir.join(relative_path);
        let bytes =
            fs::read(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if bytes.len() != file.bytes {
            return Err(format!(
                "{} byte count mismatch: expected {}, got {}",
                file.path,
                file.bytes,
                bytes.len()
            ));
        }
        let actual_sha256 = sha256_hex(&bytes);
        if actual_sha256 != file.sha256 {
            return Err(format!(
                "{} sha256 mismatch: expected {}, got {}",
                file.path, file.sha256, actual_sha256
            ));
        }
    }

    Ok(index.files.len())
}

fn read_evidence_bundle_index(bundle_dir: &Path) -> Result<EvidenceBundleIndex, String> {
    let index_path = bundle_dir.join("index.json");
    let index_bytes = fs::read(&index_path)
        .map_err(|e| format!("failed to read {}: {e}", index_path.display()))?;
    serde_json::from_slice(&index_bytes)
        .map_err(|e| format!("failed to parse {}: {e}", index_path.display()))
}

struct RemoteEvidenceBundleMetadata {
    bundle_id: String,
    root_sha256: String,
    event_count: u64,
}

#[derive(Debug)]
struct RemoteEvidenceBundleUploadPayload {
    bundle_id: String,
    root_sha256: String,
    event_count: u64,
    envelope_json: String,
    envelope_sha256: String,
}

fn load_remote_evidence_metadata_from_bundle(
    bundle_dir: &Path,
) -> Result<RemoteEvidenceBundleMetadata, String> {
    verify_evidence_bundle_dir(bundle_dir)?;
    let index = read_evidence_bundle_index(bundle_dir)?;
    let bundle_path = bundle_dir.join("bundle.json");
    let bundle_bytes = fs::read(&bundle_path)
        .map_err(|e| format!("failed to read {}: {e}", bundle_path.display()))?;
    let bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| format!("failed to parse {}: {e}", bundle_path.display()))?;
    let event_count = [
        "lifecycle_events",
        "approvals",
        "commands",
        "boundary_events",
        "credential_events",
    ]
    .iter()
    .map(|key| {
        bundle
            .get(*key)
            .and_then(|value| value.as_array())
            .map(|events| events.len() as u64)
            .unwrap_or(0)
    })
    .sum::<u64>();
    if event_count == 0 {
        return Err("evidence bundle does not contain any uploadable evidence events".to_string());
    }
    Ok(RemoteEvidenceBundleMetadata {
        bundle_id: index.bundle_id,
        root_sha256: index.root_sha256,
        event_count,
    })
}

fn build_remote_evidence_bundle_upload_payload(
    bundle_dir: &Path,
    session_id: &str,
    worker_session_id: &str,
) -> Result<RemoteEvidenceBundleUploadPayload, String> {
    let metadata = load_remote_evidence_metadata_from_bundle(bundle_dir)?;
    let index = read_evidence_bundle_index(bundle_dir)?;
    if index.session_id != session_id {
        return Err(format!(
            "bundle session id {} does not match requested session {}",
            index.session_id, session_id
        ));
    }
    let mut files = serde_json::Map::new();
    for file in &index.files {
        let path = safe_bundle_relative_path(&file.path)?;
        let bytes = fs::read(bundle_dir.join(path))
            .map_err(|e| format!("failed to read bundle file {}: {e}", file.path))?;
        let contents = String::from_utf8(bytes)
            .map_err(|_| format!("bundle file {} is not valid UTF-8 JSON text", file.path))?;
        files.insert(file.path.clone(), serde_json::Value::String(contents));
    }
    let envelope = serde_json::json!({
        "schema_version": 1,
        "kind": "AgentboxEvidenceBundleUpload",
        "session_id": session_id,
        "worker_session_id": worker_session_id,
        "index": index,
        "files": files,
    });
    let envelope_json = serde_json::to_string(&envelope)
        .map_err(|e| format!("failed to serialize evidence upload envelope: {e}"))?;
    let envelope_sha256 = sha256_hex(envelope_json.as_bytes());
    Ok(RemoteEvidenceBundleUploadPayload {
        bundle_id: metadata.bundle_id,
        root_sha256: metadata.root_sha256,
        event_count: metadata.event_count,
        envelope_json,
        envelope_sha256,
    })
}

fn write_remote_workspace_export_dir(
    response: &agentbox_daemon::runtime::providers::remote::RemoteAgentPodWorkspaceExportResponse,
    output_dir: &Path,
    force: bool,
) -> Result<RemoteWorkspaceExportManifest, String> {
    response
        .workspace_bundle
        .validate()
        .map_err(|e| format!("remote workspace bundle validation failed: {e}"))?;
    prepare_remote_workspace_output_dir(output_dir, force)?;

    let mut manifest_files = Vec::with_capacity(response.workspace_bundle.files.len());
    let mut total_bytes = 0_usize;
    for file in &response.workspace_bundle.files {
        let relative_path = safe_bundle_relative_path(&file.path)?;
        let destination = output_dir.join(&relative_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
        fs::write(&destination, file.contents_utf8.as_bytes())
            .map_err(|e| format!("failed to write {}: {e}", destination.display()))?;
        total_bytes += file.bytes;
        manifest_files.push(RemoteWorkspaceExportFile {
            path: file.path.clone(),
            media_type: file.media_type.clone(),
            sha256: file.sha256.clone(),
            bytes: file.bytes,
        });
    }

    let manifest_path = output_dir.join("agentbox-workspace-export.json");
    let manifest = RemoteWorkspaceExportManifest {
        schema_version: 1,
        session_id: response.session_id.clone(),
        worker_session_id: response.worker_session_id.clone(),
        status: format!("{:?}", response.status),
        output_dir: output_dir.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        root_sha256: response.workspace_bundle.root_sha256.clone(),
        file_count: manifest_files.len(),
        total_bytes,
        files: manifest_files,
    };
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest)
            .map_err(|e| format!("failed to serialize workspace export manifest: {e}"))?,
    )
    .map_err(|e| format!("failed to write {}: {e}", manifest_path.display()))?;
    Ok(manifest)
}

fn prepare_remote_workspace_output_dir(output_dir: &Path, force: bool) -> Result<(), String> {
    if output_dir.exists() {
        if !output_dir.is_dir() {
            return Err("output path exists and is not a directory".to_string());
        }
        let is_empty = fs::read_dir(output_dir)
            .map_err(|e| format!("failed to inspect {}: {e}", output_dir.display()))?
            .next()
            .is_none();
        if !is_empty {
            return Err(
                "output directory already exists and is not empty; choose a new directory"
                    .to_string(),
            );
        }
        if !force {
            return Err(
                "output directory already exists; pass --force to use an existing empty directory"
                    .to_string(),
            );
        }
        return Ok(());
    }
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create {}: {e}", output_dir.display()))
}

fn apply_remote_workspace_export_dir(
    export_dir: &Path,
    workspace: &Path,
    dry_run: bool,
    force: bool,
) -> Result<RemoteWorkspaceApplyReport, String> {
    let manifest = read_remote_workspace_export_manifest(export_dir)?;
    verify_remote_workspace_export_dir(export_dir, &manifest)?;
    if workspace.exists() && !workspace.is_dir() {
        return Err("workspace path exists and is not a directory".to_string());
    }

    let mut files = Vec::with_capacity(manifest.files.len());
    let mut conflict_files = 0_usize;
    let mut unchanged_files = 0_usize;
    for file in &manifest.files {
        let relative_path = safe_bundle_relative_path(&file.path)?;
        let target_path = workspace.join(relative_path);
        let target_metadata = remote_workspace_target_metadata(&target_path)?;
        let target_exists = target_metadata.is_some();
        let target_matches_export = target_metadata
            .as_ref()
            .map(|metadata| metadata.bytes == file.bytes && metadata.sha256 == file.sha256)
            .unwrap_or(false);
        let action = if target_matches_export {
            unchanged_files += 1;
            "unchanged"
        } else if target_exists && !force {
            conflict_files += 1;
            "conflict"
        } else if dry_run && target_exists {
            "would-overwrite"
        } else if dry_run {
            "would-write"
        } else if target_exists {
            "overwritten"
        } else {
            "written"
        };
        files.push(RemoteWorkspaceApplyFile {
            path: file.path.clone(),
            bytes: file.bytes,
            sha256: file.sha256.clone(),
            target_bytes: target_metadata.as_ref().map(|metadata| metadata.bytes),
            target_sha256: target_metadata.map(|metadata| metadata.sha256),
            action: action.to_string(),
        });
    }

    if conflict_files > 0 && !dry_run {
        return Err(format!(
            "{conflict_files} target file(s) already exist; rerun with --force to overwrite"
        ));
    }

    let mut applied_files = 0_usize;
    let mut skipped_files = 0_usize;
    if !dry_run {
        fs::create_dir_all(workspace)
            .map_err(|e| format!("failed to create {}: {e}", workspace.display()))?;
        for file in &manifest.files {
            let relative_path = safe_bundle_relative_path(&file.path)?;
            let source_path = export_dir.join(&relative_path);
            let target_path = workspace.join(&relative_path);
            let target_matches_export = remote_workspace_target_metadata(&target_path)?
                .map(|metadata| metadata.bytes == file.bytes && metadata.sha256 == file.sha256)
                .unwrap_or(false);
            if target_matches_export {
                skipped_files += 1;
                continue;
            }
            if target_path.exists() && !force {
                skipped_files += 1;
                continue;
            }
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
            }
            fs::copy(&source_path, &target_path).map_err(|e| {
                format!(
                    "failed to copy {} to {}: {e}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
            applied_files += 1;
        }
    }

    Ok(RemoteWorkspaceApplyReport {
        schema_version: 1,
        session_id: manifest.session_id,
        worker_session_id: manifest.worker_session_id,
        export_dir: export_dir.display().to_string(),
        workspace: workspace.display().to_string(),
        dry_run,
        force,
        applied_files,
        skipped_files,
        unchanged_files,
        conflict_files,
        total_bytes: manifest.total_bytes,
        files,
    })
}

struct RemoteWorkspaceTargetMetadata {
    bytes: usize,
    sha256: String,
}

fn remote_workspace_target_metadata(
    target_path: &Path,
) -> Result<Option<RemoteWorkspaceTargetMetadata>, String> {
    if !target_path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(target_path)
        .map_err(|e| format!("failed to read target {}: {e}", target_path.display()))?;
    Ok(Some(RemoteWorkspaceTargetMetadata {
        bytes: bytes.len(),
        sha256: sha256_hex(&bytes),
    }))
}

fn read_remote_workspace_export_manifest(
    export_dir: &Path,
) -> Result<RemoteWorkspaceExportManifest, String> {
    let manifest_path = export_dir.join("agentbox-workspace-export.json");
    let bytes = fs::read(&manifest_path)
        .map_err(|e| format!("failed to read {}: {e}", manifest_path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse {}: {e}", manifest_path.display()))
}

fn verify_remote_workspace_export_dir(
    export_dir: &Path,
    manifest: &RemoteWorkspaceExportManifest,
) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err(format!(
            "unsupported workspace export schema version {}",
            manifest.schema_version
        ));
    }
    if manifest.files.is_empty() {
        return Err("workspace export manifest does not list any files".to_string());
    }
    let mut total_bytes = 0_usize;
    let mut root_entries = Vec::with_capacity(manifest.files.len());
    for file in &manifest.files {
        let relative_path = safe_bundle_relative_path(&file.path)?;
        let path = export_dir.join(relative_path);
        let bytes =
            fs::read(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if bytes.len() != file.bytes {
            return Err(format!(
                "{} byte count mismatch: expected {}, got {}",
                file.path,
                file.bytes,
                bytes.len()
            ));
        }
        let actual_sha256 = sha256_hex(&bytes);
        if actual_sha256 != file.sha256 {
            return Err(format!(
                "{} sha256 mismatch: expected {}, got {}",
                file.path, file.sha256, actual_sha256
            ));
        }
        total_bytes += file.bytes;
        root_entries.push(format!(
            "{}\0{}\0{}\0{}",
            file.path, file.sha256, file.bytes, file.media_type
        ));
    }
    if total_bytes != manifest.total_bytes {
        return Err(format!(
            "workspace export total byte mismatch: expected {}, got {}",
            manifest.total_bytes, total_bytes
        ));
    }
    root_entries.sort();
    let actual_root =
        sha256_hex(format!("agentbox-workspace-root-v1\n{}", root_entries.join("\n")).as_bytes());
    if actual_root != manifest.root_sha256 {
        return Err(format!(
            "workspace export root sha256 mismatch: expected {}, got {}",
            manifest.root_sha256, actual_root
        ));
    }
    Ok(())
}

fn evidence_bundle_root_sha256(files: &[EvidenceBundleFile]) -> String {
    let mut entries = files
        .iter()
        .map(|file| {
            format!(
                "{}\0{}\0{}\0{}",
                file.path, file.sha256, file.bytes, file.media_type
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    sha256_hex(format!("agentbox-evidence-root-v1\n{}", entries.join("\n")).as_bytes())
}

fn safe_bundle_relative_path(path: &str) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(path);
    if candidate.as_os_str().is_empty() || candidate.is_absolute() {
        return Err(format!("invalid bundle file path `{path}`"));
    }
    if candidate.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err(format!("unsafe bundle file path `{path}`"));
    }
    Ok(candidate)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn utf8_chunks(contents: &str, max_bytes: usize) -> Result<Vec<(u64, String)>, String> {
    if max_bytes == 0 {
        return Err("chunk size must be greater than zero".into());
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_offset = 0_u64;
    let mut next_offset = 0_u64;
    for ch in contents.chars() {
        let char_len = ch.len_utf8();
        if current.is_empty() {
            current_offset = next_offset;
        }
        if !current.is_empty() && current.len() + char_len > max_bytes {
            next_offset = next_offset.saturating_add(current.len().try_into().unwrap_or(u64::MAX));
            chunks.push((current_offset, std::mem::take(&mut current)));
            current_offset = next_offset;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        chunks.push((current_offset, current));
    }
    Ok(chunks)
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
    let workspace_mode_risk = spec.risk.clone();
    apply_workspace_mode(
        &mut spec,
        &workspace_mode_risk,
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
    risk: &agentbox_daemon::runtime::types::AgentPodRiskLevel,
    raw_mode: Option<&str>,
    overlay_dir: Option<PathBuf>,
) {
    use agentbox_daemon::runtime::types::{
        AgentPodWorkspaceMode, WorkspaceOverlayMode, WorkspaceOverlayPolicy,
    };

    let mut mode = raw_mode
        .map(parse_workspace_mode)
        .unwrap_or_else(|| default_workspace_mode_for_risk(risk));
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

    let overlay_base = overlay_dir.unwrap_or_else(|| default_workspace_overlay_base(spec, &mode));
    let mut overlay = WorkspaceOverlayPolicy::review_required(Some(overlay_base));
    if mode == AgentPodWorkspaceMode::Ephemeral {
        overlay.mode = WorkspaceOverlayMode::DiscardOnDestroy;
    }
    spec.filesystem.workspace_overlay = overlay;
}

fn default_workspace_overlay_base(
    spec: &agentbox_daemon::runtime::types::MinipodSpec,
    mode: &agentbox_daemon::runtime::types::AgentPodWorkspaceMode,
) -> PathBuf {
    let preferred = agentbox_dir()
        .join("overlays")
        .join(spec.id.clone())
        .join(mode.label());
    let workspace = realish_cli_path(&spec.filesystem.workspace_host_path);
    if !path_is_inside(&preferred, &workspace) {
        return preferred;
    }

    let temp_dir = std::env::temp_dir();
    let mut candidates = vec![temp_dir.join("agentbox-overlays")];
    if let Some(parent) = temp_dir.parent() {
        candidates.push(parent.join("agentbox-overlays"));
    }
    candidates.push(PathBuf::from("/tmp/agentbox-overlays"));

    candidates
        .into_iter()
        .map(|root| root.join(spec.id.clone()).join(mode.label()))
        .find(|candidate| !path_is_inside(candidate, &workspace))
        .unwrap_or(preferred)
}

fn default_workspace_mode_for_risk(
    risk: &agentbox_daemon::runtime::types::AgentPodRiskLevel,
) -> agentbox_daemon::runtime::types::AgentPodWorkspaceMode {
    use agentbox_daemon::runtime::types::{AgentPodRiskLevel, AgentPodWorkspaceMode};

    match risk {
        AgentPodRiskLevel::Low => AgentPodWorkspaceMode::Direct,
        AgentPodRiskLevel::Medium | AgentPodRiskLevel::High | AgentPodRiskLevel::VeryHigh => {
            AgentPodWorkspaceMode::OverlayReview
        }
    }
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

fn normalize_cli_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

fn realish_cli_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    let mut suffix = PathBuf::new();
    let mut cursor = path;
    while let Some(parent) = cursor.parent() {
        if let Some(name) = cursor.file_name() {
            suffix = PathBuf::from(name).join(suffix);
        }
        if let Ok(canonical_parent) = parent.canonicalize() {
            return normalize_cli_path(&canonical_parent.join(suffix));
        }
        cursor = parent;
    }

    normalize_cli_path(path)
}

fn path_is_inside(path: &Path, parent: &Path) -> bool {
    !parent.as_os_str().is_empty() && realish_cli_path(path).starts_with(parent)
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

fn provider_status_rows() -> Vec<serde_json::Value> {
    use agentbox_daemon::runtime::registry::RuntimeProviderRegistry;

    let mut rows = vec![serde_json::json!({
        "provider": "direct-host",
        "family": "direct-host",
        "platform": std::env::consts::OS,
        "status": "shipped",
        "bridge": "unix-socket",
        "network": "command-mediation",
        "boundary_primitives": ["path-shim", "unix-socket", "sqlite-audit"],
        "boundary_primitive_statuses": [
            {
                "primitive": "path-shim",
                "status": "shipped",
                "active": true,
                "requires_gate": null,
                "enforcement_scope": "host PATH command mediation through agentbox-shim"
            },
            {
                "primitive": "unix-socket",
                "status": "shipped",
                "active": true,
                "requires_gate": null,
                "enforcement_scope": "local daemon approval and policy transport"
            },
            {
                "primitive": "sqlite-audit",
                "status": "shipped",
                "active": true,
                "requires_gate": null,
                "enforcement_scope": "hash-chained local audit persistence"
            }
        ],
        "bridge_health": {
            "schema_version": 1,
            "provider": "direct-host",
            "transports": ["UnixSocket"],
            "policy": {"supported": true, "active": true, "detail": "policy mediation through the host bridge"},
            "approval": {"supported": true, "active": true, "detail": "operator approval request and response transport"},
            "credentials": {"supported": true, "active": true, "detail": "explicit credential grant transport"},
            "evidence": {"supported": true, "active": true, "detail": "hash-linked evidence append or bundle transport"},
            "kill_switch": {"supported": true, "active": true, "detail": "session destroy and running command kill acknowledgement"},
            "network": {"supported": true, "active": false, "detail": "network boundary decisions or provider-level network enforcement"}
        },
        "capabilities": ["shim", "policy", "approval", "audit"],
        "doctor_check": "daemon socket",
        "setup_command": "agentbox setup-plan",
        "verification_command": "agentbox doctor",
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
            "boundary_primitives": provider.boundary_primitives(),
            "boundary_primitive_statuses": provider
                .boundary_primitive_statuses()
                .into_iter()
                .map(|primitive| serde_json::json!({
                    "primitive": primitive.primitive,
                    "status": format_provider_status(primitive.status),
                    "active": primitive.active,
                    "requires_gate": primitive.requires_gate,
                    "enforcement_scope": primitive.enforcement_scope,
                }))
                .collect::<Vec<_>>(),
            "bridge_health": provider.bridge_health(),
            "doctor_check": provider_doctor_check(provider.name()),
            "setup_command": provider_setup_command(provider.name()),
            "verification_command": provider_verification_command(provider.name()),
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
        "boundary_primitives": ["podman-container", "guest-shim"],
        "boundary_primitive_statuses": [
            {
                "primitive": "podman-container",
                "status": podman_status,
                "active": podman_status == "experimental",
                "requires_gate": "podman --version",
                "enforcement_scope": "compatibility container boundary managed by Podman"
            },
            {
                "primitive": "guest-shim",
                "status": podman_status,
                "active": podman_status == "experimental",
                "requires_gate": "AGENTBOX_LINUX_SHIM or build-linux-shim artifact",
                "enforcement_scope": "guest command bridge inside compatibility container"
            }
        ],
        "bridge_health": {
            "schema_version": 1,
            "provider": "podman",
            "transports": ["UnixSocket"],
            "policy": {"supported": true, "active": podman_status == "experimental", "detail": "policy mediation through the host bridge"},
            "approval": {"supported": true, "active": podman_status == "experimental", "detail": "operator approval request and response transport"},
            "credentials": {"supported": true, "active": podman_status == "experimental", "detail": "explicit credential grant transport"},
            "evidence": {"supported": true, "active": podman_status == "experimental", "detail": "hash-linked evidence append or bundle transport"},
            "kill_switch": {"supported": true, "active": podman_status == "experimental", "detail": "session destroy and running command kill acknowledgement"},
            "network": {"supported": false, "active": false, "detail": "network boundary decisions or provider-level network enforcement"}
        },
        "capabilities": ["container isolation", "shim bridge"],
        "doctor_check": "podman provider",
        "setup_command": "install Podman; on macOS run `podman machine init && podman machine start`",
        "verification_command": "agentbox run --provider podman -- <cmd>",
    }));

    rows
}

fn cmd_providers(json: bool) {
    let rows = provider_status_rows();

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
    for row in rows {
        let capabilities = row["capabilities"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        println!(
            "{:<18} {:<14} {:<10} {:<18} {:<18} {:<24} {}",
            row["provider"].as_str().unwrap_or_default(),
            row["family"].as_str().unwrap_or_default(),
            row["platform"].as_str().unwrap_or_default(),
            row["status"].as_str().unwrap_or_default(),
            row["bridge"].as_str().unwrap_or_default(),
            row["network"].as_str().unwrap_or_default(),
            capabilities
        );
    }
}

fn cmd_bridge_health(json: bool, provider_filter: Option<String>) {
    let mut rows = provider_status_rows()
        .into_iter()
        .filter_map(|row| {
            let provider = row.get("provider")?.as_str()?.to_string();
            let health = row.get("bridge_health")?.clone();
            if provider_filter
                .as_deref()
                .is_some_and(|filter| filter != provider)
            {
                return None;
            }
            Some(serde_json::json!({
                "provider": provider,
                "family": row.get("family").cloned().unwrap_or(serde_json::Value::Null),
                "platform": row.get("platform").cloned().unwrap_or(serde_json::Value::Null),
                "status": row.get("status").cloned().unwrap_or(serde_json::Value::Null),
                "doctor_check": row.get("doctor_check").cloned().unwrap_or(serde_json::Value::Null),
                "verification_command": row.get("verification_command").cloned().unwrap_or(serde_json::Value::Null),
                "readiness": bridge_readiness(&row),
                "bridge_health": health,
            }))
        })
        .collect::<Vec<_>>();

    if let Some(provider) = provider_filter.as_deref() {
        if rows.is_empty() {
            eprintln!("error: unknown provider `{provider}`");
            eprintln!(
                "hint: expected direct-host, podman, agentpod-macos, agentpod-linux, agentpod-windows, or remote-agentpod"
            );
            std::process::exit(1);
        }
    }

    rows.sort_by(|left, right| {
        left["provider"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["provider"].as_str().unwrap_or_default())
    });

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).expect("failed to serialize bridge health")
        );
        return;
    }

    println!(
        "{:<18} {:<14} {:<12} {:<9} {:<9} {:<9} {:<9} {:<9}",
        "PROVIDER", "STATUS", "TRANSPORT", "POLICY", "APPROVAL", "CREDS", "EVIDENCE", "NETWORK"
    );
    println!("{}", "-".repeat(98));
    for row in rows {
        let health = &row["bridge_health"];
        println!(
            "{:<18} {:<14} {:<12} {:<9} {:<9} {:<9} {:<9} {:<9}",
            row["provider"].as_str().unwrap_or_default(),
            row["status"].as_str().unwrap_or_default(),
            health["transports"]
                .as_array()
                .and_then(|values| values.first())
                .and_then(|value| value.as_str())
                .unwrap_or("none"),
            bridge_health_cell(&health["policy"]),
            bridge_health_cell(&health["approval"]),
            bridge_health_cell(&health["credentials"]),
            bridge_health_cell(&health["evidence"]),
            bridge_health_cell(&health["network"]),
        );
    }
}

fn bridge_health_cell(value: &serde_json::Value) -> &'static str {
    match (
        value.get("supported").and_then(serde_json::Value::as_bool),
        value.get("active").and_then(serde_json::Value::as_bool),
    ) {
        (Some(true), Some(true)) => "active",
        (Some(true), _) => "supported",
        _ => "none",
    }
}

fn bridge_readiness(row: &serde_json::Value) -> serde_json::Value {
    let provider = row["provider"].as_str().unwrap_or_default();
    let status = row["status"].as_str().unwrap_or_default();
    let verification = row
        .get("verification_command")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("agentbox providers --json");

    let (verdict, execution_scope, claim_boundary, next_command) = match provider {
        "direct-host" => (
            "active-command-mediation",
            "host process command mediation",
            "PATH/shim and daemon-mediated commands only; not a full sandbox",
            "agentbox doctor",
        ),
        "podman" if status == "experimental" => (
            "active-if-podman-available",
            "compatibility container provider",
            "Podman compatibility backend, not the AgentPod-native runtime",
            verification,
        ),
        "podman" => (
            "needs-podman",
            "compatibility container provider",
            "Podman is not installed or unavailable on this host",
            "install Podman; on macOS run `podman machine init && podman machine start`",
        ),
        "agentpod-linux" => (
            "prototype-gated",
            "Linux native primitive prototype",
            "requires Linux and AGENTBOX_LINUX_NATIVE=1; not a complete sandbox claim",
            verification,
        ),
        "remote-agentpod" => (
            "endpoint-gated",
            "remote/disposable AgentPod worker bridge",
            "requires configured worker endpoint; worker-side sandboxing remains explicit",
            "agentbox setup --provider remote-agentpod --dry-run --wizard",
        ),
        "agentpod-macos" | "agentpod-windows" => (
            "metadata-only",
            "native provider descriptor",
            "execution is not wired in this build",
            verification,
        ),
        _ => (
            "metadata-only",
            "unknown provider surface",
            "no live execution claim",
            verification,
        ),
    };

    serde_json::json!({
        "verdict": verdict,
        "execution_scope": execution_scope,
        "claim_boundary": claim_boundary,
        "next_command": next_command,
    })
}

fn provider_doctor_check(provider: &str) -> Option<&'static str> {
    match provider {
        "direct-host" => Some("daemon socket"),
        "agentpod-macos" => Some("macOS native plan"),
        "agentpod-linux" => Some("Linux native plan"),
        "agentpod-windows" => Some("Windows native plan"),
        "remote-agentpod" => Some("remote-agentpod endpoint"),
        "podman" => Some("podman provider"),
        _ => None,
    }
}

fn provider_setup_command(provider: &str) -> Option<&'static str> {
    match provider {
        "direct-host" => Some("agentbox setup-plan"),
        "agentpod-macos" => Some("agentbox native-plan --provider agentpod-macos -- <cmd>"),
        "agentpod-linux" => Some("agentbox native-plan --provider agentpod-linux -- <cmd>"),
        "agentpod-windows" => Some("agentbox native-plan --provider agentpod-windows -- <cmd>"),
        "remote-agentpod" => {
            Some("export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://worker.example.com/agentpod")
        }
        "podman" => {
            Some("install Podman; on macOS run `podman machine init && podman machine start`")
        }
        _ => None,
    }
}

fn provider_verification_command(provider: &str) -> Option<&'static str> {
    match provider {
        "direct-host" => Some("agentbox doctor"),
        "agentpod-macos" => Some("agentbox native-plan --provider agentpod-macos -- <cmd>"),
        "agentpod-linux" => Some("agentbox native-plan --provider agentpod-linux -- <cmd>"),
        "agentpod-windows" => Some("agentbox native-plan --provider agentpod-windows -- <cmd>"),
        "remote-agentpod" => {
            Some("agentbox remote-handshake --endpoint https://worker.example.com/agentpod")
        }
        "podman" => Some("agentbox run --provider podman -- <cmd>"),
        _ => None,
    }
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

fn cmd_remote_evidence(
    session_id: String,
    worker_session_id: String,
    evidence: String,
    bundle_sha256: Option<String>,
    event_count: Option<u64>,
    bundle_dir: Option<PathBuf>,
) {
    use agentbox_daemon::runtime::providers::remote::RemoteAgentPodEvidenceUploadRequest;

    let (bundle_sha256, event_count, bundle_id, bundle_root_sha256, derived_from_bundle) =
        if let Some(bundle_dir) = bundle_dir {
            if bundle_sha256.is_some() || event_count.is_some() {
                eprintln!(
                    "error: --bundle-dir cannot be combined with --bundle-sha256 or --event-count"
                );
                std::process::exit(1);
            }
            let metadata =
                load_remote_evidence_metadata_from_bundle(&bundle_dir).unwrap_or_else(|e| {
                    eprintln!(
                        "error: failed to derive remote evidence metadata from {}: {}",
                        bundle_dir.display(),
                        e
                    );
                    std::process::exit(1);
                });
            (
                metadata.root_sha256.clone(),
                metadata.event_count,
                Some(metadata.bundle_id),
                Some(metadata.root_sha256),
                true,
            )
        } else {
            let Some(bundle_sha256) = bundle_sha256 else {
                eprintln!("error: --bundle-sha256 is required unless --bundle-dir is provided");
                std::process::exit(1);
            };
            let Some(event_count) = event_count else {
                eprintln!("error: --event-count is required unless --bundle-dir is provided");
                std::process::exit(1);
            };
            (bundle_sha256, event_count, None, None, false)
        };

    let request = RemoteAgentPodEvidenceUploadRequest {
        session_id,
        worker_session_id,
        evidence_mode: parse_remote_evidence_mode(&evidence),
        bundle_sha256,
        derived_from_bundle,
        bundle_id,
        bundle_root_sha256,
        event_count,
        sealed_at: chrono::Utc::now(),
        secret_material_included: false,
    };
    request.validate().unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod evidence upload metadata: {}",
            e
        );
        std::process::exit(1);
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&request)
            .expect("failed to serialize remote AgentPod evidence upload metadata")
    );
}

async fn cmd_remote_evidence_status(
    endpoint: Option<String>,
    session_id: String,
    worker_session_id: Option<String>,
) {
    use agentbox_daemon::runtime::providers::remote::{
        HttpRemoteAgentPodTransport, RemoteAgentPodEvidenceStatusRequest, RemoteAgentPodTransport,
    };

    let (endpoint, worker_session_id) =
        resolve_remote_session_metadata(&session_id, endpoint, worker_session_id);
    let transport = HttpRemoteAgentPodTransport::new(endpoint).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod evidence status transport: {}",
            e
        );
        std::process::exit(1);
    });
    let request = RemoteAgentPodEvidenceStatusRequest {
        session_id,
        worker_session_id,
    };
    request.validate().unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod evidence status request: {}",
            e
        );
        std::process::exit(1);
    });
    let response = transport
        .evidence_status(request)
        .await
        .unwrap_or_else(|e| {
            eprintln!(
                "error: failed to query remote AgentPod evidence status: {}",
                e
            );
            std::process::exit(1);
        });

    println!(
        "{}",
        serde_json::to_string_pretty(&response)
            .expect("failed to serialize remote AgentPod evidence status")
    );
}

fn resolve_remote_session_metadata(
    session_id: &str,
    endpoint: Option<String>,
    worker_session_id: Option<String>,
) -> (String, String) {
    if let (Some(endpoint), Some(worker_session_id)) =
        (endpoint.as_ref(), worker_session_id.as_ref())
    {
        return (endpoint.clone(), worker_session_id.clone());
    }

    let session = load_persisted_session_for_remote_metadata(session_id);
    remote_session_metadata_from_session(&session, endpoint, worker_session_id).unwrap_or_else(
        |e| {
            eprintln!("{e}");
            std::process::exit(1);
        },
    )
}

fn load_persisted_session_for_remote_metadata(
    session_id: &str,
) -> agentbox_daemon::runtime::types::RuntimeSession {
    use agentbox_daemon::config;
    use agentbox_daemon::runtime::session::RuntimeSessionStore;

    let config = config::load().unwrap_or_else(|e| {
        eprintln!("error: failed to load Agentbox config: {}", e);
        std::process::exit(1);
    });
    let store = RuntimeSessionStore::new(config.session_store_path);
    store
        .get(session_id)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to read runtime session store: {}", e);
            std::process::exit(1);
        })
        .unwrap_or_else(|| {
            eprintln!("error: remote AgentPod session not found: {session_id}");
            std::process::exit(1);
        })
}

fn remote_session_metadata_from_session(
    session: &agentbox_daemon::runtime::types::RuntimeSession,
    endpoint: Option<String>,
    worker_session_id: Option<String>,
) -> Result<(String, String), String> {
    let endpoint = match endpoint {
        Some(endpoint) => endpoint,
        None => session
            .spec
            .labels
            .get(REMOTE_LABEL_ENDPOINT)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "error: session {} does not contain remote endpoint metadata; pass --endpoint",
                    session.id
                )
            })?,
    };
    let worker_session_id = match worker_session_id {
        Some(worker_session_id) => worker_session_id,
        None => session
            .spec
            .labels
            .get(REMOTE_LABEL_WORKER_SESSION)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "error: session {} does not contain remote worker session metadata; pass --worker-session",
                    session.id
                )
            })?,
    };
    Ok((endpoint, worker_session_id))
}

async fn cmd_remote_evidence_upload(
    endpoint: Option<String>,
    session_id: String,
    worker_session_id: Option<String>,
    bundle_dir: PathBuf,
) {
    use agentbox_daemon::runtime::providers::remote::{
        HttpRemoteAgentPodTransport, RemoteAgentPodEvidenceBundleUploadRequest,
        RemoteAgentPodEvidenceMode, RemoteAgentPodEvidenceUploadRequest, RemoteAgentPodTransport,
    };

    let (endpoint, worker_session_id) =
        resolve_remote_session_metadata(&session_id, endpoint, worker_session_id);
    let payload =
        build_remote_evidence_bundle_upload_payload(&bundle_dir, &session_id, &worker_session_id)
            .unwrap_or_else(|e| {
                eprintln!(
                    "error: failed to build remote AgentPod evidence upload envelope from {}: {}",
                    bundle_dir.display(),
                    e
                );
                std::process::exit(1);
            });
    let transport = HttpRemoteAgentPodTransport::new(endpoint).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod evidence upload transport: {}",
            e
        );
        std::process::exit(1);
    });
    let evidence_request = RemoteAgentPodEvidenceUploadRequest {
        session_id: session_id.clone(),
        worker_session_id: worker_session_id.clone(),
        evidence_mode: RemoteAgentPodEvidenceMode::BundleUpload,
        bundle_sha256: payload.root_sha256.clone(),
        derived_from_bundle: true,
        bundle_id: Some(payload.bundle_id.clone()),
        bundle_root_sha256: Some(payload.root_sha256.clone()),
        event_count: payload.event_count,
        sealed_at: Utc::now(),
        secret_material_included: false,
    };
    evidence_request.validate().unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod evidence receipt request: {}",
            e
        );
        std::process::exit(1);
    });
    let evidence_response = transport
        .upload_evidence(evidence_request)
        .await
        .unwrap_or_else(|e| {
            eprintln!(
                "error: failed to upload remote AgentPod evidence receipt: {}",
                e
            );
            std::process::exit(1);
        });
    let bundle_request = RemoteAgentPodEvidenceBundleUploadRequest {
        session_id,
        worker_session_id,
        bundle_sha256: payload.envelope_sha256.clone(),
        bundle_json: payload.envelope_json,
        secret_material_included: false,
    };
    bundle_request.validate().unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod evidence bundle payload request: {}",
            e
        );
        std::process::exit(1);
    });
    let bundle_response = transport
        .upload_evidence_bundle(bundle_request)
        .await
        .unwrap_or_else(|e| {
            eprintln!(
                "error: failed to upload remote AgentPod evidence bundle payload: {}",
                e
            );
            std::process::exit(1);
        });

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "evidence_receipt": evidence_response,
            "bundle_payload": bundle_response,
            "bundle_id": payload.bundle_id,
            "bundle_root_sha256": payload.root_sha256,
            "bundle_payload_sha256": payload.envelope_sha256,
        }))
        .expect("failed to serialize remote AgentPod evidence upload result")
    );
}

async fn cmd_remote_evidence_stream(
    endpoint: Option<String>,
    session_id: String,
    worker_session_id: Option<String>,
    stream_id: String,
    file: PathBuf,
    chunk_bytes: usize,
) {
    use agentbox_daemon::runtime::providers::remote::{
        HttpRemoteAgentPodTransport, RemoteAgentPodEvidenceStreamChunkRequest,
        RemoteAgentPodTransport,
    };

    let (endpoint, worker_session_id) =
        resolve_remote_session_metadata(&session_id, endpoint, worker_session_id);
    let contents = fs::read_to_string(&file).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to read remote AgentPod evidence stream file {}: {}",
            file.display(),
            e
        );
        std::process::exit(1);
    });
    let chunks = utf8_chunks(&contents, chunk_bytes).unwrap_or_else(|e| {
        eprintln!("error: failed to chunk remote AgentPod evidence stream: {e}");
        std::process::exit(1);
    });
    if chunks.is_empty() {
        eprintln!("error: remote AgentPod evidence stream file must not be empty");
        std::process::exit(1);
    }
    let transport = HttpRemoteAgentPodTransport::new(endpoint).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod evidence stream transport: {}",
            e
        );
        std::process::exit(1);
    });

    let total_chunks = chunks.len();
    let mut responses = Vec::with_capacity(total_chunks);
    for (index, (offset, chunk)) in chunks.into_iter().enumerate() {
        let request = RemoteAgentPodEvidenceStreamChunkRequest {
            session_id: session_id.clone(),
            worker_session_id: worker_session_id.clone(),
            stream_id: stream_id.clone(),
            sequence: index.try_into().unwrap_or(u64::MAX),
            offset,
            chunk_sha256: sha256_hex(chunk.as_bytes()),
            chunk_bytes: chunk.len().try_into().unwrap_or(u64::MAX),
            chunk_utf8: chunk,
            final_chunk: index + 1 == total_chunks,
            secret_material_included: false,
        };
        request.validate().unwrap_or_else(|e| {
            eprintln!(
                "error: failed to build remote AgentPod evidence stream chunk request: {}",
                e
            );
            std::process::exit(1);
        });
        let response = transport
            .upload_evidence_stream_chunk(request)
            .await
            .unwrap_or_else(|e| {
                eprintln!(
                    "error: failed to upload remote AgentPod evidence stream chunk: {}",
                    e
                );
                std::process::exit(1);
            });
        responses.push(response);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "session_id": session_id,
            "worker_session_id": worker_session_id,
            "stream_id": stream_id,
            "chunk_count": responses.len(),
            "stream_sha256": responses.last().and_then(|response| response.stream_sha256.clone()),
            "chunks": responses,
        }))
        .expect("failed to serialize remote AgentPod evidence stream upload result")
    );
}

async fn cmd_remote_approval_grant(
    endpoint: Option<String>,
    session_id: String,
    worker_session_id: Option<String>,
    request_id: String,
    reason: String,
    ttl_seconds: Option<i64>,
) {
    use agentbox_daemon::runtime::providers::remote::{
        HttpRemoteAgentPodTransport, RemoteAgentPodApprovalGrantRequest,
        RemoteAgentPodEvidenceStatusRequest, RemoteAgentPodTransport,
    };
    use agentbox_daemon::runtime::types::{ApprovalGrant, ApprovalScope};

    let (endpoint, worker_session_id) =
        resolve_remote_session_metadata(&session_id, endpoint, worker_session_id);
    let transport = HttpRemoteAgentPodTransport::new(endpoint).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod approval grant transport: {}",
            e
        );
        std::process::exit(1);
    });
    let status_request = RemoteAgentPodEvidenceStatusRequest {
        session_id: session_id.clone(),
        worker_session_id: worker_session_id.clone(),
    };
    let status = transport
        .evidence_status(status_request)
        .await
        .unwrap_or_else(|e| {
            eprintln!(
                "error: failed to query remote AgentPod pending approvals: {}",
                e
            );
            std::process::exit(1);
        });
    let Some(pending) = status
        .pending_approvals
        .iter()
        .find(|approval| approval.request_id == request_id)
    else {
        eprintln!("error: pending remote AgentPod approval request was not found");
        std::process::exit(1);
    };
    let Some(binary) = pending.command_argv.first().cloned() else {
        eprintln!("error: pending remote AgentPod approval has no command binary");
        std::process::exit(1);
    };
    let args_prefix = pending.command_argv.iter().skip(1).cloned().collect();
    let expires_at = ttl_seconds.map(|seconds| {
        if seconds <= 0 {
            eprintln!("error: --ttl-seconds must be greater than zero");
            std::process::exit(1);
        }
        chrono::Utc::now() + chrono::Duration::seconds(seconds)
    });
    let grant = ApprovalGrant {
        id: format!(
            "grant-remote-command-{}",
            ulid::Ulid::new().to_string().to_lowercase()
        ),
        scope: ApprovalScope::Command {
            binary,
            args_prefix,
        },
        reason,
        expires_at,
    };
    let request = RemoteAgentPodApprovalGrantRequest {
        session_id,
        worker_session_id,
        request_id,
        grant,
    };
    request.validate().unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod approval grant request: {}",
            e
        );
        std::process::exit(1);
    });
    let response = transport.grant_approval(request).await.unwrap_or_else(|e| {
        eprintln!("error: failed to grant remote AgentPod approval: {}", e);
        std::process::exit(1);
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&response)
            .expect("failed to serialize remote AgentPod approval grant response")
    );
}

async fn cmd_remote_workspace_export(
    endpoint: Option<String>,
    session_id: String,
    worker_session_id: Option<String>,
    output_dir: PathBuf,
    force: bool,
    json: bool,
) {
    use agentbox_daemon::runtime::providers::remote::{
        HttpRemoteAgentPodTransport, RemoteAgentPodTransport, RemoteAgentPodWorkspaceExportRequest,
    };

    let (endpoint, worker_session_id) =
        resolve_remote_session_metadata(&session_id, endpoint, worker_session_id);
    let transport = HttpRemoteAgentPodTransport::new(endpoint).unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod workspace export transport: {}",
            e
        );
        std::process::exit(1);
    });
    let request = RemoteAgentPodWorkspaceExportRequest {
        session_id,
        worker_session_id,
    };
    request.validate().unwrap_or_else(|e| {
        eprintln!(
            "error: failed to build remote AgentPod workspace export request: {}",
            e
        );
        std::process::exit(1);
    });
    let response = transport
        .export_workspace(request)
        .await
        .unwrap_or_else(|e| {
            eprintln!("error: failed to export remote AgentPod workspace: {}", e);
            std::process::exit(1);
        });
    let manifest =
        write_remote_workspace_export_dir(&response, &output_dir, force).unwrap_or_else(|e| {
            eprintln!(
                "error: failed to materialize remote AgentPod workspace at {}: {}",
                output_dir.display(),
                e
            );
            std::process::exit(1);
        });

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&manifest)
                .expect("failed to serialize remote AgentPod workspace export manifest")
        );
        return;
    }

    println!("Remote AgentPod workspace exported.");
    println!("session:        {}", manifest.session_id);
    println!("worker session: {}", manifest.worker_session_id);
    println!("status:         {}", manifest.status);
    println!("output:         {}", manifest.output_dir);
    println!("files:          {}", manifest.file_count);
    println!("bytes:          {}", manifest.total_bytes);
    println!("root sha256:    {}", manifest.root_sha256);
    println!("manifest:       {}", manifest.manifest_path);
}

fn cmd_remote_workspace_apply(
    export_dir: PathBuf,
    workspace: PathBuf,
    dry_run: bool,
    force: bool,
    json: bool,
) {
    let report = apply_remote_workspace_export_dir(&export_dir, &workspace, dry_run, force)
        .unwrap_or_else(|e| {
            eprintln!(
                "error: failed to apply remote AgentPod workspace export from {} to {}: {}",
                export_dir.display(),
                workspace.display(),
                e
            );
            std::process::exit(1);
        });

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .expect("failed to serialize remote AgentPod workspace apply report")
        );
        return;
    }

    println!("Remote AgentPod workspace apply report.");
    println!("session:        {}", report.session_id);
    println!("worker session: {}", report.worker_session_id);
    println!("export:         {}", report.export_dir);
    println!("workspace:      {}", report.workspace);
    println!("dry run:        {}", report.dry_run);
    println!("force:          {}", report.force);
    println!("applied files:  {}", report.applied_files);
    println!("unchanged:      {}", report.unchanged_files);
    println!("conflicts:      {}", report.conflict_files);
    println!("bytes:          {}", report.total_bytes);
    if !report.files.is_empty() {
        println!("files:");
        for file in &report.files {
            println!("  - {} ({})", file.path, file.action);
        }
    }
}

fn cmd_native_plan(
    provider: String,
    workspace: Option<PathBuf>,
    agent_profile: String,
    risk: String,
    command: Vec<String>,
) {
    let provider = resolve_native_plan_provider(&provider);

    if !matches!(
        provider.as_str(),
        "agentpod-linux" | "agentpod-macos" | "agentpod-windows"
    ) {
        eprintln!(
            "error: native plan provider `{}` is not supported yet",
            provider
        );
        eprintln!("hint: supported values: agentpod-linux, agentpod-macos, agentpod-windows");
        std::process::exit(1);
    }
    if command.is_empty() {
        eprintln!("error: native plan command cannot be empty");
        std::process::exit(1);
    }

    let workspace = workspace.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|e| {
            eprintln!("error: failed to determine current directory: {}", e);
            std::process::exit(1);
        })
    });
    let plan = build_native_plan_json(&provider, workspace, agent_profile, risk, command)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to build native AgentPod plan: {}", e);
            std::process::exit(1);
        });

    println!(
        "{}",
        serde_json::to_string_pretty(&plan).expect("failed to serialize native AgentPod plan")
    );
}

fn build_native_plan_json(
    provider: &str,
    workspace: PathBuf,
    agent_profile: String,
    risk: String,
    command: Vec<String>,
) -> Result<serde_json::Value, String> {
    use agentbox_daemon::runtime::providers::linux::LinuxAgentPodExecutionPlan;
    use agentbox_daemon::runtime::providers::macos::MacOsAgentPodExecutionPlan;
    use agentbox_daemon::runtime::providers::windows::WindowsAgentPodExecutionPlan;
    use agentbox_daemon::runtime::types::{ExecCommand, MinipodSpec};

    if command.is_empty() {
        return Err("native plan command cannot be empty".into());
    }

    let agent_name = command.first().cloned().unwrap_or_else(|| "agent".into());
    let mut spec = MinipodSpec::for_agent_task_with_profile(agent_name, &workspace, agent_profile);
    spec.risk = parse_agentpod_risk(&risk);
    spec.labels
        .insert("agentbox.provider".into(), provider.to_string());

    let exec = ExecCommand {
        argv: command,
        working_dir: Some(workspace.display().to_string()),
        env: HashMap::new(),
        timeout_seconds: None,
    };

    match provider {
        "agentpod-linux" => serde_json::to_value(
            LinuxAgentPodExecutionPlan::from_minipod_spec(&spec, &exec)
                .map_err(|e| format!("failed to build Linux native AgentPod plan: {e}"))?,
        )
        .map_err(|e| format!("failed to serialize Linux native AgentPod plan: {e}")),
        "agentpod-macos" => serde_json::to_value(
            MacOsAgentPodExecutionPlan::from_minipod_spec(&spec, &exec)
                .map_err(|e| format!("failed to build macOS native AgentPod plan: {e}"))?,
        )
        .map_err(|e| format!("failed to serialize macOS native AgentPod plan: {e}")),
        "agentpod-windows" => serde_json::to_value(
            WindowsAgentPodExecutionPlan::from_minipod_spec(&spec, &exec)
                .map_err(|e| format!("failed to build Windows native AgentPod plan: {e}"))?,
        )
        .map_err(|e| format!("failed to serialize Windows native AgentPod plan: {e}")),
        _ => Err(format!(
            "native plan provider `{provider}` is not supported yet"
        )),
    }
}

fn resolve_native_plan_provider(provider: &str) -> String {
    let provider = provider.trim();
    if !provider.is_empty() && !provider.eq_ignore_ascii_case("auto") {
        return provider.to_string();
    }

    if cfg!(target_os = "macos") {
        "agentpod-macos".into()
    } else if cfg!(target_os = "windows") {
        "agentpod-windows".into()
    } else {
        "agentpod-linux".into()
    }
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

fn cmd_review(session_id: String, json: bool, patch: bool, tui: bool) {
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
        let output = ReviewJsonOutput {
            action_plan: review_action_plan(&session.id),
            snapshot,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("failed to serialize workspace review")
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
    if tui {
        print_review_tui_skeleton(&session.id);
    }
}

fn print_review_tui_skeleton(session_id: &str) {
    let action_plan = review_action_plan(session_id);

    println!();
    println!("Review actions");
    println!("{}", "-".repeat(64));
    for action in &action_plan.actions {
        println!(
            "  {:<2} {:<16} {}",
            action.key, action.label, action.command
        );
    }
    println!();
    println!("This is a command menu skeleton; it does not read keys or mutate state.");
}

fn review_action_plan(session_id: &str) -> ReviewActionPlan {
    ReviewActionPlan {
        schema_version: 1,
        session_id: session_id.to_string(),
        actions: vec![
            ReviewAction {
                key: "p",
                id: "print_patch",
                label: "print patch",
                command: format!("agentbox review {session_id} --patch"),
                mutates_workspace: false,
                requires_message: false,
                description: "Print the captured workspace patch without changing files.",
            },
            ReviewAction {
                key: "a",
                id: "apply_changes",
                label: "apply changes",
                command: format!("agentbox review-apply {session_id}"),
                mutates_workspace: true,
                requires_message: false,
                description: "Apply the projected workspace output to the lower workspace.",
            },
            ReviewAction {
                key: "c",
                id: "commit_changes",
                label: "commit changes",
                command: format!("agentbox review-commit {session_id} --message \"agent output\""),
                mutates_workspace: true,
                requires_message: true,
                description:
                    "Apply the projected workspace output and commit it in the lower workspace.",
            },
            ReviewAction {
                key: "d",
                id: "discard_overlay",
                label: "discard overlay",
                command: format!("agentbox review-discard {session_id}"),
                mutates_workspace: true,
                requires_message: false,
                description:
                    "Discard the projected review workspace without touching the lower workspace.",
            },
            ReviewAction {
                key: "q",
                id: "quit",
                label: "quit",
                command: "no mutation".to_string(),
                mutates_workspace: false,
                requires_message: false,
                description: "Exit the review menu without changing files.",
            },
        ],
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
    let operator_commands = remote_session_operator_commands(session);
    if !operator_commands.is_empty() {
        println!("remote:");
        for command in operator_commands {
            println!("  {}", command);
        }
    }
}

fn remote_session_operator_commands(
    session: &agentbox_daemon::runtime::types::RuntimeSession,
) -> Vec<String> {
    if session.provider != "remote-agentpod" {
        return Vec::new();
    }
    if !session
        .spec
        .labels
        .contains_key(REMOTE_LABEL_WORKER_SESSION)
    {
        return Vec::new();
    }
    vec![
        format!("agentbox remote-evidence-status --session {}", session.id),
        format!(
            "agentbox remote-workspace-export --session {} --output-dir ./agentbox-workspace-review",
            session.id
        ),
        format!(
            "agentbox remote-evidence-upload --session {} --bundle-dir ./agentbox-evidence",
            session.id
        ),
        format!(
            "agentbox remote-evidence-stream --session {} --file ./stdout.txt",
            session.id
        ),
    ]
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
        Commands::Clean => cmd_clean(),
        Commands::Setup {
            json,
            wizard,
            dry_run,
            provider,
            endpoint,
        } => cmd_setup(json, wizard, dry_run, provider, endpoint),
        Commands::Stop => cmd_stop(),
        Commands::Status => cmd_status(),
        Commands::Doctor { json } => cmd_doctor(json),
        Commands::SetupPlan { json, provider } => cmd_setup_plan(json, provider),
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
            json,
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
                json,
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
        Commands::Pods {
            json,
            watch,
            interval_seconds,
            provider,
            status,
        } => cmd_pods(json, watch, interval_seconds, provider, status).await,
        Commands::Sessions {
            json,
            watch,
            interval_seconds,
            provider,
            status,
        } => cmd_pods(json, watch, interval_seconds, provider, status).await,
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
            bundle_dir,
        } => cmd_evidence(limit, verify, session, credentials, network, bundle_dir),
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
        Commands::BridgeHealth { json, provider } => cmd_bridge_health(json, provider),
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
        Commands::RemoteEvidence {
            session_id,
            worker_session_id,
            evidence,
            bundle_sha256,
            event_count,
            bundle_dir,
        } => cmd_remote_evidence(
            session_id,
            worker_session_id,
            evidence,
            bundle_sha256,
            event_count,
            bundle_dir,
        ),
        Commands::RemoteEvidenceStatus {
            endpoint,
            session_id,
            worker_session_id,
        } => cmd_remote_evidence_status(endpoint, session_id, worker_session_id).await,
        Commands::RemoteEvidenceUpload {
            endpoint,
            session_id,
            worker_session_id,
            bundle_dir,
        } => cmd_remote_evidence_upload(endpoint, session_id, worker_session_id, bundle_dir).await,
        Commands::RemoteEvidenceStream {
            endpoint,
            session_id,
            worker_session_id,
            stream_id,
            file,
            chunk_bytes,
        } => {
            cmd_remote_evidence_stream(
                endpoint,
                session_id,
                worker_session_id,
                stream_id,
                file,
                chunk_bytes,
            )
            .await
        }
        Commands::RemoteApprovalGrant {
            endpoint,
            session_id,
            worker_session_id,
            request_id,
            reason,
            ttl_seconds,
        } => {
            cmd_remote_approval_grant(
                endpoint,
                session_id,
                worker_session_id,
                request_id,
                reason,
                ttl_seconds,
            )
            .await
        }
        Commands::RemoteWorkspaceExport {
            endpoint,
            session_id,
            worker_session_id,
            output_dir,
            force,
            json,
        } => {
            cmd_remote_workspace_export(
                endpoint,
                session_id,
                worker_session_id,
                output_dir,
                force,
                json,
            )
            .await
        }
        Commands::RemoteWorkspaceApply {
            export_dir,
            workspace,
            dry_run,
            force,
            json,
        } => cmd_remote_workspace_apply(export_dir, workspace, dry_run, force, json),
        Commands::NativePlan {
            provider,
            workspace,
            agent_profile,
            risk,
            command,
        } => cmd_native_plan(provider, workspace, agent_profile, risk, command),
        Commands::MinipodInspect { session_id, json } => cmd_minipod_inspect(session_id, json),
        Commands::Review {
            session_id,
            json,
            patch,
            tui,
        } => cmd_review(session_id, json, patch, tui),
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

#[cfg(test)]
mod tests {
    use super::*;
    use agentbox_daemon::runtime::providers::remote::{
        RemoteAgentPodLifecycleEvent, RemoteAgentPodWorkspaceBundle,
        RemoteAgentPodWorkspaceExportResponse, RemoteAgentPodWorkspaceFile,
    };
    use agentbox_daemon::runtime::types::{
        AgentPodRiskLevel, AgentPodWorkspaceMode, MinipodSpec, RuntimeSession,
        SessionEvidenceBundle, WorkspaceWritePolicy,
    };

    #[test]
    fn entitlement_parser_detects_xml_and_plain_keys() {
        let plist = r#"
        <dict>
          <key>com.apple.developer.endpoint-security.client</key>
          <true/>
        </dict>
        "#;
        let plain = "com.apple.developer.networking.networkextension: packet-tunnel-provider";

        assert!(entitlements_contain_key(
            plist,
            "com.apple.developer.endpoint-security.client"
        ));
        assert!(entitlements_contain_key(
            plain,
            "com.apple.developer.networking.networkextension"
        ));
        assert!(!entitlements_contain_key(
            plist,
            "com.apple.developer.networking.networkextension"
        ));
    }

    #[test]
    fn macos_native_doctor_checks_keep_execution_unavailable() {
        let checks = macos_native_doctor_checks();

        assert_eq!(checks[0].name, "macOS native plan");
        assert!(checks[0].ok);
        assert!(checks[0]
            .detail
            .contains("provider execution remains unavailable"));
        assert!(checks
            .iter()
            .any(|check| check.name == "Apple Virtualization"));
        assert!(checks
            .iter()
            .any(|check| check.name == "Endpoint Security entitlement"));
        assert!(checks
            .iter()
            .any(|check| check.name == "Network Extension entitlement"));
        assert!(checks
            .iter()
            .filter(|check| check.name.contains("entitlement"))
            .all(|check| !check.release_blocker));
    }

    #[test]
    fn linux_native_doctor_checks_do_not_claim_live_sandbox() {
        let checks = linux_native_doctor_checks();

        assert_eq!(checks[0].name, "Linux native plan");
        assert!(checks[0].ok);
        assert!(checks[0].detail.contains("compiler available"));
        assert!(checks[0].detail.contains("AGENTBOX_LINUX_NATIVE=1"));
        assert!(checks.iter().any(|check| check.name == "Linux seccomp"));
        assert!(checks
            .iter()
            .any(|check| check.name == "Linux Landlock ABI"));
    }

    #[test]
    fn windows_native_doctor_checks_keep_execution_unavailable() {
        let checks = windows_native_doctor_checks();

        assert_eq!(checks[0].name, "Windows native plan");
        assert!(checks[0].ok);
        assert!(checks[0]
            .detail
            .contains("provider execution remains unavailable"));
        assert!(checks
            .iter()
            .any(|check| check.name == "Windows Job Objects" && check.ok));
        assert!(checks
            .iter()
            .any(|check| check.name == "Windows WFP" && !check.ok));
        assert!(checks
            .iter()
            .any(|check| check.name == "Windows ETW" && !check.ok));
        assert!(checks
            .iter()
            .any(|check| check.name == "Windows VM boundary" && !check.ok));
    }

    #[test]
    fn native_plan_provider_auto_resolves_current_platform() {
        let provider = resolve_native_plan_provider("auto");

        if cfg!(target_os = "macos") {
            assert_eq!(provider, "agentpod-macos");
        } else if cfg!(target_os = "windows") {
            assert_eq!(provider, "agentpod-windows");
        } else {
            assert_eq!(provider, "agentpod-linux");
        }
        assert_eq!(
            resolve_native_plan_provider("agentpod-windows"),
            "agentpod-windows"
        );
    }

    #[test]
    fn native_plan_json_contract_covers_all_platform_providers() {
        let workspace = PathBuf::from("/tmp/agentbox-native-plan-test");

        for (provider, required_field, claim_fragment) in [
            ("agentpod-linux", "user_namespace", "prototype"),
            (
                "agentpod-macos",
                "endpoint_security",
                "execution is not wired",
            ),
            ("agentpod-windows", "job_object", "execution is not wired"),
        ] {
            let plan = build_native_plan_json(
                provider,
                workspace.clone(),
                "general".into(),
                "high".into(),
                vec!["echo".into(), "demo".into()],
            )
            .unwrap();

            assert_eq!(plan["schema_version"], 1);
            assert_eq!(plan["provider"], provider);
            assert_eq!(plan["command_argv"][0], "echo");
            assert!(plan[required_field].is_object());
            assert!(plan["live_execution_enabled"].is_boolean());
            assert!(
                plan["security_claim"]
                    .as_str()
                    .unwrap()
                    .contains(claim_fragment),
                "{}",
                plan["security_claim"]
            );
        }
    }

    #[test]
    fn native_plan_json_rejects_empty_commands() {
        let err = build_native_plan_json(
            "agentpod-macos",
            PathBuf::from("/tmp/agentbox-native-plan-test"),
            "general".into(),
            "medium".into(),
            vec![],
        )
        .unwrap_err();

        assert!(err.contains("native plan command cannot be empty"));
    }

    #[test]
    fn bridge_health_rows_expose_provider_capability_contract() {
        let rows = provider_status_rows();

        assert!(rows.iter().all(|row| row.get("bridge_health").is_some()));
        let remote = rows
            .iter()
            .find(|row| row["provider"] == "remote-agentpod")
            .expect("remote provider should be listed");
        assert_eq!(
            remote["bridge_health"]["transports"][0],
            serde_json::json!("RemoteTunnel")
        );
        assert_eq!(
            remote["bridge_health"]["approval"]["supported"],
            serde_json::json!(true)
        );
        assert_eq!(
            bridge_readiness(remote)["verdict"],
            serde_json::json!("endpoint-gated")
        );

        let direct = rows
            .iter()
            .find(|row| row["provider"] == "direct-host")
            .expect("direct host provider should be listed");
        assert_eq!(
            bridge_health_cell(&direct["bridge_health"]["policy"]),
            "active"
        );

        assert_eq!(
            bridge_health_cell(&serde_json::json!({
                "supported": true,
                "active": false
            })),
            "supported"
        );
    }

    #[test]
    fn workspace_mode_defaults_to_overlay_review_for_autonomous_risk() {
        for risk in [
            AgentPodRiskLevel::Medium,
            AgentPodRiskLevel::High,
            AgentPodRiskLevel::VeryHigh,
        ] {
            let mut spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
            spec.risk = risk.clone();

            apply_workspace_mode(&mut spec, &risk, None, None);

            assert_eq!(spec.workspace_mode, AgentPodWorkspaceMode::OverlayReview);
            assert!(matches!(
                spec.filesystem.workspace_write_policy,
                WorkspaceWritePolicy::WritableOverlay
            ));
            assert!(spec.filesystem.workspace_overlay.is_enabled());
            assert_eq!(
                spec.labels.get("agentbox.workspace_mode"),
                Some(&"overlay-review".to_string())
            );
        }
    }

    #[test]
    fn workspace_mode_keeps_direct_for_low_risk_or_explicit_direct() {
        let mut low = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        low.risk = AgentPodRiskLevel::Low;
        apply_workspace_mode(&mut low, &AgentPodRiskLevel::Low, None, None);
        assert_eq!(low.workspace_mode, AgentPodWorkspaceMode::Direct);
        assert!(matches!(
            low.filesystem.workspace_write_policy,
            WorkspaceWritePolicy::Direct
        ));
        assert!(!low.filesystem.workspace_overlay.is_enabled());

        let mut high = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        high.risk = AgentPodRiskLevel::High;
        apply_workspace_mode(&mut high, &AgentPodRiskLevel::High, Some("direct"), None);
        assert_eq!(high.workspace_mode, AgentPodWorkspaceMode::Direct);
        assert!(matches!(
            high.filesystem.workspace_write_policy,
            WorkspaceWritePolicy::Direct
        ));
        assert!(!high.filesystem.workspace_overlay.is_enabled());
    }

    #[test]
    fn default_workspace_overlay_base_avoids_workspace_root() {
        let mut spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        spec.id = "01overlaytest".into();
        spec.filesystem.workspace_host_path = agentbox_dir();

        let overlay_base =
            default_workspace_overlay_base(&spec, &AgentPodWorkspaceMode::OverlayReview);

        assert!(!normalize_cli_path(&overlay_base)
            .starts_with(normalize_cli_path(&spec.filesystem.workspace_host_path)));
        assert!(overlay_base.starts_with(std::env::temp_dir()));
    }

    #[test]
    fn doctor_report_counts_failed_checks_for_json_output() {
        let report = doctor_report(vec![
            doctor_check("ready", true, "ok".into(), "none"),
            doctor_check("missing", false, "not found".into(), "install it"),
            doctor_advisory_check("planned", false, "not wired".into(), "track roadmap"),
        ]);

        assert_eq!(report.schema_version, 1);
        assert_eq!(report.ok, 1);
        assert_eq!(report.failed, 2);
        assert_eq!(report.required_failed, 1);
        assert_eq!(report.advisory_failed, 1);
        assert_eq!(report.checks.len(), 3);
        let payload = serde_json::to_value(&report).unwrap();
        assert_eq!(payload["checks"][1]["name"], "missing");
        assert_eq!(payload["checks"][1]["severity"], "required");
        assert_eq!(payload["checks"][1]["release_blocker"], true);
        assert_eq!(payload["checks"][1]["fix"], "install it");
        assert_eq!(payload["checks"][2]["severity"], "advisory");
        assert_eq!(payload["checks"][2]["release_blocker"], false);
    }

    #[test]
    fn daemon_socket_doctor_check_distinguishes_stale_socket() {
        let stale = daemon_socket_doctor_check(true, false, "/tmp/agentbox.sock".into());
        assert!(!stale.ok);
        assert!(stale.required);
        assert_eq!(stale.name, "daemon socket");
        assert!(stale.detail.contains("stale socket"));
        assert!(stale.fix.contains("agentbox clean"));

        let missing = daemon_socket_doctor_check(false, false, "/tmp/agentbox.sock".into());
        assert!(!missing.ok);
        assert!(missing.detail.contains("missing socket"));
        assert_eq!(missing.fix, "run `agentbox start`");

        let ready = daemon_socket_doctor_check(true, true, "/tmp/agentbox.sock".into());
        assert!(ready.ok);
        assert_eq!(ready.fix, "none");
    }

    #[test]
    fn setup_plan_recommends_clean_for_stale_socket() {
        let report = doctor_report(vec![daemon_socket_doctor_check(
            true,
            false,
            "/tmp/agentbox.sock".into(),
        )]);

        let plan = setup_plan_from_doctor(&report, Some("direct-host"));

        assert_eq!(plan.steps.len(), 1);
        assert_eq!(
            plan.steps[0].command.as_deref(),
            Some("agentbox clean && agentbox start")
        );
    }

    #[test]
    fn daemon_socket_status_line_reports_stale_socket() {
        assert_eq!(
            daemon_socket_status_line(true, false),
            Some("stale socket file")
        );
        assert_eq!(daemon_socket_status_line(true, true), Some("ready"));
        assert_eq!(
            daemon_socket_status_line(false, true),
            Some("missing while daemon appears to be running")
        );
        assert_eq!(daemon_socket_status_line(false, false), None);
    }

    #[test]
    fn setup_plan_prioritizes_required_next_command() {
        let report = doctor_report(vec![
            doctor_advisory_check(
                "Endpoint Security entitlement",
                false,
                "missing".into(),
                "sign extension",
            ),
            doctor_check(
                "agentbox-shim binary",
                false,
                "not found".into(),
                "run `cargo build --release` or put agentbox-shim on PATH",
            ),
            doctor_check(
                "installed shims",
                false,
                "0 shims".into(),
                "run `agentbox install`",
            ),
        ]);

        let plan = setup_plan_from_doctor(&report, None);

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.required_failed, 2);
        assert_eq!(plan.advisory_failed, 1);
        assert!(!plan.ready_for_required_setup);
        assert_eq!(plan.next_command.as_deref(), Some("cargo build --release"));
        assert_eq!(plan.steps[0].severity, "required");
        assert_eq!(
            plan.steps[0].command.as_deref(),
            Some("cargo build --release")
        );
        assert_eq!(plan.steps.last().unwrap().severity, "advisory");

        let payload = serde_json::to_value(&plan).unwrap();
        assert_eq!(payload["steps"][0]["release_blocker"], true);
        assert_eq!(payload["steps"][2]["release_blocker"], false);
    }

    #[test]
    fn setup_plan_can_filter_by_provider() {
        let report = doctor_report(vec![
            doctor_check(
                "daemon socket",
                false,
                "missing".into(),
                "run `agentbox start`",
            ),
            doctor_check("podman provider", false, "missing".into(), "install Podman"),
            doctor_advisory_check(
                "remote-agentpod endpoint",
                false,
                "missing".into(),
                "set endpoint",
            ),
        ]);

        let remote = setup_plan_from_doctor(&report, Some("remote-agentpod"));
        assert_eq!(remote.provider.as_deref(), Some("remote-agentpod"));
        assert_eq!(remote.required_failed, 0);
        assert_eq!(remote.advisory_failed, 1);
        assert_eq!(remote.steps.len(), 1);
        assert_eq!(remote.steps[0].check, "remote-agentpod endpoint");

        let podman = setup_plan_from_doctor(&report, Some("podman"));
        assert_eq!(podman.provider.as_deref(), Some("podman"));
        assert_eq!(podman.required_failed, 1);
        assert_eq!(podman.steps[0].check, "podman provider");
    }

    #[test]
    fn setup_shim_install_scope_matches_provider() {
        assert!(setup_should_install_shims(None));
        assert!(setup_should_install_shims(Some("all")));
        assert!(setup_should_install_shims(Some("direct-host")));
        assert!(!setup_should_install_shims(Some("podman")));
        assert!(!setup_should_install_shims(Some("remote-agentpod")));
        assert!(!setup_should_install_shims(Some("agentpod-macos")));
    }

    #[test]
    fn setup_operator_commands_are_stable_and_deduplicated() {
        let report = doctor_report(vec![
            doctor_check(
                "daemon socket",
                false,
                "missing".into(),
                "run `agentbox start`",
            ),
            doctor_check(
                "daemon process",
                false,
                "missing".into(),
                "run `agentbox start`",
            ),
            doctor_advisory_check(
                "remote-agentpod endpoint",
                false,
                "missing".into(),
                "set endpoint",
            ),
        ]);
        let plan = setup_plan_from_doctor(&report, Some("all"));
        let commands = setup_operator_commands(&plan, Some("all"), None);

        assert_eq!(
            commands,
            vec![
                "agentbox bridge-health".to_string(),
                "agentbox start".to_string(),
                "export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://worker.example.com/agentpod"
                    .to_string()
            ]
        );
    }

    #[test]
    fn setup_operator_commands_use_explicit_remote_endpoint() {
        let report = doctor_report(vec![doctor_advisory_check(
            "remote-agentpod endpoint",
            false,
            "missing".into(),
            "set endpoint",
        )]);
        let plan = setup_plan_from_doctor(&report, Some("remote-agentpod"));
        let commands = setup_operator_commands(
            &plan,
            Some("remote-agentpod"),
            Some("https://agentpod.example.com/run"),
        );

        assert_eq!(
            commands,
            vec![
                "agentbox bridge-health --provider remote-agentpod".to_string(),
                "agentbox remote-handshake --endpoint https://agentpod.example.com/run".to_string(),
                "export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://agentpod.example.com/run"
                    .to_string()
            ]
        );
    }

    #[test]
    fn pod_session_filters_match_provider_and_status() {
        let mut direct = RuntimeSession::new(
            "direct".into(),
            "direct-host".into(),
            "macos".into(),
            MinipodSpec::for_agent_task("codex", "/tmp/agentbox-direct"),
        );
        direct.status = agentbox_daemon::runtime::types::RuntimeStatus::Running;
        let mut remote = RuntimeSession::new(
            "remote".into(),
            "remote-agentpod".into(),
            "remote".into(),
            MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-remote"),
        );
        remote.status = agentbox_daemon::runtime::types::RuntimeStatus::Stopped;

        let filtered = filter_pod_sessions(
            vec![direct, remote],
            Some("remote-agentpod"),
            Some("stopped"),
        );

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].provider, "remote-agentpod");
        assert!(matches!(
            filtered[0].status,
            agentbox_daemon::runtime::types::RuntimeStatus::Stopped
        ));
    }

    #[test]
    fn remote_evidence_status_metadata_can_use_persisted_session_labels() {
        let mut session = RuntimeSession::new(
            "remote".into(),
            "remote-agentpod".into(),
            "remote".into(),
            MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-remote"),
        );
        session.spec.labels.insert(
            REMOTE_LABEL_ENDPOINT.into(),
            "https://worker.example.com/agentpod".into(),
        );
        session.spec.labels.insert(
            REMOTE_LABEL_WORKER_SESSION.into(),
            "worker-session-1".into(),
        );

        let (endpoint, worker_session_id) =
            remote_session_metadata_from_session(&session, None, None).unwrap();

        assert_eq!(endpoint, "https://worker.example.com/agentpod");
        assert_eq!(worker_session_id, "worker-session-1");
    }

    #[test]
    fn remote_evidence_status_metadata_allows_explicit_overrides() {
        let session = RuntimeSession::new(
            "remote".into(),
            "remote-agentpod".into(),
            "remote".into(),
            MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-remote"),
        );

        let (endpoint, worker_session_id) = remote_session_metadata_from_session(
            &session,
            Some("https://override.example.com/agentpod".into()),
            Some("override-worker".into()),
        )
        .unwrap();

        assert_eq!(endpoint, "https://override.example.com/agentpod");
        assert_eq!(worker_session_id, "override-worker");
    }

    #[test]
    fn remote_session_operator_commands_use_local_session_metadata() {
        let mut session = RuntimeSession::new(
            "remote".into(),
            "remote-agentpod".into(),
            "remote".into(),
            MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-remote"),
        );
        session.spec.labels.insert(
            REMOTE_LABEL_ENDPOINT.into(),
            "https://worker.example.com/agentpod".into(),
        );
        session.spec.labels.insert(
            REMOTE_LABEL_WORKER_SESSION.into(),
            "worker-session-1".into(),
        );

        let commands = remote_session_operator_commands(&session);
        let session_id = session.id.clone();

        assert_eq!(
            commands,
            vec![
                format!("agentbox remote-evidence-status --session {session_id}"),
                format!(
                    "agentbox remote-workspace-export --session {session_id} --output-dir ./agentbox-workspace-review"
                ),
                format!(
                    "agentbox remote-evidence-upload --session {session_id} --bundle-dir ./agentbox-evidence"
                ),
                format!("agentbox remote-evidence-stream --session {session_id} --file ./stdout.txt"),
            ]
        );
    }

    #[test]
    fn remote_agentpod_endpoint_status_matches_transport_rules() {
        assert!(!remote_agentpod_endpoint_status("", false).0);
        assert!(remote_agentpod_endpoint_status("https://worker.example.com/agentpod", false).0);
        assert!(remote_agentpod_endpoint_status("ssh://agentpod@example.com", false).0);
        assert!(!remote_agentpod_endpoint_status("http://worker.example.com/agentpod", true).0);
        assert!(!remote_agentpod_endpoint_status("http://127.0.0.1:63000/agentpod", false).0);
        assert!(remote_agentpod_endpoint_status("http://127.0.0.1:63000/agentpod", true).0);
        assert!(
            !remote_agentpod_endpoint_status("https://token@worker.example.com/agentpod", false).0
        );
    }

    #[test]
    fn utf8_chunks_preserve_offsets_and_character_boundaries() {
        let chunks = utf8_chunks("abcédef", 4).unwrap();

        assert_eq!(
            chunks,
            vec![
                (0, "abc".to_string()),
                (3, "éde".to_string()),
                (7, "f".to_string())
            ]
        );
    }

    #[test]
    fn utf8_chunks_reject_zero_chunk_size() {
        assert!(utf8_chunks("hello", 0).is_err());
    }

    #[test]
    fn evidence_bundle_dir_writes_expected_files() {
        let spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        let session = RuntimeSession::new(
            spec.name.clone(),
            "direct-host".into(),
            "macos".into(),
            spec,
        );
        let bundle = SessionEvidenceBundle::from_session_events(&session, &[]);
        let output_dir = std::env::temp_dir().join(format!(
            "agentbox-evidence-bundle-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&output_dir);

        write_session_evidence_bundle_dir(&bundle, &output_dir).unwrap();

        for file in [
            "index.json",
            "bundle.json",
            "manifest.json",
            "replay.json",
            "transcripts.json",
            "integrations.json",
        ] {
            assert!(output_dir.join(file).exists(), "{file} was not written");
        }

        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(output_dir.join("index.json")).unwrap()).unwrap();
        assert_eq!(index["schema_version"], 1);
        assert_eq!(index["session_id"], bundle.session_id);
        assert_eq!(index["root_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(index["files"].as_array().unwrap().len(), 5);
        for file in index["files"].as_array().unwrap() {
            assert_eq!(file["sha256"].as_str().unwrap().len(), 64);
            assert!(file["bytes"].as_u64().unwrap() > 0);
        }
        assert_eq!(verify_evidence_bundle_dir(&output_dir).unwrap(), 5);

        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn evidence_bundle_dir_verification_detects_tampering() {
        let spec = MinipodSpec::for_agent_task("codex", "/tmp/agentbox-work");
        let session = RuntimeSession::new(
            spec.name.clone(),
            "direct-host".into(),
            "macos".into(),
            spec,
        );
        let bundle = SessionEvidenceBundle::from_session_events(&session, &[]);
        let output_dir = std::env::temp_dir().join(format!(
            "agentbox-evidence-bundle-tamper-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&output_dir);
        write_session_evidence_bundle_dir(&bundle, &output_dir).unwrap();

        fs::write(output_dir.join("manifest.json"), b"{\"tampered\":true}").unwrap();

        let err = verify_evidence_bundle_dir(&output_dir).unwrap_err();
        assert!(err.contains("mismatch"), "{err}");

        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn remote_evidence_metadata_can_be_derived_from_bundle_dir() {
        let output_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-evidence-bundle-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&output_dir);
        fs::create_dir_all(&output_dir).unwrap();

        let bundle_json = serde_json::json!({
            "schema_version": 1,
            "commands": [{"audit_event_id": "evt_1"}],
            "approvals": [],
            "lifecycle_events": [],
            "boundary_events": [],
            "credential_events": []
        });
        let files =
            vec![
                write_bundle_json_file(&output_dir, "bundle.json", "test bundle", &bundle_json)
                    .unwrap(),
            ];
        let index = EvidenceBundleIndex {
            schema_version: 1,
            bundle_id: "bundle-test".into(),
            session_id: "session-test".into(),
            provider: "direct-host".into(),
            status: "Stopped".into(),
            root_sha256: evidence_bundle_root_sha256(&files),
            generated_at: Utc::now(),
            files,
        };
        fs::write(
            output_dir.join("index.json"),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();

        let metadata = load_remote_evidence_metadata_from_bundle(&output_dir).unwrap();
        assert_eq!(metadata.bundle_id, index.bundle_id);
        assert_eq!(metadata.root_sha256, index.root_sha256);
        assert_eq!(metadata.event_count, 1);

        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn remote_evidence_upload_payload_wraps_verified_bundle_dir() {
        let output_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-evidence-upload-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&output_dir);
        fs::create_dir_all(&output_dir).unwrap();

        let bundle_json = serde_json::json!({
            "schema_version": 1,
            "commands": [{"audit_event_id": "evt_1"}],
            "approvals": [],
            "lifecycle_events": [],
            "boundary_events": [],
            "credential_events": []
        });
        let files =
            vec![
                write_bundle_json_file(&output_dir, "bundle.json", "test bundle", &bundle_json)
                    .unwrap(),
            ];
        let index = EvidenceBundleIndex {
            schema_version: 1,
            bundle_id: "bundle-test".into(),
            session_id: "session-test".into(),
            provider: "direct-host".into(),
            status: "Stopped".into(),
            root_sha256: evidence_bundle_root_sha256(&files),
            generated_at: Utc::now(),
            files,
        };
        fs::write(
            output_dir.join("index.json"),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();

        let payload = build_remote_evidence_bundle_upload_payload(
            &output_dir,
            "session-test",
            "worker-session-test",
        )
        .unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&payload.envelope_json).unwrap();

        assert_eq!(payload.bundle_id, "bundle-test");
        assert_eq!(payload.root_sha256, index.root_sha256);
        assert_eq!(payload.event_count, 1);
        assert_eq!(
            payload.envelope_sha256,
            sha256_hex(payload.envelope_json.as_bytes())
        );
        assert_eq!(envelope["kind"], "AgentboxEvidenceBundleUpload");
        assert_eq!(envelope["session_id"], "session-test");
        assert_eq!(envelope["worker_session_id"], "worker-session-test");
        assert!(envelope["files"]["bundle.json"].is_string());

        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn remote_evidence_upload_payload_rejects_session_mismatch() {
        let output_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-evidence-upload-mismatch-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&output_dir);
        fs::create_dir_all(&output_dir).unwrap();

        let bundle_json = serde_json::json!({
            "schema_version": 1,
            "commands": [{"audit_event_id": "evt_1"}],
        });
        let files =
            vec![
                write_bundle_json_file(&output_dir, "bundle.json", "test bundle", &bundle_json)
                    .unwrap(),
            ];
        let index = EvidenceBundleIndex {
            schema_version: 1,
            bundle_id: "bundle-test".into(),
            session_id: "session-test".into(),
            provider: "direct-host".into(),
            status: "Stopped".into(),
            root_sha256: evidence_bundle_root_sha256(&files),
            generated_at: Utc::now(),
            files,
        };
        fs::write(
            output_dir.join("index.json"),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();

        let err = build_remote_evidence_bundle_upload_payload(
            &output_dir,
            "other-session",
            "worker-session-test",
        )
        .unwrap_err();

        assert!(err.contains("does not match requested session"));
        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn remote_workspace_export_writes_verified_files_and_manifest() {
        let output_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-workspace-export-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&output_dir);
        let file = remote_workspace_file("src/main.rs", "fn main() {}\n");
        let response = remote_workspace_export_response(vec![file]);

        let manifest = write_remote_workspace_export_dir(&response, &output_dir, false).unwrap();

        assert_eq!(manifest.session_id, "session-test");
        assert_eq!(manifest.worker_session_id, "worker-session-test");
        assert_eq!(manifest.file_count, 1);
        assert_eq!(manifest.total_bytes, "fn main() {}\n".len());
        assert_eq!(
            fs::read_to_string(output_dir.join("src/main.rs")).unwrap(),
            "fn main() {}\n"
        );
        assert!(output_dir.join("agentbox-workspace-export.json").exists());

        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn remote_workspace_export_rejects_non_empty_output_dir() {
        let output_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-workspace-export-nonempty-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&output_dir);
        fs::create_dir_all(&output_dir).unwrap();
        fs::write(output_dir.join("existing.txt"), b"do not overwrite").unwrap();
        let response = remote_workspace_export_response(vec![remote_workspace_file(
            "README.md",
            "remote workspace\n",
        )]);

        let err = write_remote_workspace_export_dir(&response, &output_dir, false).unwrap_err();

        assert!(err.contains("not empty"), "{err}");
        assert_eq!(
            fs::read_to_string(output_dir.join("existing.txt")).unwrap(),
            "do not overwrite"
        );
        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn remote_workspace_apply_writes_verified_export_to_workspace() {
        let export_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-workspace-apply-export-test-{}",
            std::process::id()
        ));
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-workspace-apply-target-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&export_dir);
        let _ = fs::remove_dir_all(&workspace);
        let response = remote_workspace_export_response(vec![remote_workspace_file(
            "src/main.rs",
            "fn main() {}\n",
        )]);
        write_remote_workspace_export_dir(&response, &export_dir, false).unwrap();

        let report =
            apply_remote_workspace_export_dir(&export_dir, &workspace, false, false).unwrap();

        assert_eq!(report.applied_files, 1);
        assert_eq!(report.conflict_files, 0);
        assert_eq!(
            fs::read_to_string(workspace.join("src/main.rs")).unwrap(),
            "fn main() {}\n"
        );
        let _ = fs::remove_dir_all(export_dir);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn remote_workspace_apply_reports_conflicts_without_overwrite() {
        let export_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-workspace-apply-conflict-export-test-{}",
            std::process::id()
        ));
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-workspace-apply-conflict-target-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&export_dir);
        let _ = fs::remove_dir_all(&workspace);
        let response =
            remote_workspace_export_response(vec![remote_workspace_file("README.md", "new\n")]);
        write_remote_workspace_export_dir(&response, &export_dir, false).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("README.md"), b"old\n").unwrap();

        let dry_run =
            apply_remote_workspace_export_dir(&export_dir, &workspace, true, false).unwrap();
        let err =
            apply_remote_workspace_export_dir(&export_dir, &workspace, false, false).unwrap_err();

        assert_eq!(dry_run.conflict_files, 1);
        assert_eq!(dry_run.files[0].action, "conflict");
        assert!(err.contains("already exist"), "{err}");
        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).unwrap(),
            "old\n"
        );
        let _ = fs::remove_dir_all(export_dir);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn remote_workspace_apply_skips_identical_existing_files() {
        let export_dir = std::env::temp_dir().join(format!(
            "agentbox-remote-workspace-apply-unchanged-export-test-{}",
            std::process::id()
        ));
        let workspace = std::env::temp_dir().join(format!(
            "agentbox-remote-workspace-apply-unchanged-target-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&export_dir);
        let _ = fs::remove_dir_all(&workspace);
        let response =
            remote_workspace_export_response(vec![remote_workspace_file("README.md", "same\n")]);
        write_remote_workspace_export_dir(&response, &export_dir, false).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("README.md"), b"same\n").unwrap();

        let dry_run =
            apply_remote_workspace_export_dir(&export_dir, &workspace, true, false).unwrap();
        let report =
            apply_remote_workspace_export_dir(&export_dir, &workspace, false, false).unwrap();

        assert_eq!(dry_run.conflict_files, 0);
        assert_eq!(dry_run.unchanged_files, 1);
        assert_eq!(dry_run.files[0].action, "unchanged");
        assert_eq!(dry_run.files[0].target_bytes, Some(5));
        assert_eq!(
            dry_run.files[0].target_sha256.as_deref(),
            Some(dry_run.files[0].sha256.as_str())
        );
        assert_eq!(report.applied_files, 0);
        assert_eq!(report.skipped_files, 1);
        assert_eq!(report.unchanged_files, 1);
        assert_eq!(report.conflict_files, 0);
        assert_eq!(report.files[0].action, "unchanged");
        let _ = fs::remove_dir_all(export_dir);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn review_action_plan_exposes_stable_operator_commands() {
        let plan = review_action_plan("session-123");

        assert_eq!(plan.schema_version, 1);
        assert_eq!(plan.session_id, "session-123");
        assert_eq!(plan.actions.len(), 5);
        assert_eq!(plan.actions[0].id, "print_patch");
        assert_eq!(
            plan.actions[0].command,
            "agentbox review session-123 --patch"
        );
        assert!(!plan.actions[0].mutates_workspace);
        assert_eq!(plan.actions[1].id, "apply_changes");
        assert_eq!(plan.actions[1].command, "agentbox review-apply session-123");
        assert!(plan.actions[1].mutates_workspace);
        assert_eq!(plan.actions[2].id, "commit_changes");
        assert!(plan.actions[2].requires_message);
        assert_eq!(
            plan.actions[2].command,
            "agentbox review-commit session-123 --message \"agent output\""
        );
        assert_eq!(plan.actions[3].id, "discard_overlay");
        assert_eq!(
            plan.actions[3].command,
            "agentbox review-discard session-123"
        );
        assert_eq!(plan.actions[4].id, "quit");

        let payload = serde_json::to_value(&plan).unwrap();
        assert_eq!(payload["actions"][1]["label"], "apply changes");
        assert_eq!(payload["actions"][1]["mutates_workspace"], true);
        assert_eq!(payload["actions"][4]["command"], "no mutation");
    }

    fn remote_workspace_file(path: &str, contents: &str) -> RemoteAgentPodWorkspaceFile {
        RemoteAgentPodWorkspaceFile {
            path: path.to_string(),
            media_type: "text/plain; charset=utf-8".into(),
            sha256: sha256_hex(contents.as_bytes()),
            bytes: contents.len(),
            contents_utf8: contents.to_string(),
        }
    }

    fn remote_workspace_export_response(
        files: Vec<RemoteAgentPodWorkspaceFile>,
    ) -> RemoteAgentPodWorkspaceExportResponse {
        let root_sha256 = remote_workspace_bundle_root_sha256(&files);
        RemoteAgentPodWorkspaceExportResponse {
            session_id: "session-test".into(),
            worker_session_id: "worker-session-test".into(),
            status: agentbox_daemon::runtime::types::RuntimeStatus::Running,
            workspace_bundle: RemoteAgentPodWorkspaceBundle {
                schema_version: 1,
                root_sha256,
                files,
                secret_material_included: false,
            },
            lifecycle_events: vec![RemoteAgentPodLifecycleEvent::EvidenceSealed],
        }
    }

    fn remote_workspace_bundle_root_sha256(files: &[RemoteAgentPodWorkspaceFile]) -> String {
        let mut entries = files
            .iter()
            .map(|file| {
                format!(
                    "{}\0{}\0{}\0{}",
                    file.path, file.sha256, file.bytes, file.media_type
                )
            })
            .collect::<Vec<_>>();
        entries.sort();
        sha256_hex(format!("agentbox-workspace-root-v1\n{}", entries.join("\n")).as_bytes())
    }
}
