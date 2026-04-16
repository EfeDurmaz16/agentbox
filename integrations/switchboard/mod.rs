//! # Switchboard <-> Agentbox Integration
//!
//! Reference integration showing how [Switchboard](https://github.com/user/switchboard)'s
//! `sb-policy` crate can delegate policy decisions to the Agentbox daemon.
//!
//! This module is **not compiled** as part of the Agentbox workspace. It lives here
//! as a reference for anyone wiring Switchboard to Agentbox. Copy the pieces you
//! need into your Switchboard fork or plugin crate.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐      ┌──────────────────────┐      ┌──────────────────┐
//! │  Switchboard │─────>│ AgentboxPolicyBackend │─────>│ Agentbox Daemon  │
//! │  (sb-policy) │      │ (this module)         │      │ (Unix socket)    │
//! └─────────────┘      └──────────────────────┘      └──────────────────┘
//!        │                                                     │
//!        │  AgentboxEventForwarder                             │
//!        └─────────── audit events ───────────────────────────>│
//! ```
//!
//! Three integration points:
//!
//! 1. **`AgentboxPolicyBackend`** — Switchboard calls `evaluate_command()` before
//!    spawning any subprocess. The backend delegates to the Agentbox daemon over
//!    its Unix socket and maps the response to Switchboard's `PolicyDecision` enum.
//!
//! 2. **`inject_agentbox_env()`** — Called when Switchboard builds the environment
//!    for a spawned agent process. Prepends the Agentbox shim directory to `PATH`
//!    so that dangerous commands hit the shim before the real binary.
//!
//! 3. **`AgentboxEventForwarder`** — Receives Switchboard `AgentEvent`s (tool calls,
//!    file edits, etc.) and forwards them to the Agentbox audit log via the daemon
//!    socket. This gives you a unified audit trail even for actions that bypass shims.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use std::collections::HashMap;
//!
//! // In your Switchboard policy layer setup:
//! let backend = AgentboxPolicyBackend::new();
//!
//! if !backend.is_available() {
//!     eprintln!("warning: agentbox daemon not running, falling back to default policy");
//! }
//!
//! // Before executing a command on behalf of an agent:
//! let decision = backend.evaluate_command("git", &["push".into()], "/repo", "claude-code");
//! match decision {
//!     PolicyDecision::Allow { reason } => { /* proceed */ }
//!     PolicyDecision::Deny { reason } => { /* reject with reason */ }
//!     PolicyDecision::Approve { reason, notification } => {
//!         // Agentbox already sent the phone notification and waited for the
//!         // user's response. If we reach Approve here, the user said yes.
//!         /* proceed */
//!     }
//! }
//!
//! // When spawning an agent subprocess, inject Agentbox into its environment:
//! let mut env: HashMap<String, String> = std::env::vars().collect();
//! inject_agentbox_env(&mut env);
//! // Now pass `env` to Command::new(...).envs(env)
//!
//! // Optionally, forward Switchboard events to the Agentbox audit log:
//! let forwarder = AgentboxEventForwarder::new("switchboard");
//! forwarder.forward_tool_call("bash", &["rm", "-rf", "node_modules"], "/repo");
//! forwarder.forward_file_edit("/repo/src/main.rs", "modified 3 lines");
//! ```

// ============================================================================
// Dependencies (when compiling as part of a real crate)
//
// [dependencies]
// agentbox-client = { path = "../../crates/agentbox-client" }
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"
// toml = "0.8"
// ============================================================================

use std::collections::HashMap;
use std::path::{Path, PathBuf};

// In a real build these come from the agentbox-client crate.
// Shown here with full paths for clarity.
use agentbox_client::{AgentboxClient, CheckRequest, CheckResponse, ClientError};

// ---------------------------------------------------------------------------
// Part 1: Policy Backend
// ---------------------------------------------------------------------------

/// Switchboard-native policy decision.
///
/// Agentbox uses 3 buckets (allow / approve / block). Switchboard uses a
/// slightly different vocabulary. This enum bridges the two:
///
/// | Agentbox decision | Maps to                  |
/// |--------------------|--------------------------|
/// | `allowed`          | `PolicyDecision::Allow`  |
/// | `approved`         | `PolicyDecision::Approve`|
/// | `denied`           | `PolicyDecision::Deny`   |
/// | `blocked`          | `PolicyDecision::Deny`   |
/// | `timed_out`        | `PolicyDecision::Deny`   |
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Command is safe — execute immediately.
    Allow { reason: String },
    /// Command was denied or blocked — do not execute.
    Deny { reason: String },
    /// Command required user approval, and the user approved it.
    /// `notification` contains the human-readable summary that was shown on
    /// the user's phone.
    Approve {
        reason: String,
        notification: String,
    },
}

/// Policy backend that delegates classification to the Agentbox daemon.
///
/// Plugs into Switchboard's `sb-policy` trait system. In your Switchboard
/// fork, implement `sb_policy::PolicyBackend` by calling `evaluate_command`.
///
/// ```rust,ignore
/// impl sb_policy::PolicyBackend for AgentboxPolicyBackend {
///     fn evaluate(&self, cmd: &sb_policy::Command) -> sb_policy::Decision {
///         let decision = self.evaluate_command(
///             &cmd.binary, &cmd.args, &cmd.cwd, &cmd.agent_name,
///         );
///         // Map PolicyDecision -> sb_policy::Decision here
///     }
/// }
/// ```
pub struct AgentboxPolicyBackend {
    client: AgentboxClient,
    /// What to do when the Agentbox daemon is unreachable.
    /// `true` = fail-open (allow), `false` = fail-closed (deny).
    fail_open: bool,
}

impl AgentboxPolicyBackend {
    /// Create a backend using the default socket path (`~/.agentbox/agentbox.sock`).
    pub fn new() -> Self {
        Self {
            client: AgentboxClient::new(),
            fail_open: false, // safety-first default for an agent orchestrator
        }
    }

    /// Create a backend pointing at a custom socket.
    pub fn with_socket(path: impl Into<PathBuf>) -> Self {
        Self {
            client: AgentboxClient::with_socket(path),
            fail_open: false,
        }
    }

    /// Set the fail-open policy.
    ///
    /// - `true`: if the daemon is down, allow commands (useful in dev).
    /// - `false`: if the daemon is down, deny everything (production default).
    pub fn set_fail_open(&mut self, fail_open: bool) {
        self.fail_open = fail_open;
    }

    /// Returns `true` if the Agentbox daemon socket exists on disk.
    pub fn is_available(&self) -> bool {
        self.client.is_available()
    }

    /// Evaluate a command against Agentbox policy.
    ///
    /// This call **blocks** until the daemon responds. For approve-bucket
    /// commands, this means waiting for the user's phone response (up to
    /// the configured timeout, default 120 seconds).
    ///
    /// # Arguments
    ///
    /// * `binary`     — The command name (e.g., `"git"`, `"rm"`, `"psql"`).
    /// * `args`       — Full argument list.
    /// * `cwd`        — Working directory the command would run in.
    /// * `agent_name` — Name of the agent requesting the action (for audit).
    pub fn evaluate_command(
        &self,
        binary: &str,
        args: &[String],
        cwd: &str,
        agent_name: &str,
    ) -> PolicyDecision {
        let req = CheckRequest {
            binary: binary.to_string(),
            args: args.to_vec(),
            cwd: cwd.to_string(),
            parent_process: agent_name.to_string(),
            pid: std::process::id(),
        };

        match self.client.check(&req) {
            Ok(resp) => map_response(resp),
            Err(e) => {
                // Daemon unreachable — apply fail-open/fail-closed policy.
                if self.fail_open {
                    PolicyDecision::Allow {
                        reason: format!("agentbox unavailable (fail-open): {e}"),
                    }
                } else {
                    PolicyDecision::Deny {
                        reason: format!("agentbox unavailable (fail-closed): {e}"),
                    }
                }
            }
        }
    }
}

/// Map an Agentbox `CheckResponse` to a Switchboard `PolicyDecision`.
fn map_response(resp: CheckResponse) -> PolicyDecision {
    match resp.decision.as_str() {
        "allowed" => PolicyDecision::Allow {
            reason: resp.reason,
        },
        "approved" => PolicyDecision::Approve {
            reason: resp.reason.clone(),
            notification: resp.reason, // daemon includes the notification summary in reason
        },
        "denied" | "blocked" | "timed_out" => PolicyDecision::Deny {
            reason: resp.reason,
        },
        // Unknown decision string — treat as deny (conservative).
        other => PolicyDecision::Deny {
            reason: format!("unknown agentbox decision '{}': {}", other, resp.reason),
        },
    }
}

// ---------------------------------------------------------------------------
// Part 2: Environment Injection
// ---------------------------------------------------------------------------

/// Inject Agentbox environment variables into a subprocess env map.
///
/// Call this before spawning an agent process so that its shell commands
/// hit Agentbox shims first. This function:
///
/// 1. **Prepends `~/.agentbox/shims`** to `PATH` so shim binaries for
///    dangerous commands (`rm`, `git`, `psql`, etc.) intercept calls before
///    the real binary is found.
///
/// 2. **Sets `AGENTBOX_SOCKET`** so the shim (and any direct client code)
///    knows where to reach the daemon.
///
/// 3. **Sets `AGENTBOX_TOPIC`** to the ntfy topic, read from
///    `~/.agentbox/config.toml` if available. This lets the agent (or
///    its tooling) display the topic to the user for manual subscription.
///
/// # Panics
///
/// Does not panic. If `$HOME` is unset or `config.toml` is missing/corrupt,
/// defaults are used silently.
pub fn inject_agentbox_env(env: &mut HashMap<String, String>) {
    let home = env
        .get("HOME")
        .cloned()
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_else(|| "/tmp".to_string());

    let agentbox_dir = Path::new(&home).join(".agentbox");
    let shim_dir = agentbox_dir.join("shims");
    let socket_path = agentbox_dir.join("agentbox.sock");

    // 1. Prepend shims to PATH
    let current_path = env
        .get("PATH")
        .cloned()
        .unwrap_or_else(|| "/usr/bin:/bin".to_string());

    let shim_str = shim_dir.to_string_lossy();

    // Avoid double-prepending if already present.
    if !current_path.split(':').any(|p| p == shim_str.as_ref()) {
        env.insert("PATH".to_string(), format!("{shim_str}:{current_path}"));
    }

    // 2. Set socket path
    env.insert(
        "AGENTBOX_SOCKET".to_string(),
        socket_path.to_string_lossy().to_string(),
    );

    // 3. Read ntfy topic from config.toml (best-effort)
    let config_path = agentbox_dir.join("config.toml");
    if let Some(topic) = read_ntfy_topic_from_config(&config_path) {
        env.insert("AGENTBOX_TOPIC".to_string(), topic);
    }
}

/// Try to read just the `ntfy_topic` field from a config.toml file.
///
/// Returns `None` if the file doesn't exist, can't be read, or doesn't
/// contain the field. We parse as a generic TOML table to avoid pulling
/// in the full daemon config struct (which lives in agentbox-daemon).
fn read_ntfy_topic_from_config(path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let table: toml::Table = contents.parse().ok()?;
    table
        .get("ntfy_topic")
        .and_then(|v| v.as_str())
        .map(String::from)
}

// ---------------------------------------------------------------------------
// Part 3: Event Forwarder
// ---------------------------------------------------------------------------

/// Forwards Switchboard agent events to the Agentbox audit log.
///
/// Switchboard tracks agent actions as `AgentEvent`s internally. This
/// forwarder sends relevant events (tool calls, file edits) to Agentbox
/// so they appear in the unified audit log queried via `agentbox audit`.
///
/// Events are sent as Agentbox `CheckRequest`s with a synthetic binary
/// name prefixed by `sb:` (e.g., `sb:tool_call`, `sb:file_edit`). The
/// daemon classifies these as allow-bucket (they're informational) and
/// logs them.
///
/// # Architecture note
///
/// In Switchboard, you'd wire this into the `AgentEventBus`:
///
/// ```rust,ignore
/// // In your Switchboard agent runner:
/// let forwarder = AgentboxEventForwarder::new("claude-code");
///
/// event_bus.subscribe(move |event: &AgentEvent| {
///     match event {
///         AgentEvent::ToolCall { name, args, cwd } => {
///             forwarder.forward_tool_call(name, args, cwd);
///         }
///         AgentEvent::FileEdit { path, summary } => {
///             forwarder.forward_file_edit(path, summary);
///         }
///         _ => {} // Ignore events we don't forward
///     }
/// });
/// ```
pub struct AgentboxEventForwarder {
    client: AgentboxClient,
    /// Agent name used in audit log entries.
    agent_name: String,
}

impl AgentboxEventForwarder {
    /// Create a forwarder for the given agent name.
    pub fn new(agent_name: &str) -> Self {
        Self {
            client: AgentboxClient::new(),
            agent_name: agent_name.to_string(),
        }
    }

    /// Create a forwarder with a custom socket path.
    pub fn with_socket(agent_name: &str, socket_path: impl Into<PathBuf>) -> Self {
        Self {
            client: AgentboxClient::with_socket(socket_path),
            agent_name: agent_name.to_string(),
        }
    }

    /// Forward a tool call event to the Agentbox audit log.
    ///
    /// The tool call is sent as a synthetic command `sb:tool_call <name> <args...>`.
    /// Agentbox classifies it (likely as allow) and logs it.
    pub fn forward_tool_call(&self, tool_name: &str, args: &[&str], cwd: &str) {
        let req = CheckRequest {
            binary: format!("sb:tool_call:{tool_name}"),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: cwd.to_string(),
            parent_process: self.agent_name.clone(),
            pid: std::process::id(),
        };

        // Fire-and-forget: we don't block on the daemon response.
        // If the daemon is down, the event is silently dropped.
        let _ = self.client.check(&req);
    }

    /// Forward a file edit event to the Agentbox audit log.
    ///
    /// Logged as `sb:file_edit <path>` with the summary in args.
    pub fn forward_file_edit(&self, file_path: &str, summary: &str) {
        let req = CheckRequest {
            binary: "sb:file_edit".to_string(),
            args: vec![file_path.to_string(), summary.to_string()],
            cwd: std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "/unknown".to_string()),
            parent_process: self.agent_name.clone(),
            pid: std::process::id(),
        };

        let _ = self.client.check(&req);
    }

    /// Forward a generic agent event to the Agentbox audit log.
    ///
    /// Use this for custom event types that don't fit the tool_call or
    /// file_edit categories.
    pub fn forward_event(&self, event_type: &str, details: &[&str], cwd: &str) {
        let req = CheckRequest {
            binary: format!("sb:{event_type}"),
            args: details.iter().map(|s| s.to_string()).collect(),
            cwd: cwd.to_string(),
            parent_process: self.agent_name.clone(),
            pid: std::process::id(),
        };

        let _ = self.client.check(&req);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_decision_mapping_allowed() {
        let resp = CheckResponse {
            decision: "allowed".into(),
            reason: "safe command".into(),
            real_binary: "/usr/bin/ls".into(),
        };
        match map_response(resp) {
            PolicyDecision::Allow { reason } => assert_eq!(reason, "safe command"),
            other => panic!("expected Allow, got {:?}", other),
        }
    }

    #[test]
    fn policy_decision_mapping_approved() {
        let resp = CheckResponse {
            decision: "approved".into(),
            reason: "user approved via phone".into(),
            real_binary: "/usr/bin/git".into(),
        };
        match map_response(resp) {
            PolicyDecision::Approve {
                reason,
                notification,
            } => {
                assert!(reason.contains("approved"));
                assert!(!notification.is_empty());
            }
            other => panic!("expected Approve, got {:?}", other),
        }
    }

    #[test]
    fn policy_decision_mapping_denied() {
        for decision in &["denied", "blocked", "timed_out"] {
            let resp = CheckResponse {
                decision: decision.to_string(),
                reason: "not allowed".into(),
                real_binary: String::new(),
            };
            match map_response(resp) {
                PolicyDecision::Deny { reason } => assert_eq!(reason, "not allowed"),
                other => panic!("expected Deny for '{}', got {:?}", decision, other),
            }
        }
    }

    #[test]
    fn policy_decision_mapping_unknown_is_deny() {
        let resp = CheckResponse {
            decision: "something_new".into(),
            reason: "future feature".into(),
            real_binary: String::new(),
        };
        match map_response(resp) {
            PolicyDecision::Deny { reason } => {
                assert!(reason.contains("unknown agentbox decision"));
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[test]
    fn inject_env_prepends_shims_to_path() {
        let mut env: HashMap<String, String> = HashMap::new();
        env.insert("HOME".into(), "/Users/testuser".into());
        env.insert("PATH".into(), "/usr/bin:/bin".into());

        inject_agentbox_env(&mut env);

        let path = env.get("PATH").unwrap();
        assert!(path.starts_with("/Users/testuser/.agentbox/shims:"));
        assert!(path.contains("/usr/bin:/bin"));
    }

    #[test]
    fn inject_env_sets_socket_path() {
        let mut env: HashMap<String, String> = HashMap::new();
        env.insert("HOME".into(), "/Users/testuser".into());

        inject_agentbox_env(&mut env);

        let socket = env.get("AGENTBOX_SOCKET").unwrap();
        assert_eq!(socket, "/Users/testuser/.agentbox/agentbox.sock");
    }

    #[test]
    fn inject_env_no_double_prepend() {
        let mut env: HashMap<String, String> = HashMap::new();
        env.insert("HOME".into(), "/Users/testuser".into());
        env.insert(
            "PATH".into(),
            "/Users/testuser/.agentbox/shims:/usr/bin".into(),
        );

        inject_agentbox_env(&mut env);

        let path = env.get("PATH").unwrap();
        // Should not have shims twice.
        let count = path.matches(".agentbox/shims").count();
        assert_eq!(count, 1, "shims path should appear exactly once");
    }

    #[test]
    fn read_topic_from_valid_toml() {
        let dir = std::env::temp_dir().join("agentbox-sw-test");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("config.toml");

        std::fs::write(
            &config_path,
            r#"
socket_path = "/tmp/test.sock"
ntfy_topic = "agentbox-abc123"
ntfy_server = "https://ntfy.sh"
"#,
        )
        .unwrap();

        let topic = read_ntfy_topic_from_config(&config_path);
        assert_eq!(topic.as_deref(), Some("agentbox-abc123"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_topic_returns_none_for_missing_file() {
        let topic = read_ntfy_topic_from_config(Path::new("/nonexistent/config.toml"));
        assert!(topic.is_none());
    }

    #[test]
    fn backend_reports_unavailable_when_no_daemon() {
        let backend = AgentboxPolicyBackend::with_socket("/tmp/nonexistent-agentbox.sock");
        assert!(!backend.is_available());
    }

    #[test]
    fn backend_fail_closed_by_default() {
        let backend = AgentboxPolicyBackend::with_socket("/tmp/nonexistent-agentbox.sock");
        let decision = backend.evaluate_command("ls", &[], "/tmp", "test-agent");
        match decision {
            PolicyDecision::Deny { reason } => {
                assert!(reason.contains("fail-closed"));
            }
            other => panic!("expected Deny (fail-closed), got {:?}", other),
        }
    }

    #[test]
    fn backend_fail_open_when_configured() {
        let mut backend = AgentboxPolicyBackend::with_socket("/tmp/nonexistent-agentbox.sock");
        backend.set_fail_open(true);
        let decision = backend.evaluate_command("ls", &[], "/tmp", "test-agent");
        match decision {
            PolicyDecision::Allow { reason } => {
                assert!(reason.contains("fail-open"));
            }
            other => panic!("expected Allow (fail-open), got {:?}", other),
        }
    }
}
