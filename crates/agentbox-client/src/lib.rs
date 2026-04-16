//! Lightweight client for the Agentbox daemon.
//!
//! Use this crate from Switchboard, agit, or any Rust project that needs
//! to check commands against Agentbox policy before executing them.
//!
//! # Example
//!
//! ```no_run
//! use agentbox_client::{AgentboxClient, CheckRequest};
//!
//! let client = AgentboxClient::new();
//! let req = CheckRequest {
//!     binary: "git".into(),
//!     args: vec!["push".into(), "origin".into(), "main".into()],
//!     cwd: "/home/user/project".into(),
//!     parent_process: "switchboard".into(),
//!     pid: std::process::id(),
//! };
//!
//! match client.check(&req) {
//!     Ok(resp) => {
//!         if resp.is_allowed() {
//!             println!("Allowed: {}", resp.reason);
//!         } else {
//!             println!("Denied: {}", resp.reason);
//!         }
//!     }
//!     Err(e) => {
//!         // Daemon unreachable — fail-open or fail-closed is caller's choice
//!         eprintln!("Agentbox unavailable: {}", e);
//!     }
//! }
//! ```

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("daemon socket not found at {0}")]
    SocketNotFound(String),

    #[error("connection failed: {0}")]
    Connect(#[source] std::io::Error),

    #[error("send failed: {0}")]
    Send(#[source] std::io::Error),

    #[error("receive failed: {0}")]
    Receive(#[source] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Request sent to the Agentbox daemon.
#[derive(Debug, Clone, Serialize)]
pub struct CheckRequest {
    pub binary: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub parent_process: String,
    pub pid: u32,
}

/// Response from the Agentbox daemon.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckResponse {
    /// "allowed" | "approved" | "denied" | "blocked" | "timed_out"
    pub decision: String,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Resolved path to the real binary (e.g., "/usr/bin/git").
    #[serde(default)]
    pub real_binary: String,
}

impl CheckResponse {
    /// Returns true if the command was allowed or approved.
    pub fn is_allowed(&self) -> bool {
        matches!(self.decision.as_str(), "allowed" | "approved")
    }

    /// Returns true if the command was denied, blocked, or timed out.
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Synchronous client for the Agentbox daemon.
///
/// Connects to the Unix domain socket, sends a classification request,
/// and returns the daemon's decision. Each `check()` call opens a new
/// connection (the daemon handles one request per connection).
pub struct AgentboxClient {
    socket_path: PathBuf,
    timeout: Duration,
}

impl AgentboxClient {
    /// Create a client using the default socket path (`~/.agentbox/agentbox.sock`).
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        Self {
            socket_path: PathBuf::from(home).join(".agentbox").join("agentbox.sock"),
            timeout: Duration::from_secs(130), // slightly longer than max approval timeout
        }
    }

    /// Create a client with a custom socket path.
    pub fn with_socket(path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: path.into(),
            timeout: Duration::from_secs(130),
        }
    }

    /// Set the read timeout (how long to wait for the daemon's response).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns true if the daemon socket exists on disk.
    pub fn is_available(&self) -> bool {
        self.socket_path.exists()
    }

    /// Check a command against the Agentbox policy.
    ///
    /// This will block until the daemon responds (which may involve
    /// waiting for user approval via phone notification).
    pub fn check(&self, req: &CheckRequest) -> Result<CheckResponse, ClientError> {
        if !self.socket_path.exists() {
            return Err(ClientError::SocketNotFound(
                self.socket_path.display().to_string(),
            ));
        }

        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(ClientError::Connect)?;

        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        // Send newline-delimited JSON
        let mut payload = serde_json::to_vec(req)?;
        payload.push(b'\n');
        stream.write_all(&payload).map_err(ClientError::Send)?;

        // Read one line of JSON response
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(ClientError::Receive)?;

        let resp: CheckResponse = serde_json::from_str(&line)?;
        Ok(resp)
    }

    /// Check a command and return a simple bool (true = allowed).
    ///
    /// If the daemon is unreachable, returns `default` (true = fail-open,
    /// false = fail-closed).
    pub fn is_allowed(&self, req: &CheckRequest, default: bool) -> bool {
        match self.check(req) {
            Ok(resp) => resp.is_allowed(),
            Err(_) => default,
        }
    }
}

impl Default for AgentboxClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Convenience function
// ---------------------------------------------------------------------------

/// Quick check: is this command allowed by Agentbox?
///
/// Returns true if allowed/approved, or if the daemon is unavailable (fail-open).
pub fn quick_check(binary: &str, args: &[&str], cwd: &str) -> bool {
    let client = AgentboxClient::new();
    let req = CheckRequest {
        binary: binary.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        cwd: cwd.into(),
        parent_process: "unknown".into(),
        pid: std::process::id(),
    };
    client.is_allowed(&req, true) // fail-open by default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_response_is_allowed() {
        let allowed = CheckResponse {
            decision: "allowed".into(),
            reason: "safe".into(),
            real_binary: "/bin/ls".into(),
        };
        assert!(allowed.is_allowed());
        assert!(!allowed.is_denied());

        let approved = CheckResponse {
            decision: "approved".into(),
            reason: "user approved".into(),
            real_binary: "/usr/bin/git".into(),
        };
        assert!(approved.is_allowed());

        let blocked = CheckResponse {
            decision: "blocked".into(),
            reason: "dangerous".into(),
            real_binary: String::new(),
        };
        assert!(!blocked.is_allowed());
        assert!(blocked.is_denied());

        let denied = CheckResponse {
            decision: "denied".into(),
            reason: "user denied".into(),
            real_binary: String::new(),
        };
        assert!(denied.is_denied());

        let timed_out = CheckResponse {
            decision: "timed_out".into(),
            reason: "no response".into(),
            real_binary: String::new(),
        };
        assert!(timed_out.is_denied());
    }

    #[test]
    fn client_reports_unavailable_when_no_socket() {
        let client = AgentboxClient::with_socket("/tmp/nonexistent-agentbox.sock");
        assert!(!client.is_available());

        let req = CheckRequest {
            binary: "ls".into(),
            args: vec![],
            cwd: "/tmp".into(),
            parent_process: "test".into(),
            pid: 1,
        };

        // fail-open
        assert!(client.is_allowed(&req, true));
        // fail-closed
        assert!(!client.is_allowed(&req, false));
    }

    #[test]
    fn quick_check_fails_open_when_daemon_unavailable() {
        // No daemon running, should return true (fail-open)
        assert!(quick_check("ls", &["-la"], "/tmp"));
    }
}
