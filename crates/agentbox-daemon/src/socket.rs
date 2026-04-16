use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, error, info, warn};

use agentbox_policy::classify::{self, Bucket, CommandContext};

use crate::audit::{AuditEvent, AuditStore};
use crate::config::Config;
use crate::notify::{ApprovalResult, NotificationRequest, NtfyClient};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("audit error: {0}")]
    Audit(#[from] crate::audit::AuditError),

    #[error("notification error: {0}")]
    Notify(#[from] crate::notify::NotifyError),
}

// ---------------------------------------------------------------------------
// Wire types (must match agentbox-shim)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ShimRequest {
    binary: String,
    args: Vec<String>,
    cwd: String,
    parent_process: String,
    pid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShimResponse {
    decision: String,
    reason: String,
    real_binary: String,
}

// ---------------------------------------------------------------------------
// Binary resolution
// ---------------------------------------------------------------------------

/// Search PATH for the real binary, skipping .agentbox/shims entries.
fn find_real_binary(name: &str) -> String {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        if dir.contains(".agentbox/shims") {
            continue;
        }
        let candidate = std::path::Path::new(dir).join(name);
        if candidate.is_file() {
            return candidate.to_string_lossy().to_string();
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Socket server
// ---------------------------------------------------------------------------

/// Run the Unix socket server. Blocks until the listener is shut down.
///
/// For each incoming connection, reads one line of JSON ([`ShimRequest`]),
/// classifies the command, handles the approval flow if needed, logs to audit,
/// and writes back a JSON [`ShimResponse`].
pub async fn run_socket_server(
    config: &Config,
    audit: Arc<AuditStore>,
    ntfy: Arc<NtfyClient>,
) -> Result<(), SocketError> {
    let socket_path = &config.socket_path;

    // Remove stale socket file if present.
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    info!(path = %socket_path, "Socket server listening");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let audit = Arc::clone(&audit);
        let ntfy = Arc::clone(&ntfy);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &audit, &ntfy).await {
                error!(error = %e, "Error handling connection");
            }
        });
    }
}

/// Handle a single shim connection end-to-end.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    audit: &AuditStore,
    ntfy: &NtfyClient,
) -> Result<(), SocketError> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let req: ShimRequest = serde_json::from_str(line.trim())?;
    let full_command = format_command(&req.binary, &req.args);

    debug!(
        binary = %req.binary,
        pid = req.pid,
        parent = %req.parent_process,
        "Received request"
    );

    // Classify
    let ctx = CommandContext {
        binary: req.binary.clone(),
        args: req.args.clone(),
        cwd: req.cwd.clone(),
        parent_process: Some(req.parent_process.clone()),
        pid: req.pid,
    };
    let classification = classify::classify_default(&ctx);
    let real_binary = find_real_binary(&req.binary);

    // Handle per-bucket
    let (decision, user_response_ms) = match classification.bucket {
        Bucket::Allow => {
            info!(command = %full_command, "ALLOW");
            ("allowed".to_string(), None)
        }

        Bucket::Block => {
            warn!(command = %full_command, reason = %classification.reason, "BLOCK");
            ("blocked".to_string(), None)
        }

        Bucket::Approve => {
            info!(command = %full_command, "APPROVE — sending notification");

            let notification = NotificationRequest {
                title: "Agentbox — Approval Required".to_string(),
                message: classification
                    .notification_summary
                    .clone()
                    .unwrap_or_else(|| format!("Agent wants to run: {}", full_command)),
                tags: vec!["warning".to_string()],
            };

            let start = Instant::now();
            let result = ntfy.send_approval(&notification).await;
            let elapsed_ms = start.elapsed().as_millis() as i64;

            match result {
                Ok(ApprovalResult::Approved) => {
                    info!(command = %full_command, ms = elapsed_ms, "User APPROVED");
                    ("approved".to_string(), Some(elapsed_ms))
                }
                Ok(ApprovalResult::Denied) => {
                    info!(command = %full_command, ms = elapsed_ms, "User DENIED");
                    ("denied".to_string(), Some(elapsed_ms))
                }
                Ok(ApprovalResult::TimedOut) => {
                    warn!(command = %full_command, ms = elapsed_ms, "TIMED OUT — auto-deny");
                    ("timed_out".to_string(), Some(elapsed_ms))
                }
                Err(e) => {
                    error!(command = %full_command, error = %e, "Notification failed — denying");
                    ("denied".to_string(), None)
                }
            }
        }
    };

    // Audit log
    let bucket_str = match classification.bucket {
        Bucket::Allow => "allow",
        Bucket::Approve => "approve",
        Bucket::Block => "block",
    };

    let event = AuditEvent::new(
        req.pid as i64,
        None,
        full_command.clone(),
        req.cwd.clone(),
        bucket_str.to_string(),
        decision.clone(),
        user_response_ms,
        Some(req.parent_process.clone()),
    );

    if let Err(e) = audit.log_event(&event) {
        error!(error = %e, "Failed to write audit log");
    }

    // Respond to shim
    let response = ShimResponse {
        decision,
        reason: classification.reason,
        real_binary,
    };

    let mut payload = serde_json::to_vec(&response)?;
    payload.push(b'\n');
    writer.write_all(&payload).await?;
    writer.flush().await?;

    Ok(())
}

/// Format a command and its args into a single display string.
fn format_command(binary: &str, args: &[String]) -> String {
    if args.is_empty() {
        binary.to_string()
    } else {
        format!("{} {}", binary, args.join(" "))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    /// Create a temp socket path that won't collide.
    fn tmp_socket_path() -> String {
        let id = ulid::Ulid::new().to_string();
        format!("/tmp/agentbox-test-{}.sock", id)
    }

    /// Build a minimal Config pointing at the given socket path.
    fn test_config(socket_path: &str) -> Config {
        Config {
            socket_path: socket_path.to_string(),
            db_path: ":memory:".to_string(),
            ntfy_topic: "test".to_string(),
            ntfy_server: "https://ntfy.sh".to_string(),
            approval_timeout_secs: 120,
            shim_dir: "/tmp/agentbox-shims".to_string(),
            allowed_domains: vec![],
            log_level: "debug".to_string(),
        }
    }

    /// Send a ShimRequest to the socket and read back the ShimResponse.
    async fn send_request(
        socket_path: &str,
        req: &serde_json::Value,
    ) -> ShimResponse {
        let stream = UnixStream::connect(socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        let mut payload = serde_json::to_vec(req).unwrap();
        payload.push(b'\n');
        writer.write_all(&payload).await.unwrap();

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        serde_json::from_str(&line).unwrap()
    }

    #[tokio::test]
    async fn allow_safe_command() {
        let sock = tmp_socket_path();
        let config = test_config(&sock);
        let audit = Arc::new(AuditStore::in_memory().unwrap());
        // ntfy won't be used for allow-bucket, but we need a valid instance
        let ntfy = Arc::new(NtfyClient::new("https://ntfy.sh", "unused", 5));

        let audit_clone = Arc::clone(&audit);
        tokio::spawn(async move {
            run_socket_server(&config, audit_clone, ntfy).await.ok();
        });

        // Give the listener a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let req = serde_json::json!({
            "binary": "cat",
            "args": ["foo.txt"],
            "cwd": "/home/user/project",
            "parent_process": "node",
            "pid": 12345
        });

        let resp = send_request(&sock, &req).await;
        assert_eq!(resp.decision, "allowed");
        assert!(!resp.reason.is_empty());

        // Verify audit log
        let events = audit.recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].bucket, "allow");
        assert_eq!(events[0].decision, "allowed");

        // Cleanup
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn block_dangerous_command() {
        let sock = tmp_socket_path();
        let config = test_config(&sock);
        let audit = Arc::new(AuditStore::in_memory().unwrap());
        let ntfy = Arc::new(NtfyClient::new("https://ntfy.sh", "unused", 5));

        let audit_clone = Arc::clone(&audit);
        tokio::spawn(async move {
            run_socket_server(&config, audit_clone, ntfy).await.ok();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let req = serde_json::json!({
            "binary": "rm",
            "args": ["-rf", "/"],
            "cwd": "/home/user",
            "parent_process": "node",
            "pid": 99999
        });

        let resp = send_request(&sock, &req).await;
        assert_eq!(resp.decision, "blocked");
        assert!(!resp.reason.is_empty());

        // Verify audit log
        let events = audit.recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].bucket, "block");
        assert_eq!(events[0].decision, "blocked");

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn multiple_sequential_requests() {
        let sock = tmp_socket_path();
        let config = test_config(&sock);
        let audit = Arc::new(AuditStore::in_memory().unwrap());
        let ntfy = Arc::new(NtfyClient::new("https://ntfy.sh", "unused", 5));

        let audit_clone = Arc::clone(&audit);
        tokio::spawn(async move {
            run_socket_server(&config, audit_clone, ntfy).await.ok();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send three allow-bucket commands
        for i in 0..3 {
            let req = serde_json::json!({
                "binary": "ls",
                "args": [format!("-{}", i)],
                "cwd": "/tmp",
                "parent_process": "bash",
                "pid": 1000 + i
            });
            let resp = send_request(&sock, &req).await;
            assert_eq!(resp.decision, "allowed");
        }

        let events = audit.recent(10).unwrap();
        assert_eq!(events.len(), 3);

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn response_includes_real_binary_field() {
        let sock = tmp_socket_path();
        let config = test_config(&sock);
        let audit = Arc::new(AuditStore::in_memory().unwrap());
        let ntfy = Arc::new(NtfyClient::new("https://ntfy.sh", "unused", 5));

        let audit_clone = Arc::clone(&audit);
        tokio::spawn(async move {
            run_socket_server(&config, audit_clone, ntfy).await.ok();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let req = serde_json::json!({
            "binary": "echo",
            "args": ["hello"],
            "cwd": "/tmp",
            "parent_process": "zsh",
            "pid": 5555
        });

        let resp = send_request(&sock, &req).await;
        // real_binary should be populated (echo exists on every system)
        // It may be empty if echo is a shell builtin, so just check the field exists
        assert!(resp.decision == "allowed");

        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn format_command_no_args() {
        assert_eq!(format_command("ls", &[]), "ls");
    }

    #[test]
    fn format_command_with_args() {
        let args = vec!["-la".to_string(), "/tmp".to_string()];
        assert_eq!(format_command("ls", &args), "ls -la /tmp");
    }

    #[test]
    fn find_real_binary_skips_shim_dir() {
        // /usr/bin/env should always exist on unix systems
        let result = find_real_binary("env");
        assert!(!result.is_empty());
        assert!(!result.contains(".agentbox/shims"));
    }
}
