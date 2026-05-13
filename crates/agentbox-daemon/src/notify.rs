use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Failed to parse ntfy response: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("Notification send failed with status {0}")]
    SendFailed(u16),
}

pub type Result<T> = std::result::Result<T, NotifyError>;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Outcome of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalResult {
    Approved,
    Denied,
    TimedOut,
}

/// Payload for an approval notification.
#[derive(Debug, Clone)]
pub struct NotificationRequest {
    pub title: String,
    pub message: String,
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// Internal ntfy JSON structures
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct NtfyPublish {
    topic: String,
    title: String,
    message: String,
    tags: Vec<String>,
    actions: Vec<NtfyAction>,
}

#[derive(Serialize)]
struct NtfyAction {
    action: String,
    label: String,
    url: String,
    method: String,
    body: String,
}

/// A single message returned when polling the ntfy topic.
#[derive(Deserialize, Debug)]
struct NtfyMessage {
    #[serde(default)]
    message: String,
    #[allow(dead_code)]
    #[serde(default)]
    time: u64,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client for sending approval notifications via ntfy and polling for responses.
pub struct NtfyClient {
    server: String,
    topic: String,
    timeout: Duration,
    http: Client,
}

impl NtfyClient {
    /// Create a new `NtfyClient`.
    ///
    /// * `server` — base URL of the ntfy instance, e.g. `"https://ntfy.sh"`.
    /// * `topic`  — topic name, e.g. `"agentbox-abc123"`.
    /// * `timeout_secs` — how long to wait for a response before auto-denying.
    pub fn new(server: &str, topic: &str, timeout_secs: u64) -> Self {
        Self {
            server: server.trim_end_matches('/').to_string(),
            topic: topic.to_string(),
            timeout: Duration::from_secs(timeout_secs),
            http: Client::new(),
        }
    }

    /// Send an approval notification and wait for the user to respond.
    ///
    /// Returns [`ApprovalResult::Approved`] or [`ApprovalResult::Denied`] based
    /// on the user's tap, or [`ApprovalResult::TimedOut`] if no response arrives
    /// within the configured timeout.
    pub async fn send_approval(&self, req: &NotificationRequest) -> Result<ApprovalResult> {
        let sent_at = now_epoch();
        let request_id = format!("req-{:x}", sent_at ^ std::process::id() as u64);
        self.send_notification(req, &request_id).await?;
        self.poll_response(sent_at, &request_id).await
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// POST the notification to the ntfy topic.
    ///
    /// Uses header-based approach for proper button rendering on iOS/Android.
    /// The message body is plain text; title, tags, and actions are sent as headers.
    async fn send_notification(&self, req: &NotificationRequest, request_id: &str) -> Result<()> {
        let topic_url = format!("{}/{}", self.server, self.topic);

        // Each button POSTs "{request_id}:approved" or "{request_id}:denied".
        // The poll loop only accepts messages matching this request_id,
        // so a late Deny tap after Approve was already accepted is ignored.
        let actions_header = format!(
            "http, Approve, {topic_url}, method=POST, body={request_id}:approved; http, Deny, {topic_url}, method=POST, body={request_id}:denied"
        );

        let tags_header = req.tags.join(",");

        info!(topic = %self.topic, title = %req.title, "Sending approval notification");

        let resp = self
            .http
            .post(&topic_url)
            .header("Title", &req.title)
            .header("Tags", &tags_header)
            .header("Actions", &actions_header)
            .body(req.message.clone())
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            warn!(status, "ntfy publish returned non-success status");
            return Err(NotifyError::SendFailed(status));
        }

        debug!("Notification sent successfully");
        Ok(())
    }

    /// Poll the ntfy topic for an "approved" or "denied" response message.
    ///
    /// Uses HTTP polling (`?poll=1&since=<ts>`) in a loop with a 2-second
    /// interval until the timeout expires.
    async fn poll_response(&self, since: u64, request_id: &str) -> Result<ApprovalResult> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let poll_interval = Duration::from_secs(2);

        let approve_token = format!("{}:approved", request_id);
        let deny_token = format!("{}:denied", request_id);

        loop {
            if tokio::time::Instant::now() >= deadline {
                info!(topic = %self.topic, "Approval timed out");
                return Ok(ApprovalResult::TimedOut);
            }

            let url = format!("{}/{}/json?poll=1&since={}", self.server, self.topic, since);

            debug!(%url, "Polling for response");

            let resp = self.http.get(&url).send().await?;
            let text = resp.text().await?;

            // ntfy returns one JSON object per line (ndjson).
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if let Ok(msg) = serde_json::from_str::<NtfyMessage>(line) {
                    let body = msg.message.trim().to_lowercase();

                    // Only accept responses matching our request_id.
                    // This prevents a late Deny from overriding a previous Approve.
                    if body == approve_token {
                        info!(topic = %self.topic, %request_id, "User approved the action");
                        return Ok(ApprovalResult::Approved);
                    } else if body == deny_token {
                        info!(topic = %self.topic, %request_id, "User denied the action");
                        return Ok(ApprovalResult::Denied);
                    }
                    // Also accept bare "approved"/"denied" for backward compat
                    // (e.g., manual testing via curl)
                    else if body == "approved" {
                        info!(topic = %self.topic, "User approved (legacy format)");
                        return Ok(ApprovalResult::Approved);
                    } else if body == "denied" {
                        info!(topic = %self.topic, "User denied (legacy format)");
                        return Ok(ApprovalResult::Denied);
                    }
                }
            }

            tokio::time::sleep_until((tokio::time::Instant::now() + poll_interval).min(deadline))
                .await;
        }
    }
}

/// Current unix timestamp in seconds.
fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    /// Tiny HTTP server that records requests and serves canned responses.
    /// Good enough to exercise the ntfy client without hitting the real service.
    struct MockNtfy {
        addr: SocketAddr,
        /// Collected request bodies (POST).
        bodies: Arc<Mutex<Vec<String>>>,
        /// Lines returned on the next GET poll.
        poll_response: Arc<Mutex<String>>,
    }

    impl MockNtfy {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let poll_response: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

            let b = bodies.clone();
            let p = poll_response.clone();

            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    let b = b.clone();
                    let p = p.clone();

                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        let raw = String::from_utf8_lossy(&buf[..n]).to_string();

                        let is_get = raw.starts_with("GET ");

                        // Extract body (after double CRLF).
                        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

                        if is_get {
                            let payload = p.lock().await.clone();
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                                payload.len(),
                                payload,
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        } else {
                            b.lock().await.push(body);
                            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    });
                }
            });

            Self {
                addr,
                bodies,
                poll_response,
            }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        async fn set_poll_response(&self, lines: &str) {
            *self.poll_response.lock().await = lines.to_string();
        }

        async fn post_count(&self) -> usize {
            self.bodies.lock().await.len()
        }
    }

    #[tokio::test]
    async fn test_send_and_approve() {
        let mock = MockNtfy::start().await;

        mock.set_poll_response(
            &serde_json::json!({"message": "approved", "time": 1700000001}).to_string(),
        )
        .await;

        let client = NtfyClient::new(&mock.base_url(), "test-topic", 5);

        let req = NotificationRequest {
            title: "Test".into(),
            message: "Do the thing?".into(),
            tags: vec!["warning".into()],
        };

        let result = client.send_approval(&req).await.unwrap();
        assert_eq!(result, ApprovalResult::Approved);
        assert!(mock.post_count().await >= 1);
    }

    #[tokio::test]
    async fn test_send_and_deny() {
        let mock = MockNtfy::start().await;

        mock.set_poll_response(
            &serde_json::json!({"message": "denied", "time": 1700000001}).to_string(),
        )
        .await;

        let client = NtfyClient::new(&mock.base_url(), "test-topic", 5);

        let req = NotificationRequest {
            title: "Test".into(),
            message: "Delete database?".into(),
            tags: vec!["skull".into()],
        };

        let result = client.send_approval(&req).await.unwrap();
        assert_eq!(result, ApprovalResult::Denied);
    }

    #[tokio::test]
    async fn test_timeout() {
        let mock = MockNtfy::start().await;

        // Empty poll response — no approval or denial will ever come.
        mock.set_poll_response("").await;

        // 1-second timeout so the test finishes fast.
        let client = NtfyClient::new(&mock.base_url(), "test-topic", 1);

        let req = NotificationRequest {
            title: "Test".into(),
            message: "Will time out".into(),
            tags: vec![],
        };

        let result = client.send_approval(&req).await.unwrap();
        assert_eq!(result, ApprovalResult::TimedOut);
    }

    #[tokio::test]
    async fn test_notification_body_contains_actions() {
        let mock = MockNtfy::start().await;

        mock.set_poll_response(
            &serde_json::json!({"message": "approved", "time": 1700000001}).to_string(),
        )
        .await;

        let client = NtfyClient::new(&mock.base_url(), "my-topic", 5);

        let req = NotificationRequest {
            title: "Agentbox — Approval Required".into(),
            message: "Agent wants to git push".into(),
            tags: vec!["warning".into()],
        };

        client.send_approval(&req).await.unwrap();

        // With header-based approach, the POST body is the plain message text.
        // Actions (Approve/Deny) are sent as HTTP headers, not in the body.
        let bodies = mock.bodies.lock().await;
        assert!(!bodies.is_empty());
        let first = &bodies[0];
        assert!(
            first.contains("Agent wants to git push"),
            "body should contain the message text"
        );
    }
}
