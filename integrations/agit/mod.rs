//! Reference integration: agit + Agentbox
//!
//! Shows how agit's guard system and event bus connect to the Agentbox daemon
//! via `agentbox_client`. This module is **not** compiled as part of the
//! Agentbox workspace — it lives here as a reference for the agit codebase.
//!
//! Two integration points:
//!
//! 1. **[`AgentboxGuard`]** — implements agit's `CommitGuard` pattern.
//!    Before an agent's tool-call commit is finalized, the guard checks the
//!    command against Agentbox policy and maps the response to
//!    `Allow` / `Warn` / `Block`.
//!
//! 2. **[`AgentboxAuditCallback`]** — registers on agit's `InMemoryEventBus`.
//!    When a `CommitCreated` event fires, it forwards relevant data to the
//!    Agentbox daemon's audit log via the Unix socket.

use std::collections::HashMap;

use agentbox_client::{AgentboxClient, CheckRequest};

// ---------------------------------------------------------------------------
// agit types (simplified for reference — real definitions live in agit)
// ---------------------------------------------------------------------------

/// The kind of action an agent is committing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionType {
    /// Agent is invoking a tool (shell command, API call, etc.)
    ToolCall,
    /// Agent produced an LLM response (text output)
    LlmResponse,
    /// Internal system event (heartbeat, state transition, etc.)
    SystemEvent,
}

/// Context passed to every guard before a commit is finalized.
pub struct GuardContext {
    /// What kind of action the agent is committing.
    pub action_type: ActionType,
    /// Human-readable description of the action (or the raw command string).
    pub message: String,
    /// Unique identifier of the agent performing the action.
    pub agent_id: String,
    /// Arbitrary key-value metadata attached to the commit.
    ///
    /// For `ToolCall` actions the following keys are expected:
    ///   - `binary`  — the executable name (e.g. "git", "rm", "psql")
    ///   - `args`    — space-separated argument string
    ///   - `cwd`     — working directory at invocation time
    ///
    /// Blast-radius analysis (from agit's risk engine) may add:
    ///   - `blast_radius` — "low", "medium", or "high"
    pub metadata: HashMap<String, String>,
}

/// Decision returned by a guard to the commit pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    /// Let the action proceed without interference.
    Allow,
    /// Let the action proceed but attach a warning to the audit trail.
    Warn(String),
    /// Reject the action — the commit must not be finalized.
    Block(String),
}

/// Event emitted by agit's commit store after a commit is persisted.
pub struct CommitCreatedEvent {
    pub commit_id: String,
    pub agent_id: String,
    pub action_type: ActionType,
    pub message: String,
    pub metadata: HashMap<String, String>,
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// Part 1: AgentboxGuard
// ---------------------------------------------------------------------------

/// Guard that checks tool-call commits against Agentbox policy.
///
/// When an agent commits an action of type [`ActionType::ToolCall`], this guard
/// extracts the command and checks it against the Agentbox daemon. Non-tool-call
/// actions pass through immediately — Agentbox only governs shell-level commands.
///
/// # Blast-radius mapping
///
/// If agit's risk engine has already computed a `blast_radius` for the action,
/// the guard uses it as a fast-path hint before hitting the daemon:
///
/// | agit blast_radius | Agentbox bucket | Guard decision           |
/// |-------------------|-----------------|--------------------------|
/// | `"low"`           | Allow           | `Allow` (skip daemon)    |
/// | `"medium"`        | Approve         | Delegate to daemon       |
/// | `"high"`          | Approve/Block   | Delegate to daemon       |
///
/// Low-risk actions bypass the daemon entirely for latency savings. Medium and
/// high-risk actions always go through the daemon so the user gets a phone
/// notification and the action is recorded in the audit log.
///
/// # Fail-open behavior
///
/// If the Agentbox daemon is unreachable (not running, socket missing), the
/// guard falls back to `Allow` with a warning. This keeps agit functional when
/// Agentbox is not installed. Callers who want fail-closed semantics should
/// check [`AgentboxClient::is_available`] at startup and refuse to proceed.
pub struct AgentboxGuard {
    client: AgentboxClient,
}

impl AgentboxGuard {
    /// Create a new guard connected to the default Agentbox socket.
    pub fn new() -> Self {
        Self {
            client: AgentboxClient::new(),
        }
    }

    /// Create a guard with a custom Agentbox client (e.g. custom socket path).
    pub fn with_client(client: AgentboxClient) -> Self {
        Self { client }
    }

    /// Check a commit context against Agentbox policy.
    ///
    /// Only `ToolCall` actions are forwarded to the daemon. All other action
    /// types return `Allow` immediately — they don't represent shell commands.
    pub fn check(&self, context: &GuardContext) -> GuardDecision {
        // Non-tool-call actions are outside Agentbox's scope.
        if context.action_type != ActionType::ToolCall {
            return GuardDecision::Allow;
        }

        // Extract the command from metadata.
        let binary = match context.metadata.get("binary") {
            Some(b) => b.clone(),
            None => {
                // No binary in metadata — can't classify. Warn and allow.
                return GuardDecision::Warn(
                    "ToolCall commit missing 'binary' in metadata; Agentbox cannot classify"
                        .into(),
                );
            }
        };

        let args: Vec<String> = context
            .metadata
            .get("args")
            .map(|a| a.split_whitespace().map(String::from).collect())
            .unwrap_or_default();

        let cwd = context
            .metadata
            .get("cwd")
            .cloned()
            .unwrap_or_else(|| ".".into());

        // ---------------------------------------------------------------
        // Fast-path: low blast_radius skips the daemon round-trip.
        // ---------------------------------------------------------------
        if let Some(blast_radius) = context.metadata.get("blast_radius") {
            if blast_radius == "low" {
                return GuardDecision::Allow;
            }
            // "medium" and "high" fall through to the daemon check.
        }

        // ---------------------------------------------------------------
        // Daemon check
        // ---------------------------------------------------------------
        let req = CheckRequest {
            binary,
            args,
            cwd,
            parent_process: format!("agit:{}", context.agent_id),
            pid: std::process::id(),
        };

        match self.client.check(&req) {
            Ok(resp) => match resp.decision.as_str() {
                "allowed" => GuardDecision::Allow,
                "approved" => GuardDecision::Allow,
                "denied" => GuardDecision::Block(format!("User denied: {}", resp.reason)),
                "blocked" => GuardDecision::Block(format!("Agentbox blocked: {}", resp.reason)),
                "timed_out" => {
                    GuardDecision::Block("Agentbox approval timed out (auto-deny)".into())
                }
                other => GuardDecision::Warn(format!(
                    "Agentbox returned unknown decision '{}': {}",
                    other, resp.reason
                )),
            },
            Err(e) => {
                // Fail-open: daemon unreachable, warn but allow.
                GuardDecision::Warn(format!("Agentbox daemon unavailable: {e}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Part 2: AuditEventCallback
// ---------------------------------------------------------------------------

/// Callback registered on agit's `InMemoryEventBus`.
///
/// When a [`CommitCreatedEvent`] fires, this callback serializes the relevant
/// data and forwards it to the Agentbox daemon's audit socket. This gives a
/// unified audit trail: Agentbox sees not just commands it intercepted via
/// shims, but also actions that flowed through agit's commit pipeline.
///
/// # Wire format
///
/// The callback sends a JSON object over the Agentbox Unix socket with type
/// `"audit_event"` (distinct from `"check"` requests). The daemon appends it
/// to its SQLite audit log without blocking the caller.
///
/// # Error handling
///
/// Audit forwarding is best-effort. If the daemon is down or the socket write
/// fails, the error is logged but the event is **not** retried — agit's own
/// commit store is the source of truth.
pub struct AgentboxAuditCallback {
    client: AgentboxClient,
}

/// Payload sent to the Agentbox daemon for audit logging.
#[derive(serde::Serialize)]
struct AuditPayload {
    /// Discriminator so the daemon knows this isn't a check request.
    msg_type: &'static str,
    commit_id: String,
    agent_id: String,
    action_type: String,
    message: String,
    metadata: HashMap<String, String>,
    timestamp_ms: u64,
}

impl AgentboxAuditCallback {
    /// Create a new audit callback connected to the default Agentbox socket.
    pub fn new() -> Self {
        Self {
            client: AgentboxClient::new(),
        }
    }

    /// Create an audit callback with a custom Agentbox client.
    pub fn with_client(client: AgentboxClient) -> Self {
        Self { client }
    }

    /// Handle a `CommitCreated` event from agit's event bus.
    ///
    /// This is the function you register on `InMemoryEventBus`:
    ///
    /// ```ignore
    /// let audit_cb = AgentboxAuditCallback::new();
    /// event_bus.on("CommitCreated", move |event: CommitCreatedEvent| {
    ///     audit_cb.on_commit_created(&event);
    /// });
    /// ```
    pub fn on_commit_created(&self, event: &CommitCreatedEvent) {
        if !self.client.is_available() {
            // Daemon not running — skip silently.
            return;
        }

        let action_type_str = match event.action_type {
            ActionType::ToolCall => "tool_call",
            ActionType::LlmResponse => "llm_response",
            ActionType::SystemEvent => "system_event",
        };

        let payload = AuditPayload {
            msg_type: "audit_event",
            commit_id: event.commit_id.clone(),
            agent_id: event.agent_id.clone(),
            action_type: action_type_str.into(),
            message: event.message.clone(),
            metadata: event.metadata.clone(),
            timestamp_ms: event.timestamp_ms,
        };

        // Best-effort send over Unix socket. We reuse the client's socket path
        // but write a raw JSON payload (not a CheckRequest).
        if let Err(e) = self.send_audit(&payload) {
            eprintln!("[agentbox-audit] failed to forward event: {e}");
        }
    }

    /// Low-level send: connect to the socket, write JSON, don't wait for response.
    fn send_audit(&self, payload: &AuditPayload) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        // Resolve the socket path from the client. In a real integration you'd
        // expose the path from AgentboxClient or use a shared constant.
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let socket_path = std::path::PathBuf::from(home)
            .join(".agentbox")
            .join("agentbox.sock");

        let mut stream = UnixStream::connect(&socket_path)?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;

        let mut buf = serde_json::to_vec(payload)?;
        buf.push(b'\n');
        stream.write_all(&buf)?;

        // Fire-and-forget: we don't read a response for audit events.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Blast-radius mapping reference
// ---------------------------------------------------------------------------

/// Maps agit's blast-radius levels to Agentbox policy buckets.
///
/// agit computes blast_radius based on the scope and reversibility of an
/// action. Agentbox classifies by command pattern. The mapping:
///
/// | agit blast_radius | Typical commands               | Agentbox bucket |
/// |-------------------|--------------------------------|-----------------|
/// | `low`             | `cat`, `ls`, `git diff`        | Allow           |
/// | `medium`          | `git push`, `npm publish`      | Approve         |
/// | `high`            | `rm -rf /`, `DROP TABLE`       | Block           |
///
/// In practice the Agentbox daemon has its own rule engine and the buckets
/// may not align perfectly. The guard uses blast_radius only as a fast-path
/// optimization — the daemon's classification is authoritative.
pub fn blast_radius_to_bucket(blast_radius: &str) -> &'static str {
    match blast_radius {
        "low" => "allow",
        "medium" => "approve",
        "high" => "approve", // daemon may escalate to block
        _ => "approve",      // unknown risk — let the daemon decide
    }
}

// ---------------------------------------------------------------------------
// Registration helpers
// ---------------------------------------------------------------------------

/// Wire up both the guard and the audit callback.
///
/// Typical usage in agit's initialization:
///
/// ```ignore
/// use agentbox_integration::{AgentboxGuard, AgentboxAuditCallback};
///
/// // Register the guard in the commit pipeline.
/// let guard = AgentboxGuard::new();
/// commit_pipeline.add_guard(guard);
///
/// // Register the audit callback on the event bus.
/// let audit_cb = AgentboxAuditCallback::new();
/// event_bus.on("CommitCreated", move |event| {
///     audit_cb.on_commit_created(&event);
/// });
///
/// // Optional: check if Agentbox is running and log status.
/// if AgentboxClient::new().is_available() {
///     tracing::info!("Agentbox daemon detected — guard and audit active");
/// } else {
///     tracing::warn!("Agentbox daemon not running — guard will fail-open");
/// }
/// ```
pub fn is_agentbox_available() -> bool {
    AgentboxClient::new().is_available()
}
