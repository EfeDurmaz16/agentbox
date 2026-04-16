use serde::{Deserialize, Serialize};

/// The three policy buckets. Every intercepted action falls into exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bucket {
    /// Safe — execute immediately, no notification
    Allow,
    /// Risky — send phone notification, wait for user response
    Approve,
    /// Dangerous — deny immediately, log attempt
    Block,
}

/// Context about an intercepted command, used for classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandContext {
    /// The binary name (e.g., "rm", "git", "psql")
    pub binary: String,
    /// Full argument list
    pub args: Vec<String>,
    /// Current working directory
    pub cwd: String,
    /// Parent process name (best-effort detection)
    pub parent_process: Option<String>,
    /// PID of the calling process
    pub pid: u32,
}

/// Result of classifying a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub bucket: Bucket,
    /// Human-readable explanation for the decision
    pub reason: String,
    /// Plain-English summary for phone notification (only for Approve bucket)
    pub notification_summary: Option<String>,
}

/// Classify a command into a policy bucket.
pub fn classify(ctx: &CommandContext) -> Classification {
    // Block rules checked first (most restrictive)
    if let Some(c) = crate::rules::check_block(ctx) {
        return c;
    }

    // Approve rules checked second
    if let Some(c) = crate::rules::check_approve(ctx) {
        return c;
    }

    // Default: allow
    Classification {
        bucket: Bucket::Allow,
        reason: format!("{} — safe by default", ctx.binary),
        notification_summary: None,
    }
}
