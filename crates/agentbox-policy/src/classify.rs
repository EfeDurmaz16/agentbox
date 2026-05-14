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

/// Policy configuration for context-rich classification.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Current workspace/project root (commands within this are less risky)
    pub workspace: Option<String>,
    /// Domains that don't need network approval
    pub allowed_domains: Vec<String>,
    /// Domains that are always blocked for network commands
    pub denied_domains: Vec<String>,
    /// Whether localhost and loopback HTTP targets are available without approval
    pub allow_localhost: bool,
    /// Commands that are always allowed (user overrides)
    pub always_allow: Vec<String>,
    /// Commands that are always blocked (user overrides)
    pub always_block: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            workspace: None,
            allowed_domains: vec![],
            denied_domains: vec![],
            allow_localhost: true,
            always_allow: vec![],
            always_block: vec![],
        }
    }
}

/// Classify a command into a policy bucket using default (empty) config.
/// Kept for backward compatibility.
pub fn classify_default(ctx: &CommandContext) -> Classification {
    classify(ctx, &PolicyConfig::default())
}

/// Classify a command into a policy bucket with policy configuration.
pub fn classify(ctx: &CommandContext, config: &PolicyConfig) -> Classification {
    // Config overrides checked first (user-defined always-block / always-allow / domain allowlist)
    if let Some(c) = crate::rules::check_config_overrides(ctx, config) {
        return c;
    }

    // Block rules checked next (most restrictive)
    if let Some(c) = crate::rules::check_block(ctx, config) {
        return c;
    }

    // Approve rules checked last
    if let Some(c) = crate::rules::check_approve(ctx, config) {
        return c;
    }

    // Default: allow
    Classification {
        bucket: Bucket::Allow,
        reason: format!("{} — safe by default", ctx.binary),
        notification_summary: None,
    }
}
