//! # OAPS <-> Agentbox Integration Reference
//!
//! This module demonstrates how the Open Agent Policy Standard (OAPS) protocol-level
//! policy engine connects to Agentbox's OS-level enforcement layer.
//!
//! ## Why two layers?
//!
//! OAPS and Agentbox operate at different abstraction levels:
//!
//! - **OAPS (protocol layer):** Evaluates agent *intent* — what the agent wants to do
//!   semantically (e.g., "delete a database table", "send money to address X").
//!   Works with structured tool calls, risk levels (R1-R5), and evidence chains.
//!
//! - **Agentbox (OS layer):** Intercepts the *execution* — the actual shell command
//!   that hits the operating system (e.g., `psql -c 'DROP TABLE users'`).
//!   Works with binary names, arguments, PATH shims, and file-system events.
//!
//! Together they form defense-in-depth: OAPS catches semantic risks that look
//! innocuous at the shell level, Agentbox catches shell escapes that bypass
//! protocol-level controls.
//!
//! ## Data Flow
//!
//! ```text
//!   ┌─────────────┐
//!   │   AI Agent   │
//!   │ (Claude, etc)│
//!   └──────┬───────┘
//!          │
//!          │ 1. Agent decides to execute a tool / shell command
//!          ▼
//!   ┌─────────────────────────────┐
//!   │   OAPS Policy Evaluation    │
//!   │                             │
//!   │  • Classify intent (R1-R5)  │
//!   │  • Check agent permissions  │
//!   │  • Evaluate context rules   │
//!   └──────────┬──────────────────┘
//!              │
//!              │ 2. OAPS decision + risk level passed down
//!              ▼
//!   ┌─────────────────────────────┐
//!   │   Integration Bridge        │
//!   │   (this module)             │
//!   │                             │
//!   │  • Map R1-R5 → bucket      │
//!   │  • Merge decisions          │
//!   │  • Most restrictive wins    │
//!   └──────────┬──────────────────┘
//!              │
//!              │ 3. If not blocked, command reaches OS
//!              ▼
//!   ┌─────────────────────────────┐
//!   │   Agentbox Daemon           │
//!   │                             │
//!   │  • PATH shim intercepts     │
//!   │  • OS-level classify()      │
//!   │  • Phone approval if needed │
//!   │  • Audit log                │
//!   └──────────┬──────────────────┘
//!              │
//!              │ 4. Execute or deny
//!              ▼
//!   ┌─────────────────────────────┐
//!   │   Real Binary               │
//!   │   (/usr/bin/git, etc.)      │
//!   └─────────────────────────────┘
//!
//!   Evidence flows back up:
//!   Agentbox AuditEvent → EvidenceAdapter → OAPS evidence chain
//! ```
//!
//! ## Integration Points
//!
//! 1. **Policy Enrichment** — OAPS risk levels (R1-R5) map to Agentbox buckets
//! 2. **Evidence Chain** — Agentbox audit events become OAPS evidence records
//! 3. **MCP Proxy Bridge** — Future v1.5 MCP governance connects both systems

use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Shared Types
// ============================================================================

/// Agentbox's three policy buckets, mirrored here to avoid a crate dependency
/// in this reference module. In production, import from `agentbox_policy::classify::Bucket`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentboxBucket {
    /// Safe — execute immediately, no notification.
    Allow,
    /// Risky — send phone notification, wait for user approval.
    Approve,
    /// Dangerous — deny immediately, log attempt.
    Block,
}

impl AgentboxBucket {
    /// Returns the restrictiveness rank (higher = more restrictive).
    /// Used by the bridge to pick the most restrictive of two decisions.
    fn restrictiveness(&self) -> u8 {
        match self {
            AgentboxBucket::Allow => 0,
            AgentboxBucket::Approve => 1,
            AgentboxBucket::Block => 2,
        }
    }

    /// Return the more restrictive of two buckets.
    pub fn most_restrictive(self, other: Self) -> Self {
        if other.restrictiveness() > self.restrictiveness() {
            other
        } else {
            self
        }
    }
}

/// OAPS risk levels as defined in the Open Agent Policy Standard.
///
/// ```text
///   R1 ──── Routine (read file, list directory)
///   R2 ──── Low (write file in workspace, run tests)
///   R3 ──── Moderate (network egress, install package globally)
///   R4 ──── High (database mutation, credential access)
///   R5 ──── Critical (destructive ops, financial transactions)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OapsRiskLevel {
    R1,
    R2,
    R3,
    R4,
    R5,
}

impl OapsRiskLevel {
    /// Numeric value for the risk level (1-5).
    pub fn as_u8(&self) -> u8 {
        match self {
            OapsRiskLevel::R1 => 1,
            OapsRiskLevel::R2 => 2,
            OapsRiskLevel::R3 => 3,
            OapsRiskLevel::R4 => 4,
            OapsRiskLevel::R5 => 5,
        }
    }

    /// Parse from numeric value, returning None for out-of-range.
    pub fn from_u8(level: u8) -> Option<Self> {
        match level {
            1 => Some(OapsRiskLevel::R1),
            2 => Some(OapsRiskLevel::R2),
            3 => Some(OapsRiskLevel::R3),
            4 => Some(OapsRiskLevel::R4),
            5 => Some(OapsRiskLevel::R5),
            _ => None,
        }
    }
}

// ============================================================================
// Part 1: OAPS Policy Enrichment
// ============================================================================

/// Maps OAPS risk levels (R1-R5) to Agentbox buckets.
///
/// The mapping follows a conservative principle — higher risk levels map to
/// more restrictive buckets. This is a one-way enrichment: OAPS informs
/// Agentbox's decision, but Agentbox's own classify() always runs too.
/// The final decision is the most restrictive of the two.
///
/// ## Mapping Table
///
/// ```text
///   OAPS Level │ Agentbox Bucket │ Rationale
///   ───────────┼─────────────────┼──────────────────────────────────
///   R1 (1)     │ Allow           │ Routine read-only operations
///   R2 (2)     │ Allow           │ Safe writes within workspace
///   R3 (3)     │ Approve         │ Moderate risk, human should verify
///   R4 (4)     │ Block           │ High risk, deny without approval flow
///   R5 (5)     │ Block           │ Critical, instant deny
///   unknown    │ Approve         │ Conservative default for unknown levels
/// ```
///
/// ## Example
///
/// ```rust
/// use crate::integrations::oaps::*;
///
/// // An OAPS-evaluated database mutation comes in as R4
/// let oaps_bucket = risk_to_bucket(4);
/// assert_eq!(oaps_bucket, AgentboxBucket::Block);
///
/// // A routine file read comes in as R1
/// let oaps_bucket = risk_to_bucket(1);
/// assert_eq!(oaps_bucket, AgentboxBucket::Allow);
///
/// // Unknown risk level defaults to Approve (conservative)
/// let oaps_bucket = risk_to_bucket(99);
/// assert_eq!(oaps_bucket, AgentboxBucket::Approve);
/// ```
pub fn risk_to_bucket(risk_level: u8) -> AgentboxBucket {
    match risk_level {
        1..=2 => AgentboxBucket::Allow,
        3 => AgentboxBucket::Approve,
        4..=5 => AgentboxBucket::Block,
        _ => AgentboxBucket::Approve, // conservative default
    }
}

/// Enriched classification that combines Agentbox's OS-level decision
/// with OAPS's protocol-level risk assessment.
///
/// ## Decision Logic
///
/// ```text
///   OAPS says Allow  + Agentbox says Allow   → Allow
///   OAPS says Allow  + Agentbox says Approve → Approve  (OS-level sees risk)
///   OAPS says Approve + Agentbox says Allow  → Approve  (protocol-level sees risk)
///   OAPS says Block  + Agentbox says Allow   → Block    (most restrictive wins)
///   OAPS says Block  + Agentbox says Block   → Block
/// ```
#[derive(Debug, Clone)]
pub struct EnrichedClassification {
    /// The final decision — most restrictive of OAPS and Agentbox.
    pub bucket: AgentboxBucket,
    /// Which system drove the final decision.
    pub decided_by: DecisionSource,
    /// OAPS risk level that was evaluated.
    pub oaps_risk: OapsRiskLevel,
    /// What Agentbox's own classify() returned.
    pub agentbox_bucket: AgentboxBucket,
    /// What OAPS's risk mapping returned.
    pub oaps_bucket: AgentboxBucket,
    /// Human-readable explanation combining both assessments.
    pub reason: String,
}

/// Which system's assessment drove the final (most restrictive) decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// Agentbox OS-level classification was more restrictive.
    Agentbox,
    /// OAPS protocol-level assessment was more restrictive.
    Oaps,
    /// Both systems agreed on the same bucket.
    Unanimous,
}

/// Combine an OAPS risk assessment with an Agentbox classification.
///
/// The most restrictive decision wins. This ensures that neither layer
/// can unilaterally weaken the other's assessment.
///
/// ## Data Flow
///
/// ```text
///   Agent action
///       │
///       ├──► OAPS evaluate() ──► R3 ──► risk_to_bucket() ──► Approve
///       │
///       ├──► Agentbox classify() ──────────────────────────► Allow
///       │
///       └──► enrich() ──► most_restrictive(Approve, Allow) ──► Approve
///                                                               │
///                                                    decided_by: Oaps
/// ```
pub fn enrich(
    oaps_risk: OapsRiskLevel,
    agentbox_bucket: AgentboxBucket,
    agentbox_reason: &str,
) -> EnrichedClassification {
    let oaps_bucket = risk_to_bucket(oaps_risk.as_u8());
    let final_bucket = agentbox_bucket.most_restrictive(oaps_bucket);

    let decided_by = if oaps_bucket == agentbox_bucket {
        DecisionSource::Unanimous
    } else if final_bucket == oaps_bucket {
        DecisionSource::Oaps
    } else {
        DecisionSource::Agentbox
    };

    let reason = match decided_by {
        DecisionSource::Unanimous => format!(
            "Both OAPS ({:?}) and Agentbox agree: {:?}. {}",
            oaps_risk, final_bucket, agentbox_reason
        ),
        DecisionSource::Oaps => format!(
            "OAPS escalated to {:?} (risk {:?}). Agentbox said {:?}: {}",
            final_bucket, oaps_risk, agentbox_bucket, agentbox_reason
        ),
        DecisionSource::Agentbox => format!(
            "Agentbox escalated to {:?}. OAPS said {:?} (risk {:?}): {}",
            final_bucket, oaps_bucket, oaps_risk, agentbox_reason
        ),
    };

    EnrichedClassification {
        bucket: final_bucket,
        decided_by,
        oaps_risk,
        agentbox_bucket,
        oaps_bucket,
        reason,
    }
}

// ============================================================================
// Part 2: Evidence Chain Integration
// ============================================================================

/// An OAPS evidence record — the atomic unit of the tamper-evident audit chain.
///
/// Each record is hash-linked to the previous one via `previous_hash`,
/// forming an append-only chain. Any modification to a historical record
/// breaks the chain, making tampering detectable.
///
/// ## Chain Structure
///
/// ```text
///   ┌───────────────────────────┐
///   │ Evidence Record #1        │
///   │                           │
///   │ id: "ev_001"              │
///   │ timestamp: 1718900000     │
///   │ action: "git push ..."    │
///   │ outcome: "approved"       │
///   │ actor_ref: "claude-code"  │
///   │ evidence_hash: "a3f2..."  │ ◄── SHA-256(id + timestamp + action + outcome + actor_ref)
///   │ previous_hash: "0000..."  │ ◄── genesis record (no predecessor)
///   └────────────┬──────────────┘
///                │
///                │ previous_hash links to evidence_hash of #1
///                ▼
///   ┌───────────────────────────┐
///   │ Evidence Record #2        │
///   │                           │
///   │ id: "ev_002"              │
///   │ timestamp: 1718900042     │
///   │ action: "psql DROP ..."   │
///   │ outcome: "blocked"        │
///   │ actor_ref: "hermes"       │
///   │ evidence_hash: "b7c1..."  │
///   │ previous_hash: "a3f2..."  │ ◄── matches #1's evidence_hash
///   └───────────────────────────┘
/// ```
#[derive(Debug, Clone)]
pub struct OapsEvidenceRecord {
    /// Unique identifier for this evidence record.
    pub id: String,
    /// Unix timestamp in seconds when the action was intercepted.
    pub timestamp: u64,
    /// Human-readable description of the intercepted action.
    /// Derived from Agentbox's `command` field.
    pub action: String,
    /// Result of the interception: "allowed", "approved", "denied", "blocked", "timed_out".
    /// Maps directly from Agentbox's `decision` field.
    pub outcome: String,
    /// Reference to the acting agent. Combines Agentbox's `agent_name` and `agent_pid`.
    /// Format: "{agent_name}:{agent_pid}" or "unknown:{pid}" if name is absent.
    pub actor_ref: String,
    /// SHA-256 hash of this record's content fields (id + timestamp + action + outcome + actor_ref).
    /// Used as the integrity anchor — the next record links to this hash.
    pub evidence_hash: String,
    /// SHA-256 hash of the previous record in the chain.
    /// Genesis record uses "0000000000000000000000000000000000000000000000000000000000000000".
    pub previous_hash: String,
}

/// The genesis hash — used as `previous_hash` for the first record in a chain.
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Converts Agentbox audit events into OAPS evidence records, maintaining
/// the hash-linked chain.
///
/// ## Mapping: Agentbox AuditEvent → OAPS EvidenceRecord
///
/// ```text
///   Agentbox AuditEvent Field  │  OAPS EvidenceRecord Field
///   ───────────────────────────┼───────────────────────────
///   id (ULID)                  │  id (prefixed with "ab_")
///   timestamp (RFC 3339)       │  timestamp (unix seconds)
///   command                    │  action
///   decision                   │  outcome
///   agent_name + agent_pid     │  actor_ref
///   (computed)                 │  evidence_hash
///   (from previous record)     │  previous_hash
/// ```
///
/// ## Usage
///
/// ```rust
/// use crate::integrations::oaps::*;
///
/// let adapter = AgentboxEvidenceAdapter::new();
///
/// // Adapter converts Agentbox audit events one at a time,
/// // maintaining the chain internally.
/// let record = adapter.convert(&some_audit_event);
/// ```
pub struct AgentboxEvidenceAdapter {
    /// The hash of the most recently produced evidence record.
    /// Used as `previous_hash` for the next record.
    last_hash: String,
}

impl AgentboxEvidenceAdapter {
    /// Create a new adapter. The first record produced will be a genesis record
    /// (its `previous_hash` will be all zeros).
    pub fn new() -> Self {
        Self {
            last_hash: GENESIS_HASH.to_string(),
        }
    }

    /// Convert an Agentbox AuditEvent into an OAPS evidence record.
    ///
    /// Each call advances the chain — the returned record's `previous_hash`
    /// points to the last record produced by this adapter instance.
    ///
    /// ## Field Mapping
    ///
    /// - `id`: Prefixed with "ab_" to distinguish Agentbox-originated records
    ///   from records produced by other OAPS evidence sources.
    /// - `timestamp`: Parsed from the AuditEvent's RFC 3339 string to unix seconds.
    ///   Falls back to current time if parsing fails.
    /// - `action`: The raw command string from the audit event.
    /// - `outcome`: The decision string (allowed/approved/denied/blocked/timed_out).
    /// - `actor_ref`: "{agent_name}:{agent_pid}" or "unknown:{pid}".
    /// - `evidence_hash`: SHA-256 of the concatenated content fields.
    /// - `previous_hash`: Hash of the previous record in the chain.
    pub fn convert(&mut self, event: &AgentboxAuditEvent) -> OapsEvidenceRecord {
        let id = format!("ab_{}", event.id);

        let timestamp = parse_rfc3339_to_unix(&event.timestamp).unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });

        let actor_ref = match &event.agent_name {
            Some(name) => format!("{}:{}", name, event.agent_pid),
            None => format!("unknown:{}", event.agent_pid),
        };

        let action = event.command.clone();
        let outcome = event.decision.clone();

        // Compute evidence hash: SHA-256(id || timestamp || action || outcome || actor_ref)
        let hash_input = format!("{}{}{}{}{}", id, timestamp, action, outcome, actor_ref);
        let evidence_hash = sha256_hex(&hash_input);

        let previous_hash = self.last_hash.clone();
        self.last_hash = evidence_hash.clone();

        OapsEvidenceRecord {
            id,
            timestamp,
            action,
            outcome,
            actor_ref,
            evidence_hash,
            previous_hash,
        }
    }

    /// Verify that a sequence of evidence records forms a valid chain.
    ///
    /// Returns `Ok(())` if every record's `previous_hash` matches the
    /// preceding record's `evidence_hash`. Returns `Err` with the index
    /// of the first broken link.
    pub fn verify_chain(records: &[OapsEvidenceRecord]) -> Result<(), usize> {
        for i in 1..records.len() {
            if records[i].previous_hash != records[i - 1].evidence_hash {
                return Err(i);
            }
        }
        Ok(())
    }
}

/// Minimal representation of an Agentbox AuditEvent for this reference module.
/// In production, import `agentbox_daemon::audit::AuditEvent` directly.
#[derive(Debug, Clone)]
pub struct AgentboxAuditEvent {
    pub id: String,
    pub timestamp: String,
    pub agent_pid: i64,
    pub agent_name: Option<String>,
    pub command: String,
    pub cwd: String,
    pub bucket: String,
    pub decision: String,
    pub user_response_ms: Option<i64>,
    pub parent_process: Option<String>,
}

// ============================================================================
// Part 3: MCP Proxy Bridge
// ============================================================================

/// Bridge between Agentbox's MCP Governance Proxy (v1.5) and OAPS's MCP adapter.
///
/// When an agent makes an MCP tool call, two systems evaluate it independently:
///
/// 1. **OAPS MCP Adapter** — Understands the tool's *semantic meaning*.
///    For example, `supabase.delete_table("users")` is R5 regardless of
///    how it's implemented under the hood.
///
/// 2. **Agentbox MCP Proxy** — Intercepts the *execution-level* side effects.
///    The same `delete_table` call might execute `psql -c 'DROP TABLE users'`
///    which Agentbox catches at the shell level.
///
/// The bridge combines both evaluations. The most restrictive decision wins.
///
/// ## MCP Tool Call Flow
///
/// ```text
///   ┌───────────────┐
///   │   AI Agent     │
///   │                │
///   │  tool_call:    │
///   │   supabase.    │
///   │   delete_table │
///   │   ("users")    │
///   └───────┬────────┘
///           │
///           │  MCP JSON-RPC request
///           ▼
///   ┌───────────────────────────────────────────┐
///   │         McpPolicyBridge                    │
///   │                                           │
///   │  ┌─────────────────┐ ┌─────────────────┐  │
///   │  │ OAPS MCP Adapter│ │Agentbox MCP     │  │
///   │  │                 │ │Proxy            │  │
///   │  │ Semantic eval:  │ │                 │  │
///   │  │ delete_table    │ │ OS-level eval:  │  │
///   │  │ → R5 (critical) │ │ psql DROP TABLE │  │
///   │  │ → Block         │ │ → Approve       │  │
///   │  └────────┬────────┘ └────────┬────────┘  │
///   │           │                    │           │
///   │           └──────┬─────────────┘           │
///   │                  ▼                         │
///   │       most_restrictive(Block, Approve)     │
///   │                  │                         │
///   │                  ▼                         │
///   │            Final: Block                    │
///   │            Source: OAPS                    │
///   └──────────────────┬────────────────────────┘
///                      │
///                      ▼
///               Action denied.
///               Evidence record created.
/// ```
pub struct McpPolicyBridge {
    /// Client for the Agentbox daemon (OS-level policy evaluation).
    /// In production, this would be an `AgentboxClient` from agentbox-client crate.
    agentbox_socket_path: String,

    /// OAPS policy evaluator (protocol-level semantic risk assessment).
    /// In production, this would be an OAPS policy engine client or a direct
    /// reference to the OAPS evaluate() function.
    oaps_endpoint: String,

    /// Evidence adapter for recording bridge decisions into the OAPS chain.
    evidence_adapter: AgentboxEvidenceAdapter,
}

/// Represents an MCP tool call that the bridge needs to evaluate.
#[derive(Debug, Clone)]
pub struct McpToolCall {
    /// The MCP server name (e.g., "supabase", "github", "stripe").
    pub server: String,
    /// The tool name (e.g., "delete_table", "create_pr", "charge_card").
    pub tool: String,
    /// Tool arguments as a JSON string.
    pub arguments_json: String,
    /// The agent making the call (for audit trail).
    pub agent_id: String,
}

/// Result of the bridge's combined policy evaluation.
#[derive(Debug, Clone)]
pub struct McpPolicyDecision {
    /// The final bucket — most restrictive of OAPS and Agentbox.
    pub bucket: AgentboxBucket,
    /// Which system drove the decision.
    pub decided_by: DecisionSource,
    /// OAPS's semantic risk assessment.
    pub oaps_risk: OapsRiskLevel,
    /// What OAPS recommended.
    pub oaps_bucket: AgentboxBucket,
    /// What Agentbox recommended.
    pub agentbox_bucket: AgentboxBucket,
    /// Combined explanation.
    pub reason: String,
    /// Evidence record for the audit chain (created regardless of outcome).
    pub evidence: OapsEvidenceRecord,
}

impl McpPolicyBridge {
    /// Create a new bridge connecting Agentbox and OAPS for MCP tool call evaluation.
    ///
    /// - `agentbox_socket`: Path to the Agentbox daemon socket (e.g., "~/.agentbox/agentbox.sock").
    /// - `oaps_endpoint`: URL or socket path for the OAPS policy engine.
    pub fn new(agentbox_socket: &str, oaps_endpoint: &str) -> Self {
        Self {
            agentbox_socket_path: agentbox_socket.to_string(),
            oaps_endpoint: oaps_endpoint.to_string(),
            evidence_adapter: AgentboxEvidenceAdapter::new(),
        }
    }

    /// Evaluate an MCP tool call against both policy engines.
    ///
    /// This is the core method. In production it would:
    /// 1. Send the tool call to OAPS for semantic risk evaluation.
    /// 2. Extract the shell commands the MCP server would execute.
    /// 3. Send those commands to Agentbox for OS-level classification.
    /// 4. Combine both decisions (most restrictive wins).
    /// 5. Create an evidence record for the audit chain.
    ///
    /// ## Reference Implementation
    ///
    /// The actual network calls are stubbed here. In production, replace
    /// `evaluate_oaps_risk` and `evaluate_agentbox_bucket` with real
    /// client calls to each system.
    pub fn evaluate(&mut self, tool_call: &McpToolCall) -> McpPolicyDecision {
        // Step 1: OAPS semantic evaluation
        let oaps_risk = self.evaluate_oaps_risk(tool_call);
        let oaps_bucket = risk_to_bucket(oaps_risk.as_u8());

        // Step 2: Agentbox OS-level evaluation
        // The bridge infers what shell command(s) the MCP tool call would produce.
        let agentbox_bucket = self.evaluate_agentbox_bucket(tool_call);

        // Step 3: Most restrictive wins
        let final_bucket = agentbox_bucket.most_restrictive(oaps_bucket);
        let decided_by = if oaps_bucket == agentbox_bucket {
            DecisionSource::Unanimous
        } else if final_bucket == oaps_bucket {
            DecisionSource::Oaps
        } else {
            DecisionSource::Agentbox
        };

        let reason = format!(
            "MCP tool {}.{}: OAPS={:?} (risk {:?}), Agentbox={:?} → Final={:?} (by {:?})",
            tool_call.server, tool_call.tool,
            oaps_bucket, oaps_risk,
            agentbox_bucket, final_bucket, decided_by
        );

        // Step 4: Create evidence record
        let decision_str = match final_bucket {
            AgentboxBucket::Allow => "allowed",
            AgentboxBucket::Approve => "pending_approval",
            AgentboxBucket::Block => "blocked",
        };

        let audit_event = AgentboxAuditEvent {
            id: format!("mcp_{}_{}", tool_call.server, generate_id()),
            timestamp: now_rfc3339(),
            agent_pid: 0, // MCP calls don't have a direct PID
            agent_name: Some(tool_call.agent_id.clone()),
            command: format!("{}.{}({})", tool_call.server, tool_call.tool, tool_call.arguments_json),
            cwd: String::new(),
            bucket: format!("{:?}", final_bucket).to_lowercase(),
            decision: decision_str.to_string(),
            user_response_ms: None,
            parent_process: None,
        };

        let evidence = self.evidence_adapter.convert(&audit_event);

        McpPolicyDecision {
            bucket: final_bucket,
            decided_by,
            oaps_risk,
            oaps_bucket,
            agentbox_bucket,
            reason,
            evidence,
        }
    }

    /// Stub: Evaluate the MCP tool call via OAPS semantic risk engine.
    ///
    /// In production, this sends the tool call to the OAPS endpoint and receives
    /// an R1-R5 risk classification based on the tool's semantic meaning.
    ///
    /// Example heuristic (for reference only):
    /// - read_* tools → R1
    /// - create_*/update_* tools → R3
    /// - delete_* tools → R4-R5
    /// - financial tools (charge, transfer) → R5
    fn evaluate_oaps_risk(&self, tool_call: &McpToolCall) -> OapsRiskLevel {
        // Reference heuristic — replace with actual OAPS client call.
        let tool_lower = tool_call.tool.to_lowercase();

        if tool_lower.starts_with("read") || tool_lower.starts_with("get") || tool_lower.starts_with("list") {
            OapsRiskLevel::R1
        } else if tool_lower.starts_with("create") || tool_lower.starts_with("update") {
            OapsRiskLevel::R3
        } else if tool_lower.starts_with("delete") || tool_lower.starts_with("drop") {
            OapsRiskLevel::R5
        } else if tool_lower.contains("charge") || tool_lower.contains("transfer") || tool_lower.contains("send") {
            OapsRiskLevel::R5
        } else {
            OapsRiskLevel::R3 // unknown tools get moderate risk
        }
    }

    /// Stub: Evaluate what Agentbox would classify for the underlying shell command.
    ///
    /// In production, the MCP proxy intercepts the actual command execution and
    /// sends it through the Agentbox daemon socket. Here we use a heuristic
    /// based on the MCP server name and tool.
    fn evaluate_agentbox_bucket(&self, tool_call: &McpToolCall) -> AgentboxBucket {
        // Reference heuristic — replace with actual Agentbox client call.
        let server = tool_call.server.to_lowercase();
        let tool_lower = tool_call.tool.to_lowercase();

        // Database servers get Approve by default (Agentbox flags all DB clients)
        if ["supabase", "postgres", "mysql", "sqlite", "mongo"].iter().any(|s| server.contains(s)) {
            return AgentboxBucket::Approve;
        }

        // Destructive tools on any server get Approve
        if tool_lower.contains("delete") || tool_lower.contains("drop") || tool_lower.contains("remove") {
            return AgentboxBucket::Approve;
        }

        // Network-related MCP servers
        if ["stripe", "sendgrid", "twilio", "aws"].iter().any(|s| server.contains(s)) {
            return AgentboxBucket::Approve;
        }

        AgentboxBucket::Allow
    }

    /// Returns the socket path this bridge uses for Agentbox communication.
    pub fn agentbox_socket(&self) -> &str {
        &self.agentbox_socket_path
    }

    /// Returns the OAPS endpoint this bridge communicates with.
    pub fn oaps_endpoint(&self) -> &str {
        &self.oaps_endpoint
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Simple SHA-256 hex digest. In production, use the `sha2` crate.
/// This reference implementation uses a basic string hash for illustration.
fn sha256_hex(input: &str) -> String {
    // NOTE: Replace with proper SHA-256 in production.
    // Using a simple FNV-style hash here for zero-dependency reference code.
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut hash2: u64 = 0x517cc1b727220a95;
    for byte in input.bytes().rev() {
        hash2 ^= byte as u64;
        hash2 = hash2.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}{:016x}{:016x}{:016x}", hash, hash2, hash ^ hash2, hash.wrapping_add(hash2))
}

/// Parse an RFC 3339 timestamp string to unix seconds.
/// Returns None if parsing fails.
fn parse_rfc3339_to_unix(rfc3339: &str) -> Option<u64> {
    // Minimal parser for "YYYY-MM-DDTHH:MM:SS..." format.
    // In production, use chrono::DateTime::parse_from_rfc3339().
    let parts: Vec<&str> = rfc3339.split('T').collect();
    if parts.len() < 2 {
        return None;
    }

    // For this reference module, we return None and let the fallback
    // use SystemTime::now(). Production code should use chrono.
    None
}

/// Generate a short unique ID. In production, use ULID or UUID.
fn generate_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}", now.as_nanos())
}

/// Current time as RFC 3339 string.
fn now_rfc3339() -> String {
    // Minimal implementation. In production, use chrono::Utc::now().to_rfc3339().
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    format!("1970-01-01T00:00:00+00:00#{}", secs) // placeholder format
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Part 1: Risk-to-bucket mapping ----

    #[test]
    fn r1_maps_to_allow() {
        assert_eq!(risk_to_bucket(1), AgentboxBucket::Allow);
    }

    #[test]
    fn r2_maps_to_allow() {
        assert_eq!(risk_to_bucket(2), AgentboxBucket::Allow);
    }

    #[test]
    fn r3_maps_to_approve() {
        assert_eq!(risk_to_bucket(3), AgentboxBucket::Approve);
    }

    #[test]
    fn r4_maps_to_block() {
        assert_eq!(risk_to_bucket(4), AgentboxBucket::Block);
    }

    #[test]
    fn r5_maps_to_block() {
        assert_eq!(risk_to_bucket(5), AgentboxBucket::Block);
    }

    #[test]
    fn unknown_risk_defaults_to_approve() {
        assert_eq!(risk_to_bucket(0), AgentboxBucket::Approve);
        assert_eq!(risk_to_bucket(6), AgentboxBucket::Approve);
        assert_eq!(risk_to_bucket(255), AgentboxBucket::Approve);
    }

    // ---- Part 1: Most-restrictive merging ----

    #[test]
    fn most_restrictive_selects_block_over_allow() {
        let result = AgentboxBucket::Allow.most_restrictive(AgentboxBucket::Block);
        assert_eq!(result, AgentboxBucket::Block);
    }

    #[test]
    fn most_restrictive_selects_approve_over_allow() {
        let result = AgentboxBucket::Allow.most_restrictive(AgentboxBucket::Approve);
        assert_eq!(result, AgentboxBucket::Approve);
    }

    #[test]
    fn most_restrictive_same_bucket_returns_same() {
        let result = AgentboxBucket::Approve.most_restrictive(AgentboxBucket::Approve);
        assert_eq!(result, AgentboxBucket::Approve);
    }

    // ---- Part 1: Enrichment ----

    #[test]
    fn enrich_oaps_escalates_when_more_restrictive() {
        let result = enrich(OapsRiskLevel::R4, AgentboxBucket::Allow, "safe by default");
        assert_eq!(result.bucket, AgentboxBucket::Block);
        assert_eq!(result.decided_by, DecisionSource::Oaps);
    }

    #[test]
    fn enrich_agentbox_escalates_when_more_restrictive() {
        let result = enrich(OapsRiskLevel::R1, AgentboxBucket::Approve, "git push");
        assert_eq!(result.bucket, AgentboxBucket::Approve);
        assert_eq!(result.decided_by, DecisionSource::Agentbox);
    }

    #[test]
    fn enrich_unanimous_when_both_agree() {
        let result = enrich(OapsRiskLevel::R3, AgentboxBucket::Approve, "moderate risk");
        assert_eq!(result.bucket, AgentboxBucket::Approve);
        assert_eq!(result.decided_by, DecisionSource::Unanimous);
    }

    // ---- Part 2: Evidence chain ----

    #[test]
    fn first_record_has_genesis_previous_hash() {
        let mut adapter = AgentboxEvidenceAdapter::new();
        let event = make_test_event("allowed", "cat README.md");
        let record = adapter.convert(&event);
        assert_eq!(record.previous_hash, GENESIS_HASH);
        assert!(record.id.starts_with("ab_"));
    }

    #[test]
    fn chain_links_correctly() {
        let mut adapter = AgentboxEvidenceAdapter::new();

        let e1 = make_test_event("allowed", "cat README.md");
        let e2 = make_test_event("approved", "git push origin main");
        let e3 = make_test_event("blocked", "rm -rf /");

        let r1 = adapter.convert(&e1);
        let r2 = adapter.convert(&e2);
        let r3 = adapter.convert(&e3);

        // Each record links to the previous
        assert_eq!(r2.previous_hash, r1.evidence_hash);
        assert_eq!(r3.previous_hash, r2.evidence_hash);

        // Chain verification passes
        assert!(AgentboxEvidenceAdapter::verify_chain(&[r1, r2, r3]).is_ok());
    }

    #[test]
    fn tampered_chain_detected() {
        let mut adapter = AgentboxEvidenceAdapter::new();

        let e1 = make_test_event("allowed", "ls");
        let e2 = make_test_event("blocked", "rm -rf /");

        let r1 = adapter.convert(&e1);
        let mut r2 = adapter.convert(&e2);

        // Tamper with r2's previous_hash
        r2.previous_hash = "tampered_hash".to_string();

        assert_eq!(AgentboxEvidenceAdapter::verify_chain(&[r1, r2]), Err(1));
    }

    #[test]
    fn actor_ref_format_with_name() {
        let mut adapter = AgentboxEvidenceAdapter::new();
        let mut event = make_test_event("allowed", "ls");
        event.agent_name = Some("claude-code".to_string());
        event.agent_pid = 4242;

        let record = adapter.convert(&event);
        assert_eq!(record.actor_ref, "claude-code:4242");
    }

    #[test]
    fn actor_ref_format_without_name() {
        let mut adapter = AgentboxEvidenceAdapter::new();
        let mut event = make_test_event("allowed", "ls");
        event.agent_name = None;
        event.agent_pid = 9999;

        let record = adapter.convert(&event);
        assert_eq!(record.actor_ref, "unknown:9999");
    }

    // ---- Part 3: MCP bridge ----

    #[test]
    fn bridge_blocks_destructive_database_tool() {
        let mut bridge = McpPolicyBridge::new(
            "/tmp/test-agentbox.sock",
            "http://localhost:9090/oaps",
        );

        let tool_call = McpToolCall {
            server: "supabase".to_string(),
            tool: "delete_table".to_string(),
            arguments_json: r#"{"table": "users"}"#.to_string(),
            agent_id: "claude-code".to_string(),
        };

        let decision = bridge.evaluate(&tool_call);

        // OAPS: delete_table → R5 → Block
        // Agentbox: supabase server → Approve
        // Most restrictive: Block (from OAPS)
        assert_eq!(decision.bucket, AgentboxBucket::Block);
        assert_eq!(decision.decided_by, DecisionSource::Oaps);
        assert_eq!(decision.oaps_risk, OapsRiskLevel::R5);
    }

    #[test]
    fn bridge_allows_read_operations() {
        let mut bridge = McpPolicyBridge::new(
            "/tmp/test-agentbox.sock",
            "http://localhost:9090/oaps",
        );

        let tool_call = McpToolCall {
            server: "github".to_string(),
            tool: "list_repos".to_string(),
            arguments_json: "{}".to_string(),
            agent_id: "hermes".to_string(),
        };

        let decision = bridge.evaluate(&tool_call);

        // OAPS: list_* → R1 → Allow
        // Agentbox: github read → Allow
        // Both agree: Allow
        assert_eq!(decision.bucket, AgentboxBucket::Allow);
        assert_eq!(decision.decided_by, DecisionSource::Unanimous);
    }

    #[test]
    fn bridge_creates_evidence_for_every_decision() {
        let mut bridge = McpPolicyBridge::new(
            "/tmp/test-agentbox.sock",
            "http://localhost:9090/oaps",
        );

        let tool_call = McpToolCall {
            server: "stripe".to_string(),
            tool: "charge_card".to_string(),
            arguments_json: r#"{"amount": 5000}"#.to_string(),
            agent_id: "agent-x".to_string(),
        };

        let decision = bridge.evaluate(&tool_call);

        // Evidence record should exist
        assert!(decision.evidence.id.starts_with("ab_mcp_stripe_"));
        assert_eq!(decision.evidence.outcome, "blocked");
        assert!(decision.evidence.action.contains("charge_card"));
    }

    // ---- Helpers ----

    fn make_test_event(decision: &str, command: &str) -> AgentboxAuditEvent {
        AgentboxAuditEvent {
            id: generate_id(),
            timestamp: "2026-04-16T12:00:00+00:00".to_string(),
            agent_pid: 1234,
            agent_name: Some("test-agent".to_string()),
            command: command.to_string(),
            cwd: "/home/user/project".to_string(),
            bucket: "allow".to_string(),
            decision: decision.to_string(),
            user_response_ms: None,
            parent_process: None,
        }
    }
}
