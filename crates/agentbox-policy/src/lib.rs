/// Agentbox policy engine — classifies commands into allow/approve/block buckets.
///
/// This is the core risk classification logic. It must be:
/// - Fast (called on every shim invocation)
/// - Deterministic (no network, no LLM, no randomness)
/// - Conservative (when in doubt, approve rather than allow)

pub mod classify;
pub mod rules;
