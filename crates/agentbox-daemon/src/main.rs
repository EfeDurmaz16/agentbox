// Agentbox Daemon — the core process.
//
// Listens on a Unix socket for classification requests from shims.
// For each request:
//   1. Classify the command (allow/approve/block)
//   2. If approve: send ntfy notification, wait for response
//   3. Log decision to audit DB
//   4. Return decision to shim
//
// TODO: implement this. Start with the socket listener.

fn main() {
    println!("agentbox daemon — not yet implemented");
    println!("socket: ~/.agentbox/agentbox.sock");
}
