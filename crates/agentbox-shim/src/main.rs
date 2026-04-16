// Agentbox Shim — a single binary that acts as multiple command interceptors.
//
// How it works:
// 1. Binary is compiled once as `agentbox-shim`
// 2. Symlinked to ~/.agentbox/shims/rm, ~/.agentbox/shims/git, etc.
// 3. ~/.agentbox/shims is prepended to PATH
// 4. When agent calls `rm`, this binary runs instead
// 5. It detects which command it's being called as (argv[0])
// 6. Sends classification request to daemon via Unix socket
// 7. If allowed: exec the real binary (found by searching PATH minus shim dir)
// 8. If denied: exit with error message
//
// The shim must be FAST. For allowed commands, overhead should be <50ms.
// It connects to the daemon socket, sends JSON, reads JSON response.
//
// TODO: implement this. The key challenge is finding the real binary
// (search PATH entries after the shim directory).

use std::env;

fn main() {
    let argv0 = env::args().next().unwrap_or_default();
    let binary_name = std::path::Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let args: Vec<String> = env::args().skip(1).collect();

    eprintln!("agentbox-shim: intercepted `{} {}`", binary_name, args.join(" "));
    eprintln!("agentbox-shim: not yet implemented — passing through");

    // TODO: connect to daemon, classify, approve/deny, then exec real binary
    std::process::exit(1);
}
