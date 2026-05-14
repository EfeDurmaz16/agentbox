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
// No async runtime. Pure synchronous std::os::unix.

use serde::{Deserialize, Serialize};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ShimRequest {
    binary: String,
    args: Vec<String>,
    cwd: String,
    parent_process: String,
    pid: u32,
}

#[derive(Deserialize)]
struct ShimResponse {
    #[serde(default)]
    decision: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    real_binary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailMode {
    Open,
    Closed,
}

// ---------------------------------------------------------------------------
// Socket path
// ---------------------------------------------------------------------------

fn socket_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".agentbox").join("agentbox.sock")
}

fn fail_mode_from_env() -> FailMode {
    parse_fail_mode(std::env::var("AGENTBOX_FAIL_MODE").ok().as_deref())
}

fn parse_fail_mode(value: Option<&str>) -> FailMode {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        Some(value) if matches!(value.as_str(), "closed" | "fail-closed" | "deny") => {
            FailMode::Closed
        }
        _ => FailMode::Open,
    }
}

// ---------------------------------------------------------------------------
// Find real binary by searching PATH, skipping the shim directory
// ---------------------------------------------------------------------------

fn find_real_binary(name: &str) -> Option<PathBuf> {
    let path_var = env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        // Skip any PATH entry that contains our shim directory
        if dir.contains(".agentbox/shims") {
            continue;
        }
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Parent process detection (macOS via sysctl)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn get_parent_process_name() -> String {
    let ppid = unsafe { libc::getppid() };

    // Use proc_pidpath to get the executable path of the parent process.
    // This is the simplest reliable API on macOS (libproc.h).
    extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_char,
            buffersize: u32,
        ) -> libc::c_int;
    }

    let mut buf = [0u8; libc::PATH_MAX as usize];
    let ret = unsafe {
        proc_pidpath(
            ppid,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len() as u32,
        )
    };

    if ret <= 0 {
        return format!("unknown(ppid={})", ppid);
    }

    let path_bytes = &buf[..ret as usize];
    let path = String::from_utf8_lossy(path_bytes);

    // Extract just the binary name from the full path
    Path::new(path.as_ref())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(target_os = "linux")]
fn get_parent_process_name() -> String {
    let ppid = unsafe { libc::getppid() };
    let comm_path = format!("/proc/{}/comm", ppid);
    std::fs::read_to_string(&comm_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| format!("unknown(ppid={})", ppid))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn get_parent_process_name() -> String {
    let ppid = unsafe { libc::getppid() };
    format!("unknown(ppid={})", ppid)
}

// ---------------------------------------------------------------------------
// Daemon communication
// ---------------------------------------------------------------------------

fn ask_daemon(request: &ShimRequest) -> Result<ShimResponse, String> {
    let sock_path = socket_path();

    let mut stream =
        UnixStream::connect(&sock_path).map_err(|e| format!("connect failed: {}", e))?;

    // Set a reasonable timeout so we don't hang forever
    let timeout = std::time::Duration::from_secs(5);
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    // Send newline-delimited JSON
    let mut payload = serde_json::to_vec(request).map_err(|e| format!("serialize: {}", e))?;
    payload.push(b'\n');

    stream
        .write_all(&payload)
        .map_err(|e| format!("write: {}", e))?;

    // Read one line of JSON response
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read: {}", e))?;

    serde_json::from_str(&line).map_err(|e| format!("deserialize: {}", e))
}

// ---------------------------------------------------------------------------
// Run the real binary — replaces this process entirely via unix exec
// ---------------------------------------------------------------------------

fn run_binary(binary_path: &str, args: &[String]) -> ! {
    let err = Command::new(binary_path).args(args).exec();
    // exec() only returns on error
    eprintln!("agentbox-shim: failed to run {}: {}", binary_path, err);
    std::process::exit(126);
}

// ---------------------------------------------------------------------------
// Fallback: daemon unreachable; fail-open runs the real binary, fail-closed denies.
// ---------------------------------------------------------------------------

fn fallback(binary_name: &str, args: &[String], reason: &str) -> ! {
    if matches!(fail_mode_from_env(), FailMode::Closed) {
        eprintln!(
            "agentbox-shim: daemon unavailable ({}), fail-closed denying `{}`",
            reason, binary_name
        );
        std::process::exit(111);
    }

    eprintln!(
        "agentbox-shim: daemon unavailable ({}), passing through `{}`",
        reason, binary_name
    );
    match find_real_binary(binary_name) {
        Some(real) => run_binary(real.to_str().unwrap_or(binary_name), args),
        None => {
            eprintln!(
                "agentbox-shim: cannot find `{}` in PATH (excluding shim dir)",
                binary_name
            );
            std::process::exit(127);
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let argv0 = env::args().next().unwrap_or_default();
    let binary_name = Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let args: Vec<String> = env::args().skip(1).collect();

    let cwd = env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| ".".to_string());

    let parent_process = get_parent_process_name();
    let pid = std::process::id();

    let request = ShimRequest {
        binary: binary_name.clone(),
        args: args.clone(),
        cwd,
        parent_process,
        pid,
    };

    // If the daemon socket doesn't exist, fail-open immediately (skip connect attempt)
    if !socket_path().exists() {
        fallback(&binary_name, &args, "socket not found");
    }

    // Ask the daemon
    let response = match ask_daemon(&request) {
        Ok(resp) => resp,
        Err(e) => fallback(&binary_name, &args, &e),
    };

    // Act on the decision
    match response.decision.as_str() {
        "allowed" | "approved" => {
            // Use the real_binary from daemon response if provided, otherwise find it ourselves
            let real_path = if response.real_binary.is_empty() {
                match find_real_binary(&binary_name) {
                    Some(p) => p.to_string_lossy().to_string(),
                    None => {
                        eprintln!(
                            "agentbox-shim: cannot find `{}` in PATH (excluding shim dir)",
                            binary_name
                        );
                        std::process::exit(127);
                    }
                }
            } else {
                response.real_binary
            };
            run_binary(&real_path, &args);
        }
        "denied" | "blocked" | "timed_out" => {
            eprintln!(
                "agentbox: {} `{} {}` — {}",
                response.decision,
                binary_name,
                args.join(" "),
                response.reason
            );
            std::process::exit(1);
        }
        other => {
            // Unknown decision — treat as deny for safety
            eprintln!(
                "agentbox: unknown decision '{}' for `{} {}` — denying",
                other,
                binary_name,
                args.join(" ")
            );
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fail_mode_defaults_open() {
        assert_eq!(parse_fail_mode(None), FailMode::Open);
        assert_eq!(parse_fail_mode(Some("")), FailMode::Open);
        assert_eq!(parse_fail_mode(Some("open")), FailMode::Open);
    }

    #[test]
    fn parse_fail_mode_accepts_closed_aliases() {
        assert_eq!(parse_fail_mode(Some("closed")), FailMode::Closed);
        assert_eq!(parse_fail_mode(Some("fail-closed")), FailMode::Closed);
        assert_eq!(parse_fail_mode(Some("deny")), FailMode::Closed);
        assert_eq!(parse_fail_mode(Some(" CLOSED ")), FailMode::Closed);
    }
}
