use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "agentbox",
    about = "2FA for AI agent actions",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon in background
    Start,
    /// Stop the daemon
    Stop,
    /// Show daemon status
    Status,
    /// Query audit log
    Audit {
        /// Number of events to show
        #[arg(long, default_value_t = 20)]
        limit: usize,

        /// Filter by bucket (allow, approve, block)
        #[arg(long)]
        bucket: Option<String>,

        /// Live tail mode (re-query every 2s)
        #[arg(long)]
        tail: bool,
    },
    /// Set up shims for dangerous commands
    Install,
    /// Add domain to network allowlist
    Allow {
        /// Domain to allow (e.g. api.example.com)
        domain: String,
    },
    /// Run a command inside an isolated Agentbox sandbox pod
    Run {
        /// Command to run (e.g., "openclaw start" or "npm test")
        command: Vec<String>,

        /// Runtime image (node, python, rust, go, ruby)
        #[arg(long)]
        runtime: Option<String>,

        /// Add a service sidecar (postgres, redis, mysql, mongo)
        #[arg(long = "with", num_args = 1..)]
        services: Vec<String>,

        /// Mount current directory into pod (default: true)
        #[arg(long, default_value = "true")]
        mount_cwd: bool,

        /// Resource limit: memory in MB (default: 1024)
        #[arg(long, default_value = "1024")]
        memory: u64,
    },
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn agentbox_dir() -> PathBuf {
    dirs::home_dir()
        .expect("cannot determine home directory")
        .join(".agentbox")
}

fn pid_path() -> PathBuf {
    agentbox_dir().join("agentbox.pid")
}

fn socket_path() -> PathBuf {
    agentbox_dir().join("agentbox.sock")
}

fn config_path() -> PathBuf {
    agentbox_dir().join("config.toml")
}

fn audit_db_path() -> PathBuf {
    agentbox_dir().join("audit.db")
}

fn shims_dir() -> PathBuf {
    agentbox_dir().join("shims")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ensure_dir(p: &PathBuf) {
    if !p.exists() {
        fs::create_dir_all(p).expect("failed to create directory");
    }
}

/// Read PID from the pid file. Returns None if file missing or unreadable.
fn read_pid() -> Option<u32> {
    fs::read_to_string(pid_path())
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Check if a process with the given PID is alive.
fn process_alive(pid: u32) -> bool {
    // signal 0 checks existence without sending a real signal
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Locate the agentbox-daemon binary.
/// Looks next to the current executable first, then falls back to PATH.
fn find_daemon_binary() -> Option<PathBuf> {
    // Same directory as this binary
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap().join("agentbox-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    // Fall back: assume it's on PATH
    which_in_path("agentbox-daemon")
}

fn which_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full = dir.join(name);
            if full.is_file() {
                Some(full)
            } else {
                None
            }
        })
    })
}

/// Locate the agentbox-shim binary.
fn find_shim_binary() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap().join("agentbox-shim");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    which_in_path("agentbox-shim")
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_start() {
    ensure_dir(&agentbox_dir());

    // Check if already running
    if let Some(pid) = read_pid() {
        if process_alive(pid) {
            eprintln!("daemon already running (PID: {})", pid);
            std::process::exit(1);
        }
    }

    let daemon = find_daemon_binary().unwrap_or_else(|| {
        eprintln!("error: agentbox-daemon binary not found");
        eprintln!("hint: run `cargo build -p agentbox-daemon` first");
        std::process::exit(1);
    });

    let child = Command::new(&daemon)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("failed to start daemon: {}", e);
            std::process::exit(1);
        });

    let pid = child.id();

    // Write PID file
    fs::write(pid_path(), pid.to_string()).expect("failed to write pid file");

    println!("daemon started (PID: {})", pid);
}

fn cmd_stop() {
    let pid = match read_pid() {
        Some(pid) if process_alive(pid) => pid,
        Some(_) => {
            // Stale PID file
            let _ = fs::remove_file(pid_path());
            eprintln!("daemon not running (stale pid file cleaned)");
            std::process::exit(1);
        }
        None => {
            eprintln!("daemon not running (no pid file)");
            std::process::exit(1);
        }
    };

    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }

    // Wait briefly for process to exit
    for _ in 0..20 {
        if !process_alive(pid) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = fs::remove_file(pid_path());
    println!("daemon stopped");
}

fn cmd_status() {
    let running = read_pid().map_or(false, |pid| process_alive(pid));

    if running {
        let pid = read_pid().unwrap();
        println!("status:  running");
        println!("pid:     {}", pid);
    } else {
        println!("status:  stopped");
    }

    let sock = socket_path();
    println!("socket:  {}", sock.display());

    // Read ntfy topic from config if available
    let topic = fs::read_to_string(config_path())
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .and_then(|t| {
            t.get("ntfy")
                .and_then(|v| v.as_table())
                .and_then(|nt| nt.get("topic"))
                .and_then(|v| v.as_str().map(String::from))
        })
        .unwrap_or_else(|| "(not configured)".into());
    println!("ntfy:    {}", topic);

    // List active shims
    let shims = shims_dir();
    if shims.exists() {
        let mut names: Vec<String> = fs::read_dir(&shims)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let path = e.path();
                if path.is_symlink() || path.is_file() {
                    Some(e.file_name().to_string_lossy().into_owned())
                } else {
                    None
                }
            })
            .collect();
        names.sort();
        if names.is_empty() {
            println!("shims:   (none)");
        } else {
            println!("shims:   {} active", names.len());
            for name in &names {
                println!("         - {}", name);
            }
        }
    } else {
        println!("shims:   (not installed, run `agentbox install`)");
    }
}

fn cmd_audit(limit: usize, bucket: Option<String>, tail: bool) {
    let db_path = audit_db_path();
    if !db_path.exists() {
        eprintln!("no audit log found at {}", db_path.display());
        eprintln!("hint: start the daemon first with `agentbox start`");
        std::process::exit(1);
    }

    if tail {
        // Live tail: re-query every 2 seconds
        let mut last_id: i64 = 0;
        print_audit_header();
        loop {
            last_id = print_audit_events(&db_path, limit, &bucket, Some(last_id));
            io::stdout().flush().ok();
            thread::sleep(Duration::from_secs(2));
        }
    } else {
        print_audit_header();
        print_audit_events(&db_path, limit, &bucket, None);
    }
}

fn print_audit_header() {
    println!(
        "{:<14} {:<9} {:<10} {}",
        "TIME", "BUCKET", "DECISION", "COMMAND"
    );
}

/// Query and print audit events. Returns the max rowid seen (for tail mode).
fn print_audit_events(
    db_path: &PathBuf,
    limit: usize,
    bucket: &Option<String>,
    after_id: Option<i64>,
) -> i64 {
    let conn = Connection::open(db_path).expect("failed to open audit db");

    let mut sql = String::from(
        "SELECT rowid, timestamp, bucket, decision, command FROM audit_log WHERE 1=1",
    );

    if let Some(ref b) = bucket {
        sql.push_str(&format!(" AND bucket = '{}'", b));
    }
    if let Some(id) = after_id {
        sql.push_str(&format!(" AND rowid > {}", id));
    }
    sql.push_str(&format!(" ORDER BY rowid DESC LIMIT {}", limit));

    let mut stmt = conn.prepare(&sql).expect("failed to prepare query");

    let mut max_id: i64 = after_id.unwrap_or(0);

    let rows = stmt
        .query_map([], |row| {
            let rowid: i64 = row.get(0)?;
            let timestamp: String = row.get(1)?;
            let bucket: String = row.get(2)?;
            let decision: String = row.get(3)?;
            let command: String = row.get(4)?;
            Ok((rowid, timestamp, bucket, decision, command))
        })
        .expect("failed to query audit log");

    let mut events: Vec<_> = rows.filter_map(|r| r.ok()).collect();
    // Reverse so oldest prints first (we queried DESC for LIMIT)
    events.reverse();

    for (rowid, timestamp, bucket, decision, command) in &events {
        if *rowid > max_id {
            max_id = *rowid;
        }
        // Extract just the time portion if possible
        let time_display = if timestamp.len() >= 19 {
            &timestamp[11..19]
        } else {
            timestamp.as_str()
        };
        println!(
            "{:<14} {:<9} {:<10} {}",
            time_display, bucket, decision, command
        );
    }

    max_id
}

fn cmd_install() {
    let shims = shims_dir();
    ensure_dir(&shims);

    let shim_binary = find_shim_binary().unwrap_or_else(|| {
        eprintln!("error: agentbox-shim binary not found");
        eprintln!("hint: run `cargo build -p agentbox-shim` first");
        std::process::exit(1);
    });

    let commands = [
        "rm",
        "git",
        "ssh",
        "scp",
        "curl",
        "wget",
        "psql",
        "mysql",
        "sqlite3",
        "npm",
        "cargo",
        "gem",
        "pip",
        "gh",
        "osascript",
        "chmod",
        "kill",
        "killall",
        "docker",
        "kubectl",
        "cat",
        "head",
        "tail",
        "dd",
        "mkfs",
        "diskutil",
        "csrutil",
        "spctl",
    ];

    let mut created = 0;
    let mut skipped = 0;

    for cmd in &commands {
        let link_path = shims.join(cmd);
        if link_path.exists() || link_path.is_symlink() {
            // Remove old symlink to ensure it points to current shim
            let _ = fs::remove_file(&link_path);
        }
        match std::os::unix::fs::symlink(&shim_binary, &link_path) {
            Ok(()) => created += 1,
            Err(e) => {
                eprintln!("warning: failed to create shim for {}: {}", cmd, e);
                skipped += 1;
            }
        }
    }

    println!("installed {} shims ({} skipped)", created, skipped);
    println!();
    println!("Add this to your shell profile (~/.zshrc or ~/.bashrc):");
    println!();
    println!("  export PATH=\"{}:$PATH\"", shims.display());
    println!();
    println!("Then restart your shell or run:");
    println!();
    println!("  source ~/.zshrc");
}

fn cmd_run(command: Vec<String>, runtime: Option<String>, services: Vec<String>, mount_cwd: bool, memory: u64) {
    use agentbox_daemon::pod::intent::IntentParser;
    use agentbox_daemon::pod::types::MountSpec;

    let parser = IntentParser::new();
    let mut spec = parser.from_run_args(
        &command,
        runtime.as_deref(),
        &services,
        memory,
    );

    // Generate a short pod id
    let pod_id: String = format!("{:08x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32);
    spec.name = format!("sb-{}", pod_id);

    // Mount current working directory → /workspace
    if mount_cwd {
        if let Ok(cwd) = std::env::current_dir() {
            spec.mounts.push(MountSpec {
                host_path: cwd,
                container_path: "/workspace".to_string(),
                read_only: false,
            });
        }
    }

    // Mount agentbox socket into pod
    let sock = socket_path();
    spec.mounts.push(MountSpec {
        host_path: sock,
        container_path: "/run/agentbox.sock".to_string(),
        read_only: false,
    });

    // Print spec summary
    let ws = &spec.containers[0];
    println!("Creating sandbox...");
    println!("  name:    {}", spec.name);
    println!("  image:   {}", ws.image);
    if let Some(ref cmd) = ws.command {
        println!("  command: {}", cmd.join(" "));
    }
    println!("  memory:  {} MB", memory);

    if spec.containers.len() > 1 {
        println!("  sidecars:");
        for c in &spec.containers[1..] {
            println!("         - {} ({})", c.name, c.image);
        }
    }

    if !spec.env.is_empty() {
        println!("  env:");
        for (k, v) in &spec.env {
            println!("         {}={}", k, v);
        }
    }

    if !spec.mounts.is_empty() {
        println!("  mounts:");
        for m in &spec.mounts {
            let ro = if m.read_only { " (ro)" } else { "" };
            println!("         {} → {}{}", m.host_path.display(), m.container_path, ro);
        }
    }

    println!();
    println!("Pod created. To exec: podman exec -it {} bash", spec.name);

    if !command.is_empty() {
        println!();
        println!("[would exec: {} in {}]", command.join(" "), spec.name);
    }
}

fn cmd_allow(domain: String) {
    ensure_dir(&agentbox_dir());

    let cfg_path = config_path();

    let mut config: toml::Table = if cfg_path.exists() {
        let content = fs::read_to_string(&cfg_path).expect("failed to read config.toml");
        content.parse().expect("failed to parse config.toml")
    } else {
        toml::Table::new()
    };

    // Get or create [network] table
    let network = config
        .entry("network")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .expect("network should be a table");

    // Get or create allowed_domains array
    let domains = network
        .entry("allowed_domains")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .expect("allowed_domains should be an array");

    // Check for duplicates
    let already_exists = domains.iter().any(|v| v.as_str() == Some(&domain));
    if already_exists {
        println!("{} is already in the allowlist", domain);
        return;
    }

    domains.push(toml::Value::String(domain.clone()));

    let serialized = toml::to_string_pretty(&config).expect("failed to serialize config");
    fs::write(&cfg_path, serialized).expect("failed to write config.toml");

    println!("added {} to allowlist", domain);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start => cmd_start(),
        Commands::Stop => cmd_stop(),
        Commands::Status => cmd_status(),
        Commands::Audit {
            limit,
            bucket,
            tail,
        } => cmd_audit(limit, bucket, tail),
        Commands::Install => cmd_install(),
        Commands::Allow { domain } => cmd_allow(domain),
        Commands::Run {
            command,
            runtime,
            services,
            mount_cwd,
            memory,
        } => cmd_run(command, runtime, services, mount_cwd, memory),
    }
}
