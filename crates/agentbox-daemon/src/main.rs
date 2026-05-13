use agentbox_daemon::{audit::AuditStore, config, notify::NtfyClient, socket};
use std::sync::Arc;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load config first (creates default if missing).
    let cfg = config::load()?;

    // Initialize tracing with the configured log level.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.log_level)),
        )
        .init();

    // Ensure ~/.agentbox/ and shims/ directories exist.
    config::ensure_dirs()?;

    // Print startup banner.
    println!("agentbox daemon v0.1.0");
    println!("  socket:     {}", cfg.socket_path);
    println!("  ntfy topic: {}", cfg.ntfy_topic);
    println!("  audit db:   {}", cfg.db_path);

    // Create shared services.
    let audit = Arc::new(AuditStore::new(&cfg.db_path)?);
    let ntfy = Arc::new(NtfyClient::new(
        &cfg.ntfy_server,
        &cfg.ntfy_topic,
        cfg.approval_timeout_secs,
    ));

    // Write PID file.
    let pid_path = config::config_dir().join("agentbox.pid");
    std::fs::write(&pid_path, std::process::id().to_string())?;
    info!(
        pid = std::process::id(),
        "wrote PID file: {}",
        pid_path.display()
    );

    let socket_path = cfg.socket_path.clone();

    info!("daemon starting");

    // Run socket server with graceful shutdown on Ctrl-C / SIGTERM.
    tokio::select! {
        result = socket::run_socket_server(&cfg, audit.clone(), ntfy.clone()) => {
            if let Err(e) = result {
                error!("socket server error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    // Cleanup.
    if std::path::Path::new(&socket_path).exists() {
        let _ = std::fs::remove_file(&socket_path);
        info!("removed socket file: {socket_path}");
    }

    if pid_path.exists() {
        let _ = std::fs::remove_file(&pid_path);
        info!("removed PID file: {}", pid_path.display());
    }

    info!("daemon stopped");
    Ok(())
}
