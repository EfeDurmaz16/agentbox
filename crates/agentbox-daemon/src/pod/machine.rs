use std::path::PathBuf;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::pod::provider::PodError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Linux,
}

pub struct MachineManager {
    platform: Platform,
}

impl MachineManager {
    pub fn new() -> Self {
        Self {
            platform: Self::detect_platform(),
        }
    }

    pub fn platform(&self) -> Platform {
        self.platform
    }

    pub fn needs_vm(&self) -> bool {
        self.platform == Platform::MacOS
    }

    /// Ensure the podman machine is ready (init + start on macOS, no-op on Linux).
    pub async fn ensure_ready(&self) -> Result<(), PodError> {
        if !self.needs_vm() {
            debug!("linux detected, no VM needed");
            return Ok(());
        }

        match self.machine_status().await? {
            MachineState::Running => {
                debug!("podman machine already running");
                Ok(())
            }
            MachineState::Stopped => {
                info!("podman machine stopped, starting...");
                self.machine_start().await
            }
            MachineState::NotFound => {
                info!("podman machine not found, initializing...");
                self.machine_init().await?;
                self.machine_start().await
            }
        }
    }

    /// Returns the podman socket path for the current platform.
    pub fn socket_path(&self) -> PathBuf {
        match self.platform {
            Platform::MacOS => {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(format!(
                    "{}/.local/share/containers/podman/machine/podman.sock",
                    home
                ))
            }
            Platform::Linux => {
                let uid = unsafe { libc::getuid() };
                PathBuf::from(format!("/run/user/{}/podman/podman.sock", uid))
            }
        }
    }

    fn detect_platform() -> Platform {
        if cfg!(target_os = "macos") {
            Platform::MacOS
        } else {
            Platform::Linux
        }
    }

    async fn machine_status(&self) -> Result<MachineState, PodError> {
        let output = Command::new("podman")
            .args(["machine", "inspect"])
            .output()
            .await
            .map_err(|e| PodError::Unavailable(format!("podman not found: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("no machine") || stderr.contains("not exist") {
                return Ok(MachineState::NotFound);
            }
            return Err(PodError::Internal(format!(
                "podman machine inspect failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("\"State\": \"running\"") || stdout.contains("\"Running\": true") {
            Ok(MachineState::Running)
        } else {
            Ok(MachineState::Stopped)
        }
    }

    async fn machine_init(&self) -> Result<(), PodError> {
        let output = Command::new("podman")
            .args(["machine", "init"])
            .output()
            .await
            .map_err(|e| PodError::Internal(format!("failed to run podman machine init: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Already initialized is fine
            if !stderr.contains("already exists") {
                return Err(PodError::Internal(format!(
                    "podman machine init failed: {}",
                    stderr
                )));
            }
            warn!("podman machine already initialized");
        }

        Ok(())
    }

    async fn machine_start(&self) -> Result<(), PodError> {
        let output = Command::new("podman")
            .args(["machine", "start"])
            .output()
            .await
            .map_err(|e| {
                PodError::Internal(format!("failed to run podman machine start: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Already running is fine
            if !stderr.contains("already running") {
                return Err(PodError::Internal(format!(
                    "podman machine start failed: {}",
                    stderr
                )));
            }
        }

        info!("podman machine started");
        Ok(())
    }
}

impl Default for MachineManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
enum MachineState {
    Running,
    Stopped,
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let mgr = MachineManager::new();
        if cfg!(target_os = "macos") {
            assert_eq!(mgr.platform(), Platform::MacOS);
            assert!(mgr.needs_vm());
        } else {
            assert_eq!(mgr.platform(), Platform::Linux);
            assert!(!mgr.needs_vm());
        }
    }

    #[test]
    fn test_socket_path_not_empty() {
        let mgr = MachineManager::new();
        let path = mgr.socket_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_socket_path_platform_specific() {
        let mgr = MachineManager::new();
        let path = mgr.socket_path();
        let path_str = path.to_string_lossy();
        if cfg!(target_os = "macos") {
            assert!(path_str.contains("podman.sock"));
            assert!(path_str.contains(".local/share/containers"));
        } else {
            assert!(path_str.contains("/run/user/"));
            assert!(path_str.contains("podman.sock"));
        }
    }
}
