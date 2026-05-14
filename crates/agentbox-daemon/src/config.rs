use std::fs;
use std::path::{Path, PathBuf};

use agentbox_policy::classify::PolicyConfig;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Read(#[from] std::io::Error),

    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("failed to serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("could not determine home directory")]
    NoHomeDir,

    #[error("invalid approval_timeout_secs: {0} (must be 30-600)")]
    InvalidTimeout(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    pub socket_path: String,
    pub db_path: String,
    #[serde(default = "default_session_store_path")]
    pub session_store_path: String,
    #[serde(default = "default_runtime_provider")]
    pub runtime_provider: String,
    pub ntfy_topic: String,
    pub ntfy_server: String,
    pub approval_timeout_secs: u64,
    pub shim_dir: String,
    #[serde(default)]
    pub workspace: Option<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub denied_domains: Vec<String>,
    #[serde(default)]
    pub always_allow: Vec<String>,
    #[serde(default)]
    pub always_block: Vec<String>,
    pub log_level: String,
}

impl Config {
    /// Validate config values. Returns error if any field is out of range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.approval_timeout_secs < 30 || self.approval_timeout_secs > 600 {
            return Err(ConfigError::InvalidTimeout(self.approval_timeout_secs));
        }
        Ok(())
    }

    /// Build a default config rooted at the given base directory.
    pub fn default_for_dir(base: &Path) -> Self {
        let random_id = generate_topic_id();

        Self {
            socket_path: base.join("agentbox.sock").to_string_lossy().into_owned(),
            db_path: base.join("audit.db").to_string_lossy().into_owned(),
            session_store_path: base
                .join("runtime-sessions.json")
                .to_string_lossy()
                .into_owned(),
            runtime_provider: default_runtime_provider(),
            ntfy_topic: format!("agentbox-{random_id}"),
            ntfy_server: "https://ntfy.sh".to_string(),
            approval_timeout_secs: 120,
            shim_dir: base.join("shims").to_string_lossy().into_owned(),
            workspace: None,
            allowed_domains: Vec::new(),
            denied_domains: Vec::new(),
            always_allow: Vec::new(),
            always_block: Vec::new(),
            log_level: "info".to_string(),
        }
    }

    pub fn to_policy_config(&self) -> PolicyConfig {
        PolicyConfig {
            workspace: self.workspace.clone(),
            allowed_domains: self.allowed_domains.clone(),
            denied_domains: self.denied_domains.clone(),
            always_allow: self.always_allow.clone(),
            always_block: self.always_block.clone(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::default_for_dir(&config_dir())
    }
}

/// Returns ~/.agentbox/
pub fn config_dir() -> PathBuf {
    dirs::home_dir()
        .expect("could not determine home directory")
        .join(".agentbox")
}

fn default_session_store_path() -> String {
    config_dir()
        .join("runtime-sessions.json")
        .to_string_lossy()
        .into_owned()
}

fn default_runtime_provider() -> String {
    "auto".to_string()
}

/// Creates ~/.agentbox/ and ~/.agentbox/shims/ if they don't exist.
pub fn ensure_dirs() -> Result<(), ConfigError> {
    ensure_dirs_at(&config_dir())
}

/// Creates the given base dir and its shims/ subdirectory.
fn ensure_dirs_at(base: &Path) -> Result<(), ConfigError> {
    fs::create_dir_all(base.join("shims")).map_err(ConfigError::Read)?;
    Ok(())
}

/// Load config from ~/.agentbox/config.toml.
/// Creates the file with defaults if it doesn't exist.
pub fn load() -> Result<Config, ConfigError> {
    load_from(&config_dir())
}

/// Load config from a specific base directory.
/// Creates the file with defaults if it doesn't exist.
pub fn load_from(base: &Path) -> Result<Config, ConfigError> {
    ensure_dirs_at(base)?;

    let config_path = base.join("config.toml");

    if !config_path.exists() {
        let config = Config::default_for_dir(base);
        let contents = toml::to_string_pretty(&config)?;
        fs::write(&config_path, &contents)?;
        tracing::info!("created default config at {}", config_path.display());
        return Ok(config);
    }

    let contents = fs::read_to_string(&config_path)?;
    let config: Config = toml::from_str(&contents)?;
    config.validate()?;
    Ok(config)
}

/// Generate a short random hex ID for the default ntfy topic.
fn generate_topic_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 6] = rng.gen();
    hex::encode(&bytes)
}

/// Minimal hex encoder — avoids pulling in the `hex` crate for 12 chars.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a fresh temp directory for each test.
    fn temp_base() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agentbox-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn default_config_has_valid_values() {
        let base = temp_base();
        fs::create_dir_all(&base).unwrap();

        let config = Config::default_for_dir(&base);
        assert_eq!(config.approval_timeout_secs, 120);
        assert_eq!(config.ntfy_server, "https://ntfy.sh");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.runtime_provider, "auto");
        assert!(config.workspace.is_none());
        assert!(config.allowed_domains.is_empty());
        assert!(config.always_allow.is_empty());
        assert!(config.always_block.is_empty());
        assert!(config.ntfy_topic.starts_with("agentbox-"));
        assert!(config.socket_path.ends_with("agentbox.sock"));
        assert!(config.db_path.ends_with("audit.db"));
        assert!(config.session_store_path.ends_with("runtime-sessions.json"));
        assert!(config.shim_dir.ends_with("shims"));
        assert!(config.validate().is_ok());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn load_creates_default_config_file() {
        let base = temp_base();
        let config_path = base.join("config.toml");
        assert!(!config_path.exists());

        let config = load_from(&base).unwrap();
        assert!(config_path.exists());
        assert_eq!(config.approval_timeout_secs, 120);
        assert_eq!(config.ntfy_server, "https://ntfy.sh");

        // Shims dir should also exist
        assert!(base.join("shims").is_dir());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn load_reads_custom_config() {
        let base = temp_base();
        fs::create_dir_all(base.join("shims")).unwrap();

        let custom = Config {
            socket_path: "/tmp/custom.sock".to_string(),
            db_path: "/tmp/custom.db".to_string(),
            session_store_path: "/tmp/runtime-sessions.json".to_string(),
            runtime_provider: "podman".to_string(),
            ntfy_topic: "my-topic".to_string(),
            ntfy_server: "https://my-ntfy.example.com".to_string(),
            approval_timeout_secs: 60,
            shim_dir: "/tmp/shims".to_string(),
            workspace: Some("/tmp/workspace".to_string()),
            allowed_domains: vec!["github.com".to_string(), "api.openai.com".to_string()],
            denied_domains: vec!["metadata.google.internal".to_string()],
            always_allow: vec!["git status".to_string()],
            always_block: vec!["npm *".to_string()],
            log_level: "debug".to_string(),
        };

        let contents = toml::to_string_pretty(&custom).unwrap();
        fs::write(base.join("config.toml"), &contents).unwrap();

        let loaded = load_from(&base).unwrap();
        assert_eq!(loaded, custom);
        assert_eq!(loaded.approval_timeout_secs, 60);
        assert_eq!(loaded.session_store_path, "/tmp/runtime-sessions.json");
        assert_eq!(loaded.runtime_provider, "podman");
        assert_eq!(loaded.workspace.as_deref(), Some("/tmp/workspace"));
        assert_eq!(loaded.allowed_domains.len(), 2);
        assert_eq!(loaded.always_allow, vec!["git status"]);
        assert_eq!(loaded.always_block, vec!["npm *"]);
        assert_eq!(loaded.ntfy_server, "https://my-ntfy.example.com");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn load_rejects_invalid_timeout_in_file() {
        let base = temp_base();
        fs::create_dir_all(base.join("shims")).unwrap();

        let bad_toml = r#"
socket_path = "/tmp/test.sock"
db_path = "/tmp/test.db"
session_store_path = "/tmp/runtime-sessions.json"
runtime_provider = "auto"
ntfy_topic = "test"
ntfy_server = "https://ntfy.sh"
approval_timeout_secs = 5
shim_dir = "/tmp/shims"
workspace = "/tmp/workspace"
allowed_domains = []
always_allow = []
always_block = []
log_level = "info"
"#;
        fs::write(base.join("config.toml"), bad_toml).unwrap();

        let result = load_from(&base);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid approval_timeout_secs"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn validate_rejects_invalid_timeout() {
        let base = temp_base();
        fs::create_dir_all(&base).unwrap();

        let mut config = Config::default_for_dir(&base);

        config.approval_timeout_secs = 10;
        assert!(config.validate().is_err());

        config.approval_timeout_secs = 700;
        assert!(config.validate().is_err());

        config.approval_timeout_secs = 30;
        assert!(config.validate().is_ok());

        config.approval_timeout_secs = 600;
        assert!(config.validate().is_ok());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ensure_dirs_creates_directories() {
        let base = temp_base();
        assert!(!base.exists());

        ensure_dirs_at(&base).unwrap();

        assert!(base.is_dir());
        assert!(base.join("shims").is_dir());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn config_maps_to_policy_config() {
        let mut config = Config::default_for_dir(&temp_base());
        config.workspace = Some("/tmp/project".to_string());
        config.allowed_domains = vec!["github.com".to_string()];
        config.always_allow = vec!["git status".to_string()];
        config.always_block = vec!["rm".to_string()];

        let policy = config.to_policy_config();

        assert_eq!(policy.workspace.as_deref(), Some("/tmp/project"));
        assert_eq!(policy.allowed_domains, vec!["github.com"]);
        assert_eq!(policy.always_allow, vec!["git status"]);
        assert_eq!(policy.always_block, vec!["rm"]);
    }

    #[test]
    fn config_dir_points_to_dot_agentbox() {
        let dir = config_dir();
        assert!(dir.ends_with(".agentbox"));
    }

    #[test]
    fn roundtrip_serialize_deserialize() {
        let base = temp_base();
        fs::create_dir_all(&base).unwrap();

        let config = Config::default_for_dir(&base);
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);

        let _ = fs::remove_dir_all(&base);
    }
}
