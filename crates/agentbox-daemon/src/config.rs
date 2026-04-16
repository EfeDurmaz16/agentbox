use std::fs;
use std::path::{Path, PathBuf};

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
    pub ntfy_topic: String,
    pub ntfy_server: String,
    pub approval_timeout_secs: u64,
    pub shim_dir: String,
    pub allowed_domains: Vec<String>,
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
            ntfy_topic: format!("agentbox-{random_id}"),
            ntfy_server: "https://ntfy.sh".to_string(),
            approval_timeout_secs: 120,
            shim_dir: base.join("shims").to_string_lossy().into_owned(),
            allowed_domains: Vec::new(),
            log_level: "info".to_string(),
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
        assert!(config.allowed_domains.is_empty());
        assert!(config.ntfy_topic.starts_with("agentbox-"));
        assert!(config.socket_path.ends_with("agentbox.sock"));
        assert!(config.db_path.ends_with("audit.db"));
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
            ntfy_topic: "my-topic".to_string(),
            ntfy_server: "https://my-ntfy.example.com".to_string(),
            approval_timeout_secs: 60,
            shim_dir: "/tmp/shims".to_string(),
            allowed_domains: vec!["github.com".to_string(), "api.openai.com".to_string()],
            log_level: "debug".to_string(),
        };

        let contents = toml::to_string_pretty(&custom).unwrap();
        fs::write(base.join("config.toml"), &contents).unwrap();

        let loaded = load_from(&base).unwrap();
        assert_eq!(loaded, custom);
        assert_eq!(loaded.approval_timeout_secs, 60);
        assert_eq!(loaded.allowed_domains.len(), 2);
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
ntfy_topic = "test"
ntfy_server = "https://ntfy.sh"
approval_timeout_secs = 5
shim_dir = "/tmp/shims"
allowed_domains = []
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
