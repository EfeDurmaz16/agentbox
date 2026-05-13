use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::runtime::types::RuntimeSession;

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("failed to read session store: {0}")]
    Read(#[from] std::io::Error),

    #[error("failed to parse session store: {0}")]
    Parse(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SessionStoreError>;

#[derive(Debug, Clone)]
pub struct RuntimeSessionStore {
    path: PathBuf,
}

impl RuntimeSessionStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn list(&self) -> Result<Vec<RuntimeSession>> {
        Ok(self.load()?.into_values().collect())
    }

    pub fn get(&self, id: &str) -> Result<Option<RuntimeSession>> {
        Ok(self.load()?.remove(id))
    }

    pub fn upsert(&self, session: RuntimeSession) -> Result<()> {
        let mut sessions = self.load()?;
        sessions.insert(session.id.clone(), session);
        self.save(&sessions)
    }

    pub fn remove(&self, id: &str) -> Result<Option<RuntimeSession>> {
        let mut sessions = self.load()?;
        let removed = sessions.remove(id);
        self.save(&sessions)?;
        Ok(removed)
    }

    fn load(&self) -> Result<BTreeMap<String, RuntimeSession>> {
        if !self.path.exists() {
            return Ok(BTreeMap::new());
        }

        let contents = fs::read_to_string(&self.path)?;
        if contents.trim().is_empty() {
            return Ok(BTreeMap::new());
        }

        serde_json::from_str(&contents).map_err(SessionStoreError::Parse)
    }

    fn save(&self, sessions: &BTreeMap<String, RuntimeSession>) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(sessions)?;
        fs::write(&self.path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::MinipodSpec;

    fn store_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "agentbox-session-store-{}-{name}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn empty_store_lists_no_sessions() {
        let path = store_path("empty");
        let store = RuntimeSessionStore::new(&path);

        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn upsert_and_get_roundtrip_session() {
        let path = store_path("roundtrip");
        let store = RuntimeSessionStore::new(&path);
        let spec = MinipodSpec::for_agent_task("openclaw", "/tmp/workspace");
        let session = RuntimeSession::new(
            spec.name.clone(),
            "native-test".to_string(),
            "test".to_string(),
            spec,
        );
        let id = session.id.clone();

        store.upsert(session.clone()).unwrap();

        let got = store.get(&id).unwrap().unwrap();
        assert_eq!(got.id, id);
        assert_eq!(got.provider, "native-test");
        assert_eq!(store.list().unwrap().len(), 1);

        let removed = store.remove(&id).unwrap().unwrap();
        assert_eq!(removed.id, id);
        assert!(store.list().unwrap().is_empty());

        let _ = fs::remove_file(path);
    }
}
