use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),
}

pub type Result<T> = std::result::Result<T, AuditError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub agent_pid: i64,
    pub agent_name: Option<String>,
    pub command: String,
    pub cwd: String,
    pub bucket: String,
    pub decision: String,
    pub user_response_ms: Option<i64>,
    pub parent_process: Option<String>,
}

impl AuditEvent {
    /// Create a new AuditEvent with auto-generated ULID and timestamp.
    pub fn new(
        agent_pid: i64,
        agent_name: Option<String>,
        command: String,
        cwd: String,
        bucket: String,
        decision: String,
        user_response_ms: Option<i64>,
        parent_process: Option<String>,
    ) -> Self {
        Self {
            id: Ulid::new().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            agent_pid,
            agent_name,
            command,
            cwd,
            bucket,
            decision,
            user_response_ms,
            parent_process,
        }
    }
}

pub struct AuditStore {
    pool: Pool<SqliteConnectionManager>,
}

impl AuditStore {
    /// Open or create the audit database at `db_path`.
    /// Use ":memory:" for in-memory databases (tests).
    pub fn new(db_path: &str) -> Result<Self> {
        let manager = SqliteConnectionManager::file(db_path);
        let pool = Pool::builder().max_size(4).build(manager)?;

        let conn = pool.get()?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id                TEXT PRIMARY KEY,
                timestamp         TEXT NOT NULL,
                agent_pid         INTEGER NOT NULL,
                agent_name        TEXT,
                command           TEXT NOT NULL,
                cwd               TEXT NOT NULL,
                bucket            TEXT NOT NULL,
                decision          TEXT NOT NULL,
                user_response_ms  INTEGER,
                parent_process    TEXT
            );",
        )?;

        Ok(Self { pool })
    }

    /// Open an in-memory database (convenience for tests).
    pub fn in_memory() -> Result<Self> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager)?;

        let conn = pool.get()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id                TEXT PRIMARY KEY,
                timestamp         TEXT NOT NULL,
                agent_pid         INTEGER NOT NULL,
                agent_name        TEXT,
                command           TEXT NOT NULL,
                cwd               TEXT NOT NULL,
                bucket            TEXT NOT NULL,
                decision          TEXT NOT NULL,
                user_response_ms  INTEGER,
                parent_process    TEXT
            );",
        )?;

        Ok(Self { pool })
    }

    /// Insert a single audit event.
    pub fn log_event(&self, event: &AuditEvent) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO audit_log
                (id, timestamp, agent_pid, agent_name, command, cwd, bucket, decision, user_response_ms, parent_process)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                event.id,
                event.timestamp,
                event.agent_pid,
                event.agent_name,
                event.command,
                event.cwd,
                event.bucket,
                event.decision,
                event.user_response_ms,
                event.parent_process,
            ],
        )?;
        Ok(())
    }

    /// Return the last `limit` events ordered by most recent first.
    pub fn recent(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, agent_pid, agent_name, command, cwd, bucket, decision, user_response_ms, parent_process
             FROM audit_log
             ORDER BY timestamp DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], row_to_event)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(AuditError::from)
    }

    /// Return the last `limit` events filtered by bucket.
    pub fn query_by_bucket(&self, bucket: &str, limit: usize) -> Result<Vec<AuditEvent>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, agent_pid, agent_name, command, cwd, bucket, decision, user_response_ms, parent_process
             FROM audit_log
             WHERE bucket = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![bucket, limit as i64], row_to_event)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(AuditError::from)
    }
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<AuditEvent> {
    Ok(AuditEvent {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        agent_pid: row.get(2)?,
        agent_name: row.get(3)?,
        command: row.get(4)?,
        cwd: row.get(5)?,
        bucket: row.get(6)?,
        decision: row.get(7)?,
        user_response_ms: row.get(8)?,
        parent_process: row.get(9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(bucket: &str, decision: &str, command: &str) -> AuditEvent {
        AuditEvent::new(
            1234,
            Some("claude-code".into()),
            command.into(),
            "/home/user/project".into(),
            bucket.into(),
            decision.into(),
            None,
            Some("/usr/bin/node".into()),
        )
    }

    #[test]
    fn insert_and_query_recent() {
        let store = AuditStore::in_memory().unwrap();

        let e1 = make_event("allow", "allowed", "cat foo.txt");
        let e2 = make_event("approve", "approved", "git push origin main");
        store.log_event(&e1).unwrap();
        store.log_event(&e2).unwrap();

        let recent = store.recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        // Most recent first
        assert_eq!(recent[0].command, "git push origin main");
        assert_eq!(recent[1].command, "cat foo.txt");
    }

    #[test]
    fn query_by_bucket() {
        let store = AuditStore::in_memory().unwrap();

        store
            .log_event(&make_event("allow", "allowed", "ls -la"))
            .unwrap();
        store
            .log_event(&make_event("approve", "approved", "git push"))
            .unwrap();
        store
            .log_event(&make_event("block", "blocked", "rm -rf /"))
            .unwrap();
        store
            .log_event(&make_event("approve", "denied", "ssh root@prod"))
            .unwrap();

        let approve_events = store.query_by_bucket("approve", 10).unwrap();
        assert_eq!(approve_events.len(), 2);
        for e in &approve_events {
            assert_eq!(e.bucket, "approve");
        }

        let block_events = store.query_by_bucket("block", 10).unwrap();
        assert_eq!(block_events.len(), 1);
        assert_eq!(block_events[0].command, "rm -rf /");
    }

    #[test]
    fn recent_respects_limit() {
        let store = AuditStore::in_memory().unwrap();

        for i in 0..10 {
            store
                .log_event(&make_event("allow", "allowed", &format!("cmd-{i}")))
                .unwrap();
        }

        let recent = store.recent(3).unwrap();
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn event_fields_roundtrip() {
        let store = AuditStore::in_memory().unwrap();

        let event = AuditEvent::new(
            9999,
            Some("openclaw".into()),
            "psql -c 'DROP TABLE users'".into(),
            "/var/app".into(),
            "approve".into(),
            "timed_out".into(),
            Some(120000),
            Some("/usr/local/bin/python3".into()),
        );

        store.log_event(&event).unwrap();

        let results = store.recent(1).unwrap();
        let got = &results[0];
        assert_eq!(got.id, event.id);
        assert_eq!(got.agent_pid, 9999);
        assert_eq!(got.agent_name.as_deref(), Some("openclaw"));
        assert_eq!(got.command, "psql -c 'DROP TABLE users'");
        assert_eq!(got.cwd, "/var/app");
        assert_eq!(got.bucket, "approve");
        assert_eq!(got.decision, "timed_out");
        assert_eq!(got.user_response_ms, Some(120000));
        assert_eq!(
            got.parent_process.as_deref(),
            Some("/usr/local/bin/python3")
        );
    }

    #[test]
    fn null_optional_fields() {
        let store = AuditStore::in_memory().unwrap();

        let event = AuditEvent::new(
            42,
            None,
            "echo hello".into(),
            "/tmp".into(),
            "allow".into(),
            "allowed".into(),
            None,
            None,
        );

        store.log_event(&event).unwrap();

        let results = store.recent(1).unwrap();
        let got = &results[0];
        assert!(got.agent_name.is_none());
        assert!(got.user_response_ms.is_none());
        assert!(got.parent_process.is_none());
    }
}
