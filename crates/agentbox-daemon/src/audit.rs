use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    pub schema_version: i64,
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
    pub prev_hash: Option<String>,
    pub event_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerification {
    pub checked_events: usize,
    pub valid: bool,
    pub violations: Vec<AuditViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditViolation {
    pub event_id: String,
    pub reason: String,
}

const REDACTED: &str = "<redacted>";

impl AuditEvent {
    /// Create a new AuditEvent with auto-generated ULID and timestamp.
    #[allow(clippy::too_many_arguments)]
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
            schema_version: 2,
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
            prev_hash: None,
            event_hash: None,
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
                schema_version    INTEGER NOT NULL DEFAULT 1,
                timestamp         TEXT NOT NULL,
                agent_pid         INTEGER NOT NULL,
                agent_name        TEXT,
                command           TEXT NOT NULL,
                cwd               TEXT NOT NULL,
                bucket            TEXT NOT NULL,
                decision          TEXT NOT NULL,
                user_response_ms  INTEGER,
                parent_process    TEXT,
                prev_hash         TEXT,
                event_hash        TEXT
            );",
        )?;
        migrate_schema(&conn)?;

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
                schema_version    INTEGER NOT NULL DEFAULT 1,
                timestamp         TEXT NOT NULL,
                agent_pid         INTEGER NOT NULL,
                agent_name        TEXT,
                command           TEXT NOT NULL,
                cwd               TEXT NOT NULL,
                bucket            TEXT NOT NULL,
                decision          TEXT NOT NULL,
                user_response_ms  INTEGER,
                parent_process    TEXT,
                prev_hash         TEXT,
                event_hash        TEXT
            );",
        )?;
        migrate_schema(&conn)?;

        Ok(Self { pool })
    }

    /// Insert a single audit event.
    pub fn log_event(&self, event: &AuditEvent) -> Result<()> {
        let conn = self.pool.get()?;
        let mut event = event.clone();
        event.schema_version = 2;
        event.command = redact_sensitive_text(&event.command);
        event.cwd = redact_sensitive_text(&event.cwd);
        event.parent_process = event.parent_process.as_deref().map(redact_sensitive_text);
        event.prev_hash = latest_event_hash(&conn)?;
        event.event_hash = Some(compute_event_hash(&event));

        conn.execute(
            "INSERT INTO audit_log
                (id, schema_version, timestamp, agent_pid, agent_name, command, cwd, bucket, decision, user_response_ms, parent_process, prev_hash, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                event.id,
                event.schema_version,
                event.timestamp,
                event.agent_pid,
                event.agent_name,
                event.command,
                event.cwd,
                event.bucket,
                event.decision,
                event.user_response_ms,
                event.parent_process,
                event.prev_hash,
                event.event_hash,
            ],
        )?;
        Ok(())
    }

    /// Return the last `limit` events ordered by most recent first.
    pub fn recent(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, schema_version, timestamp, agent_pid, agent_name, command, cwd, bucket, decision, user_response_ms, parent_process, prev_hash, event_hash
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
            "SELECT id, schema_version, timestamp, agent_pid, agent_name, command, cwd, bucket, decision, user_response_ms, parent_process, prev_hash, event_hash
             FROM audit_log
             WHERE bucket = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![bucket, limit as i64], row_to_event)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(AuditError::from)
    }

    pub fn verify_hash_chain(&self) -> Result<AuditVerification> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, schema_version, timestamp, agent_pid, agent_name, command, cwd, bucket, decision, user_response_ms, parent_process, prev_hash, event_hash
             FROM audit_log
             ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map([], row_to_event)?;
        let events = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(AuditError::from)?;

        let mut violations = Vec::new();
        let mut previous_hash: Option<String> = None;

        for event in &events {
            if event.prev_hash != previous_hash {
                violations.push(AuditViolation {
                    event_id: event.id.clone(),
                    reason: "prev_hash does not match previous event hash".to_string(),
                });
            }

            let expected_hash = compute_event_hash(event);
            if event.event_hash.as_deref() != Some(expected_hash.as_str()) {
                violations.push(AuditViolation {
                    event_id: event.id.clone(),
                    reason: "event_hash does not match event contents".to_string(),
                });
            }

            previous_hash = event.event_hash.clone();
        }

        Ok(AuditVerification {
            checked_events: events.len(),
            valid: violations.is_empty(),
            violations,
        })
    }
}

pub fn redact_sensitive_text(input: &str) -> String {
    let mut tokens = Vec::new();
    let mut redact_next = false;

    for token in input.split_whitespace() {
        let redacted = if redact_next {
            redact_next = false;
            REDACTED.to_string()
        } else if is_sensitive_flag(token) {
            redact_next = true;
            token.to_string()
        } else {
            redact_sensitive_token(token)
        };
        tokens.push(redacted);
    }

    tokens.join(" ")
}

fn redact_sensitive_token(token: &str) -> String {
    let (prefix, core, suffix) = split_shell_wrapping(token);
    let redacted = if let Some((key, value)) = core.split_once('=') {
        if is_sensitive_key(key) || is_sensitive_flag(key) {
            format!("{key}={REDACTED}")
        } else {
            redact_url_userinfo(value)
                .map(|value| format!("{key}={value}"))
                .unwrap_or_else(|| redact_sensitive_path(core).unwrap_or_else(|| core.to_string()))
        }
    } else {
        redact_url_userinfo(core)
            .or_else(|| redact_sensitive_path(core))
            .unwrap_or_else(|| core.to_string())
    };

    format!("{prefix}{redacted}{suffix}")
}

fn split_shell_wrapping(token: &str) -> (&str, &str, &str) {
    let mut start = 0;
    let mut end = token.len();
    let bytes = token.as_bytes();

    while start < end && matches!(bytes[start], b'\'' | b'"') {
        start += 1;
    }
    while end > start && matches!(bytes[end - 1], b'\'' | b'"' | b',' | b';') {
        end -= 1;
    }

    (&token[..start], &token[start..end], &token[end..])
}

fn is_sensitive_flag(token: &str) -> bool {
    let token = token.trim_start_matches('-').to_ascii_lowercase();
    matches!(
        token.as_str(),
        "api-key"
            | "apikey"
            | "auth-token"
            | "client-secret"
            | "credential"
            | "key"
            | "password"
            | "private-key"
            | "secret"
            | "token"
    )
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("token")
        || key.contains("secret")
        || key.contains("password")
        || key.contains("passwd")
        || key.contains("api_key")
        || key.contains("apikey")
        || key.contains("access_key")
        || key.contains("private_key")
        || key == "key"
}

fn redact_url_userinfo(value: &str) -> Option<String> {
    let scheme_pos = value.find("://")?;
    let authority_start = scheme_pos + 3;
    let authority = &value[authority_start..];
    let authority_end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    let authority = &authority[..authority_end];
    let at_pos = authority.rfind('@')?;
    let host = &authority[at_pos + 1..];

    Some(format!(
        "{}{}@{}{}",
        &value[..authority_start],
        REDACTED,
        host,
        &value[authority_start + authority_end..]
    ))
}

fn redact_sensitive_path(value: &str) -> Option<String> {
    let normalized = value.replace('\\', "/");
    let sensitive = [
        "/.aws/",
        "/.azure/",
        "/.config/gcloud/",
        "/.docker/config.json",
        "/.gnupg/",
        "/.kube/",
        "/.npmrc",
        "/.ssh/",
        ".env",
        "id_rsa",
        "id_ed25519",
    ];

    if sensitive.iter().any(|needle| normalized.contains(needle)) {
        Some(REDACTED.to_string())
    } else {
        None
    }
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<AuditEvent> {
    Ok(AuditEvent {
        id: row.get(0)?,
        schema_version: row.get(1)?,
        timestamp: row.get(2)?,
        agent_pid: row.get(3)?,
        agent_name: row.get(4)?,
        command: row.get(5)?,
        cwd: row.get(6)?,
        bucket: row.get(7)?,
        decision: row.get(8)?,
        user_response_ms: row.get(9)?,
        parent_process: row.get(10)?,
        prev_hash: row.get(11)?,
        event_hash: row.get(12)?,
    })
}

fn migrate_schema(conn: &rusqlite::Connection) -> Result<()> {
    let columns = table_columns(conn)?;

    if !columns.iter().any(|c| c == "schema_version") {
        conn.execute_batch(
            "ALTER TABLE audit_log ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;",
        )?;
    }
    if !columns.iter().any(|c| c == "prev_hash") {
        conn.execute_batch("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;")?;
    }
    if !columns.iter().any(|c| c == "event_hash") {
        conn.execute_batch("ALTER TABLE audit_log ADD COLUMN event_hash TEXT;")?;
    }

    Ok(())
}

fn table_columns(conn: &rusqlite::Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("PRAGMA table_info(audit_log)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(AuditError::from)
}

fn latest_event_hash(conn: &rusqlite::Connection) -> Result<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT event_hash FROM audit_log
         WHERE event_hash IS NOT NULL
         ORDER BY rowid DESC
         LIMIT 1",
    )?;
    let mut rows = stmt.query([])?;
    if let Some(row) = rows.next()? {
        Ok(row.get(0)?)
    } else {
        Ok(None)
    }
}

fn compute_event_hash(event: &AuditEvent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.schema_version.to_string());
    hasher.update(b"\x1f");
    hasher.update(&event.id);
    hasher.update(b"\x1f");
    hasher.update(&event.timestamp);
    hasher.update(b"\x1f");
    hasher.update(event.agent_pid.to_string());
    hasher.update(b"\x1f");
    hasher.update(event.agent_name.as_deref().unwrap_or(""));
    hasher.update(b"\x1f");
    hasher.update(&event.command);
    hasher.update(b"\x1f");
    hasher.update(&event.cwd);
    hasher.update(b"\x1f");
    hasher.update(&event.bucket);
    hasher.update(b"\x1f");
    hasher.update(&event.decision);
    hasher.update(b"\x1f");
    hasher.update(
        event
            .user_response_ms
            .map(|ms| ms.to_string())
            .unwrap_or_default(),
    );
    hasher.update(b"\x1f");
    hasher.update(event.parent_process.as_deref().unwrap_or(""));
    hasher.update(b"\x1f");
    hasher.update(event.prev_hash.as_deref().unwrap_or(""));

    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
        assert_eq!(recent[0].schema_version, 2);
        assert!(recent[0].event_hash.is_some());
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
        assert_eq!(got.schema_version, 2);
        assert!(got.event_hash.is_some());
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

    #[test]
    fn redacts_sensitive_command_material_before_storage() {
        let store = AuditStore::in_memory().unwrap();
        let event = AuditEvent::new(
            42,
            Some("codex".into()),
            "OPENAI_API_KEY=sk-live curl --token abc123 https://user:pass@example.com ~/.ssh/id_ed25519".into(),
            "/home/user/.aws/credentials".into(),
            "approve".into(),
            "approved".into(),
            None,
            Some("/usr/bin/env AWS_SECRET_ACCESS_KEY=secret-value".into()),
        );

        store.log_event(&event).unwrap();

        let got = store.recent(1).unwrap().remove(0);
        assert_eq!(
            got.command,
            "OPENAI_API_KEY=<redacted> curl --token <redacted> https://<redacted>@example.com <redacted>"
        );
        assert_eq!(got.cwd, "<redacted>");
        assert_eq!(
            got.parent_process.as_deref(),
            Some("/usr/bin/env AWS_SECRET_ACCESS_KEY=<redacted>")
        );
        assert!(got.event_hash.is_some());
        assert!(store.verify_hash_chain().unwrap().valid);
    }

    #[test]
    fn redacts_sensitive_tokens_for_cli_output() {
        assert_eq!(
            redact_sensitive_text("vercel --token=abc deploy"),
            "vercel --token=<redacted> deploy"
        );
        assert_eq!(
            redact_sensitive_text("git clone https://user:pass@example.com/repo.git"),
            "git clone https://<redacted>@example.com/repo.git"
        );
        assert_eq!(
            redact_sensitive_text(
                "cat /Users/efe/.config/gcloud/application_default_credentials.json"
            ),
            "cat <redacted>"
        );
    }

    #[test]
    fn migrates_legacy_audit_schema_without_losing_rows() {
        let path = std::env::temp_dir().join(format!(
            "agentbox-legacy-audit-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_log (
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
            )
            .unwrap();
            conn.execute(
                "INSERT INTO audit_log
                    (id, timestamp, agent_pid, agent_name, command, cwd, bucket, decision, user_response_ms, parent_process)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    "legacy-event",
                    "2026-05-14T00:00:00Z",
                    1234,
                    "codex",
                    "git push origin main",
                    "/tmp/project",
                    "approve",
                    "approved",
                    1500,
                    "agentbox-shim",
                ],
            )
            .unwrap();
        }

        let store = AuditStore::new(&path.to_string_lossy()).unwrap();
        let columns = {
            let conn = store.pool.get().unwrap();
            table_columns(&conn).unwrap()
        };
        assert!(columns.iter().any(|column| column == "schema_version"));
        assert!(columns.iter().any(|column| column == "prev_hash"));
        assert!(columns.iter().any(|column| column == "event_hash"));

        let rows = store.recent(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "legacy-event");
        assert_eq!(rows[0].schema_version, 1);
        assert!(rows[0].prev_hash.is_none());
        assert!(rows[0].event_hash.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn writes_hash_chained_events_after_legacy_schema_migration() {
        let path = std::env::temp_dir().join(format!(
            "agentbox-legacy-audit-new-event-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_log (
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
            )
            .unwrap();
        }

        let store = AuditStore::new(&path.to_string_lossy()).unwrap();
        store
            .log_event(&make_event(
                "runtime",
                "created",
                "runtime.create session-1",
            ))
            .unwrap();

        let rows = store.recent(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].schema_version, 2);
        assert!(rows[0].event_hash.is_some());
        assert!(store.verify_hash_chain().unwrap().valid);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn events_are_hash_chained() {
        let store = AuditStore::in_memory().unwrap();

        store
            .log_event(&make_event("allow", "allowed", "ls"))
            .unwrap();
        store
            .log_event(&make_event("block", "blocked", "rm -rf /"))
            .unwrap();

        let recent = store.recent(10).unwrap();
        let newest = &recent[0];
        let oldest = &recent[1];

        assert!(oldest.prev_hash.is_none());
        assert!(oldest.event_hash.is_some());
        assert_eq!(newest.prev_hash, oldest.event_hash);
        assert!(newest.event_hash.is_some());
        assert_ne!(newest.event_hash, oldest.event_hash);
    }

    #[test]
    fn verifies_hash_chain_integrity() {
        let store = AuditStore::in_memory().unwrap();

        store
            .log_event(&make_event("allow", "allowed", "ls"))
            .unwrap();
        store
            .log_event(&make_event("approve", "approved", "git push"))
            .unwrap();

        let verification = store.verify_hash_chain().unwrap();

        assert!(verification.valid);
        assert_eq!(verification.checked_events, 2);
        assert!(verification.violations.is_empty());
    }

    #[test]
    fn detects_tampered_audit_rows() {
        let store = AuditStore::in_memory().unwrap();
        store
            .log_event(&make_event("allow", "allowed", "ls"))
            .unwrap();

        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "UPDATE audit_log SET decision = 'tampered' WHERE command = 'ls'",
                [],
            )
            .unwrap();
        }

        let verification = store.verify_hash_chain().unwrap();

        assert!(!verification.valid);
        assert_eq!(verification.checked_events, 1);
        assert_eq!(verification.violations.len(), 1);
        assert_eq!(
            verification.violations[0].reason,
            "event_hash does not match event contents"
        );
    }
}
