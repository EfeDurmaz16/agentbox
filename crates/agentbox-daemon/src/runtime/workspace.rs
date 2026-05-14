use std::path::Path;
use std::process::Command;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::runtime::types::RuntimeSession;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceDiffSnapshot {
    pub schema_version: i64,
    pub snapshot_id: String,
    pub session_id: String,
    pub workspace: String,
    pub captured_at: DateTime<Utc>,
    pub available: bool,
    pub reason: Option<String>,
    pub git_head: Option<String>,
    pub status_porcelain: Vec<String>,
    pub diff_shortstat: Option<String>,
    pub diff_name_status: Vec<String>,
    pub changed_files: Vec<String>,
}

impl WorkspaceDiffSnapshot {
    pub fn evidence_ref(&self) -> String {
        format!("workspace-diff:{}", self.snapshot_id)
    }

    pub fn has_changes(&self) -> bool {
        !self.changed_files.is_empty()
    }
}

pub struct WorkspaceDiffSnapshotter;

impl WorkspaceDiffSnapshotter {
    pub fn capture(session: &RuntimeSession) -> WorkspaceDiffSnapshot {
        let workspace = &session.spec.filesystem.workspace_host_path;
        let mut snapshot = WorkspaceDiffSnapshot {
            schema_version: 1,
            snapshot_id: Ulid::new().to_string(),
            session_id: session.id.clone(),
            workspace: workspace.display().to_string(),
            captured_at: Utc::now(),
            available: false,
            reason: None,
            git_head: None,
            status_porcelain: vec![],
            diff_shortstat: None,
            diff_name_status: vec![],
            changed_files: vec![],
        };

        if !workspace.exists() {
            snapshot.reason = Some("workspace path does not exist".to_string());
            return snapshot;
        }

        let Some(head) = git_output(workspace, &["rev-parse", "--verify", "HEAD"]) else {
            snapshot.reason = Some("workspace is not a git repository with a HEAD".to_string());
            return snapshot;
        };

        snapshot.available = true;
        snapshot.git_head = Some(head.trim().to_string());
        snapshot.status_porcelain = git_output(workspace, &["status", "--porcelain=v1"])
            .map(lines)
            .unwrap_or_default();
        snapshot.diff_shortstat = git_output(workspace, &["diff", "--shortstat"])
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        snapshot.diff_name_status = git_output(workspace, &["diff", "--name-status"])
            .map(lines)
            .unwrap_or_default();
        snapshot.changed_files = changed_files_from_status(&snapshot.status_porcelain);

        snapshot
    }
}

fn git_output(workspace: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(args)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn lines(value: String) -> Vec<String> {
    value
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn changed_files_from_status(status: &[String]) -> Vec<String> {
    status
        .iter()
        .filter_map(|line| line.get(3..))
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::{FilesystemPolicy, MinipodSpec, RuntimeSession, RuntimeStatus};
    use std::fs;

    fn session_for_workspace(workspace: &Path) -> RuntimeSession {
        let mut spec = MinipodSpec::for_agent_task("hermes", workspace);
        spec.filesystem = FilesystemPolicy::workspace(workspace);
        RuntimeSession {
            id: "01agentboxsession".into(),
            name: spec.name.clone(),
            provider: "agentpod-linux".into(),
            platform: "linux".into(),
            status: RuntimeStatus::Running,
            spec,
            approval_grants: vec![],
            transcripts: vec![],
            started_at: Utc::now(),
            stopped_at: None,
        }
    }

    fn unique_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "agentbox-workspace-snapshot-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn snapshot_reports_unavailable_for_missing_workspace() {
        let workspace = unique_dir("missing");
        let _ = fs::remove_dir_all(&workspace);
        let session = session_for_workspace(&workspace);

        let snapshot = WorkspaceDiffSnapshotter::capture(&session);

        assert!(!snapshot.available);
        assert_eq!(
            snapshot.reason.as_deref(),
            Some("workspace path does not exist")
        );
        assert!(!snapshot.has_changes());
    }

    #[test]
    fn snapshot_captures_git_workspace_changes() {
        let workspace = unique_dir("git");
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).unwrap();
        run_git(&workspace, &["init"]);
        run_git(
            &workspace,
            &["config", "user.email", "agentbox@example.test"],
        );
        run_git(&workspace, &["config", "user.name", "Agentbox Test"]);
        fs::write(workspace.join("README.md"), "hello\n").unwrap();
        run_git(&workspace, &["add", "README.md"]);
        run_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "hello\nchanged\n").unwrap();

        let session = session_for_workspace(&workspace);
        let snapshot = WorkspaceDiffSnapshotter::capture(&session);

        assert!(snapshot.available);
        assert!(snapshot.git_head.is_some());
        assert!(snapshot.has_changes());
        assert!(snapshot.changed_files.contains(&"README.md".to_string()));
        assert_eq!(
            snapshot.evidence_ref(),
            format!("workspace-diff:{}", snapshot.snapshot_id)
        );

        let _ = fs::remove_dir_all(&workspace);
    }

    fn run_git(workspace: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
