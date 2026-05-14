use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::runtime::types::{
    AgentPodWorkspaceMode, MinipodSpec, RuntimeSession, WorkspaceOverlayMode,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceOverlayAllocation {
    pub mode: AgentPodWorkspaceMode,
    pub overlay_mode: WorkspaceOverlayMode,
    pub upper_host_path: PathBuf,
    pub work_host_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceOverlayError {
    MissingUpperPath,
    MissingWorkPath,
    SameUpperAndWorkPath(PathBuf),
    OverlayInsideWorkspace {
        overlay_path: PathBuf,
        workspace_path: PathBuf,
    },
    Io(String),
}

impl fmt::Display for WorkspaceOverlayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUpperPath => write!(f, "workspace overlay upper path is missing"),
            Self::MissingWorkPath => write!(f, "workspace overlay work path is missing"),
            Self::SameUpperAndWorkPath(path) => write!(
                f,
                "workspace overlay upper and work paths must be different: {}",
                path.display()
            ),
            Self::OverlayInsideWorkspace {
                overlay_path,
                workspace_path,
            } => write!(
                f,
                "workspace overlay path {} must not be inside workspace {}",
                overlay_path.display(),
                workspace_path.display()
            ),
            Self::Io(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for WorkspaceOverlayError {}

pub struct WorkspaceOverlayAllocator;

impl WorkspaceOverlayAllocator {
    pub fn allocate(
        spec: &mut MinipodSpec,
    ) -> Result<Option<WorkspaceOverlayAllocation>, WorkspaceOverlayError> {
        if !spec.filesystem.workspace_overlay.is_enabled() {
            return Ok(None);
        }

        let upper_host_path = spec
            .filesystem
            .workspace_overlay
            .upper_host_path
            .clone()
            .ok_or(WorkspaceOverlayError::MissingUpperPath)?;
        let work_host_path = spec
            .filesystem
            .workspace_overlay
            .work_host_path
            .clone()
            .ok_or(WorkspaceOverlayError::MissingWorkPath)?;

        let workspace_path = canonicalize_existing(&spec.filesystem.workspace_host_path)?;
        let upper_host_path = canonicalize_for_create(&upper_host_path)?;
        let work_host_path = canonicalize_for_create(&work_host_path)?;

        if upper_host_path == work_host_path {
            return Err(WorkspaceOverlayError::SameUpperAndWorkPath(upper_host_path));
        }

        for path in [&upper_host_path, &work_host_path] {
            if path.starts_with(&workspace_path) {
                return Err(WorkspaceOverlayError::OverlayInsideWorkspace {
                    overlay_path: path.clone(),
                    workspace_path: workspace_path.clone(),
                });
            }
        }

        fs::create_dir_all(&upper_host_path).map_err(|err| {
            WorkspaceOverlayError::Io(format!(
                "failed to create workspace overlay upper path {}: {err}",
                upper_host_path.display()
            ))
        })?;
        fs::create_dir_all(&work_host_path).map_err(|err| {
            WorkspaceOverlayError::Io(format!(
                "failed to create workspace overlay work path {}: {err}",
                work_host_path.display()
            ))
        })?;

        spec.filesystem.workspace_host_path = workspace_path;
        spec.filesystem.workspace_overlay.upper_host_path = Some(upper_host_path.clone());
        spec.filesystem.workspace_overlay.work_host_path = Some(work_host_path.clone());

        Ok(Some(WorkspaceOverlayAllocation {
            mode: spec.workspace_mode.clone(),
            overlay_mode: spec.filesystem.workspace_overlay.mode.clone(),
            upper_host_path,
            work_host_path,
        }))
    }
}

fn canonicalize_existing(path: &Path) -> Result<PathBuf, WorkspaceOverlayError> {
    path.canonicalize().map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to canonicalize workspace path {}: {err}",
            path.display()
        ))
    })
}

fn canonicalize_for_create(path: &Path) -> Result<PathBuf, WorkspaceOverlayError> {
    if path.exists() {
        return path.canonicalize().map_err(|err| {
            WorkspaceOverlayError::Io(format!(
                "failed to canonicalize workspace overlay path {}: {err}",
                path.display()
            ))
        });
    }

    let parent = path.parent().ok_or_else(|| {
        WorkspaceOverlayError::Io(format!(
            "workspace overlay path {} has no parent directory",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to create workspace overlay parent {}: {err}",
            parent.display()
        ))
    })?;
    let parent = parent.canonicalize().map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to canonicalize workspace overlay parent {}: {err}",
            parent.display()
        ))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        WorkspaceOverlayError::Io(format!(
            "workspace overlay path {} has no terminal component",
            path.display()
        ))
    })?;
    Ok(parent.join(file_name))
}

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
    use crate::runtime::types::{
        AgentPodWorkspaceMode, FilesystemPolicy, RuntimeSession, RuntimeStatus,
        WorkspaceOverlayPolicy,
    };
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

    #[test]
    fn overlay_allocator_skips_direct_workspace_mode() {
        let workspace = unique_dir("overlay-disabled-workspace");
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);

        let allocation = WorkspaceOverlayAllocator::allocate(&mut spec).unwrap();

        assert!(allocation.is_none());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn overlay_allocator_creates_review_directories() {
        let workspace = unique_dir("overlay-workspace");
        let overlay = unique_dir("overlay-root");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));

        let allocation = WorkspaceOverlayAllocator::allocate(&mut spec)
            .unwrap()
            .expect("overlay should be allocated");

        assert!(allocation.upper_host_path.exists());
        assert!(allocation.work_host_path.exists());
        assert_eq!(
            spec.filesystem.workspace_overlay.upper_host_path.as_ref(),
            Some(&allocation.upper_host_path)
        );
        assert_eq!(
            spec.filesystem.workspace_overlay.work_host_path.as_ref(),
            Some(&allocation.work_host_path)
        );

        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[test]
    fn overlay_allocator_rejects_missing_upper_path() {
        let workspace = unique_dir("overlay-missing-upper");
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(unique_dir("overlay-missing-upper-root")));
        spec.filesystem.workspace_overlay.upper_host_path = None;

        let err = WorkspaceOverlayAllocator::allocate(&mut spec).unwrap_err();

        assert_eq!(err, WorkspaceOverlayError::MissingUpperPath);
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn overlay_allocator_rejects_overlay_inside_workspace() {
        let workspace = unique_dir("overlay-inside-workspace");
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(workspace.join(".agentbox-overlay")));

        let err = WorkspaceOverlayAllocator::allocate(&mut spec).unwrap_err();

        assert!(matches!(
            err,
            WorkspaceOverlayError::OverlayInsideWorkspace { .. }
        ));
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
