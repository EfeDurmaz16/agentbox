use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

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
    OverlayUpperNotEmpty(PathBuf),
    OverlayInsideWorkspace {
        overlay_path: PathBuf,
        workspace_path: PathBuf,
    },
    WorkspaceSymlinkEscapes {
        link_path: PathBuf,
        target_path: PathBuf,
        workspace_path: PathBuf,
    },
    WorkspaceHardlinkRejected {
        path: PathBuf,
        link_count: u64,
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
            Self::OverlayUpperNotEmpty(path) => write!(
                f,
                "workspace overlay upper path must be empty before projection: {}",
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
            Self::WorkspaceSymlinkEscapes {
                link_path,
                target_path,
                workspace_path,
            } => write!(
                f,
                "workspace symlink {} points outside workspace {}: {}",
                link_path.display(),
                workspace_path.display(),
                target_path.display()
            ),
            Self::WorkspaceHardlinkRejected { path, link_count } => write!(
                f,
                "workspace hardlink {} is not safe for projection (link count: {})",
                path.display(),
                link_count
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceProjection {
    pub lower_host_path: PathBuf,
    pub projected_host_path: PathBuf,
    pub work_host_path: PathBuf,
}

pub struct WorkspaceProjectionMaterializer;

impl WorkspaceProjectionMaterializer {
    pub fn materialize(
        spec: &mut MinipodSpec,
    ) -> Result<Option<WorkspaceProjection>, WorkspaceOverlayError> {
        let Some(allocation) = WorkspaceOverlayAllocator::allocate(spec)? else {
            return Ok(None);
        };

        let lower_host_path = spec.filesystem.workspace_host_path.clone();
        ensure_empty_dir(&allocation.upper_host_path)?;
        copy_tree(
            &lower_host_path,
            &allocation.upper_host_path,
            &lower_host_path,
        )?;

        spec.labels.insert(
            "agentbox.workspace.lower".to_string(),
            lower_host_path.display().to_string(),
        );
        spec.labels.insert(
            "agentbox.workspace.projected".to_string(),
            allocation.upper_host_path.display().to_string(),
        );
        spec.filesystem.workspace_host_path = allocation.upper_host_path.clone();

        Ok(Some(WorkspaceProjection {
            lower_host_path,
            projected_host_path: allocation.upper_host_path,
            work_host_path: allocation.work_host_path,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceProjectionDiscard {
    pub lower_host_path: Option<PathBuf>,
    pub projected_host_path: PathBuf,
    pub work_host_path: Option<PathBuf>,
}

pub struct WorkspaceProjectionDiscarder;

impl WorkspaceProjectionDiscarder {
    pub fn discard(
        session: &RuntimeSession,
    ) -> Result<Option<WorkspaceProjectionDiscard>, WorkspaceOverlayError> {
        let Some(projected) = session.spec.labels.get("agentbox.workspace.projected") else {
            return Ok(None);
        };

        let projected_host_path = PathBuf::from(projected);
        let lower_host_path = session
            .spec
            .labels
            .get("agentbox.workspace.lower")
            .map(PathBuf::from);
        let work_host_path = session
            .spec
            .filesystem
            .workspace_overlay
            .work_host_path
            .clone();

        if let Some(lower) = &lower_host_path {
            let lower = canonicalize_existing(lower)?;
            let projected = canonicalize_for_delete(&projected_host_path)?;
            if projected == lower || projected.starts_with(&lower) {
                return Err(WorkspaceOverlayError::OverlayInsideWorkspace {
                    overlay_path: projected,
                    workspace_path: lower,
                });
            }
        }

        remove_dir_if_exists(&projected_host_path)?;
        if let Some(work) = &work_host_path {
            remove_dir_if_exists(work)?;
        }

        Ok(Some(WorkspaceProjectionDiscard {
            lower_host_path,
            projected_host_path,
            work_host_path,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceProjectionApply {
    pub lower_host_path: PathBuf,
    pub projected_host_path: PathBuf,
    pub patch_bytes: usize,
}

pub struct WorkspaceProjectionApplier;

impl WorkspaceProjectionApplier {
    pub fn apply(
        session: &RuntimeSession,
    ) -> Result<Option<WorkspaceProjectionApply>, WorkspaceOverlayError> {
        let Some(projected) = session.spec.labels.get("agentbox.workspace.projected") else {
            return Ok(None);
        };
        let Some(lower) = session.spec.labels.get("agentbox.workspace.lower") else {
            return Ok(None);
        };

        let projected_host_path = canonicalize_existing(Path::new(projected))?;
        let lower_host_path = canonicalize_existing(Path::new(lower))?;
        if projected_host_path == lower_host_path
            || projected_host_path.starts_with(&lower_host_path)
        {
            return Err(WorkspaceOverlayError::OverlayInsideWorkspace {
                overlay_path: projected_host_path,
                workspace_path: lower_host_path,
            });
        }

        let mut projected_session = session.clone();
        projected_session.spec.filesystem.workspace_host_path = projected_host_path.clone();
        let snapshot = WorkspaceDiffSnapshotter::capture(&projected_session);
        let Some(patch) = snapshot.diff_patch else {
            return Ok(None);
        };

        reject_hardlinked_changed_files(&lower_host_path, &snapshot.changed_files)?;
        apply_patch_to_workspace(&lower_host_path, &patch)?;

        Ok(Some(WorkspaceProjectionApply {
            lower_host_path,
            projected_host_path,
            patch_bytes: patch.len(),
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceProjectionCommit {
    pub apply: WorkspaceProjectionApply,
    pub commit_hash: String,
    pub message: String,
}

pub struct WorkspaceProjectionCommitter;

impl WorkspaceProjectionCommitter {
    pub fn commit(
        session: &RuntimeSession,
        message: &str,
    ) -> Result<Option<WorkspaceProjectionCommit>, WorkspaceOverlayError> {
        let message = message.trim();
        if message.is_empty() {
            return Err(WorkspaceOverlayError::Io(
                "workspace projection commit message cannot be empty".into(),
            ));
        }

        let Some(apply) = WorkspaceProjectionApplier::apply(session)? else {
            return Ok(None);
        };
        git_commit_all(&apply.lower_host_path, message)?;
        let commit_hash = git_output(&apply.lower_host_path, &["rev-parse", "HEAD"])
            .ok_or_else(|| {
                WorkspaceOverlayError::Io(format!(
                    "failed to resolve commit hash in {}",
                    apply.lower_host_path.display()
                ))
            })?
            .trim()
            .to_string();

        Ok(Some(WorkspaceProjectionCommit {
            apply,
            commit_hash,
            message: message.to_string(),
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

fn canonicalize_for_delete(path: &Path) -> Result<PathBuf, WorkspaceOverlayError> {
    if path.exists() {
        path.canonicalize().map_err(|err| {
            WorkspaceOverlayError::Io(format!(
                "failed to canonicalize workspace overlay path {}: {err}",
                path.display()
            ))
        })
    } else {
        canonicalize_for_create(path)
    }
}

fn remove_dir_if_exists(path: &Path) -> Result<(), WorkspaceOverlayError> {
    if !path.exists() {
        return Ok(());
    }
    if !path.is_dir() {
        return Err(WorkspaceOverlayError::Io(format!(
            "workspace projection path {} is not a directory",
            path.display()
        )));
    }
    fs::remove_dir_all(path).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to remove workspace projection path {}: {err}",
            path.display()
        ))
    })
}

fn apply_patch_to_workspace(workspace: &Path, patch: &str) -> Result<(), WorkspaceOverlayError> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .arg("apply")
        .arg("--whitespace=nowarn")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            WorkspaceOverlayError::Io(format!(
                "failed to start git apply in {}: {err}",
                workspace.display()
            ))
        })?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| WorkspaceOverlayError::Io("failed to open git apply stdin".into()))?
        .write_all(patch.as_bytes())
        .map_err(|err| WorkspaceOverlayError::Io(format!("failed to write patch: {err}")))?;

    let output = child.wait_with_output().map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to wait for git apply in {}: {err}",
            workspace.display()
        ))
    })?;
    if !output.status.success() {
        return Err(WorkspaceOverlayError::Io(format!(
            "git apply failed in {}: {}",
            workspace.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(())
}

fn git_commit_all(workspace: &Path, message: &str) -> Result<(), WorkspaceOverlayError> {
    let add = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["add", "-A"])
        .output()
        .map_err(|err| {
            WorkspaceOverlayError::Io(format!(
                "failed to start git add in {}: {err}",
                workspace.display()
            ))
        })?;
    if !add.status.success() {
        return Err(WorkspaceOverlayError::Io(format!(
            "git add failed in {}: {}",
            workspace.display(),
            String::from_utf8_lossy(&add.stderr).trim()
        )));
    }

    let commit = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["commit", "-m", message])
        .output()
        .map_err(|err| {
            WorkspaceOverlayError::Io(format!(
                "failed to start git commit in {}: {err}",
                workspace.display()
            ))
        })?;
    if !commit.status.success() {
        return Err(WorkspaceOverlayError::Io(format!(
            "git commit failed in {}: {}",
            workspace.display(),
            String::from_utf8_lossy(&commit.stderr).trim()
        )));
    }

    Ok(())
}

fn ensure_empty_dir(path: &Path) -> Result<(), WorkspaceOverlayError> {
    let mut entries = fs::read_dir(path).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to read workspace overlay upper path {}: {err}",
            path.display()
        ))
    })?;
    if entries.next().is_some() {
        return Err(WorkspaceOverlayError::OverlayUpperNotEmpty(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path, workspace_root: &Path) -> Result<(), WorkspaceOverlayError> {
    for entry in fs::read_dir(src).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to read workspace path {}: {err}",
            src.display()
        ))
    })? {
        let entry = entry.map_err(|err| {
            WorkspaceOverlayError::Io(format!(
                "failed to inspect workspace entry under {}: {err}",
                src.display()
            ))
        })?;
        let source_path = entry.path();
        if should_skip_projected_workspace_entry(&source_path) {
            continue;
        }
        let target_path = dst.join(entry.file_name());
        copy_entry(&source_path, &target_path, workspace_root)?;
    }
    Ok(())
}

fn should_skip_projected_workspace_entry(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    matches!(
        name,
        "target" | "node_modules" | ".next" | ".turbo" | ".svelte-kit" | "dist" | "build"
    )
}

fn copy_entry(src: &Path, dst: &Path, workspace_root: &Path) -> Result<(), WorkspaceOverlayError> {
    let metadata = fs::symlink_metadata(src).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to inspect workspace entry {}: {err}",
            src.display()
        ))
    })?;

    if metadata.file_type().is_symlink() {
        reject_symlink_escape(src, workspace_root)?;
        copy_symlink(src, dst)?;
        return Ok(());
    }

    if metadata.is_dir() {
        fs::create_dir_all(dst).map_err(|err| {
            WorkspaceOverlayError::Io(format!(
                "failed to create projected workspace directory {}: {err}",
                dst.display()
            ))
        })?;
        copy_tree(src, dst, workspace_root)?;
        return Ok(());
    }

    fs::copy(src, dst).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to copy workspace file {} to {}: {err}",
            src.display(),
            dst.display()
        ))
    })?;
    Ok(())
}

fn reject_symlink_escape(
    link_path: &Path,
    workspace_root: &Path,
) -> Result<(), WorkspaceOverlayError> {
    let target = fs::read_link(link_path).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to read workspace symlink {}: {err}",
            link_path.display()
        ))
    })?;
    let workspace_root = normalize_path(workspace_root);
    let resolved = if target.is_absolute() {
        normalize_path(&target)
    } else {
        let parent = link_path.parent().unwrap_or_else(|| Path::new(""));
        normalize_path(&parent.join(&target))
    };

    if !resolved.starts_with(&workspace_root) {
        return Err(WorkspaceOverlayError::WorkspaceSymlinkEscapes {
            link_path: link_path.to_path_buf(),
            target_path: resolved,
            workspace_path: workspace_root,
        });
    }

    Ok(())
}

#[cfg(unix)]
fn reject_hardlinked_changed_files(
    workspace: &Path,
    changed_files: &[String],
) -> Result<(), WorkspaceOverlayError> {
    for changed_file in changed_files {
        let path = workspace.join(changed_file);
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        reject_hardlink(&path, &metadata)?;
    }
    Ok(())
}

#[cfg(unix)]
fn reject_hardlink(path: &Path, metadata: &fs::Metadata) -> Result<(), WorkspaceOverlayError> {
    let link_count = metadata.nlink();
    if metadata.is_file() && link_count > 1 {
        return Err(WorkspaceOverlayError::WorkspaceHardlinkRejected {
            path: path.to_path_buf(),
            link_count,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_hardlinked_changed_files(
    _workspace: &Path,
    _changed_files: &[String],
) -> Result<(), WorkspaceOverlayError> {
    Ok(())
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

#[cfg(unix)]
fn copy_symlink(src: &Path, dst: &Path) -> Result<(), WorkspaceOverlayError> {
    let target = fs::read_link(src).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to read workspace symlink {}: {err}",
            src.display()
        ))
    })?;
    std::os::unix::fs::symlink(&target, dst).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to copy workspace symlink {} to {}: {err}",
            src.display(),
            dst.display()
        ))
    })
}

#[cfg(not(unix))]
fn copy_symlink(src: &Path, dst: &Path) -> Result<(), WorkspaceOverlayError> {
    let target = fs::read_link(src).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to read workspace symlink {}: {err}",
            src.display()
        ))
    })?;
    fs::write(dst, target.display().to_string()).map_err(|err| {
        WorkspaceOverlayError::Io(format!(
            "failed to preserve workspace symlink marker {}: {err}",
            src.display()
        ))
    })
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
    pub diff_patch: Option<String>,
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
            diff_patch: None,
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
        snapshot.diff_patch =
            git_output(workspace, &["diff", "--binary"]).filter(|value| !value.trim().is_empty());
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
        assert!(snapshot
            .diff_patch
            .as_deref()
            .is_some_and(|patch| { patch.contains("diff --git") && patch.contains("+changed") }));
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

    #[test]
    fn projection_materializer_copies_workspace_into_upper_layer() {
        let workspace = unique_dir("projection-workspace");
        let overlay = unique_dir("projection-overlay");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::write(workspace.join("README.md"), "lower\n").unwrap();
        fs::write(workspace.join("src").join("main.rs"), "fn main() {}\n").unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));

        let projection = WorkspaceProjectionMaterializer::materialize(&mut spec)
            .unwrap()
            .expect("workspace should be projected");

        assert_eq!(
            projection.lower_host_path,
            workspace.canonicalize().unwrap()
        );
        assert_eq!(
            spec.filesystem.workspace_host_path,
            projection.projected_host_path
        );
        assert_eq!(
            fs::read_to_string(projection.projected_host_path.join("README.md")).unwrap(),
            "lower\n"
        );
        fs::write(
            projection.projected_host_path.join("README.md"),
            "overlay\n",
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).unwrap(),
            "lower\n"
        );
        assert_eq!(
            spec.labels.get("agentbox.workspace.lower"),
            Some(&workspace.canonicalize().unwrap().display().to_string())
        );

        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[test]
    fn projection_materializer_skips_generated_workspace_directories() {
        let workspace = unique_dir("projection-generated-workspace");
        let overlay = unique_dir("projection-generated-overlay");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::create_dir_all(workspace.join("target").join("debug")).unwrap();
        fs::write(workspace.join("src").join("main.rs"), "fn main() {}\n").unwrap();
        fs::write(
            workspace.join("target").join("debug").join("cache"),
            "cache\n",
        )
        .unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));

        let projection = WorkspaceProjectionMaterializer::materialize(&mut spec)
            .unwrap()
            .expect("workspace should be projected");

        assert!(projection
            .projected_host_path
            .join("src")
            .join("main.rs")
            .exists());
        assert!(!projection.projected_host_path.join("target").exists());
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[test]
    fn projection_materializer_rejects_non_empty_upper_layer() {
        let workspace = unique_dir("projection-nonempty-workspace");
        let overlay = unique_dir("projection-nonempty-overlay");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(overlay.join("upper")).unwrap();
        fs::write(overlay.join("upper").join("existing.txt"), "stale\n").unwrap();
        fs::create_dir_all(overlay.join("work")).unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));

        let err = WorkspaceProjectionMaterializer::materialize(&mut spec).unwrap_err();

        assert!(matches!(
            err,
            WorkspaceOverlayError::OverlayUpperNotEmpty(_)
        ));
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[cfg(unix)]
    #[test]
    fn projection_materializer_rejects_symlink_escape() {
        let workspace = unique_dir("projection-symlink-escape-workspace");
        let outside = unique_dir("projection-symlink-escape-outside");
        let overlay = unique_dir("projection-symlink-escape-overlay");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), "outside\n").unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), workspace.join("secret-link"))
            .unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));

        let err = WorkspaceProjectionMaterializer::materialize(&mut spec).unwrap_err();

        assert!(matches!(
            err,
            WorkspaceOverlayError::WorkspaceSymlinkEscapes { .. }
        ));
        assert_eq!(
            fs::read_to_string(outside.join("secret.txt")).unwrap(),
            "outside\n"
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[cfg(unix)]
    #[test]
    fn projection_materializer_preserves_internal_symlink() {
        let workspace = unique_dir("projection-internal-symlink-workspace");
        let overlay = unique_dir("projection-internal-symlink-overlay");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(workspace.join("docs")).unwrap();
        fs::write(workspace.join("docs").join("guide.md"), "inside\n").unwrap();
        std::os::unix::fs::symlink("docs/guide.md", workspace.join("guide-link")).unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));

        let projection = WorkspaceProjectionMaterializer::materialize(&mut spec)
            .unwrap()
            .expect("workspace should be projected");

        assert_eq!(
            fs::read_link(projection.projected_host_path.join("guide-link")).unwrap(),
            PathBuf::from("docs/guide.md")
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[test]
    fn projection_discarder_removes_projected_workspace_without_touching_lower() {
        let workspace = unique_dir("discard-workspace");
        let overlay = unique_dir("discard-overlay");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("README.md"), "lower\n").unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));
        let projection = WorkspaceProjectionMaterializer::materialize(&mut spec)
            .unwrap()
            .expect("workspace should be projected");
        fs::write(
            projection.projected_host_path.join("README.md"),
            "projected\n",
        )
        .unwrap();
        let session = RuntimeSession {
            id: "01agentboxsession".into(),
            name: spec.name.clone(),
            provider: "podman".into(),
            platform: "linux-vm".into(),
            status: RuntimeStatus::Stopped,
            spec,
            approval_grants: vec![],
            transcripts: vec![],
            started_at: Utc::now(),
            stopped_at: Some(Utc::now()),
        };

        let discard = WorkspaceProjectionDiscarder::discard(&session)
            .unwrap()
            .expect("projection should be discarded");

        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).unwrap(),
            "lower\n"
        );
        assert!(!discard.projected_host_path.exists());
        assert!(!discard.work_host_path.unwrap().exists());
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[test]
    fn projection_applier_applies_projected_patch_to_lower_workspace() {
        let workspace = unique_dir("apply-workspace");
        let overlay = unique_dir("apply-overlay");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        run_git(&workspace, &["init"]);
        run_git(
            &workspace,
            &["config", "user.email", "agentbox@example.test"],
        );
        run_git(&workspace, &["config", "user.name", "Agentbox Test"]);
        fs::write(workspace.join("README.md"), "lower\n").unwrap();
        run_git(&workspace, &["add", "README.md"]);
        run_git(&workspace, &["commit", "-m", "initial"]);
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));
        let projection = WorkspaceProjectionMaterializer::materialize(&mut spec)
            .unwrap()
            .expect("workspace should be projected");
        fs::write(
            projection.projected_host_path.join("README.md"),
            "lower\napplied\n",
        )
        .unwrap();
        let session = RuntimeSession {
            id: "01agentboxsession".into(),
            name: spec.name.clone(),
            provider: "podman".into(),
            platform: "linux-vm".into(),
            status: RuntimeStatus::Stopped,
            spec,
            approval_grants: vec![],
            transcripts: vec![],
            started_at: Utc::now(),
            stopped_at: Some(Utc::now()),
        };

        let applied = WorkspaceProjectionApplier::apply(&session)
            .unwrap()
            .expect("patch should be applied");

        assert!(applied.patch_bytes > 0);
        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).unwrap(),
            "lower\napplied\n"
        );
        assert!(applied.projected_host_path.exists());
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[cfg(unix)]
    #[test]
    fn projection_applier_rejects_hardlinked_changed_files() {
        let workspace = unique_dir("apply-hardlink-escape-workspace");
        let outside = unique_dir("apply-hardlink-escape-outside");
        let overlay = unique_dir("apply-hardlink-escape-overlay");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&outside).unwrap();
        run_git(&workspace, &["init"]);
        run_git(
            &workspace,
            &["config", "user.email", "agentbox@example.test"],
        );
        run_git(&workspace, &["config", "user.name", "Agentbox Test"]);
        fs::write(outside.join("shared.txt"), "outside\n").unwrap();
        fs::hard_link(outside.join("shared.txt"), workspace.join("shared.txt")).unwrap();
        run_git(&workspace, &["add", "shared.txt"]);
        run_git(&workspace, &["commit", "-m", "initial"]);
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::OverlayReview;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));
        let projection = WorkspaceProjectionMaterializer::materialize(&mut spec)
            .unwrap()
            .expect("workspace should be projected");
        fs::write(
            projection.projected_host_path.join("shared.txt"),
            "outside\nchanged\n",
        )
        .unwrap();
        let session = RuntimeSession {
            id: "01agentboxsession".into(),
            name: spec.name.clone(),
            provider: "podman".into(),
            platform: "linux-vm".into(),
            status: RuntimeStatus::Stopped,
            spec,
            approval_grants: vec![],
            transcripts: vec![],
            started_at: Utc::now(),
            stopped_at: Some(Utc::now()),
        };

        let err = WorkspaceProjectionApplier::apply(&session).unwrap_err();

        assert!(matches!(
            err,
            WorkspaceOverlayError::WorkspaceHardlinkRejected { .. }
        ));
        assert_eq!(
            fs::read_to_string(outside.join("shared.txt")).unwrap(),
            "outside\n"
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&overlay);
    }

    #[test]
    fn projection_committer_applies_patch_and_creates_commit() {
        let workspace = unique_dir("commit-workspace");
        let overlay = unique_dir("commit-overlay");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
        fs::create_dir_all(&workspace).unwrap();
        run_git(&workspace, &["init"]);
        run_git(
            &workspace,
            &["config", "user.email", "agentbox@example.test"],
        );
        run_git(&workspace, &["config", "user.name", "Agentbox Test"]);
        fs::write(workspace.join("README.md"), "lower\n").unwrap();
        run_git(&workspace, &["add", "README.md"]);
        run_git(&workspace, &["commit", "-m", "initial"]);
        let initial = git_output(&workspace, &["rev-parse", "HEAD"]).unwrap();
        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.workspace_mode = AgentPodWorkspaceMode::CommitGated;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some(overlay.clone()));
        let projection = WorkspaceProjectionMaterializer::materialize(&mut spec)
            .unwrap()
            .expect("workspace should be projected");
        fs::write(
            projection.projected_host_path.join("README.md"),
            "lower\ncommitted\n",
        )
        .unwrap();
        let session = RuntimeSession {
            id: "01agentboxsession".into(),
            name: spec.name.clone(),
            provider: "podman".into(),
            platform: "linux-vm".into(),
            status: RuntimeStatus::Stopped,
            spec,
            approval_grants: vec![],
            transcripts: vec![],
            started_at: Utc::now(),
            stopped_at: Some(Utc::now()),
        };

        let commit = WorkspaceProjectionCommitter::commit(&session, "agentbox review output")
            .unwrap()
            .expect("commit should be created");

        assert_ne!(commit.commit_hash, initial.trim());
        assert_eq!(commit.message, "agentbox review output");
        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).unwrap(),
            "lower\ncommitted\n"
        );
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&overlay);
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
