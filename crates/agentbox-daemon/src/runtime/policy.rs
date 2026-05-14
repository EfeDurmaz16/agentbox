use std::path::{Component, Path, PathBuf};

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::{
    CredentialGrantKind, MinipodSpec, MountMode, NetworkMode, TaskPolicyBundle,
    WorkspaceWritePolicy,
};

pub fn load_task_policy_bundle(path: impl AsRef<Path>) -> Result<TaskPolicyBundle, RuntimeError> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|e| {
        RuntimeError::ManifestRejected(format!(
            "failed to read task policy bundle {}: {e}",
            path.display()
        ))
    })?;
    let mut bundle: TaskPolicyBundle = serde_json::from_str(&contents).map_err(|e| {
        RuntimeError::ManifestRejected(format!(
            "failed to parse task policy bundle {}: {e}",
            path.display()
        ))
    })?;
    if bundle.source.is_none() {
        bundle.source = Some(path.display().to_string());
    }
    validate_task_policy_bundle(&bundle)?;
    Ok(bundle)
}

pub fn validate_minipod_spec(spec: &MinipodSpec) -> Result<(), RuntimeError> {
    if spec.agent.command.is_empty() {
        return reject("agent command cannot be empty");
    }

    if spec.policy_profile.id.trim().is_empty() {
        return reject("agent policy profile id cannot be empty");
    }

    if spec.filesystem.workspace_host_path.as_os_str().is_empty() {
        return reject("workspace host path cannot be empty");
    }
    validate_workspace_overlay(spec)?;

    if !spec.filesystem.deny_home_by_default {
        return reject("home directory must be denied by default");
    }

    if spec.credentials.inherit_host_env {
        return reject("host environment inheritance is not allowed");
    }

    if matches!(spec.network.mode, NetworkMode::Host) {
        return reject("host network mode is not allowed for governed minipods");
    }
    if spec
        .network
        .allowed_domains
        .iter()
        .chain(spec.network.denied_domains.iter())
        .any(|domain| domain.trim().is_empty())
    {
        return reject("network policy domains cannot be empty");
    }

    if spec.resources.memory_bytes == 0 {
        return reject("memory limit must be greater than zero");
    }

    if spec.seccomp.enabled && spec.seccomp.rules.is_empty() {
        return reject("enabled seccomp profile must contain at least one syscall rule");
    }
    if spec
        .seccomp
        .rules
        .iter()
        .any(|rule| rule.syscall.trim().is_empty())
    {
        return reject("seccomp syscall names cannot be empty");
    }

    for bundle in &spec.policy_bundles {
        validate_task_policy_bundle(bundle)?;
    }

    for mount in &spec.filesystem.mounts {
        if mount.host_path.as_os_str().is_empty() {
            return reject("mount host path cannot be empty");
        }
        if escapes_workspace_via_symlink(spec, &mount.host_path) {
            return reject("mount path escapes workspace through symlink");
        }
        if matches!(mount.mode, MountMode::ReadWrite) && is_protected_path(spec, &mount.host_path) {
            return reject("protected paths cannot be mounted read-write");
        }
        if is_protected_path(spec, &mount.host_path)
            && !has_matching_file_grant(spec, mount.host_path.as_path())
        {
            return reject("protected paths require an explicit file grant");
        }
    }

    Ok(())
}

fn validate_workspace_overlay(spec: &MinipodSpec) -> Result<(), RuntimeError> {
    let overlay = &spec.filesystem.workspace_overlay;
    match spec.filesystem.workspace_write_policy {
        WorkspaceWritePolicy::Direct if overlay.is_enabled() => {
            return reject("direct workspace writes cannot carry a workspace overlay");
        }
        WorkspaceWritePolicy::Direct => return Ok(()),
        WorkspaceWritePolicy::WritableOverlay if !overlay.is_enabled() => {
            return reject("writable overlay policy requires a workspace overlay");
        }
        WorkspaceWritePolicy::WritableOverlay => {}
    }

    if overlay.guest_path != spec.filesystem.workspace_guest_path {
        return reject("workspace overlay guest path must match workspace guest path");
    }
    if overlay.upper_host_path.is_none() || overlay.work_host_path.is_none() {
        return reject("writable overlay requires upper and work host paths");
    }
    if overlay.upper_host_path == overlay.work_host_path {
        return reject("workspace overlay upper and work paths must be different");
    }
    if !overlay.is_enabled() {
        return Ok(());
    }
    if overlay.guest_path.trim().is_empty() {
        return reject("workspace overlay guest path cannot be empty");
    }
    if let Some(upper) = &overlay.upper_host_path {
        if upper.as_os_str().is_empty() {
            return reject("workspace overlay upper path cannot be empty");
        }
        if is_inside_workspace(spec, upper) && !is_materialized_projection_path(spec, upper) {
            return reject("workspace overlay upper path cannot sit inside the workspace");
        }
        if escapes_workspace_via_symlink(spec, upper)
            && !is_materialized_projection_path(spec, upper)
        {
            return reject("workspace overlay upper path escapes workspace through symlink");
        }
        if is_protected_path(spec, upper) {
            return reject("workspace overlay upper path cannot be protected");
        }
    }
    if let Some(work) = &overlay.work_host_path {
        if work.as_os_str().is_empty() {
            return reject("workspace overlay work path cannot be empty");
        }
        if is_inside_workspace(spec, work) {
            return reject("workspace overlay work path cannot sit inside the workspace");
        }
        if escapes_workspace_via_symlink(spec, work) {
            return reject("workspace overlay work path escapes workspace through symlink");
        }
        if is_protected_path(spec, work) {
            return reject("workspace overlay work path cannot be protected");
        }
    }
    Ok(())
}

fn validate_task_policy_bundle(bundle: &TaskPolicyBundle) -> Result<(), RuntimeError> {
    if bundle.schema_version != 1 {
        return reject(format!(
            "unsupported task policy bundle schema version {}",
            bundle.schema_version
        ));
    }
    if bundle.id.trim().is_empty() {
        return reject("task policy bundle id cannot be empty");
    }
    for mount in &bundle.read_only_mounts {
        if !matches!(mount.mode, MountMode::ReadOnly) {
            return reject("task policy bundle mounts must be read-only");
        }
    }
    if let Some(overlay) = &bundle.workspace_overlay {
        if bundle.workspace_write_policy.is_none() {
            return reject("task policy bundle workspace overlay requires a write policy");
        }
        if overlay.is_enabled() && overlay.guest_path.trim().is_empty() {
            return reject("task policy bundle workspace overlay guest path cannot be empty");
        }
    }
    Ok(())
}

fn is_protected_path(spec: &MinipodSpec, path: &Path) -> bool {
    let path = normalize_path(path);
    spec.filesystem
        .protected_paths
        .iter()
        .any(|protected| path.starts_with(normalize_path(&protected.path)))
}

fn is_inside_workspace(spec: &MinipodSpec, path: &Path) -> bool {
    let workspace = normalize_path(&spec.filesystem.workspace_host_path);
    !workspace.as_os_str().is_empty() && normalize_path(path).starts_with(workspace)
}

fn is_materialized_projection_path(spec: &MinipodSpec, path: &Path) -> bool {
    let Some(projected) = spec.labels.get("agentbox.workspace.projected") else {
        return false;
    };
    let Some(lower) = spec.labels.get("agentbox.workspace.lower") else {
        return false;
    };

    normalize_path(path) == normalize_path(Path::new(projected))
        && normalize_path(&spec.filesystem.workspace_host_path)
            == normalize_path(Path::new(projected))
        && normalize_path(Path::new(lower)) != normalize_path(Path::new(projected))
}

fn has_matching_file_grant(spec: &MinipodSpec, path: &Path) -> bool {
    let path = normalize_path(path).to_string_lossy().to_string();
    spec.credentials.grants.iter().any(|grant| {
        matches!(grant.kind, CredentialGrantKind::FileMount)
            && grant.target == path
            && grant.requires_approval
    })
}

fn escapes_workspace_via_symlink(spec: &MinipodSpec, path: &Path) -> bool {
    let workspace = normalize_path(&spec.filesystem.workspace_host_path);
    let path = normalize_path(path);
    if workspace.as_os_str().is_empty() {
        return false;
    }
    if !path.starts_with(&workspace) {
        return false;
    }

    let Ok(workspace_real) = std::fs::canonicalize(&workspace) else {
        return false;
    };
    let Ok(path_real) = std::fs::canonicalize(&path) else {
        return false;
    };

    !path_real.starts_with(workspace_real)
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

fn reject<T>(reason: impl Into<String>) -> Result<T, RuntimeError> {
    Err(RuntimeError::ManifestRejected(reason.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::{
        CredentialGrant, FilesystemPolicy, MountRule, ProtectedPath, SeccompProfile,
        SensitivePathClass, TaskPolicyBundle, WorkspaceOverlayMode, WorkspaceOverlayPolicy,
    };

    fn spec() -> MinipodSpec {
        MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work")
    }

    fn rejection_reason(result: Result<(), RuntimeError>) -> String {
        match result {
            Err(RuntimeError::ManifestRejected(reason)) => reason,
            other => panic!("expected manifest rejection, got {other:?}"),
        }
    }

    #[test]
    fn default_task_spec_is_valid() {
        validate_minipod_spec(&spec()).unwrap();
    }

    #[test]
    fn rejects_host_environment_inheritance() {
        let mut spec = spec();
        spec.credentials.inherit_host_env = true;

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("host environment"));
    }

    #[test]
    fn rejects_empty_agent_policy_profile_id() {
        let mut spec = spec();
        spec.policy_profile.id = " ".into();

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("policy profile"));
    }

    #[test]
    fn rejects_host_network_mode() {
        let mut spec = spec();
        spec.network.mode = NetworkMode::Host;

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("host network"));
    }

    #[test]
    fn rejects_empty_network_policy_domains() {
        let mut spec = spec();
        spec.network.denied_domains.push(" ".into());

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("domains"));
    }

    #[test]
    fn rejects_enabled_empty_seccomp_profile() {
        let mut spec = spec();
        spec.seccomp.enabled = true;

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("seccomp"));
    }

    #[test]
    fn rejects_empty_seccomp_syscall_names() {
        let mut spec = spec();
        spec.seccomp = SeccompProfile::deny_syscalls(&[" "], "invalid syscall");

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("syscall"));
    }

    #[test]
    fn rejects_read_write_mount_of_protected_path() {
        let mut spec = spec();
        spec.filesystem = FilesystemPolicy {
            protected_paths: vec![ProtectedPath {
                path: "/tmp/agentbox-secret".into(),
                class: SensitivePathClass::Custom("secret".into()),
                reason: "test secret".into(),
            }],
            mounts: vec![MountRule {
                host_path: "/tmp/agentbox-secret/key".into(),
                guest_path: "/secret/key".into(),
                mode: MountMode::ReadWrite,
                kind: Default::default(),
            }],
            ..FilesystemPolicy::workspace("/tmp/agentbox-work")
        };

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("read-write"));
    }

    #[test]
    fn protected_read_only_mount_requires_file_grant() {
        let mut spec = spec();
        spec.filesystem = FilesystemPolicy {
            protected_paths: vec![ProtectedPath {
                path: "/tmp/agentbox-secret".into(),
                class: SensitivePathClass::Custom("secret".into()),
                reason: "test secret".into(),
            }],
            mounts: vec![MountRule {
                host_path: "/tmp/agentbox-secret/key".into(),
                guest_path: "/secret/key".into(),
                mode: MountMode::ReadOnly,
                kind: Default::default(),
            }],
            ..FilesystemPolicy::workspace("/tmp/agentbox-work")
        };

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("file grant"));
    }

    #[test]
    fn default_sensitive_paths_are_denied_without_grants() {
        let mut spec = spec();
        let ssh_path = spec
            .filesystem
            .protected_paths
            .iter()
            .find(|protected| matches!(protected.class, SensitivePathClass::Ssh))
            .expect("default protected paths should include ssh")
            .path
            .join("id_ed25519");
        spec.filesystem.mounts.push(MountRule {
            host_path: ssh_path,
            guest_path: "/secrets/id_ed25519".into(),
            mode: MountMode::ReadOnly,
            kind: Default::default(),
        });

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("file grant"));
    }

    #[test]
    fn protected_read_only_mount_with_file_grant_is_valid() {
        let mut spec = spec();
        spec.filesystem = FilesystemPolicy {
            protected_paths: vec![ProtectedPath {
                path: "/tmp/agentbox-secret".into(),
                class: SensitivePathClass::Custom("secret".into()),
                reason: "test secret".into(),
            }],
            mounts: vec![MountRule {
                host_path: "/tmp/agentbox-secret/key".into(),
                guest_path: "/secret/key".into(),
                mode: MountMode::ReadOnly,
                kind: Default::default(),
            }],
            ..FilesystemPolicy::workspace("/tmp/agentbox-work")
        };
        spec.credentials.grants.push(CredentialGrant {
            name: "secret-key".into(),
            kind: CredentialGrantKind::FileMount,
            target: "/tmp/agentbox-secret/key".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });

        validate_minipod_spec(&spec).unwrap();
    }

    #[test]
    fn accepts_review_required_workspace_overlay() {
        let mut spec = spec();
        spec.filesystem.workspace_write_policy = WorkspaceWritePolicy::WritableOverlay;
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some("/tmp/agentbox-overlay/session-1".into()));

        validate_minipod_spec(&spec).unwrap();
    }

    #[test]
    fn rejects_direct_workspace_policy_with_overlay() {
        let mut spec = spec();
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some("/tmp/agentbox-overlay/session-1".into()));

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("direct workspace"));
    }

    #[test]
    fn rejects_writable_overlay_policy_without_overlay() {
        let mut spec = spec();
        spec.filesystem.workspace_write_policy = WorkspaceWritePolicy::WritableOverlay;

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("requires a workspace overlay"));
    }

    #[test]
    fn rejects_workspace_overlay_with_empty_guest_path() {
        let mut spec = spec();
        spec.filesystem.workspace_write_policy = WorkspaceWritePolicy::WritableOverlay;
        spec.filesystem.workspace_overlay = WorkspaceOverlayPolicy {
            mode: WorkspaceOverlayMode::ReviewRequired,
            upper_host_path: Some("/tmp/agentbox-overlay/upper".into()),
            work_host_path: Some("/tmp/agentbox-overlay/work".into()),
            guest_path: " ".into(),
        };

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("guest path"));
    }

    #[test]
    fn rejects_workspace_overlay_inside_workspace() {
        let mut spec = spec();
        spec.filesystem.workspace_write_policy = WorkspaceWritePolicy::WritableOverlay;
        spec.filesystem.workspace_overlay = WorkspaceOverlayPolicy::review_required(Some(
            "/tmp/agentbox-work/.agentbox-overlay".into(),
        ));

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("inside the workspace"));
    }

    #[test]
    fn rejects_workspace_overlay_stored_in_protected_path() {
        let mut spec = spec();
        spec.filesystem.workspace_write_policy = WorkspaceWritePolicy::WritableOverlay;
        spec.filesystem.protected_paths.push(ProtectedPath {
            path: "/tmp/agentbox-secret".into(),
            class: SensitivePathClass::Custom("secret".into()),
            reason: "test secret".into(),
        });
        spec.filesystem.workspace_overlay =
            WorkspaceOverlayPolicy::review_required(Some("/tmp/agentbox-secret/overlay".into()));

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("overlay upper path"));
    }

    #[test]
    fn protected_file_grants_must_require_approval() {
        let mut spec = spec();
        spec.filesystem = FilesystemPolicy {
            protected_paths: vec![ProtectedPath {
                path: "/tmp/agentbox-secret".into(),
                class: SensitivePathClass::Custom("secret".into()),
                reason: "test secret".into(),
            }],
            mounts: vec![MountRule {
                host_path: "/tmp/agentbox-secret/key".into(),
                guest_path: "/secret/key".into(),
                mode: MountMode::ReadOnly,
                kind: Default::default(),
            }],
            ..FilesystemPolicy::workspace("/tmp/agentbox-work")
        };
        spec.credentials.grants.push(CredentialGrant {
            name: "secret-key".into(),
            kind: CredentialGrantKind::FileMount,
            target: "/tmp/agentbox-secret/key".into(),
            one_time: true,
            requires_approval: false,
            expires_at: None,
        });

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("file grant"));
    }

    #[test]
    fn protected_path_checks_normalize_dot_dot_segments() {
        let mut spec = spec();
        spec.filesystem = FilesystemPolicy {
            protected_paths: vec![ProtectedPath {
                path: "/tmp/agentbox-secret".into(),
                class: SensitivePathClass::Custom("secret".into()),
                reason: "test secret".into(),
            }],
            mounts: vec![MountRule {
                host_path: "/tmp/agentbox-work/../agentbox-secret/key".into(),
                guest_path: "/secret/key".into(),
                mode: MountMode::ReadOnly,
                kind: Default::default(),
            }],
            ..FilesystemPolicy::workspace("/tmp/agentbox-work")
        };

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("file grant"));
    }

    #[test]
    fn file_grants_match_normalized_mount_paths() {
        let mut spec = spec();
        spec.filesystem = FilesystemPolicy {
            protected_paths: vec![ProtectedPath {
                path: "/tmp/agentbox-secret".into(),
                class: SensitivePathClass::Custom("secret".into()),
                reason: "test secret".into(),
            }],
            mounts: vec![MountRule {
                host_path: "/tmp/agentbox-work/../agentbox-secret/key".into(),
                guest_path: "/secret/key".into(),
                mode: MountMode::ReadOnly,
                kind: Default::default(),
            }],
            ..FilesystemPolicy::workspace("/tmp/agentbox-work")
        };
        spec.credentials.grants.push(CredentialGrant {
            name: "secret-key".into(),
            kind: CredentialGrantKind::FileMount,
            target: "/tmp/agentbox-secret/key".into(),
            one_time: true,
            requires_approval: true,
            expires_at: None,
        });

        validate_minipod_spec(&spec).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_mount_that_escapes_workspace_through_symlink() {
        let base =
            std::env::temp_dir().join(format!("agentbox-symlink-escape-{}", std::process::id()));
        let workspace = base.join("workspace");
        let outside = base.join("outside");
        let link = workspace.join("outside-link");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let mut spec = MinipodSpec::for_agent_task("hermes", &workspace);
        spec.filesystem.mounts.push(MountRule {
            host_path: link,
            guest_path: "/mnt/outside".into(),
            mode: MountMode::ReadOnly,
            kind: Default::default(),
        });

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("symlink"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn rejects_task_policy_bundle_without_id() {
        let mut spec = spec();
        spec.policy_bundles.push(TaskPolicyBundle {
            schema_version: 1,
            id: " ".into(),
            source: None,
            description: None,
            labels: Default::default(),
            allowed_domains: vec![],
            denied_domains: vec![],
            read_only_mounts: vec![],
            workspace_write_policy: None,
            workspace_overlay: None,
            credential_grants: vec![],
            approval_grants: vec![],
            protected_paths: vec![],
        });

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("policy bundle id"));
    }

    #[test]
    fn rejects_read_write_mounts_inside_task_policy_bundle() {
        let mut spec = spec();
        spec.policy_bundles.push(TaskPolicyBundle {
            schema_version: 1,
            id: "deploy".into(),
            source: None,
            description: None,
            labels: Default::default(),
            allowed_domains: vec![],
            denied_domains: vec![],
            read_only_mounts: vec![MountRule {
                host_path: "/tmp/config".into(),
                guest_path: "/mnt/config".into(),
                mode: MountMode::ReadWrite,
                kind: Default::default(),
            }],
            workspace_write_policy: None,
            workspace_overlay: None,
            credential_grants: vec![],
            approval_grants: vec![],
            protected_paths: vec![],
        });

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("read-only"));
    }

    #[test]
    fn rejects_unknown_task_policy_bundle_schema_version() {
        let mut spec = spec();
        spec.policy_bundles.push(TaskPolicyBundle {
            schema_version: 99,
            id: "deploy".into(),
            ..TaskPolicyBundle::default()
        });

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("schema version"));
    }

    #[test]
    fn loads_task_policy_bundle_from_json() {
        let path =
            std::env::temp_dir().join(format!("agentbox-policy-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{
              "schema_version": 1,
              "id": "github-research",
              "allowed_domains": ["api.github.com"],
              "read_only_mounts": [{
                "host_path": "/tmp/docs",
                "guest_path": "/mnt/docs",
                "mode": "ReadOnly"
              }]
            }"#,
        )
        .unwrap();

        let bundle = load_task_policy_bundle(&path).unwrap();

        assert_eq!(bundle.id, "github-research");
        assert_eq!(bundle.source, Some(path.display().to_string()));
        assert_eq!(bundle.allowed_domains, vec!["api.github.com"]);
        assert_eq!(bundle.read_only_mounts.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_invalid_task_policy_bundle_file() {
        let path = std::env::temp_dir().join(format!(
            "agentbox-policy-invalid-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, "{not-json").unwrap();

        let reason = rejection_reason(load_task_policy_bundle(&path).map(|_| ()));

        assert!(reason.contains("failed to parse"));
        let _ = std::fs::remove_file(path);
    }
}
