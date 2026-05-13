use std::path::Path;

use crate::runtime::provider::RuntimeError;
use crate::runtime::types::{CredentialGrantKind, MinipodSpec, MountMode, NetworkMode};

pub fn validate_minipod_spec(spec: &MinipodSpec) -> Result<(), RuntimeError> {
    if spec.agent.command.is_empty() {
        return reject("agent command cannot be empty");
    }

    if spec.filesystem.workspace_host_path.as_os_str().is_empty() {
        return reject("workspace host path cannot be empty");
    }

    if !spec.filesystem.deny_home_by_default {
        return reject("home directory must be denied by default");
    }

    if spec.credentials.inherit_host_env {
        return reject("host environment inheritance is not allowed");
    }

    if matches!(spec.network.mode, NetworkMode::Host) {
        return reject("host network mode is not allowed for governed minipods");
    }

    if spec.resources.memory_bytes == 0 {
        return reject("memory limit must be greater than zero");
    }

    for mount in &spec.filesystem.mounts {
        if mount.host_path.as_os_str().is_empty() {
            return reject("mount host path cannot be empty");
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

fn is_protected_path(spec: &MinipodSpec, path: &Path) -> bool {
    spec.filesystem
        .protected_paths
        .iter()
        .any(|protected| path.starts_with(&protected.path))
}

fn has_matching_file_grant(spec: &MinipodSpec, path: &Path) -> bool {
    let path = path.to_string_lossy();
    spec.credentials
        .grants
        .iter()
        .any(|grant| matches!(grant.kind, CredentialGrantKind::FileMount) && grant.target == path)
}

fn reject<T>(reason: impl Into<String>) -> Result<T, RuntimeError> {
    Err(RuntimeError::ManifestRejected(reason.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::{
        CredentialGrant, FilesystemPolicy, MountRule, ProtectedPath, SensitivePathClass,
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
    fn rejects_host_network_mode() {
        let mut spec = spec();
        spec.network.mode = NetworkMode::Host;

        let reason = rejection_reason(validate_minipod_spec(&spec));

        assert!(reason.contains("host network"));
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
            }],
            ..FilesystemPolicy::workspace("/tmp/agentbox-work")
        };

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
            }],
            ..FilesystemPolicy::workspace("/tmp/agentbox-work")
        };
        spec.credentials.grants.push(CredentialGrant {
            name: "secret-key".into(),
            kind: CredentialGrantKind::FileMount,
            target: "/tmp/agentbox-secret/key".into(),
            one_time: true,
            requires_approval: true,
        });

        validate_minipod_spec(&spec).unwrap();
    }
}
