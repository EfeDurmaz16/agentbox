use std::path::{Component, Path, PathBuf};

use agentbox_policy::classify::CommandContext;

use crate::runtime::types::{
    ApprovalGrant, ApprovalScope, ExecCommand, FileAccessMode, RuntimeSession,
};

pub fn command_context_for_session(
    session: &RuntimeSession,
    command: &ExecCommand,
) -> CommandContext {
    let binary = command.argv.first().cloned().unwrap_or_default();
    let args = command.argv.iter().skip(1).cloned().collect();
    let cwd = command
        .working_dir
        .clone()
        .unwrap_or_else(|| session.spec.filesystem.workspace_guest_path.clone());

    CommandContext {
        binary,
        args,
        cwd,
        parent_process: Some("agentbox-runtime-manager".into()),
        pid: 0,
    }
}

pub fn grant_matches_command(
    grant: &ApprovalGrant,
    session: &RuntimeSession,
    command: &ExecCommand,
) -> bool {
    let ctx = command_context_for_session(session, command);
    match &grant.scope {
        ApprovalScope::Once => true,
        ApprovalScope::Command {
            binary,
            args_prefix,
        } => ctx.binary == *binary && ctx.args.starts_with(args_prefix),
        ApprovalScope::Path { path, access } => command_paths(&ctx).iter().any(|candidate| {
            path_matches(path, candidate) && access_allows(access, &path_access(&ctx))
        }),
        ApprovalScope::Domain { domain } => command_domains(&ctx)
            .iter()
            .any(|candidate| domain_matches(domain, candidate)),
        ApprovalScope::Session { session_id } => session_id == &session.id,
    }
}

pub fn consume_once_grant(grants: &mut Vec<ApprovalGrant>, grant_id: &str) -> bool {
    if let Some(index) = grants
        .iter()
        .position(|grant| grant.id == grant_id && matches!(grant.scope, ApprovalScope::Once))
    {
        grants.remove(index);
        true
    } else {
        false
    }
}

fn command_paths(ctx: &CommandContext) -> Vec<PathBuf> {
    ctx.args
        .iter()
        .filter(|arg| !arg.starts_with('-') && !arg.contains("://"))
        .map(|arg| {
            let path = PathBuf::from(arg);
            if path.is_absolute() {
                normalize_path(&path)
            } else {
                normalize_path(&PathBuf::from(&ctx.cwd).join(path))
            }
        })
        .collect()
}

fn path_access(ctx: &CommandContext) -> FileAccessMode {
    match ctx.binary.as_str() {
        "cat" | "less" | "more" | "head" | "tail" | "grep" | "rg" => FileAccessMode::Read,
        "rm" | "touch" | "mkdir" | "rmdir" | "mv" | "cp" | "chmod" | "chown" | "nano" | "vim"
        | "vi" | "code" => FileAccessMode::Write,
        _ => FileAccessMode::ReadWrite,
    }
}

fn path_matches(grant_path: &Path, candidate: &Path) -> bool {
    normalize_path(candidate).starts_with(normalize_path(grant_path))
}

fn access_allows(grant: &FileAccessMode, requested: &FileAccessMode) -> bool {
    matches!(grant, FileAccessMode::ReadWrite) || grant == requested
}

fn command_domains(ctx: &CommandContext) -> Vec<String> {
    ctx.args
        .iter()
        .filter_map(|arg| extract_domain(arg))
        .collect()
}

fn extract_domain(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }

    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .rsplit('@')
        .next()
        .unwrap_or("");
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split_once(']')?.0
    } else {
        authority.split(':').next().unwrap_or("")
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn domain_matches(grant_domain: &str, candidate: &str) -> bool {
    let grant_domain = grant_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let candidate = candidate.trim().trim_end_matches('.').to_ascii_lowercase();
    candidate == grant_domain || candidate.ends_with(&format!(".{grant_domain}"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::types::{ApprovalScope, MinipodSpec};

    fn session() -> RuntimeSession {
        let spec = MinipodSpec::for_agent_task("hermes", "/tmp/agentbox-work");
        RuntimeSession::new(spec.name.clone(), "native-test".into(), "test".into(), spec)
    }

    fn command(argv: &[&str]) -> ExecCommand {
        ExecCommand {
            argv: argv.iter().map(|value| value.to_string()).collect(),
            working_dir: Some("/workspace".into()),
            env: Default::default(),
            timeout_seconds: None,
        }
    }

    fn grant(scope: ApprovalScope) -> ApprovalGrant {
        ApprovalGrant {
            id: "grant-1".into(),
            scope,
            reason: "test".into(),
            expires_at: None,
        }
    }

    #[test]
    fn command_scope_matches_binary_and_args_prefix() {
        let session = session();
        let grant = grant(ApprovalScope::Command {
            binary: "git".into(),
            args_prefix: vec!["push".into()],
        });

        assert!(grant_matches_command(
            &grant,
            &session,
            &command(&["git", "push", "origin", "main"])
        ));
        assert!(!grant_matches_command(
            &grant,
            &session,
            &command(&["git", "status"])
        ));
    }

    #[test]
    fn domain_scope_matches_subdomains_without_suffix_tricks() {
        let session = session();
        let grant = grant(ApprovalScope::Domain {
            domain: "github.com".into(),
        });

        assert!(grant_matches_command(
            &grant,
            &session,
            &command(&["curl", "https://api.github.com/repos"])
        ));
        assert!(!grant_matches_command(
            &grant,
            &session,
            &command(&["curl", "https://evilgithub.com/repos"])
        ));
    }

    #[test]
    fn path_scope_matches_normalized_paths_and_access() {
        let session = session();
        let grant = grant(ApprovalScope::Path {
            path: "/workspace/secret.env".into(),
            access: FileAccessMode::Read,
        });

        assert!(grant_matches_command(
            &grant,
            &session,
            &command(&["cat", "./nested/../secret.env"])
        ));
        assert!(!grant_matches_command(
            &grant,
            &session,
            &command(&["rm", "./nested/../secret.env"])
        ));
    }

    #[test]
    fn session_scope_matches_only_current_session() {
        let session = session();
        let matching_grant = grant(ApprovalScope::Session {
            session_id: session.id.clone(),
        });
        let other = grant(ApprovalScope::Session {
            session_id: "other-session".into(),
        });

        assert!(grant_matches_command(
            &matching_grant,
            &session,
            &command(&["git", "push"])
        ));
        assert!(!grant_matches_command(
            &other,
            &session,
            &command(&["git", "push"])
        ));
    }

    #[test]
    fn once_scope_is_consumed_by_id() {
        let mut grants = vec![grant(ApprovalScope::Once)];

        assert!(consume_once_grant(&mut grants, "grant-1"));
        assert!(grants.is_empty());
        assert!(!consume_once_grant(&mut grants, "grant-1"));
    }
}
