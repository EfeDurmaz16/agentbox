use crate::classify::{Bucket, Classification, CommandContext, PolicyConfig};

/// Extract domain from a URL string. Returns None if parsing fails.
fn extract_domain(url: &str) -> Option<String> {
    let without_scheme = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return None;
    };
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host_port = host_port.split('?').next().unwrap_or(host_port);
    let host = if host_port.contains(':') {
        host_port
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_port)
    } else {
        host_port
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// Check if a command matches a pattern from always_allow / always_block.
/// Patterns: "ls" (exact binary), "git push" (binary + subcommand), "npm *" (any npm invocation).
fn command_matches_pattern(ctx: &CommandContext, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if let Some(binary) = pattern.strip_suffix(" *") {
        return ctx.binary == binary.trim();
    }
    let parts: Vec<&str> = pattern.splitn(2, ' ').collect();
    if parts.len() == 1 {
        ctx.binary == parts[0]
    } else {
        ctx.binary == parts[0] && ctx.args.first().map(|s| s.as_str()) == Some(parts[1])
    }
}

/// Check config overrides. Runs BEFORE block/approve rules.
/// - If command matches always_block → Block
/// - If command matches always_allow → Allow
/// - If it's a network command and domain is in allowed_domains → Allow
pub fn check_config_overrides(
    ctx: &CommandContext,
    config: &PolicyConfig,
) -> Option<Classification> {
    // Always-block overrides (highest priority)
    for pattern in &config.always_block {
        if command_matches_pattern(ctx, pattern) {
            return Some(Classification {
                bucket: Bucket::Block,
                reason: format!("{} — blocked by user policy override", ctx.binary),
                notification_summary: None,
            });
        }
    }

    // Always-allow overrides
    for pattern in &config.always_allow {
        if command_matches_pattern(ctx, pattern) {
            return Some(Classification {
                bucket: Bucket::Allow,
                reason: format!("{} — allowed by user policy override", ctx.binary),
                notification_summary: None,
            });
        }
    }

    // Domain allowlist for network commands
    if matches!(ctx.binary.as_str(), "curl" | "wget") {
        if let Some(url) = ctx.args.iter().find(|a| a.starts_with("http")) {
            if let Some(domain) = extract_domain(url) {
                if config.allowed_domains.iter().any(|d| {
                    let d_lower = d.to_lowercase();
                    domain == d_lower || domain.ends_with(&format!(".{}", d_lower))
                }) {
                    return Some(Classification {
                        bucket: Bucket::Allow,
                        reason: format!("{} to {} — domain in allowlist", ctx.binary, domain),
                        notification_summary: None,
                    });
                }
            }
        }
    }

    None
}

/// Check if a command should be BLOCKED (instant deny).
pub fn check_block(ctx: &CommandContext, config: &PolicyConfig) -> Option<Classification> {
    let args_joined = ctx.args.join(" ");
    let _ = config; // config used by check_config_overrides; kept in signature for future extensibility

    match ctx.binary.as_str() {
        "rm" => {
            // rm -rf / or rm -rf ~ or rm -rf $HOME
            let has_recursive_force = ctx.args.iter().any(|a| {
                if !a.starts_with('-') {
                    return false;
                }
                a.contains('r') && a.contains('f')
            });

            let targets_root = ctx.args.iter().any(|a| {
                if a.starts_with('-') {
                    return false;
                }
                let trimmed = a.trim_end_matches('/');
                trimmed.is_empty() // "/" trimmed becomes ""
                    || trimmed == "/"
                    || trimmed == "~"
                    || trimmed == "$HOME"
                    || trimmed == std::env::var("HOME").unwrap_or_default()
            });

            if has_recursive_force && targets_root {
                return Some(Classification {
                    bucket: Bucket::Block,
                    reason: "rm -rf targeting root or home directory".into(),
                    notification_summary: None,
                });
            }
        }
        "mkfs" | "diskutil" => {
            if args_joined.contains("eraseDisk")
                || args_joined.contains("eraseVolume")
                || ctx.binary == "mkfs"
            {
                return Some(Classification {
                    bucket: Bucket::Block,
                    reason: "disk format/erase command".into(),
                    notification_summary: None,
                });
            }
        }
        "csrutil" | "spctl" => {
            return Some(Classification {
                bucket: Bucket::Block,
                reason: "attempt to modify system security settings".into(),
                notification_summary: None,
            });
        }
        "dd" => {
            return Some(Classification {
                bucket: Bucket::Block,
                reason: "dd — raw disk/device write tool".into(),
                notification_summary: None,
            });
        }
        "git" => {
            // git push --force to main/master → Block
            let subcommand = ctx.args.first().map(|s| s.as_str()).unwrap_or("");
            if subcommand == "push" {
                let is_force = ctx
                    .args
                    .iter()
                    .any(|a| a == "--force" || a == "-f" || a == "--force-with-lease");
                if is_force {
                    let targets_protected = ctx.args.iter().any(|a| {
                        !a.starts_with('-')
                            && a != "push"
                            && a != "origin"
                            && (a == "main"
                                || a == "master"
                                || a.ends_with("/main")
                                || a.ends_with("/master")
                                || a.starts_with("main:")
                                || a.starts_with("master:"))
                    });
                    if targets_protected {
                        return Some(Classification {
                            bucket: Bucket::Block,
                            reason: "git force push to protected branch (main/master)".into(),
                            notification_summary: None,
                        });
                    }
                }
            }
        }
        _ => {}
    }

    None
}

/// Check if a command should require APPROVAL (phone notification).
pub fn check_approve(ctx: &CommandContext, config: &PolicyConfig) -> Option<Classification> {
    let args_joined = ctx.args.join(" ");

    match ctx.binary.as_str() {
        "rm" => {
            // Workspace-aware: rm inside workspace → Allow (fall through), rm outside → Approve
            let workspace = config.workspace.as_deref().unwrap_or(&ctx.cwd);

            let outside_workspace = ctx.args.iter().any(|a| {
                if a.starts_with('-') {
                    return false;
                }
                !a.starts_with(workspace)
            });
            if outside_workspace {
                let file_count = ctx.args.iter().filter(|a| !a.starts_with('-')).count();
                return Some(Classification {
                    bucket: Bucket::Approve,
                    reason: "rm targeting files outside workspace".into(),
                    notification_summary: Some(format!(
                        "Agent wants to delete {} file(s) outside the current project",
                        file_count
                    )),
                });
            }
        }
        "git" => {
            let subcommand = ctx.args.first().map(|s| s.as_str()).unwrap_or("");
            match subcommand {
                "push" => {
                    let is_force = ctx
                        .args
                        .iter()
                        .any(|a| a == "--force" || a == "-f" || a == "--force-with-lease");
                    let summary = if is_force {
                        "Agent wants to FORCE PUSH to remote repository"
                    } else {
                        "Agent wants to push code to remote repository"
                    };
                    return Some(Classification {
                        bucket: Bucket::Approve,
                        reason: "git push to remote".into(),
                        notification_summary: Some(summary.into()),
                    });
                }
                _ => {}
            }
        }
        "ssh" | "scp" => {
            let target = ctx
                .args
                .iter()
                .find(|a| !a.starts_with('-'))
                .cloned()
                .unwrap_or_default();
            return Some(Classification {
                bucket: Bucket::Approve,
                reason: format!("{} to remote host", ctx.binary),
                notification_summary: Some(format!("Agent wants to {} to {}", ctx.binary, target)),
            });
        }
        "psql" | "mysql" | "sqlite3" => {
            return Some(Classification {
                bucket: Bucket::Approve,
                reason: "database client invocation".into(),
                notification_summary: Some(format!(
                    "Agent wants to run database command: {} {}",
                    ctx.binary,
                    args_joined.chars().take(100).collect::<String>()
                )),
            });
        }
        "curl" | "wget" => {
            // Network egress — if we reach here, domain was NOT in allowlist
            let url = ctx
                .args
                .iter()
                .find(|a| a.starts_with("http"))
                .cloned()
                .unwrap_or_default();
            return Some(Classification {
                bucket: Bucket::Approve,
                reason: "network egress".into(),
                notification_summary: Some(format!("Agent wants to make HTTP request to {}", url)),
            });
        }
        "npm" | "cargo" | "gem" => {
            if ctx.args.first().map(|s| s.as_str()) == Some("publish") {
                return Some(Classification {
                    bucket: Bucket::Approve,
                    reason: "package publish".into(),
                    notification_summary: Some(format!(
                        "Agent wants to publish package via {}",
                        ctx.binary
                    )),
                });
            }
        }
        "osascript" => {
            return Some(Classification {
                bucket: Bucket::Approve,
                reason: "AppleScript execution (can control other apps)".into(),
                notification_summary: Some(
                    "Agent wants to run AppleScript (can control macOS apps)".into(),
                ),
            });
        }
        "cat" | "head" | "tail" | "less" | "more" | "vim" | "nano" | "code" => {
            // Reading/editing credential/secret files requires approval
            let sensitive_patterns = [
                ".env",
                ".ssh/",
                ".aws/",
                ".config/",
                ".gnupg/",
                "credentials",
                "secrets",
                "token",
                ".netrc",
            ];
            let reads_sensitive = ctx.args.iter().any(|a| {
                if a.starts_with('-') {
                    return false;
                }
                let lower = a.to_lowercase();
                sensitive_patterns.iter().any(|p| lower.contains(p))
            });
            if reads_sensitive {
                let files: Vec<_> = ctx.args.iter().filter(|a| !a.starts_with('-')).collect();
                let verb = match ctx.binary.as_str() {
                    "vim" | "nano" | "code" => "edit",
                    _ => "read",
                };
                return Some(Classification {
                    bucket: Bucket::Approve,
                    reason: format!("{}ing sensitive/credential file", verb),
                    notification_summary: Some(format!(
                        "Agent wants to {} sensitive file: {}",
                        verb,
                        files
                            .iter()
                            .map(|f| f.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                });
            }
        }
        "chmod" | "chown" => {
            return Some(Classification {
                bucket: Bucket::Approve,
                reason: format!("{} — file permission/ownership change", ctx.binary),
                notification_summary: Some(format!(
                    "Agent wants to change permissions: {} {}",
                    ctx.binary,
                    ctx.args.join(" ")
                )),
            });
        }
        "kill" | "killall" | "pkill" => {
            return Some(Classification {
                bucket: Bucket::Approve,
                reason: format!("{} — process termination", ctx.binary),
                notification_summary: Some(format!(
                    "Agent wants to terminate process: {} {}",
                    ctx.binary,
                    ctx.args.join(" ")
                )),
            });
        }
        "docker" | "podman" => {
            let subcommand = ctx.args.first().map(|s| s.as_str()).unwrap_or("");
            match subcommand {
                "ps" | "images" | "inspect" | "logs" => {} // read-only, fall through to allow
                _ => {
                    return Some(Classification {
                        bucket: Bucket::Approve,
                        reason: format!("docker {} — container mutation", subcommand),
                        notification_summary: Some(format!(
                            "Agent wants to run: {} {} {}",
                            ctx.binary,
                            subcommand,
                            ctx.args.get(1).unwrap_or(&String::new())
                        )),
                    });
                }
            }
        }
        "kubectl" | "helm" => {
            let subcommand = ctx.args.first().map(|s| s.as_str()).unwrap_or("");
            match subcommand {
                "get" | "describe" | "logs" => {} // read-only, fall through to allow
                _ => {
                    return Some(Classification {
                        bucket: Bucket::Approve,
                        reason: format!("{} {} — cluster mutation", ctx.binary, subcommand),
                        notification_summary: Some(format!(
                            "Agent wants to run: {} {}",
                            ctx.binary,
                            ctx.args.join(" ")
                        )),
                    });
                }
            }
        }
        "gh" => {
            let subcommand = ctx.args.first().map(|s| s.as_str()).unwrap_or("");
            match subcommand {
                "pr" | "issue" | "release" | "api" => {
                    return Some(Classification {
                        bucket: Bucket::Approve,
                        reason: format!("gh {} — visible GitHub operation", subcommand),
                        notification_summary: Some(format!(
                            "Agent wants to run: gh {} {}",
                            subcommand,
                            ctx.args.get(1).unwrap_or(&String::new())
                        )),
                    });
                }
                _ => {}
            }
        }
        _ => {}
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{classify, classify_default, Bucket};

    fn ctx(binary: &str, args: &[&str]) -> CommandContext {
        CommandContext {
            binary: binary.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: "/Users/test/project".into(),
            parent_process: None,
            pid: 1234,
        }
    }

    // === Original 22 tests (using classify_default for backward compat) ===

    #[test]
    fn test_rm_rf_root_is_blocked() {
        let c = classify_default(&ctx("rm", &["-rf", "/"]));
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_rm_rf_home_is_blocked() {
        let c = classify_default(&ctx("rm", &["-rf", "~"]));
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_git_push_needs_approval() {
        let c = classify_default(&ctx("git", &["push", "origin", "main"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_git_commit_is_allowed() {
        let c = classify_default(&ctx("git", &["commit", "-m", "fix bug"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_ssh_needs_approval() {
        let c = classify_default(&ctx("ssh", &["user@server.com"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_psql_needs_approval() {
        let c = classify_default(&ctx("psql", &["-h", "localhost", "-d", "mydb"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_ls_is_allowed() {
        let c = classify_default(&ctx("ls", &["-la"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_cat_is_allowed() {
        let c = classify_default(&ctx("cat", &["README.md"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_mkfs_is_blocked() {
        let c = classify_default(&ctx("mkfs", &["-t", "ext4", "/dev/sda1"]));
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_npm_publish_needs_approval() {
        let c = classify_default(&ctx("npm", &["publish"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_npm_install_is_allowed() {
        let c = classify_default(&ctx("npm", &["install", "express"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_dd_is_blocked() {
        let c = classify_default(&ctx("dd", &["if=/dev/zero", "of=/dev/sda"]));
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_cat_ssh_key_needs_approval() {
        let c = classify_default(&ctx("cat", &["/Users/test/.ssh/id_rsa"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_cat_env_file_needs_approval() {
        let c = classify_default(&ctx("cat", &[".env"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_cat_readme_is_allowed() {
        let c = classify_default(&ctx("cat", &["README.md"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_chmod_needs_approval() {
        let c = classify_default(&ctx("chmod", &["777", "important.txt"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_kill_needs_approval() {
        let c = classify_default(&ctx("kill", &["-9", "12345"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_killall_needs_approval() {
        let c = classify_default(&ctx("killall", &["node"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_docker_build_needs_approval() {
        let c = classify_default(&ctx("docker", &["build", "-t", "myapp", "."]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_docker_ps_is_allowed() {
        let c = classify_default(&ctx("docker", &["ps"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_kubectl_apply_needs_approval() {
        let c = classify_default(&ctx("kubectl", &["apply", "-f", "deploy.yaml"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_kubectl_get_is_allowed() {
        let c = classify_default(&ctx("kubectl", &["get", "pods"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    // === New context-rich tests ===

    #[test]
    fn test_rm_inside_workspace_is_allowed() {
        let config = PolicyConfig {
            workspace: Some("/Users/test/project".into()),
            ..Default::default()
        };
        let c = classify(&ctx("rm", &["/Users/test/project/tmp/old.log"]), &config);
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_rm_outside_workspace_needs_approval() {
        let config = PolicyConfig {
            workspace: Some("/Users/test/project".into()),
            ..Default::default()
        };
        let c = classify(&ctx("rm", &["/Users/test/other/file.txt"]), &config);
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_curl_allowed_domain_is_allowed() {
        let config = PolicyConfig {
            allowed_domains: vec!["api.github.com".into(), "registry.npmjs.org".into()],
            ..Default::default()
        };
        let c = classify(&ctx("curl", &["https://api.github.com/repos"]), &config);
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_curl_unknown_domain_needs_approval() {
        let config = PolicyConfig {
            allowed_domains: vec!["api.github.com".into()],
            ..Default::default()
        };
        let c = classify(&ctx("curl", &["https://evil.example.com/steal"]), &config);
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_curl_subdomain_of_allowed_is_allowed() {
        let config = PolicyConfig {
            allowed_domains: vec!["github.com".into()],
            ..Default::default()
        };
        let c = classify(&ctx("curl", &["https://api.github.com/repos"]), &config);
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_always_allow_override() {
        let config = PolicyConfig {
            always_allow: vec!["git push".into()],
            ..Default::default()
        };
        let c = classify(&ctx("git", &["push", "origin", "main"]), &config);
        assert_eq!(c.bucket, Bucket::Allow);
        assert!(c.reason.contains("user policy override"));
    }

    #[test]
    fn test_always_block_override() {
        let config = PolicyConfig {
            always_block: vec!["npm *".into()],
            ..Default::default()
        };
        let c = classify(&ctx("npm", &["install", "express"]), &config);
        assert_eq!(c.bucket, Bucket::Block);
        assert!(c.reason.contains("user policy override"));
    }

    #[test]
    fn test_always_block_takes_priority_over_always_allow() {
        let config = PolicyConfig {
            always_allow: vec!["rm".into()],
            always_block: vec!["rm".into()],
            ..Default::default()
        };
        let c = classify(&ctx("rm", &["file.txt"]), &config);
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_git_force_push_main_is_blocked() {
        let c = classify_default(&ctx("git", &["push", "--force", "origin", "main"]));
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_git_force_push_master_is_blocked() {
        let c = classify_default(&ctx("git", &["push", "-f", "origin", "master"]));
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_git_force_push_feature_branch_needs_approval() {
        let c = classify_default(&ctx("git", &["push", "--force", "origin", "feature/foo"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_vim_env_file_needs_approval() {
        let c = classify_default(&ctx("vim", &[".env"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_nano_ssh_config_needs_approval() {
        let c = classify_default(&ctx("nano", &["/Users/test/.ssh/config"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_code_env_local_needs_approval() {
        let c = classify_default(&ctx("code", &[".env.local"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_vim_regular_file_is_allowed() {
        let c = classify_default(&ctx("vim", &["src/main.rs"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_extract_domain_basic() {
        assert_eq!(
            extract_domain("https://api.github.com/repos"),
            Some("api.github.com".into())
        );
        assert_eq!(
            extract_domain("http://localhost:8080/path"),
            Some("localhost".into())
        );
        assert_eq!(extract_domain("not-a-url"), None);
        assert_eq!(
            extract_domain("https://example.com"),
            Some("example.com".into())
        );
    }
}
