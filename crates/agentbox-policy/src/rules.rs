use crate::classify::{Bucket, Classification, CommandContext};

/// Check if a command should be BLOCKED (instant deny).
pub fn check_block(ctx: &CommandContext) -> Option<Classification> {
    let args_joined = ctx.args.join(" ");

    match ctx.binary.as_str() {
        "rm" => {
            // rm -rf / or rm -rf ~ or rm -rf $HOME
            let has_recursive_force = ctx.args.iter().any(|a| {
                if !a.starts_with('-') { return false; }
                a.contains('r') && a.contains('f')
            });

            let targets_root = ctx.args.iter().any(|a| {
                if a.starts_with('-') { return false; }
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
            if args_joined.contains("eraseDisk") || args_joined.contains("eraseVolume") || ctx.binary == "mkfs" {
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
        _ => {}
    }

    None
}

/// Check if a command should require APPROVAL (phone notification).
pub fn check_approve(ctx: &CommandContext) -> Option<Classification> {
    let args_joined = ctx.args.join(" ");

    match ctx.binary.as_str() {
        "rm" => {
            // Any rm outside workspace
            let outside_workspace = ctx.args.iter().any(|a| {
                !a.starts_with('-') && !a.starts_with(&ctx.cwd)
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
                    let is_force = ctx.args.iter().any(|a| a == "--force" || a == "-f" || a == "--force-with-lease");
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
            let target = ctx.args.iter().find(|a| !a.starts_with('-')).cloned().unwrap_or_default();
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
            // Network egress — check if domain is in allowlist (TODO: implement allowlist)
            let url = ctx.args.iter().find(|a| a.starts_with("http")).cloned().unwrap_or_default();
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
                    notification_summary: Some(format!("Agent wants to publish package via {}", ctx.binary)),
                });
            }
        }
        "osascript" => {
            return Some(Classification {
                bucket: Bucket::Approve,
                reason: "AppleScript execution (can control other apps)".into(),
                notification_summary: Some("Agent wants to run AppleScript (can control macOS apps)".into()),
            });
        }
        "gh" => {
            // GitHub CLI — most operations are visible to others
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
    use crate::classify::{classify, Bucket};

    fn ctx(binary: &str, args: &[&str]) -> CommandContext {
        CommandContext {
            binary: binary.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: "/Users/test/project".into(),
            parent_process: None,
            pid: 1234,
        }
    }

    #[test]
    fn test_rm_rf_root_is_blocked() {
        let c = classify(&ctx("rm", &["-rf", "/"]));
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_rm_rf_home_is_blocked() {
        let c = classify(&ctx("rm", &["-rf", "~"]));
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_git_push_needs_approval() {
        let c = classify(&ctx("git", &["push", "origin", "main"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_git_commit_is_allowed() {
        let c = classify(&ctx("git", &["commit", "-m", "fix bug"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_ssh_needs_approval() {
        let c = classify(&ctx("ssh", &["user@server.com"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_psql_needs_approval() {
        let c = classify(&ctx("psql", &["-h", "localhost", "-d", "mydb"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_ls_is_allowed() {
        let c = classify(&ctx("ls", &["-la"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_cat_is_allowed() {
        let c = classify(&ctx("cat", &["README.md"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }

    #[test]
    fn test_mkfs_is_blocked() {
        let c = classify(&ctx("mkfs", &["-t", "ext4", "/dev/sda1"]));
        assert_eq!(c.bucket, Bucket::Block);
    }

    #[test]
    fn test_npm_publish_needs_approval() {
        let c = classify(&ctx("npm", &["publish"]));
        assert_eq!(c.bucket, Bucket::Approve);
    }

    #[test]
    fn test_npm_install_is_allowed() {
        let c = classify(&ctx("npm", &["install", "express"]));
        assert_eq!(c.bucket, Bucket::Allow);
    }
}
