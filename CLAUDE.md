# Agentbox

## What is this?

Agentbox is "2FA for AI agent actions." A local daemon that lets autonomous agents (OpenClaw, Hermes, Claude Code, etc.) run free on your machine for safe operations, and intercepts dangerous actions with a phone approval gate.

**One-liner:** Your agent runs free. We catch the dangerous stuff.

**Category:** Agent safety layer for individual developers/creators. NOT enterprise middleware.

## Architecture

Three-phase build, each ships independently:

### v0.1 — PATH Shim Daemon (current target)
- Rust daemon listening on Unix socket
- Compiled shim binaries for dangerous commands (rm, git push, psql, etc.)
- Shims sit first in PATH, intercept calls, check policy via daemon socket
- 3-bucket policy: allow / approve / block
- Phone notification via ntfy (free, self-hostable) for approve-bucket actions
- SQLite audit log (append-only, tamper-evident)
- macOS only for now

### v1.0 — Endpoint Security Agent (future)
- macOS Endpoint Security framework for kernel-level interception
- Cannot be bypassed (no PATH tricks, no absolute paths, no direct syscalls)
- Requires Apple Developer Program ($99/yr) + System Extension entitlement

### v1.5 — MCP Governance Proxy (future)
- Local MCP proxy between agent and MCP servers
- Tool-level semantic interception ("Agent wants to call supabase.delete_table('users')")
- Richer risk classification than shell command parsing

## Tech Stack

- **Language:** Rust (2021 edition)
- **Async:** Tokio
- **DB:** SQLite (rusqlite + r2d2)
- **IPC:** Unix domain socket, JSON messages
- **Notifications:** ntfy (HTTP POST to ntfy.sh or self-hosted)
- **Build:** Cargo workspace
- **Distribution:** Homebrew tap, GitHub Releases
- **CI:** GitHub Actions

## Project Structure

```
agentbox/
  Cargo.toml              # Workspace root
  crates/
    agentbox-daemon/      # Main daemon process
    agentbox-shim/        # Shim binary (one binary, symlinked per command)
    agentbox-cli/         # CLI for setup, status, audit queries
    agentbox-policy/      # Risk classification engine
  tests/
    integration/          # End-to-end tests
  scripts/
    install.sh            # Post-brew setup (PATH manipulation)
  docs/
    design.md             # Full design doc (from office hours)
    research.md           # Market research findings
```

## Key Design Decisions

1. **PATH shims over LD_PRELOAD/DYLD_INSERT:** PATH shims are simpler, cross-shell, and don't require SIP disable on macOS. Tradeoff: bypassable via absolute paths. Acceptable for v0.1.

2. **Rust over TypeScript:** Daemon + shims must be fast (<50ms pass-through), small (no runtime deps), and reliable. A Node daemon adds 100MB+ and visible startup delay. Shims are compiled binaries.

3. **ntfy over Pushover/custom app:** ntfy is free, self-hostable, has iOS/Android apps, and requires zero auth setup. HTTP POST to send, WebSocket to receive response. Perfect for v0.1.

4. **3 buckets, not N risk levels:** Simplicity is the product. Users don't configure policies. Strong defaults, 3 buckets (allow/approve/block), that's it.

5. **Append-only SQLite audit log:** Every intercepted action logged with timestamp, command, PID, decision, user response time. Not signed (v0.1) but append-only with WAL mode.

6. **Auto-deny after 120s:** If user doesn't respond to phone notification within 120 seconds, action is denied. Configurable 30s-600s.

## Policy Buckets

### Allow (no notification, execute immediately)
- Read any file
- Write files within current workspace/repo
- Run build/test commands (npm test, cargo test, pytest, etc.)
- Install packages within workspace (npm install, pip install, etc.)
- Git operations within workspace (git add, git commit, git diff, git log)

### Approve (phone notification, wait for response)
- Delete files outside workspace
- git push, git force-push
- Network egress to domains not in allowlist
- Database mutations (psql, mysql, sqlite3 with write operations)
- Send email/messages (curl to mail APIs, sendmail)
- SSH/SCP to remote hosts
- Credential access (~/.ssh/, ~/.aws/, ~/.config/, *.env files)
- Package publish (npm publish, cargo publish)

### Block (instant deny, no notification)
- rm -rf / or rm -rf ~
- Format/wipe disk commands
- Modify system files (/etc/, /System/)
- Kill system processes
- Disable security features (SIP, firewall)

## Development

```bash
cargo build                    # Build all crates
cargo test                     # Run all tests
cargo run -p agentbox-daemon   # Run daemon
cargo run -p agentbox-cli      # Run CLI
```

## Competitive Positioning

- NOT an enterprise product (Palo Alto, WitnessAI, Noma own that)
- NOT a cloud sandbox (E2B, Daytona own that)
- NOT an SDK integration (Agent Action Firewall does that)
- IS: local-first, zero-config, brew-installable agent safety for individual developers
- Closest comp model: Tailscale (OSS core, paid sync/team features)
- Closest technical comp: NVIDIA OpenShell (but K8s-required, no commercial product)

## Commands

- `agentbox start` — start daemon
- `agentbox stop` — stop daemon  
- `agentbox status` — show daemon status + active shims
- `agentbox audit` — query audit log
- `agentbox audit --tail` — live tail of intercepted actions
- `agentbox allow <domain>` — add domain to network allowlist
- `agentbox config` — show/edit config
