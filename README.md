# Agentbox

**2FA for AI agent actions.** A local daemon that lets autonomous agents run free on your machine for safe operations, and intercepts dangerous actions with a phone approval gate.

Your agent runs free. We catch the dangerous stuff.

## The Problem

AI agents (OpenClaw, Hermes, Claude Code, Codex) run 24/7 on personal machines. People are so afraid of destructive actions that they buy dedicated Mac Minis ($599) as physical isolation. Meanwhile, the majority runs agents with zero governance.

Agentbox replaces the $599 Mac Mini with a daemon that costs nothing.

## How It Works

```
Agent calls "git push"
     |
     v
PATH shim intercepts ──> Daemon classifies
                              |
                    +---------+---------+
                    |         |         |
                  ALLOW    APPROVE    BLOCK
                    |         |         |
                 <50ms    Phone      Instant
                 pass    notif.      deny
                through  wait for
                         tap
```

**Three buckets, zero config:**

| Bucket | What happens | Examples |
|--------|-------------|----------|
| **Allow** | Pass through instantly (<50ms) | `ls`, `cat`, `git commit`, `npm install`, `cargo build` |
| **Approve** | Phone notification, wait for tap | `git push`, `ssh`, `curl`, `psql`, `rm` outside workspace |
| **Block** | Instant deny, no notification | `rm -rf /`, `dd`, `mkfs`, `git push --force main` |

## Quick Start

```bash
# Build from source
git clone https://github.com/EfeDurmaz16/agentbox.git
cd agentbox
cargo build --release

# Install shims (creates symlinks for 28 dangerous commands)
cargo run -p agentbox-cli -- install

# Add shims to your PATH (add to ~/.zshrc for persistence)
export PATH="$HOME/.agentbox/shims:$PATH"

# Set your ntfy topic for phone notifications
# (edit ~/.agentbox/config.toml after first run)

# Start the daemon
cargo run -p agentbox-cli -- start

# Check status
cargo run -p agentbox-cli -- status
```

## Phone Notifications (ntfy)

Agentbox uses [ntfy](https://ntfy.sh) for phone notifications. Free, no account needed.

### Setup

**1. Install the ntfy app:**
- iOS: [App Store](https://apps.apple.com/app/ntfy/id1625396347)
- Android: [Play Store](https://play.google.com/store/apps/details?id=io.heckel.ntfy)

**2. Find your topic:**
```bash
# Start the daemon once to generate config
cargo run -p agentbox-daemon

# Check the generated topic
cat ~/.agentbox/config.toml | grep ntfy_topic
# ntfy_topic = "agentbox-0ff3a6402299"
```

**3. Subscribe in the app:**
- Open ntfy app
- Tap "+" to add a subscription
- Enter your topic name (e.g., `agentbox-0ff3a6402299`)
- Tap Subscribe

**4. Test it:**
```bash
# Terminal 1: Start daemon
cargo run -p agentbox-daemon

# Terminal 2: Send a test approval request
python3 -c "
import socket, json
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('$HOME/.agentbox/agentbox.sock')
req = json.dumps({
    'binary': 'git',
    'args': ['push', 'origin', 'main'],
    'cwd': '$(pwd)',
    'parent_process': 'test',
    'pid': 1234
})
sock.sendall((req + '\n').encode())
print('Sent! Check your phone...')
# Wait for response (will block until you tap Approve/Deny or 120s timeout)
resp = sock.recv(4096).decode()
print('Response:', resp)
sock.close()
"
```

Your phone should buzz with:
> **Agentbox -- Approval Required**
> Agent wants to push code to remote repository
> [Approve] [Deny]

Tap Approve or Deny. The daemon receives your response and returns it to the caller.

**5. Custom topic (optional):**
```bash
# Edit ~/.agentbox/config.toml
ntfy_topic = "my-secret-topic-name"  # use something hard to guess
ntfy_server = "https://ntfy.sh"       # or self-host: https://your-server.com
approval_timeout_secs = 120            # 30-600 seconds
```

## Sandbox Mode (Pod Runtime)

Run agents in isolated containers. The agent can't touch your host filesystem.

```bash
# Run an agent in a sandbox
agentbox run "openclaw start"

# With specific runtime and services
agentbox run --runtime node --with postgres "npm test"

# List running sandboxes
agentbox pods

# Stop a sandbox
agentbox stop-pod sb-a1b2c3
```

**Requires:** [Podman](https://podman.io) (`brew install podman` on macOS)

**How isolation works:**
- Agent runs inside a container with isolated filesystem and network
- Agentbox daemon socket is bind-mounted into the pod (the ONLY host connection)
- Shim binaries are injected into the pod's PATH
- Commands inside the pod still go through shim -> daemon -> policy check
- Defense in depth: container isolation + command interception

## CLI Commands

```bash
agentbox start           # Start the daemon
agentbox stop            # Stop the daemon
agentbox status          # Show daemon status + active shims

agentbox install         # Create shim symlinks in ~/.agentbox/shims/
agentbox allow <domain>  # Add domain to network allowlist

agentbox audit           # Query audit log (last 20 events)
agentbox history         # Rich timeline view with stats
agentbox why             # Explain the last block/deny
agentbox policy          # Show current policy posture

agentbox run <command>   # Run agent in isolated sandbox pod
agentbox pods            # List running sandbox pods
agentbox stop-pod <id>   # Remove a sandbox pod
```

## Policy Engine

Context-rich classification with workspace awareness:

```toml
# ~/.agentbox/config.toml

# Domains that skip network approval
allowed_domains = ["github.com", "api.openai.com", "registry.npmjs.org"]

# Commands that are always allowed (overrides all rules)
# Patterns: "ls" (exact), "git push" (binary + subcommand), "npm *" (wildcard)
always_allow = []

# Commands that are always blocked
always_block = []

# How long to wait for phone approval (seconds, 30-600)
approval_timeout_secs = 120
```

**Workspace boundary:** `rm` inside your project = Allow. `rm` outside = Approve.

**Domain allowlist:** `curl https://api.openai.com/...` = Allow (if in allowlist). Unknown domain = Approve.

**Git protection:** `git push --force main` = Block (not just approve).

## Architecture

```
agentbox/
  crates/
    agentbox-policy/     # Risk classification engine (38 tests)
    agentbox-daemon/     # Unix socket server + audit + ntfy + pod runtime
    agentbox-shim/       # Single binary, symlinked per command
    agentbox-cli/        # User-facing commands
    agentbox-client/     # Lightweight client for other Rust projects
  integrations/
    switchboard/         # Coordination layer integration
    agit/                # Audit trail integration
    oaps/                # Protocol governance integration
```

**IPC Protocol:** Newline-delimited JSON over Unix domain socket.

```json
// Shim -> Daemon
{"binary":"git","args":["push","origin","main"],"cwd":"/path","parent_process":"claude-code","pid":12345}

// Daemon -> Shim
{"decision":"approved","reason":"git push to remote","real_binary":"/usr/bin/git"}
```

## Roadmap

| Phase | What | Status |
|-------|------|--------|
| v0.1 | PATH shim daemon + phone approval | Done |
| v0.2 | Pod sandbox runtime (podman) | Done |
| v0.3 | Context-rich policy engine | Done |
| v1.0 | macOS Endpoint Security (kernel-level, bypass-proof) | Planned |
| v1.5 | MCP Governance Proxy (protocol-level interception) | Planned |

## Why Not...

| Alternative | Problem |
|-------------|---------|
| Mac Mini ($599) | Expensive, sync friction, separate machine |
| Docker/VM | Manual setup, not agent-aware, no approval flow |
| OpenAI Agents SDK guardrails | Only works with OpenAI SDK agents |
| Enterprise governance (Palo Alto, Microsoft) | $$$$, team setup, cloud-dependent |
| Nothing (YOLO) | Your agent will `rm -rf` something at 3am |

Agentbox: **local-first, zero-config, agent-agnostic, brew-installable.**

## Tech Stack

- **Language:** Rust (2021 edition)
- **Async:** Tokio
- **DB:** SQLite (rusqlite, r2d2 pool, WAL mode)
- **IPC:** Unix domain socket, JSON
- **Notifications:** ntfy (free, self-hostable)
- **Containers:** Podman (rootless, daemonless)
- **Build:** Cargo workspace (5 crates)

## License

Apache 2.0
