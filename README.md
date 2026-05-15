# Agentbox

**Governed execution cells for autonomous agents.** Agentbox runs AgentPods:
task-scoped execution cells for agents that need to touch files, run commands,
use credentials, reach networks, or interact with local and remote systems.

The wedge is not "2FA for agents" and it is not a generic Docker wrapper. The
problem is that people run autonomous agents on their real machines, then buy
separate hardware when they stop trusting those agents with local files,
credentials, browser state, cloud CLIs, databases, deploys, or production
repos. Agentbox aims to make that separation available locally as software.

The validated core today is the control loop: **shim -> daemon -> policy ->
approval -> audit**. The product direction is broader: **agent intent ->
AgentPod -> adaptive execution provider -> governed host bridge -> policy /
approval / credentials / evidence**. Providers may use guarded host processes,
native OS sandboxes, containers, VMs, or remote workers. Podman is only a
compatibility provider; Agentbox owns the AgentPod contract.

## Why

Autonomous agents are no longer just coding helpers. Coding agents, browser
agents, computer-use agents, personal workflow agents, DevOps agents, and
general systems such as Aspendos-style agents all need to operate on local
machines. Most users choose between two bad defaults: let the agent run directly
in the real shell and home directory, or move the agent into a heavy remote
sandbox they do not control.

Agentbox aims at the missing execution governance layer: a task-scoped AgentPod
with the right workspace, services, credentials, and tools, while dangerous
side effects still go through policy, approval, and audit before they touch the
host.

The interception primitive is what makes the sandbox agent-aware instead of just container-shaped. PATH-mediated calls to commands such as `git push`, `ssh`, `curl`, `psql`, or `rm` outside the workspace pass through the daemon. The classifier inspects the full context -- command name, arguments, current working directory, environment -- and routes to one of three buckets:

- **Allow**: pass through quickly. Examples: `ls`, `cat`, `git commit`, `npm install`, `cargo build`.
- **Approve**: phone notification via ntfy, wait for tap. Examples: `git push`, `ssh`, `curl`, `psql`, `rm` outside the workspace.
- **Block**: instant deny, no notification. Examples: `rm -rf /`, `dd`, `mkfs`, `git push --force main`.

The policy engine ships with conservative defaults and supports local configuration for allowlists, blocklists, workspace boundaries, and approval timeouts.

## How It Works

```
Autonomous agent task
  |
  +-- current validated mode: host workspace with Agentbox shims on PATH
  |
  +-- product direction: local minipod with explicit boundaries
        |
        v
filesystem / network / credential / process / host-action boundary
        |
        v
Rust daemon classifies command + args + cwd + environment + session policy
        |
        +--> ALLOW    pass through
        +--> APPROVE  ask out-of-band, then continue or deny
        +--> BLOCK    deny immediately
        |
        v
SQLite audit log and future evidence adapters record the decision
```

**Three buckets, local policy:**

| Bucket | What happens | Examples |
|--------|-------------|----------|
| **Allow** | Pass through without approval | `ls`, `cat`, `git commit`, `npm install`, `cargo build` |
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

## Out-of-Band Approvals (ntfy)

Agentbox uses [ntfy](https://ntfy.sh) for approval notifications. The default setup is phone-based, free, and does not require an account; self-hosted ntfy also works.

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

## Guarded Minipods (Experimental AgentPod Runtime)

Run agents in local AgentPod minipods while routing selected host-impacting
actions through Agentbox policy. Today, `agentbox run` uses the runtime manager
with a Podman compatibility adapter because that gives a runnable backend while
the native `agentpod-macos`, `agentpod-linux`, and `agentpod-windows` providers
are being built. Podman is not the architecture; it is the bootstrap backend.

```bash
# Run an agent in a governed local minipod
agentbox run "openclaw start"

# Preview the AgentPod run plan without requiring a runnable backend
agentbox run --plan --risk high --workspace-mode overlay-review "codex"
# The preview includes provider selection, candidates, backend actions,
# network enforcement metadata, warnings, and the full AgentPod manifest.

# Emit machine-readable run output for automation when a backend is runnable
agentbox run --json --provider podman "npm test"

# Generate the governed minipod manifest without starting a backend
agentbox minipod-spec hermes --workspace . --allow-domain api.openai.com

# Generate a manifest where writes go to a reviewable overlay instead of being
# modeled as direct host workspace writes. Provider execution support is still
# separate from this manifest contract.
agentbox minipod-spec hermes --workspace . --workspace-mode overlay-review

# Generate a higher-risk manifest that recommends the platform AgentPod provider
# while staying honest if that provider is descriptor-only.
agentbox minipod-spec codex --workspace . --risk high --provider auto

# Force the current compatibility backend in the manifest.
agentbox minipod-spec codex --workspace . --provider podman

# Run a safe OpenClaw/Hermes-style manifest demo
scripts/demo-autonomous-agent.sh

# Live compatibility smoke for daemon socket + shim bridge when Podman exists
scripts/smoke-podman-bridge.sh

# Build the Linux guest shim artifact used by Podman compatibility minipods
rustup target add x86_64-unknown-linux-musl
eval "$(scripts/build-linux-shim.sh)"

# Block high-risk destinations for the task
agentbox minipod-spec hermes --workspace . --deny-domain metadata.google.internal

# Require approval on first contact for unknown external destinations
agentbox minipod-spec hermes --workspace . --network-mode first-contact

# Use normal internet access with guardrails for dangerous destinations.
agentbox minipod-spec hermes --workspace . --network-mode open-with-guardrails

# Disable localhost/loopback service access for a task
agentbox minipod-spec hermes --workspace . --deny-localhost

# Bind a task-scoped policy bundle into the manifest
agentbox minipod-spec hermes --workspace . --policy-bundle ./agentbox.task-policy.json

# Select policy defaults by agent role without hardcoding a specific agent brand
agentbox minipod-spec hermes --workspace . --agent-profile research

# With specific runtime and services
agentbox run --runtime node --with postgres "npm test"

# List running minipods
agentbox pods

# Stop a minipod session
agentbox stop-pod 01hxyzagentpod
```

Service sidecars such as `postgres`, `redis`, `mysql`, and `mongo` carry
readiness probes. The compatibility backend starts sidecars first and waits for
their probe command before starting the workspace agent container.

**Current compatibility backend:** [Podman](https://podman.io)
(`brew install podman` on macOS). Native AgentPod providers are descriptor-only
or prototype-gated until enforcement lands. `agentbox providers` separates
planned provider capability metadata from active network enforcement flags, so
Podman compatibility is not presented as domain or packet-level policy
enforcement. Linux AgentPod work has started with user, mount, PID namespace,
cgroups v2, seccomp profile, and Landlock filesystem primitives, plus a gated
prototype executor. macOS AgentPod now has a native plan compiler for the Apple
Virtualization, Endpoint Security, Network Extension, entitlement, host bridge,
and evidence surfaces, but provider execution remains unavailable until live
runner and enforcement tests exist.

**How guarded minipods work:**
- Agent runs inside a container with governed filesystem and network policy metadata
- Agentbox daemon socket is bind-mounted into the pod (the ONLY host connection)
- Shim binaries are injected into the pod's PATH
- Commands inside the pod still go through shim -> daemon -> policy check
- Defense in depth: container isolation + command interception
- Not bypass-proof yet; macOS Endpoint Security and protocol-level interception are roadmap items

**What minipods still need before v0.2 is credible:**
- native AgentPod provider execution beyond descriptors
- live smoke proof for the current Podman compatibility backend
- protected host path denial tests
- smoke tests proving the shim and daemon socket work inside the minipod
- honest platform-specific bypass documentation

See [docs/product-direction.md](docs/product-direction.md) and
[docs/status-matrix.md](docs/status-matrix.md) for current shipped status, and
[docs/roadmap-250-commits.md](docs/roadmap-250-commits.md) for the current
250+ atomic-commit product sprint. The older
[docs/roadmap-100-issues.md](docs/roadmap-100-issues.md) is kept as historical
planning context.
See [docs/agentpod-contract.md](docs/agentpod-contract.md) for the final
AgentPod product contract: adaptive providers, workspace modes, credential
grants, network policy, host bridge, approval, and evidence.
See [docs/glossary.md](docs/glossary.md) for the Agentbox vocabulary:
AgentPod, minipod, boundary, provider, authority, evidence, and host bridge.
See [docs/mac-mini-replacement-wedge.md](docs/mac-mini-replacement-wedge.md)
for the local-software-boundary wedge and its limits.
See [docs/release-readiness.md](docs/release-readiness.md) for the release
gate before tagging public builds.
See [docs/installer-packaging.md](docs/installer-packaging.md) for the
packaging path and the rule against shipping unverified installers.
Evidence records can now be mapped into FIDES-style signed action drafts and
AGIT-style lineage drafts, but both intentionally require external authority or
adapter code before claiming live integration.
Runtime sessions can also capture Git workspace diff snapshots as evidence
references for later AGIT lineage attachment.
Session evidence bundles include redacted command transcripts so operators can
inspect what ran without storing raw credential-like output.
They also include metadata-only replay steps linked to audit hashes; Agentbox
does not automatically rerun side-effecting commands from evidence bundles.

```sh
# Export a portable evidence bundle directory for a persisted AgentPod session
agentbox evidence --session <session-id> --bundle ./agentbox-evidence

# Verify the bundle file manifest without requiring the original session store
agentbox evidence --verify --bundle ./agentbox-evidence
```

The generated `index.json` includes per-file SHA-256 digests, byte counts, and a
bundle `root_sha256` so the same artifact can be handed to remote evidence
upload, AGIT lineage, or FIDES-style verification without trusting loose local
filenames.

For macOS specifically, see
[docs/macos-minipod-limitations.md](docs/macos-minipod-limitations.md).
For file boundaries, see
[docs/safe-file-sharing.md](docs/safe-file-sharing.md).
For the public security boundary, see
[docs/threat-model.md](docs/threat-model.md),
[docs/platform-isolation.md](docs/platform-isolation.md), and
[docs/limitations.md](docs/limitations.md).

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
agentbox doctor          # Local readiness check for daemon, shims, audit, and providers
agentbox setup-plan      # Show the next local setup actions without changing host state
agentbox setup-plan --provider remote-agentpod
agentbox setup --dry-run --provider remote-agentpod --json
agentbox evidence        # Export audit/evidence JSONL
agentbox minipod-spec    # Generate and validate a governed minipod manifest
agentbox minipod-spec --policy-bundle ./task-policy.json

agentbox run <command>   # Run agent in a guarded local minipod
agentbox pods            # List running compatibility-backend minipods
agentbox stop-pod <id>   # Remove a minipod session
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
    agentbox-daemon/     # Unix socket server + audit + ntfy + minipod runtime
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
| v0.2 | Guarded minipod runtime spine | In progress |
| v0.3 | Context-rich policy engine | Done |
| v1.0 | macOS Endpoint Security host process/file enforcement | Planned |
| v1.5 | MCP Governance Proxy (protocol-level interception) | Planned |

## Why Not...

| Alternative | Problem |
|-------------|---------|
| Mac Mini ($599) | Expensive, sync friction, separate machine |
| Docker/VM | Manual setup, not agent-aware, no approval flow or local audit model by default |
| OpenAI Agents SDK guardrails | Only works with OpenAI SDK agents |
| Enterprise governance (Palo Alto, Microsoft) | $$$$, team setup, cloud-dependent |
| Nothing | Agents can mutate files, credentials, remotes, databases, and services without a local policy boundary |

Agentbox: **local-first, agent-aware, policy-bound, audit-first minipods.**

## Tech Stack

- **Language:** Rust (2021 edition)
- **Async:** Tokio
- **DB:** SQLite (rusqlite, r2d2 pool, WAL mode)
- **IPC:** Unix domain socket, JSON
- **Notifications:** ntfy (free, self-hostable)
- **Runtime:** Provider abstraction with AgentPod-native descriptors and a Podman compatibility adapter
- **Build:** Cargo workspace (5 crates)

## License

Apache 2.0
