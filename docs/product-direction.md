# Agentbox Product Direction

Agentbox is a local-first governed micro-runtime for autonomous agents.

The original problem is not limited to coding agents and it is not primarily
"phone approval for shell commands." People buy separate machines for autonomous
agents because they do not trust those agents with the host filesystem,
credentials, browser state, network, cloud accounts, payment surfaces, or
production tools. Agentbox should make that separation available locally as a
software runtime.

## Product Thesis

An autonomous agent should not run directly in the user's real shell by default.
It should run inside a task-scoped local minipod with an explicit boundary:

- what files it can read
- what files it can write
- what credentials it can see
- what network destinations it can reach
- what host actions require approval
- what actions are blocked outright
- what evidence is produced after the run

The approval flow is one control plane inside that runtime. It is not the whole
product.

## Target Agents

Agentbox should support any local autonomous agent that executes tools or tasks
on a personal or workstation machine:

- coding agents such as Codex, Claude Code, Cursor, Aider, OpenHands
- computer-use and browser agents such as OpenClaw, Hermes-style agents, and
  emerging personal computer operators
- personal workflow agents for email, calendar, files, notes, and research
- DevOps agents that touch cloud CLIs, databases, deploys, and repos
- Aspendos-style general agents that combine memory, planning, web actions, and
  reversible or irreversible operations

Coding is the first visible wedge because it is easy to demo and test. The
runtime should not be designed as coding-only infrastructure.

## What "Minipod" Means

A minipod is a small, local, task-scoped execution cell for an agent. It is not
just a container and it is not necessarily the same primitive on every operating
system.

The product-level contract is stable:

```text
agent task
  -> minipod manifest
  -> local execution cell
  -> governed host boundary
  -> policy / approval / evidence
```

The platform implementation can vary:

- macOS: Podman/Lima/Apple Virtualization backed Linux cells first, Endpoint
  Security later for stronger host enforcement.
- Linux: native namespaces, cgroups v2, seccomp, Landlock, rootless runtime,
  and optional eBPF observability/enforcement.
- Windows: Job Objects, AppContainer, Windows Sandbox, Hyper-V isolation, and
  platform-specific filesystem/registry/network policy.

"Micro" should mean fast to create, cheap to keep around, and tiny in per-task
state. Strong isolation is still provided by real OS or virtualization
primitives, not by branding.

## Current State

The validated core today is:

```text
PATH shim -> daemon -> policy classifier -> ntfy approval -> SQLite audit log
```

This is useful but incomplete. It provides a control boundary for selected shell
commands, but it does not yet prove a full governed minipod runtime.

The experimental Podman path exists, but the project should keep calling it
experimental until it proves:

- reliable minipod lifecycle management
- explicit mount policy
- protected host path denial
- credential isolation
- governed network behavior
- shim and socket bridge working inside the minipod
- bypass limitations documented and tested
- evidence export for the whole task session

## Runtime Layers

Agentbox should evolve into five layers:

1. **Runtime orchestration**
   Builds minipod manifests, starts/stops sessions, manages overlays and
   sidecars, and exposes a stable provider abstraction.

2. **Boundary enforcement**
   Controls filesystem, process, network, credential, and host-action access
   using the best primitive available on each operating system.

3. **Policy and approval**
   Classifies actions, applies task/agent/user policy, requests approval when
   needed, and blocks actions that should never run.

4. **Evidence and audit**
   Produces a durable, tamper-evident session record: commands, approvals,
   denied actions, filesystem changes, network events, and commit/artifact
   lineage.

5. **Ecosystem integration**
   Connects to FIDES for authority and signed policy/approval primitives, and
   to agit for action lineage, workspace diffs, and commit-linked evidence.

## Language and Systems Strategy

Rust remains the right core language for:

- daemon
- CLI
- policy engine
- runtime orchestration
- audit/evidence
- provider traits
- Linux low-level launcher wrappers

Use OS-native languages where the platform requires them:

- Swift/C/C++ for macOS Endpoint Security and System Extension packaging.
- Rust with `libc`/`nix` plus small C helpers if needed for Linux
  namespaces/cgroups/seccomp/Landlock.
- C++/Rust FFI for Windows Job Objects, AppContainer, Windows Sandbox, and
  Hyper-V bridges.
- Zig only if a tiny static init/launcher becomes clearly useful.

Kernel-grade work is allowed when it earns concrete enforcement. It should be
isolated behind provider/enforcer traits so the public product can ship useful
versions before every OS has maximum-strength enforcement.

## Adjacent Project Boundaries

Agentbox should stay focused on local runtime governance.

- **FIDES** owns authority, identities, signed policy bundles, signed approvals,
  delegation tokens, revocation, and verification.
- **agit** owns evidence lineage, workspace diffs, action history, and
  commit-linked provenance.
- **Aspendos** can be a high-value consumer: a general autonomous agent that
  should run inside Agentbox minipods instead of the raw host.
- **Switchboard** can coordinate multi-agent work, but Agentbox owns the local
  execution boundary.

## Success Criteria

A successful early product should be able to demonstrate this:

1. A local autonomous agent starts in an Agentbox minipod.
2. The agent can work inside the assigned task workspace.
3. Host home directories, browser profiles, SSH keys, cloud credentials, and
   sensitive env files are not visible by default.
4. Network egress is governed.
5. Git push, deploy, database mutation, credential access, and destructive host
   file operations require approval or are blocked.
6. The user can inspect what happened afterward.
7. The session can export evidence for FIDES/agit-compatible verification.

The v0 product does not need to be impossible to bypass. It does need to be
honest, useful, and visibly safer than running an agent directly on the host.
