# Agentbox Product Checkpoint Audit

This checkpoint captures the product as implemented in this repository, not the
full AgentPod vision. It should be updated after large sprint waves so roadmap
language does not outrun runnable behavior.

## Current Product Shape

Agentbox is now a governed AgentPod runtime surface with multiple provider
levels:

```text
agent command
  -> AgentPod manifest / run plan
  -> provider selection
  -> policy, approval, credential, network, workspace boundaries
  -> runtime session
  -> evidence bundle / receipt / replay
```

The direct-host path is the strongest generally runnable local path on macOS
today. Linux native execution is a gated prototype on Linux hosts. macOS,
Windows, remote, and Podman provider surfaces are useful, but their support
levels differ and must stay explicit.

## Runnable Today

| Surface | Status | Proof command |
| --- | --- | --- |
| Direct host governed command execution | Shipped | `agentbox run --provider direct-host --risk low --json -- echo ok` |
| Direct host policy, approval, credential, audit, and evidence path | Shipped | `cargo test -p agentbox-daemon` |
| Provider truth and bridge health reports | Shipped | `agentbox providers --json`, `agentbox bridge-health --json`, `agentbox provider-gaps --json` |
| Run-plan preview without execution | Shipped | `agentbox run --plan --json -- <cmd>` |
| Session evidence bundle and AgentPod native receipt rendering | Shipped | `agentbox evidence --session <id> --bundle <dir>`, `agentbox evidence --session <id> --agentpod-receipt` |
| Remote worker contract over gated loopback or HTTPS endpoint | Experimental gated | `AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 scripts/smoke-remote-worker.sh` |
| Podman compatibility provider | Experimental | `AGENTBOX_LIVE_PODMAN=1 scripts/smoke-podman-bridge.sh` on hosts with Podman |

## Prototype Primitives

| Provider | Prototype behavior | Gate |
| --- | --- | --- |
| `agentpod-linux` | rootless namespace wrapper, mount namespace plan, PID namespace plan, no-new-privs, cgroups v2 planning/apply, write-oriented Landlock loader, targeted seccomp deny loader, overlayfs review workspace apply, native runner phase evidence | `AGENTBOX_LINUX_NATIVE=1` on Linux |
| `remote-agentpod` | typed worker handshake/create/exec/destroy, workspace bundle handoff/export/apply, env/file credential handoff, command policy, approval-grant resolution, evidence upload/stream/status, lifecycle event journal, restart/status contract | HTTPS endpoint, or loopback HTTP only with `AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1` |
| `agentpod-macos` | native plan compiler, VM cell storage layout, VM runner request contract, gated runner invocation that currently returns an honest unavailable result | `AGENTBOX_MACOS_NATIVE=1` |

Prototype means the surface has code and tests, but it is not yet a full
sandbox or release-grade isolation claim.

## Descriptor-Only Or Metadata-Only

| Provider | Descriptor surface | Current limit |
| --- | --- | --- |
| `agentpod-macos` | Apple Virtualization, Endpoint Security, Network Extension, VM evidence observer plan | no VM boot lifecycle, no signed system extension, no live ES/NE denial proof |
| `agentpod-windows` | Job Objects, AppContainer, WFP, ETW, Windows Sandbox, Hyper-V, Windows native receipt descriptor | no live Windows apply proof, no WFP denial proof, no Sandbox/Hyper-V lifecycle |
| FIDES / AGIT / OAPS integrations | evidence and authority descriptors | no external authority adapter or live publisher configured |
| Linux eBPF / nftables | observability and egress policy descriptors | no probe loading, no packet/domain enforcement proof |

Descriptor-only means the product can explain the boundary and emit typed
metadata, but it must not imply enforcement.

## Known Skips

- Linux live native smoke skips outside Linux or without native prerequisites.
- Podman smoke skips unless Podman and a runnable machine are available.
- Remote worker loopback HTTP is development-only and requires an explicit gate.
- macOS and Windows native providers intentionally remain unavailable without
  platform lifecycle proof.
- Release signing is still an explicit unsigned placeholder.

## Operator Commands

Use these commands to inspect the actual product boundary before making claims:

```sh
cargo fmt --check
cargo test -p agentbox-cli
cargo test -p agentbox-daemon
bash scripts/smoke-cli-contracts.sh
bash scripts/smoke-remote-worker.sh
cargo run -p agentbox-cli -- providers --json
cargo run -p agentbox-cli -- provider-gaps --json
cargo run -p agentbox-cli -- bridge-health --json
```

Use platform/live gates only when the host supports them:

```sh
AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh
AGENTBOX_LIVE_PODMAN=1 bash scripts/smoke-podman-bridge.sh
```

## Next Product Work

The next valuable work is not broader roadmap language. It is closing proof
gaps:

1. macOS: boot a minimal Apple Virtualization VM cell, mount a workspace, and
   prove create/exec/destroy lifecycle with evidence.
2. Linux: strengthen seccomp/landlock coverage, add read/execute path policy,
   and turn nftables from descriptor into a live denial gate.
3. Windows: add live Job Object process cleanup proof before claiming execution.
4. Remote: add richer worker-side approval UX and full event streaming without
   weakening current credential restrictions.
5. Installer UX: turn provider gap reports and bridge health into guided setup
   output for first-run operators.

## Claim Boundary

Agentbox can currently claim governed local command execution, task-scoped
manifests, provider truth reporting, evidence bundles, remote worker contract
proof, and gated Linux native prototype execution.

It cannot yet claim complete VM replacement, bypass-proof host isolation, full
macOS or Windows native sandboxing, packet-level network enforcement, live FIDES
authority, live AGIT publication, or full credential isolation across arbitrary
processes.
