# Agentbox Status Matrix

This file separates what is shipped in this repository from what is still
experimental or planned. Agentbox is moving from command interception into a
governed local minipod runtime for autonomous agents, but not every boundary is
implemented yet.

## Product Surface

| Surface | Status | Current proof |
|---------|--------|---------------|
| PATH shim interception | Shipped | `agentbox-shim` forwards command context to the daemon over a Unix socket. |
| Policy classifier | Shipped | `agentbox-policy` classifies allow, approve, and block decisions with workspace and config input. |
| Out-of-band approval | Shipped | The daemon can send ntfy approvals and waits for approve, deny, or timeout. |
| SQLite audit log | Shipped | The daemon records command, cwd, bucket, decision, parent process, and timing. |
| Hash-chained evidence | Shipped | New audit rows include `schema_version`, `prev_hash`, and `event_hash`. |
| Evidence export | Shipped | `agentbox evidence --limit N` exports audit rows as JSONL. |
| Doctor command | Shipped | `agentbox doctor` reports daemon, shim, audit, PATH, and provider readiness. |
| Minipod manifest model | Shipped | `MinipodSpec` models filesystem, network, credentials, resources, services, labels, agent profile, approvals, and task policy bundles. |
| Manifest policy validation | Shipped | Unsafe host env inheritance, host network mode, and protected mounts are rejected before provider create. |
| One-time credential file grants | Shipped | `--credential-file` creates read-only credential mounts and one-time file grants; provider mount metadata distinguishes them from ordinary read-only host mounts. |
| Credential revocation evidence | Shipped | Destroying a runtime session records hash-chained credential revocation audit events for one-time grants. |
| Per-agent policy profiles | Shipped | `general`, `coding`, `research`, `deploy`, and custom profile ids can set policy defaults without hardcoding specific agent products. |
| Runtime session store | Shipped | Runtime sessions persist to a local JSON store. |
| Runtime manager | Shipped | Provider create, exec, status refresh, destroy, session persistence, and evidence events share one daemon-owned manager. |
| Session-scoped approval grants | Shipped | Runtime sessions can carry approval grants that are persisted with the session and removed when the session is destroyed. |
| Approval scope enforcement | Shipped | Runtime manager exec enforces once, command, path, domain, and session approval grants for approve-bucket commands. Expired grants are ignored and block-bucket commands cannot be grant-bypassed. |
| Signed approval model | Shipped | Approval grants can be represented as signed approval records with evidence refs and optional FIDES-style signatures; no fake signing provider is shipped. |
| First-contact network mode | Shipped | `ApprovalOnFirstContact` is a first-class minipod network mode exposed through `--network-mode first-contact`. |
| Network denylist | Shipped | Minipod network policy and daemon policy config carry denied domains; denied network destinations are blocked before allowlists or approval grants. |
| Localhost service policy | Shipped | Minipod manifests model localhost/loopback access and `--deny-localhost` makes runtime exec policy block loopback HTTP commands. |
| Network boundary evidence | Shipped | Runtime exec records network-specific audit events for allowed, blocked, and approval-required HTTP boundary decisions. |
| Workspace diff snapshots | Shipped | Runtime sessions can capture Git workspace diff snapshots and record hash-chained workspace evidence without claiming AGIT commit creation. |
| Command transcript export | Shipped | Runtime exec stores redacted stdout/stderr transcripts in the session evidence bundle with size metadata and truncation limits. |
| Session replay metadata | Shipped | Session evidence bundles include ordered replay metadata with audit ids, hash links, policy buckets, decisions, and explicit metadata-only limitations. |
| Minipod manifest CLI | Shipped | `agentbox minipod-spec` generates and validates a deny-by-default manifest, including `--policy-bundle` task policy JSON files. |
| Runtime provider registry | Shipped | `RuntimeProviderRegistry` can resolve AgentPod provider descriptors and compatibility providers. |
| Runtime provider listing | Shipped | `agentbox providers` reports shipped, experimental, unavailable, and planned provider surfaces. |
| Network enforcement capability flags | Shipped | Runtime providers separately report active network enforcement strength, so planned policy support is not confused with packet/domain enforcement. |
| AgentPod provider descriptors | Shipped | `agentpod-macos`, `agentpod-linux`, and `agentpod-windows` expose capability metadata while returning unavailable for execution. |
| Podman compatibility adapter | Shipped | `agentbox run` now routes through `RuntimeManager` and the Podman `RuntimeProvider` adapter, creating governed runtime sessions and evidence events. |

## Runtime Backends

| Backend | Status | Notes |
|---------|--------|-------|
| Direct host with shims | Shipped | Strongest validated path today. It governs host-impacting shell commands but does not isolate all process behavior. |
| AgentPod macOS | Descriptor only | Candidate surfaces include Apple Virtualization for local cells, Endpoint Security for host-event enforcement, and Network Extension for egress governance. Execution intentionally returns unavailable. See [Endpoint Security design](macos-endpoint-security.md) and [system extension scaffold](macos-system-extension-scaffold.md). |
| AgentPod Linux | Prototype primitives | Candidate surfaces include namespaces, cgroups, Landlock, seccomp, eBPF, nftables, and overlayfs. Linux-only user, mount, PID namespace, and cgroups v2 primitives exist, but provider execution intentionally remains unavailable until the full boundary is wired and verified. |
| AgentPod Windows | Descriptor only | Candidate surfaces include Job Objects, AppContainer, WFP, ETW, and Windows sandbox primitives. Execution intentionally returns unavailable. |
| Podman compatibility minipods | Experimental | `agentbox run` uses the daemon-owned runtime manager path. `agentbox pods` and `agentbox stop-pod` still use the older Podman CLI path, and live socket/shim smoke proof remains open. |

## Ecosystem Integrations

| Surface | Status | Notes |
|---------|--------|-------|
| FIDES credential authority hook | Shipped | Agentbox exposes a FIDES-compatible credential authority request/decision skeleton without hard dependency on the FIDES runtime. The default hook requires external authority and does not fake approval. |
| agit evidence lineage | Shipped skeleton | Agentbox can map runtime audit events into AGIT-style lineage records with optional commit and workspace diff refs. The default publisher requires an external AGIT adapter and does not claim live integration. |
| Switchboard coordination | Planned | Switchboard can coordinate multiple agents, while Agentbox owns each local runtime boundary. No direct integration is shipped yet. |
| Aspendos consumer path | Planned | Aspendos-style general agents are target consumers for governed minipods. No bundled Aspendos runtime integration is shipped yet. |

## Current Direction

Agentbox is not trying to be a smaller VM manager. The target product is:

```text
agent intent
  -> governed minipod manifest
  -> local runtime provider
  -> filesystem / network / credential / process boundaries
  -> policy and approval decisions
  -> tamper-evident evidence
```

Podman is allowed to remain a compatibility backend, but AgentPod providers are
the product direction and should become the real enforcement layer.

See [macOS minipod limitations](macos-minipod-limitations.md) for the current
VM-backed boundary and native enforcement gap.
See [safe file sharing](safe-file-sharing.md) for current workspace, read-only
mount, credential, and system bridge guidance.
See [threat model](threat-model.md), [platform isolation strategy](platform-isolation.md),
and [public limitations](limitations.md) for the current public boundary.
