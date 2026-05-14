# Agentbox Status Matrix

This file separates what is shipped in this repository from what is still
experimental or planned. Agentbox is moving from command interception into the
AgentPod contract: adaptive governed execution cells for autonomous agents.
Not every provider boundary is implemented yet.

## Product Surface

| Surface | Status | Current proof |
|---------|--------|---------------|
| PATH shim interception | Shipped | `agentbox-shim` forwards command context to the daemon over a Unix socket. |
| Policy classifier | Shipped | `agentbox-policy` classifies allow, approve, and block decisions with workspace and config input. |
| Out-of-band approval | Shipped | The daemon can send ntfy approvals and waits for approve, deny, or timeout. |
| SQLite audit log | Shipped | The daemon records command, cwd, bucket, decision, parent process, and timing. |
| Hash-chained evidence | Shipped | New audit rows include `schema_version`, `prev_hash`, and `event_hash`. |
| Evidence export | Shipped | `agentbox evidence --limit N` exports audit rows as JSONL. `agentbox evidence --session <id> --bundle <dir>` writes a session evidence bundle directory with `index.json`, `bundle.json`, `manifest.json`, `replay.json`, and `transcripts.json`; `index.json` carries a deterministic `root_sha256`; `agentbox evidence --verify --bundle <dir>` verifies the root hash, file hashes, and byte counts without needing the original session store. |
| Doctor command | Shipped | `agentbox doctor` reports daemon, shim, audit, PATH, and provider readiness. |
| AgentPod manifest model | Shipped | `MinipodSpec` is now the compatibility type behind the AgentPod manifest surface. New manifests carry `schema_version`, `kind: AgentPod`, risk, workspace mode, filesystem, network, credentials, resources, services, labels, approvals, and task policy bundles. |
| Manifest policy validation | Shipped | Unsafe host env inheritance, host network mode, and protected mounts are rejected before provider create. |
| AgentPod workspace modes | Shipped partial | Manifests can declare `direct`, `overlay-review`, `ephemeral`, and `commit-gated` workspace modes. Non-direct modes allocate validated upper/work paths and can materialize a projected review workspace before provider create. Native overlayfs/provider mount wiring is still incomplete. |
| AgentPod risk model | Shipped model | Manifests carry `low`, `medium`, `high`, or `very-high` risk intent for provider selection and evidence. |
| One-time credential file grants | Shipped | `--credential-file` creates read-only credential mounts and one-time file grants; provider mount metadata distinguishes them from ordinary read-only host mounts. |
| Explicit credential env grants | Shipped partial | `--credential-env name=HOST_ENV` records an explicit env grant and runtime exec injects only that named host env value into the command environment. Missing host env targets deny execution, one-time env grants are consumed after exposure, and transcripts redact credential-like output. Socket and provider-token grants remain manifest/authority metadata until provider-mediated sources are implemented. |
| Credential grant expiry | Shipped | Credential grants can carry `expires_at`; `agentbox run` and `agentbox minipod-spec` expose `--credential-ttl-seconds`; expired grants are removed before list/exec, not injected, and recorded as credential revocation evidence. |
| Credential grant operator commands | Shipped partial | `agentbox credentials <session>` lists persisted non-expired session grants and `agentbox credential-revoke <session> <name>` removes a grant from the session manifest while recording credential revocation evidence. This does not yet rotate upstream provider credentials or revoke external tokens. |
| Credential revocation evidence | Shipped | Destroying a runtime session records hash-chained credential revocation audit events for one-time grants. |
| Per-agent policy profiles | Shipped | `general`, `coding`, `research`, `deploy`, and custom profile ids can set policy defaults without hardcoding specific agent products. |
| Runtime session store | Shipped | Runtime sessions persist to a local JSON store. |
| Runtime manager | Shipped | Provider create, exec, status refresh, destroy, session persistence, and evidence events share one daemon-owned manager. |
| Sidecar readiness metadata | Shipped | Minipod services can carry command-based readiness probes; the Podman compatibility path starts sidecars and waits for probes before starting the workspace agent container. |
| Session-scoped approval grants | Shipped | Runtime sessions can carry approval grants that are persisted with the session and removed when the session is destroyed. |
| Approval scope enforcement | Shipped | Runtime manager exec enforces once, command, path, domain, and session approval grants for approve-bucket commands. Expired grants are ignored and block-bucket commands cannot be grant-bypassed. |
| Signed approval model | Shipped | Approval grants can be represented as signed approval records with evidence refs and optional FIDES-style signatures; no fake signing provider is shipped. |
| First-contact network mode | Shipped | `ApprovalOnFirstContact` is a first-class minipod network mode exposed through `--network-mode first-contact`. |
| Open-with-guardrails network mode | Shipped command mediation | General AgentPod manifests default to usable internet with metadata endpoints denied. Runtime command mediation allows unknown HTTP in this mode while recording network boundary evidence; provider packet/domain enforcement is still reported separately. |
| Network denylist | Shipped | Minipod network policy and daemon policy config carry denied domains; denied network destinations are blocked before allowlists or approval grants. |
| Localhost service policy | Shipped | Minipod manifests model localhost/loopback access and `--deny-localhost` makes runtime exec policy block loopback HTTP commands. |
| Network boundary evidence | Shipped | Runtime exec records network-specific audit events for allowed, blocked, and approval-required HTTP boundary decisions. |
| Network evidence export | Shipped | `agentbox evidence --network` exports only network boundary audit events as JSONL while preserving hash links and redaction. |
| Network explain CLI | Shipped | `agentbox network-explain <url>` explains URL policy buckets for a selected network mode without making the request and states that it is command mediation, not packet filtering. |
| Session network grants | Shipped | `agentbox network-grant <session> <domain>` adds a session-scoped domain approval grant for first-contact style HTTP commands. Denylists still win before grants. |
| Workspace review/apply/discard | Shipped partial | Runtime sessions can capture Git workspace diff snapshots, export patches via `agentbox review --patch`, apply projected patches via `agentbox review-apply`, discard projected workspaces via `agentbox review-discard`, and create explicit lower-workspace commits via `agentbox review-commit`. These actions record workspace evidence; native overlayfs/provider mount wiring is still incomplete. |
| Command transcript export | Shipped | Runtime exec stores redacted stdout/stderr transcripts in the session evidence bundle with size metadata and truncation limits. |
| Session credential evidence | Shipped | Session evidence bundles include redacted credential grant summaries and credential audit events; `agentbox evidence --session <id> --credentials` exports just that credential evidence as JSONL. |
| Session replay metadata | Shipped | Session evidence bundles include ordered replay metadata with audit ids, hash links, policy buckets, decisions, and explicit metadata-only limitations. |
| Minipod manifest CLI | Shipped | `agentbox minipod-spec` generates and validates a deny-by-default manifest, including `--policy-bundle` task policy JSON files. |
| Run plan preview | Shipped | `agentbox run --plan` emits a JSON preview with selected provider metadata, selection reason, candidate providers, planned backend actions, warnings, network enforcement metadata, and the full AgentPod manifest. It does not start a backend, hydrate credentials, create sessions, or execute the command. |
| Run JSON output | Shipped partial | `agentbox run --json` emits machine-readable session/run output for automation and avoids the interactive cleanup prompt for command runs. Actual execution still depends on a runnable backend such as Podman compatibility or gated Linux native prototype execution. |
| Runtime provider registry | Shipped | `RuntimeProviderRegistry` can resolve AgentPod provider descriptors and compatibility providers, and can explain provider selection by risk and explicit provider hints. |
| Runtime provider listing | Shipped | `agentbox providers` reports family, platform, shipped/experimental/descriptor-only status, and network enforcement claims. `agentbox providers --json` exposes the same provider truth metadata for scripts and release checks. |
| Network enforcement capability flags | Shipped | Runtime providers separately report active network enforcement strength, so planned policy support is not confused with packet/domain enforcement. |
| AgentPod provider truth | Shipped | `agentpod-macos`, `agentpod-linux`, `agentpod-windows`, and `remote-agentpod` expose capability/status metadata. Linux reports prototype primitives; macOS and Windows remain descriptor-only; remote is experimental and only becomes available when `AGENTBOX_REMOTE_AGENTPOD_ENDPOINT` points at an HTTPS worker. |
| Podman compatibility adapter | Shipped | `agentbox run` now routes through `RuntimeManager` and the Podman `RuntimeProvider` adapter, creating governed runtime sessions and evidence events. |
| AgentPod lifecycle CLI | Shipped partial | `agentbox pods` lists persisted runtime sessions and `agentbox stop-pod` stops runtime sessions through `RuntimeManager` before falling back to legacy Podman ids. Stopped sessions are retained for review and evidence, while transient approval grants are cleared. Runtime manager now rejects exec against stopped sessions before credential hydration or provider dispatch. |

## Runtime Backends

| Backend | Status | Notes |
|---------|--------|-------|
| Direct host with shims | Shipped | Strongest validated path today. It governs host-impacting shell commands but does not isolate all process behavior. |
| AgentPod macOS | Descriptor only | Candidate surfaces include Apple Virtualization for local cells, Endpoint Security for host-event enforcement, and Network Extension for egress governance. Execution intentionally returns unavailable. See [Endpoint Security design](macos-endpoint-security.md) and [system extension scaffold](macos-system-extension-scaffold.md). |
| AgentPod Linux | Prototype runnable behind gate | Candidate surfaces include namespaces, cgroups, Landlock, seccomp, eBPF, nftables, and overlayfs. Linux-only user, mount, PID namespace, cgroups v2, seccomp, Landlock, isolation benchmark, eBPF observability, a composed native execution plan, and a gated prototype executor exist. `agentbox native-plan --provider agentpod-linux -- <cmd>` exposes the plan without execution. On Linux with `AGENTBOX_LINUX_NATIVE=1`, `agentbox run --provider agentpod-linux -- <cmd>` can use the prototype provider lifecycle, and `scripts/smoke-linux-native.sh` is the live gate. This is not a complete sandbox claim and network enforcement is not wired. |
| AgentPod Windows | Prototype primitives | Candidate surfaces include Job Objects, AppContainer, WFP, ETW, and Windows sandbox primitives. A Windows Job Object plan/controller exists with Windows-only apply behavior, but provider execution intentionally remains unavailable. See [Windows native provider](windows-native-provider.md). |
| Remote AgentPod | Experimental gated | The `remote-agentpod` descriptor models remote/disposable worker execution over a remote bridge. `agentbox remote-descriptor` emits a secret-free transport/auth/evidence/lifecycle descriptor, `agentbox remote-handshake` emits a secret-free signed-challenge descriptor, and `agentbox remote-evidence` emits validated evidence upload metadata without uploading it. `agentbox remote-evidence --bundle-dir <dir>` derives the upload hash and event count from a verified evidence bundle root and marks the request with bundle provenance metadata. The daemon also has an in-memory transport conformance contract plus an HTTPS adapter for handshake/create/exec/evidence/evidence-bundle/destroy response validation, including Ed25519 challenge signature verification, legacy canonical challenge binding, and required destroy-time `KillSwitchAck` when the kill switch is required. With `AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://...`, `RemoteAgentPodProvider` can handshake, create a session, persist worker metadata, execute direct argv commands, and destroy through a worker transport. `agentbox-remote-worker` is a contract worker binary that signs handshakes, responds to the expected worker routes, prepares the requested workspace during create-session, refuses credential grants until handoff exists, requires a created running worker session before exec, records evidence upload receipts with bundle provenance metadata for matching sessions, stores hash-verified evidence bundle JSON payloads when `--state-dir` is set, persists worker session snapshots when `--state-dir` is set, reloads persisted running sessions after worker restart, defaults exec to the session workspace, refuses explicit working directories outside that workspace, refuses command environment material until credential handoff exists, runs direct argv commands without a shell, and maps destroy to a running-command kill signal; `scripts/smoke-remote-worker.sh` proves loopback HTTP handshake, create, exec, evidence upload, hash-verified bundle payload storage, persisted receipt state, restart reload, and destroy-time kill behavior. Sandboxed remote execution, evidence streaming, credential handoff, and supervised worker restarts are not implemented. See [Remote AgentPod](remote-agentpod.md). |
| Podman compatibility minipods | Experimental | `agentbox run` uses the daemon-owned runtime manager path. `agentbox pods` lists persisted runtime sessions and `agentbox stop-pod` stops sessions through `RuntimeManager` before falling back to legacy Podman ids. Non-direct workspace modes can prepare projected review workspaces with review/apply/discard commands, but native provider overlayfs semantics are not complete. `scripts/smoke-podman-bridge.sh` remains the live gate for socket/shim bridge proof. The provider resolves Linux guest shim artifacts through `AGENTBOX_LINUX_SHIM`, `.linux` sidecar artifacts, or common Rust target paths, and rejects non-Linux shim binaries before injecting them into Linux containers. |

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

See [glossary](glossary.md) for the canonical meanings of AgentPod, minipod,
boundary, policy, authority, evidence, provider, and host bridge.
See [AgentPod contract](agentpod-contract.md) for the final product shape:
adaptive providers, workspace modes, credential grants, network policy, host
bridge, approval, and evidence.
See [Mac mini replacement wedge](mac-mini-replacement-wedge.md) for the local
software-boundary positioning and its limits.
See [250+ commit product sprint](roadmap-250-commits.md) for the current
execution queue that supersedes the original 100-issue planning cut.
See [release readiness](release-readiness.md) for the checklist before tagging
public builds.
See [installer packaging](installer-packaging.md) for the packaging path and the
rule against shipping unverified installers.
See [macOS minipod limitations](macos-minipod-limitations.md) for the current
VM-backed boundary and native enforcement gap.
See [safe file sharing](safe-file-sharing.md) for current workspace, read-only
mount, credential, and system bridge guidance.
See [safe credential patterns](safe-credential-patterns.md) for task-scoped
credential grants, redaction limits, and FIDES authority handoff.
See [Linux eBPF observability](linux-ebpf-observability.md) for kernel event
evidence design that is not yet enforcement.
See [network enforcement limits](network-enforcement-limits.md) for the
platform-specific line between classification, observation, provider network
mode, and packet/domain enforcement.
See [threat model](threat-model.md), [platform isolation strategy](platform-isolation.md),
and [public limitations](limitations.md) for the current public boundary.
