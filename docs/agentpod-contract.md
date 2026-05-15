# AgentPod Contract

Agentbox creates governed execution cells for agents that need to touch files,
run commands, use credentials, reach networks, or interact with local and
remote systems.

An AgentPod is not a Docker wrapper and it is not a VM brand. It is the stable
contract around an agent task. The provider underneath may be a guarded host
process, a native OS sandbox, a container-like runtime, a VM-backed cell, or a
remote worker. The contract remains the same.

```text
agent intent
  -> AgentPod manifest
  -> adaptive execution provider
  -> governed host bridge
  -> policy / approval / credential / network boundary
  -> evidence bundle
  -> reviewable output
```

## Product Definition

Agentbox is an agent execution governance layer.

It runs AgentPods. Some AgentPods are light, some are native sandboxes, some are
VM-backed, and some may be remote. The runtime choice is an implementation
decision based on risk, platform support, and task needs.

Agentbox should not be positioned as:

- a generic container manager
- a smaller VM manager
- a Podman/Docker frontend
- a coding-agent-only sandbox
- only phone approval for shell commands

The durable product surface is:

- filesystem boundary
- workspace write mode
- credential grants
- network policy
- host action approval
- sidecar readiness
- evidence and replay metadata
- provider truth reporting

## Execution Providers

AgentPod providers are allowed to use real isolation primitives. In fact, strong
AgentPods require them.

| Provider | Intended role | Final primitive |
|----------|---------------|-----------------|
| `direct-host` | Low-risk guarded process mode | PATH shims, daemon policy, approval, audit |
| `agentpod-macos` | macOS native/strong mode | Apple Virtualization.framework cell, Endpoint Security, Network Extension |
| `agentpod-linux` | Linux native mode | namespaces, no-new-privs, cgroups v2, overlayfs, seccomp, Landlock, nftables, optional eBPF |
| `agentpod-windows` | Windows native mode | Job Objects, AppContainer, restricted tokens, WFP, ETW, optional Hyper-V |
| `remote-agentpod` | Remote/disposable worker mode | same AgentPod contract over a remote bridge |
| `podman-compat` | Compatibility and smoke backend | Podman containers; not the product center |

Provider status must stay honest:

- `shipped`: runnable lifecycle behavior exists and is tested
- `experimental`: runnable but not fully proven or hardened
- `prototype primitive`: isolated building blocks exist, but no provider
  lifecycle claim is made
- `descriptor only`: metadata exists, execution returns unavailable
- `planned`: product direction only

`agentpod-linux` now has a composed native execution plan in code. The plan
combines rootless user namespace, mount namespace metadata, PID namespace,
cgroup v2 resource writes, seccomp profile metadata, and Landlock ruleset
metadata into one object. The gated executor also sets `PR_SET_NO_NEW_PRIVS`
before exec and can install a prototype BPF seccomp filter for supported
syscall deny rules and a prototype write-oriented Landlock path-beneath
filesystem ruleset. The Landlock loader currently handles write/create/remove
access only so launcher binaries, dynamic loaders, and host libraries are not
accidentally blocked before the real post-launch runner boundary exists. The
executor currently maps the guest workspace working directory to the host
workspace path; bind-mount setup inside the mount namespace is explicitly not
wired yet. The Linux native plan exposes ordered `runner_phases` so the
namespace, workspace bind, Landlock, seccomp, and exec stages can be reviewed
separately; today `bind-workspace` remains `planned` while Landlock/seccomp are
prototype phases. The `agentbox-linux-runner` helper binary is present as the
future unshare-internal runner for workspace bind mounts, post-setup kernel
policy application, and final argv exec. This is still a prototype primitive: live execution must be
explicitly gated with `AGENTBOX_LINUX_NATIVE`, and it is not a complete sandbox
claim until the remaining loaders and provider lifecycle are wired and tested on
Linux.

The plan can be inspected without execution:

```sh
agentbox native-plan --provider agentpod-linux -- /bin/true
agentbox native-plan --provider agentpod-macos -- /bin/true
```

Task manifests can also enable the prototype seccomp path directly from the CLI:

```sh
agentbox run --provider agentpod-linux --deny-syscall kill --max-processes 64 --plan -- /bin/true
agentbox minipod-spec hermes --provider agentpod-linux --deny-syscall kill --max-processes 64
agentbox native-plan --provider agentpod-linux --deny-syscall kill --max-processes 64 -- /bin/true
```

The macOS plan compiler emits the VM cell, host bridge, Endpoint Security,
Network Extension, entitlement, and evidence shape. It remains a plan compiler:
provider execution is still unavailable until the Apple Virtualization runner,
signed system extension, Network Extension lifecycle, and live enforcement tests
exist.

The Rust daemon also contains a prototype Linux executor function for that plan.
It refuses to run unless `AGENTBOX_LINUX_NATIVE=1` is set on a Linux host, and
tests keep the non-Linux path unavailable. With that gate enabled on Linux,
`agentbox run --provider agentpod-linux -- <cmd>` can use the prototype provider
lifecycle. Without the gate, the command exits with this boundary instead of
silently falling back to Podman or pretending the native provider is ready.

Linux live verification is intentionally separate from the default macOS test
suite:

```sh
scripts/smoke-linux-native.sh
```

The smoke script requires Linux, `unshare`, and `jq`; it enables
`AGENTBOX_LINUX_NATIVE=1` only for the gated run.

## Adaptive Runtime Selection

Agentbox should choose or recommend a provider by task risk.

| Risk | Example | Default provider shape |
|------|---------|------------------------|
| Low | read repo, run tests, format code | direct guarded process or native lightweight sandbox |
| Medium | edit workspace, install packages, call public APIs | native/container-like AgentPod with overlay review |
| High | browser/computer-use, cloud CLI, database, deploy, git push | VM-backed AgentPod with explicit grants |
| Very high | untrusted tools, malware-like workloads, production secrets | disposable VM or remote AgentPod |

This is why Agentbox should not ask "which kind of agent?" first. The important
question is what the agent can touch and what damage it can cause.

## Workspace Modes

Every AgentPod declares how writes work.

| Mode | Meaning | Use case |
|------|---------|----------|
| `direct` | Agent writes directly to the host workspace | fast low-risk local loops |
| `overlay-review` | Host workspace is the lower layer; agent writes to reviewable overlay | default for autonomous work |
| `ephemeral` | Writes disappear unless explicitly exported | research, browser, risky experiments |
| `commit-gated` | Output becomes a patch or commit only after review | AGIT/Git lineage workflows |

The default long-term mode should be `overlay-review`. Direct writes are useful,
but they are not the safety default for autonomous agents.

## Filesystem Boundary

An AgentPod manifest declares:

- workspace root
- workspace write mode
- read-only mounts
- credential mounts
- service data mounts
- protected host paths
- host bridge paths

Protected paths include SSH keys, cloud credentials, browser profiles, keychain
material, home-level config directories, and operator-selected private paths.

Protected paths must not be writable. Reading protected paths requires an
explicit grant and should usually require approval.

## Credential Grants

AgentPods should not inherit the host environment by default.

Credential access is explicit:

```text
grant env:OPENAI_API_KEY
grant file:./tokens/openai.task
grant aws-profile:dev
grant keychain:github-token
```

Each grant can carry:

- scope
- expiry
- one-time use
- approval requirement
- redaction policy
- revocation evidence

Agentbox may integrate with Keychain, 1Password, Bitwarden, FIDES, or cloud
identity systems later. The core contract remains brokered grants, not ambient
host credential inheritance.

## Network Policy

The default network posture should be usable, not paralyzing.

Agentbox should support:

- `none`
- `deny-by-default`
- `allowlisted`
- `first-contact`
- `open-with-guardrails`

For general local use, `open-with-guardrails` is practical:

- public internet is allowed unless policy says otherwise
- cloud metadata endpoints are blocked
- private/LAN IP destinations require explicit mediation
- localhost access is controlled
- unknown high-risk destinations can trigger approval
- databases, cloud admin APIs, deploy endpoints, and payment endpoints can be
  governed separately

Provider status must distinguish:

- classified
- observed
- provider network mode
- packet/domain enforced

## Host Bridge

AgentPods should talk to the host through a governed bridge, not by mounting
all host state.

The bridge handles:

- command mediation
- file grants
- credential grants
- network first-contact events
- approvals
- sidecar readiness
- evidence append
- workspace diff snapshots
- kill switch

The bridge is part of the AgentPod contract. Its implementation can be a Unix
socket, named pipe, VM channel, vsock, or remote tunnel depending on provider.

## Approval Model

Policy decisions use three buckets:

- `allow`: run without interruption
- `approve`: ask the operator
- `block`: deny immediately

Approval is not the product by itself. It is one control surface inside the
AgentPod runtime. Approvals should be available through CLI first, then TUI or
menubar if that improves operator ergonomics.

## Evidence Bundle

Every meaningful AgentPod session should be able to export:

```text
agentbox-evidence/
  manifest.json
  policy.json
  approvals.jsonl
  commands.jsonl
  network.jsonl
  filesystem.jsonl
  credentials.jsonl
  workspace-diff.patch
  transcripts/
  hashes.json
```

Evidence must be tamper-evident where practical. External systems such as FIDES
or AGIT can attach authority, signatures, or lineage later, but Agentbox must
not claim those integrations unless adapters are configured.

## What Complete Looks Like

A complete Agentbox run should look like this:

```sh
agentbox setup
agentbox doctor
agentbox run codex --repo ~/repo --workspace-mode overlay-review --network open-with-guardrails
```

Expected behavior:

- an AgentPod provider is selected based on risk and platform support
- the agent starts inside a governed execution cell
- host workspace writes go to the declared workspace mode
- `git commit` can be allowed
- `git push` can require approval
- `rm -rf /` is blocked
- metadata endpoints are blocked
- selected credentials require explicit grants
- sidecars report readiness before the agent runs
- the run produces evidence
- output can be reviewed, applied, committed, or discarded

## Current Implementation Alignment

The repository already has parts of this contract:

- direct-host shim governance
- policy classifier
- out-of-band approval
- SQLite audit and hash-chain evidence
- minipod manifest model
- provider registry
- workspace overlay policy model
- credential grant model
- network modes and denied domains
- sidecar readiness metadata
- Podman compatibility harness
- native provider descriptors and prototype primitives

The current gap is provider execution. The product direction is now clear:
Agentbox owns AgentPods; Podman is only one compatibility provider.
