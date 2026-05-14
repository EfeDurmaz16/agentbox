# Platform Isolation Strategy

Agentbox is not a VM manager with an agent label. It is a governed local runtime
for agent work. The runtime can use containers, VMs, or OS-native controls, but
the product boundary is the same on every platform:

```text
agent task
  -> minipod manifest
  -> runtime provider
  -> policy and approval
  -> evidence
```

## Support Levels

| Level | Meaning |
|-------|---------|
| Shipped | Implemented, tested, and available in the current repo. |
| Experimental | Runnable, but missing full live proof or production hardening. |
| Descriptor only | Named in provider metadata, but execution intentionally returns unavailable. |
| Planned | Design direction only. |

## Direct Host

Status: shipped.

Direct-host mode uses PATH shims, a local daemon, policy classification,
out-of-band approval, and audit/evidence. It is the strongest validated path in
the repo today because it actually runs and is covered by tests.

What it is good for:

- governing common shell commands used by coding and DevOps agents
- adding approval checkpoints for destructive or externally visible actions
- recording local evidence for decisions

What it does not isolate:

- direct syscalls
- absolute-path invocations that bypass shims
- browser, keychain, or network APIs that do not route through a shim
- malicious local users with control of the same account

## Podman Compatibility

Status: experimental.

Podman gives Agentbox a runnable compatibility backend while native AgentPod
providers are built. It is useful for early minipod flows, sidecars, workspace
mounting, resource limits, and daemon/shim injection. It is not the long-term
architecture.

The Podman path should become credible only when live smoke tests prove:

- the minipod starts on the target host
- the daemon socket is mounted as intended
- injected shims are first on `PATH`
- selected commands inside the minipod hit the host policy daemon
- lifecycle cleanup removes the session
- evidence export records the run

## macOS AgentPod

Status: descriptor only.

The macOS provider should combine three surfaces:

- Apple Virtualization for local Linux cells when a VM boundary is useful
- Endpoint Security for host process and filesystem authorization
- Network Extension for egress governance

Until the system extension and entitlement flow exist, `agentpod-macos` must
remain unavailable for execution.

## Linux AgentPod

Status: descriptor only.

The Linux provider should be the first place to pursue a smaller, efficient
AgentPod because the platform has strong local primitives:

- user, mount, PID, IPC, UTS, and network namespaces
- cgroups v2 for resource control
- overlayfs or equivalent workspace layering
- seccomp for syscall filtering
- Landlock for unprivileged filesystem constraints
- nftables or eBPF for network visibility and enforcement

The near-term goal is not to recreate Docker. The goal is a narrow agent-task
runtime with explicit filesystem, network, credential, process, approval, and
evidence semantics.

## Windows AgentPod

Status: descriptor only.

The Windows provider should use:

- Job Objects for process tree and resource control
- AppContainer or related sandboxing for app-style isolation
- Windows Filtering Platform for network governance
- ETW for evidence and observability

Windows support should not be marked available until process containment,
credential boundary behavior, and evidence events are tested on Windows CI or a
documented live host.

## Provider Rule

Every provider must be honest:

- report only capabilities it actually supports
- return unavailable for unsupported execution
- keep live tests separate from unit tests
- skip live tests only when the host dependency is absent
- fail live tests when the dependency is present but behavior is wrong
