# macOS Endpoint Security Enforcement Design

Agentbox should not claim kernel-grade macOS enforcement until it has a signed
and entitled system extension. This document defines the target architecture for
`agentpod-macos` without pretending it is currently implemented.

## Goal

`agentpod-macos` should combine a local execution cell with host-event
enforcement:

```text
agent process
  -> AgentPod session policy
  -> Endpoint Security event stream
  -> Agentbox daemon decision
  -> allow / deny / require approval
  -> tamper-evident evidence
```

The system extension is not a replacement for the daemon. It is the privileged
sensor and enforcement point. The daemon remains the policy, approval, and
evidence control plane.

## Events To Cover First

The first useful slice should subscribe only to events that directly protect
the host from autonomous agents:

| Surface | Endpoint Security class | Agentbox decision |
|---------|-------------------------|-------------------|
| File read/write outside workspace | file open, create, rename, unlink | allow if workspace-scoped, approve or deny if protected |
| Process execution | exec | classify binary and argv |
| Script interpreter launch | exec | inspect interpreter plus script path |
| Sensitive credential access | file open | deny by default unless explicit grant |
| Shell escape from tool runtime | exec | preserve parent process and session id |

Network egress should be handled separately through Network Extension or a
provider-specific proxy. Endpoint Security is not the right primary API for
domain allowlists.

## Required Metadata

The extension must attach enough metadata for the daemon to make a deterministic
decision:

- AgentPod session id.
- audit token and pid.
- parent pid and executable path.
- executable path and argv where available.
- target file path.
- requested access mode.
- code-signing identity where available.
- current workspace root.
- policy bundle id or hash.

If the event cannot be mapped to an AgentPod session, the default should be
configurable but conservative. For early builds, unknown events should be
observed rather than denied globally to avoid bricking the host.

## Policy Flow

```text
ES event
  -> extension extracts stable event fields
  -> extension asks agentbox-daemon over a local privileged channel
  -> daemon evaluates session policy and approval grants
  -> daemon returns allow / deny / defer
  -> extension applies ES response
  -> daemon writes evidence event
```

The extension should not contain complex policy logic. It should enforce a
short timeout and fail closed only for events that are inside an active AgentPod
session and clearly protected by policy.

## Entitlements And Packaging

Endpoint Security requires Apple approval for the
`com.apple.developer.endpoint-security.client` entitlement. This means the
public open-source repo should keep the privileged target isolated:

- no entitlement placeholders that imply anyone can build enforcement locally;
- no test that requires the entitlement in normal CI;
- no fake fallback that reports enforcement as active;
- clear `agentbox doctor` output for entitlement missing, extension missing,
  extension installed, and extension active.

## Failure Modes

Agentbox must handle these explicitly:

- daemon unavailable while extension receives auth events;
- extension version newer/older than daemon protocol;
- event cannot be mapped to a session;
- approval request times out;
- user revokes extension permission;
- extension crash or restart;
- high event volume from package managers or build tools.

Every failure mode should produce an evidence event if the daemon is reachable.

## First Implementation Slice

The first code slice is a descriptor and protocol scaffold, not a privileged
extension:

1. Add `agentpod-macos` primitive descriptors for Endpoint Security and Network
   Extension.
2. Add a native plan compiler that emits Apple Virtualization, Endpoint
   Security, Network Extension, entitlement, host bridge, and evidence
   requirements without executing them.
3. Add a local event schema for file and exec authorization requests.
4. Add `agentbox doctor` rows for macOS entitlement/extension readiness.
5. Add tests that unknown macOS enforcement returns unavailable.

Only after that should a separate macOS system extension target be added.

## Current Event Schema

The daemon now models the future Endpoint Security authorization boundary in
code without installing a system extension:

- exec requests carry session id, ES event id, process subject, argv, target
  executable, requested execute access, and observation time.
- file requests carry session id, ES event id, process subject, target path,
  requested access such as read/write/delete, and observation time.
- decisions carry allow/approve/block, reason, optional evidence reference, and
  decision time.

This is protocol shape only. There is still no privileged ES client, no kernel
authorization callback, and no live allow/deny enforcement on macOS.
