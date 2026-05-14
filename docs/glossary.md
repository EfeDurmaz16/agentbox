# Agentbox Glossary

This glossary defines the product vocabulary used across Agentbox docs, issues,
and provider code.

## Agent

An autonomous or semi-autonomous program that can execute tools, commands,
browser actions, API calls, or workflow steps on behalf of a user.

Agentbox is not coding-agent-only. Codex, Claude Code, OpenClaw,
Hermes-style computer-use agents, DevOps agents, personal workflow agents, and
Aspendos-style systems are all valid target agents.

## AgentPod

The product-level execution cell for an agent task. An AgentPod is the governed
local runtime boundary that turns a raw host process into a session with
declared filesystem, network, credential, process, policy, approval, and
evidence semantics.

AgentPod is not synonymous with Podman, Docker, VM, or sandbox. Those can be
provider implementations, but the AgentPod contract is Agentbox-owned.

## Minipod

A small, task-scoped AgentPod instance. A minipod should be fast to create,
cheap to keep around, and narrow in state.

A minipod has:

- one task or agent role
- one workspace boundary
- explicit mounts and credential grants
- explicit network policy
- provider metadata
- evidence and lifecycle records

## Boundary

A declared limit around what an agent can read, write, reach, execute, or
mutate.

Common boundaries:

- filesystem
- credential
- network
- process tree
- host action
- approval
- evidence

Boundaries can be classified, observed, provider-mode, or enforced. The docs
must say which one is true.

## Policy

Rules that decide whether an action is allowed, requires approval, or is
blocked.

Policy may come from:

- conservative built-in defaults
- local config
- minipod manifests
- task policy bundles
- session-scoped approval grants
- future FIDES authority decisions

Policy is not the same as enforcement. Enforcement depends on the provider and
platform primitive that can actually stop an action.

## Approval

An operator decision that allows a specific risky action, scope, or session
behavior.

Approvals should be:

- scoped
- recorded
- expirable where possible
- non-bypassable for block-bucket actions
- linked to evidence

Out-of-band approval is one control plane inside Agentbox. It is not the whole
product.

## Authority

The entity or system that is allowed to grant, deny, sign, revoke, or verify an
agent's permission to act.

Agentbox owns local runtime governance. FIDES is the intended authority layer
for signed policies, signed approvals, delegation tokens, revocation, and
verification.

## Evidence

The durable record of what happened during a session.

Evidence can include:

- audit events
- policy decisions
- approvals
- denied actions
- credential revocation events
- command transcripts
- workspace diffs
- network boundary events
- replay metadata
- future FIDES and agit references

Evidence should be redacted where necessary and hash-chained where possible.

## Provider

The runtime backend that maps the AgentPod contract onto a platform.

Examples:

- direct host with shims
- Podman compatibility minipods
- macOS AgentPod
- Linux AgentPod
- Windows AgentPod

Providers must be honest about capabilities. Descriptor-only providers return
unavailable for execution.

## Host Bridge

An intentional connection between a minipod and the host.

Examples:

- Agentbox daemon socket
- injected shim directory
- credential file mount
- service sidecar socket
- future browser/keychain/cloud mediation channel

Host bridges are high-risk. They should be explicit, typed, audited, and added
by the provider rather than by arbitrary user mounts.

## Compatibility Backend

A backend used to make early minipod flows runnable before native AgentPod
providers are complete.

Podman is the current compatibility backend. It is useful, but it is not the
long-term architecture.

## Native Provider

A provider that uses the operating system's own primitives rather than treating
all platforms like generic containers.

Examples:

- macOS: Apple Virtualization, Endpoint Security, Network Extension
- Linux: namespaces, cgroups v2, seccomp, Landlock, nftables, eBPF
- Windows: Job Objects, AppContainer, WFP, ETW, Windows Sandbox, Hyper-V

## Descriptor Only

A provider state where Agentbox exposes metadata and planned capabilities but
intentionally returns unavailable for execution.

Descriptor-only means direction is visible, not shipped enforcement.

## Live Proof

A verification run on a host that has the relevant runtime or OS primitive.

Live proof must fail when the dependency exists but behavior is wrong. A skipped
live test is not proof.
