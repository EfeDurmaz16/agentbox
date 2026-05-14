# Agentbox Threat Model

Agentbox is a local governed runtime for autonomous agents. Its primary threat
is not a remote attacker breaking into a hardened server. The primary threat is
a useful local agent that has enough tool access to damage files, exfiltrate
credentials, mutate cloud accounts, deploy code, send messages, or touch
payment surfaces before the operator notices.

This document defines the current trust boundary and the target boundary. It is
intentionally conservative: if a surface is not enforced in code, it is marked
as planned or out of scope.

## Assets

- workspace source code and generated artifacts
- SSH keys, cloud credentials, package registry tokens, `.env` files, browser
  profiles, keychains, and local wallet material
- local databases and service state
- remote systems reachable through local CLIs such as `gh`, `aws`, `gcloud`,
  `az`, `kubectl`, `vercel`, `stripe`, and messaging tools
- audit and evidence records used to reconstruct what an agent did
- operator attention and approval decisions

## Trusted Computing Base

The current shipped control loop trusts:

- the Rust daemon process
- the Unix socket between shim and daemon
- the installed shim directory being first on `PATH`
- the policy classifier and local config
- ntfy delivery for out-of-band approval prompts
- SQLite for local audit storage
- the local operating system account running Agentbox

The experimental Podman compatibility path additionally trusts:

- Podman and the Podman machine or host container runtime
- the generated mount, label, and runtime session metadata
- the socket and shim injection into the compatibility minipod

Planned AgentPod providers will add platform-specific trusted components such
as Endpoint Security, Network Extension, Linux namespaces, cgroups, Landlock,
seccomp, eBPF, nftables, Windows Job Objects, AppContainer, WFP, and ETW.
Those are descriptor-only today unless a provider explicitly reports shipped
execution support.

## In-Scope Threats

- accidental or opportunistic destructive shell commands
- command-line access to sensitive credential paths
- remote mutation through GitHub, cloud, deploy, database, payment, or
  messaging CLIs
- unexpected network egress from tools such as `curl` and `wget`
- filesystem writes outside the configured workspace
- unsafe minipod manifests that try to inherit host env, use host networking,
  or mount protected host paths without explicit grants
- tampering with audit rows after decisions are recorded

## Current Controls

- allow, approve, and block policy buckets for intercepted commands
- deny-by-default minipod manifest fields for host env and host network mode
- protected path validation for generated minipod mounts
- redaction of credential-like material in audit and evidence output
- hash-chained audit events for tamper detection
- provider status reporting that separates shipped, experimental, unavailable,
  and planned surfaces

## Known Bypass Classes

The current direct-host shim path is useful, but it is not bypass-proof.
Known bypass classes include:

- invoking tools by absolute path outside the shim directory
- direct syscalls from a process that never invokes a shimmed command
- scripts, interpreters, or binaries that perform sensitive work internally
- network, browser, keychain, or file access through APIs not mediated by the
  current daemon
- a compromised local user account modifying config, shims, DB files, or the
  daemon process
- intentionally mounted host paths inside the experimental Podman compatibility
  path

These are exactly why AgentPod native providers exist in the roadmap. Until the
native provider enforces host process, filesystem, network, and credential
events, Agentbox should be described as governed and evidence-producing, not as
kernel-bypass-proof isolation.

## Out of Scope Today

- defending against a malicious local administrator
- defending against kernel compromise
- proving full browser profile isolation
- proving full keychain or wallet isolation
- proving macOS Endpoint Security enforcement before the system extension ships
- proving Linux namespace, cgroup, Landlock, seccomp, eBPF, or nftables
  enforcement before the Linux provider ships
- proving Windows Job Object, AppContainer, WFP, or ETW enforcement before the
  Windows provider ships

## Security Posture

Agentbox should fail closed for high-risk actions whenever the daemon or policy
surface has enough context to classify the action. It may fail open only for
explicitly low-risk local commands or for compatibility paths that are clearly
documented as best-effort.

Every new provider must satisfy this rule before it is marked available:

1. The provider reports its actual capabilities.
2. Unsupported execution paths return unavailable instead of pretending to run.
3. Sensitive host access requires a policy decision or explicit grant.
4. Evidence records are produced for allowed, approved, denied, and failed
   boundary crossings.
5. Live tests skip honestly when required OS support or credentials are absent.
