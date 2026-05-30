# Provider Truth Contract

Agentbox provider metadata is a product contract, not marketing copy. A
provider can appear in CLI output before it is production-ready, but every
surface must use the same status language and must separate metadata from
active enforcement.

These terms mirror `ProviderImplementationStatus` in the daemon.

| Term | Meaning | Release rule |
|------|---------|--------------|
| `shipped` | Implemented, tested, available without hidden gates, and covered by normal release verification. | May be described as available in public docs. |
| `experimental` | Runnable behind explicit setup or environment gates, with useful tests, but not hardened enough for broad production claims. | May be demoed only with its gate and live-test boundary stated. |
| `prototype primitive` | A real primitive exists, such as a plan compiler, loader, or gated smoke, but it does not compose into a complete provider boundary yet. | May be described as a building block, not as provider isolation. |
| `descriptor only` | Typed metadata or a plan exists, but provider execution intentionally returns unavailable. | Must not be presented as runnable support. |
| `planned` | Design direction only. No runnable implementation or enforcement proof exists. | Must remain roadmap language. |
| `unavailable` | The provider or primitive is not usable on this host or without a required gate. | CLI output must include the missing gate or next diagnostic command. |

## Boundary Primitive Rules

Provider-level status is not enough for AgentPod claims. Each boundary
primitive must also report:

- `active`: whether this primitive is actually in force for the current host
  and configuration
- `requires_gate`: the exact env var, entitlement, service, or setup condition
  needed before it can run
- `enforcement_scope`: what the primitive enforces and what it does not enforce

Planned primitives and descriptor metadata are useful for operators and
installers, but they are never enforcement by themselves.

## Current Provider Truth

| Provider | Current status | Truth boundary |
|----------|----------------|----------------|
| `direct-host` | `shipped` | Useful command mediation, approval, audit, and evidence. Weak isolation; no OS sandbox. |
| `podman-compat` | `experimental` | Compatibility backend. Useful when live smoke passes on the target host; not the AgentPod product center. Legacy `podman` remains a deprecated CLI alias. |
| `agentpod-linux` | `prototype primitive` | Gated native prototype primitives exist. Do not claim complete sandboxing until live denial, cleanup, and evidence gates pass. |
| `agentpod-macos` | `descriptor only` plus gated runner contract | VM, Endpoint Security, and Network Extension shapes exist, but execution remains unavailable until lifecycle and entitlement proof exists. |
| `agentpod-windows` | `prototype primitive` / descriptor surfaces | Job Object, AppContainer, WFP, ETW, and VM-boundary descriptors exist. Provider execution remains unavailable until Windows live tests pass. |
| `remote-agentpod` | `experimental` | Runnable only with an explicit HTTPS worker endpoint or gated loopback dev transport. Trust depends on worker identity, capability reporting, and returned evidence. |

## Claim Gate

Before moving any provider or primitive upward:

1. Code must enforce the behavior, not only describe it.
2. Tests or smoke scripts must fail when the claimed behavior is absent.
3. CLI JSON must expose status, active flag, gate, and scope.
4. Docs must link the proof command and keep unsupported behavior explicit.
5. Skipped live tests must remain skips, not passes.
