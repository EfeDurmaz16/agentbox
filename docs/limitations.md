# Public Limitations and Bypass Boundaries

Agentbox is useful today, but it is not complete isolation. This document is the
public boundary for what Agentbox can and cannot currently claim.

## Direct-Host Shim Mode

Shipped direct-host mode governs commands that enter through Agentbox shims.
It can approve, block, and audit common shell actions.

Limitations:

- absolute paths can bypass PATH shims
- direct syscalls are not intercepted
- code running inside an interpreter can perform work without spawning a
  shimmed command
- browser, keychain, wallet, and cloud SDK APIs are not fully mediated
- a local user with access to the same account can alter config, DB files, or
  process state

Use this mode for command governance and evidence, not as a full sandbox.

## Podman Compatibility Minipods

Experimental Podman-backed minipods add a useful runtime cell around agent work.
They do not prove kernel-grade host enforcement.

Limitations:

- host paths intentionally mounted into the minipod remain reachable
- daemon socket and shim injection must be proven by live smoke tests on the
  target host
- container isolation does not govern every host bridge
- macOS Podman runs through a VM layer, so host enforcement and VM enforcement
  are different boundaries
- provider behavior may differ across macOS, Linux, and Windows hosts

Use this mode as a compatibility backend while AgentPod native providers mature.

## Native AgentPod Descriptors

`agentpod-macos`, `agentpod-linux`, and `agentpod-windows` currently describe
planned capability surfaces. They intentionally return unavailable for
execution.

Limitations:

- no native provider is shipped as an enforcement backend yet
- planned primitives do not imply active protection
- provider metadata is not a security boundary
- tests currently prove honest unavailability and metadata, not live kernel or
  OS enforcement

Use these descriptors to understand direction and plan integrations. Do not
market them as shipped isolation.

## Credential Boundaries

Agentbox now redacts credential-like material in audit and evidence output and
rejects unsafe minipod manifests such as host env inheritance. That is not the
same as complete secret isolation.

Limitations:

- redaction is pattern-based and can miss unusual secret formats
- existing external logs outside Agentbox are not scrubbed
- credential grants are still evolving
- browser profiles, keychains, wallets, and cloud SDK caches need provider-level
  mediation before they are safe for broad agent access

## Live-Test Policy

A skipped live test is not a pass. Live tests may skip only when a required
host dependency is absent, for example:

- Podman is not installed
- a Podman machine is not initialized on macOS
- a native OS entitlement or system extension is unavailable
- provider credentials are intentionally missing

If the dependency is present and behavior is wrong, the test must fail. Do not
replace live proof with mocked success for provider support claims.
