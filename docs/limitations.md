# Public Limitations and Bypass Boundaries

Agentbox is useful today, but it is not complete isolation. This document is the
public boundary for what Agentbox can and cannot currently claim.

## Taxonomy

Risk below means the operator-facing risk if a provider limitation is mistaken
for stronger enforcement than Agentbox currently proves.

| Provider | Current boundary | Risk | Operator check / handling |
|----------|------------------|------|---------------------------|
| `direct-host` | Weak fallback/dev command governance through shims, approvals, explicit grants, audit, and evidence. | High for untrusted agents; acceptable only for low-risk trusted commands. | Mitigation: use for low-risk or development fallback flows. High and very-high risk sessions require `--direct-host-dev-mode` or explicit session approval. Keep credential grants explicit and short-lived, and inspect evidence. Non-goal: filesystem, process, browser, wallet, keychain, or packet isolation. |
| `podman` | Podman compatibility backend for container-backed sessions when the target host passes live smoke. | Medium to high when host mounts, daemon sockets, or VM layers are treated as Agentbox-owned native enforcement. | Operator check: run `bash scripts/smoke-podman-bridge.sh` on the target host. Mitigation: treat it as compatibility only. Non-goal: paid-product isolation center or uniform cross-platform enforcement. |
| `agentpod-linux` | Gated native prototype with Linux namespace, cgroup, Landlock, seccomp, overlayfs, and runner prerequisites. | High until denial, cleanup, workspace, credential, network, and evidence gates pass live on Linux. | Operator check: run `AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh` on Linux. Mitigation: use only for prototype validation. Non-goal: default paid-product backend or complete sandbox. |
| `agentpod-macos` | Descriptor and gated runner contract; native execution remains unavailable until live VM, entitlement, denial, evidence, and cleanup gates pass. | High if descriptors are read as shipped macOS enforcement. | Operator check: inspect provider truth and future macOS live smoke results before any public claim. Non-goal: native macOS AgentPod execution or enforcement today. |
| `agentpod-windows` | Descriptor/prototype surfaces for Job Objects, AppContainer, WFP, ETW, Windows Sandbox, and Hyper-V planning. | High until Windows live gates prove process assignment, cleanup, filesystem or credential constraints, network evidence or denial, and evidence export. | Operator check: `AGENTBOX_WINDOWS_JOB_OBJECT=1 bash scripts/smoke-windows-job-object.sh` proves only Job Object create/close. Non-goal: native Windows AgentPod execution or enforcement today. |
| `remote-agentpod` | Experimental remote worker path gated by an HTTPS endpoint or explicitly allowed loopback development endpoint. | High because trust depends on worker identity, worker isolation, capability reporting, transport security, and returned evidence. | Operator check: run `bash scripts/smoke-remote-worker.sh` plus endpoint-specific readiness and evidence verification. Mitigation: use only trusted workers and avoid broad secrets. Non-goal: general managed sandbox service or secret-safe production worker fleet. |

## Direct-Host Shim Mode

Shipped direct-host mode governs commands that enter through Agentbox shims.
It can approve, block, and audit common shell actions.

Environment behavior is intentionally narrow. Direct-host command execution
does not inherit the ambient daemon environment. The child process receives only
the explicit environment attached to the `ExecCommand` request and any approved
credential environment grants. This limits accidental credential bleed, but it
does not turn direct-host mode into an OS sandbox.

Limitations and handling:

- high and very-high risk sessions are denied unless the operator passes
  `--direct-host-dev-mode` or provides an explicit session approval in the
  manifest. Mitigation: prefer a stronger live-gated AgentPod provider for
  untrusted or paid-product workflows.
- absolute paths can bypass PATH shims. Mitigation: use direct-host only for
  low-risk trusted commands and review evidence for the actual argv executed.
- direct syscalls are not intercepted. Non-goal: direct-host is not kernel or
  syscall mediation.
- code running inside an interpreter can perform work without spawning a
  shimmed command. Mitigation: prefer stronger live-gated providers for
  untrusted interpreter workloads.
- explicit environment or credential grants can still be read, copied, printed,
  or exfiltrated by the process that receives them. Mitigation: grant only the
  minimum credential needed, keep grants short-lived, and avoid broad secrets.
- browser, keychain, wallet, and cloud SDK APIs are not fully mediated.
  Non-goal: direct-host does not isolate ambient desktop or cloud SDK state.
- a local user with access to the same account can alter config, DB files, or
  process state. Operator check: inspect daemon, shim, and audit health before
  relying on local evidence for a workflow.

Use this mode for command governance and evidence, not as a full sandbox.

## Podman Compatibility Minipods

Experimental Podman-backed minipods add a useful runtime cell around agent work.
They do not prove kernel-grade host enforcement.

Limitations and handling:

- host paths intentionally mounted into the minipod remain reachable.
  Mitigation: mount only the workspace and explicit credential files needed for
  the task.
- daemon socket and shim injection must be proven by live smoke tests on the
  target host. Operator check: run `bash scripts/smoke-podman-bridge.sh`; a skip
  is not a pass.
- container isolation does not govern every host bridge. Non-goal: Podman
  compatibility is not Agentbox-owned native host enforcement.
- macOS Podman runs through a VM layer, so host enforcement and VM enforcement
  are different boundaries. Mitigation: document which boundary was tested for
  any macOS compatibility claim.
- provider behavior may differ across macOS, Linux, and Windows hosts.
  Operator check: verify the exact target host rather than reusing another
  platform's smoke result.

Use this mode as a compatibility backend while AgentPod native providers mature.

## Native AgentPod Descriptors

`agentpod-macos`, `agentpod-linux`, and `agentpod-windows` currently describe
planned capability surfaces. `agentpod-linux` has a gated prototype executor on
Linux, and `agentpod-macos` has a native plan compiler. macOS and Windows
provider execution intentionally returns unavailable.

Limitations and handling:

- no native provider is shipped as a complete enforcement backend yet.
  Non-goal: do not claim native AgentPod isolation until live provider gates
  prove execution, denial, cleanup, and evidence.
- planned primitives do not imply active protection. Operator check: inspect
  provider truth metadata for `active`, `requires_gate`, and
  `enforcement_scope`.
- provider metadata is not a security boundary. Mitigation: require live smoke
  or denial proof before upgrading any provider claim.
- default tests prove honest unavailability, metadata, and plan compilers, not
  live kernel or OS enforcement. Operator check: run the provider-specific live
  smoke on the target OS before marketing enforcement.

Provider-specific boundaries:

- `agentpod-linux` is a gated prototype. Mitigation: keep it behind Linux live
  gates until namespace, mount, cgroup, seccomp, Landlock, workspace, cleanup,
  network, credential, and evidence behavior pass on the target host.
- `agentpod-macos` is unavailable for native execution today. Non-goal: a
  descriptor, plan compiler, or gated runner contract is not macOS enforcement.
- `agentpod-windows` is descriptor/prototype until Windows live gates pass.
  Non-goal: Job Object planning or descriptor metadata is not Windows AgentPod
  execution.

Use these descriptors to understand direction and plan integrations. Do not
market them as shipped isolation.

## Remote AgentPod Workers

`remote-agentpod` is an experimental provider for attached machines,
disposable workers, or future managed worker pools. It can be useful only when
an HTTPS worker endpoint, or explicitly gated loopback development endpoint, is
configured and returns evidence that the operator can inspect.

Limitations and handling:

- worker-side isolation is outside the local daemon's direct control.
  Mitigation: use only workers whose identity, deployment, and isolation model
  the operator trusts.
- capability reports and evidence are remote assertions unless independently
  verified. Operator check: verify returned evidence, worker status, restart,
  destroy, and support artifacts for the endpoint.
- credential payloads cross the daemon-to-worker boundary when granted.
  Mitigation: avoid broad secrets, prefer scoped and revocable credentials, and
  assume a remote process can print what it receives.
- loopback HTTP is for local development only when explicitly gated. Non-goal:
  HTTP loopback is not a production transport.
- remote execution is not a managed paid sandbox by default. Non-goal: do not
  claim a durable or secret-safe production worker fleet without endpoint-level
  live gates.

## Credential Boundaries

Agentbox now redacts credential-like material in audit and evidence output and
rejects unsafe minipod manifests such as host env inheritance. That is not the
same as complete secret isolation.

Limitations and handling:

- redaction is pattern-based and can miss unusual secret formats. Mitigation:
  avoid sending broad or long-lived secrets to agent processes.
- existing external logs outside Agentbox are not scrubbed. Operator check:
  review external tool, shell, browser, and cloud SDK logs separately when
  credentials may have been exposed.
- one-time credential file grants are modeled and carried into provider mount
  metadata, but native provider revocation is still evolving. Mitigation: pair
  Agentbox revocation with upstream credential rotation where possible.
- browser profiles, keychains, wallets, and cloud SDK caches need provider-level
  mediation before they are safe for broad agent access. Non-goal: current
  credential redaction is not desktop, wallet, keychain, or cloud account
  isolation.

See [safe credential patterns](safe-credential-patterns.md) for the recommended
operator flow.

## Live-Test Policy

A skipped live test is not a pass. Live tests may skip only when a required
host dependency is absent, for example:

- Podman is not installed
- a Podman machine is not initialized on macOS
- a native OS entitlement or system extension is unavailable
- provider credentials are intentionally missing

If the dependency is present and behavior is wrong, the test must fail. Do not
replace live proof with mocked success for provider support claims.

See [network enforcement limits](network-enforcement-limits.md) for the current
platform-by-platform boundary between classified, observed, provider-mode, and
packet/domain-enforced network behavior.
