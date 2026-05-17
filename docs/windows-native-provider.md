# Windows Native Provider Design

Agentbox on Windows should become a native AgentPod provider, not a thin Docker
or WSL wrapper. The product contract is the same as the other platforms:

```text
agent task
  -> minipod manifest
  -> Windows AgentPod execution cell
  -> process / filesystem / network / credential boundary
  -> policy and approval
  -> ETW-backed evidence
```

The Windows provider must remain descriptor-only until containment and evidence
are tested on a real Windows host or Windows CI.

## Support Tiers

| Tier | Meaning |
|------|---------|
| Descriptor | Provider exists in metadata and returns unavailable. |
| Prototype | Windows-only code models or applies one primitive, but provider execution is still unavailable. |
| Experimental | Create, exec, status, and destroy run on Windows with live tests. |
| Shipped | Live tests prove denial behavior, cleanup, and evidence export. |

## Primitive Map

| Boundary | Windows primitive | Agentbox role |
|----------|-------------------|---------------|
| Process tree | Job Objects | Contain child process tree, terminate session, apply CPU/memory limits where practical. |
| App identity | AppContainer / low-integrity process | Reduce process authority and constrain resource access. |
| Network | Windows Filtering Platform | Observe or filter network flows by process/session. |
| Evidence | Event Tracing for Windows | Capture process, network, and provider events for evidence bundles. |
| Strong VM boundary | Windows Sandbox / Hyper-V isolation | Use when a task needs a harder boundary than same-kernel primitives. |
| Filesystem | ACLs, AppContainer capabilities, per-task workspace | Restrict reads/writes to declared workspace and mounts. |
| Registry | AppContainer, registry virtualization where applicable | Keep task registry effects scoped or observable. |

## Job Objects First

The first implementation slice should be Job Objects because it gives Agentbox a
credible process lifecycle boundary without requiring kernel drivers.

Current repo status: Agentbox models a Windows Job Object plan/controller and
keeps the live Win32 apply path unavailable until Windows-only tests prove
behavior. `agentbox native-plan --provider agentpod-windows -- <cmd>` now emits
the full intended execution-cell contract across Job Objects, AppContainer, WFP,
ETW, and Windows Sandbox/Hyper-V fallback metadata without running anything.
The Job Object descriptor maps memory, CPU weight, risk-based process limits,
and wall-clock timeout action metadata into the plan, while explicitly stating
that live Win32 apply proof is not wired.
`scripts/smoke-windows-job-object.sh` adds a narrower gated lifecycle smoke:
with `AGENTBOX_WINDOWS_JOB_OBJECT=1` on Windows it calls `CreateJobObjectW` and
`CloseHandle` through PowerShell P/Invoke. That proves create/close access only;
it does not assign a process to the job, set limits, prove cleanup, or upgrade
the provider execution claim.
The VM boundary descriptor includes the planned workspace mount, named-pipe or
Hyper-V socket host bridge, policy/evidence endpoints, credential delivery
channels, guest evidence spool path, and teardown policy. These fields are a
contract for the future runner, not proof that Windows Sandbox or Hyper-V
lifecycle is currently wired.

Target behavior:

- create one job object per `RuntimeSession`
- start the agent task process suspended or immediately assign it before work
- assign all known children to the job
- configure kill-on-close behavior
- map memory/process/time limits from `ResourcePolicy` where supported
- record job id, pid, and limit metadata in session evidence
- destroy the session by closing/terminating the job

Job Objects are not a full sandbox. They manage a process group and resource
limits; they do not by themselves prevent all filesystem, registry, credential,
or network access.

## AppContainer Later

AppContainer is the candidate authority boundary for Windows desktop-style
process isolation. It can become the equivalent of the Linux Landlock/seccomp
layer only after Agentbox can reliably create a restricted token/profile and
map minipod capabilities to allowed resources.

Current repo status: the AppContainer descriptor now carries workspace mode,
workspace write policy, overlay/review metadata, read-only or read-write mount
descriptors, protected path rules, and an explicit non-claim that live ACL proof
is not wired. This keeps Windows native planning aligned with the AgentPod
workspace contract while avoiding a false AppContainer enforcement claim.

Open questions:

- how to create per-session AppContainer identities without leaking stale
  profiles
- how to map host workspace directories into the allowed capability set
- how to handle developer tools that expect normal user profile access
- how to preserve browser and credential isolation without breaking useful
  workflows
- whether Less Privileged AppContainer is viable for common agent toolchains

Until these are answered, AppContainer should be planned or prototype-only.

## WFP Network Boundary

Windows Filtering Platform is the correct direction for Windows network
governance, but it has two separate roles:

- observability: record flows and classify destinations for evidence
- enforcement: block or redirect flows at a WFP layer

Agentbox can ship observability earlier than enforcement. A provider must not
claim WFP enforcement until a live test proves that a denied destination is
actually blocked for the target AgentPod process and that unrelated host traffic
is not affected.

Current repo status: the WFP descriptor compiles network policy into planned
rule classes for loopback, private/LAN mediation, manifest domain allow/deny
entries, and WFP evidence event names. It remains a policy descriptor only; no
packet or domain denial proof is wired.

## ETW Evidence

ETW should be the Windows equivalent of Linux eBPF observability:

```text
Windows process/network/provider events
  -> session correlation
  -> redaction
  -> hash-chained Agentbox evidence
```

Current repo status: the Windows native execution plan carries an observed-only
ETW descriptor with job-name correlation, PID fallback, manifest label keys, and
evidence schemas for process, network, and provider lifecycle events. It also
models the planned ETW evidence export bundle files, redaction policy, spool
path, hash-chain algorithm, and bundle-root linkage. It does not start an ETW
session, export events, or claim enforcement.

Initial ETW evidence should focus on:

- process start and exit
- image path and command metadata after redaction
- network connect metadata where available
- provider lifecycle events
- job assignment and termination events emitted by Agentbox userspace code

ETW is evidence, not enforcement. Missing ETW support should not be converted
into a false pass in live tests.

## Hyper-V / Windows Sandbox

Hyper-V isolation and Windows Sandbox are valid higher-strength options for
tasks that need a VM boundary. They are also heavier than the minipod target.

Use them when:

- same-kernel controls cannot protect the requested task
- credential or browser profile separation requires a hard VM boundary
- enterprise policy requires VM-backed execution

Do not make them the only Windows architecture. Agentbox should still pursue a
fast native same-kernel path for common agent work.

The current VM cell config is intentionally explicit:

- workspace mount from the host workspace to the AgentPod guest workspace
- review-required metadata for overlay-review, ephemeral, and commit-gated work
- host bridge endpoint names for policy and evidence mediation
- credential channels for env vars, read-only files, named-pipe socket proxies,
  and broker-mediated provider tokens
- guest evidence spool path under `C:\ProgramData\Agentbox\Evidence`
- shutdown policy to terminate the VM cell and seal evidence

None of these fields claim live VM execution yet. They make the Windows runner
contract comparable to the macOS VM-cell descriptor before any Win32 or Hyper-V
integration is shipped.

## Rust Integration Direction

Keep the public provider trait in Rust. Put Windows-specific calls behind
`#[cfg(target_os = "windows")]`.

Recommended shape:

```text
runtime/providers/windows.rs
  JobObjectPlan
  JobObjectController
  AppContainerPlan
  WfpBoundaryPlan
  EtwObserverPlan
```

Dependency direction:

- use the `windows` crate for Win32 bindings when prototype code lands
- avoid broad Windows container runtimes for the first native provider
- avoid adding driver-level WFP code until userspace observability and process
  containment are tested

## Provider Availability Rule

`agentpod-windows` should remain unavailable until all of these pass:

- process starts inside the intended boundary
- destroy kills the whole process tree
- resource limits are applied or explicitly reported unavailable
- workspace policy has a tested filesystem boundary
- network observation or enforcement emits evidence
- credential and profile access limitations are documented
- evidence export links Windows events to the Agentbox session id

## Verification Gates

Portable gate:

```sh
git diff --check
cargo test --workspace
```

Future Windows live gate:

```powershell
$env:AGENTBOX_WINDOWS_JOB_OBJECT = "1"
bash scripts/smoke-windows-job-object.sh
```

The first smoke should skip only when Windows support or the explicit gate is
unavailable. If the smoke is gated on Windows and `CreateJobObjectW` or
`CloseHandle` fails, it should fail. Process assignment, kill-on-close, and
resource limit behavior still require later live proof.

## References

- Microsoft Job Objects: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
- Microsoft AppContainer / application isolation: https://learn.microsoft.com/windows/security/book/application-security-application-isolation
- Microsoft Windows Filtering Platform: https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform
- Microsoft WFP architecture: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/windows-filtering-platform-architecture-overview
- Microsoft Event Tracing for Windows: https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing
- Microsoft Windows container isolation modes: https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container
