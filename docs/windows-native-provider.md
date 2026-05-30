# Windows Native Provider Architecture

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

Current status: `agentpod-windows` is not runnable. The repository contains
plan/compiler metadata and narrow prototype primitives, but provider execution
must return unavailable until the live gates in this document pass. This
document is an architecture contract, not an implementation claim.

## Support Tiers

| Tier | Meaning |
|------|---------|
| Descriptor | Provider exists in metadata and returns unavailable. |
| Prototype | Windows-only code models or applies one primitive, but provider execution is still unavailable. |
| Experimental | Create, exec, status, and destroy run on Windows with live tests. |
| Shipped | Live tests prove denial behavior, cleanup, and evidence export. |

## Provider Boundary

The Windows provider boundary should stay aligned with the shared AgentPod
provider contract:

```text
RuntimeProvider
  create(manifest, workspace, policy, credentials) -> RuntimeSession
  exec(session, argv, env) -> RuntimeExecResult
  status(session) -> RuntimeStatus
  destroy(session) -> RuntimeDestroyResult
  descriptor() -> ProviderDescriptor
```

Windows-specific code owns only the translation from the AgentPod manifest and
provider APIs into Windows primitives. It must not own policy semantics,
approval grants, evidence bundle layout, credential authority, or workspace
review semantics. Those remain shared Agentbox concerns.

The provider may emit a plan before it can execute. A plan can describe intended
Job Object, restricted token, AppContainer, WFP, ETW, and VM-cell settings, but
it must be marked descriptor-only or prototype until a Windows live test proves
the setting is applied to the target process.

Hard API rules:

- `create` must fail closed when required Windows primitives are missing
- `exec` must never spawn work outside the selected session boundary
- `destroy` must be best-effort cleanup plus explicit evidence about what was
  confirmed, failed, or unavailable
- `descriptor` must report capability status per primitive, not one coarse
  Windows support bit
- provider-specific evidence must flow into the same session evidence and
  AgentPod receipt vocabulary used by other providers

## Primitive Map

| Boundary | Windows primitive | Agentbox role |
|----------|-------------------|---------------|
| Process tree | Job Objects | Contain child process tree, terminate session, apply CPU/memory limits where practical. |
| User authority | Restricted tokens | Remove or deny privileges before process start; pair with low integrity or AppContainer where practical. |
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

## Capability Descriptor

`agentpod-windows` should expose primitive-level capability descriptors so
operator UIs, installers, and release checks can see the exact truth surface.
A representative descriptor should include:

```json
{
  "provider": "agentpod-windows",
  "status": "descriptor-only",
  "runnable": false,
  "primitives": [
    {
      "name": "job_objects",
      "status": "prototype primitive",
      "active": false,
      "scope": "process_tree_lifecycle",
      "gate": "AGENTBOX_WINDOWS_JOB_OBJECT=1 smoke on Windows",
      "claims": ["planned_process_tree_cleanup", "planned_resource_limits"],
      "non_claims": ["no_live_process_assignment_proof", "no_limit_enforcement_proof"]
    },
    {
      "name": "restricted_tokens",
      "status": "descriptor only",
      "active": false,
      "scope": "process_authority_reduction",
      "gate": "live restricted token process creation and privilege denial test",
      "claims": ["planned_privilege_reduction"],
      "non_claims": ["no_current_token_apply_path"]
    },
    {
      "name": "appcontainer_low_integrity",
      "status": "descriptor only",
      "active": false,
      "scope": "app_identity_and_filesystem_authority",
      "gate": "live workspace allow and protected path deny test",
      "claims": ["planned_profile_or_low_integrity_boundary"],
      "non_claims": ["no_acl_or_profile_isolation_proof"]
    },
    {
      "name": "wfp",
      "status": "descriptor only",
      "active": false,
      "scope": "network_observation_or_enforcement",
      "gate": "live target-process network event and denial test",
      "claims": ["planned_flow_observation", "planned_policy_mapping"],
      "non_claims": ["no_packet_or_domain_denial_proof"]
    },
    {
      "name": "etw",
      "status": "descriptor only",
      "active": false,
      "scope": "evidence_observation",
      "gate": "live ETW capture linked to Agentbox session evidence",
      "claims": ["planned_process_network_provider_events"],
      "non_claims": ["no_live_capture_or_export_proof"]
    },
    {
      "name": "hyperv_or_windows_sandbox",
      "status": "planned",
      "active": false,
      "scope": "optional_vm_boundary",
      "gate": "live VM cell boot, bridge, teardown, and evidence proof",
      "claims": ["planned_strong_boundary_fallback"],
      "non_claims": ["no_current_vm_lifecycle"]
    }
  ]
}
```

The exact CLI JSON may evolve, but the descriptor must preserve these
distinctions: planned versus active, observation versus enforcement, and
prototype primitive versus runnable provider.

## Restricted Tokens and AppContainer

Restricted tokens are the first authority-reduction primitive to model because
they map directly to Windows process creation. They should be used to remove
unneeded privileges, deny high-risk SIDs where appropriate, and prevent ambient
administrator authority from leaking into the AgentPod process.

AppContainer is the candidate identity boundary for Windows desktop-style
process isolation. Low-integrity processes are a weaker fallback for tools that
cannot run in an AppContainer profile. These can become the Windows equivalent
of the Linux filesystem/syscall authority layer only after Agentbox can
reliably create a restricted token or AppContainer profile and map minipod
capabilities to allowed resources.

Current repo status: the AppContainer descriptor now carries workspace mode,
workspace write policy, overlay/review metadata, read-only or read-write mount
descriptors, protected path rules, and an explicit non-claim that live ACL proof
is not wired. This keeps Windows native planning aligned with the AgentPod
workspace contract while avoiding a false AppContainer enforcement claim.

Open questions:

- how to create per-session AppContainer identities without leaking stale
  profiles
- how to compose restricted tokens, low integrity, and AppContainer without
  accidentally granting broader access than the parent token
- how to map host workspace directories into the allowed capability set
- how to handle developer tools that expect normal user profile access
- how to preserve browser and credential isolation without breaking useful
  workflows
- whether Less Privileged AppContainer is viable for common agent toolchains

Until these are answered, AppContainer should be planned or prototype-only.

## Workspace Boundary

The Windows native provider must treat the workspace as a declared boundary,
not just a current working directory. The manifest should compile into:

- a per-session workspace root under an Agentbox-owned directory
- explicit read-only mounts for approved host paths
- explicit read-write mounts for the task workspace only when the workspace
  mode allows it
- protected path deny rules for user profiles, SSH keys, cloud credentials,
  browser profiles, OS directories, and Agentbox state unless explicitly
  granted
- overlay-review, ephemeral, and commit-gated metadata matching the shared
  AgentPod workspace modes
- evidence for prepared workspace paths, mount intent, denied protected paths,
  and cleanup results

Descriptor-only workspace plans are acceptable. Runnable Windows support is not
acceptable until a live test proves the target process cannot read or write
outside the declared workspace and granted mounts.

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

## Evidence and Receipt Parity

Windows evidence must produce the same operator-facing receipt shape as other
AgentPod providers. A Windows receipt should be able to answer:

- what manifest and risk profile were requested
- what provider primitives were planned
- which primitives were active, skipped, unavailable, or failed
- what process tree was started and destroyed
- what workspace paths and credential grants were exposed
- what network events were observed or denied
- what ETW/provider events were linked to the session id
- what cleanup was confirmed at destroy time
- which limitations prevent treating the run as a shipped Windows sandbox

Before live support, the receipt may contain descriptor-only planned evidence
refs. After live support, it must contain observed evidence refs that verify the
Windows provider actually applied the boundary to the target process.

## Lifecycle

Target lifecycle:

```text
plan
  -> validate host prerequisites
  -> prepare workspace boundary
  -> prepare credential grants
  -> create restricted token / AppContainer identity if enabled
  -> create Job Object
  -> start target process suspended or otherwise assign before user work
  -> attach target process to Job Object
  -> start ETW correlation and provider lifecycle evidence
  -> apply WFP observation/enforcement policy if enabled
  -> resume/exec target command
  -> collect stdout/stderr and provider events
  -> destroy session through Job Object termination and cleanup
  -> seal evidence bundle and AgentPod receipt
```

The important invariant is ordering: policy, workspace, credentials, token,
AppContainer, Job Object, and evidence setup happen before the target command
does useful work. If the process cannot be assigned to the intended boundary
before work starts, the provider must fail closed.

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
  RestrictedTokenPlan
  AppContainerPlan
  WfpBoundaryPlan
  EtwObserverPlan
  WindowsVmCellPlan
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

## v0 and v1 Gates

v0 descriptor gate:

- provider is listed as `descriptor-only` or `prototype primitive`, not shipped
- `agentbox native-plan --provider agentpod-windows -- <cmd>` emits a
  secret-free plan for Job Objects, restricted tokens, AppContainer or low
  integrity, WFP, ETW, workspace boundary, credential channels, and optional
  Hyper-V or Windows Sandbox fallback
- unsupported execution returns unavailable
- provider capability descriptors include `active=false` for unproven
  primitives
- docs and CLI metadata agree on the non-runnable status
- portable verification passes on non-Windows hosts

v1 runnable gate:

- Windows CI or a documented Windows live host runs provider create, exec,
  status, and destroy
- process assignment to the Job Object happens before target work
- destroy kills the full process tree and records cleanup evidence
- restricted token or AppContainer/low-integrity behavior denies at least one
  protected privilege or protected path that the parent user could access
- workspace read/write policy denies out-of-bound access and preserves the
  expected review/ephemeral/commit-gated semantics
- WFP or ETW network observation is linked to the Agentbox session, and any
  claimed enforcement proves target-process denial without blocking unrelated
  host traffic
- credential grants are scoped to the session and not inherited from the
  ambient user profile unless explicitly granted
- evidence bundle verification and AgentPod native receipt export pass

Anything short of the v1 gate is not Windows support. It is planning or a
prototype primitive.

## Verification Gates

Portable gate:

```sh
git diff --check
cargo test --workspace
```

Descriptor coverage check:

```sh
rg -n "Job Objects|restricted tokens|AppContainer|WFP|ETW|Hyper-V|Windows Sandbox" docs/windows-native-provider.md docs/platform-isolation.md docs/status-matrix.md
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

## Test and Verification Plan

Test coverage should advance in layers:

- descriptor tests verify that provider metadata reports every primitive with
  truthful status, gate, scope, active state, and non-claims
- plan tests verify manifest fields compile into Job Object, restricted token,
  AppContainer or low-integrity, WFP, ETW, workspace, credential, and optional
  VM-cell descriptors without secrets
- negative execution tests verify unsupported Windows execution returns
  unavailable before spawning work
- Windows live smoke tests verify primitive creation only when explicitly gated
- Windows live lifecycle tests verify process assignment, kill-on-close cleanup,
  resource limit behavior, workspace denial, credential scoping, network
  evidence or denial, ETW export, and receipt verification

Live Windows tests must skip only when the host dependency or explicit gate is
absent. Once a live gate is enabled on Windows, failure to apply the primitive
must fail the test.

## Known Limitations

- no runnable Windows provider is shipped today
- Job Object create/close proof is not process assignment, kill-on-close
  cleanup, or resource-limit proof
- restricted token creation and privilege-denial behavior are not wired
- AppContainer profile lifecycle, ACL mapping, and low-integrity fallback are
  not proven
- WFP descriptors do not prove packet or domain denial
- ETW descriptors do not prove live capture, redaction, export, or receipt
  linkage
- Hyper-V and Windows Sandbox descriptors do not prove VM boot, host bridge,
  workspace mount, credential delivery, or teardown
- developer tool compatibility is unknown for restricted tokens,
  AppContainer, low integrity, and VM-backed cells
- Windows support must not be marketed as runnable until the v1 gates pass

## References

- Microsoft Job Objects: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
- Microsoft AppContainer / application isolation: https://learn.microsoft.com/windows/security/book/application-security-application-isolation
- Microsoft Windows Filtering Platform: https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform
- Microsoft WFP architecture: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/windows-filtering-platform-architecture-overview
- Microsoft Event Tracing for Windows: https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing
- Microsoft Windows container isolation modes: https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container
