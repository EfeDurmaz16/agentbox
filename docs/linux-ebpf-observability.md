# Linux eBPF Observability Design

Agentbox should treat eBPF as a Linux observability and evidence layer first,
not as the primary enforcement boundary. Enforcement still belongs to explicit
runtime controls: namespaces, cgroups v2, seccomp, Landlock, and network policy
hooks that can prove denial behavior in live tests.

The useful eBPF role is narrower and valuable:

```text
AgentPod process tree
  -> kernel event stream
  -> session correlation
  -> evidence bundle
  -> optional policy signal
```

## Design Boundary

eBPF can observe and summarize kernel events with low overhead, but observation
is not the same as governance. Agentbox must not mark a provider as enforcing a
policy only because an eBPF program saw the event.

| Surface | Agentbox meaning |
|---------|------------------|
| Tracepoint / kprobe event | Evidence signal. |
| BPF map counter | Runtime metric or anomaly signal. |
| Perf/ring buffer event | Streaming session evidence. |
| cgroup-attached network program | Possible enforcement only after live denial tests. |
| LSM hook | Possible enforcement only after explicit support and fail-closed behavior. |

## Candidate Signals

Start with signals that help explain what an autonomous agent did inside a
Linux AgentPod:

| Signal | Source shape | Evidence use |
|--------|--------------|--------------|
| Process exec | `sched_process_exec` tracepoint | Command lineage, binary path, pid/tgid. |
| Process exit | `sched_process_exit` tracepoint | Runtime duration, exit correlation. |
| File open | LSM or tracepoint where available | Read/write intent evidence for mounted paths. |
| Network connect | cgroup sock/connect program or tracepoint | Destination metadata for network boundary evidence. |
| DNS-like access | Userspace correlation first | Avoid pretending kernel DNS semantics are complete. |
| Capability changes | tracepoint/kprobe where available | Detect privilege boundary changes. |
| BPF load attempts | tracepoint/kprobe where available | Flag agents trying kernel instrumentation. |

The first shipped slice should record process and network metadata only. File
and LSM hooks are more sensitive because path semantics, kernel support, and
permission models vary by host.

## Session Correlation

Every Linux AgentPod session should have a stable correlation key before eBPF
events are exported:

- `session_id`
- provider name, for example `agentpod-linux`
- root pid or cgroup path
- minipod manifest hash
- policy bundle ids and hashes
- monotonic event sequence

The runtime should prefer cgroup-based correlation when the session cgroup is
available. PID-only correlation is not enough because pids are recycled and
process trees can be short-lived.

## Event Schema

The event exported into Agentbox evidence should be intentionally small:

```json
{
  "schema_version": 1,
  "session_id": "01...",
  "event_type": "linux.process.exec",
  "timestamp": "2026-05-14T00:00:00Z",
  "pid": 1234,
  "tgid": 1234,
  "cgroup": "/sys/fs/cgroup/agentbox-01...",
  "binary": "/usr/bin/git",
  "argv_redacted": ["git", "push"],
  "policy_ref": "policy:deploy",
  "decision_ref": "audit:event-id",
  "enforcement": "observed"
}
```

The `enforcement` field must stay explicit:

- `observed`: eBPF saw the event only.
- `blocked-by-runtime`: another runtime primitive blocked it.
- `blocked-by-bpf`: only valid after a live test proves the exact hook denied
  the action.

## Implementation Path

1. Keep `agentpod-linux` unavailable.
2. Add a Linux-only `EbpfObserverPlan` model with program names, required
   capabilities, map names, and event schemas. The native execution plan now
   carries this observed-only descriptor without adding a live loader.
3. Add a userspace collector interface that can ingest events from a future eBPF
   loader without depending on the loader in the core runtime.
4. Add session evidence export for observed process and network events.
5. Add live tests gated by `AGENTBOX_LINUX_LIVE_TESTS=1`.
6. Only after live tests pass, consider a Linux-only dependency.

## Dependency Direction

Use one eBPF stack, not several.

| Option | Use when | Notes |
|--------|----------|-------|
| `aya` | Rust-first implementation | Best fit for a Rust Agentbox runtime because it avoids a C libbpf dependency. |
| `libbpf-rs` | CO-RE/libbpf compatibility is more important | Strong ecosystem fit, but adds libbpf toolchain and packaging concerns. |
| Raw `bpf()` syscalls | Minimal prototype only | Too much verifier, map, and loader surface to own long term. |

Do not add an eBPF dependency until the first observer plan and event schema are
tested without a live loader. The immediate repo value is the contract between
kernel events and Agentbox evidence, not premature kernel code.

## Security Rules

- Do not load eBPF programs from untrusted agent workspaces.
- Do not let agents write BPF maps directly.
- Do not store raw argv or environment values without redaction.
- Do not treat missing BPF support as a pass in live tests.
- Do not claim packet/domain enforcement from trace-only programs.
- Keep all privileged loader behavior outside normal agent task execution.

## Verification Gates

Portable gate:

```sh
git diff --check
cargo test --workspace
```

Future Linux live gate:

```sh
AGENTBOX_LINUX_LIVE_TESTS=1 cargo test -p agentbox-daemon linux_ebpf
```

The live gate should skip only when kernel support or privileges are absent. If
the hook loads and observes the wrong session or misses expected events, it
should fail.

## References

- Linux kernel BPF documentation: https://docs.kernel.org/bpf/
- Linux kernel eBPF userspace API: https://docs.kernel.org/userspace-api/ebpf/
- Linux kernel tracepoints: https://docs.kernel.org/trace/tracepoints.html
- Aya Rust eBPF project: https://aya-rs.dev/
