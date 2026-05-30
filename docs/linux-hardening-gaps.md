# Linux AgentPod Hardening Gaps

`agentpod-linux` is a gated prototype primitive. It can exercise native Linux
runner phases on suitable hosts, and portable CI checks that the native-plan
contract stays honest. It is not a complete sandbox, a production-safe boundary
for arbitrary untrusted code, or a kernel-grade isolation claim yet.

This document maps the remaining Linux hardening gaps to explicit follow-up
issues so public docs, demos, and release notes do not overclaim the current
implementation.

## Gap Map

| Gap | Current proof | Follow-up issue | Claim boundary |
| --- | --- | --- | --- |
| Complete syscall policy | Generated seccomp deny rules, imported OCI/libseccomp subset profiles, and a coarse connect-deny bridge for deny-all network modes. The importer validates schema, action semantics, architectures, and syscall names before compiling supported unconditional deny rules into the prototype BPF loader. | #261 | Do not claim complete libseccomp profile compatibility, default-deny profile support, conditional argument rules, notify/listener support, arbitrary profile enforcement, or syscall coverage beyond the supported prototype loader set. |
| Complete filesystem policy | Landlock read/write/execute path-beneath rules, workspace bindings, read-only mount descriptors, and guest aliases in the native plan. | #262 | Do not claim complete Landlock ABI coverage, complete filesystem mediation, or full protection against every path escape class. |
| Packet/domain network policy | Network mode descriptors, coarse deny-all connect denial through seccomp, and a gated nftables table lifecycle smoke. | #263 | Do not claim domain allowlist enforcement, packet firewall denial, DNS semantic completeness, or session-scoped firewall cleanup. |
| Kernel event evidence | eBPF observability receipt schemas in the native plan, including provider, session, cgroup path, event identity, pid/tgid fallback fields, and observed-only semantics. | #264 | Do not claim live eBPF probe loading, live event capture, enforcement, or observed events as denial proof. |
| Mount/rootfs/proc/device boundary | Workspace bind and overlay-review planning plus runner prerequisites. Hardened rootfs, `/proc`, tmp, device, and host path invisibility are not proven. | #265 | Do not claim hardened rootfs isolation, complete `/proc` isolation, a safe device namespace, or complete host path invisibility. |
| Fail-closed lifecycle cleanup | Prototype create/exec/destroy phases and conformance checks for plan truth. Some parallel cleanup behavior is tested, but partial setup and killed process cleanup are not fully proven. | #266 | Do not claim reliable cleanup after every failed mount, cgroup, network, policy, timeout, kill, or partial setup path. |

## Safe Release Language

Use these phrases for the current Linux surface:

- `gated prototype primitive`
- `portable native-plan conformance`
- `descriptor-only`
- `observed-only`
- `coarse connect-deny bridge`
- `optional live Linux smoke`
- `supported OCI/libseccomp import subset`

Avoid these phrases until the mapped issues are complete and verified by live
tests:

- `complete sandbox`
- `kernel-grade isolation`
- `production-safe arbitrary untrusted code execution`
- `complete libseccomp support`
- `complete Landlock coverage`
- `domain allowlist enforcement`
- `packet firewall enforcement`

## Verification Surface

Portable CI runs the conformance wrapper:

```sh
bash scripts/smoke-linux-agentpod-conformance.sh
```

Live Linux proof remains optional and host-dependent:

```sh
AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh
AGENTBOX_LINUX_NFTABLES=1 bash scripts/smoke-linux-nftables.sh
```

A skipped live smoke is not a pass. It records that the current host cannot
prove the stronger Linux boundary.
