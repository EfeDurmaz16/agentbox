# macOS Minipod Limitations

Agentbox is moving toward local governed minipods for autonomous agents, but the
macOS path has two distinct enforcement layers:

1. VM-backed Linux cells, currently via the experimental Podman path.
2. Future native host enforcement, likely involving Endpoint Security, Network
   Extension, Apple Virtualization, and stricter host bridge controls.

The first layer is useful, but it is not the same thing as kernel-grade host
enforcement.

## What Podman-Backed Minipods Can Do

- Run an agent command inside a Linux container or Podman machine.
- Keep the default workspace separate from the full macOS home directory.
- Mount only selected host paths into the minipod.
- Inject the Agentbox daemon socket and shims so selected commands still route
  through policy, approval, and audit.
- Attach sidecars such as databases for local task execution.
- Produce session metadata and audit/evidence events when routed through the
  runtime manager.

## What They Do Not Prove Yet

- They do not stop every possible host-side action if the agent has another
  host bridge.
- They do not provide macOS kernel-level file event enforcement.
- They do not provide macOS kernel-level network enforcement.
- They do not prevent all data movement through intentionally mounted paths.
- They do not make browser profiles, keychains, SSH keys, or cloud credentials
  safe unless those paths remain unmounted or are explicitly mediated.
- They do not replace a future Endpoint Security or Network Extension layer.

## Current Guarded Boundary

The current guarded path is:

```text
agent command
  -> minipod filesystem/network/process boundary
  -> injected Agentbox shim for selected commands
  -> host daemon policy decision
  -> approval or block
  -> hash-chained audit/evidence event
```

This is useful defense in depth. It is not bypass-proof yet.

## Practical Operator Rules

- Treat Podman-backed minipods as experimental until live smoke tests prove
  socket mount, shim execution, lifecycle cleanup, and evidence export.
- macOS-built `agentbox-shim` binaries cannot execute inside Linux containers.
  The Podman bridge needs a Linux-compatible shim artifact before shim execution
  proof can pass on macOS.
- Mount the smallest workspace possible.
- Do not mount the home directory.
- Do not mount browser profiles, keychains, `.ssh`, `.aws`, `.config/gcloud`,
  `.env`, or deployment credentials unless a task explicitly requires it and the
  credential grant is mediated.
- Prefer generated `MinipodSpec` manifests over ad hoc container commands.
- Use `agentbox providers` to see whether the active backend is shipped,
  experimental, unavailable, or planned.

## Target Native Direction

The macOS native provider should eventually own:

- Apple Virtualization-backed Linux cells where a VM is genuinely needed.
- Endpoint Security-based host file and process event enforcement.
- Network Extension-based egress policy.
- Explicit host bridge mediation for daemon sockets, credentials, browser
  state, cloud CLIs, and local services.
- Tamper-evident evidence for both allowed and denied boundary crossings.

Agentbox now exposes the planned macOS shape through:

```sh
agentbox native-plan --provider agentpod-macos -- /bin/true
```

That command is a compiler for the VM cell, Endpoint Security, Network
Extension, entitlement, host bridge, and evidence surfaces. The VM cell boot
contract follows Apple's Linux VM path: `VZLinuxBootLoader` needs a host
architecture kernel image, a matching initial RAM disk, a
`VZVirtualMachineConfiguration` that passes `validate()`, and an executable with
`com.apple.security.virtualization`. `agentbox-macos-vm-runner` can emit a typed
boot-prerequisite report behind `AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1`, but it
still does not make `agentpod-macos` provider execution available, install a
system extension, activate Network Extension filtering, or enforce host
file/network decisions. Until those pieces exist, Agentbox should describe macOS
native enforcement as a gated prototype plus descriptors, not as shipped support.

See [macOS Endpoint Security enforcement design](macos-endpoint-security.md) and
[macOS system extension scaffold plan](macos-system-extension-scaffold.md) for
the planned host-level enforcement path.
