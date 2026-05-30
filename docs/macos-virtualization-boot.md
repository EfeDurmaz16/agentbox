# macOS Apple Virtualization Boot Prototype

`agentpod-macos` is still unavailable for provider execution. The current
macOS work only adds a gated Apple Virtualization boot prototype so Agentbox can
move from descriptor-only planning toward a real VM lifecycle without claiming a
shipped sandbox.

## Apple-Aligned Requirements

The boot prototype follows Apple's Virtualization framework shape:

- `VZVirtualMachine.isSupported` must be true on the host.
- The executable that uses Virtualization must carry
  `com.apple.security.virtualization`.
- `VZVirtualMachineConfiguration` must include a boot loader and pass
  `validate()`.
- Linux guests use `VZLinuxBootLoader` with a host-architecture kernel image and
  a matching initial RAM disk.
- `VZVirtualMachine.start(completionHandler:)` starts the VM asynchronously.

Apple references:

- <https://developer.apple.com/documentation/virtualization/vzvirtualmachine>
- <https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration>
- <https://developer.apple.com/documentation/virtualization/vzlinuxbootloader>
- <https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.virtualization>
- <https://developer.apple.com/documentation/virtualization/virtualize-linux-on-a-mac>

## Current Gate

The native plan and runner request carry Linux boot artifact metadata from:

```sh
AGENTBOX_MACOS_VM_KERNEL_IMAGE=/path/to/vmlinuz
AGENTBOX_MACOS_VM_INITRD_IMAGE=/path/to/initrd.img
```

`agentbox-macos-vm-runner` only attempts the boot prototype when this gate is
set:

```sh
AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1 agentbox-macos-vm-runner --request <request.json>
```

Without the gate, the runner validates the request and refuses execution. With
the gate, it emits a typed JSON report. If prerequisites are missing, the report
is `blocked` with a reason such as `host-os`, `virtualization-framework`,
`linux-kernel-image`, `linux-initial-ramdisk`, `swiftc`, or `codesign`. If the
host and artifacts are present, the runner compiles and ad-hoc signs a temporary
Swift boot helper with `com.apple.security.virtualization`, validates the
`VZVirtualMachineConfiguration`, and attempts a short-lived
`VZVirtualMachine.start`.

## Claim Boundary

This is not `agentbox run --provider agentpod-macos`.

The boot prototype does not yet prove:

- guest agent command execution through the Agentbox host bridge
- workspace sharing through Apple Virtualization
- Endpoint Security authorization
- Network Extension egress mediation
- lifecycle cleanup evidence
- allow/deny evidence linked into the Agentbox evidence bundle

Until those are wired together, public claims must stay at "gated boot
prototype plus descriptors", not native macOS AgentPod execution.
