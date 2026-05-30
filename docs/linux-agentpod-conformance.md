# Linux AgentPod Conformance

`agentpod-linux` has two conformance levels:

1. Portable CI target: contract-level checks that run from a clean checkout on
   normal Ubuntu CI without claiming live sandbox enforcement.
2. Live Linux target: gated native smoke on a Linux host with `unshare`,
   Landlock, delegated or writable cgroups v2, and overlayfs.

The portable CI target is:

```sh
bash scripts/smoke-linux-agentpod-conformance.sh
```

It verifies that the Linux native plan is reproducible and still carries the
expected AgentPod boundaries: provider id, live gate name, workspace mount
contract, Landlock handled mask, network/nftables gates, runner phase evidence
names, imported OCI/libseccomp subset metadata, and descriptor-only eBPF
observability receipts. It also prints the exact live command instead of
treating skipped kernel support as a fake pass.

The live target is:

```sh
AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh
```

or, through the conformance wrapper:

```sh
AGENTBOX_LINUX_NATIVE_CONFORMANCE_LIVE=1 bash scripts/smoke-linux-agentpod-conformance.sh
```

Live mode runs the full native smoke, including an imported OCI/libseccomp
`kill(2)` denial fixture, and should only be treated as passing when the host
prerequisites are present. If the host lacks the required kernel features or
delegated cgroups, the smoke exits with skip status instead of claiming Linux
AgentPod enforcement.
