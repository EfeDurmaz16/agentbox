# Installer Packaging Plan

Agentbox does not currently ship a verified installer. The supported install
path is still a source build plus `agentbox install` for shims. This plan
defines how packaging should graduate without pretending that unverified
installers or native providers are shipped.

## Packaging Contract

Every package must preserve the same public support levels used by
`agentbox providers` and the release checklist:

- shipped
- experimental
- prototype primitive
- descriptor only
- planned

An installer may make setup easier, but it must not upgrade a runtime backend's
status. Native AgentPod providers remain unavailable until their execution path
and enforcement boundary have live proof on that platform.

## Current Supported Path

```sh
cargo build --release
cargo run -p agentbox-cli -- install
export PATH="$HOME/.agentbox/shims:$PATH"
cargo run -p agentbox-cli -- doctor
```

For a non-mutating guided flow that installers and operators can render first:

```sh
cargo run -p agentbox-cli -- setup --dry-run --wizard
cargo run -p agentbox-cli -- setup --dry-run --wizard --json
```

The installer work should keep this path working. Source builds are the
fallback for all platforms until packages are reproducible, signed where
appropriate, and verified on clean hosts.

## Artifact Matrix

| Artifact | Current status | Packaging rule |
|----------|----------------|----------------|
| `agentbox-cli` | Shipped | Include in every package. |
| `agentbox-daemon` | Shipped | Include in every package; service installation may be separate. |
| `agentbox-shim` | Shipped | Include and install via `agentbox install`; do not silently reorder `PATH`. |
| Runtime provider metadata | Shipped | Include descriptors, but preserve unavailable status for native providers. |
| Demo scripts | Shipped docs/test assets | Include in source and tarball packages; do not make them mandatory install steps. |
| Podman compatibility backend | Experimental | Detect Podman with `doctor`; do not install or claim it as native AgentPod. |
| macOS native provider | Descriptor only | Package only when live execution and entitlement requirements are proven. |
| Linux native provider | Prototype primitives | Package only after rootless execution wiring and denial tests are proven. |
| Windows native provider | Prototype primitives | Package only after Windows live tests prove Job Object/AppContainer behavior. |

## macOS Path

Initial macOS packaging should be a Homebrew formula or source tarball that
installs the CLI, daemon, and shim binary. It should not ship privileged
components as a side effect.

Rules:

- run `agentbox doctor` after installation and report daemon, shim, PATH,
  audit, and provider readiness
- keep shim installation explicit through `agentbox install`
- avoid changing shell startup files without an explicit operator step
- keep Podman compatibility detection separate from Agentbox installation
- do not claim Endpoint Security, Network Extension, or Virtualization
  enforcement until signed, entitled, and verified builds exist
- package launchd service setup only after start/stop/status behavior is
  covered by a clean-host smoke test

Future package shapes:

- Homebrew formula for source or bottle distribution
- signed `.pkg` for CLI/daemon/shim installation
- separate signed system-extension package if native macOS enforcement lands

## Linux Path

Initial Linux packaging should be a tarball or distro package that installs
the CLI, daemon, and shim binary without requiring root for normal operation.

Rules:

- keep rootless execution as the default expectation
- verify cgroups v2, namespace, seccomp, and Landlock availability with
  explicit readiness checks instead of assuming kernel support
- make native primitive scripts skip honestly on unsupported hosts
- avoid installing global firewall or nftables rules before there is a tested
  rollback path
- keep systemd user-service setup optional until daemon lifecycle tests cover it

Future package shapes:

- `.tar.gz` release archive with checksums
- Debian package
- RPM package
- optional systemd user-service unit

## Windows Path

Initial Windows packaging should remain source-build oriented until a Windows
host verifies daemon lifecycle, shim-equivalent command routing, and provider
readiness behavior.

Rules:

- treat Job Object and AppContainer support as prototype primitives until live
  tests pass on Windows
- do not claim WFP network enforcement without packet or domain denial tests
- prefer explicit PowerShell setup over hidden global shell mutation
- keep Windows service installation separate from the CLI package until
  service lifecycle behavior is verified
- ensure `agentbox providers` reports unavailable or prototype states honestly

Future package shapes:

- signed MSI
- winget package
- Scoop manifest
- optional Windows service registration

## Release Integrity

Public release artifacts should include:

- checksums for every archive or installer
- a generated software bill of materials when the release pipeline supports it
- release notes that name shipped, experimental, prototype, descriptor-only,
  and planned surfaces separately
- verification output for the package host
- exact installer version and git commit

Signing and notarization are release gates for privileged or auto-starting
platform components. They are not required for local source builds.

## Verification Before Publishing

At minimum, run this on the packaging host:

```sh
scripts/release-readiness.sh
```

If `doctor` fails because local state is missing, fix the installer or record
the failure as a release blocker. Do not convert missing daemon, PATH, shim,
Podman, audit, or native-provider readiness into a fake pass.

The script emits machine-readable `doctor.json`, `setup-plan.json`, and
`providers.json` artifacts under `target/agentbox-release-readiness` by default.
`doctor.json` separates required failures from advisory native-provider
prerequisites, and `setup-plan.json` records the next operator action an
installer or package UI should show. Packaging jobs may set
`AGENTBOX_RELEASE_ARTIFACT_DIR` to persist those files with installer logs.

## Do Not Ship Rule

Do not publish an installer when any of these are true:

- it has not been run on a clean host for that platform
- it mutates shell or service state without an explicit operator command
- it claims native AgentPod execution without live provider proof
- it hides missing Podman, kernel, entitlement, WFP, or service prerequisites
- it logs secrets, private paths, tokens, database URLs, or credential grants
- it leaves the user unable to uninstall shims, services, or generated state

The package can be incomplete. It cannot be misleading.
