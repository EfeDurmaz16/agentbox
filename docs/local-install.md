# Reproducible Local Install

This is the supported source install path for local development and operator
trials. It builds the shipped direct-host components from this checkout and
installs local binaries plus command shims. It does not install packaged
binaries, signed artifacts, native OS extensions, release services, network
services, or secrets.

For release archives downloaded from GitHub Actions or GitHub Releases, verify
the artifact before installing from it:

```sh
shasum -a 256 -c SHA256SUMS
gh attestation verify ./agentbox-<version>-<target>.tar.gz \
  -R EfeDurmaz16/agentbox \
  --signer-workflow EfeDurmaz16/agentbox/.github/workflows/release.yml
```

Those commands verify archive integrity and GitHub Actions provenance. They do
not prove platform code signing or notarization; release archives must keep
`SIGNING_STATUS.json` at `code_signing.signed: false` until a real signing path
exists.

## Prerequisites

- Rust stable toolchain with `cargo`.
- A POSIX shell on macOS or Linux.
- This repository checkout, including `Cargo.lock`.
- A writable local install prefix. The examples use `~/.local`; no `sudo` is
  required.

Optional provider prerequisites such as Podman, macOS Endpoint Security,
Network Extension, Linux native primitives, Windows native primitives, or a
remote AgentPod endpoint are not part of this local install path.

## Locked Build and Test

Run the locked checks from the repository root:

```sh
cargo test --locked --workspace
cargo build --locked --release -p agentbox-cli -p agentbox-daemon -p agentbox-shim
```

These commands use the committed `Cargo.lock`. They should not require network
services or credentials beyond fetching Rust crates when the local Cargo cache
is empty.

## Install From Source

Preview the install without changing the prefix:

```sh
scripts/install-agentbox-local.sh --dry-run --prefix "$HOME/.local"
```

Install the local binaries:

```sh
scripts/install-agentbox-local.sh --prefix "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
```

The script installs:

- `agentbox`, a local command name for the CLI.
- `agentbox-cli`, the package binary name for compatibility with build output.
- `agentbox-daemon`, used by `agentbox start`.
- `agentbox-shim`, used by direct-host command shims.

The script only writes under `PREFIX/bin`, defaults to `~/.local/bin`, and does
not edit shell startup files.

## Configure Direct-Host Shims

Inspect the setup plan first:

```sh
agentbox setup --dry-run --wizard
agentbox setup --dry-run --provider direct-host --json
```

Install local command shims:

```sh
agentbox install
export PATH="$HOME/.agentbox/shims:$PATH"
```

For persistence, add both path entries to your shell profile in this order:

```sh
export PATH="$HOME/.agentbox/shims:$HOME/.local/bin:$PATH"
```

This shim path enables the shipped direct-host command mediation path. It is
not a filesystem, process, browser, wallet, keychain, packet, or native OS
sandbox.

## Verification

Run the exact local readiness command:

```sh
agentbox doctor
```

For machine-readable verification:

```sh
agentbox doctor --json
```

`doctor` should report the daemon, shim binary, installed shims, shim PATH
priority, audit database, and provider readiness. If a previous daemon left a
stale socket or pid file, use:

```sh
agentbox clean
agentbox start
agentbox doctor
```

## Support Bundle

For support or bug reports, export a redacted diagnostic bundle:

```sh
agentbox support-bundle --output target/agentbox-support-bundle --json
```

The bundle includes doctor output, provider status, local daemon/shim status, a
redacted config snapshot, evidence references, and diagnostic log notes. It is
not a raw transcript export: secrets, tokens, credential paths, and raw command
values are redacted or omitted.

## Upgrade, Rollback, and Uninstall

`scripts/install-agentbox-local.sh` backs up existing local binaries before it
installs a new set. It does not mutate `~/.agentbox/config.toml`, `audit.db`,
`runtime-sessions.json`, AgentPod state, or evidence directories during
upgrade or rollback.

Upgrade from this checkout or from a verified release archive using the same
prefix you used before:

```sh
scripts/install-agentbox-local.sh --prefix "$HOME/.local"
```

If the previous prefix contained Agentbox binaries, the script writes a backup
under:

```text
$HOME/.local/.agentbox-backups/<timestamp>/bin
```

Rollback restores the previous binary set from the latest backup:

```sh
scripts/install-agentbox-local.sh --prefix "$HOME/.local" --rollback
```

To restore a specific backup:

```sh
scripts/install-agentbox-local.sh \
  --prefix "$HOME/.local" \
  --rollback-from "$HOME/.local/.agentbox-backups/<timestamp>"
```

The rollback path restores `agentbox`, `agentbox-cli`, `agentbox-daemon`, and
`agentbox-shim`. It preserves config and evidence state.

For a local source install, manual binary removal is still possible. Use the
same prefix you used for installation:

```sh
AGENTBOX_LOCAL_PREFIX="$HOME/.local"
rm -f "$AGENTBOX_LOCAL_PREFIX/bin/agentbox" \
      "$AGENTBOX_LOCAL_PREFIX/bin/agentbox-cli" \
      "$AGENTBOX_LOCAL_PREFIX/bin/agentbox-daemon" \
      "$AGENTBOX_LOCAL_PREFIX/bin/agentbox-shim"
```

Use the CLI uninstall path to remove command shims and daemon pid/socket
artifacts while preserving evidence by default:

```sh
agentbox uninstall --dry-run
agentbox uninstall
```

Then remove Agentbox path entries from your shell profile if you no longer want
the prefix or shim directory on `PATH`.

The rollback commands intentionally preserve `~/.agentbox/config.toml`, audit
data, evidence, sessions, and other local state. Remove those only after
exporting or backing up anything you need.
