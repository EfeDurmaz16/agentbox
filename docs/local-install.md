# Reproducible Local Install

This is the supported source install path for local development and operator
trials. It builds the shipped direct-host components from this checkout and
installs local binaries plus command shims. It does not install packaged
binaries, signed artifacts, native OS extensions, release services, network
services, or secrets.

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

## Rollback and Uninstall

There is no packaged uninstaller yet. For a local source install, rollback is
limited to files created by the commands above. Use the same prefix you used
for installation:

```sh
AGENTBOX_LOCAL_PREFIX="$HOME/.local"
rm -f "$AGENTBOX_LOCAL_PREFIX/bin/agentbox" \
      "$AGENTBOX_LOCAL_PREFIX/bin/agentbox-cli" \
      "$AGENTBOX_LOCAL_PREFIX/bin/agentbox-daemon" \
      "$AGENTBOX_LOCAL_PREFIX/bin/agentbox-shim"
rm -f "$HOME/.agentbox/shims/"*
```

Then remove the Agentbox path entries from your shell profile.

The rollback commands intentionally preserve `~/.agentbox/config.toml`, audit
data, evidence, sessions, and other local state. Remove those only after
exporting or backing up anything you need.
