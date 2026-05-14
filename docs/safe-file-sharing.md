# Safe File Sharing Into Minipods

Agentbox minipods should receive the smallest useful file surface for a task.
Do not treat a minipod like a second terminal with the whole home directory
mounted inside it.

## Default Shape

Every generated minipod has one workspace boundary:

```text
host workspace -> /workspace
```

Use a narrow project directory as the workspace. Avoid launching a minipod from
`$HOME`, `~/Desktop`, or a parent directory that contains unrelated projects,
credentials, browser profiles, or deployment state.

## Read-Only Host Mounts

Use read-only mounts for reference material the agent may inspect but should not
change:

```sh
agentbox minipod-spec hermes \
  --workspace ./task \
  --mount-ro ./docs:/mnt/docs

agentbox run --runtime node \
  --mount-ro ./fixtures:/mnt/fixtures \
  npm test
```

Task-scoped policy bundles can carry the same read-only mounts alongside
allowed domains, denied domains, approval grants, protected paths, and explicit
credential grants:

```sh
agentbox minipod-spec hermes \
  --workspace ./task \
  --policy-bundle ./agentbox.task-policy.json
```

Bundle mounts are validated as read-only. Credential grants inside a bundle are
still explicit grants and should require approval; a bundle is manifest-time
policy composition, not a signed authority boundary by itself.

These mounts are represented as:

```json
{
  "host_path": "./fixtures",
  "guest_path": "/mnt/fixtures",
  "mode": "ReadOnly",
  "kind": "ReadOnlyHost"
}
```

The `kind` field is intentionally separate from read/write mode. It lets
Agentbox distinguish ordinary read-only reference mounts from credential mounts,
system bridges, service data, and future custom boundary types.

## Sensitive Paths

Agentbox denies sensitive host paths by default. Examples include:

- `~/.ssh`
- `~/.aws`
- `~/.config/gcloud`
- `~/Library/Application Support`
- `~/Library/Keychains`
- `~/.env`

Do not mount these paths as normal workspace or read-only host mounts. If a task
really needs a credential, model it as an explicit credential grant rather than a
general host mount.

## Credential Grants

Credential grants are first-class minipod manifest entries for exact files or
future provider-mediated secret sources. `--credential-file name=host:guest`
creates a read-only credential mount and a one-time file grant, and provider
adapters preserve that metadata separately from ordinary read-only mounts.

Until native provider enforcement is complete:

- prefer short-lived task-specific tokens
- pass only the exact file or env value needed
- avoid mounting whole credential directories
- avoid inheriting the host environment
- verify evidence export after credential-sensitive runs

Host environment inheritance is rejected by manifest validation.

## System Bridges

System bridges are host connections such as:

- the Agentbox daemon socket
- shim binaries
- future browser, keychain, or cloud CLI mediation sockets

They should be inserted by Agentbox runtime providers, not by arbitrary user
mounts. A system bridge is not ordinary task data.

## Recommended Patterns

Use these patterns:

- one narrow writable workspace
- read-only mounts for fixtures, docs, source snapshots, or generated inputs
- explicit sidecars for databases and services
- explicit credential grants for secrets
- `agentbox minipod-spec` before running unfamiliar workflows
- `agentbox minipod-inspect` after creating persistent sessions
- `agentbox evidence` after sensitive runs

Avoid these patterns:

- mounting `$HOME`
- mounting browser profiles
- mounting cloud CLI config directories
- mounting SSH directories
- mounting keychains
- letting agents inherit the full host environment
- treating Podman/VM-backed macOS minipods as bypass-proof native enforcement

## Verification

Useful checks:

```sh
agentbox minipod-spec hermes --workspace ./task --mount-ro ./docs:/mnt/docs
agentbox providers
agentbox evidence --limit 20
```

For live Podman-backed minipods, socket and shim execution proof remain separate
smoke-test work items.
