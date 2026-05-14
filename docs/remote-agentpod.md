# Remote AgentPod

Remote AgentPod is the provider shape for attached machines, disposable workers,
and cloud-hosted execution cells. It is experimental and disabled by default.
`RemoteAgentPodProvider` becomes available only when
`AGENTBOX_REMOTE_AGENTPOD_ENDPOINT` points at an HTTPS worker endpoint.
For local verification against `agentbox-remote-worker`, loopback-only HTTP can
be enabled with `AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1`; non-loopback
HTTP and credential-bearing endpoints remain rejected.
Create-session requests can also carry an optional hash-bound workspace bundle.
The worker verifies every indexed path, byte count, and SHA-256 digest before
materializing files into the worker workspace.
The provider builds that bundle only when
`AGENTBOX_REMOTE_AGENTPOD_WORKSPACE_BUNDLE=1` is set. The builder skips common
secret/generated paths, symlinks, non-UTF-8 files, and files over the configured
size limits.
Workers can export the current workspace as the same verified bundle shape from
`/sessions/{worker_session_id}/workspace/export`, allowing a later CLI flow to
review or pull changed files without trusting raw paths.

The product surface starts with a secret-free transport descriptor:

```sh
agentbox remote-descriptor \
  --endpoint https://worker.example.com/agentpod \
  --auth signed-challenge \
  --evidence append-only-stream
```

The descriptor records:

- the remote endpoint
- the auth model
- the evidence delivery mode
- whether a kill switch is required
- lifecycle timeouts and required worker/session events
- whether secret material is embedded

Agentbox rejects remote endpoints that are empty, use insecure `http://`, or
embed credentials in a non-SSH URL. The descriptor is intentionally not a worker
credential, tunnel config, or deployment artifact.

## Handshake Challenge

Remote workers must prove identity before Agentbox can treat the worker as a
governed execution target. The current CLI can emit a secret-free challenge
descriptor:

```sh
agentbox remote-handshake \
  --endpoint https://worker.example.com/agentpod \
  --auth signed-challenge \
  --ttl-seconds 300
```

The descriptor includes a challenge id, a SHA-256 digest of the nonce, an expiry
time, and the response fields a future worker must return:

- `WorkerIdentity`
- `WorkerPublicKey`
- `SignedChallenge`
- `Capabilities`
- `EvidenceEndpoint`
- `LifecycleAck`

It does not include the nonce itself or any credential material. Current
validation requires the acknowledgement signature field to bind the challenge id,
so a worker cannot return an unrelated signed payload and satisfy the contract.

The HTTPS adapter accepts two verifier paths. The legacy compatibility path
still enforces a canonical challenge-binding digest:

```text
agentbox-v1:<challenge-id>:sha256(<challenge-id>:<nonce-sha256>:<worker-identity>:<worker-public-key>)
```

The cryptographic path requires:

- `worker_public_key`: `ed25519:<hex-public-key>`
- `signed_challenge`: `ed25519:<challenge-id>:<hex-signature>`

The signature covers the challenge id, nonce digest, worker identity, worker
public key, and evidence endpoint. This gives the remote contract a real
challenge-bound worker identity proof while keeping future mTLS,
workload-identity, and SSH verifier modes pluggable.

## Evidence Upload Metadata

The CLI can emit the metadata a future worker would submit when uploading or
acknowledging sealed evidence:

```sh
agentbox remote-evidence \
  --session agentbox-session-id \
  --worker-session worker-session-id \
  --evidence bundle-upload \
  --bundle-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --event-count 12
```

If the session evidence was exported as a bundle directory, Agentbox can derive
the upload hash and event count from the verified bundle index instead:

```sh
agentbox evidence --session agentbox-session-id --bundle ./agentbox-evidence
agentbox remote-evidence \
  --session agentbox-session-id \
  --worker-session worker-session-id \
  --bundle-dir ./agentbox-evidence
```

This only validates and prints upload metadata. It does not upload evidence,
sign the bundle, or claim a live worker connection.
When `--bundle-dir` is used, the printed request includes `derived_from_bundle`,
`bundle_id`, and `bundle_root_sha256` so a future worker can distinguish manual
hash entry from metadata derived from a verified local bundle.
To upload both the evidence receipt and the verified bundle envelope to an HTTPS
worker:

```sh
agentbox remote-evidence-upload \
  --endpoint https://worker.example.com/agentpod \
  --session agentbox-session-id \
  --worker-session worker-session-id \
  --bundle-dir ./agentbox-evidence
```

The command verifies the local bundle directory, builds an
`AgentboxEvidenceBundleUpload` envelope, posts the receipt metadata, uploads the
bundle payload, and prints both validated worker acknowledgements.
When `agentbox run --provider remote-agentpod` is destroyed through the daemon,
the runtime also seals the final stopped-session evidence bundle after the local
`runtime.destroy` audit event is written, then sends the same receipt and
verified bundle envelope through the remote transport.
After a worker accepts evidence, the CLI can query its evidence status route:

```sh
agentbox remote-evidence-status \
  --endpoint https://worker.example.com/agentpod \
  --session agentbox-session-id \
  --worker-session worker-session-id
```

The command prints the validated worker response, including session status,
evidence metadata receipts, and stored bundle payload references.

Workers can also export the current session workspace as a verified pullback
bundle. The CLI validates the worker response, materializes the files into a
local review directory, and writes `agentbox-workspace-export.json` with the
session ids, file index, byte counts, and root hash:

```sh
agentbox remote-workspace-export \
  --endpoint https://worker.example.com/agentpod \
  --session agentbox-session-id \
  --worker-session worker-session-id \
  --output-dir ./agentbox-workspace-review
```

To apply a pulled export into a local workspace, use the separate apply command.
It verifies the manifest and file hashes before writing, supports `--dry-run`,
skips identical existing files as `unchanged`, and refuses to overwrite
conflicting existing files unless `--force` is set:

```sh
agentbox remote-workspace-apply \
  --export-dir ./agentbox-workspace-review \
  --workspace ./local-workspace \
  --dry-run
```

## Transport Conformance

The daemon models the minimum remote transport contract in code and ships an
HTTPS adapter for the gated worker path. A conforming worker must:

- return a handshake acknowledgement without secret material
- acknowledge the lifecycle contract before session creation
- emit `WorkerAllocated` and `SessionCreated` for session creation
- emit `CommandStarted`, `CommandFinished`, and `EvidenceSealed` for command
  execution
- acknowledge submitted evidence bundle hashes and event counts without secret
  material
- accept ordered evidence stream chunks only when chunk hashes, offsets, and
  session ids match
- emit `KillSwitchAck` and `WorkerDestroyed` for session destruction when the
  kill switch is required

The current test suite uses an in-memory fake transport to prove this schema and
lifecycle ordering. `RemoteAgentPodProvider` uses the HTTPS adapter when
`AGENTBOX_REMOTE_AGENTPOD_ENDPOINT` is configured.

An HTTPS transport adapter now exists in the daemon code for the future worker
API. It posts:

- `POST /handshake`
- `POST /sessions`
- `POST /sessions/{worker_session_id}/exec`
- `POST /sessions/{worker_session_id}/evidence`
- `GET /sessions/{worker_session_id}/evidence/status?session_id=...`
- `POST /sessions/{worker_session_id}/evidence/bundle`
- `POST /sessions/{worker_session_id}/evidence/stream`
- `POST /sessions/{worker_session_id}/destroy`

The adapter validates the same handshake, create, exec, evidence metadata,
evidence bundle payload, evidence stream chunk, and lifecycle contracts before
returning responses. The handshake path now routes
`ed25519:<challenge-id>:<signature>` acknowledgements through Ed25519 signature
verification and falls back to the legacy canonical digest verifier for older
fixtures.

Evidence metadata upload identifies the session, worker session, evidence mode,
SHA-256 bundle hash, event count, and sealed time. Agentbox rejects metadata that
embeds secret material, carries an invalid bundle hash, or accepts a different
bundle than the one submitted. The worker also exposes an experimental
`/evidence/bundle` payload route that requires `--state-dir`, verifies the
SHA-256 hash against the submitted JSON payload, rejects secret-bearing payloads,
and stores the bundle under the worker state directory. The stream route is
chunked and append-only, but full live event streaming into daemon-side evidence
readers is still future work.

## Contract Worker Binary

The repository now includes `agentbox-remote-worker`, a minimal Axum worker
server for exercising the remote contract:

```sh
cargo run -p agentbox-remote-worker -- \
  --listen 127.0.0.1:8787 \
  --worker worker.local/dev \
  --evidence-endpoint https://worker.example.com/agentpod/evidence \
  --state-dir .agentbox/remote-worker \
  --signing-key-hex 0000000000000000000000000000000000000000000000000000000000000001
```

The worker requires an explicit 32-byte hex Ed25519 seed. It signs handshake
acknowledgements using the Ed25519 format described above and exposes the same
`/handshake`, `/sessions`, `/sessions/{worker_session_id}/exec`,
`/sessions/{worker_session_id}/evidence`,
`/sessions/{worker_session_id}/evidence/bundle`,
`/sessions/{worker_session_id}/evidence/stream`, and
`/sessions/{worker_session_id}/destroy` routes expected by the HTTPS adapter.
When `--state-dir` is set, created sessions, stopped status, and evidence
receipt metadata are written to `worker-sessions.json` and loaded again when the
worker starts. The smoke test restarts the worker process with the same state
directory and verifies that a previously created running session can execute
again after reload.
Worker contract violations such as unknown worker sessions, mismatched session
ids, unsupported credential grant kinds, unpreparable workspace paths,
stopped-session exec, or invalid evidence metadata return HTTP error statuses
so the daemon-side transport treats them as rejected remote operations.
Mutating routes also bind the `{worker_session_id}` URL path to the JSON body
worker session id before applying exec, evidence, bundle, or destroy side
effects.
Create-session rejects duplicate worker session ids instead of replacing an
existing session snapshot.

This is still a contract worker, not the final sandboxed remote execution
engine. The `exec` route runs the provided argv directly, without invoking a
shell, and returns exit code, stdout, stderr, duration, and lifecycle evidence.
Exec now requires a created, running worker session, so the worker will not
accept an arbitrary `worker_session_id` before `/sessions` has allocated it.
Each worker session also carries the AgentPod workspace host path from the create
request. The worker prepares that directory during create-session and refuses to
record a running session if it cannot be created or is not a directory. Exec
defaults to that workspace and refuses an explicit working directory outside it.
The contract worker accepts explicit environment credential grant metadata from
the session manifest. During exec it only accepts command environment keys that
match those session-bound grant names; arbitrary env material is rejected so
remote env injection does not become an accidental secret channel. Create-session
still rejects file, socket, provider-token, and host environment inheritance
until those handoff protocols are explicit.
Before spawning a process, exec classifies the argv with the session AgentPod
network policy. Commands outside the allowed policy return exit code `126`
without being spawned. Approval-required commands can run only when the
session manifest already carries a matching, non-expired approval grant for the
command, path, domain, or session. `Once` approval grants are deliberately not
honored by the worker yet because the worker cannot safely synchronize one-time
grant consumption back to the daemon. Dynamic worker-side approval prompts are
still future work.
Evidence upload validates the evidence metadata and records an in-memory receipt
on the matching worker session before acknowledging the bundle hash and event
count. With `--state-dir`, those receipts are also persisted in the worker state
snapshot, including bundle provenance fields such as `bundle_id`,
`bundle_root_sha256`, `derived_from_bundle`, and `sealed_at` when provided.
The separate evidence bundle payload route verifies the submitted bundle JSON
against its SHA-256 and stores it under `evidence/<worker_session_id>/` inside
the worker state directory. The payload must be an
`AgentboxEvidenceBundleUpload` v1 envelope containing the verified bundle index
and indexed JSON file contents; the worker recomputes every file hash, byte
count, and the bundle root before accepting it. Successful payload storage is
also recorded on the matching worker session snapshot with the stored bundle
hash, byte count, and storage path so a restarted worker can prove which bundle
payloads it accepted.
The stream route accepts ordered, session-bound UTF-8 evidence chunks with a
per-chunk SHA-256, explicit offset, and final-chunk marker. The worker rejects
out-of-order chunks, rejects writes after a stream is sealed, and reports the
final stream SHA-256 in the acknowledgement and status response. This is the
first executable append-only stream contract; it is still not a full live event
bus or bidirectional approval channel.
Worker routes that mutate session state fail the request if the configured
state file cannot be serialized, prepared, or written; they do not acknowledge
state-changing operations as durable when persistence fails.
The status route returns the matching session status, command supervision
counters, the last command exit code/timestamp, evidence metadata receipts, and
stored bundle payload references, and evidence stream status after binding the
caller-provided `session_id` to the allocated `worker_session_id`. If a worker
restarts from persisted state, running command counters are reset to zero
because the current contract worker does not yet reattach to orphaned OS
processes.
When the daemon-side provider creates a remote session, it persists the worker
endpoint, worker session id, worker identity, and worker evidence endpoint in
session labels so later exec/destroy calls can route back to the same worker.
Runtime status refresh for remote sessions uses those labels to query the
worker evidence-status route instead of treating remote status as unavailable.
Workspace materialization, workspace export, local apply, worker-side command
policy, manifest-bound worker approval grants, command supervision counters, and
session-bound env credential handoff now exist as governed flows. Ordered
evidence stream chunks also exist at the worker contract layer. Dynamic
approval prompts, file/socket/provider-token credential handoff, full evidence
event streaming, supervised worker restarts, and merge/conflict UX beyond
overwrite protection remain future work.

`scripts/smoke-remote-worker.sh` starts this worker on a random loopback port,
posts a handshake descriptor, checks the Ed25519 acknowledgement shape, creates
worker sessions from generated AgentPod specs, runs a direct `printf` exec
request, proves session-bound env credential handoff through the provider path,
proves deny-by-default worker policy blocks an unknown `curl` before spawn,
exports the worker workspace through both direct HTTP and the CLI pullback
command, applies the pulled workspace to a local directory, uploads a bundle
metadata receipt, verifies the returned lifecycle evidence, uploads and verifies
a hash-bound bundle payload, uploads ordered evidence stream chunks and verifies
the sealed stream hash, restarts the worker to prove persisted session reload,
then starts a long-running command and proves destroy sends a kill signal that
returns exit code `130` plus `KillSwitchAck`.

## Lifecycle Contract

Remote workers must eventually prove lifecycle events rather than only returning
a command result. The current descriptor requires:

- `WorkerAllocated`
- `SessionCreated`
- `CommandStarted`
- `CommandFinished`
- `EvidenceSealed`
- `KillSwitchAck`
- `WorkerDestroyed`

The default lifecycle also carries create, command, idle, and destroy timeouts.
All timeouts must be non-zero. `EvidenceSealed` is mandatory, and
`KillSwitchAck` is mandatory whenever the kill switch is required, so remote
execution cannot silently ignore operator stop requests in a future
implementation.

## Auth Modes

| Mode | Use |
|------|-----|
| `signed-challenge` | Operator or controller signs a per-session challenge. |
| `workload-identity` | Remote worker authenticates through platform identity. |
| `mtls` | Worker and controller authenticate with mutual TLS. |
| `operator-ssh` | Operator-attached machine reached through SSH. |

## Evidence Modes

| Mode | Use |
|------|-----|
| `append-only-stream` | Worker streams audit events back during execution. |
| `bundle-upload` | Worker uploads a final evidence bundle after session stop. |
| `local-pull` | Operator pulls evidence from an attached worker. |

## Current Boundary

`remote-agentpod` is now an experimental gated provider. The missing pieces are
sandboxed remote execution, file/socket/provider-token credential handoff,
full live event streaming, supervised worker lifecycle, richer workspace merge
UX, and live HTTPS worker conformance tests.
