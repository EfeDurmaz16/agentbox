# Remote AgentPod

Remote AgentPod is the provider shape for attached machines, disposable workers,
and cloud-hosted execution cells. It is experimental and disabled by default.
`RemoteAgentPodProvider` becomes available only when
`AGENTBOX_REMOTE_AGENTPOD_ENDPOINT` points at an HTTPS worker endpoint.

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

## Transport Conformance

The daemon models the minimum remote transport contract in code without shipping
a network adapter yet. A conforming worker must:

- return a handshake acknowledgement without secret material
- acknowledge the lifecycle contract before session creation
- emit `WorkerAllocated` and `SessionCreated` for session creation
- emit `CommandStarted`, `CommandFinished`, and `EvidenceSealed` for command
  execution
- acknowledge submitted evidence bundle hashes and event counts without secret
  material
- emit `KillSwitchAck` and `WorkerDestroyed` for session destruction when the
  kill switch is required

The current test suite uses an in-memory fake transport to prove this schema and
lifecycle ordering. `RemoteAgentPodProvider` still returns unavailable until a
real HTTP, SSH, or tunnel adapter exists.

An HTTPS transport adapter now exists in the daemon code for the future worker
API. It posts:

- `POST /handshake`
- `POST /sessions`
- `POST /sessions/{worker_session_id}/exec`
- `POST /sessions/{worker_session_id}/evidence`
- `POST /sessions/{worker_session_id}/destroy`

The adapter validates the same handshake, create, exec, and lifecycle evidence
contracts before returning responses. The handshake path now routes
`ed25519:<challenge-id>:<signature>` acknowledgements through Ed25519 signature
verification and falls back to the legacy canonical digest verifier for older
fixtures. It is not wired into `RemoteAgentPodProvider` yet because there is no
shipped remote worker server.

Evidence upload is currently metadata-only: the worker must identify the session,
worker session, evidence mode, SHA-256 bundle hash, event count, and sealed time.
Agentbox rejects evidence upload metadata that embeds secret material, carries an
invalid bundle hash, or accepts a different bundle than the one submitted. The
actual evidence stream/storage backend is still future work.

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
`/sessions/{worker_session_id}/evidence`, and
`/sessions/{worker_session_id}/destroy` routes expected by the HTTPS adapter.
When `--state-dir` is set, created sessions, stopped status, and evidence
receipt metadata are written to `worker-sessions.json` and loaded again when the
worker starts. The smoke test restarts the worker process with the same state
directory and verifies that a previously created running session can execute
again after reload.
Worker contract violations such as unknown worker sessions, mismatched session
ids, unpreparable workspace paths, stopped-session exec, or invalid evidence
metadata return HTTP error statuses so the daemon-side transport treats them as
rejected remote operations.

This is still a contract worker, not the final sandboxed remote execution
engine. The `exec` route runs the provided argv directly, without invoking a
shell, and returns exit code, stdout, stderr, duration, and lifecycle evidence.
Exec now requires a created, running worker session, so the worker will not
accept an arbitrary `worker_session_id` before `/sessions` has allocated it.
Each worker session also carries the AgentPod workspace host path from the create
request. The worker prepares that directory during create-session and refuses to
record a running session if it cannot be created or is not a directory. Exec
defaults to that workspace and refuses an explicit working directory outside it.
The contract worker also refuses command environment material until an explicit
remote credential handoff protocol exists; remote env injection must not become
an accidental secret channel.
Evidence upload validates the evidence metadata and records an in-memory receipt
on the matching worker session before acknowledging the bundle hash and event
count. With `--state-dir`, those receipts are also persisted in the worker state
snapshot.
When the daemon-side provider creates a remote session, it persists the worker
endpoint, worker session id, worker identity, and worker evidence endpoint in
session labels so later exec/destroy calls can route back to the same worker.
Workspace materialization, policy enforcement, credential handoff, full evidence
bundle storage, and supervised worker restarts remain future work.

`scripts/smoke-remote-worker.sh` starts this worker on a random loopback port,
posts a handshake descriptor, checks the Ed25519 acknowledgement shape, creates
worker sessions from generated AgentPod specs, runs a direct `printf` exec
request, uploads a bundle metadata receipt, verifies the returned lifecycle
evidence, restarts the worker to prove persisted session reload, then starts a
long-running command and proves destroy sends a kill signal that returns exit
code `130` plus `KillSwitchAck`.

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
sandboxed remote execution, workspace materialization, policy enforcement inside
the worker, credential handoff, evidence streaming/storage, and live HTTPS
worker conformance tests.
