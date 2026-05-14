# Remote AgentPod

Remote AgentPod is the future provider shape for attached machines, disposable
workers, and cloud-hosted execution cells. It is not a runnable provider in this
repository yet.

The current product surface is a secret-free transport descriptor:

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

The HTTPS adapter also enforces a canonical challenge-binding digest:

```text
agentbox-v1:<challenge-id>:sha256(<challenge-id>:<nonce-sha256>:<worker-identity>:<worker-public-key>)
```

This is a verifier boundary, not final worker authentication. It proves the
adapter is no longer accepting loose challenge substrings, while keeping the
future Ed25519, mTLS, workload-identity, or SSH verifier pluggable.

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

This only validates and prints upload metadata. It does not upload evidence or
claim a live worker connection.

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
contracts before returning responses, and the handshake path now requires the
canonical challenge-binding verifier. It is not wired into
`RemoteAgentPodProvider` yet because there is no shipped remote worker server or
cryptographic signed response verifier.

Evidence upload is currently metadata-only: the worker must identify the session,
worker session, evidence mode, SHA-256 bundle hash, event count, and sealed time.
Agentbox rejects evidence upload metadata that embeds secret material, carries an
invalid bundle hash, or accepts a different bundle than the one submitted. The
actual evidence stream/storage backend is still future work.

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

`remote-agentpod` remains descriptor-only. The missing pieces are a live worker
server, cryptographic worker authentication, provider lifecycle wiring, command
execution, evidence streaming, credential handoff, kill switch enforcement, and
live conformance tests.
