#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMPDIR="$(mktemp -d)"
WORKER_PID=""
trap 'if [[ -n "$WORKER_PID" ]]; then kill "$WORKER_PID" 2>/dev/null || true; wait "$WORKER_PID" 2>/dev/null || true; fi; rm -rf "$TMPDIR"' EXIT

PORT="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"

SIGNING_KEY_HEX="0000000000000000000000000000000000000000000000000000000000000021"

cargo run --locked -q -p agentbox-remote-worker -- \
  --listen "127.0.0.1:${PORT}" \
  --worker worker.local/smoke \
  --evidence-endpoint https://worker.example.com/agentpod/evidence \
  --state-dir "$TMPDIR/worker-state" \
  --signing-key-hex "$SIGNING_KEY_HEX" >"$TMPDIR/worker.out" 2>"$TMPDIR/worker.err" &
WORKER_PID="$!"

for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:${PORT}/handshake" \
    -H 'content-type: application/json' \
    --data '{"schema_version":1,"provider":"remote-agentpod","endpoint":"https://worker.example.com/agentpod","auth_kind":"SignedChallenge","challenge_id":"agentpod-challenge-smoke","challenge_nonce_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","expires_at":"2026-05-14T23:59:59Z","required_response_fields":["WorkerIdentity","WorkerPublicKey","SignedChallenge","Capabilities","EvidenceEndpoint","LifecycleAck"],"secret_material_included":false,"created_at":"2026-05-14T00:00:00Z"}' \
    >"$TMPDIR/handshake-ack.json" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

python3 - "$TMPDIR/handshake-ack.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["worker_identity"] == "worker.local/smoke"
assert data["worker_public_key"].startswith("ed25519:")
assert data["signed_challenge"].startswith("ed25519:agentpod-challenge-smoke:")
assert data["lifecycle_ack"] is True
assert data["secret_material_included"] is False
PY

mkdir -p "$TMPDIR/home"
cargo build --locked -q -p agentbox-cli
AGENTBOX_REMOTE_AGENTPOD_ENDPOINT="http://127.0.0.1:${PORT}" \
AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 \
HOME="$TMPDIR/home" \
"$ROOT/target/debug/agentbox-cli" run \
  --provider remote-agentpod \
  --json \
  -- \
  printf provider-remote-smoke >"$TMPDIR/provider-run.json"

python3 - "$TMPDIR/provider-run.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["session"]["provider"] == "remote-agentpod"
assert data["session"]["status"] == "Running"
assert data["command_result"]["exit_code"] == 0
assert data["command_result"]["stdout"] == "provider-remote-smoke"
assert data["destroyed"] is True
assert data["cleanup_error"] is None
PY

AGENTBOX_REMOTE_AGENTPOD_ENDPOINT="http://127.0.0.1:${PORT}" \
AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 \
AGENTBOX_REMOTE_AGENTPOD_TOKEN="remote-env-smoke" \
HOME="$TMPDIR/home" \
"$ROOT/target/debug/agentbox-cli" run \
  --provider remote-agentpod \
  --credential-env AGENTBOX_REMOTE_TOKEN=AGENTBOX_REMOTE_AGENTPOD_TOKEN \
  --json \
  -- \
  sh -c 'printf %s "$AGENTBOX_REMOTE_TOKEN"' >"$TMPDIR/provider-env-run.json"

python3 - "$TMPDIR/provider-env-run.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["session"]["provider"] == "remote-agentpod"
assert data["command_result"]["exit_code"] == 0
assert data["command_result"]["stdout"] == "remote-env-smoke"
assert data["destroyed"] is True
assert data["cleanup_error"] is None
PY

printf remote-file-smoke >"$TMPDIR/provider-file-token"
(
  cd "$TMPDIR"
  AGENTBOX_REMOTE_AGENTPOD_ENDPOINT="http://127.0.0.1:${PORT}" \
  AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 \
  HOME="$TMPDIR/home" \
  "$ROOT/target/debug/agentbox-cli" run \
    --provider remote-agentpod \
    --credential-file "remote_token=$TMPDIR/provider-file-token:/workspace/.agentbox/credentials/remote-token" \
    --json \
    -- \
    sh -c 'printf %s "$(cat "$AGENTBOX_CREDENTIAL_FILE_REMOTE_TOKEN")"'
) >"$TMPDIR/provider-file-run.json"

python3 - "$TMPDIR/provider-file-run.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["session"]["provider"] == "remote-agentpod"
assert data["command_result"]["exit_code"] == 0
assert data["command_result"]["stdout"] == "remote-file-smoke"
assert "remote-file-smoke" not in data["command_result"].get("stderr", "")
assert data["destroyed"] is True
assert data["cleanup_error"] is None
PY

mkdir -p "$TMPDIR/workspace"
printf remote-status-file-smoke >"$TMPDIR/status-file-token"
cargo run --locked -q -p agentbox-cli -- minipod-spec remote-smoke \
  --risk medium \
  --workspace "$TMPDIR/workspace" \
  --credential-env AGENTBOX_REMOTE_TOKEN=AGENTBOX_REMOTE_AGENTPOD_TOKEN \
  --credential-file "remote_token=$TMPDIR/status-file-token:/workspace/.agentbox/credentials/remote-token" \
  >"$TMPDIR/spec.json"
python3 - "$TMPDIR/spec.json" "$TMPDIR/handshake-ack.json" "$TMPDIR/status-file-token" >"$TMPDIR/create-request.json" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    spec = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    handshake_ack = json.load(fh)
with open(sys.argv[3], "r", encoding="utf-8") as fh:
    credential_contents = fh.read()

now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
json.dump({
    "transport": {
        "schema_version": 1,
        "provider": "remote-agentpod",
        "endpoint": "https://worker.example.com/agentpod",
        "auth_kind": "SignedChallenge",
        "evidence_mode": "BundleUpload",
        "kill_switch_required": True,
        "secret_material_included": False,
        "lifecycle": {
            "schema_version": 1,
            "create_timeout_seconds": 120,
            "command_timeout_seconds": 3600,
            "idle_timeout_seconds": 300,
            "destroy_timeout_seconds": 60,
            "heartbeat_interval_seconds": 30,
            "restart_policy": {
                "strategy": "OnFailure",
                "max_attempts": 2,
                "backoff_ms": 1000,
            },
            "required_events": [
                "WorkerAllocated",
                "SessionCreated",
                "CommandStarted",
                "CommandFinished",
                "EvidenceSealed",
                "KillSwitchAck",
                "WorkerDestroyed",
            ],
            "kill_switch_required": True,
        },
        "created_at": now,
    },
    "handshake_ack": handshake_ack,
    "spec": spec,
    "credential_files": [{
        "name": "remote_token",
        "guest_path": "/workspace/.agentbox/credentials/remote-token",
        "sha256": hashlib.sha256(credential_contents.encode("utf-8")).hexdigest(),
        "bytes": len(credential_contents.encode("utf-8")),
        "contents_utf8": credential_contents,
        "one_time": True,
    }],
}, sys.stdout)
PY

curl -fsS "http://127.0.0.1:${PORT}/sessions" \
  -H 'content-type: application/json' \
  --data @"$TMPDIR/create-request.json" \
  >"$TMPDIR/create-response.json"
SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session_id"])' "$TMPDIR/create-response.json")"
WORKER_SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["worker_session_id"])' "$TMPDIR/create-response.json")"

curl -fsS "http://127.0.0.1:${PORT}/sessions/${WORKER_SESSION_ID}/evidence/status?session_id=${SESSION_ID}" \
  >"$TMPDIR/create-status.json"

python3 - "$TMPDIR/create-status.json" "$TMPDIR/status-file-token" <<'PY'
import hashlib
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    file_token = fh.read()

credentials = {credential["name"]: credential for credential in data["credentials"]}
assert credentials["AGENTBOX_REMOTE_TOKEN"]["kind"] == "EnvVar"
assert "sha256" not in credentials["AGENTBOX_REMOTE_TOKEN"]
assert credentials["remote_token"]["kind"] == "FileMount"
assert credentials["remote_token"]["guest_path"] == "/workspace/.agentbox/credentials/remote-token"
assert credentials["remote_token"]["sha256"] == hashlib.sha256(file_token.encode("utf-8")).hexdigest()
assert credentials["remote_token"]["bytes"] == len(file_token.encode("utf-8"))
assert credentials["remote_token"]["one_time"] is True
assert file_token not in json.dumps(data)
PY

curl -fsS "http://127.0.0.1:${PORT}/sessions/${WORKER_SESSION_ID}/exec" \
  -H 'content-type: application/json' \
  --data "{\"session_id\":\"${SESSION_ID}\",\"worker_session_id\":\"${WORKER_SESSION_ID}\",\"command\":{\"argv\":[\"printf\",\"remote-worker-smoke\"],\"working_dir\":null,\"env\":{},\"timeout_seconds\":5}}" \
  >"$TMPDIR/exec-response.json"

python3 - "$TMPDIR/exec-response.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["result"]["exit_code"] == 0
assert data["result"]["stdout"] == "remote-worker-smoke"
assert "EvidenceSealed" in data["lifecycle_events"]
PY

mkdir -p "$TMPDIR/policy-workspace"
cargo run --locked -q -p agentbox-cli -- minipod-spec remote-policy-smoke \
  --risk medium \
  --workspace "$TMPDIR/policy-workspace" \
  --network-mode deny-by-default \
  >"$TMPDIR/policy-spec.json"
python3 - "$TMPDIR/policy-spec.json" "$TMPDIR/handshake-ack.json" >"$TMPDIR/policy-create-request.json" <<'PY'
import json
import sys
from datetime import datetime, timezone

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    spec = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    handshake_ack = json.load(fh)

now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
json.dump({
    "transport": {
        "schema_version": 1,
        "provider": "remote-agentpod",
        "endpoint": "https://worker.example.com/agentpod",
        "auth_kind": "SignedChallenge",
        "evidence_mode": "BundleUpload",
        "kill_switch_required": True,
        "secret_material_included": False,
        "lifecycle": {
            "schema_version": 1,
            "create_timeout_seconds": 120,
            "command_timeout_seconds": 3600,
            "idle_timeout_seconds": 300,
            "destroy_timeout_seconds": 60,
            "heartbeat_interval_seconds": 30,
            "restart_policy": {
                "strategy": "OnFailure",
                "max_attempts": 2,
                "backoff_ms": 1000,
            },
            "required_events": [
                "WorkerAllocated",
                "SessionCreated",
                "CommandStarted",
                "CommandFinished",
                "EvidenceSealed",
                "KillSwitchAck",
                "WorkerDestroyed",
            ],
            "kill_switch_required": True,
        },
        "created_at": now,
    },
    "handshake_ack": handshake_ack,
    "spec": spec,
}, sys.stdout)
PY

curl -fsS "http://127.0.0.1:${PORT}/sessions" \
  -H 'content-type: application/json' \
  --data @"$TMPDIR/policy-create-request.json" \
  >"$TMPDIR/policy-create-response.json"
POLICY_SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session_id"])' "$TMPDIR/policy-create-response.json")"
POLICY_WORKER_SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["worker_session_id"])' "$TMPDIR/policy-create-response.json")"

curl -fsS "http://127.0.0.1:${PORT}/sessions/${POLICY_WORKER_SESSION_ID}/exec" \
  -H 'content-type: application/json' \
  --data "{\"session_id\":\"${POLICY_SESSION_ID}\",\"worker_session_id\":\"${POLICY_WORKER_SESSION_ID}\",\"command\":{\"argv\":[\"curl\",\"https://unknown.example.com\"],\"working_dir\":null,\"env\":{},\"timeout_seconds\":5}}" \
  >"$TMPDIR/policy-exec-response.json"

python3 - "$TMPDIR/policy-exec-response.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["result"]["exit_code"] == 126
assert "policy denied" in data["result"]["stderr"]
assert "unknown.example.com" in data["result"]["stderr"]
assert "EvidenceSealed" in data["lifecycle_events"]
PY

mkdir -p "$TMPDIR/approval-workspace"
cargo run --locked -q -p agentbox-cli -- minipod-spec remote-approval-smoke \
  --risk medium \
  --workspace "$TMPDIR/approval-workspace" \
  --network-mode first-contact \
  >"$TMPDIR/approval-spec.json"
python3 - "$TMPDIR/approval-spec.json" "$TMPDIR/handshake-ack.json" >"$TMPDIR/approval-create-request.json" <<'PY'
import json
import sys
from datetime import datetime, timezone

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    spec = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    handshake_ack = json.load(fh)

now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
json.dump({
    "transport": {
        "schema_version": 1,
        "provider": "remote-agentpod",
        "endpoint": "https://worker.example.com/agentpod",
        "auth_kind": "SignedChallenge",
        "evidence_mode": "BundleUpload",
        "kill_switch_required": True,
        "secret_material_included": False,
        "lifecycle": {
            "schema_version": 1,
            "create_timeout_seconds": 120,
            "command_timeout_seconds": 3600,
            "idle_timeout_seconds": 300,
            "destroy_timeout_seconds": 60,
            "heartbeat_interval_seconds": 30,
            "restart_policy": {
                "strategy": "OnFailure",
                "max_attempts": 2,
                "backoff_ms": 1000,
            },
            "required_events": [
                "WorkerAllocated",
                "SessionCreated",
                "CommandStarted",
                "CommandFinished",
                "EvidenceSealed",
                "KillSwitchAck",
                "WorkerDestroyed",
            ],
            "kill_switch_required": True,
        },
        "created_at": now,
    },
    "handshake_ack": handshake_ack,
    "spec": spec,
}, sys.stdout)
PY

curl -fsS "http://127.0.0.1:${PORT}/sessions" \
  -H 'content-type: application/json' \
  --data @"$TMPDIR/approval-create-request.json" \
  >"$TMPDIR/approval-create-response.json"
APPROVAL_SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session_id"])' "$TMPDIR/approval-create-response.json")"
APPROVAL_WORKER_SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["worker_session_id"])' "$TMPDIR/approval-create-response.json")"

curl -fsS "http://127.0.0.1:${PORT}/sessions/${APPROVAL_WORKER_SESSION_ID}/exec" \
  -H 'content-type: application/json' \
  --data "{\"session_id\":\"${APPROVAL_SESSION_ID}\",\"worker_session_id\":\"${APPROVAL_WORKER_SESSION_ID}\",\"command\":{\"argv\":[\"curl\",\"https://approval.example.com\"],\"working_dir\":null,\"env\":{},\"timeout_seconds\":1}}" \
  >"$TMPDIR/approval-exec-response.json"
curl -fsS "http://127.0.0.1:${PORT}/sessions/${APPROVAL_WORKER_SESSION_ID}/evidence/status?session_id=${APPROVAL_SESSION_ID}" \
  >"$TMPDIR/approval-status-before.json"
APPROVAL_REQUEST_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pending_approvals"][0]["request_id"])' "$TMPDIR/approval-status-before.json")"

AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 \
"$ROOT/target/debug/agentbox-cli" remote-approval-grant \
  --endpoint "http://127.0.0.1:${PORT}" \
  --session "$APPROVAL_SESSION_ID" \
  --worker-session "$APPROVAL_WORKER_SESSION_ID" \
  --request "$APPROVAL_REQUEST_ID" \
  --ttl-seconds 60 \
  >"$TMPDIR/approval-grant-response.json"

curl -fsS "http://127.0.0.1:${PORT}/sessions/${APPROVAL_WORKER_SESSION_ID}/exec" \
  -H 'content-type: application/json' \
  --data "{\"session_id\":\"${APPROVAL_SESSION_ID}\",\"worker_session_id\":\"${APPROVAL_WORKER_SESSION_ID}\",\"command\":{\"argv\":[\"curl\",\"https://approval.example.com\"],\"working_dir\":null,\"env\":{},\"timeout_seconds\":1}}" \
  >"$TMPDIR/approval-exec-after-grant-response.json"
curl -fsS "http://127.0.0.1:${PORT}/sessions/${APPROVAL_WORKER_SESSION_ID}/evidence/status?session_id=${APPROVAL_SESSION_ID}" \
  >"$TMPDIR/approval-status-after.json"

python3 - "$TMPDIR/approval-exec-response.json" "$TMPDIR/approval-status-before.json" "$TMPDIR/approval-grant-response.json" "$TMPDIR/approval-exec-after-grant-response.json" "$TMPDIR/approval-status-after.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    before_exec = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    before_status = json.load(fh)
with open(sys.argv[3], "r", encoding="utf-8") as fh:
    grant = json.load(fh)
with open(sys.argv[4], "r", encoding="utf-8") as fh:
    after_exec = json.load(fh)
with open(sys.argv[5], "r", encoding="utf-8") as fh:
    after_status = json.load(fh)

assert before_exec["result"]["exit_code"] == 126
assert "policy denied" in before_exec["result"]["stderr"]
assert before_status["pending_approvals"]
assert grant["remaining_pending_approvals"] == 0
assert after_status["pending_approvals"] == []
assert "policy denied" not in after_exec["result"]["stderr"]
PY

printf 'worker export smoke\n' >"$TMPDIR/workspace/export.txt"
curl -fsS "http://127.0.0.1:${PORT}/sessions/${WORKER_SESSION_ID}/workspace/export?session_id=${SESSION_ID}" \
  >"$TMPDIR/workspace-export-response.json"

python3 - "$TMPDIR/workspace-export-response.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["workspace_bundle"]["schema_version"] == 1
paths = {file["path"]: file for file in data["workspace_bundle"]["files"]}
assert paths["export.txt"]["contents_utf8"] == "worker export smoke\n"
assert "EvidenceSealed" in data["lifecycle_events"]
PY

AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 \
"$ROOT/target/debug/agentbox-cli" remote-workspace-export \
  --endpoint "http://127.0.0.1:${PORT}" \
  --session "$SESSION_ID" \
  --worker-session "$WORKER_SESSION_ID" \
  --output-dir "$TMPDIR/workspace-pullback" \
  --json >"$TMPDIR/workspace-pullback.json"

python3 - "$TMPDIR/workspace-pullback.json" "$TMPDIR/workspace-pullback" <<'PY'
import json
import pathlib
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

pullback = pathlib.Path(sys.argv[2])
assert data["file_count"] >= 1
assert data["root_sha256"]
assert (pullback / "export.txt").read_text(encoding="utf-8") == "worker export smoke\n"
assert (pullback / "agentbox-workspace-export.json").exists()
PY

"$ROOT/target/debug/agentbox-cli" remote-workspace-apply \
  --export-dir "$TMPDIR/workspace-pullback" \
  --workspace "$TMPDIR/workspace-applied" \
  --json >"$TMPDIR/workspace-apply.json"
"$ROOT/target/debug/agentbox-cli" remote-workspace-apply \
  --export-dir "$TMPDIR/workspace-pullback" \
  --workspace "$TMPDIR/workspace-applied" \
  --dry-run \
  --json >"$TMPDIR/workspace-apply-unchanged.json"

python3 - "$TMPDIR/workspace-apply.json" "$TMPDIR/workspace-apply-unchanged.json" "$TMPDIR/workspace-applied" <<'PY'
import json
import pathlib
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    unchanged = json.load(fh)

applied = pathlib.Path(sys.argv[3])
assert data["applied_files"] >= 1
assert data["conflict_files"] == 0
assert unchanged["conflict_files"] == 0
assert unchanged["unchanged_files"] >= 1
assert any(file["action"] == "unchanged" for file in unchanged["files"])
assert (applied / "export.txt").read_text(encoding="utf-8") == "worker export smoke\n"
PY

SEALED_AT="$(python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
PY
)"
curl -fsS "http://127.0.0.1:${PORT}/sessions/${WORKER_SESSION_ID}/evidence" \
  -H 'content-type: application/json' \
  --data "{\"session_id\":\"${SESSION_ID}\",\"worker_session_id\":\"${WORKER_SESSION_ID}\",\"evidence_mode\":\"BundleUpload\",\"bundle_sha256\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"derived_from_bundle\":false,\"bundle_id\":null,\"bundle_root_sha256\":null,\"event_count\":2,\"sealed_at\":\"${SEALED_AT}\",\"secret_material_included\":false}" \
  >"$TMPDIR/evidence-response.json"

python3 - "$TMPDIR/evidence-response.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["accepted_bundle_sha256"] == "f" * 64
assert data["accepted_event_count"] == 2
assert "EvidenceSealed" in data["lifecycle_events"]
PY

printf 'remote stream\n' >"$TMPDIR/stream.txt"
python3 - "$TMPDIR" <<'PY'
import hashlib
import sys

tmpdir = sys.argv[1]
with open(f"{tmpdir}/stream.expected", "w", encoding="utf-8") as fh:
    fh.write(hashlib.sha256("remote stream\n".encode()).hexdigest())
PY

AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 \
"$ROOT/target/debug/agentbox-cli" remote-evidence-stream \
  --endpoint "http://127.0.0.1:${PORT}" \
  --session "$SESSION_ID" \
  --worker-session "$WORKER_SESSION_ID" \
  --stream stdout \
  --file "$TMPDIR/stream.txt" \
  --chunk-bytes 7 \
  >"$TMPDIR/stream-response.json"

python3 - "$TMPDIR/stream-response.json" "$TMPDIR/stream.expected" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    expected_stream_hash = fh.read().strip()

assert data["chunk_count"] == 2
assert data["stream_sha256"] == expected_stream_hash
first = data["chunks"][0]
second = data["chunks"][1]
assert first["accepted_sequence"] == 0
assert first["accepted_offset"] == 0
assert first["accepted_bytes"] == 7
assert first.get("stream_sha256") is None
assert second["accepted_sequence"] == 1
assert second["accepted_offset"] == 7
assert second["accepted_bytes"] == 7
assert second["stream_sha256"] == expected_stream_hash
assert "EvidenceSealed" in second["lifecycle_events"]
PY

python3 - "$TMPDIR" "$SESSION_ID" "$WORKER_SESSION_ID" <<'PY'
import hashlib
import json
import sys

tmpdir, session_id, worker_session_id = sys.argv[1:4]
bundle_file = json.dumps(
    {
        "schema_version": 1,
        "session_id": session_id,
        "commands": [{"audit_event_id": "evt_1"}],
        "approvals": [],
        "lifecycle_events": [],
        "boundary_events": [],
        "credential_events": [],
    },
    separators=(",", ":"),
)
manifest_file = json.dumps(
    {"schema_version": 1, "kind": "AgentPod"},
    separators=(",", ":"),
)
files = []
for path, contents in [
    ("bundle.json", bundle_file),
    ("manifest.json", manifest_file),
]:
    files.append(
        {
            "path": path,
            "media_type": "application/json",
            "description": "remote worker smoke evidence file",
            "sha256": hashlib.sha256(contents.encode()).hexdigest(),
            "bytes": len(contents.encode()),
        }
    )
root_entries = [
    f"{entry['path']}\0{entry['sha256']}\0{entry['bytes']}\0{entry['media_type']}"
    for entry in sorted(files, key=lambda value: value["path"])
]
root_sha256 = hashlib.sha256(
    ("agentbox-evidence-root-v1\n" + "\n".join(root_entries)).encode()
).hexdigest()
bundle_json = json.dumps(
    {
        "schema_version": 1,
        "kind": "AgentboxEvidenceBundleUpload",
        "session_id": session_id,
        "worker_session_id": worker_session_id,
        "index": {
            "schema_version": 1,
            "bundle_id": "smoke-bundle",
            "session_id": session_id,
            "provider": "direct-host",
            "status": "Stopped",
            "root_sha256": root_sha256,
            "files": files,
        },
        "files": {
            "bundle.json": bundle_file,
            "manifest.json": manifest_file,
        },
    },
    separators=(",", ":"),
)
bundle_sha256 = hashlib.sha256(bundle_json.encode()).hexdigest()
with open(f"{tmpdir}/evidence-bundle-upload.json", "w", encoding="utf-8") as fh:
    json.dump(
        {
            "session_id": session_id,
            "worker_session_id": worker_session_id,
            "bundle_sha256": bundle_sha256,
            "bundle_json": bundle_json,
            "secret_material_included": False,
        },
        fh,
    )
with open(f"{tmpdir}/evidence-bundle-upload.expected", "w", encoding="utf-8") as fh:
    fh.write(bundle_sha256)
PY

curl -fsS "http://127.0.0.1:${PORT}/sessions/${WORKER_SESSION_ID}/evidence/bundle" \
  -H 'content-type: application/json' \
  --data @"$TMPDIR/evidence-bundle-upload.json" \
  >"$TMPDIR/evidence-bundle-upload-response.json"

python3 - "$TMPDIR/evidence-bundle-upload-response.json" "$TMPDIR/evidence-bundle-upload.expected" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    expected_hash = fh.read().strip()

assert data["stored_bundle_sha256"] == expected_hash
assert data["stored_bytes"] > 0
assert data["storage_path"].endswith(f"{expected_hash}.json")
assert "EvidenceSealed" in data["lifecycle_events"]
with open(data["storage_path"], "r", encoding="utf-8") as fh:
    stored = fh.read()
assert stored
PY

curl -fsS "http://127.0.0.1:${PORT}/sessions/${WORKER_SESSION_ID}/evidence/status?session_id=${SESSION_ID}" \
  >"$TMPDIR/evidence-status.json"

python3 - "$TMPDIR/evidence-status.json" "$TMPDIR/evidence-bundle-upload.expected" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    expected_bundle_hash = fh.read().strip()

assert data["status"] == "Running"
assert data["commands_started"] >= 1
assert data["commands_finished"] >= 1
assert data["active_command_count"] == 0
assert data["last_command_exit_code"] == 0
assert data["last_command_finished_at"]
assert data["restart_policy"]["strategy"] == "OnFailure"
assert data["restart_policy"]["max_attempts"] == 2
assert data["heartbeat_interval_seconds"] == 30
assert data["last_heartbeat_at"]
assert data["supervision"]["boot_count"] == 1
assert data["supervision"]["persistence"] == "StateDir"
assert data["supervision"]["recovered_sessions"] == 0
assert data["kill_switch_armed"] is True
assert data["evidence_sealed"] is True
assert data["evidence_receipts"][0]["bundle_sha256"] == "f" * 64
assert data["evidence_receipts"][0]["event_count"] == 2
assert data["stored_evidence_bundles"][0]["bundle_sha256"] == expected_bundle_hash
assert data["stored_evidence_bundles"][0]["stored_bytes"] > 0
assert data["evidence_streams"][0]["stream_id"] == "stdout"
assert data["evidence_streams"][0]["next_sequence"] == 2
assert data["evidence_streams"][0]["next_offset"] == 14
assert data["evidence_streams"][0]["received_bytes"] == 14
assert data["evidence_streams"][0]["sealed"] is True
PY

python3 - "$TMPDIR/worker-state/worker-sessions.json" "$SESSION_ID" "$WORKER_SESSION_ID" "$TMPDIR/evidence-bundle-upload.expected" "$TMPDIR/stream.expected" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    sessions = json.load(fh)
with open(sys.argv[4], "r", encoding="utf-8") as fh:
    expected_bundle_hash = fh.read().strip()
with open(sys.argv[5], "r", encoding="utf-8") as fh:
    expected_stream_hash = fh.read().strip()

matches = [
    session for session in sessions
    if session["session_id"] == sys.argv[2]
    and session["worker_session_id"] == sys.argv[3]
]
assert matches
assert matches[0]["status"] == "Running"
assert matches[0]["commands_started"] >= 1
assert matches[0]["commands_finished"] >= 1
assert matches[0]["active_command_count"] == 0
assert matches[0]["last_command_exit_code"] == 0
assert matches[0]["last_command_finished_at"]
assert matches[0]["evidence_receipts"][0]["bundle_sha256"] == "f" * 64
assert matches[0]["evidence_receipts"][0]["event_count"] == 2
assert matches[0]["stored_evidence_bundles"][0]["bundle_sha256"] == expected_bundle_hash
assert matches[0]["stored_evidence_bundles"][0]["stored_bytes"] > 0
assert matches[0]["stored_evidence_bundles"][0]["storage_path"].endswith(
    f"{expected_bundle_hash}.json"
)
assert matches[0]["evidence_streams"][0]["stream_id"] == "stdout"
assert matches[0]["evidence_streams"][0]["stream_sha256"] == expected_stream_hash
assert matches[0]["evidence_streams"][0]["contents_utf8"] == "remote stream\n"
PY

curl -fsS "http://127.0.0.1:${PORT}/worker/status" >"$TMPDIR/worker-status-before-restart.json"

python3 - "$TMPDIR/worker-status-before-restart.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["boot_count"] == 1
assert data["previous_boot_id"] is None
assert data["persistence"] == "StateDir"
assert data["boot_id"].startswith("worker-")
PY

kill "$WORKER_PID"
wait "$WORKER_PID" 2>/dev/null || true
WORKER_PID=""

cargo run --locked -q -p agentbox-remote-worker -- \
  --listen "127.0.0.1:${PORT}" \
  --worker worker.local/smoke \
  --evidence-endpoint https://worker.example.com/agentpod/evidence \
  --state-dir "$TMPDIR/worker-state" \
  --signing-key-hex "$SIGNING_KEY_HEX" >"$TMPDIR/worker-restarted.out" 2>"$TMPDIR/worker-restarted.err" &
WORKER_PID="$!"

for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:${PORT}/handshake" \
    -H 'content-type: application/json' \
    --data '{"schema_version":1,"provider":"remote-agentpod","endpoint":"https://worker.example.com/agentpod","auth_kind":"SignedChallenge","challenge_id":"agentpod-challenge-smoke-restarted","challenge_nonce_sha256":"1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","expires_at":"2026-05-14T23:59:59Z","required_response_fields":["WorkerIdentity","WorkerPublicKey","SignedChallenge","Capabilities","EvidenceEndpoint","LifecycleAck"],"secret_material_included":false,"created_at":"2026-05-14T00:00:00Z"}' \
    >"$TMPDIR/restarted-handshake-ack.json" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

curl -fsS "http://127.0.0.1:${PORT}/worker/status" >"$TMPDIR/worker-status-after-restart.json"

AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 \
"$ROOT/target/debug/agentbox-cli" remote-worker-status \
  --endpoint "http://127.0.0.1:${PORT}" \
  >"$TMPDIR/worker-status-cli.json"

python3 - "$TMPDIR/worker-status-before-restart.json" "$TMPDIR/worker-status-after-restart.json" "$TMPDIR/worker-status-cli.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    before = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    after = json.load(fh)
with open(sys.argv[3], "r", encoding="utf-8") as fh:
    cli = json.load(fh)

assert after["boot_count"] == before["boot_count"] + 1
assert after["previous_boot_id"] == before["boot_id"]
assert after["boot_id"] != before["boot_id"]
assert after["recovered_sessions"] >= 1
assert after["persistence"] == "StateDir"
assert cli == after
PY

curl -fsS "http://127.0.0.1:${PORT}/sessions/${WORKER_SESSION_ID}/exec" \
  -H 'content-type: application/json' \
  --data "{\"session_id\":\"${SESSION_ID}\",\"worker_session_id\":\"${WORKER_SESSION_ID}\",\"command\":{\"argv\":[\"printf\",\"remote-worker-restored\"],\"working_dir\":null,\"env\":{},\"timeout_seconds\":5}}" \
  >"$TMPDIR/restarted-exec-response.json"

python3 - "$TMPDIR/restarted-exec-response.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

assert data["result"]["exit_code"] == 0
assert data["result"]["stdout"] == "remote-worker-restored"
assert "EvidenceSealed" in data["lifecycle_events"]
PY

cargo run --locked -q -p agentbox-cli -- minipod-spec remote-smoke-long --risk medium --workspace "$TMPDIR/workspace" \
  >"$TMPDIR/spec-long.json"
python3 - "$TMPDIR/spec-long.json" "$TMPDIR/handshake-ack.json" >"$TMPDIR/create-long-request.json" <<'PY'
import json
import sys
from datetime import datetime, timezone

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    spec = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    handshake_ack = json.load(fh)

now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
json.dump({
    "transport": {
        "schema_version": 1,
        "provider": "remote-agentpod",
        "endpoint": "https://worker.example.com/agentpod",
        "auth_kind": "SignedChallenge",
        "evidence_mode": "BundleUpload",
        "kill_switch_required": True,
        "secret_material_included": False,
        "lifecycle": {
            "schema_version": 1,
            "create_timeout_seconds": 120,
            "command_timeout_seconds": 3600,
            "idle_timeout_seconds": 300,
            "destroy_timeout_seconds": 60,
            "heartbeat_interval_seconds": 30,
            "restart_policy": {
                "strategy": "OnFailure",
                "max_attempts": 2,
                "backoff_ms": 1000,
            },
            "required_events": [
                "WorkerAllocated",
                "SessionCreated",
                "CommandStarted",
                "CommandFinished",
                "EvidenceSealed",
                "KillSwitchAck",
                "WorkerDestroyed",
            ],
            "kill_switch_required": True,
        },
        "created_at": now,
    },
    "handshake_ack": handshake_ack,
    "spec": spec,
}, sys.stdout)
PY
curl -fsS "http://127.0.0.1:${PORT}/sessions" \
  -H 'content-type: application/json' \
  --data @"$TMPDIR/create-long-request.json" \
  >"$TMPDIR/create-long-response.json"
LONG_SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session_id"])' "$TMPDIR/create-long-response.json")"
LONG_WORKER_SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["worker_session_id"])' "$TMPDIR/create-long-response.json")"

curl -fsS "http://127.0.0.1:${PORT}/sessions/${LONG_WORKER_SESSION_ID}/exec" \
  -H 'content-type: application/json' \
  --data "{\"session_id\":\"${LONG_SESSION_ID}\",\"worker_session_id\":\"${LONG_WORKER_SESSION_ID}\",\"command\":{\"argv\":[\"sleep\",\"5\"],\"working_dir\":null,\"env\":{},\"timeout_seconds\":30}}" \
  >"$TMPDIR/killed-exec-response.json" &
EXEC_CURL_PID="$!"
sleep 0.2
curl -fsS "http://127.0.0.1:${PORT}/sessions/${LONG_WORKER_SESSION_ID}/destroy" \
  -H 'content-type: application/json' \
  --data "{\"session_id\":\"${LONG_SESSION_ID}\",\"worker_session_id\":\"${LONG_WORKER_SESSION_ID}\",\"reason\":\"smoke kill\",\"kill_switch_required\":true}" \
  >"$TMPDIR/destroy-response.json"
wait "$EXEC_CURL_PID"

python3 - "$TMPDIR/killed-exec-response.json" "$TMPDIR/destroy-response.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    killed = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    destroyed = json.load(fh)

assert killed["result"]["exit_code"] == 130
assert "killed" in killed["result"]["stderr"]
assert "KillSwitchAck" in destroyed["lifecycle_events"]
assert "WorkerDestroyed" in destroyed["lifecycle_events"]
PY

AGENTBOX_REMOTE_AGENTPOD_ALLOW_HTTP_LOOPBACK=1 \
"$ROOT/target/debug/agentbox-cli" remote-restart \
  --endpoint "http://127.0.0.1:${PORT}" \
  --session "$LONG_SESSION_ID" \
  --worker-session "$LONG_WORKER_SESSION_ID" \
  --reason "smoke explicit restart" \
  >"$TMPDIR/restart-response.json"

curl -fsS "http://127.0.0.1:${PORT}/sessions/${LONG_WORKER_SESSION_ID}/exec" \
  -H 'content-type: application/json' \
  --data "{\"session_id\":\"${LONG_SESSION_ID}\",\"worker_session_id\":\"${LONG_WORKER_SESSION_ID}\",\"command\":{\"argv\":[\"printf\",\"explicit-restart\"],\"working_dir\":null,\"env\":{},\"timeout_seconds\":5}}" \
  >"$TMPDIR/restarted-long-exec-response.json"

python3 - "$TMPDIR/restart-response.json" "$TMPDIR/restarted-long-exec-response.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    restart = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    exec_response = json.load(fh)

assert restart["status"] == "Running"
assert restart["restart_attempt"] == 1
assert "WorkerRestarted" in restart["lifecycle_events"]
assert "SessionResumed" in restart["lifecycle_events"]
assert "EvidenceSealed" in restart["lifecycle_events"]
assert exec_response["result"]["exit_code"] == 0
assert exec_response["result"]["stdout"] == "explicit-restart"
PY

echo "remote worker smoke passed on 127.0.0.1:${PORT}"
