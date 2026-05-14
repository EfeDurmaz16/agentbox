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

mkdir -p "$TMPDIR/workspace"
cargo run --locked -q -p agentbox-cli -- minipod-spec remote-smoke --risk medium --workspace "$TMPDIR/workspace" \
  >"$TMPDIR/spec.json"
python3 - "$TMPDIR/spec.json" "$TMPDIR/handshake-ack.json" >"$TMPDIR/create-request.json" <<'PY'
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
  --data @"$TMPDIR/create-request.json" \
  >"$TMPDIR/create-response.json"
SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session_id"])' "$TMPDIR/create-response.json")"
WORKER_SESSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["worker_session_id"])' "$TMPDIR/create-response.json")"

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

python3 - "$TMPDIR" "$SESSION_ID" "$WORKER_SESSION_ID" <<'PY'
import hashlib
import json
import sys

tmpdir, session_id, worker_session_id = sys.argv[1:4]
bundle_json = json.dumps(
    {"session_id": session_id, "worker_session_id": worker_session_id, "events": []},
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
assert data["evidence_receipts"][0]["bundle_sha256"] == "f" * 64
assert data["evidence_receipts"][0]["event_count"] == 2
assert data["stored_evidence_bundles"][0]["bundle_sha256"] == expected_bundle_hash
assert data["stored_evidence_bundles"][0]["stored_bytes"] > 0
PY

python3 - "$TMPDIR/worker-state/worker-sessions.json" "$SESSION_ID" "$WORKER_SESSION_ID" "$TMPDIR/evidence-bundle-upload.expected" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    sessions = json.load(fh)
with open(sys.argv[4], "r", encoding="utf-8") as fh:
    expected_bundle_hash = fh.read().strip()

matches = [
    session for session in sessions
    if session["session_id"] == sys.argv[2]
    and session["worker_session_id"] == sys.argv[3]
]
assert matches
assert matches[0]["status"] == "Running"
assert matches[0]["evidence_receipts"][0]["bundle_sha256"] == "f" * 64
assert matches[0]["evidence_receipts"][0]["event_count"] == 2
assert matches[0]["stored_evidence_bundles"][0]["bundle_sha256"] == expected_bundle_hash
assert matches[0]["stored_evidence_bundles"][0]["stored_bytes"] > 0
assert matches[0]["stored_evidence_bundles"][0]["storage_path"].endswith(
    f"{expected_bundle_hash}.json"
)
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

echo "remote worker smoke passed on 127.0.0.1:${PORT}"
