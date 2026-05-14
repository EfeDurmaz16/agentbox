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

curl -fsS "http://127.0.0.1:${PORT}/sessions/worker-smoke/exec" \
  -H 'content-type: application/json' \
  --data '{"session_id":"session-smoke","worker_session_id":"worker-smoke","command":{"argv":["printf","remote-worker-smoke"],"working_dir":null,"env":{},"timeout_seconds":5}}' \
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

curl -fsS "http://127.0.0.1:${PORT}/sessions/worker-smoke-long/exec" \
  -H 'content-type: application/json' \
  --data '{"session_id":"session-smoke-long","worker_session_id":"worker-smoke-long","command":{"argv":["sleep","5"],"working_dir":null,"env":{},"timeout_seconds":30}}' \
  >"$TMPDIR/killed-exec-response.json" &
EXEC_CURL_PID="$!"
sleep 0.2
curl -fsS "http://127.0.0.1:${PORT}/sessions/worker-smoke-long/destroy" \
  -H 'content-type: application/json' \
  --data '{"session_id":"session-smoke-long","worker_session_id":"worker-smoke-long","reason":"smoke kill","kill_switch_required":true}' \
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
