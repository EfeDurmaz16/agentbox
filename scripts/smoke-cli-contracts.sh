#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CLI=(cargo run --locked -q -p agentbox-cli --)
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

log() {
  printf '\n==> %s\n' "$*"
}

validate_json() {
  local file="$1"
  local expression="$2"
  python3 - "$file" "$expression" <<'PY'
import json
import sys

path, expression = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

if not eval(expression, {"__builtins__": {}}, {"data": data, "any": any, "len": len}):
    raise SystemExit(f"JSON contract failed for {path}: {expression}")
PY
}

log "checking provider truth JSON"
"${CLI[@]}" providers --json >"$TMPDIR/providers.json"
validate_json "$TMPDIR/providers.json" \
  "any(p.get('provider') == 'podman' for p in data) and any(p.get('provider') == 'remote-agentpod' and p.get('status') == 'descriptor-only' for p in data)"

log "checking AgentPod run plan JSON"
"${CLI[@]}" run --plan --json -- echo agentbox-contract >"$TMPDIR/run-plan.json"
validate_json "$TMPDIR/run-plan.json" \
  "data.get('schema_version') == 1 and data.get('selected_provider', {}).get('availability_check') == 'not performed by --plan' and data.get('manifest', {}).get('kind') == 'AgentPod' and len(data.get('backend_actions', [])) >= 3"

log "checking high-risk provider recommendation truth"
"${CLI[@]}" run --plan --risk high --json -- echo agentbox-contract >"$TMPDIR/run-plan-high.json"
validate_json "$TMPDIR/run-plan-high.json" \
  "data.get('schema_version') == 1 and data.get('selected_provider', {}).get('name', '').startswith('agentpod-') and any('not generally runnable' in warning for warning in data.get('warnings', []))"

log "checking remote descriptor JSON"
"${CLI[@]}" remote-descriptor \
  --endpoint https://worker.example.com/agentpod \
  --auth signed-challenge \
  --evidence bundle-upload >"$TMPDIR/remote-descriptor.json"
validate_json "$TMPDIR/remote-descriptor.json" \
  "data.get('provider') == 'remote-agentpod' and data.get('endpoint') == 'https://worker.example.com/agentpod' and data.get('auth_kind') == 'SignedChallenge' and data.get('evidence_mode') == 'BundleUpload' and data.get('secret_material_included') == False"

log "checking remote handshake JSON"
"${CLI[@]}" remote-handshake \
  --endpoint https://worker.example.com/agentpod \
  --auth signed-challenge \
  --ttl-seconds 120 >"$TMPDIR/remote-handshake.json"
validate_json "$TMPDIR/remote-handshake.json" \
  "data.get('provider') == 'remote-agentpod' and data.get('auth_kind') == 'SignedChallenge' and data.get('challenge_id') and data.get('challenge_nonce_sha256') and data.get('secret_material_included') == False"

log "checking remote evidence metadata JSON"
"${CLI[@]}" remote-evidence \
  --session abx-session-1 \
  --worker-session worker-session-1 \
  --evidence bundle-upload \
  --bundle-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --event-count 3 >"$TMPDIR/remote-evidence.json"
validate_json "$TMPDIR/remote-evidence.json" \
  "data.get('session_id') == 'abx-session-1' and data.get('worker_session_id') == 'worker-session-1' and data.get('event_count') == 3 and data.get('bundle_sha256', '').startswith('012345')"

log "checking evidence bundle verification"
BUNDLE_DIR="$TMPDIR/evidence-bundle"
mkdir -p "$BUNDLE_DIR"
printf '{"schema_version":1,"kind":"AgentPod"}\n' >"$BUNDLE_DIR/manifest.json"
python3 - "$BUNDLE_DIR" <<'PY'
import hashlib
import json
import pathlib
import sys

bundle = pathlib.Path(sys.argv[1])
manifest = bundle / "manifest.json"
data = manifest.read_bytes()
file_entry = {
    "path": "manifest.json",
    "media_type": "application/json",
    "description": "smoke manifest",
    "sha256": hashlib.sha256(data).hexdigest(),
    "bytes": len(data),
}
root_payload = (
    "agentbox-evidence-root-v1\n"
    + f"{file_entry['path']}\0{file_entry['sha256']}\0{file_entry['bytes']}\0{file_entry['media_type']}"
).encode()
index = {
    "schema_version": 1,
    "bundle_id": "smoke-bundle",
    "session_id": "smoke-session",
    "provider": "direct-host",
    "status": "Stopped",
    "root_sha256": hashlib.sha256(root_payload).hexdigest(),
    "generated_at": "2026-05-14T00:00:00Z",
    "files": [file_entry],
}
(bundle / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
PY
"${CLI[@]}" evidence --verify --bundle "$BUNDLE_DIR"
printf '{"tampered":true}\n' >"$BUNDLE_DIR/manifest.json"
if "${CLI[@]}" evidence --verify --bundle "$BUNDLE_DIR" >/tmp/agentbox-invalid-evidence-bundle.out 2>/tmp/agentbox-invalid-evidence-bundle.err; then
  echo "evidence bundle verification accepted tampered bundle" >&2
  exit 1
fi

log "checking remote evidence rejects invalid bundle digests"
if "${CLI[@]}" remote-evidence \
  --session abx-session-1 \
  --worker-session worker-session-1 \
  --evidence bundle-upload \
  --bundle-sha256 not-a-sha256 \
  --event-count 3 >/tmp/agentbox-invalid-remote-evidence.out 2>/tmp/agentbox-invalid-remote-evidence.err; then
  echo "remote-evidence accepted an invalid bundle digest" >&2
  exit 1
fi

log "CLI contract smoke passed"
