#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CLI=(cargo run --locked -q -p agentbox-cli --)
REMOTE_WORKER=(cargo run --locked -q -p agentbox-remote-worker --)
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

if not eval(expression, {"__builtins__": {}}, {"data": data, "all": all, "any": any, "len": len}):
    raise SystemExit(f"JSON contract failed for {path}: {expression}")
PY
}

log "checking provider truth JSON"
"${CLI[@]}" providers --json >"$TMPDIR/providers.json"
validate_json "$TMPDIR/providers.json" \
  "any(p.get('provider') == 'podman' and p.get('setup_command') and p.get('verification_command') for p in data) and any(p.get('provider') == 'remote-agentpod' and p.get('status') == 'experimental' and p.get('setup_command') and p.get('doctor_check') == 'remote-agentpod endpoint' for p in data) and any(p.get('provider') == 'agentpod-windows' and 'job-objects' in p.get('boundary_primitives', []) and 'wfp' in p.get('boundary_primitives', []) and 'windows-sandbox' in p.get('boundary_primitives', []) and 'hyper-v' in p.get('boundary_primitives', []) for p in data) and any(p.get('provider') == 'agentpod-linux' and 'user-namespaces' in p.get('boundary_primitives', []) and 'seccomp' in p.get('boundary_primitives', []) and p.get('verification_command') for p in data)"

log "checking doctor JSON truth"
set +e
"${CLI[@]}" doctor --json >"$TMPDIR/doctor.json"
doctor_status=$?
set -e
validate_json "$TMPDIR/doctor.json" \
  "data.get('schema_version') == 1 and data.get('checks') is not None and data.get('ok', 0) + data.get('failed', 0) == len(data.get('checks', [])) and data.get('required_failed', 0) + data.get('advisory_failed', 0) == data.get('failed', 0) and any(c.get('name') == 'agentbox-shim binary' and c.get('severity') == 'required' and c.get('release_blocker') == (not c.get('ok')) for c in data.get('checks', [])) and any(c.get('name') == 'remote-agentpod endpoint' and c.get('severity') == 'advisory' for c in data.get('checks', []))"
if [ "$doctor_status" -ne 0 ]; then
  validate_json "$TMPDIR/doctor.json" "data.get('required_failed', 0) > 0"
fi

log "checking setup plan JSON truth"
"${CLI[@]}" setup-plan --json >"$TMPDIR/setup-plan.json"
validate_json "$TMPDIR/setup-plan.json" \
  "data.get('schema_version') == 1 and data.get('required_failed', 0) + data.get('advisory_failed', 0) == data.get('failed', 0) and data.get('steps') is not None and all(step.get('severity') in ['required', 'advisory'] for step in data.get('steps', []))"
"${CLI[@]}" setup-plan --provider remote-agentpod --json >"$TMPDIR/setup-plan-remote.json"
validate_json "$TMPDIR/setup-plan-remote.json" \
  "data.get('schema_version') == 1 and data.get('provider') == 'remote-agentpod' and all(step.get('check') == 'remote-agentpod endpoint' for step in data.get('steps', []))"
"${CLI[@]}" setup --dry-run --provider remote-agentpod --json >"$TMPDIR/setup-dry-run-remote.json"
validate_json "$TMPDIR/setup-dry-run-remote.json" \
  "data.get('schema_version') == 1 and data.get('dry_run') == True and data.get('provider') == 'remote-agentpod' and data.get('shims') is None and data.get('setup_plan', {}).get('provider') == 'remote-agentpod' and 'export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://worker.example.com/agentpod' in data.get('operator_commands', [])"
"${CLI[@]}" setup --dry-run --provider remote-agentpod --endpoint https://agentpod.example.com/run --json >"$TMPDIR/setup-dry-run-remote-endpoint.json"
validate_json "$TMPDIR/setup-dry-run-remote-endpoint.json" \
  "data.get('remote_endpoint') == 'https://agentpod.example.com/run' and 'export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://agentpod.example.com/run' in data.get('operator_commands', []) and 'agentbox remote-handshake --endpoint https://agentpod.example.com/run' in data.get('operator_commands', [])"

log "checking pods JSON truth"
"${CLI[@]}" pods --json >"$TMPDIR/pods.json"
validate_json "$TMPDIR/pods.json" \
  "data == [] or all(item.get('id') and item.get('provider') for item in data)"

log "checking AgentPod run plan JSON"
"${CLI[@]}" run --plan --json -- echo agentbox-contract >"$TMPDIR/run-plan.json"
validate_json "$TMPDIR/run-plan.json" \
  "data.get('schema_version') == 1 and data.get('selected_provider', {}).get('availability_check') == 'not performed by --plan' and data.get('manifest', {}).get('kind') == 'AgentPod' and len(data.get('backend_actions', [])) >= 3"

log "checking native plan auto provider truth"
"${CLI[@]}" native-plan \
  --workspace "$TMPDIR" \
  -- /bin/true >"$TMPDIR/native-plan-auto.json"
validate_json "$TMPDIR/native-plan-auto.json" \
  "data.get('schema_version') == 1 and data.get('provider') in ['agentpod-linux', 'agentpod-macos', 'agentpod-windows'] and data.get('live_execution_enabled') == False and data.get('security_claim')"

log "checking high-risk provider recommendation truth"
"${CLI[@]}" run --plan --risk high --json -- echo agentbox-contract >"$TMPDIR/run-plan-high.json"
validate_json "$TMPDIR/run-plan-high.json" \
  "data.get('schema_version') == 1 and data.get('selected_provider', {}).get('name', '').startswith('agentpod-') and len(data.get('selected_provider', {}).get('boundary_primitives', [])) >= 1 and any('not generally runnable' in warning for warning in data.get('warnings', []))"

log "checking macOS native plan compiler truth"
AGENTBOX_MACOS_NATIVE= "${CLI[@]}" native-plan \
  --provider agentpod-macos \
  --workspace "$TMPDIR" \
  -- /bin/true >"$TMPDIR/native-plan-macos.json"
validate_json "$TMPDIR/native-plan-macos.json" \
  "data.get('schema_version') == 1 and data.get('provider') == 'agentpod-macos' and data.get('virtualization', {}).get('requires_apple_virtualization') == True and data.get('endpoint_security', {}).get('requires_system_extension') == True and data.get('network_extension', {}).get('requires_network_extension') == True and data.get('live_env_var') == 'AGENTBOX_MACOS_NATIVE' and data.get('live_execution_enabled') == False and 'execution is not wired' in data.get('security_claim', '')"

log "checking Windows native plan compiler truth"
AGENTBOX_WINDOWS_NATIVE= "${CLI[@]}" native-plan \
  --provider agentpod-windows \
  --workspace "$TMPDIR" \
  -- codex exec >"$TMPDIR/native-plan-windows.json"
validate_json "$TMPDIR/native-plan-windows.json" \
  "data.get('schema_version') == 1 and data.get('provider') == 'agentpod-windows' and data.get('job_object', {}).get('kill_on_close') == True and data.get('app_container', {}).get('requires_profile_creation') == True and data.get('wfp', {}).get('requires_wfp') == True and data.get('etw', {}).get('requires_etw') == True and 'windows-sandbox' in data.get('vm_boundary', {}).get('candidate_backends', []) and data.get('live_env_var') == 'AGENTBOX_WINDOWS_NATIVE' and data.get('live_execution_enabled') == False and 'execution is not wired' in data.get('security_claim', '')"

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

log "checking remote evidence status command surface"
"${CLI[@]}" remote-evidence-status --help >"$TMPDIR/remote-evidence-status-help.txt"
grep -F "Query a remote AgentPod worker for accepted evidence state" \
  "$TMPDIR/remote-evidence-status-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-evidence-status-help.txt" >/dev/null
"${CLI[@]}" remote-approval-grant --help >"$TMPDIR/remote-approval-grant-help.txt"
grep -F "Grant a pending remote AgentPod command approval" \
  "$TMPDIR/remote-approval-grant-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-approval-grant-help.txt" >/dev/null
"${CLI[@]}" remote-evidence-upload --help >"$TMPDIR/remote-evidence-upload-help.txt"
grep -F "Upload a verified evidence bundle directory to a remote AgentPod worker" \
  "$TMPDIR/remote-evidence-upload-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-evidence-upload-help.txt" >/dev/null
"${CLI[@]}" remote-workspace-export --help >"$TMPDIR/remote-workspace-export-help.txt"
grep -F "Export a remote AgentPod worker workspace into a local review directory" \
  "$TMPDIR/remote-workspace-export-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-workspace-export-help.txt" >/dev/null
"${CLI[@]}" remote-workspace-apply --help >"$TMPDIR/remote-workspace-apply-help.txt"
grep -F "Apply a pulled remote AgentPod workspace export to a local workspace" \
  "$TMPDIR/remote-workspace-apply-help.txt" >/dev/null

log "checking evidence bundle verification"
BUNDLE_DIR="$TMPDIR/evidence-bundle"
mkdir -p "$BUNDLE_DIR"
printf '{"schema_version":1,"kind":"AgentPod"}\n' >"$BUNDLE_DIR/manifest.json"
printf '{"schema_version":1,"commands":[{"audit_event_id":"evt_1"}],"approvals":[],"lifecycle_events":[],"boundary_events":[],"credential_events":[]}\n' >"$BUNDLE_DIR/bundle.json"
python3 - "$BUNDLE_DIR" <<'PY'
import hashlib
import json
import pathlib
import sys

bundle = pathlib.Path(sys.argv[1])
files = []
for path, description in [
    ("bundle.json", "smoke bundle"),
    ("manifest.json", "smoke manifest"),
]:
    data = (bundle / path).read_bytes()
    files.append(
        {
            "path": path,
            "media_type": "application/json",
            "description": description,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
    )
root_entries = [
    f"{entry['path']}\0{entry['sha256']}\0{entry['bytes']}\0{entry['media_type']}"
    for entry in sorted(files, key=lambda value: value["path"])
]
root_payload = ("agentbox-evidence-root-v1\n" + "\n".join(root_entries)).encode()
index = {
    "schema_version": 1,
    "bundle_id": "smoke-bundle",
    "session_id": "smoke-session",
    "provider": "direct-host",
    "status": "Stopped",
    "root_sha256": hashlib.sha256(root_payload).hexdigest(),
    "generated_at": "2026-05-14T00:00:00Z",
    "files": files,
}
(bundle / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
PY
"${CLI[@]}" evidence --verify --bundle "$BUNDLE_DIR"
"${CLI[@]}" remote-evidence \
  --session smoke-session \
  --worker-session smoke-worker-session \
  --bundle-dir "$BUNDLE_DIR" >"$TMPDIR/remote-evidence-from-bundle.json"
validate_json "$TMPDIR/remote-evidence-from-bundle.json" \
  "data.get('session_id') == 'smoke-session' and data.get('worker_session_id') == 'smoke-worker-session' and data.get('event_count') == 1 and len(data.get('bundle_sha256', '')) == 64 and data.get('derived_from_bundle') == True and data.get('bundle_id') == 'smoke-bundle' and data.get('bundle_root_sha256') == data.get('bundle_sha256')"
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

log "checking remote worker binary contract"
"${REMOTE_WORKER[@]}" --help >/tmp/agentbox-remote-worker-help.out 2>/tmp/agentbox-remote-worker-help.err
if "${REMOTE_WORKER[@]}" >/tmp/agentbox-remote-worker-missing-key.out 2>/tmp/agentbox-remote-worker-missing-key.err; then
  echo "remote worker started without an explicit signing key" >&2
  exit 1
fi

log "CLI contract smoke passed"
