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

safe_globals = {
    "__builtins__": {},
    "all": all,
    "any": any,
    "len": len,
    "data": data,
}
if not eval(expression, safe_globals, {}):
    raise SystemExit(f"JSON contract failed for {path}: {expression}")
PY
}

log "checking release provider status truth"
"${CLI[@]}" providers --json >"$TMPDIR/providers.json"
validate_json "$TMPDIR/providers.json" \
  "any(p.get('provider') == 'direct-host' and p.get('status') == 'shipped' and any(s.get('primitive') == 'path-shim' and s.get('status') == 'shipped' and s.get('active') == True for s in p.get('boundary_primitive_statuses', [])) for p in data) and any(p.get('provider') == 'agentpod-linux' and p.get('status') == 'prototype' and all(s.get('active') == False and s.get('requires_gate') == 'AGENTBOX_LINUX_NATIVE=1' for s in p.get('boundary_primitive_statuses', [])) for p in data) and any(p.get('provider') == 'agentpod-macos' and p.get('status') in ['descriptor-only', 'prototype'] and any(s.get('active') == False and 'AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1' in s.get('requires_gate', '') for s in p.get('boundary_primitive_statuses', [])) for p in data) and any(p.get('provider') == 'remote-agentpod' and p.get('status') == 'experimental' and p.get('doctor_check') == 'remote-agentpod endpoint' for p in data)"

log "checking release doctor JSON truth"
set +e
"${CLI[@]}" doctor --json >"$TMPDIR/doctor.json"
doctor_status=$?
set -e
validate_json "$TMPDIR/doctor.json" \
  "data.get('schema_version') == 1 and data.get('checks') is not None and data.get('ok', 0) + data.get('failed', 0) == len(data.get('checks', [])) and data.get('required_failed', 0) + data.get('advisory_failed', 0) == data.get('failed', 0) and all(c.get('severity') in ['required', 'advisory'] for c in data.get('checks', [])) and all(c.get('release_blocker') == (c.get('severity') == 'required' and not c.get('ok')) for c in data.get('checks', []))"
if [ "$doctor_status" -ne 0 ]; then
  validate_json "$TMPDIR/doctor.json" "data.get('required_failed', 0) > 0"
fi

log "checking direct-host low-risk allow"
"${CLI[@]}" run --provider direct-host --risk low --json -- echo agentbox-release-smoke >"$TMPDIR/direct-host-allow.json"
validate_json "$TMPDIR/direct-host-allow.json" \
  "data.get('schema_version') == 1 and data.get('session', {}).get('provider') == 'direct-host' and data.get('command_result', {}).get('exit_code') == 0 and data.get('command_result', {}).get('stdout') == 'agentbox-release-smoke\n' and data.get('destroyed') == True"

log "checking direct-host high-risk deny"
set +e
"${CLI[@]}" run --provider direct-host --risk high --json -- echo agentbox-release-deny >"$TMPDIR/direct-host-deny.out" 2>"$TMPDIR/direct-host-deny.err"
deny_status=$?
set -e
if [ "$deny_status" -eq 0 ]; then
  echo "direct-host high-risk command unexpectedly succeeded" >&2
  cat "$TMPDIR/direct-host-deny.out" >&2
  exit 1
fi
grep -F "policy denied: direct-host high-risk sessions require" "$TMPDIR/direct-host-deny.err" >/dev/null
grep -F "not an AgentPod sandbox" "$TMPDIR/direct-host-deny.err" >/dev/null

log "checking evidence bundle verification"
BUNDLE_DIR="$TMPDIR/evidence-bundle"
mkdir -p "$BUNDLE_DIR"
printf '{"schema_version":1,"kind":"AgentPod"}\n' >"$BUNDLE_DIR/manifest.json"
printf '{"schema_version":1,"commands":[{"audit_event_id":"evt_release_smoke"}],"approvals":[],"lifecycle_events":[],"boundary_events":[],"credential_events":[]}\n' >"$BUNDLE_DIR/bundle.json"
python3 - "$BUNDLE_DIR" <<'PY'
import hashlib
import json
import pathlib
import sys

bundle = pathlib.Path(sys.argv[1])
files = []
for path, description in [
    ("bundle.json", "release smoke bundle"),
    ("manifest.json", "release smoke manifest"),
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
    "bundle_id": "release-smoke-bundle",
    "session_id": "release-smoke-session",
    "provider": "direct-host",
    "status": "Stopped",
    "root_sha256": hashlib.sha256(root_payload).hexdigest(),
    "generated_at": "2026-05-30T00:00:00Z",
    "files": files,
}
(bundle / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
PY
"${CLI[@]}" evidence verify --bundle "$BUNDLE_DIR" >"$TMPDIR/evidence-verify.out"
printf '{"tampered":true}\n' >"$BUNDLE_DIR/manifest.json"
if "${CLI[@]}" evidence verify --bundle "$BUNDLE_DIR" >"$TMPDIR/evidence-tamper.out" 2>"$TMPDIR/evidence-tamper.err"; then
  echo "evidence verify accepted a tampered release smoke bundle" >&2
  exit 1
fi

log "AgentPod release smoke suite passed"
