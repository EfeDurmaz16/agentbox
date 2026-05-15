#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ARTIFACT_DIR="${AGENTBOX_RELEASE_ARTIFACT_DIR:-target/agentbox-release-readiness}"
ALLOW_DOCTOR_FAILURE="${AGENTBOX_RELEASE_ALLOW_DOCTOR_FAILURE:-0}"
RUN_LIVE_SMOKE="${AGENTBOX_RELEASE_LIVE_SMOKE:-0}"

mkdir -p "$ARTIFACT_DIR"

log() {
  printf '\n==> %s\n' "$*"
}

run_step() {
  local name="$1"
  shift
  log "$name"
  "$@" 2>&1 | tee "$ARTIFACT_DIR/${name}.log"
}

validate_json_file() {
  local file="$1"
  local expression="$2"
  python3 - "$file" "$expression" <<'PY'
import json
import sys

path, expression = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

safe_globals = {"__builtins__": {}, "all": all, "any": any, "len": len}
if not eval(expression, safe_globals, {"data": data}):
    raise SystemExit(f"JSON contract failed for {path}: {expression}")
PY
}

run_step fmt cargo fmt --check
run_step clippy cargo clippy --locked --workspace --all-targets -- -D warnings
run_step test cargo test --locked --workspace
run_step build-release cargo build --locked --release

log "providers JSON"
cargo run --locked -q -p agentbox-cli -- providers --json >"$ARTIFACT_DIR/providers.json"
validate_json_file "$ARTIFACT_DIR/providers.json" \
  "any(p.get('provider') == 'direct-host' and any(s.get('primitive') == 'path-shim' and s.get('status') == 'shipped' and s.get('active') == True for s in p.get('boundary_primitive_statuses', [])) for p in data) and any(p.get('provider') == 'podman' and any(s.get('primitive') == 'guest-shim' and s.get('requires_gate') for s in p.get('boundary_primitive_statuses', [])) for p in data) and any(p.get('provider') == 'remote-agentpod' for p in data) and any(p.get('provider') == 'agentpod-linux' and any(s.get('primitive') == 'seccomp' and s.get('status') == 'prototype' and s.get('active') == False for s in p.get('boundary_primitive_statuses', [])) for p in data)"

log "doctor JSON"
set +e
cargo run --locked -q -p agentbox-cli -- doctor --json >"$ARTIFACT_DIR/doctor.json"
doctor_status=$?
set -e
validate_json_file "$ARTIFACT_DIR/doctor.json" \
  "data.get('schema_version') == 1 and data.get('ok', 0) + data.get('failed', 0) == len(data.get('checks', [])) and data.get('required_failed', 0) + data.get('advisory_failed', 0) == data.get('failed', 0)"
if [ "$doctor_status" -ne 0 ] && [ "$ALLOW_DOCTOR_FAILURE" != "1" ]; then
  echo "error: doctor --json reported required failed readiness checks" >&2
  echo "hint: inspect $ARTIFACT_DIR/doctor.json or set AGENTBOX_RELEASE_ALLOW_DOCTOR_FAILURE=1 for an explicitly blocked candidate" >&2
  exit "$doctor_status"
fi

log "setup plan JSON"
cargo run --locked -q -p agentbox-cli -- setup-plan --json >"$ARTIFACT_DIR/setup-plan.json"
validate_json_file "$ARTIFACT_DIR/setup-plan.json" \
  "data.get('schema_version') == 1 and data.get('required_failed', 0) + data.get('advisory_failed', 0) == data.get('failed', 0) and data.get('steps') is not None"

run_step cli-contract-smoke bash scripts/smoke-cli-contracts.sh
run_step remote-worker-smoke bash scripts/smoke-remote-worker.sh

if [ "$RUN_LIVE_SMOKE" = "1" ]; then
  run_step podman-bridge-smoke bash scripts/smoke-podman-bridge.sh
  run_step macos-minipod-smoke bash scripts/smoke-macos-minipod.sh
  run_step linux-native-smoke bash scripts/smoke-linux-native.sh
else
  log "live smoke skipped"
  printf 'Set AGENTBOX_RELEASE_LIVE_SMOKE=1 to run optional platform/live-provider smoke scripts.\n' \
    | tee "$ARTIFACT_DIR/live-smoke-skipped.log" >/dev/null
fi

python3 - "$ARTIFACT_DIR" <<'PY'
import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone

artifact_dir = pathlib.Path(sys.argv[1])
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
status = subprocess.check_output(["git", "status", "--short", "--branch"], text=True).strip()
manifest = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "git_commit": commit,
    "git_status": status,
    "artifact_dir": str(artifact_dir),
    "doctor_json": "doctor.json",
    "providers_json": "providers.json",
    "setup_plan_json": "setup-plan.json",
}
(artifact_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY

log "release readiness artifacts"
printf 'wrote %s\n' "$ARTIFACT_DIR"
