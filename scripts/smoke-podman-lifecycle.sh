#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CLI=(cargo run --locked -q -p agentbox-cli --)
CONTRACT_ONLY="${AGENTBOX_PODMAN_LIFECYCLE_CONTRACT_ONLY:-0}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentbox-podman-lifecycle.XXXXXX")"
SESSION_ID=""
STOPPED_SESSION=0

cleanup() {
  if [[ -n "$SESSION_ID" && "$STOPPED_SESSION" != "1" ]]; then
    "${CLI[@]}" stop-pod "$SESSION_ID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

log() {
  printf '\n==> %s\n' "$*"
}

skip() {
  printf 'SKIP: %s\n' "$*" >&2
  exit 77
}

require() {
  command -v "$1" >/dev/null 2>&1 || skip "$1 is not installed"
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

safe_globals = {"__builtins__": {}, "all": all, "any": any, "len": len}
if not eval(expression, safe_globals, {"data": data}):
    raise SystemExit(f"JSON contract failed for {path}: {expression}")
PY
}

extract_json_string() {
  local file="$1"
  local expression="$2"
  python3 - "$file" "$expression" <<'PY'
import json
import sys

path, expression = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

value = eval(expression, {"__builtins__": {}}, {"data": data})
if not isinstance(value, str) or not value:
    raise SystemExit(f"expected non-empty string for {expression}")
print(value)
PY
}

is_linux_elf() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  head -c 4 "$path" | od -An -tx1 | grep -qi '7f 45 4c 46'
}

resolve_linux_shim() {
  if [[ -n "${AGENTBOX_LINUX_SHIM:-}" ]]; then
    is_linux_elf "$AGENTBOX_LINUX_SHIM" || skip "AGENTBOX_LINUX_SHIM is not a Linux ELF binary: $AGENTBOX_LINUX_SHIM"
    printf '%s\n' "$AGENTBOX_LINUX_SHIM"
    return
  fi

  if [[ "$(uname -s)" != "Darwin" ]]; then
    cargo build -q -p agentbox-shim
    local host_shim="$ROOT/target/debug/agentbox-shim"
    is_linux_elf "$host_shim" || skip "local agentbox-shim is not a Linux ELF binary; set AGENTBOX_LINUX_SHIM"
    printf '%s\n' "$host_shim"
    return
  fi

  local build_output
  if ! build_output="$(AGENTBOX_LINUX_SHIM_PROFILE="${AGENTBOX_LINUX_SHIM_PROFILE:-debug}" scripts/build-linux-shim.sh 2>&1)"; then
    skip "Linux guest shim artifact is unavailable; run scripts/build-linux-shim.sh first. ${build_output//$'\n'/ }"
  fi
  local built_shim
  built_shim="$(printf '%s\n' "$build_output" | sed -n 's/^AGENTBOX_LINUX_SHIM=//p' | tail -n 1)"
  [[ -n "$built_shim" ]] || skip "scripts/build-linux-shim.sh did not print AGENTBOX_LINUX_SHIM"
  is_linux_elf "$built_shim" || skip "built shim is not a Linux ELF binary: $built_shim"
  printf '%s\n' "$built_shim"
}

check_contract_mode() {
  log "checking Podman lifecycle plan contract without live provider"
  "${CLI[@]}" agentpod run \
    --plan \
    --provider podman \
    --risk medium \
    --json \
    -- sh -c 'printf lifecycle-ok' >"$TMP/run-plan.json"
  validate_json "$TMP/run-plan.json" \
    "data.get('schema_version') == 1 and data.get('selected_provider', {}).get('name') == 'podman' and data.get('selected_provider', {}).get('availability_check') == 'not performed by --plan' and 'check Podman availability and start compatibility VM if required' in data.get('backend_actions', []) and 'create runtime session through selected provider' in data.get('backend_actions', []) and 'execute command through RuntimeManager policy checks' in data.get('backend_actions', []) and 'record hash-chained runtime evidence' in data.get('backend_actions', []) and any('plan output does not start a backend' in warning for warning in data.get('warnings', []))"

  "${CLI[@]}" setup-plan --provider podman --json >"$TMP/setup-plan-podman.json"
  validate_json "$TMP/setup-plan-podman.json" \
    "data.get('schema_version') == 1 and data.get('provider') == 'podman' and data.get('required_failed') == 0 and data.get('ready_for_required_setup') == True and all(step.get('severity') == 'advisory' and step.get('check') in ['podman CLI', 'podman machine', 'podman host bridge'] for step in data.get('steps', []))"

  log "Podman lifecycle contract smoke passed"
}

if [[ "$CONTRACT_ONLY" = "1" ]]; then
  require cargo
  require python3
  check_contract_mode
  exit 0
fi

require cargo
require podman
require python3

if [[ "$(uname -s)" == "Darwin" ]]; then
  podman machine inspect >/dev/null 2>&1 || skip "podman machine is not initialized; run: podman machine init && podman machine start"
  podman machine inspect | grep -Eq '"Running": true|"State": "running"' || skip "podman machine is not running; run: podman machine start"
fi

log "checking Podman CLI availability"
podman --version
podman info --format json >/dev/null 2>&1 || skip "podman info failed; Podman compatibility provider is not runnable"

log "resolving Linux guest shim artifact"
SHIM="$(resolve_linux_shim)"
export AGENTBOX_LINUX_SHIM="$SHIM"

log "checking non-live Podman lifecycle contract before live execution"
check_contract_mode

log "running Podman create/exec/destroy lifecycle through AgentPod CLI"
"${CLI[@]}" agentpod run \
  --provider podman \
  --risk medium \
  --json \
  -- sh -c 'printf lifecycle-ok' >"$TMP/run-exec-destroy.json"
validate_json "$TMP/run-exec-destroy.json" \
  "data.get('schema_version') == 1 and data.get('session', {}).get('provider') == 'podman' and data.get('command_result', {}).get('exit_code') == 0 and data.get('command_result', {}).get('stdout') == 'lifecycle-ok' and data.get('destroyed') == True"

log "creating a persistent Podman AgentPod session"
"${CLI[@]}" agentpod run \
  --provider podman \
  --risk medium \
  --json >"$TMP/create-session.json"
validate_json "$TMP/create-session.json" \
  "data.get('schema_version') == 1 and data.get('session', {}).get('provider') == 'podman' and data.get('session', {}).get('status') == 'Running' and data.get('destroyed') == False and data.get('cleanup_command')"
SESSION_ID="$(extract_json_string "$TMP/create-session.json" "data['session']['id']")"

log "checking persistent session status"
"${CLI[@]}" agentpod status "$SESSION_ID" --json >"$TMP/status-session.json"
validate_json "$TMP/status-session.json" \
  "data.get('id') == '$SESSION_ID' and data.get('provider') == 'podman' and data.get('status') == 'Running'"

log "destroying persistent Podman AgentPod session"
"${CLI[@]}" stop-pod "$SESSION_ID" >"$TMP/stop-session.txt"
STOPPED_SESSION=1
grep -F "AgentPod session $SESSION_ID stopped." "$TMP/stop-session.txt" >/dev/null

log "checking destroyed session status is persisted honestly"
"${CLI[@]}" agentpod status "$SESSION_ID" --json >"$TMP/status-destroyed-session.json"
validate_json "$TMP/status-destroyed-session.json" \
  "data.get('id') == '$SESSION_ID' and data.get('provider') == 'podman' and data.get('status') == 'Stopped'"

log "Podman lifecycle conformance smoke passed"
