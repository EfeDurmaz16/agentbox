#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CLI=(cargo run --locked -q -p agentbox-cli --)
CONTRACT_ONLY="${AGENTBOX_PODMAN_BRIDGE_CONTRACT_ONLY:-0}"
INTENDED_BRIDGE_PATH="/run/agentbox.sock"
SHIM_SOCKET_LINK="/root/.agentbox/agentbox.sock"

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

check_contract_mode() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/agentbox-podman-bridge-contract.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN

  log "checking Podman bridge metadata contract without live provider"
  "${CLI[@]}" bridge-health --provider podman --json >"$tmp/bridge-health-podman.json"
  validate_json "$tmp/bridge-health-podman.json" \
    "len(data) == 1 and data[0].get('provider') == 'podman' and data[0].get('readiness', {}).get('verdict') in ['active-if-podman-available', 'needs-podman-prereqs'] and data[0].get('readiness', {}).get('next_command') == 'agentbox setup-plan --provider podman' and data[0].get('bridge_health', {}).get('policy', {}).get('supported') == True and data[0].get('bridge_health', {}).get('approval', {}).get('supported') == True and data[0].get('bridge_health', {}).get('credentials', {}).get('supported') == True and data[0].get('bridge_health', {}).get('evidence', {}).get('supported') == True and data[0].get('bridge_health', {}).get('kill_switch', {}).get('supported') == True and data[0].get('bridge_health', {}).get('network', {}).get('supported') == False and 'UnixSocket' in data[0].get('bridge_health', {}).get('transports', []) and data[0].get('verification_command') == 'agentbox run --provider podman -- <cmd>'"

  "${CLI[@]}" setup-plan --provider podman --json >"$tmp/setup-plan-podman.json"
  validate_json "$tmp/setup-plan-podman.json" \
    "data.get('schema_version') == 1 and data.get('provider') == 'podman' and data.get('required_failed') == 0 and data.get('ready_for_required_setup') == True and all(step.get('severity') == 'advisory' for step in data.get('steps', [])) and any(step.get('check') == 'podman host bridge' and 'compatibility bridge' in step.get('action', '') for step in data.get('steps', []))"

  log "Podman bridge contract smoke passed"
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

if [[ "$(uname -s)" == "Darwin" ]]; then
  podman machine inspect >/dev/null 2>&1 || skip "podman machine is not initialized; run: podman machine init && podman machine start"
  podman machine inspect | grep -Eq '"Running": true|"State": "running"' || skip "podman machine is not running; run: podman machine start"
fi

log "resolving Linux guest shim artifact"
SHIM="$(resolve_linux_shim)"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentbox-podman-bridge.XXXXXX")"
SOCKET_DIR="$TMP/home/.agentbox"
SOCKET="$SOCKET_DIR/agentbox.sock"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$SOCKET_DIR"

log "starting fake Agentbox daemon socket"
python3 - "$SOCKET" <<'PY' &
import json
import os
import socket
import sys

path = sys.argv[1]
try:
    os.unlink(path)
except FileNotFoundError:
    pass

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)
conn, _ = server.accept()
with conn:
    _ = conn.recv(4096)
    conn.sendall(json.dumps({
        "decision": "blocked",
        "reason": "podman bridge smoke",
        "real_binary": "/bin/false"
    }).encode() + b"\n")
server.close()
PY
SERVER_PID="$!"

for _ in $(seq 1 50); do
  [[ -S "$SOCKET" ]] && break
  sleep 0.1
done
[[ -S "$SOCKET" ]] || {
  printf 'fake daemon socket did not appear at %s\n' "$SOCKET" >&2
  exit 1
}

log "proving daemon socket is visible inside a Podman minipod"
podman run --rm \
  -v "$SOCKET:$INTENDED_BRIDGE_PATH:ro" \
  alpine:3.20 \
  sh -c "test -S '$INTENDED_BRIDGE_PATH' && ! test -e '$SHIM_SOCKET_LINK'"

log "proving injected shim can execute through the provider bridge path"
podman run --rm \
  -e "HOME=/root" \
  -e "AGENTBOX_FAIL_MODE=closed" \
  -v "$SOCKET:$INTENDED_BRIDGE_PATH:ro" \
  -v "$SHIM:/usr/local/bin/agentbox-shim:ro" \
  alpine:3.20 \
  sh -c "mkdir -p /root/.agentbox && ln -sf '$INTENDED_BRIDGE_PATH' '$SHIM_SOCKET_LINK' && test \"\$(readlink '$SHIM_SOCKET_LINK')\" = '$INTENDED_BRIDGE_PATH' && ln -sf /usr/local/bin/agentbox-shim /usr/local/bin/git && PATH=\"/usr/local/bin:/bin:/usr/bin\" git push origin main 2>/tmp/agentbox-shim.err; test \"\$?\" -ne 0 && grep -qi \"blocked\\|denied\\|podman bridge smoke\" /tmp/agentbox-shim.err"

log "podman daemon socket and shim bridge smoke passed"
