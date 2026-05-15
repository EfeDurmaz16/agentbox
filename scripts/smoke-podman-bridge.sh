#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

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
HOME_IN_CONTAINER="/tmp/agentbox-home"
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
  -v "$SOCKET:$HOME_IN_CONTAINER/.agentbox/agentbox.sock:ro" \
  alpine:3.20 \
  sh -c "test -S '$HOME_IN_CONTAINER/.agentbox/agentbox.sock'"

log "proving injected shim can execute and reach the mounted socket"
podman run --rm \
  -e "HOME=$HOME_IN_CONTAINER" \
  -e "AGENTBOX_FAIL_MODE=closed" \
  -v "$SOCKET:$HOME_IN_CONTAINER/.agentbox/agentbox.sock:ro" \
  -v "$SHIM:/usr/local/bin/agentbox-shim:ro" \
  alpine:3.20 \
  sh -c 'ln -sf /usr/local/bin/agentbox-shim /usr/local/bin/git && PATH="/usr/local/bin:/bin:/usr/bin" git push origin main 2>/tmp/agentbox-shim.err; test "$?" -ne 0 && grep -qi "blocked\\|denied\\|podman bridge smoke" /tmp/agentbox-shim.err'

log "podman daemon socket and shim bridge smoke passed"
