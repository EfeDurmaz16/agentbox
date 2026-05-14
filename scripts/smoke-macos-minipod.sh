#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CLI=(cargo run -q -p agentbox-cli --)

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

if [[ "$(uname -s)" != "Darwin" ]]; then
  printf 'note: this script is named for macOS, but will run the same compatibility smoke on %s\n' "$(uname -s)"
fi

log "building Agentbox binaries"
cargo build -q -p agentbox-cli -p agentbox-daemon -p agentbox-shim

log "checking provider surface"
"${CLI[@]}" providers

log "checking Podman compatibility backend"
podman --version
if [[ "$(uname -s)" == "Darwin" ]]; then
  podman machine inspect >/dev/null 2>&1 || skip "podman machine is not initialized; run: podman machine init && podman machine start"
  podman machine inspect | rg -q '"Running": true|"State": "running"' || skip "podman machine is not running; run: podman machine start"
fi

SESSION_ID=""
cleanup() {
  if [[ -n "$SESSION_ID" ]]; then
    "${CLI[@]}" stop-pod "$SESSION_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log "creating a persistent minipod session"
CREATE_OUTPUT="$("${CLI[@]}" run --runtime python 2>&1)"
printf '%s\n' "$CREATE_OUTPUT"
SESSION_ID="$(printf '%s\n' "$CREATE_OUTPUT" | awk -F': ' '/Session id:/ {print $2}' | tail -1)"
if [[ -z "$SESSION_ID" ]]; then
  printf 'failed to parse session id from agentbox run output\n' >&2
  exit 1
fi

log "inspecting minipod session $SESSION_ID"
"${CLI[@]}" minipod-inspect "$SESSION_ID" --json

log "destroying persistent minipod session"
"${CLI[@]}" stop-pod "$SESSION_ID"
SESSION_ID=""

log "creating, executing, and destroying a command minipod"
printf 'y\n' | "${CLI[@]}" run --runtime python -- python -c 'print("agentbox-minipod-smoke")'

log "verifying evidence hash chain"
"${CLI[@]}" evidence --verify

log "macOS minipod compatibility smoke passed"
