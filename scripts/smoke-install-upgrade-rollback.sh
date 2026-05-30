#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

log() {
  printf '\n==> %s\n' "$*"
}

make_bin() {
  local path="$1"
  local marker="$2"
  cat >"$path" <<EOF
#!/usr/bin/env sh
printf '%s\n' '$marker'
EOF
  chmod 0755 "$path"
}

PREFIX="$TMPDIR/prefix"
BIN_DIR="$PREFIX/bin"
BACKUP_ROOT="$TMPDIR/backups"
NEW_BIN_DIR="$TMPDIR/new-bin"
HOME_DIR="$TMPDIR/home"
AGENTBOX_DIR="$HOME_DIR/.agentbox"

mkdir -p "$BIN_DIR" "$NEW_BIN_DIR" "$AGENTBOX_DIR/agentpods/session/evidence"
make_bin "$BIN_DIR/agentbox" "old agentbox"
make_bin "$BIN_DIR/agentbox-cli" "old agentbox-cli"
make_bin "$BIN_DIR/agentbox-daemon" "old agentbox-daemon"
make_bin "$BIN_DIR/agentbox-shim" "old agentbox-shim"
make_bin "$NEW_BIN_DIR/agentbox-cli" "new agentbox-cli"
make_bin "$NEW_BIN_DIR/agentbox-daemon" "new agentbox-daemon"
make_bin "$NEW_BIN_DIR/agentbox-shim" "new agentbox-shim"
printf 'config\n' >"$AGENTBOX_DIR/config.toml"
printf 'audit\n' >"$AGENTBOX_DIR/audit.db"
printf '{}\n' >"$AGENTBOX_DIR/runtime-sessions.json"
printf '{}\n' >"$AGENTBOX_DIR/agentpods/session/evidence/receipt.json"

log "checking upgrade backs up existing binaries and preserves state"
HOME="$HOME_DIR" scripts/install-agentbox-local.sh \
  --prefix "$PREFIX" \
  --backup-root "$BACKUP_ROOT" \
  --binary-dir "$NEW_BIN_DIR" >"$TMPDIR/install.out"
grep -F "Backed up existing Agentbox binaries" "$TMPDIR/install.out" >/dev/null
grep -F "new agentbox-cli" "$BIN_DIR/agentbox" >/dev/null
grep -F "new agentbox-cli" "$BIN_DIR/agentbox-cli" >/dev/null
grep -F "new agentbox-daemon" "$BIN_DIR/agentbox-daemon" >/dev/null
grep -F "new agentbox-shim" "$BIN_DIR/agentbox-shim" >/dev/null
grep -F "old agentbox" "$BACKUP_ROOT/latest/bin/agentbox" >/dev/null
grep -F "old agentbox-cli" "$BACKUP_ROOT/latest/bin/agentbox-cli" >/dev/null
test -e "$AGENTBOX_DIR/config.toml"
test -e "$AGENTBOX_DIR/audit.db"
test -e "$AGENTBOX_DIR/runtime-sessions.json"
test -e "$AGENTBOX_DIR/agentpods/session/evidence/receipt.json"

log "checking rollback restores previous working binaries"
HOME="$HOME_DIR" scripts/install-agentbox-local.sh \
  --prefix "$PREFIX" \
  --backup-root "$BACKUP_ROOT" \
  --rollback >"$TMPDIR/rollback.out"
grep -F "Rolled back local Agentbox binaries" "$TMPDIR/rollback.out" >/dev/null
grep -F "old agentbox" "$BIN_DIR/agentbox" >/dev/null
grep -F "old agentbox-cli" "$BIN_DIR/agentbox-cli" >/dev/null
grep -F "old agentbox-daemon" "$BIN_DIR/agentbox-daemon" >/dev/null
grep -F "old agentbox-shim" "$BIN_DIR/agentbox-shim" >/dev/null
test -e "$AGENTBOX_DIR/config.toml"
test -e "$AGENTBOX_DIR/audit.db"
test -e "$AGENTBOX_DIR/runtime-sessions.json"
test -e "$AGENTBOX_DIR/agentpods/session/evidence/receipt.json"

log "checking rollback requires a complete backup"
rm -f "$BACKUP_ROOT/latest/bin/agentbox-shim"
if HOME="$HOME_DIR" scripts/install-agentbox-local.sh \
  --prefix "$PREFIX" \
  --backup-root "$BACKUP_ROOT" \
  --rollback >"$TMPDIR/incomplete-rollback.out" 2>"$TMPDIR/incomplete-rollback.err"; then
  echo "rollback accepted an incomplete backup" >&2
  exit 1
fi
grep -F "rollback backup is missing executable" "$TMPDIR/incomplete-rollback.err" >/dev/null

log "install upgrade rollback smoke passed"
