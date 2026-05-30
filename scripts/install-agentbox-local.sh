#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${AGENTBOX_LOCAL_PREFIX:-$HOME/.local}"
DRY_RUN=0
RUN_TESTS=0
BINARY_DIR=""
ROLLBACK=0
ROLLBACK_FROM=""
BACKUP_ROOT=""

usage() {
  cat <<'EOF'
Usage: scripts/install-agentbox-local.sh [--prefix DIR] [--dry-run] [--run-tests]
       scripts/install-agentbox-local.sh --prefix DIR --rollback [--rollback-from DIR]

Build Agentbox from this checkout and install local development binaries into
PREFIX/bin. Defaults to ~/.local/bin and never uses sudo.

Options:
  --prefix DIR       Install under DIR/bin instead of ~/.local/bin
  --binary-dir DIR   Install prebuilt binaries from DIR instead of target/release
  --backup-root DIR  Store/lookup binary backups under DIR
  --rollback         Restore binaries from the latest backup and exit
  --rollback-from DIR
                     Restore binaries from a specific backup directory
  --dry-run          Print commands without mutating PREFIX
  --run-tests        Run cargo test --locked --workspace before installing
  -h, --help         Show this help
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix)
      if [ "$#" -lt 2 ]; then
        echo "error: --prefix requires a directory" >&2
        exit 2
      fi
      PREFIX="$2"
      shift 2
      ;;
    --binary-dir)
      if [ "$#" -lt 2 ]; then
        echo "error: --binary-dir requires a directory" >&2
        exit 2
      fi
      BINARY_DIR="$2"
      shift 2
      ;;
    --backup-root)
      if [ "$#" -lt 2 ]; then
        echo "error: --backup-root requires a directory" >&2
        exit 2
      fi
      BACKUP_ROOT="$2"
      shift 2
      ;;
    --rollback)
      ROLLBACK=1
      shift
      ;;
    --rollback-from)
      if [ "$#" -lt 2 ]; then
        echo "error: --rollback-from requires a directory" >&2
        exit 2
      fi
      ROLLBACK=1
      ROLLBACK_FROM="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --run-tests)
      RUN_TESTS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

PREFIX="${PREFIX%/}"
if [ -z "$PREFIX" ]; then
  PREFIX="/"
fi
BIN_DIR="$PREFIX/bin"
if [ -z "$BACKUP_ROOT" ]; then
  BACKUP_ROOT="$PREFIX/.agentbox-backups"
fi

BINARY_NAMES=(agentbox agentbox-cli agentbox-daemon agentbox-shim)

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if [ "$DRY_RUN" -eq 0 ]; then
    "$@"
  fi
}

install_binary() {
  local source="$1"
  local name="$2"

  if [ "$DRY_RUN" -eq 0 ] && [ ! -x "$source" ]; then
    echo "error: expected built binary at $source" >&2
    exit 1
  fi

  run install -m 0755 "$source" "$BIN_DIR/$name"
}

backup_existing_binaries() {
  local backup_id backup_dir created name
  backup_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  backup_dir="$BACKUP_ROOT/$backup_id"
  created=0

  for name in "${BINARY_NAMES[@]}"; do
    if [ -e "$BIN_DIR/$name" ]; then
      if [ "$created" -eq 0 ]; then
        run mkdir -p "$backup_dir/bin"
        created=1
      fi
      run cp -p "$BIN_DIR/$name" "$backup_dir/bin/$name"
    fi
  done

  if [ "$created" -eq 1 ]; then
    run ln -sfn "$backup_dir" "$BACKUP_ROOT/latest"
    cat <<EOF
Backed up existing Agentbox binaries to:
  $backup_dir
Rollback command:
  scripts/install-agentbox-local.sh --prefix "$PREFIX" --rollback
EOF
  else
    printf 'No existing Agentbox binaries found under %s; no rollback backup created.\n' "$BIN_DIR"
  fi
}

rollback_binaries() {
  local backup_dir backup_bin_dir name source

  if [ -n "$ROLLBACK_FROM" ]; then
    backup_dir="$ROLLBACK_FROM"
  else
    backup_dir="$BACKUP_ROOT/latest"
  fi
  backup_bin_dir="$backup_dir/bin"

  if [ "$DRY_RUN" -eq 0 ] && [ ! -d "$backup_bin_dir" ]; then
    echo "error: rollback backup not found: $backup_bin_dir" >&2
    exit 1
  fi

  run mkdir -p "$BIN_DIR"
  for name in "${BINARY_NAMES[@]}"; do
    source="$backup_bin_dir/$name"
    if [ "$DRY_RUN" -eq 0 ] && [ ! -x "$source" ]; then
      echo "error: rollback backup is missing executable $source" >&2
      exit 1
    fi
    run install -m 0755 "$source" "$BIN_DIR/$name"
  done

  cat <<EOF

Rolled back local Agentbox binaries from:
  $backup_dir

Preserved:
  $HOME/.agentbox/config.toml
  $HOME/.agentbox/audit.db
  $HOME/.agentbox/runtime-sessions.json
  $HOME/.agentbox/agentpods
EOF
}

cd "$ROOT"

if [ "$ROLLBACK" -eq 1 ]; then
  rollback_binaries
  exit 0
fi

if [ "$RUN_TESTS" -eq 1 ]; then
  run cargo test --locked --workspace
fi

if [ -z "$BINARY_DIR" ]; then
  run cargo build --locked --release \
    -p agentbox-cli \
    -p agentbox-daemon \
    -p agentbox-shim
  BINARY_DIR="$ROOT/target/release"
else
  printf 'Using prebuilt Agentbox binaries from:\n  %s\n' "$BINARY_DIR"
fi

run mkdir -p "$BIN_DIR"
backup_existing_binaries
install_binary "$BINARY_DIR/agentbox-cli" agentbox
install_binary "$BINARY_DIR/agentbox-cli" agentbox-cli
install_binary "$BINARY_DIR/agentbox-daemon" agentbox-daemon
install_binary "$BINARY_DIR/agentbox-shim" agentbox-shim

if [ "$DRY_RUN" -eq 1 ]; then
  cat <<EOF

Dry run complete. No files were installed.
Target local Agentbox binary directory:
  $BIN_DIR
EOF
else
  cat <<EOF

Installed local Agentbox binaries into:
  $BIN_DIR
EOF
fi

cat <<EOF
Preserved:
  $HOME/.agentbox/config.toml
  $HOME/.agentbox/audit.db
  $HOME/.agentbox/runtime-sessions.json
  $HOME/.agentbox/agentpods

Next:
  export PATH="$BIN_DIR:\$PATH"
  agentbox setup --dry-run --wizard
  agentbox install
  agentbox doctor
EOF
