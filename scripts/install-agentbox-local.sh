#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${AGENTBOX_LOCAL_PREFIX:-$HOME/.local}"
DRY_RUN=0
RUN_TESTS=0

usage() {
  cat <<'EOF'
Usage: scripts/install-agentbox-local.sh [--prefix DIR] [--dry-run] [--run-tests]

Build Agentbox from this checkout and install local development binaries into
PREFIX/bin. Defaults to ~/.local/bin and never uses sudo.

Options:
  --prefix DIR   Install under DIR/bin instead of ~/.local/bin
  --dry-run      Print commands without mutating PREFIX
  --run-tests    Run cargo test --locked --workspace before installing
  -h, --help     Show this help
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

cd "$ROOT"

if [ "$RUN_TESTS" -eq 1 ]; then
  run cargo test --locked --workspace
fi

run cargo build --locked --release \
  -p agentbox-cli \
  -p agentbox-daemon \
  -p agentbox-shim

run mkdir -p "$BIN_DIR"
install_binary "$ROOT/target/release/agentbox-cli" agentbox
install_binary "$ROOT/target/release/agentbox-cli" agentbox-cli
install_binary "$ROOT/target/release/agentbox-daemon" agentbox-daemon
install_binary "$ROOT/target/release/agentbox-shim" agentbox-shim

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
Next:
  export PATH="$BIN_DIR:\$PATH"
  agentbox setup --dry-run --wizard
  agentbox install
  agentbox doctor
EOF
