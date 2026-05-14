#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${AGENTBOX_LINUX_SHIM_TARGET:-x86_64-unknown-linux-musl}"
PROFILE="${AGENTBOX_LINUX_SHIM_PROFILE:-release}"

case "$PROFILE" in
  debug)
    PROFILE_FLAG=""
    ;;
  release)
    PROFILE_FLAG="--release"
    ;;
  *)
    echo "error: AGENTBOX_LINUX_SHIM_PROFILE must be debug or release" >&2
    exit 2
    ;;
esac

if ! rustup target list --installed | grep -qx "$TARGET"; then
  echo "error: Rust target $TARGET is not installed" >&2
  echo "hint: rustup target add $TARGET" >&2
  exit 2
fi

cd "$ROOT"
cargo build -p agentbox-shim --target "$TARGET" $PROFILE_FLAG

ARTIFACT="$ROOT/target/$TARGET/$PROFILE/agentbox-shim"
if [ ! -f "$ARTIFACT" ]; then
  echo "error: expected shim artifact not found: $ARTIFACT" >&2
  exit 1
fi

if ! head -c 4 "$ARTIFACT" | od -An -tx1 | grep -qi '7f 45 4c 46'; then
  echo "error: built shim is not an ELF binary: $ARTIFACT" >&2
  exit 1
fi

echo "AGENTBOX_LINUX_SHIM=$ARTIFACT"
