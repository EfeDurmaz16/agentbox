#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DIST_DIR="${AGENTBOX_RELEASE_DIST_DIR:-target/agentbox-release-artifacts}"
VERSION_RAW="${AGENTBOX_RELEASE_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || git rev-parse --short HEAD)}"
VERSION="$(printf '%s' "$VERSION_RAW" | sed 's/[^A-Za-z0-9._-]/-/g')"

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Linux:x86_64) printf 'x86_64-unknown-linux-gnu' ;;
    Linux:aarch64 | Linux:arm64) printf 'aarch64-unknown-linux-gnu' ;;
    Darwin:x86_64) printf 'x86_64-apple-darwin' ;;
    Darwin:arm64 | Darwin:aarch64) printf 'aarch64-apple-darwin' ;;
    *) printf '%s-%s' "$(printf '%s' "$os" | tr '[:upper:]' '[:lower:]')" "$arch" ;;
  esac
}

TARGET="${AGENTBOX_RELEASE_TARGET:-$(detect_target)}"
ARCHIVE_BASE="agentbox-${VERSION}-${TARGET}"
STAGING_DIR="${DIST_DIR}/${ARCHIVE_BASE}"
ARCHIVE_NAME="${ARCHIVE_BASE}.tar.gz"

REQUIRED_BINARIES=(
  agentbox-cli
  agentbox-daemon
  agentbox-shim
)

OPTIONAL_BINARIES=(
  agentbox-remote-worker
  agentbox-linux-runner
  agentbox-macos-vm-runner
)

rm -rf "$DIST_DIR"
mkdir -p "$STAGING_DIR/bin"

for bin in "${REQUIRED_BINARIES[@]}"; do
  source_path="target/release/${bin}"
  if [ ! -x "$source_path" ]; then
    echo "error: missing release binary: $source_path" >&2
    echo "hint: run cargo build --locked --release --workspace first" >&2
    exit 1
  fi
  cp "$source_path" "$STAGING_DIR/bin/$bin"
done

for bin in "${OPTIONAL_BINARIES[@]}"; do
  source_path="target/release/${bin}"
  if [ -x "$source_path" ]; then
    cp "$source_path" "$STAGING_DIR/bin/$bin"
  fi
done

cp README.md LICENSE "$STAGING_DIR/"
mkdir -p "$STAGING_DIR/docs"
cp docs/local-install.md docs/release-readiness.md docs/limitations.md "$STAGING_DIR/docs/"

python3 - "$STAGING_DIR" "$VERSION" "$TARGET" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone

staging = pathlib.Path(sys.argv[1])
version = sys.argv[2]
target = sys.argv[3]
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
status = subprocess.check_output(["git", "status", "--short", "--branch"], text=True).strip()

files = []
for path in sorted(staging.rglob("*")):
    if path.is_file():
        rel = path.relative_to(staging).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files.append({"path": rel, "sha256": digest, "bytes": path.stat().st_size})

manifest = {
    "schema_version": 1,
    "product": "agentbox-agentpod",
    "version": version,
    "target": target,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "git_commit": commit,
    "git_status": status,
    "files": files,
}
(staging / "RELEASE_MANIFEST.json").write_text(
    json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
)

signing = {
    "schema_version": 1,
    "artifact_integrity": "sha256-checksums",
    "code_signing": {
        "configured": False,
        "signed": False,
        "claim": "No platform code signing, notarization, minisign, or cosign blob signature is configured by this package script.",
    },
    "provenance": {
        "configured_in_ci": True,
        "workflow": ".github/workflows/release.yml",
        "claim": "GitHub Actions release workflow is expected to attach Sigstore-backed GitHub artifact attestations for the archive checksum subjects.",
    },
}
(staging / "SIGNING_STATUS.json").write_text(
    json.dumps(signing, indent=2) + "\n", encoding="utf-8"
)
PY

tar -C "$DIST_DIR" -czf "$DIST_DIR/$ARCHIVE_NAME" "$ARCHIVE_BASE"
rm -rf "$STAGING_DIR"

(
  cd "$DIST_DIR"
  shasum -a 256 "$ARCHIVE_NAME" >SHA256SUMS
)

printf 'release_archive=%s\n' "$DIST_DIR/$ARCHIVE_NAME"
printf 'checksums=%s\n' "$DIST_DIR/SHA256SUMS"
