#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP: Linux nftables smoke must run on Linux"
  exit 77
fi

if [ "${AGENTBOX_LINUX_NFTABLES:-0}" != "1" ]; then
  echo "SKIP: set AGENTBOX_LINUX_NFTABLES=1 to run nftables live gate smoke"
  exit 77
fi

if ! command -v nft >/dev/null 2>&1; then
  echo "SKIP: nft command is not installed"
  exit 77
fi

table="agentbox_smoke_$$"
cleanup() {
  nft delete table inet "$table" >/dev/null 2>&1 || true
}
trap cleanup EXIT

nft add table inet "$table"
nft list table inet "$table" >/dev/null
nft delete table inet "$table"
trap - EXIT

echo "Linux nftables live gate smoke passed for inet table $table"
