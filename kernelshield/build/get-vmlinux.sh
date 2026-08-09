#!/usr/bin/env bash
# get-vmlinux.sh — гарантирует наличие vmlinux.h.
# Порядок: 1) /sys/kernel/btf/vmlinux (bpftool dump)
#          2) локальный vmlinux.btf  (VMLINUX_BTF env)
#          3) BTFHub для известных дистрибутивов (бекап)
set -euo pipefail

VMLINUX_H="${1:-include/vmlinux.h}"
BPFTOOL="${BPFTOOL:-bpftool}"

mkdir -p "$(dirname "$VMLINUX_H")"

if [ -f /sys/kernel/btf/vmlinux ]; then
  echo "[vmlinux] dumping from /sys/kernel/btf/vmlinux"
  $BPFTOOL btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_H"
  exit 0
fi

if [ -n "${VMLINUX_BTF:-}" ] && [ -f "$VMLINUX_BTF" ]; then
  echo "[vmlinux] dumping from $VMLINUX_BTF"
  $BPFTOOL btf dump file "$VMLINUX_BTF" format c > "$VMLINUX_H"
  exit 0
fi

echo "[vmlinux] ERROR: BTF not found. Provide VMLINUX_BTF or run on a BTF-enabled kernel." >&2
exit 1
