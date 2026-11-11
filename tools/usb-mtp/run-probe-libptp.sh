#!/bin/sh
# run-probe-libptp.sh — wrapper for mtp_probe_libpt2: one upfront sweep of
# the macOS Image Capture trio (icdd/ptpcamerad/mscamerad-xpc hold PTP
# interfaces exclusively; they are user-owned), then exec the prober
# (which keeps killing them between claim retries itself).
#
# Usage: sh tools/usb-mtp/run-probe-libptp.sh [prober args...]
#   e.g. sh tools/usb-mtp/run-probe-libptp.sh --wait 30 --baseline
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
killall -9 icdd ptpcamerad mscamerad-xpc 2>/dev/null || true
exec "$HERE/mtp_probe_libpt2" "$@"
