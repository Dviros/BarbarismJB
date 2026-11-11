#!/usr/bin/env bash
# tests/run-all.sh — BarbarismJB offline verification: everything that can be
# checked without a console, in one deterministic, headless run.
#
# Steps: node --check syntax sweep over every first-party .cjs/.js file, the
# protocol conformance suite (real host stack vs fake console), the civshim
# simulation (real payload vs stubbed loader primitives), and the python tool
# self-tests. Prints a summary table; exits non-zero if any step failed.
# Origin: original — BarbarismJB.
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

pass=0
fail=0
failed_names=()

record() { # name status(0 ok / 1 fail) detail
  if [ "$2" -eq 0 ]; then
    pass=$((pass + 1))
    printf '  ok    %s\n' "$1"
  else
    fail=$((fail + 1))
    failed_names+=("$1")
    printf '  FAIL  %s %s\n' "$1" "${3:-}"
  fi
}

echo "BarbarismJB test sweep — $ROOT"
echo
mkdir -p runs

# Watchdog wrapper: no step may wedge the sweep. A step that exceeds its
# budget is killed and recorded as failed, with its name marked (timeout).
run_step() { # timeout_seconds command [args...]
  local budget=$1; shift
  "$@" &
  local step_pid=$!
  ( sleep "$budget" 2>/dev/null; kill "$step_pid" 2>/dev/null ) & local guard=$!
  wait "$step_pid"
  local rc=$?
  kill "$guard" 2>/dev/null; wait "$guard" 2>/dev/null
  if [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then
    echo "  (timeout after ${budget}s: $*)"
  fi
  return "$rc"
}

# 1) Syntax sweep over every first-party JS file.
syntax_detail=""
js_count=$(find run.cjs engine payloads tests -type f \( -name '*.cjs' -o -name '*.js' \) | wc -l | tr -d ' ')
while IFS= read -r file; do
  if ! node --check "$file" >/dev/null 2>&1; then
    syntax_detail="$syntax_detail $file"
  fi
done < <(find run.cjs engine payloads tests -type f \( -name '*.cjs' -o -name '*.js' \) | LC_ALL=C sort)
if [ -n "$syntax_detail" ]; then
  record "node --check sweep" 1 "($syntax_detail )"
else
  record "node --check sweep ($js_count files)" 0
fi

# 2) Host-stack protocol conformance.
if run_step 300 node tests/protocol-conformance.cjs; then
  record "protocol conformance" 0
else
  record "protocol conformance" 1
fi

# 3) Console-side civshim simulation.
if run_step 300 node tests/civshim-sim.cjs; then
  record "civshim simulation" 0
else
  record "civshim simulation" 1
fi

# 3b) Shell layer simulation.
if run_step 120 node tests/shell-sim.cjs; then
  record "shell simulation" 0
else
  record "shell simulation" 1
fi

# 4) Python tool self-tests (each watchdogged: a wedged self-test must fail
# the sweep, not stall it).
if run_step 60 python3 tools/svc_scan.py --self-test; then record "svc_scan self-test" 0; else record "svc_scan self-test" 1; fi
if run_step 60 python3 tools/gadget_scan.py --self-test; then record "gadget_scan self-test" 0; else record "gadget_scan self-test" 1; fi
if run_step 60 python3 tools/dump_recv.py --self-test; then record "dump_recv self-test" 0; else record "dump_recv self-test" 1; fi
# npdm.py --self-test validates parser invariants against a REAL ro NPDM.
# The fixture is Nintendo-copyrighted, so it is never vendored: point
# BARBARISM_NPDM_FIXTURE at one (defaults to the reference dump's ro NPDM).
NPDM_FIXTURE="${BARBARISM_NPDM_FIXTURE:?set BARBARISM_NPDM_FIXTURE to a dump-root npdm fixture}"
if [ -r "$NPDM_FIXTURE" ]; then
  if run_step 60 python3 tools/npdm.py --self-test "$NPDM_FIXTURE" >/dev/null 2>&1; then record "npdm self-test" 0; else record "npdm self-test" 1; fi
else
  echo "  skip  npdm self-test (no fixture: set BARBARISM_NPDM_FIXTURE)"
fi
if run_step 120 python3 tools/validate_ipc.py --self-test >/dev/null 2>&1; then record "validate_ipc self-test" 0; else record "validate_ipc self-test" 1; fi
if run_step 60 python3 -I tools/make_test_nso.py "$ROOT/runs/test-nso-smoke.nso" 2>/dev/null && [ -s "$ROOT/runs/test-nso-smoke.nso" ]; then
  record "make_test_nso smoke" 0
else
  record "make_test_nso smoke" 1
fi
rm -f "$ROOT/runs/test-nso-smoke.nso"

# 5) webkit-rig launcher self-test (loopback-only: portal+dns on high ports,
# conntest 302, applet banner + kit-page journaling, kit pages + their
# node --check, parked-page exclusion, stale-listener hygiene, journal,
# teardown port-verification; no console, no pf, no sudo).
if run_step 90 python3 tools/webkit-rig/launch.py --self-test; then record "webkit-rig launcher self-test" 0; else record "webkit-rig launcher self-test" 1; fi

echo
echo "────────────────────────────────────────────"
printf '  %-24s %s\n' "Total:" "$((pass + fail))"
printf '  %-24s %s\n' "Passed:" "$pass"
printf '  %-24s %s\n' "Failed:" "$fail"
echo "────────────────────────────────────────────"
if [ "$fail" -ne 0 ]; then
  printf 'Failed steps: %s\n' "${failed_names[*]}"
  exit 1
fi
echo "ALL GREEN"
exit 0
