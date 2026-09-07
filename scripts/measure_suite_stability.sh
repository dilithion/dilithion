#!/bin/bash
# Is a suite a deterministic FAIL, an intermittent flake, or a HANG?
#
# Usage:  N=20 BIN=./rpc_tests TMO=60 scripts/measure_suite_stability.sh
#
# Written while un-quarantining rpc_tests: before lifting a quarantine you need
# to know WHICH of the three a suite is, and one run cannot tell you.
#
# A quarantine reason is a PREDICTION until it is run, and consecutive greens
# (or reds) are not a rate measurement -- 4 samples at a 10% rate is a 66%
# likely outcome -- so this defaults to N=20.
#
# NOTE: --preserve-status must come BEFORE the duration; after it, timeout
# treats it as the COMMAND and every run exits 126 ("Permission denied"),
# which tallies as 20/20 FAIL and looks exactly like a real result.
# Classification: 124/137/143 = TIMEOUT (hang), anything else non-zero = FAIL.
# NOTE, and this is a live gap rather than a footnote: run_test_suites.sh:259
# currently matches only 124 and 137, NOT 143 -- so a suite killed by SIGTERM
# under `timeout --preserve-status` is filed by the gate as [FAIL], not
# [TIMEOUT]. PR #180 adds 143 and is still an open draft at time of writing.
# Until it lands, a hang and a test failure are indistinguishable in the gate's
# own output; this script tells them apart, which is why it prints the
# histogram rather than a verdict.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
N="${N:-20}"
BIN="${BIN:-./rpc_tests}"
# Both suites are measured the same way: BIN=./integration_tests N=20 ...
TMO="${TMO:-60}"

[ -x "$BIN" ] || { echo "FATAL: $BIN is not built/executable -- an unbuilt binary exits 127"; echo "and would tally as a deterministic 20/20 FAIL, i.e. exactly like a suite"; echo "that deserves to stay quarantined."; exit 2; }

pass=0; fail=0; hang=0
first_bad=""
RUNDIR="$(mktemp -d)"   # per-invocation: the header invites running this twice
trap 'rm -rf "$RUNDIR"' EXIT
declare -A codes
for i in $(seq 1 "$N"); do
  timeout --preserve-status -k 5 "$TMO" "$BIN" >"$RUNDIR/run_$i.out" 2>&1
  rc=$?
  codes[$rc]=$(( ${codes[$rc]:-0} + 1 ))
  if [ "$rc" -eq 0 ]; then pass=$((pass+1))
  elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then hang=$((hang+1)); [ -z "$first_bad" ] && first_bad="$i"
  else fail=$((fail+1)); [ -z "$first_bad" ] && first_bad="$i"; fi
done

echo "runs=$N  PASS=$pass  FAIL=$fail  HANG(124/137/143)=$hang"
echo -n "exit-code histogram: "
for c in "${!codes[@]}"; do echo -n "$c x${codes[$c]}  "; done
echo
# Show a FAILING run when there is one: on 19-pass/1-fail the passing tail is
# the one run you do not need.
show="${first_bad:-1}"
echo "--- tail of run ${show} ---"
tail -12 "$RUNDIR/run_${show}.out"
