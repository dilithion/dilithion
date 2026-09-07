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
# Classification uses the SAME exit codes run_test_suites.sh uses post-#180:
# 124/137/143 = TIMEOUT (hang), anything else non-zero = FAIL.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
N="${N:-20}"
BIN="${BIN:-./rpc_tests}"
# Both suites are measured the same way: BIN=./integration_tests N=20 ...
TMO="${TMO:-60}"

pass=0; fail=0; hang=0
declare -A codes
for i in $(seq 1 "$N"); do
  timeout --preserve-status -k 5 "$TMO" "$BIN" >"/tmp/rpcrun_$i.out" 2>&1
  rc=$?
  codes[$rc]=$(( ${codes[$rc]:-0} + 1 ))
  if [ "$rc" -eq 0 ]; then pass=$((pass+1))
  elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then hang=$((hang+1))
  else fail=$((fail+1)); fi
done

echo "runs=$N  PASS=$pass  FAIL=$fail  HANG(124/137/143)=$hang"
echo -n "exit-code histogram: "
for c in "${!codes[@]}"; do echo -n "$c x${codes[$c]}  "; done
echo
echo "--- first run's tail ---"
tail -12 /tmp/rpcrun_1.out
