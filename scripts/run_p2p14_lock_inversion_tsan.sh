#!/bin/bash
# Run BOTH arms of the P2P-14/15 cs_headers<->cs_main lock-inversion harness.
#
# Build first:  make TSAN=1 -j8 p2p14_lock_inversion_tsan_tests
# Then:         scripts/run_p2p14_lock_inversion_tsan.sh
#
# EXPECTED ON THE UNFIXED TREE (this is a RED baseline, not a passing test):
#   registered    -> HANGS (timeout, exit 124) and TSan reports lock-order-inversion
#   unregistered  -> exits 0 cleanly with 0 reports
# After the lock order is fixed, the registered arm should also exit 0 with 0 reports.
#
# The two arms differ by ONE line inside the binary (the RegisterTipUpdateCallback
# copied from dilithion-node.cpp:3551). The unregistered arm is the control: it
# proves a clean result is not just the harness failing to wire the cycle up.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
B=./p2p14_lock_inversion_tsan_tests

if [ ! -x "$B" ]; then
  echo "FATAL: $B not built. Run: make TSAN=1 -j8 p2p14_lock_inversion_tsan_tests"
  exit 2
fi

# "It ran" is not "it was instrumented". A TSan build that silently lost its
# instrumentation runs clean and looks identical to a pass. NOTE: nm -C reports
# 0 here even when correct -- the symbols are dynamic, so query nm -D.
SYMS=$(nm -D "$B" 2>/dev/null | grep -c tsan)
LINKED=$(ldd "$B" 2>/dev/null | grep -c libtsan)
echo "TSAN_SYMS_DYNAMIC=${SYMS}  LIBTSAN_LINKED=${LINKED}"
if [ "$SYMS" -eq 0 ] && [ "$LINKED" -eq 0 ]; then
  echo "FATAL: no ThreadSanitizer runtime in this binary — any result would be meaningless"
  exit 2
fi

export TSAN_OPTIONS="detect_deadlocks=1:second_deadlock_stack=1:halt_on_error=0"

rc_registered=0
rc_unregistered=0
for arm in registered unregistered; do
  echo "================ ARM: ${arm} ================"
  # setarch -R: without it TSan aborts before main with "unexpected memory
  # mapping" on modern kernels, which looks like TSan being broken and is not.
  timeout -k 5 120 setarch "$(uname -m)" -R "$B" "${arm}" \
    >"/tmp/p2p14_${arm}.out" 2>"/tmp/p2p14_${arm}.err"
  rc=$?
  [ "$arm" = registered ] && rc_registered=$rc || rc_unregistered=$rc
  echo "EXIT=${rc}"
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then
    echo "VERDICT: HUNG — a real deadlock, not merely an observed inversion"
  fi
  echo "INVERSION_REPORTS=$(grep -c 'lock-order-inversion' "/tmp/p2p14_${arm}.err")"
  grep -E 'EDGE-|REACH' "/tmp/p2p14_${arm}.out" 2>/dev/null
done

echo "================ SUMMARY ================"
echo "registered   EXIT=${rc_registered}"
echo "unregistered EXIT=${rc_unregistered}"

# ---------------------------------------------------------------------------
# EXIT STATUS — added by P2P-14/15 after the final red-team named the
# "unconditional green" class as the largest unaudited hole, and it was here.
#
# This script previously ENDED on the echo above. It captured rc_registered and
# rc_unregistered, printed them, and then exited 0 — the status of the last
# echo. So the registered arm could HANG (exit 124, which is the whole RED
# signal this harness exists to produce) and CI would still see a green run.
# A harness built to demonstrate a deadlock could not fail a build.
#
# Measured, not assumed: before this block, `bash run_p2p14_lock_inversion_tsan.sh;
# echo $?` printed 0 on a tree where both arms were clean AND would have printed
# 0 on a tree where the registered arm hung.
#
# Semantics now: the fixed tree must have BOTH arms exit 0 with ZERO
# lock-order-inversion reports. Anything else is a failure.
#
# NOTE FOR THE RED BASELINE: on an UNFIXED tree this script is now EXPECTED to
# exit 1 — that is correct and is what makes it a regression test rather than a
# demonstration. Do not "fix" that by relaxing this check.
fail=0
for arm in registered unregistered; do
    err="/tmp/p2p14_${arm}.err"
    rc_var="rc_${arm}"
    rc="${!rc_var}"
    # grep -c PRINTS 0 and RETURNS 1 when there are no matches, so a
    # `|| echo 0` fallback appends a SECOND line and the integer test below
    # then fails with "integer expression expected" — caught by running it.
    inv=0
    if [ -f "$err" ]; then
        inv=$(grep -c 'lock-order-inversion' "$err" 2>/dev/null)
        inv=${inv:-0}
    fi
    if [ "${rc:-1}" -ne 0 ]; then
        echo "FAIL: arm '$arm' exited ${rc} (124 = hung = the deadlock reproduced)"
        fail=1
    fi
    if [ "$inv" -gt 0 ]; then
        echo "FAIL: arm '$arm' reported ${inv} lock-order-inversion(s)"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL — the cs_headers lock-order cycle is present on this tree"
    exit 1
fi
echo "RESULT: PASS — both arms clean, zero inversions"
exit 0
