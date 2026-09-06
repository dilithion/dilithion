#!/usr/bin/env bash
#
# Self-test for run_boost_tests.sh. Exercises every outcome against fake
# binaries, so the wrapper's behaviour is a MEASURED result and not a claim
# about what the script probably does.
#
# The load-bearing assertion is case 2: a hang must NOT be swallowed even when
# --swallow-failures is passed. If that ever regresses, the wrapper silently
# stops solving CI-12 while continuing to look installed and working -- the
# exact "reports success without working" shape this repo has been bitten by.

set -uo pipefail
cd "$(dirname "$0")/.."

WRAP=scripts/run_boost_tests.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASSED=0; FAILED=0

mk() { printf '%s\n' "$2" > "$TMP/$1"; chmod +x "$TMP/$1"; }

# A hang that has announced two suites — the second is the one it hangs in.
mk hang.sh '#!/bin/sh
echo "Entering test suite \"mempool_persist_tests\""
echo "Entering test case \"roundtrip_empty\""
sleep 300'
mk fail.sh '#!/bin/sh
echo "Entering test suite \"some_tests\""
echo "error: check failed"
exit 1'
mk pass.sh '#!/bin/sh
echo "Entering test suite \"some_tests\""
echo "*** No errors detected"
exit 0'

check() {
    local name="$1" want="$2" got="$3"
    if [ "$want" = "$got" ]; then
        printf '  [PASS] %-58s exit %s\n' "$name" "$got"; PASSED=$((PASSED+1))
    else
        printf '  [FAIL] %-58s want %s, got %s\n' "$name" "$want" "$got"; FAILED=$((FAILED+1))
    fi
}

echo "=== run_boost_tests.sh self-test ==="

out=$(BOOST_TEST_LOGDIR="$TMP/logs" bash "$WRAP" --bin "$TMP/hang.sh" --timeout 2 2>&1); rc=$?
check "hang -> exit 124" 124 "$rc"
case "$out" in *"TIMEOUT — test_dilithion HUNG"*) m=yes;; *) m=no;; esac
check "hang -> prints the TIMEOUT marker (yes)" yes "$m"
case "$out" in *"roundtrip_empty"*) m=yes;; *) m=no;; esac
check "hang -> names the hung case (yes)" yes "$m"

# THE LOAD-BEARING ONE.
out=$(BOOST_TEST_LOGDIR="$TMP/logs" bash "$WRAP" --bin "$TMP/hang.sh" --timeout 2 --swallow-failures 2>&1); rc=$?
check "hang + --swallow-failures -> STILL 124 (never swallowed)" 124 "$rc"

BOOST_TEST_LOGDIR="$TMP/logs" bash "$WRAP" --bin "$TMP/fail.sh" >/dev/null 2>&1; rc=$?
check "ordinary failure -> propagates exit 1" 1 "$rc"

BOOST_TEST_LOGDIR="$TMP/logs" bash "$WRAP" --bin "$TMP/fail.sh" --swallow-failures >/dev/null 2>&1; rc=$?
check "failure + --swallow-failures -> 0 (legacy '|| true' preserved)" 0 "$rc"

BOOST_TEST_LOGDIR="$TMP/logs" bash "$WRAP" --bin "$TMP/pass.sh" >/dev/null 2>&1; rc=$?
check "pass -> 0" 0 "$rc"

BOOST_TEST_LOGDIR="$TMP/logs" bash "$WRAP" --bin "$TMP/nope.sh" --swallow-failures >/dev/null 2>&1; rc=$?
check "missing binary -> 2 even when swallowing (no vacuous green)" 2 "$rc"

# Args must reach the binary, or the wrapper would silently run the FULL suite
# in jobs that rely on --run_test exclusions.
mk echoargs.sh '#!/bin/sh
echo "ARGS:$*"
exit 0'
out=$(BOOST_TEST_LOGDIR="$TMP/logs" bash "$WRAP" --bin "$TMP/echoargs.sh" --run_test='!wallet_hd_tests' 2>&1)
case "$out" in *"ARGS:--run_test=!wallet_hd_tests"*) m=yes;; *) m=no;; esac
check "passes through binary args verbatim (yes)" yes "$m"

echo
echo "  passed=$PASSED failed=$FAILED"
[ "$FAILED" -eq 0 ] || exit 1
