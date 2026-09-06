#!/usr/bin/env bash
#
# run_boost_tests.sh — run the Boost unit-test binary under a bound, and make a
# HANG distinguishable from a FAILURE.
#
# CI-12. On 2026-09-05 seven CI jobs were killed at their job ceiling (four at
# 45m14s, one at 45m15s, one at 2h00m15s) and every one of them rendered in the
# rollup as an ordinary red. Each was adjudicated as a PR failure. None was:
# they were the same intermittent in-process hang in main's own mempool suites,
# which take 0.108s combined when healthy. Seven false verdicts in one day, on
# PRs that had nothing to do with the hung code.
#
# A job ceiling is the worst possible place to discover a hang:
#   * it costs the full ceiling (45 or 120 minutes) before saying anything,
#   * it reports "cancelled", which readers collapse into "failed", and
#   * it names no suite, so every reader has to go log-diving to learn that the
#     kill had nothing to do with their diff.
#
# This wrapper bounds the binary well under the ceiling and, on a timeout,
# prints a loud self-identifying marker naming the last suite and case Boost
# entered — which is the hung one. A 45-minute mystery cancellation becomes a
# fast, attributable failure.
#
# The mechanism is not new here. scripts/run_test_suites.sh has run the
# standalone suites under a per-suite `timeout` since F4, classifying a timeout
# as an outcome distinct from a failure. It was simply never applied to
# test_dilithion — the one binary that contains the suites that actually hang.
# This ports that local practice to it.
#
# CAVEAT, found while building this and reported separately: that script's
# TIMEOUT arm does not actually fire in the common case. See the note on the
# timeout invocation below — it passes --preserve-status but tests for 124/137,
# and a suite killed by SIGTERM returns 143. So the shape is right there and
# the detection is not. This script does not repeat that mistake.
#
# ---------------------------------------------------------------------------
# ON --swallow-failures, AND WHY THE TIMEOUT IS NEVER SWALLOWED
#
# Four jobs (asan, ubsan, tsan, coverage) currently invoke the binary with a
# trailing `|| true`, which discards its exit status. In those jobs a genuine
# test failure therefore renders GREEN, and the only things that can render
# them RED are a ceiling kill or infrastructure. That inversion is a separate
# defect with its own owner and its own held PR (#165), and this script does
# NOT pre-empt that decision: --swallow-failures reproduces today's `|| true`
# behaviour exactly for ordinary failures.
#
# But a timeout is ALWAYS reported and ALWAYS exits non-zero, swallow or not.
# A swallowed hang is strictly worse than a swallowed failure: the failure at
# least costs nothing, while the hang burns the entire job ceiling first and
# then lies about why. Nothing is gained by hiding it, so it is not hidden.
#
# When #165 lands, delete `--swallow-failures` from those four call sites and
# nothing else changes. The two fixes are orthogonal by construction.
# ---------------------------------------------------------------------------

set -uo pipefail

SWALLOW=0
LIMIT="${BOOST_TEST_TIMEOUT:-900}"
BIN="${BOOST_TEST_BIN:-./test_dilithion}"
LOGDIR="${BOOST_TEST_LOGDIR:-test-suite-logs}"

ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --swallow-failures) SWALLOW=1; shift ;;
        --timeout)          LIMIT="$2"; shift 2 ;;
        --bin)              BIN="$2";   shift 2 ;;
        *)                  ARGS+=("$1"); shift ;;
    esac
done

if [ ! -x "$BIN" ]; then
    echo "run_boost_tests.sh: FATAL: test binary '$BIN' not found or not executable" >&2
    # Deliberately fatal even under --swallow-failures. A missing binary means
    # zero tests ran, and "no tests ran" must never render as success -- that
    # is the vacuous-green shape this repo has already been bitten by.
    exit 2
fi

mkdir -p "$LOGDIR"
log="$LOGDIR/boost-test_dilithion.log"

start=$(date +%s)
# NOTE: deliberately NOT --preserve-status, and this differs from
# run_test_suites.sh:207 on purpose. --preserve-status makes timeout report the
# CHILD's status, so a process killed by SIGTERM yields 143 (128+15) and only a
# process that ignores SIGTERM until the -k SIGKILL yields 137. Plain timeout
# reports 124 for "I timed this out", which is the thing we actually want to
# detect. Measured on this host:
#     timeout --preserve-status -k 10 1 ./hang.sh  -> 143
#     timeout               -k 10 1 ./hang.sh      -> 124
# run_test_suites.sh:236 tests for 124 or 137 while :207 passes
# --preserve-status, so a suite that dies on SIGTERM returns 143, matches
# neither arm, and is reported [FAIL] rather than [TIMEOUT] -- a hang
# misfiling itself as a failure inside the very code meant to tell them apart.
# Reported separately; not fixed here, that script has its own owner.
# 137 and 143 are accepted below anyway, so this is correct either way.
timeout -k 10 "$LIMIT" "$BIN" "${ARGS[@]}" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
end=$(date +%s)
elapsed=$((end - start))

# 124 = timeout fired; 137 = SIGKILL after -k; 143 = SIGTERM at the limit.
if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then
    # The hung suite/case is the last one Boost announced entering. With
    # --log_level=test_suite it prints "Entering test suite/case" lines, so the
    # final one is where execution stopped.
    last_entered=$(grep -a 'Entering test' "$log" | tail -n 1)
    [ -z "$last_entered" ] && last_entered='(no "Entering test" line in the log — check --log_level)'

    echo
    echo "=============================================================================="
    echo "  ⛔ TIMEOUT — test_dilithion HUNG. This is NOT a test failure."
    echo "=============================================================================="
    echo "  Ran for ${elapsed}s against a ${LIMIT}s bound (exit ${rc})."
    echo
    echo "  HUNG AT: ${last_entered}"
    echo
    echo "  This bound is deliberately well under the job ceiling, so the job was"
    echo "  NOT cancelled by the runner -- the hang was caught and named here."
    echo
    echo "  Do NOT read this as a verdict on the diff under test. CI-12 is a known"
    echo "  intermittent in-process hang in main's own mempool suites; it fires on"
    echo "  whatever PR happens to be running. Confirm against the suite named above"
    echo "  before attributing it to this branch."
    echo
    echo "  ---- last 40 lines ----"
    tail -n 40 "$log" | sed 's/^/  | /'
    echo "=============================================================================="
    exit 124
fi

if [ "$rc" -ne 0 ]; then
    if [ "$SWALLOW" -eq 1 ]; then
        echo
        echo "run_boost_tests.sh: test_dilithion exited ${rc} after ${elapsed}s — SWALLOWED."
        echo "  This job still carries the legacy '|| true' behaviour (--swallow-failures),"
        echo "  so this red is being reported as green. See PR #165. A GREEN result from"
        echo "  this job is NOT evidence the tests passed."
        exit 0
    fi
    echo
    echo "run_boost_tests.sh: test_dilithion FAILED (exit ${rc}) after ${elapsed}s."
    exit "$rc"
fi

echo
echo "run_boost_tests.sh: test_dilithion passed in ${elapsed}s (bound ${LIMIT}s)."
exit 0
