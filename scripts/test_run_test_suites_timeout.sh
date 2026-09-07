#!/usr/bin/env bash
# Self-test for run_test_suites.sh's TIMEOUT classification.
#
# WHY THIS FILE EXISTS. The runner classified a timed-out suite by matching exit
# codes 124 and 137. But the runner invokes `timeout --preserve-status`, whose
# whole purpose is to return the command's SIGNAL-derived status instead of
# timeout's own 124 — and a SIGTERM'd child is 128+15 = 143. So the common case
# never matched, and EVERY HANG WAS REPORTED AS A TEST FAILURE, with the TIMEOUT
# count structurally pinned at zero.
#
# Reading the script did not catch that; the man page says "exit status 124 if
# the command times out", and the --preserve-status caveat is a sentence further
# down. What catches it is running a binary that actually hangs and asserting on
# the number that comes back. That is all this file does.
#
# It asserts against the REAL runner's classification expression, extracted from
# the script rather than restated here — a copy of the condition would agree with
# a wrong condition just as happily.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
RUNNER="${1:-$HERE/run_test_suites.sh}"
P=0; F=0
chk(){ if [ "$2" = "$3" ]; then echo "   PASS  $1 ($2)"; P=$((P+1)); else echo "   FAIL  $1 got=$2 want=$3"; F=$((F+1)); fi; }

[ -f "$RUNNER" ] || { echo "FAIL: runner not found at $RUNNER" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. GROUND TRUTH — what does a real timeout return on THIS machine?
#    Not asserted from documentation; measured, because the answer differs with
#    and without --preserve-status and that difference is the entire defect.
# ---------------------------------------------------------------------------
echo "== ground truth: exit codes from a binary that really hangs =="
timeout --preserve-status -k 10 1 sleep 30; rc_preserve=$?
timeout -k 10 1 sleep 30;                   rc_plain=$?
trapper="$(mktemp)"; printf '#!/usr/bin/env bash\ntrap "" TERM\nsleep 30\n' > "$trapper"; chmod +x "$trapper"
timeout --preserve-status -k 2 1 bash "$trapper" 2>/dev/null; rc_kill=$?
rm -f "$trapper"
chk "--preserve-status, SIGTERM honoured -> 143" "$rc_preserve" "143"
chk "no --preserve-status              -> 124" "$rc_plain" "124"
chk "--preserve-status, SIGTERM ignored -> 137 (SIGKILL after -k)" "$rc_kill" "137"

# ---------------------------------------------------------------------------
# 2. THE RUNNER MUST CLASSIFY ALL THREE AS A TIMEOUT.
#    The condition is lifted out of the runner verbatim, so this test tracks the
#    real code instead of a restatement of it.
# ---------------------------------------------------------------------------
echo
echo "== the runner's own classification expression, applied to those codes =="
COND="$(grep -oE '\[ "\$rc" -eq 124 \].*then' "$RUNNER" | head -1 | sed 's/; then$//')"
if [ -z "$COND" ]; then
  echo "   FAIL  could not extract the timeout condition from $RUNNER"; F=$((F+1))
else
  echo "   condition: $COND"
  for code in 124 137 143; do
    rc="$code"
    if eval "$COND"; then verdict=TIMEOUT; else verdict=FAIL; fi
    chk "exit $code is classified TIMEOUT (not a test failure)" "$verdict" "TIMEOUT"
  done
  # Non-timeout codes must NOT be swallowed as timeouts, or a real failing suite
  # would be filed as a hang — the same defect pointing the other way.
  for code in 1 2 139; do
    rc="$code"
    if eval "$COND"; then verdict=TIMEOUT; else verdict=FAIL; fi
    chk "exit $code is still a FAILURE (no over-broad match)" "$verdict" "FAIL"
  done
fi

echo
echo "   ===== run_test_suites timeout classification: $P passed, $F failed ====="
[ "$F" -eq 0 ]
