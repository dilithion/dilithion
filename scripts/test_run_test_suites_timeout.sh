#!/usr/bin/env bash
# MERGE NOTE: the roster gained a fifth ARGS field, so these injected
# rows carry a trailing pipe. A 4-field row is now a ROSTER ERROR and the
# runner exits 2 before running anything -- which reads as every arm
# failing for its own reason rather than as one format mismatch.
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
echo "== drive the REAL runner against binaries that really hang / really fail =="
# Previously this section extracted the classifier expression with grep and
# `eval`d it. That was still a restatement: it exercised a string, never the
# runner, so the [TIMEOUT] arm and its FAILED increment had no coverage at all
# -- and the extraction broke the moment the condition spanned two lines.
#
# Instead: copy the real runner, swap ONLY its ROSTER for fake suites, and run
# it. Everything under test -- the timeout invocation, the classification, the
# printed row, the exit status -- is the real code.
drive() {                       # drive <script-body> <timeout> ; echoes row + counts
  local body="$1" tmo="$2" d
  d="$(mktemp -d)"
  # A source tree, because THE STALENESS GUARD IN THIS SAME RUNNER REFUSES TO
  # RUN WITHOUT ONE UNDER CI -- deliberately, so the guard can never silently
  # disable itself. Without these, every arm below fails under GITHUB_ACTIONS
  # with the runner exiting FATAL before it runs anything, while passing
  # locally where the CI variable is unset. That is exactly how this file
  # failed the gcc-Release leg on the branch that introduced the guard, and it
  # is a CI-ONLY reproduction: 9/0 locally, 3/6 with GITHUB_ACTIONS=true.
  #
  # Sources are back-dated a minute: the guard compares with -le on purpose
  # (same-second mtimes are not "demonstrably newer"), and one-second
  # filesystem granularity would otherwise mark the fake binary STALE.
  mkdir -p "$d/src"
  printf 'int main(){return 0;}
' > "$d/src/fake.cpp"
  printf 'all:
' > "$d/Makefile"
  touch -d "@$(( $(date +%s) - 60 ))" "$d/src/fake.cpp" "$d/Makefile"
  printf '%s' "$body" > "$d/fake_suite"
  chmod +x "$d/fake_suite"
  # REPLACE the roster, do not prepend to it. An earlier version inserted the
  # fake row and left the other ~41 rows in place, so 37 of them resolved to no
  # binary and reported [MISSING], supplying failed=37 all by themselves. That
  # made "a hung suite makes the runner exit non-zero" VACUOUS -- deleting the
  # TIMEOUT arm's FAILED increment still passed. With a one-row roster the
  # counts mean what they say.
  awk -v row="fast|fake_suite|${tmo}||" '
    /^ROSTER=.$/ { print; print row; skip=1; next }
    skip && /^.$/ { print; skip=0; next }
    skip { next }
    { print }
  ' "$RUNNER" > "$d/runner.sh"
  ( cd "$d" && TEST_SUITE_LOGDIR="$d/logs" bash runner.sh fast >"$d/out" 2>&1 )
  echo "RUNNER_EXIT=$?" >> "$d/out"
  grep -E '\[(TIMEOUT|FAIL|PASS) ' "$d/out" | head -1
  grep -E '^  ran=' "$d/out" | head -1
  grep -E '^RUNNER_EXIT=' "$d/out"
  rm -rf "$d"
}

# (a) A binary that genuinely hangs must be classified TIMEOUT.
#     Limit 20 (not 2): with the threshold now `elapsed >= timeout` and no
#     slack, a 2-second limit is too coarse to demonstrate the real arm -- the
#     comparison has to be made against a limit a hang can plausibly sit under.
out="$(drive '#!/usr/bin/env bash
sleep 300
' 20)"
case "$out" in
  *"[TIMEOUT"*) chk "a real hang is classified TIMEOUT by the real runner" "yes" "yes" ;;
  *)            echo "   FAIL  real hang not classified TIMEOUT. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac
# COUNT DELTA, not a bare non-zero exit: with a one-row roster, a hang must
# produce exactly ran=1 failed=1. "exit non-zero" alone was satisfiable by
# unrelated rows and so proved nothing.
case "$out" in
  *"ran=1  failed=1"*) chk "the hang is counted: ran=1 failed=1" "yes" "yes" ;;
  *)                   echo "   FAIL  counts wrong for a hung suite. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac

# (b) A binary that fails fast must be FAIL, not swallowed as a timeout.
out="$(drive '#!/usr/bin/env bash
exit 1
' 30)"
case "$out" in
  *"[FAIL"*) chk "a fast failure is classified FAIL (not a hang)" "yes" "yes" ;;
  *)         echo "   FAIL  fast failure misclassified. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac
case "$out" in
  *"ran=1  failed=1"*) chk "the fast failure is counted: ran=1 failed=1" "yes" "yes" ;;
  *)                   echo "   FAIL  counts wrong for a failing suite. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac

# (c) THE ELAPSED CHECK. A suite that SIGTERMs itself immediately exits 143 --
#     the same code `timeout` produces -- but it is not a hang and must not be
#     recorded as one. This is the case the exit-code-only classifier got wrong,
#     and it is live for the crash-injection and shutdown suites, which kill
#     themselves by design.
out="$(drive '#!/usr/bin/env bash
kill -TERM $$
sleep 5
' 300)"
case "$out" in
  *"[FAIL"*) chk "a self-SIGTERM that exits 143 EARLY is FAIL, not a false hang" "yes" "yes" ;;
  *)         echo "   FAIL  early self-SIGTERM recorded as a hang. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac

# (d) PIN THE SLACK MAGNITUDE, not just its sign. Case (c) catches slack=0 and
#     the wrong sign, but a regression back to a LARGE slack (the original 15s)
#     passes every case above -- so the magnitude was unpinned.
#     Limit 20 with a self-TERM at ~10s discriminates:
#         slack 2  -> threshold 18 -> 10 < 18 -> FAIL      (correct)
#         slack 15 -> threshold  5 -> 10 >= 5 -> TIMEOUT   (wrong, caught here)
out="$(drive '#!/usr/bin/env bash
sleep 10
kill -TERM $$
sleep 60
' 20)"
case "$out" in
  *"[FAIL"*) chk "a self-SIGTERM at ~half the limit is FAIL (slack magnitude pinned)" "yes" "yes" ;;
  *)         echo "   FAIL  mid-limit self-SIGTERM recorded as a hang - slack too large. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac

echo
echo "   ===== run_test_suites timeout classification: $P passed, $F failed ====="
[ "$F" -eq 0 ]
