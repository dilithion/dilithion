#!/usr/bin/env bash
# Self-test for run_test_suites.sh's per-row ARGS field and `partial:` semantics.
#
# WHY THIS FILE EXISTS
# --------------------
# A census of every roster suite (2026-09-07, 51 rows) found ZERO Boost suites:
# every one is a hand-written main() that calls scenario functions in sequence,
# and 24 of them assert(). An assert() aborts the PROCESS, so on any failing
# suite only the FIRST failing case is ever observed and every later scenario in
# the file HAS NEVER RUN AT ALL. That makes every quarantine reason of the form
# "N assertions fail" a systematic UNDERCOUNT, and it makes the quarantine
# itself all-or-nothing: one broken scenario takes the whole file out of the
# gate, including the scenarios that were passing.
#
# The fix is a per-row ARGS field plus a `partial:` reason prefix, so a row can
# run the scenarios that work while excluding, in writing, the ones that do not.
#
# THE SINGLE INVARIANT this file pins:
#   a NON-EMPTY reason means SOMETHING IN THIS ROW IS NOT RUN.
#     ""          -> live; the whole suite runs; ARGS must be empty.
#     "partial:"  -> live WITH ARGS; the suite runs, and the reason says which
#                    part is excluded; ARGS must be NON-empty.
#     anything    -> quarantined; nothing runs; ARGS must be empty.
#
# The two ERROR arms are the load-bearing ones. A `partial:` row with empty ARGS
# excludes nothing while claiming to, and ARGS on a non-partial row runs
# something other than what the roster says -- both are a gate reporting on a
# scope nobody declared. They FATAL, and they FATAL under --list too, because
# --list is what the Makefile builds from: a roster error must break the build,
# not silently produce a shorter list.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
RUNNER="${1:-$HERE/run_test_suites.sh}"
P=0; F=0
chk(){ if [ "$2" = "$3" ]; then echo "   PASS  $1"; P=$((P+1)); else echo "   FAIL  $1 got=$2 want=$3"; F=$((F+1)); fi; }
fail(){ echo "   FAIL  $1"; shift; printf '%s\n' "$@" | sed 's/^/     | /' | head -12; F=$((F+1)); }

[ -f "$RUNNER" ] || { echo "FAIL: runner not found at $RUNNER" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Sandbox: a runner whose ROSTER is REPLACED (not prepended) by the rows under
# test, plus a fake suite binary that ECHOES ITS ARGV -- which is the only way
# to assert ARGS actually reached the process rather than merely being printed
# in a column.
# ---------------------------------------------------------------------------
sandbox() {               # sandbox <exit-code> <roster-row>...
    local rc="$1"; shift
    local d; d="$(mktemp -d)"
    {
      echo '#!/usr/bin/env bash'
      echo 'echo "ARGV_COUNT=$#"'
      echo 'for a in "$@"; do echo "ARGV=$a"; done'
      echo "exit $rc"
    } > "$d/fake_suite"
    chmod +x "$d/fake_suite"
    cp "$d/fake_suite" "$d/other_suite"
    local rows; rows="$(printf '%s\n' "$@")"
    awk -v rows="$rows" '
      /^ROSTER=.$/ { print; print rows; skip=1; next }
      skip && /^.$/ { print; skip=0; next }
      skip { next }
      { print }
    ' "$RUNNER" > "$d/runner.sh"
    echo "$d"
}

drive() {                 # drive <exit-code> <row>... ; prints output + RUNNER_EXIT
    local rc="$1"; shift
    local d; d="$(sandbox "$rc" "$@")"
    ( cd "$d" && TEST_SUITE_LOGDIR="$d/logs" bash runner.sh fast >"$d/out" 2>&1 )
    local e=$?
    cat "$d/logs"/*.log 2>/dev/null | sed 's/^/LOG /' >> "$d/out"
    echo "RUNNER_EXIT=$e" >> "$d/out"
    cat "$d/out"
    rm -rf "$d"
}

drive_list() {            # drive_list <row>... ; runs --list
    local d; d="$(sandbox 0 "$@")"
    ( cd "$d" && bash runner.sh --list fast >"$d/out" 2>&1 )
    echo "RUNNER_EXIT=$?" >> "$d/out"
    cat "$d/out"
    rm -rf "$d"
}

# ===========================================================================
echo "== a partial: row RUNS, and its ARGS reach the process =="
out="$(drive 0 'fast|fake_suite|60|partial: scenario_2 aborts, so only 1 and 3 run|--only=scenario_1 --only=scenario_3')"
case "$out" in
  *"[QUARANTINE"*) fail "a partial: row was quarantined -- it must RUN" "$out" ;;
  *"[PASS"*)       chk "a partial: row runs and passes" yes yes ;;
  *)               fail "a partial: row neither ran nor quarantined" "$out" ;;
esac
case "$out" in
  *"LOG ARGV=--only=scenario_1"*) chk "the first ARG reached the process" yes yes ;;
  *) fail "ARGS did not reach the binary" "$out" ;;
esac
case "$out" in
  *"LOG ARGV=--only=scenario_3"*) chk "the second ARG reached the process" yes yes ;;
  *) fail "second ARG missing" "$out" ;;
esac
# Word-splitting is a REAL failure mode, not a nicety: passed as one quoted
# string, a suite sees a single unparseable argv[1] and (correctly) exits
# non-zero on an unknown selector -- which reads as a suite failure, not a
# roster bug.
case "$out" in
  *"LOG ARGV_COUNT=2"*) chk "ARGS are split into separate argv entries, not one blob" yes yes ;;
  *) fail "ARGS were not word-split (expected ARGV_COUNT=2)" "$out" ;;
esac
case "$out" in
  *"RUNNER_EXIT=0"*) chk "a passing partial row exits 0" yes yes ;;
  *) fail "passing partial row did not exit 0" "$out" ;;
esac

echo
echo "== a partial: row is NOT excused from failing =="
# The whole risk of this feature is that `partial:` becomes a second quarantine
# keyword -- a way to keep a red suite in the roster while it reports green.
out="$(drive 3 'fast|fake_suite|60|partial: only scenario_1|--only=scenario_1')"
case "$out" in
  *"RUNNER_EXIT=0"*) fail "a FAILING partial row exited 0 -- partial is not an excuse" "$out" ;;
  *)                 chk "a failing partial row fails the run" yes yes ;;
esac
case "$out" in
  *"[FAIL"*) chk "and it is reported as a FAIL, not a quarantine" yes yes ;;
  *) fail "failing partial row not reported as FAIL" "$out" ;;
esac

echo
echo "== ROSTER ERROR: partial: with EMPTY args =="
# Excludes nothing while the reason claims it does.
out="$(drive 0 'fast|fake_suite|60|partial: only scenario_1|')"
case "$out" in
  *"RUNNER_EXIT=0"*) fail "partial: with no ARGS was accepted" "$out" ;;
  *)                 chk "partial: with empty ARGS is fatal" yes yes ;;
esac
case "$out" in
  *"ROSTER ERROR"*) chk "and it says ROSTER ERROR" yes yes ;;
  *) fail "no ROSTER ERROR diagnostic" "$out" ;;
esac
# Must name the row ON THE ERROR LINE. A bare `case "$out" in *fake_suite*)`
# passes vacuously here -- the quarantine line already prints the suite name --
# which is the kind of arm that reports green while proving nothing.
if printf '%s\n' "$out" | grep -q 'ROSTER ERROR.*fake_suite'; then
  chk "and the error line itself names the offending row" yes yes
else
  fail "the ROSTER ERROR line did not name the row" "$out"
fi

echo
echo "== ROSTER ERROR: ARGS on a LIVE (empty-reason) row =="
out="$(drive 0 'fast|fake_suite|60||--only=scenario_1')"
case "$out" in
  *"RUNNER_EXIT=0"*) fail "ARGS on a live row was accepted" "$out" ;;
  *)                 chk "ARGS on a live row is fatal" yes yes ;;
esac

echo
echo "== ROSTER ERROR: ARGS on a plain QUARANTINE row =="
# A quarantined row does not run, so args on it are silently meaningless --
# exactly the kind of thing that rots into a lie the day the quarantine lifts.
out="$(drive 0 'fast|fake_suite|60|UNTRIAGED: something broke|--only=scenario_1')"
case "$out" in
  *"RUNNER_EXIT=0"*) fail "ARGS on a quarantined row was accepted" "$out" ;;
  *)                 chk "ARGS on a quarantined row is fatal" yes yes ;;
esac

echo
echo "== ROSTER ERROR: wrong field count =="
# `read -r a b c d e` puts the remainder in the LAST variable, so a stray pipe
# inside a reason silently truncates the reason and turns its tail into ARGS.
# Nothing about that is visible in the output it produces.
out="$(drive 0 'fast|fake_suite|60|reason with a | pipe in it|--only=x')"
case "$out" in
  *"RUNNER_EXIT=0"*) fail "a 6-field row was accepted" "$out" ;;
  *)                 chk "a row with the wrong field count is fatal" yes yes ;;
esac

echo
echo "== no regression: plain quarantine and plain live rows are unchanged =="
out="$(drive 0 'fast|fake_suite|60|UNTRIAGED: broken|' 'fast|other_suite|60||')"
case "$out" in
  *"[QUARANTINE"*fake_suite*) chk "a plain quarantine row is still quarantined" yes yes ;;
  *) fail "plain quarantine row changed behaviour" "$out" ;;
esac
case "$out" in
  *"[PASS"*other_suite*) chk "a plain live row still runs" yes yes ;;
  *) fail "plain live row changed behaviour" "$out" ;;
esac
case "$out" in
  *"LOG ARGV_COUNT=0"*) chk "a live row is invoked with NO arguments" yes yes ;;
  *) fail "a live row was given arguments" "$out" ;;
esac

echo
echo "== the census counts live / partial / quarantined separately =="
out="$(drive 0 'fast|fake_suite|60|partial: only scenario_1|--only=scenario_1' 'fast|other_suite|60||')"
case "$out" in
  *"partial=1"*) chk "partial rows are counted" yes yes ;;
  *) fail "no partial= counter in the summary" "$out" ;;
esac
case "$out" in
  *"live=1"*) chk "live rows are counted separately from partial" yes yes ;;
  *) fail "no live= counter in the summary" "$out" ;;
esac
# A partial row must NOT also be counted as quarantined -- it runs.
case "$out" in
  *"quarantined=0"*) chk "a partial row is not counted as quarantined" yes yes ;;
  *) fail "partial row leaked into the quarantined count" "$out" ;;
esac

echo
echo "== --list: partial rows must still be BUILT, and errors must break it =="
out="$(drive_list 'fast|fake_suite|60|partial: only scenario_1|--only=scenario_1')"
case "$out" in
  *fake_suite*) chk "--list includes a partial row (it must be built)" yes yes ;;
  *) fail "--list dropped a partial row -- it would stop being built" "$out" ;;
esac
out="$(drive_list 'fast|fake_suite|60|partial: only scenario_1|')"
case "$out" in
  *"RUNNER_EXIT=0"*) fail "--list exited 0 on a broken roster -- the build proceeds on a lie" "$out" ;;
  *)                 chk "--list is fatal on a roster error" yes yes ;;
esac

echo
echo "== the real roster in this tree must itself be valid =="
# Every arm above runs against synthetic rows. This one runs the validator over
# the roster that actually ships.
if bash "$RUNNER" --check-roster >/dev/null 2>&1; then
  chk "the shipped roster passes its own validator" yes yes
else
  fail "the shipped roster FAILS its own validator" "$(bash "$RUNNER" --check-roster 2>&1 | tail -5)"
fi

echo
echo "   ===== run_test_suites ARGS/partial: $P passed, $F failed ====="
[ "$F" -eq 0 ]
