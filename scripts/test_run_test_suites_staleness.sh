#!/usr/bin/env bash
# Self-test for run_test_suites.sh's STALENESS GUARD.
#
# WHY THIS FILE EXISTS. On 2026-09-07 an r8 roster run reported 54 suites PASS
# against binaries built two to four days before the merge under test. Nothing
# in the output distinguished it from a genuine run -- that is the entire
# danger. `make` builds the node binaries and `make tests` builds the roster,
# so a partial build leaves yesterday's binaries next to today's source and the
# runner reads out green.
#
# The guard refuses to call a stale binary a PASS. This asserts that, by
# building a fake suite and back-dating it -- not by reading the code.
#
# BOTH ARMS, because a guard that never fires and a guard that always fires are
# equally useless:
#   stale binary -> [STALE], counted, run FAILS
#   fresh binary -> PASS, run succeeds
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
RUNNER="${1:-$HERE/run_test_suites.sh}"
P=0; F=0
chk(){ if [ "$2" = "$3" ]; then echo "   PASS  $1 ($2)"; P=$((P+1)); else echo "   FAIL  $1 got=$2 want=$3"; F=$((F+1)); fi; }

[ -f "$RUNNER" ] || { echo "FAIL: runner not found at $RUNNER" >&2; exit 1; }

REPO="$(cd "$HERE/.." && pwd)"
HEAD_EPOCH="$(cd "$REPO" && git log -1 --format=%ct 2>/dev/null || echo 0)"
if [ "${HEAD_EPOCH:-0}" -le 0 ]; then
  echo "   SKIP  not a git checkout -- the guard has no reference time here"
  exit 0
fi

# Copy the real runner, swap ONLY its ROSTER for one fake row, and run it.
# Everything under test is the real code.
drive() {          # drive <binary-mtime-epoch> ; echoes the row + counts + exit
  local mtime="$1" d
  d="$(mktemp -d)"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$d/fake_suite"
  chmod +x "$d/fake_suite"
  touch -d "@${mtime}" "$d/fake_suite"
  awk -v row="fast|fake_suite|60|" '
    /^ROSTER=.$/ { print; print row; skip=1; next }
    skip && /^.$/ { print; skip=0; next }
    skip { next }
    { print }
  ' "$RUNNER" > "$d/runner.sh"
  # Run from a directory inside the repo so `git log -1` still resolves HEAD.
  local work="$REPO/.staleness-selftest.$$"
  mkdir -p "$work"
  cp "$d/fake_suite" "$work/fake_suite"
  touch -d "@${mtime}" "$work/fake_suite"
  cp "$d/runner.sh" "$work/runner.sh"
  ( cd "$work" && TEST_SUITE_LOGDIR="$work/logs" bash runner.sh fast >"$work/out" 2>&1 )
  echo "RUNNER_EXIT=$?" >> "$work/out"
  grep -E '\[(STALE|PASS|FAIL) ' "$work/out" | head -1
  grep -E '^  ran=' "$work/out" | head -1
  grep -E '^RUNNER_EXIT=' "$work/out"
  rm -rf "$d" "$work"
}

echo "== a binary OLDER than HEAD must never be reported as a pass =="
out="$(drive $(( HEAD_EPOCH - 86400 )))"     # one day older than the commit
case "$out" in
  *"[STALE"*) chk "an out-of-date binary is reported [STALE]" "yes" "yes" ;;
  *)          echo "   FAIL  stale binary not flagged. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac
case "$out" in
  *"[PASS"*) echo "   FAIL  a stale binary was reported as a PASS -- this is the r8 defect"; F=$((F+1)) ;;
  *)         chk "a stale binary is NOT counted as a pass" "yes" "yes" ;;
esac
case "$out" in
  *"stale=1"*) chk "the stale row is counted (stale=1)" "yes" "yes" ;;
  *)           echo "   FAIL  stale row not counted. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac
case "$out" in
  *"RUNNER_EXIT=0"*) echo "   FAIL  runner exited 0 with a stale binary"; F=$((F+1)) ;;
  *)                 chk "a stale binary fails the run" "yes" "yes" ;;
esac

echo
echo "== the guard must NOT fire on a current binary (or it is just noise) =="
out="$(drive $(( HEAD_EPOCH + 60 )))"        # built just after the commit
case "$out" in
  *"[STALE"*) echo "   FAIL  a CURRENT binary was flagged stale. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
  *)          chk "a current binary is not flagged stale" "yes" "yes" ;;
esac
case "$out" in
  *"RUNNER_EXIT=0"*) chk "a current, passing binary still exits 0" "yes" "yes" ;;
  *)                 echo "   FAIL  current binary did not pass. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac

echo
echo "   ===== run_test_suites staleness guard: $P passed, $F failed ====="
[ "$F" -eq 0 ]
