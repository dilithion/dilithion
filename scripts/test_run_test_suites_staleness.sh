#!/usr/bin/env bash
# Self-test for run_test_suites.sh's STALENESS GUARD.
#
# WHY THIS FILE EXISTS. On 2026-09-07 an r8 roster run reported 54 suites PASS
# against binaries built two to four days before the merge under test. Nothing
# in the output distinguished it from a genuine run -- that is the entire
# danger. `make` builds the node binaries and `make tests` builds the roster, so
# a partial build leaves yesterday's binaries beside today's source and the
# runner reads out green.
#
# THE REFERENCE IS SOURCE MTIME, NOT HEAD's COMMIT TIME. An earlier version
# compared against HEAD %ct, which is one-directional: it caught "binary older
# than the commit" but passed a binary built from a DIFFERENT tree onto an
# older-dated HEAD, and passed uncommitted edits entirely. It also inherited the
# committer clock -- a forward-skewed push marked every row STALE by 0h and no
# rebuild could clear it. A binary older than a file it is built from is stale
# whatever git thinks.
#
# Every arm below asserts on a REAL back-dated binary, not on the code.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
RUNNER="${1:-$HERE/run_test_suites.sh}"
P=0; F=0
chk(){ if [ "$2" = "$3" ]; then echo "   PASS  $1 ($2)"; P=$((P+1)); else echo "   FAIL  $1 got=$2 want=$3"; F=$((F+1)); fi; }

[ -f "$RUNNER" ] || { echo "FAIL: runner not found at $RUNNER" >&2; exit 1; }

# Build a self-contained sandbox: a fake src/ tree (so the guard has a
# reference) plus one fake suite binary whose mtime we control.
make_sandbox() {          # make_sandbox <binary-age-seconds-relative-to-source>
    local skew="$1" d now
    d="$(mktemp -d)"
    mkdir -p "$d/src"
    printf 'int main(){return 0;}\n' > "$d/src/fake.cpp"
    printf 'all:\n' > "$d/Makefile"
    now="$(date +%s)"
    touch -d "@${now}" "$d/src/fake.cpp" "$d/Makefile"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$d/fake_suite"
    chmod +x "$d/fake_suite"
    touch -d "@$(( now + skew ))" "$d/fake_suite"
    awk -v row="fast|fake_suite|60|" '
      /^ROSTER=.$/ { print; print row; skip=1; next }
      skip && /^.$/ { print; skip=0; next }
      skip { next }
      { print }
    ' "$RUNNER" > "$d/runner.sh"
    echo "$d"
}

drive() {                 # drive <skew> [env-assignments...]
    local d; d="$(make_sandbox "$1")"; shift
    ( cd "$d" && env "$@" TEST_SUITE_LOGDIR="$d/logs" bash runner.sh fast >"$d/out" 2>&1 )
    echo "RUNNER_EXIT=$?" >> "$d/out"
    grep -E '\[(STALE|PASS|FAIL) ' "$d/out" | head -1
    grep -E '^  ran=' "$d/out" | head -1
    grep -E '^RUNNER_EXIT=' "$d/out"
    grep -E 'FATAL' "$d/out" | head -1
    rm -rf "$d"
}

echo "== a binary older than the source must never be reported as a pass =="
out="$(drive -3600)"                       # built an hour before the source
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
  *)           echo "   FAIL  stale row not counted"; F=$((F+1)) ;;
esac
case "$out" in
  *"RUNNER_EXIT=0"*) echo "   FAIL  runner exited 0 with a stale binary"; F=$((F+1)) ;;
  *)                 chk "a stale binary fails the run" "yes" "yes" ;;
esac

echo
echo "== an UNCOMMITTED source edit must also make the binary stale =="
# This is the case the HEAD-%ct version could not see at all: nothing is
# committed, so a commit-time reference is unchanged and the binary looks fine.
out="$(drive -60)"                         # source touched a minute after the binary
case "$out" in
  *"[STALE"*) chk "a binary older than an edited source is [STALE]" "yes" "yes" ;;
  *)          echo "   FAIL  edited source did not invalidate the binary. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
esac

echo
echo "== the guard must NOT fire on a current binary (or it is just noise) =="
out="$(drive 60)"                          # built a minute after the source
case "$out" in
  *"[STALE"*) echo "   FAIL  a CURRENT binary was flagged stale. Got:"; echo "$out" | sed 's/^/     | /'; F=$((F+1)) ;;
  *)          chk "a current binary is not flagged stale" "yes" "yes" ;;
esac
case "$out" in
  *"RUNNER_EXIT=0"*) chk "a current, passing binary still exits 0" "yes" "yes" ;;
  *)                 echo "   FAIL  current binary did not pass"; F=$((F+1)) ;;
esac

echo
echo "== no reference => FATAL, in CI and wherever a source tree exists =="
# A guard with no reference is a guard that is off. Both trigger arms are
# pinned: CI, and the presence of a source tree. The second was unpinned in the
# first version and passed 8/0 with it deleted.
nosrc="$(mktemp -d)"
printf '#!/usr/bin/env bash\nexit 0\n' > "$nosrc/fake_suite"; chmod +x "$nosrc/fake_suite"
awk -v row="fast|fake_suite|60|" '
  /^ROSTER=.$/ { print; print row; skip=1; next }
  skip && /^.$/ { print; skip=0; next }
  skip { next }
  { print }
' "$RUNNER" > "$nosrc/runner.sh"
( cd "$nosrc" && GITHUB_ACTIONS=1 TEST_SUITE_LOGDIR="$nosrc/logs" bash runner.sh fast >"$nosrc/out" 2>&1 )
rc_ci=$?
[ "$rc_ci" -ne 0 ] && chk "CI with no reference fails the run" "yes" "yes" \
  || { echo "   FAIL  CI run exited 0 with no reference"; F=$((F+1)); }
grep -q 'could not determine a source reference' "$nosrc/out" 2>/dev/null \
  && chk "and it says why, rather than failing opaquely" "yes" "yes" \
  || { echo "   FAIL  fatal exit carried no explanation"; F=$((F+1)); }
rm -rf "$nosrc"

# M2: the src-tree arm, WITHOUT any CI variable set. Unpinned before.
srcnoref="$(mktemp -d)"
mkdir -p "$srcnoref/src"                   # a src/ dir with no matching sources
printf '#!/usr/bin/env bash\nexit 0\n' > "$srcnoref/fake_suite"; chmod +x "$srcnoref/fake_suite"
awk -v row="fast|fake_suite|60|" '
  /^ROSTER=.$/ { print; print row; skip=1; next }
  skip && /^.$/ { print; skip=0; next }
  skip { next }
  { print }
' "$RUNNER" > "$srcnoref/runner.sh"
( cd "$srcnoref" && env -u GITHUB_ACTIONS -u CI TEST_SUITE_LOGDIR="$srcnoref/logs" bash runner.sh fast >"$srcnoref/out" 2>&1 )
rc_src=$?
[ "$rc_src" -ne 0 ] && chk "a source tree with no readable reference fails, even outside CI" "yes" "yes" \
  || { echo "   FAIL  exited 0 with a src/ tree and no reference -- guard silently off"; F=$((F+1)); }
rm -rf "$srcnoref"

echo
echo "   ===== run_test_suites staleness guard: $P passed, $F failed ====="
[ "$F" -eq 0 ]
