#!/usr/bin/env bash
# Mutation verification for the mempool shutdown lost-wakeup fix (N4).
#
# Proves the regression suite is not decorative:
#   ARM A  fixed tree            -> suite must be GREEN
#   ARM B  fix reverted (mutant) -> suite must be RED
#   ARM C  fix restored          -> suite must be GREEN again
#
# HARD RULES (a previous run in this repo silently tested a STALE binary
# because it swallowed a compile error):
#   * a build failure is FATAL and aborts the whole run
#   * the binary's mtime is printed before every run, and the run is refused
#     unless the binary is NEWER than the sources it is supposed to contain
#
# Usage:  bash scripts/mempool_shutdown_wakeup_mutation_check.sh
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1

SUITE="mempool_shutdown_wakeup_tests"
BIN="./test_dilithion"
SRC="src/node/mempool.cpp"
TESTSRC="src/test/${SUITE}.cpp"
MUTANT_BAK="$(mktemp)"
JOBS="${JOBS:-4}"

RESULT_A=""; RESULT_B=""; RESULT_C=""

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf '\nFATAL: %s\n' "$*"; restore_if_needed; exit 1; }

MUTATED=0
restore_if_needed() {
    if [ "$MUTATED" -eq 1 ]; then
        printf 'restoring %s from backup\n' "$SRC"
        cp "$MUTANT_BAK" "$SRC" && MUTATED=0
    fi
}
trap restore_if_needed EXIT

stamp() {
    if [ ! -f "$BIN" ]; then
        printf '  BINARY: %s DOES NOT EXIST\n' "$BIN"
        return 1
    fi
    printf '  BINARY: %s  mtime=%s  size=%s\n' \
        "$BIN" "$(date -r "$BIN" '+%Y-%m-%d %H:%M:%S')" "$(stat -c %s "$BIN")"
    printf '  SOURCE: %s  mtime=%s\n' "$SRC" "$(date -r "$SRC" '+%Y-%m-%d %H:%M:%S')"
    printf '  TEST  : %s  mtime=%s\n' "$TESTSRC" "$(date -r "$TESTSRC" '+%Y-%m-%d %H:%M:%S')"
    # Staleness guard: the binary MUST be newer than both sources.
    if [ "$SRC" -nt "$BIN" ]; then
        printf '  STALE: %s is newer than the binary\n' "$SRC"
        return 1
    fi
    if [ "$TESTSRC" -nt "$BIN" ]; then
        printf '  STALE: %s is newer than the binary\n' "$TESTSRC"
        return 1
    fi
    return 0
}

build() {
    log "BUILD ($1)"
    if ! make -j"$JOBS" test_dilithion; then
        fail "build failed during arm '$1' -- refusing to run a stale binary"
    fi
    stamp || fail "binary staleness check failed after arm '$1' build"
}

run_suite() {
    log "RUN ($1): $BIN --run_test=$SUITE"
    "$BIN" --run_test="$SUITE" --log_level=test_suite --report_level=short
    return $?
}

# ---------------------------------------------------------------------------
# ARM A -- fixed tree, expect GREEN
# ---------------------------------------------------------------------------
build "A: fixed"
if run_suite "A: fixed"; then
    RESULT_A="GREEN"
else
    RESULT_A="RED"
fi
printf '\nARM A (fixed tree): %s  [expected GREEN]\n' "$RESULT_A"

# ---------------------------------------------------------------------------
# ARM B -- revert the fix (mutant), expect RED
# ---------------------------------------------------------------------------
cp "$SRC" "$MUTANT_BAK" || fail "could not back up $SRC"

log "MUTATE: reverting the lock around the stop-flag store in StopExpirationThread"
python - "$SRC" <<'PY'
import sys, io
path = sys.argv[1]
s = io.open(path, encoding='utf-8', errors='surrogateescape').read()
fixed = """    {
        std::lock_guard<std::mutex> lock(expiration_mutex);
        stop_expiration_thread.store(true);
    }
    expiration_cv.notify_all();
"""
# The mutant restores the PRE-FIX shape: flag written with no lock held, and
# notify_all() likewise unlocked -- exactly the code that lost the wakeup.
mutant = """    stop_expiration_thread.store(true);       /* MUTANT: no lock held */
    expiration_cv.notify_all();              /* MUTANT: no lock held */
"""
if fixed not in s:
    sys.stderr.write("MUTATION ANCHOR NOT FOUND -- refusing to proceed\n")
    sys.exit(2)
io.open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s.replace(fixed, mutant, 1))
sys.stderr.write("mutation applied\n")
PY
[ $? -eq 0 ] || fail "mutation step failed"
MUTATED=1

build "B: mutant (fix reverted)"
if run_suite "B: mutant"; then
    RESULT_B="GREEN"
else
    RESULT_B="RED"
fi
printf '\nARM B (fix reverted): %s  [expected RED]\n' "$RESULT_B"

# ---------------------------------------------------------------------------
# ARM C -- restore, expect GREEN again
# ---------------------------------------------------------------------------
log "RESTORE"
restore_if_needed
build "C: restored"
if run_suite "C: restored"; then
    RESULT_C="GREEN"
else
    RESULT_C="RED"
fi
printf '\nARM C (fix restored): %s  [expected GREEN]\n' "$RESULT_C"

# ---------------------------------------------------------------------------
log "MUTATION VERIFICATION SUMMARY"
printf '  ARM A fixed    : %-5s (expected GREEN)\n' "$RESULT_A"
printf '  ARM B mutant   : %-5s (expected RED)\n'   "$RESULT_B"
printf '  ARM C restored : %-5s (expected GREEN)\n' "$RESULT_C"

if [ "$RESULT_A" = "GREEN" ] && [ "$RESULT_B" = "RED" ] && [ "$RESULT_C" = "GREEN" ]; then
    printf '\nVERDICT: PASS -- the regression test genuinely detects the defect.\n'
    exit 0
fi
printf '\nVERDICT: FAIL -- the test does NOT discriminate the defect.\n'
exit 1
