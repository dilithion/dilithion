#!/usr/bin/env bash
# ============================================================================
# asan_uaf_arms.sh — the memory-safety verdict for deferred reclamation.
#
# ⚠️ TWO OF THE THREE ARMS MUST CRASH. That is the point, and it is why this
# cannot be a normal test target: a suite that is green when nothing crashes
# cannot tell "the fix works" apart from "the fixture never reached the free".
#
#   deferred   MUST EXIT 0    — a pointer resolved before an eviction on another
#                               thread is still readable. The fix, working.
#   immediate  MUST TRAP      — same fixture, deferral off (the evictor frees in
#                               place, as it did before this branch). The defect.
#   drained    MUST TRAP      — deferral on, but the holder checkpoints while
#                               still holding, so the drain frees under it. The
#                               INVERSE CONTROL: it proves the fixture reaches
#                               the free, so the clean arm is clean because of
#                               the deferral rather than because nothing was
#                               freed.
#
# A run where `deferred` is clean and a trap arm is ALSO clean is a FAILURE, not
# a partial pass — that is the vacuous-green shape this script exists to refuse.
#
# The binary must be built with -fsanitize=address. Without it, the two trap arms
# are undefined behaviour that usually reads stale bytes and exits 0, so this
# script reports NO VERDICT rather than a pass. Build:
#
#   make clean
#   CXX=clang++ CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -std=c++17" \
#     LDFLAGS="-fsanitize=address" make blockindex_uaf_asan_arm -j$(nproc)
# ============================================================================
set -uo pipefail

BIN=${BIN:-./blockindex_uaf_asan_arm}
[ -x "$BIN" ] || { echo "FATAL: $BIN not built"; exit 2; }

# Leak detection off: the epoch slots are deliberately leaked (they must outlive
# their threads — see the comment on MyEpochSlot), and a leak report is not the
# question this script asks. use-after-free detection is unaffected.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=0}"

# Does this binary actually carry the sanitizer? The arm prints it, and the arms
# that must trap cannot be judged without it.
# ⚠️ GREP THE AFFIRMATIVE. This first asked whether the binary printed "built
# WITHOUT AddressSanitizer" and treated its ABSENCE as presence -- and on GCC the
# arm printed neither line, so a non-sanitized build was certified as sanitized and
# both trap arms were reported as real FAILURES of the fix rather than as an
# unusable build. Absence of the negative is not evidence of the positive.
probe=$("$BIN" --arm=deferred 2>&1)
if echo "$probe" | grep -q "sanitizer: PRESENT"; then
    HAVE_ASAN=1
elif echo "$probe" | grep -q "sanitizer: ABSENT"; then
    HAVE_ASAN=0
else
    echo "FATAL: the arm printed no sanitizer line at all. This driver cannot"
    echo "       judge a binary whose sanitizer state is unknown."
    exit 2
fi

rc=0
run_arm() {   # $1 = arm, $2 = expect ("clean" | "trap")
    local arm=$1 expect=$2 out ec
    out=$("$BIN" --arm="$arm" 2>&1); ec=$?
    echo "--- arm=$arm (exit $ec) ---"
    echo "$out" | sed 's/^/    /'

    # Exit 3 is the fixture's own refusal: nothing evicted, or the drain freed
    # nothing. It is never a pass in either direction — a broken fixture cannot
    # certify anything.
    if [ $ec -eq 3 ]; then
        echo "  FAIL  $arm: THE FIXTURE REFUSED TO REPORT — see above"; rc=$((rc+1)); return
    fi

    if [ "$expect" = "clean" ]; then
        if [ $ec -eq 0 ]; then echo "  PASS  $arm: clean, as required"
        else echo "  FAIL  $arm: expected a clean run, got exit $ec"; rc=$((rc+1)); fi
        return
    fi

    # expect == trap
    if [ $HAVE_ASAN -eq 0 ]; then
        echo "  SKIP  $arm: no sanitizer in this binary — NO VERDICT (not a pass)"
        return
    fi
    if echo "$out" | grep -q "heap-use-after-free"; then
        echo "  PASS  $arm: AddressSanitizer reported heap-use-after-free"
    elif [ $ec -ne 0 ]; then
        echo "  FAIL  $arm: crashed (exit $ec) but NOT with heap-use-after-free"; rc=$((rc+1))
    else
        echo "  FAIL  $arm: NO TRAP. Either the free is not being reached, or the"
        echo "        sanitizer is not watching this allocation. Every clean arm in"
        echo "        this suite is vacuous until this one traps."
        rc=$((rc+1))
    fi
}

echo "=== deferred reclamation: the ASan verdict ==="
[ $HAVE_ASAN -eq 1 ] && echo "sanitizer: PRESENT" || echo "sanitizer: ABSENT — trap arms will be SKIPPED, not passed"
echo

run_arm deferred  clean
run_arm immediate trap
run_arm drained   trap

echo
if [ $HAVE_ASAN -eq 0 ]; then
    echo "===== NO VERDICT: built without -fsanitize=address ====="
    echo "The clean arm passing here says the fixture runs, nothing more."
    [ $rc -eq 0 ] && exit 0 || exit 1
fi
echo "===== ASan arms: $([ $rc -eq 0 ] && echo PASS || echo FAIL) ($rc failed) ====="
exit $rc
