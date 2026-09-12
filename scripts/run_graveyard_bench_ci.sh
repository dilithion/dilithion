#!/usr/bin/env bash
# ==============================================================================
# run_graveyard_bench_ci.sh — the drain-cost observation that F59's decision rests on.
# ==============================================================================
#
# ⚠️ WHY THIS IS A CI LEG AND NOT A NOTE. `MyEpochSlot` retains one slot per thread
# that EVER participated — the exit hook retires, never reclaims, deliberately,
# because a drain on another thread may read a slot after its owner is gone.
# `DrainGraveyard` is O(slots), so the cost that grows is DRAIN LATENCY.
#
# The accepted operating limit (round-9 F59) is explicitly NOT "we will remember to
# look": at ~5,760 slots/day the 50 ms redesign threshold arrives in roughly SIX TO
# EIGHT WEEKS of continuous mining. A margin stated once in a comment decays exactly
# as fast as the thing it describes. So the bench runs, and the number is recorded
# where a human sees it.
#
# ⚠️ THIS LEG REPORTS, IT DOES NOT GATE — YET, AND THAT IS DELIBERATE.
#   * Gating on an absolute millisecond figure measured on a GitHub runner would be
#     gating on runner noise: shared CPU, unknown neighbours, 2-5x variance between
#     identical runs. A threshold that red-lines at random teaches everyone to
#     re-run, which is how a gate becomes decoration — this branch has already
#     written that lesson once.
#   * So it PRINTS the number with the threshold beside it, every run. When enough
#     runs exist to know the runner's spread, the gate gets a number derived from
#     that spread rather than from a laptop.
#   * ⚠️ MEASURED, NOT ASSUMED: three consecutive runs on ONE developer machine,
#     same binary, same arguments, gave 3.4 / 10.7 / 3.6 ms — a 3.1x spread with no
#     variable changed. A gate at any fixed millisecond value would have fired on
#     the middle run and passed the other two. That is the evidence for report-only,
#     and it took three runs to have it rather than one.
# Stated here rather than left as an omission, because "the bench runs in CI" would
# otherwise imply a protection that does not exist.

set -u

THRESHOLD_MS=50          # F59's redesign trigger; see MyEpochSlot in chain.cpp

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2

if [ ! -x ./graveyard_occupancy_bench ] && [ ! -x ./graveyard_occupancy_bench.exe ]; then
    echo "===== graveyard bench: FAIL (binary not built — run 'make graveyard_occupancy_bench') ====="
    exit 2
fi
BIN=./graveyard_occupancy_bench
[ -x ./graveyard_occupancy_bench.exe ] && BIN=./graveyard_occupancy_bench.exe

echo "graveyard occupancy + drain cost (F59 operating limit: redesign at ${THRESHOLD_MS} ms)"
out="$("$BIN" 2>&1)" || {
    echo "$out"
    echo "===== graveyard bench: FAIL (the bench itself exited non-zero) ====="
    exit 1
}
printf '%s\n' "$out"

# ⚠️ A MISSING FIELD MUST NOT READ AS ZERO. If the bench stops printing its drain
# line, an unparsed value would silently become "0 ms", i.e. infinitely below the
# threshold — the same failure the occupancy sweep already had and fixed.
line="$(printf '%s\n' "$out" | grep 'drain cost' || true)"
if [ -z "$line" ]; then
    echo "===== graveyard bench: FAIL (no 'drain cost' line — the bench's output"
    echo "      changed and this check can no longer read it; that is a broken"
    echo "      instrument, not a passing run) ====="
    exit 2
fi

max="$(printf '%s\n' "$line" | sed -n 's/.*max \([0-9.][0-9.]*\) ms.*/\1/p')"
if [ -z "$max" ]; then
    echo "===== graveyard bench: FAIL (could not parse a drain max from: $line) ====="
    exit 2
fi

echo
echo "  drain max this run : ${max} ms"
echo "  redesign threshold : ${THRESHOLD_MS} ms  (generation-stamped free list)"
awk -v m="$max" -v t="$THRESHOLD_MS" 'BEGIN {
    if (m + 0 > t + 0) {
        print "  ⚠️ ABOVE THRESHOLD on this runner. Runner noise is 2-5x, so ONE";
        print "     reading is not the decision -- but it is the signal to measure";
        print "     on real hardware and take F59'"'"'s decision.";
    } else {
        printf "  below threshold (%.1f%% of it)\n", (m + 0) * 100.0 / (t + 0);
    }
}'

echo "===== graveyard bench: RECORDED (report-only; see the header for why) ====="
exit 0
