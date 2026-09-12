#!/usr/bin/env bash
# ============================================================================
# graveyard_occupancy_sweep.sh — every occupancy configuration, one table.
#
# The design note quotes five numbers that came from five separate invocations
# typed by hand, which is how a table drifts from the code it describes: one
# configuration gets re-measured after a change and the other four keep their old
# values, and nothing says which is which. This runs all of them and prints one
# table, so the note can be regenerated instead of edited.
#
# THE CONFIGURATIONS, and why each is in the table:
#   A  wired shape        1 Hz drain, 1 Hz slowest checkpoint — what production does
#   B  slow everything    10 s drain, 10 s slowest checkpoint — the old "10 s grace"
#   C  slow participant   1 Hz drain, 10 s slowest checkpoint — proves the SLOWEST
#                         CHECKPOINT dominates, not the drain cadence
#   D  parked, online     a participant checkpoints then parks — THE DEFECT the
#                         round-1 panel found; unbounded growth
#   E  parked, offline    the same thread parks inside EpochOfflineScope — THE FIX
#   F  partial reclaim    a large survivor set with a small freed prefix, which is
#                         the regime the container choice was measured in
#
# ⚠️ D AND E ARE A PAIR AND MUST BE READ TOGETHER. E alone says "6 MB, fine"; the
# pair says "unbounded became bounded", which is the actual claim.
#
# Fails closed: a missing binary, a stale binary, or a run that produces no
# MEASURED block is an error, not a blank row.
# ============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." || exit 9

BIN=./graveyard_occupancy_bench
[ -x "$BIN" ] || BIN=./graveyard_occupancy_bench.exe
[ -x "$BIN" ] || { echo "FATAL: graveyard_occupancy_bench not built"; exit 2; }

# STALE-BINARY GUARD. A bench older than the code it measures reports the previous
# design's numbers, identically formatted and completely wrong.
newest_src=$(ls -t src/consensus/chain.cpp src/consensus/chain.h \
                    src/tools/graveyard_occupancy_bench.cpp 2>/dev/null | head -1)
if [ -n "$newest_src" ] && [ "$newest_src" -nt "$BIN" ]; then
    echo "FATAL: $BIN is older than $newest_src — rebuild before measuring."
    exit 3
fi

# entries pinned% drain_ms ckpt_ms run_ms rate parked
CONFIGS=(
  "A|wired (1 Hz drain, 1 Hz checkpoint) [run 1 of 3]|500000 50 1000 1000 15000 10400 0"
  "A2|wired [run 2 of 3] — peak is a SAMPLE, not a constant|500000 50 1000 1000 15000 10400 0"
  "A3|wired [run 3 of 3] — quote the range, defend the upper end|500000 50 1000 1000 15000 10400 0"
  "B|slow both (10 s / 10 s)|500000 25 10000 10000 30000 10400 0"
  "C|slow participant only (1 Hz drain, 10 s checkpoint)|500000 25 1000 10000 30000 10400 0"
  "D|parked participant ONLINE — the defect|500000 25 1000 1000 15000 10400 1"
  "E|parked participant OFFLINE — the fix|500000 25 1000 1000 15000 10400 2"
  "F|partial reclamation, large survivor set|500000 25 1000 10000 20000 10400 0"
)

field() { echo "$1" | grep -m1 "$2" | sed 's/.*: *//' | sed 's/  *$//'; }

printf '\n%-3s %-46s %14s %10s %16s %8s\n' \
       "cfg" "configuration" "PEAK graveyard" "freed" "drain ms max/mean" "offline"
printf '%s\n' "--------------------------------------------------------------------------------------------------------"

rc=0
for row in "${CONFIGS[@]}"; do
    IFS='|' read -r tag label args <<< "$row"
    out=$($BIN $args 2>&1); bench_rc=$?
    # ⚠️ THE BENCH'S EXIT STATUS WAS IGNORED. A run that printed a MEASURED block and
    # then failed (a fixture refusal, an abort after the table) was scored as a good
    # row. Status first, marker second.
    if [ $bench_rc -ne 0 ]; then
        printf '%-3s %-46s %s\n' "$tag" "$label" "BENCH EXITED $bench_rc — row rejected"
        echo "$out" | tail -4 | sed 's/^/      /'
        rc=$((rc+1)); continue
    fi
    if ! echo "$out" | grep -q -- "--- MEASURED ---"; then
        printf '%-3s %-46s %s\n' "$tag" "$label" "RUN PRODUCED NO MEASUREMENT — see below"
        echo "$out" | tail -5 | sed 's/^/      /'
        rc=$((rc+1)); continue
    fi
    peak=$(field "$out" "PEAK graveyard")
    freed=$(field "$out" "freed during the run")
    cost=$(field "$out" "drain cost")
    offl=$(field "$out" "resolves while OFFLINE")
    peak_mb=$(echo "$peak"  | sed 's/.*= *//')
    freed_n=$(echo "$freed" | sed 's/ over.*//')
    cost_s=$(echo "$cost"   | sed 's/max //; s/, mean /\//; s/ ms.*/ ms/; s/ ⚠️.*//')
    offl_n=$(echo "$offl"   | sed 's/ .*//')
    printf '%-3s %-46s %14s %10s %16s %8s\n' \
           "$tag" "$label" "$peak_mb" "$freed_n" "$cost_s" "$offl_n"

    # ⚠️ A NON-ZERO OFFLINE-RESOLVE COUNT IS A FAILURE, NOT A COLUMN. It means some
    # thread resolved a CBlockIndex* after publishing that it holds nothing — safe at
    # the resolve and still a defect. Printing it in a table nobody's exit code reads
    # is how it would be ignored.
    # ⚠️ A MISSING FIELD IS NOT A ZERO. This read `${offl_n:-0}`, so a bench that
    # stopped printing the offline-resolve line -- a rename, a reordered report, an
    # older binary -- would have been scored as "0 offline resolves" forever. The
    # field must be PRESENT and an integer; absence is a failure of the measurement,
    # not a passing measurement.
    if ! echo "$offl_n" | grep -qE '^[0-9]+$'; then
        echo "      ^^ FAIL: configuration $tag reported no parsable offline-resolve"
        echo "         count (got '$offl_n') — the measurement is incomplete, not clean"
        rc=$((rc+1))
    elif [ "$offl_n" != "0" ]; then
        echo "      ^^ FAIL: $offl_n resolve(s) while OFFLINE in configuration $tag"
        rc=$((rc+1))
    fi
done

echo
echo "EVERY PEAK HERE IS A SAMPLE, AND THE LONGER THE DRAIN PERIOD THE WIDER THE"
echo "SPREAD. The peak is read after each eviction, so it depends where the run stops"
echo "in the drain cycle, and the swing is about ONE CYCLE OF ACCUMULATION:"
echo "  A (1 s cycle) : ~1 s x 10,400/s x 305 B  ~=  3 MB of swing  (3.5-6.4 observed)"
echo "  B (10 s cycle): ~10 s x 10,400/s x 305 B ~= 32 MB of swing  (34.8-63.5 observed)"
echo "B and C are single runs and inherit that spread -- do not quote either as a point"
echo "value. A is repeated below because it is the WIRED setting and the one the design"
echo "note cites."
echo
echo "CONFIG A IS RUN THREE TIMES ON PURPOSE. Its peak is sampled after each"
echo "eviction, so it depends where the run stops relative to the drain cycle: three"
echo "runs of the identical command have measured 6.42, 6.39 and 3.53 MB. Quote the"
echo "RANGE and defend the upper end. A single run of A is a sample that a document"
echo "will then treat as a constant -- which is what happened for three review rounds."
echo
echo "READ D AND E AS A PAIR: D is a participant that checkpoints and then parks —"
echo "the graveyard grows at the ingress rate and NOTHING is freed for the whole run."
echo "E is the same thread inside an EpochOfflineScope. The claim is the difference,"
echo "not either number on its own."
echo
echo "'offline' is CChainState::OfflineResolveCount(): resolves that happened while a"
echo "thread had published that it holds nothing. Non-zero means a quiesce/checkpoint"
echo "pairing is wrong somewhere — it is safe at the resolve and still a defect."
[ $rc -eq 0 ] || echo
[ $rc -eq 0 ] || echo "===== SWEEP INCOMPLETE: $rc configuration(s) produced no measurement ====="
exit $rc
