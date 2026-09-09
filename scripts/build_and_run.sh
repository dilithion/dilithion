#!/usr/bin/env bash
# ============================================================================
# build_and_run.sh — build targets, then run them ONLY if the build succeeded.
#
# WHY THIS EXISTS, and it is not a hypothetical. Three times in PR #129 a "green"
# reading came from binaries that had not been rebuilt, and the third time was
# mine and looked like this:
#
#     make -j8 <targets> > /tmp/log 2>&1
#     echo "BUILD_RC=$?"                  # printed 2, and scrolled past
#     for t in ...; do ./$t; echo "RC=$?"; done   # ran the OLD binaries
#
# Five suites reported RC=0. The build had failed. The RC=0 lines were true
# statements about stale executables and false statements about the code.
#
# scripts/run_test_suites.sh already guards this properly (#185's staleness
# check: a binary older than its sources is [STALE] and counted INCOMPLETE, never
# a PASS). That guard was never the problem — the problem is ad-hoc verification
# loops typed at a prompt, which bypass the roster entirely. This script is the
# safe shape for those.
#
# WHAT IT GUARANTEES
#   1. A non-zero build exit ABORTS. Nothing is run, so nothing can report green.
#   2. Every named binary is DELETED before the build, so a target that silently
#      fails to relink cannot be executed from a previous run.
#   3. Each binary must exist after the build, or it is a hard error.
#   4. The first failing suite sets the exit status; every suite still runs, so
#      one failure does not hide the others.
#
# USAGE
#   scripts/build_and_run.sh <target> [<target> ...]
#   scripts/build_and_run.sh --build-only <target> ...
# ============================================================================
set -uo pipefail

BUILD_ONLY=0
if [ "${1:-}" = "--build-only" ]; then BUILD_ONLY=1; shift; fi

if [ $# -eq 0 ]; then
    echo "usage: $0 [--build-only] <target> [<target> ...]" >&2
    exit 2
fi

TARGETS=("$@")
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
LOG="${LOG:-/tmp/build_and_run.log}"

# (2) Remove the binaries FIRST. If the build does not recreate one, we find out
# by its absence rather than by running last week's copy.
for t in "${TARGETS[@]}"; do rm -f "./$t"; done

echo "== building ${#TARGETS[@]} target(s), -j$JOBS =="
if ! make -j"$JOBS" "${TARGETS[@]}" > "$LOG" 2>&1; then
    echo "BUILD FAILED — NOTHING WILL BE RUN. First errors:" >&2
    grep -E 'error:|Error [0-9]+' "$LOG" | head -12 >&2
    echo "(full log: $LOG)" >&2
    exit 1
fi
echo "   build OK"

# (3) Presence check. `make` can exit 0 having skipped a target that was never
# a real rule; an absent binary must not be silently treated as "nothing to run".
missing=0
for t in "${TARGETS[@]}"; do
    if [ ! -x "./$t" ]; then
        echo "   MISSING after a successful build: $t" >&2
        missing=$((missing + 1))
    fi
done
if [ "$missing" -gt 0 ]; then
    echo "BUILD reported success but $missing binary(ies) do not exist." >&2
    exit 1
fi

[ "$BUILD_ONLY" -eq 1 ] && { echo "   (--build-only: not running)"; exit 0; }

echo
echo "== running =="
fail=0
for t in "${TARGETS[@]}"; do
    # PER-SUITE TIMEOUT (round-5 reader, LOW). Without one, a suite that hangs
    # hangs this script forever — the reader's arm 2 did exactly that. The roster
    # runner has had a per-suite timeout since #180; this convenience wrapper did
    # not, which is the same "the guard exists on the sanctioned path only" shape
    # that put this script here in the first place.
    #
    # --preserve-status is deliberate: without it `timeout` reports 124 and a hang
    # is indistinguishable from a failure. See lesson_timeout_exit_codes_143.
    # -k IS LOAD-BEARING (round-5 seats, LOW). Without --kill-after, `timeout`
    # sends SIGTERM and then WAITS FOREVER for a process that ignores it — so the
    # timeout that exists to stop a hang can itself hang. -k follows with SIGKILL,
    # which cannot be ignored. The grace is 30s: long enough for a suite that is
    # merely slow to flush and exit cleanly, short enough that a wedged one does not
    # hold the run. (Measured with a 3s grace during development; the shipped value
    # is 30 -- stating both so the number in the comment matches the code.)
    #
    # And a suite that CATCHES SIGTERM and exits 0 would be reported PASS by a
    # plain exit-code check: the deadline expiring is a FAILURE regardless of what
    # the process chose to return. --preserve-status gives us the signal-derived
    # status (143 = SIGTERM, 137 = SIGKILL; NOT 124 — see
    # lesson_timeout_exit_codes_143), so those are treated as failures explicitly
    # rather than trusted to be non-zero.
    # ELAPSED TIME, NOT JUST THE EXIT CODE (round-6 confirming reader, measured).
    # A suite that CATCHES SIGTERM and exits 0 promptly is reported PASS by any
    # rc-only check — the deadline fired, the run did not complete on its own
    # terms, and the exit code says success. So the wall clock is the authority:
    # if it took at least the deadline, it FAILED, whatever it returned.
    __t0=$(date +%s)
    timeout -k 30 --preserve-status "${SUITE_TIMEOUT:-600}" ./"$t" > "/tmp/${t}.out" 2>&1
    rc=$?
    __elapsed=$(( $(date +%s) - __t0 ))
    if [ "$__elapsed" -ge "${SUITE_TIMEOUT:-600}" ]; then
        printf '   FAIL  %-52s DEADLINE: ran %ss >= %ss limit (rc=%s)
'                "$t" "$__elapsed" "${SUITE_TIMEOUT:-600}" "$rc"
        echo "         rc=0 here would mean the suite CAUGHT the kill signal and"
        echo "         exited cleanly — that is still a deadline failure."
        fail=$((fail + 1))
        continue
    fi
    if [ "$rc" -eq 143 ] || [ "$rc" -eq 137 ] || [ "$rc" -eq 124 ]; then
        printf '   FAIL  %-52s DEADLINE EXPIRED after %ss (rc=%s)
'                "$t" "${SUITE_TIMEOUT:-600}" "$rc"
        echo "         a suite that exceeds its deadline is a FAILURE even if it"
        echo "         then exits 0 — the run did not complete on its own terms."
        fail=$((fail + 1))
        continue
    fi
    if [ "$rc" -eq 0 ]; then
        printf '   PASS  %-52s\n' "$t"
    else
        printf '   FAIL  %-52s rc=%s   (see /tmp/%s.out)\n' "$t" "$rc" "$t"
        tail -5 "/tmp/${t}.out" | sed 's/^/         /'
        fail=$((fail + 1))
    fi
done

echo
if [ "$fail" -eq 0 ]; then
    echo "   ===== ${#TARGETS[@]} target(s), all PASS ====="
else
    echo "   ===== $fail of ${#TARGETS[@]} FAILED ====="
fi
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
