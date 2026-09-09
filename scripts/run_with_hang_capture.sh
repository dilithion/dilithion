#!/usr/bin/env bash
# ============================================================================
# run_with_hang_capture.sh — run a command under a watchdog that captures a
# stack before the runner kills it.
#
# WHY THIS IS A SCRIPT AND NOT INLINE YAML.
#
# It used to live inside a `run: |` block in ci.yml, which meant NOTHING COULD
# TEST IT. The budget arithmetic, the PID-reuse guard, the kill/wait/status
# propagation and the "a hang must FAIL the step" property were all unexercised
# except in CI, on a hang that fires about 8% of the time. An instrument that
# only runs during the incident it exists to record is one you find out about
# during the incident: if it is broken you learn nothing AND you do not learn
# that you learned nothing.
#
# Extracted so scripts/test_run_with_hang_capture.sh can drive it against a
# binary that really hangs. Same reasoning as the #127/#125 folds -- a test that
# re-implements the logic agrees with its own copy, so the logic has to move to
# where a test can reach it.
#
# CONTRACT
#   run_with_hang_capture.sh <budget_seconds> <artifact_dir> <command> [args...]
#
#   exit 0     the command exited 0
#   exit N     the command exited N (propagated verbatim)
#   exit 137   the command hung and the watchdog killed it (128+9)
#
# A HANG MUST NEVER BE GREEN. That is the whole point: an instrument that
# records a hang and lets the job pass would leave the hang merging, and the
# artifact would be read by nobody. The self-test pins it directly.
# ============================================================================
set -uo pipefail

BUDGET="${1:?budget seconds required}"
ARTIFACT_DIR="${2:?artifact dir required}"
shift 2
[ "$#" -gt 0 ] || { echo "run_with_hang_capture.sh: no command given" >&2; exit 2; }

mkdir -p "$ARTIFACT_DIR"

"$@" &
CMD_PID=$!
CMD_NAME="$(basename "$1")"

# CAPTURE THE EXPECTED comm NOW, while we still know this PID is ours, rather
# than comparing later against basename "$1". Found by this script's own
# self-test, which reported a hang as GREEN:
#
#   * /proc/<pid>/comm is the EXECUTABLE's name, not argv[0]. For anything run
#     through a shebang it is "bash", so a basename comparison never matches,
#     the watchdog silently never fires, and its silence reads as "no hang
#     happened" -- an inert instrument that looks healthy.
#   * comm is also truncated to 15 characters. "test_dilithion" is 14, so it
#     fits TODAY BY ONE CHARACTER. Renaming the binary to anything longer would
#     disable the watchdog with no other symptom.
#
# Snapshotting removes both failure modes and still detects PID reuse: a
# recycled PID running something else will not match the comm we recorded.
# NO /proc, NO WATCHDOG -- and it must SAY SO rather than run inert.
# MSYS2/Git Bash has no /proc/<pid>/comm, so EXPECT_COMM comes back empty, the
# guard can never match, and the watchdog silently never fires: measured on
# Windows as an 8s hang against a 2s budget returning rc=0 with no artifact.
# An instrument that quietly does nothing on a whole platform is worse than one
# that is absent, because its silence is read as "no hang happened".
if [ ! -r "/proc/$CMD_PID/comm" ]; then
    echo "run_with_hang_capture: no /proc/<pid>/comm on this platform (MSYS2/Git Bash?)." >&2
    echo "run_with_hang_capture: the hang watchdog CANNOT ARM here; running the command unwatched." >&2
    echo "run_with_hang_capture: a missing hang artifact from this run means nothing." >&2
    wait "$CMD_PID"
    exit $?
fi
EXPECT_COMM="$(cat /proc/$CMD_PID/comm 2>/dev/null || true)"

(
    sleep "$BUDGET"
    # PID-REUSE GUARD. `kill -0` alone happily matches a recycled PID on a busy
    # runner, and we would capture some unrelated process's stack under an
    # ::error:: claiming our command hung. One comm check removes the ambiguity.
    if kill -0 "$CMD_PID" 2>/dev/null \
       && [ -n "$EXPECT_COMM" ] \
       && [ "$(cat /proc/$CMD_PID/comm 2>/dev/null)" = "$EXPECT_COMM" ]; then
        echo "::error::$CMD_NAME still alive after ${BUDGET}s - capturing stack before kill (intermittent hang)"
        {
            echo "=== $CMD_NAME hang, captured $(date -u +%FT%TZ) ==="
            echo "=== /proc/$CMD_PID/status ==="; cat "/proc/$CMD_PID/status" 2>&1
            echo "=== per-thread wchan (kernel wait channel) ==="
            for t in /proc/"$CMD_PID"/task/*; do
                echo "--- tid ${t##*/} comm=$(cat "$t/comm" 2>/dev/null) wchan=$(cat "$t/wchan" 2>/dev/null)"
            done
            # gdb gets its OWN timeout: if it stalls on attach we ride to the job
            # ceiling and learn nothing, which is the failure this exists to end.
            #
            # ATTACH IS FROM A SIBLING SUBSHELL, not a parent, so it needs
            # kernel.yama.ptrace_scope=0. ci.yml's "Install hang-capture
            # tooling" step sets exactly that (`sudo sysctl -w
            # kernel.yama.ptrace_scope=0`) alongside installing gdb, which is
            # why attach succeeds there. Run this script OUTSIDE that workflow
            # and a restrictive ptrace_scope will refuse the attach -- the
            # artifact then says CAPTURE INCOMPLETE and the wchan table is the
            # only stack evidence, which is the intended degradation rather
            # than a silent one.
            echo "=== gdb: thread map + all backtraces ==="
            gdb_out="$(timeout -k 10 180 gdb -p "$CMD_PID" -batch \
                        -ex 'info threads' -ex 'thread apply all bt 25' 2>&1)"
            gdb_rc=$?
            printf '%s\n' "$gdb_out"
            # SAY WHETHER WE ACTUALLY GOT BACKTRACES. An attach failure
            # (ptrace_scope, missing gdb, a 180s stall) previously produced an
            # artifact that looked like a capture and contained an error string,
            # so "the artifact exists" was not the same as "we learned
            # something" -- and the artifact is read weeks later by someone who
            # was not here.
            if [ "$gdb_rc" -eq 124 ] || [ "$gdb_rc" -eq 137 ]; then
                echo "!!! CAPTURE INCOMPLETE: gdb itself timed out after 180s (rc=$gdb_rc)."
                echo "!!! The wchan table above is the only stack evidence in this file."
            elif [ "$gdb_rc" -ne 0 ]; then
                echo "!!! CAPTURE INCOMPLETE: gdb exited $gdb_rc without attaching."
                echo "!!! Check ptrace_scope and that gdb is installed on the runner."
                echo "!!! The wchan table above is the only stack evidence in this file."
            elif ! printf '%s' "$gdb_out" | grep -q '#0'; then
                echo "!!! CAPTURE INCOMPLETE: gdb exited 0 but produced no stack frames."
            else
                echo "(gdb exit: 0 - backtraces captured)"
            fi
        } > "$ARTIFACT_DIR/${CMD_NAME}_hang_stack.txt"
        kill -9 "$CMD_PID" 2>/dev/null || true
    fi
) &
WATCHDOG=$!

# `wait` under `bash -e` (GitHub's default shell) ABORTS on a non-zero status,
# so `wait "$CMD_PID"; rc=$?` would make every line below dead on exactly the
# failure path we care about.
rc=0
wait "$CMD_PID" || rc=$?

# Kill the sleep CHILD FIRST, then the subshell. Order is the whole fix.
#
# The previous version killed the subshell first and then ran `pkill -P` against
# it -- but once the subshell is dead its children are reparented to init, so
# `pkill -P` matches nothing and the sleep survives, holding the step's stdout
# open. The comment above that code named this exact failure mode ("killing only
# the subshell leaves the sleep orphaned") while the code did not actually
# prevent it: a fix that describes the bug it does not fix.
#
# Measured by this script's self-test, which counts `sleep <budget>` by its exact
# argument after a fast command: 1 leaked before, 0 after. A bare `pgrep -c
# sleep` had reported 0 by accident, because it counted every sleep on the
# machine including the test's own.
pkill -P "$WATCHDOG" 2>/dev/null || true
kill "$WATCHDOG" 2>/dev/null || true
wait "$WATCHDOG" 2>/dev/null || true

exit "$rc"
