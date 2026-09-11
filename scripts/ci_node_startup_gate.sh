#!/usr/bin/env bash
# ==============================================================================
# ci_node_startup_gate.sh — prove the epoch startup gate is REACHED by a real node.
# ==============================================================================
#
# ⚠️ WHY THIS EXISTS. `dilithion-node` declares its epoch participants, checkpoints
# the main thread, and then calls `AwaitEpochRegistration(60000)` — refusing to start
# if any declared thread never checkpointed. Around it sits a one-shot
# `ConsensusInvariant(!IsEpochParticipant())` asserting the main thread has published
# no epoch before that point, which is what sixteen `EPOCH-WAIT-EXEMPT` markers rest on.
#
# **None of that had any automated value**, because nothing in CI ever ran a node past
# startup. A review seat said so plainly in round 9 of #198: the assertion could be
# deleted, or start failing, and every green suite would stay green. This is the leg
# that makes it observable — the difference between a check that exists and a check
# that runs.
#
# WHAT IT PROVES (and only this):
#   1. a real node REACHES the gate and PASSES it, printing the participant census;
#   2. the startup assertion does NOT fire (the process does not abort);
#   3. the census names a plausible number of participants, not zero.
# It does NOT exercise mining, sync, or any steady-state behaviour, and says so rather
# than letting "the node started" imply more.
#
# ⚠️ SAFETY, AND IT IS NOT INCIDENTAL:
#   * `--datadir` is an ISOLATED TEMP DIR, removed on exit. **There is a live HIGH
#     (2026-09-11) that a node given `--datadir=` can still resolve SEED-ATTESTATION
#     paths from the chainparams default** — and on a developer box that default is a
#     real, protected directory. That path is armed by `--relay-only`, which this
#     script therefore NEVER passes.
#   * `--generate-seed-key` is NEVER passed. It is forbidden on hosts with protected
#     data and has no business in a startup check.
#   * MAINNET datadir only. Testnet's default directory is the protected one.
#   * ⚠️ THIS IS A CI SCRIPT. It is safe on an ephemeral Linux runner with no
#     pre-existing node data. Running it on a developer machine is NOT recommended
#     while that HIGH is open, and `DIL_STARTUP_GATE_ALLOW_LOCAL=1` must be set to do
#     it at all — a deliberate step, not a default.
#
# Self-test: scripts/ci_node_startup_gate.sh --self-test
#   Drives the wait/timeout/kill logic against a FAKE node that prints scripted output,
#   so the logic is proved without launching anything. The real node is CI's job.

set -u

GATE_LINE='declared epoch participants have checkpointed'
REFUSE_LINE='REFUSING TO START'
TIMEOUT_S="${DIL_STARTUP_GATE_TIMEOUT:-120}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# watch_for_gate <logfile> <pidfile> — returns 0 when the gate line appears,
# 1 if the node refused, 2 if it died, 3 on timeout.
# ---------------------------------------------------------------------------
watch_for_gate() {
    local log="$1" pid="$2" waited=0
    while [ "$waited" -lt "$TIMEOUT_S" ]; do
        if grep -qF "$GATE_LINE" "$log" 2>/dev/null; then return 0; fi
        if grep -qF "$REFUSE_LINE" "$log" 2>/dev/null; then return 1; fi
        if ! kill -0 "$pid" 2>/dev/null; then return 2; fi
        sleep 1
        waited=$((waited + 1))
    done
    return 3
}

# ---------------------------------------------------------------------------
# --self-test: the wait logic, without a node
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT INT TERM
    fails=0
    TIMEOUT_S=5

    # (1) the gate line appears -> 0
    ( sleep 1; echo "[Chain] deferred reclamation: all 28 $GATE_LINE" >> "$tmp/a.log" ) &
    faker=$!; : > "$tmp/a.log"
    watch_for_gate "$tmp/a.log" "$faker"; rc=$?
    wait "$faker" 2>/dev/null
    [ "$rc" -eq 0 ] && echo "  PASS  gate line detected" || { echo "  FAIL  gate line not detected (rc=$rc)"; fails=$((fails+1)); }

    # (2) a REFUSAL must not read as success -- this is the failure the gate exists
    #     to produce, and a check that cannot tell it from success is worthless
    ( sleep 1; echo "FATAL: $REFUSE_LINE -- 1 thread(s) never checkpointed" >> "$tmp/b.log" ) &
    faker=$!; : > "$tmp/b.log"
    watch_for_gate "$tmp/b.log" "$faker"; rc=$?
    wait "$faker" 2>/dev/null
    [ "$rc" -eq 1 ] && echo "  PASS  refusal distinguished from success" || { echo "  FAIL  refusal not distinguished (rc=$rc)"; fails=$((fails+1)); }

    # (3) a node that DIES silently must not read as success
    ( sleep 1 ) & faker=$!; : > "$tmp/c.log"
    watch_for_gate "$tmp/c.log" "$faker"; rc=$?
    wait "$faker" 2>/dev/null
    [ "$rc" -eq 2 ] && echo "  PASS  a died-without-output node is a failure" || { echo "  FAIL  silent death not caught (rc=$rc)"; fails=$((fails+1)); }

    # (4) a node that never reaches the gate must TIME OUT, not hang forever
    ( sleep 30 ) & faker=$!; : > "$tmp/d.log"
    watch_for_gate "$tmp/d.log" "$faker"; rc=$?
    kill "$faker" 2>/dev/null; wait "$faker" 2>/dev/null
    [ "$rc" -eq 3 ] && echo "  PASS  a node that never reaches the gate times out" || { echo "  FAIL  no timeout (rc=$rc)"; fails=$((fails+1)); }

    echo
    if [ "$fails" -ne 0 ]; then
        echo "===== node startup gate SELF-TEST: FAIL ($fails) ====="; exit 1
    fi
    echo "===== node startup gate SELF-TEST: PASS (4 cases) ====="
    exit 0
fi

# ---------------------------------------------------------------------------
# the real run
# ---------------------------------------------------------------------------
cd "$ROOT" || exit 2

if [ ! -f /.dockerenv ] && [ -z "${CI:-}" ] && [ "${DIL_STARTUP_GATE_ALLOW_LOCAL:-}" != "1" ]; then
    echo "===== node startup gate: REFUSED TO RUN ====="
    echo "  This launches a real node. On a developer machine that is not safe while"
    echo "  the --datadir attestation-path HIGH is open: a node given --datadir can"
    echo "  still resolve seed-attestation paths from the chainparams default, which"
    echo "  on a developer box is a REAL directory holding wallet and seed material."
    echo "  Set DIL_STARTUP_GATE_ALLOW_LOCAL=1 only if you know this box has none."
    exit 2
fi

NODE=./dilithion-node
[ -x ./dilithion-node.exe ] && NODE=./dilithion-node.exe
if [ ! -x "$NODE" ]; then
    echo "===== node startup gate: FAIL (dilithion-node not built) ====="
    exit 2
fi

workdir="$(mktemp -d)"
log="$workdir/node.log"
cleanup() {
    if [ -n "${node_pid:-}" ] && kill -0 "$node_pid" 2>/dev/null; then
        kill "$node_pid" 2>/dev/null
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$node_pid" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$node_pid" 2>/dev/null
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

echo "launching a node with an isolated datadir (no --relay-only, no seed-key generation)"
# ⚠️ Non-default ports so this can never collide with, or be mistaken for, a real node.
# ⚠️ `--connect=` TO A DEAD ADDRESS, NOT `--noconnect` — THE LATTER DOES NOT EXIST.
# I wrote `--noconnect` from memory. The node's argument loop ends in an
# "Unknown option" error and REFUSES TO START, so this leg would have failed on a
# perfectly healthy tree — and the failure would have looked exactly like the gate
# rejecting a real wiring defect. Verified against the real parser instead of
# assumed: the flags that exist are `--datadir=`, `--port=`, `--rpcport=`,
# `--connect=`. `--connect=` also disables DNS seeds, which is what was wanted.
"$NODE" --datadir="$workdir/data" --port=18555 --rpcport=18556 \
        --connect=127.0.0.1:1 \
        > "$log" 2>&1 &
node_pid=$!

watch_for_gate "$log" "$node_pid"; rc=$?

# ⚠️ AN UNKNOWN OPTION IS A BUG IN THIS SCRIPT, NOT A GATE FAILURE, AND MUST SAY SO.
# Otherwise it arrives below as "the node refused to start" — indistinguishable from
# the gate catching a real wiring defect, and far more likely to send the next reader
# into the epoch code than into this file. I shipped precisely that bug in the first
# draft, so the discrimination is here rather than the lesson left to be repeated.
if grep -q "Unknown option:" "$log" 2>/dev/null; then
    echo "  ⚠️ THIS SCRIPT PASSED A FLAG THE NODE DOES NOT ACCEPT. That is a bug in"
    echo "     the leg, NOT a failure of the startup gate. Fix the flag; do not read"
    echo "     it as a wiring defect."
    grep "Unknown option:" "$log" | head -3 | sed 's/^/       /'
    echo "===== node startup gate: FAIL (bad flag in this script) ====="
    exit 2
fi

case "$rc" in
  0) ;;
  1) echo "  ⚠️ THE NODE REFUSED TO START. The startup gate found a declared"
     echo "     participant that never checkpointed, or an unregistered resolver."
     echo "     That is the gate working -- and it means this tree has a wiring bug."
     grep -F "$REFUSE_LINE" "$log" | head -3 | sed 's/^/       /'
     echo "===== node startup gate: FAIL (node refused) ====="; exit 1 ;;
  2) echo "  ⚠️ THE NODE DIED BEFORE REACHING THE GATE. If the one-shot"
     echo "     ConsensusInvariant(!IsEpochParticipant()) fired, it aborts here --"
     echo "     which is exactly the case this leg exists to make visible."
     tail -20 "$log" | sed 's/^/       /'
     echo "===== node startup gate: FAIL (node died) ====="; exit 1 ;;
  3) echo "  ⚠️ TIMED OUT after ${TIMEOUT_S}s without reaching the gate."
     tail -20 "$log" | sed 's/^/       /'
     echo "===== node startup gate: FAIL (timeout) ====="; exit 1 ;;
esac

census="$(grep -F "$GATE_LINE" "$log" | head -1)"
echo "  $census"

# ⚠️ A CENSUS OF ZERO WOULD PASS THE GATE AND PROVE NOTHING. The gate is satisfied
# when every DECLARED participant has checkpointed -- and zero declared participants
# satisfy it vacuously. Assert a plausible floor so a regression that stops
# DECLARING threads cannot read as a healthy start.
count="$(printf '%s\n' "$census" | sed -n 's/.*all \([0-9][0-9]*\) declared.*/\1/p')"
if [ -z "$count" ]; then
    echo "  ⚠️ could not parse a participant count from the census line -- the"
    echo "     output format changed and this check can no longer read it."
    echo "===== node startup gate: FAIL (unparsable census) ====="; exit 2
fi
if [ "$count" -lt 5 ]; then
    echo "  ⚠️ only $count declared participants. The gate passed, but vacuously:"
    echo "     a tree that stopped DECLARING threads would look exactly like this."
    echo "===== node startup gate: FAIL (census too small) ====="; exit 1
fi

echo "  the startup assertion did not fire and $count participants checkpointed"
echo "===== node startup gate: PASS ====="
exit 0
