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
# in_ci — are we on a CI runner?
#
# ⚠️ `[ -n "$CI" ]` IS THE WRONG TEST, AND IT INVERTS ON THE ONE VALUE PEOPLE
# TYPE DELIBERATELY. `CI=false` is non-empty, so an emptiness test reads the
# string that MEANS "not CI" as "yes, CI" and launches a node on a developer
# box. That is not a nit here: the Actions runners are plain VMs with no
# `/.dockerenv`, so this predicate — not the docker check — is what actually
# decides, and what it holds back is a real node launch on a machine whose
# chainparams-default datadir holds wallet and seed material (the open
# `--datadir` attestation HIGH). The guard was weaker than the warning in this
# file's own header.
#
# `GITHUB_ACTIONS` is set to "true" by Actions itself and by nothing else, so it
# is the primary. `CI` is still honoured — many runners set only that — but a
# FALSEY value is taken to mean what it says.
# ---------------------------------------------------------------------------
in_ci() {
    [ -f /.dockerenv ] && return 0
    case "${GITHUB_ACTIONS:-}" in [Tt][Rr][Uu][Ee]|1) return 0 ;; esac
    case "${CI:-}" in
        ''|[Ff][Aa][Ll][Ss][Ee]|0|[Nn][Oo]|[Oo][Ff][Ff]) return 1 ;;
        *) return 0 ;;
    esac
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

    # (5) the CI predicate. ⚠️ THE POINT OF THESE CASES IS `CI=false`: the
    #     previous emptiness test ran the node on exactly that input, which is
    #     the value someone sets to say "I am NOT in CI". A guard that inverts on
    #     its most deliberate input is worse than no guard, because the header
    #     promises it holds.
    check_ci() {  # <label> <expected 0|1> <env assignments...>
        local label="$1" want="$2"; shift 2
        ( unset CI GITHUB_ACTIONS; [ -n "$1" ] && export "$@"; in_ci ) ; local got=$?
        if [ "$got" -eq "$want" ]; then
            echo "  PASS  in_ci: $label"
        else
            echo "  FAIL  in_ci: $label (want $want, got $got)"; fails=$((fails+1))
        fi
    }
    check_ci "CI=false must NOT read as CI" 1 "CI=false"
    check_ci "CI=0 must NOT read as CI"     1 "CI=0"
    check_ci "CI unset is not CI"           1 ""
    check_ci "CI=true is CI"                0 "CI=true"
    check_ci "GITHUB_ACTIONS=true is CI"    0 "GITHUB_ACTIONS=true"

    echo
    if [ "$fails" -ne 0 ]; then
        echo "===== node startup gate SELF-TEST: FAIL ($fails) ====="; exit 1
    fi
    echo "===== node startup gate SELF-TEST: PASS (9 cases) ====="
    exit 0
fi

# ---------------------------------------------------------------------------
# the real run
# ---------------------------------------------------------------------------
cd "$ROOT" || exit 2

if ! in_ci && [ "${DIL_STARTUP_GATE_ALLOW_LOCAL:-}" != "1" ]; then
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
        # ⚠️ THE `kill -9` IS SAFE **HERE AND ONLY HERE**, AND THE REASON IS THE
        # DATADIR, NOT THE TIMEOUT. This node owns an isolated temp directory
        # created seconds ago and deleted on the next line: there is no
        # persistent state to corrupt, so losing the clean-shutdown path costs
        # nothing. Against a REAL node that is false — OPS-6 requires SIGTERM
        # and a wait, because SIGKILL during a flush can leave a chainstate that
        # must be rebuilt (a sibling session came within one command of doing
        # exactly that to 11 GB this morning). **Do not lift this pattern into
        # any script that points at a real datadir.**
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

# ---------------------------------------------------------------------------
# PARTIAL LOSS. The floor above catches zero and near-zero; it does NOT catch a
# tree that drops SOME declarations, which is the more plausible regression and
# the one sixteen EPOCH-WAIT-EXEMPT markers rest on.
#
# ⚠️ AND YET AN EXACT EXPECTED COUNT WOULD BE A CHECK THAT FAILS ON A HEALTHY
# TREE. The census total is CORE-COUNT DEPENDENT: headers_manager.cpp:3617 sets
# `m_hash_worker_count = std::thread::hardware_concurrency()` and that pool
# declares with its own size, so a 2-core runner and a 16-core runner report
# different, equally correct totals. Pinning the number I happen to observe
# would redden this leg on the next runner with a different shape — the precise
# failure mode this script's own header was written about. The RPC pool (8) and
# the block-worker pool (1) are fixed; the hash-worker pool is not.
#
# So the drop check is keyed to a MEASURED baseline, not a read-derived one, and
# it is a FLOOR rather than an equality so extra cores can only ever add.
# ---------------------------------------------------------------------------
baseline_file="$ROOT/scripts/epoch_participant_census.baseline"
expect_min="${DIL_STARTUP_GATE_MIN:-$(cat "$baseline_file" 2>/dev/null | tr -dc '0-9')}"
if [ -n "$expect_min" ]; then
    if [ "$count" -lt "$expect_min" ]; then
        echo "  ⚠️ CENSUS DROPPED: $count declared, baseline floor $expect_min."
        echo "     Some participants stopped being DECLARED. The gate still passed"
        echo "     -- it only asks that declared threads checkpoint -- so this is"
        echo "     the check that catches it. Either a declaration was lost, or"
        echo "     this runner has fewer cores than the one that set the baseline"
        echo "     (hash workers = hardware_concurrency); confirm which before"
        echo "     lowering $baseline_file."
        echo "===== node startup gate: FAIL (census below baseline) ====="; exit 1
    fi
    echo "  census $count >= baseline floor $expect_min"
else
    # ⚠️ SOFT, AND SAYS SO. A number I cannot measure on this box is a number I
    # will not invent: the baseline is seeded from a real run, not from reading.
    echo "  ⚠️ NO BASELINE RECORDED -- partial-loss detection is NOT active."
    echo "     This run observed $count. To arm it, commit that number (minus any"
    echo "     slack you want for smaller runners) as:"
    echo "       echo $count > scripts/epoch_participant_census.baseline"
fi

echo "  the startup assertion did not fire and $count participants checkpointed"
echo "===== node startup gate: PASS ====="
exit 0
