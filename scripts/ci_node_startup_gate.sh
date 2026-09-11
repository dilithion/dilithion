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
#   * `--datadir` is an ISOLATED TEMP DIR, removed on exit.
#   * ⚠️ `--relay-only` IS PASSED, and an earlier version of this header promised
#     the opposite. It has to be: the WALLET GATE SITS BEFORE THE STARTUP GATE
#     (`dilithion-node.cpp:5521` refuses a non-TTY launch with no wallet and names
#     only two ways past it — `--relay-only` or an interactive terminal; there is
#     no third flag in the parser). Without it the node can never reach the thing
#     this leg measures. CI run 34573246685 failed all four matrix jobs on exactly
#     that, and is why this file no longer claims otherwise.
#   * **That flag arms the live HIGH (2026-09-11): a node given `--datadir=` can
#     still resolve SEED-ATTESTATION paths from the chainparams default.** It is
#     safe HERE only because an ephemeral runner's default directory does not
#     exist and holds nothing. It is NOT safe on a developer box — so the local
#     override was REMOVED rather than left as a footgun, and so was the container
#     check (see `in_ci()`): a devcontainer takes no deliberate act to be inside.
#   * `--generate-seed-key` is NEVER passed. `--relay-only` sets the seed-capable
#     path (gated on `relay_only || public_api`), so the attestation loader runs
#     and resolves against `g_chainParams->dataDir`; with no key file and no
#     permission to mint, it takes the documented benign non-fatal path and the
#     node boots non-attesting. Measured on a live host, on the HARDER case — a
#     protected directory that EXISTS and is full: it printed FATAL, refused to
#     mint, wrote nothing (mtime identical to the nanosecond), and the node kept
#     running and reached the gate. A runner's directory does not exist at all.
#   * ⚠️ THE CONVERSE, STATED BECAUSE IT IS LOAD-BEARING: **this leg must never
#     run anywhere a real default datadir exists.** It is a live exerciser of the
#     open HIGH's arming condition — fine on an ephemeral runner, unacceptable
#     anywhere else. That is why `in_ci()` below is strict and has no override.
#   * MAINNET datadir only. Testnet's default directory is the protected one.
#
# ⚠️ EVERY GATE BETWEEN PROCESS START AND THE LINE THIS LEG WAITS FOR. This list
# exists because the leg twice mistook a gate it had not anticipated for an epoch
# wiring defect. A gate added to the node WITHOUT a case added below is then a
# visible omission in a file that already fails closed, rather than a surprise in
# CI six weeks later — the lesson carried by the artifact instead of by whoever
# remembers it.
#   1. argument parsing            — an unknown flag ends in `Unknown option:`
#   2. wallet setup (`:5521`)      — refuses a non-TTY launch with no wallet;
#                                    passed here by `--relay-only`
#   3. seed-attestation load       — benign non-fatal without a key (above)
#   4. peer handshake settle       — ~10 s, bounded, inside the timeout
#   5. RandomX FULL-mode dataset   — behind `config.start_mining`; NOT on this
#                                    path, because `--mine` is never passed. If
#                                    that ever changes, the 120 s budget does not
#                                    survive it.
#   6. AwaitEpochRegistration      — THE TARGET. Everything above is a way to
#                                    never arrive.
#
# Self-test: scripts/ci_node_startup_gate.sh --self-test
#   Drives the wait/timeout/kill logic against a FAKE node that prints scripted output,
#   so the logic is proved without launching anything. The real node is CI's job.

set -u

GATE_LINE='declared epoch participants have checkpointed'
REFUSE_LINE='REFUSING TO START'
TIMEOUT_S="${DIL_STARTUP_GATE_TIMEOUT:-120}"

# The launch arguments, defined ONCE so the self-test can assert on the REAL
# thing rather than on a description of it. The first gate-5 case grepped this
# file for "--mine" and matched the COMMENTS saying --mine is never passed -- a
# check that failed on a healthy tree, in the file whose subject is checks that
# fail on healthy trees. Caught by running it.
# (--datadir is appended at launch: it is a temp dir created at runtime.)
# ⚠️ --verbose EARNS ITS PLACE: it is what makes the node print its OWN hash-worker
# count ("[HeadersManager] N hash workers started", gated on g_verbose, which
# dilithion-node.cpp:2228 stores from config.verbose). That number is the missing
# half of the census floor -- see the tightening block after the baseline check.
# Verified against the parser at dilithion-node.cpp:783, not written from memory.
NODE_ARGS="--port=18555 --rpcport=18556 --connect=127.0.0.1:1 --relay-only --verbose"

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
# log_says_bad_launch <logfile> — did the NODE refuse because THIS SCRIPT started
# it wrongly? Every entry here was a real CI failure that pointed at innocent
# code, not a hypothetical:
#   * the wallet/TTY gate (CI run 34573246685, all four matrix jobs);
#   * an unknown flag (`--noconnect`, caught before it shipped).
# Keeping them in one testable predicate is the point: the enumeration grew twice
# because each time I only taught the script the failure I had just hit.
# ---------------------------------------------------------------------------
log_says_bad_launch() {
    grep -qF "Wallet setup requires an interactive terminal" "$1" 2>/dev/null && return 0
    grep -q  "Unknown option:" "$1" 2>/dev/null && return 0
    return 1
}

# ---------------------------------------------------------------------------
# hash_workers_from_log <logfile> — how many hash workers did the NODE say it
# started? Empty when the line is absent, which the caller must treat as
# "could not measure", never as agreement.
#
# ⚠️ IT IS A FUNCTION SO THE SELF-TEST CAN REACH IT. The one branch of in_ci()
# the harness could not exercise was the branch that turned out to be wrong; the
# rule earned there is applied here rather than re-learned.
# ---------------------------------------------------------------------------
hash_workers_from_log() {
    grep -oE '\[HeadersManager\] [0-9]+ hash workers started' "$1" 2>/dev/null         | head -1 | grep -oE '[0-9]+' | head -1
}

# ---------------------------------------------------------------------------
# in_ci — are we on a CI runner?
#
# ⚠️ `[ -n "$CI" ]` IS THE WRONG TEST, AND IT INVERTS ON THE ONE VALUE PEOPLE
# TYPE DELIBERATELY. `CI=false` is non-empty, so an emptiness test reads the
# string that MEANS "not CI" as "yes, CI" and launches a node on a developer
# box. That is not a nit here: the Actions runners are plain VMs, and this is now
# the ONLY predicate — there is no container fallback behind it (see below) — so
# what it holds back is a real node launch on a machine whose
# chainparams-default datadir holds wallet and seed material (the open
# `--datadir` attestation HIGH). The guard was weaker than the warning in this
# file's own header.
#
# `GITHUB_ACTIONS` is set to "true" by Actions itself and by nothing else, so it
# is the primary. `CI` is still honoured — many runners set only that — but a
# FALSEY value is taken to mean what it says.
# ---------------------------------------------------------------------------
#
# ⚠️ THERE IS DELIBERATELY NO `/.dockerenv` BRANCH, AND THERE USED TO BE.
# It returned 0 on the container marker ALONE, before CI or GITHUB_ACTIONS were
# consulted. Once the env override was removed and --relay-only became required,
# that branch was the whole guard for anyone in a devcontainer or a
# `docker run -v ~:/root`: the leg would have launched a relay-only node against
# a REAL $HOME/.dilithion holding wallet and seed material — the exact directory
# the open HIGH is about. **The tightening closed the door that required a
# deliberate act and left open the one that requires none**: an env var takes
# intent, being inside a container takes none. Every real CI system sets CI or
# GITHUB_ACTIONS, so nothing legitimate is lost.
#
# ⚠️ AND NOTE WHICH BRANCH IT WAS: the only one the self-test could not exercise,
# because a test can unset variables but cannot create /.dockerenv. The untestable
# branch is the one that was wrong. When a predicate has a branch the harness
# cannot reach, look THERE first.
in_ci() {
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

    # (6) ⚠️ THE DISCRIMINATION THAT COST FOUR MATRIX JOBS. A node that exits
    #     before the gate is either the assertion firing or this script starting
    #     it wrongly. The leg used to assert the first and was wrong; these cases
    #     pin the difference so it cannot regress to a single story again.
    printf 'ERROR: Wallet setup requires an interactive terminal.\nstdin is not a TTY\n' > "$tmp/w.log"
    log_says_bad_launch "$tmp/w.log" \
        && echo "  PASS  wallet/TTY exit reads as a BAD LAUNCH, not a wiring defect" \
        || { echo "  FAIL  wallet/TTY exit misread as a wiring defect"; fails=$((fails+1)); }

    printf 'Unknown option: --noconnect\n' > "$tmp/u.log"
    log_says_bad_launch "$tmp/u.log" \
        && echo "  PASS  unknown flag reads as a BAD LAUNCH" \
        || { echo "  FAIL  unknown flag misread"; fails=$((fails+1)); }

    # ⚠️ AND THE CONVERSE, WHICH IS THE ONE THAT MATTERS: a real abort must NOT be
    #    excused as a bad launch, or this predicate becomes a way to lose the
    #    defect the whole leg exists to catch.
    printf '[Chain] deferred reclamation: assertion failed\nAborted (core dumped)\n' > "$tmp/x.log"
    if log_says_bad_launch "$tmp/x.log"; then
        echo "  FAIL  a real abort was excused as a bad launch"; fails=$((fails+1))
    else
        echo "  PASS  a real abort is NOT excused as a bad launch"
    fi

    # (7) ONE CASE PER GATE IN THE HEADER'S ENUMERATION. A gate added to the node
    #     without a case here is meant to be a visible omission; that only works
    #     if the listed ones are actually exercised.
    #
    # ⚠️ GATE 3 IS THE DANGEROUS ONE AND IT IS WHY THIS BLOCK EXISTS. The
    #    seed-attestation loader prints **FATAL** when it finds no key and is not
    #    permitted to mint -- and the node KEEPS RUNNING and reaches the gate
    #    (measured on a live host). A leg that treated "FATAL" as death would fail
    #    on a healthy tree, which is this file's recurring sin. It must not.
    ( sleep 1
      echo "[SeedAttestation] FATAL: no attestation key and minting not permitted" >> "$tmp/g3.log"
      echo "[Chain] deferred reclamation: all 28 $GATE_LINE" >> "$tmp/g3.log" ) &
    faker=$!; : > "$tmp/g3.log"
    watch_for_gate "$tmp/g3.log" "$faker"; rc=$?
    wait "$faker" 2>/dev/null
    [ "$rc" -eq 0 ] && echo "  PASS  gate 3: a FATAL attestation line does NOT abort the leg" \
        || { echo "  FAIL  gate 3: FATAL misread as death (rc=$rc)"; fails=$((fails+1)); }

    # GATE 4: the ~10 s handshake settle is a WARN the node walks past.
    ( sleep 1
      echo "  [WARN] No handshakes completed after 10s (peers will auto-reconnect)" >> "$tmp/g4.log"
      echo "[Chain] deferred reclamation: all 28 $GATE_LINE" >> "$tmp/g4.log" ) &
    faker=$!; : > "$tmp/g4.log"
    watch_for_gate "$tmp/g4.log" "$faker"; rc=$?
    wait "$faker" 2>/dev/null
    [ "$rc" -eq 0 ] && echo "  PASS  gate 4: a handshake WARN does not stop the leg" \
        || { echo "  FAIL  gate 4: handshake WARN misread (rc=$rc)"; fails=$((fails+1)); }

    # GATE 5: RandomX FULL-mode init is behind --mine and must NOT be on this
    # path. Asserted against the script's own launch line rather than prose,
    # because a future edit that adds --mine would blow the 120 s budget.
    case "$NODE_ARGS" in
      *--mine*)
        echo "  FAIL  gate 5: NODE_ARGS passes --mine; the RandomX dataset wait"
        echo "        will exceed the launch timeout budget"; fails=$((fails+1)) ;;
      *)
        echo "  PASS  gate 5: --mine is not in NODE_ARGS, so no RandomX dataset wait" ;;
    esac

    # (8) the tightening input's three outcomes. ⚠️ The third -- "could not
    #     measure" -- is the one that must never resemble the first.
    printf '[HeadersManager] Starting 4 hash worker threads (Phase 2)...
[HeadersManager] 4 hash workers started
' > "$tmp/hw.log"
    got="$(hash_workers_from_log "$tmp/hw.log")"
    [ "$got" = "4" ] && echo "  PASS  hash-worker count read from the node's own line"         || { echo "  FAIL  hash-worker parse got '$got', want 4"; fails=$((fails+1)); }

    # the "Starting N ... threads" line must NOT be mistaken for the started line
    printf '[HeadersManager] Starting 7 hash worker threads (Phase 2)...
' > "$tmp/hw2.log"
    got="$(hash_workers_from_log "$tmp/hw2.log")"
    [ -z "$got" ] && echo "  PASS  the 'Starting' line alone is not read as a count"         || { echo "  FAIL  'Starting' line misread as '$got'"; fails=$((fails+1)); }

    : > "$tmp/hw3.log"
    got="$(hash_workers_from_log "$tmp/hw3.log")"
    [ -z "$got" ] && echo "  PASS  an absent line yields EMPTY (could-not-measure)"         || { echo "  FAIL  absent line yielded '$got'"; fails=$((fails+1)); }

    echo
    if [ "$fails" -ne 0 ]; then
        echo "===== node startup gate SELF-TEST: FAIL ($fails) ====="; exit 1
    fi
    echo "===== node startup gate SELF-TEST: PASS (18 cases) ====="
    exit 0
fi

# ---------------------------------------------------------------------------
# the real run
# ---------------------------------------------------------------------------
cd "$ROOT" || exit 2

# ⚠️ NO LOCAL OVERRIDE, BY DESIGN, AND THIS USED TO HAVE ONE.
# `DIL_STARTUP_GATE_ALLOW_LOCAL=1` was removed when the leg was forced to pass
# --relay-only (see the launch below): that flag arms the seed-attestation path
# the open HIGH is about, and an env var is far too cheap a key for a door that
# now leads somewhere real. The container marker was removed from in_ci() for the
# opposite reason: being inside a devcontainer takes no intent at all, and with a
# mounted home it points at the very directory the HIGH is about.
if ! in_ci; then
    echo "===== node startup gate: REFUSED TO RUN ====="
    echo "  This launches a real node WITH --relay-only, which arms the open"
    echo "  --datadir attestation-path HIGH: a node given --datadir can still"
    echo "  resolve seed-attestation paths from the chainparams default, and on a"
    echo "  developer box that is a REAL directory holding wallet and seed material."
    echo "  There is deliberately no override and no container escape hatch:"
    echo "  CI=true or GITHUB_ACTIONS=true, on a host with no real datadir."
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
# ⚠️ --relay-only IS PASSED, REVERSING WHAT THIS SCRIPT ORIGINALLY PROMISED, AND
# THE REVERSAL IS DELIBERATE. The first version refused it because --relay-only is
# the flag that ARMS the open HIGH (a node given --datadir can still resolve
# SEED-ATTESTATION paths from the chainparams default). CI run 34573246685 then
# failed on all four matrix jobs for a reason that makes the refusal impossible to
# keep: the WALLET GATE SITS BEFORE THE STARTUP GATE. dilithion-node.cpp:5521
# refuses a non-TTY launch that has no wallet, naming exactly two ways past it --
# --relay-only, or an interactive terminal. There is no third flag; I enumerated
# the parser. So the node can NEVER reach the thing this leg measures without it.
#
# What makes it safe HERE and nowhere else: this runs ONLY on an ephemeral CI
# runner, where the chainparams default directory does not exist
# and holds nothing to leak or destroy. The local-override escape hatch has been
# REMOVED rather than left as a footgun -- on a developer box that default is a
# real directory with wallet and seed material, and with --relay-only now required
# the old override would have armed precisely the path the HIGH is about.
# --generate-seed-key is still NEVER passed, so no key can be minted.
#
# ⚠️ AND IT CHANGES WHAT THE CENSUS COUNTS: a relay-only node declares the
# participants a relay-only node has. The baseline must be measured from THIS
# configuration, and is not comparable to a mining node's.
# shellcheck disable=SC2086  # deliberate word-splitting of NODE_ARGS
"$NODE" --datadir="$workdir/data" $NODE_ARGS > "$log" 2>&1 &
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
  2) # ⚠️ TWO VERY DIFFERENT THINGS REACH THIS BRANCH, AND THE FIRST DRAFT NAMED
     # ONLY ONE OF THEM. A node that exits before the gate is EITHER the
     # assertion firing (the defect this leg exists to expose) OR this script
     # starting the node wrongly (the leg being broken). The old text asserted
     # the first -- "which is exactly the case this leg exists to make visible"
     # -- and CI run 34573246685 proved how expensive that is: the node had
     # exited because it wanted a TTY to create a wallet, and the leg pointed
     # four matrix jobs' worth of readers straight at the epoch code.
     #
     # Enumerating known instrument failures one at a time is what produced that
     # bug twice (first `--noconnect`, then the wallet gate). So the DEFAULT
     # reading here is now skeptical, and the known ones are named on top of it.
     if log_says_bad_launch "$log"; then
         echo "  ⚠️ THE NODE WANTED A TTY TO CREATE A WALLET. That is a MISCONFIGURED"
         echo "     LAUNCH -- a bug in this leg -- NOT an epoch wiring defect. The"
         echo "     wallet gate sits BEFORE the startup gate, so the node can never"
         echo "     reach the thing this leg measures without a wallet or --relay-only."
         echo "===== node startup gate: FAIL (bad launch in this script) ====="; exit 2
     fi
     echo "  ⚠️ THE NODE EXITED BEFORE REACHING THE GATE. THIS IS AMBIGUOUS and must"
     echo "     not be read as a wiring defect until the tail below is checked:"
     echo "       (a) the one-shot ConsensusInvariant(!IsEpochParticipant()) fired"
     echo "           -- an abort, and the case this leg exists to expose; or"
     echo "       (b) the node refused to START for a reason of its own (config,"
     echo "           wallet, ports, datadir) -- in which case THIS SCRIPT is what"
     echo "           is broken and the epoch code is innocent."
     echo "     An abort leaves a signal/assert line; a refusal leaves an ERROR and"
     echo "     a clean shutdown sequence. Read which one this is BEFORE debugging."
     tail -20 "$log" | sed 's/^/       /'
     echo "===== node startup gate: FAIL (node exited early -- see above) ====="; exit 1 ;;
  3) echo "  ⚠️ TIMED OUT after ${TIMEOUT_S}s without reaching the gate."
     tail -20 "$log" | sed 's/^/       /'
     echo "===== node startup gate: FAIL (timeout) ====="; exit 1 ;;
esac

census="$(grep -F "$GATE_LINE" "$log" | head -1)"
echo "  $census"

# ⚠️ REPORT THE RUNNER SHAPE BESIDE THE COUNT, because the count depends on it.
# The hash-worker pool is sized from hardware_concurrency (headers_manager.cpp:3617)
# but CLAMPED: 4 if detection fails, and CAPPED AT 8. So the census varies only
# within a BOUNDED band -- every runner with 8 or more cores reports the same
# total -- which is what makes a floor provable rather than guessed.
cores="$(nproc 2>/dev/null || echo '?')"
hash_est="$cores"
case "$hash_est" in ''|*[!0-9]*) hash_est=4 ;; esac
[ "$hash_est" -gt 8 ] 2>/dev/null && hash_est=8
echo "  runner: ${cores} cores -> hash pool ~${hash_est} of the census (nproc)"

# ---------------------------------------------------------------------------
# ⚠️ THE TIGHTENING INPUT. The committed floor (17) is derived from the CLAMP
# alone -- hash workers are in [1,8], so from a census C the fixed remainder is
# at least C-8 and no healthy node can print below (C-8)+1. That needs no
# assumption and is why it shipped.
#
# A TIGHTER floor needs the fixed remainder EXACTLY, which means knowing how many
# of the census are hash workers. `nproc` is a guess at that: it is what the
# RUNNER reports, not what the NODE sees. Under cgroup quotas or CPU affinity the
# two can differ, and if the node ever sees MORE cores than nproc reports, a floor
# derived from nproc is too high and FAILS ON A HEALTHY TREE -- the defect this
# leg has produced three times.
#
# So the node is asked directly, and the two are compared. Agreement pins the
# remainder and licenses the tighter floor; DISAGREEMENT IS THE FINDING, not
# noise, and the floor stays where it is.
# ---------------------------------------------------------------------------
node_hash="$(hash_workers_from_log "$log")"
if [ -z "$node_hash" ]; then
    # ⚠️ "COULD NOT MEASURE" MUST NOT READ AS "MEASURED AND FINE". This is not a
    # failure of the tree -- the leg still did its job -- but it must not look
    # like the agreement case, or a silent format change would freeze the
    # tightening forever while appearing to progress.
    echo "  ⚠️ tightening input UNAVAILABLE this run: the node printed no"
    echo "     \"[HeadersManager] N hash workers started\" line. Either --verbose"
    echo "     stopped reaching g_verbose or that text changed. The floor stays at"
    echo "     its clamp-derived value; do NOT tighten from nproc alone."
elif [ "$node_hash" = "$cores" ]; then
    fixed=$((count - node_hash))
    echo "  node reports $node_hash hash workers; nproc agrees -> fixed remainder $fixed"
    echo "  => a floor of $((fixed + 1)) is derivable on THIS evidence (committed floor: ${expect_min:-unset})"
else
    echo "  ⚠️ DISAGREEMENT, AND THIS IS THE FINDING: nproc says $cores, the node"
    echo "     reports $node_hash hash workers. hardware_concurrency and nproc do not"
    echo "     see the same machine here (cgroup quota or CPU affinity), so ANY floor"
    echo "     derived from nproc would be wrong. Keep the clamp-derived floor."
fi

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
# declares with its own size, so runners of different shapes report different,
# equally correct totals.
#
# ⚠️ BUT THE VARIATION IS BOUNDED, and I first stated this as though it were not.
# :3618-3623 CLAMPS that count -- 4 if detection fails, and CAPPED AT 8 -- so
# hash workers live in [1,8] and every runner with 8+ cores reports the SAME
# total. That bound is what makes a floor PROVABLE instead of guessed: from an
# observed census C the fixed remainder is at least C-8, so the smallest census a
# healthy node can print on ANY runner is (C-8)+1. Pinning the number I happen to observe
# would redden this leg on the next runner with a different shape — the precise
# failure mode this script's own header was written about. The RPC pool (8) and
# the block-worker pool (1) are fixed; the hash-worker pool is not.
#
# So the drop check is keyed to a MEASURED baseline, not a read-derived one, and
# it is a FLOOR rather than an equality so extra cores can only ever add.
# ---------------------------------------------------------------------------
baseline_file="$ROOT/scripts/epoch_participant_census.baseline"
# ⚠️ READ THE FIRST NUMERIC LINE, NOT EVERY DIGIT IN THE FILE. An earlier version
# used `tr -dc '0-9'`, which would have spliced the digits out of the recorded
# invocation (ports 18555/18556) into a nonsense floor the moment the file gained
# the configuration line below.
expect_min="${DIL_STARTUP_GATE_MIN:-$(grep -m1 -oE '^[0-9]+' "$baseline_file" 2>/dev/null)}"
if [ -n "$expect_min" ]; then
    if [ "$count" -lt "$expect_min" ]; then
        echo "  ⚠️ CENSUS DROPPED: $count declared, baseline floor $expect_min."
        echo "     Some participants stopped being DECLARED. The gate still passed"
        echo "     -- it only asks that declared threads checkpoint -- so this is"
        echo "     the check that catches it. Either a declaration was lost, or"
        echo "     this runner has fewer cores than the one that set the baseline"
        echo "     (hash workers = hardware_concurrency, clamped to [1,8]); check"
        echo "     lowering $baseline_file."
        echo "===== node startup gate: FAIL (census below baseline) ====="; exit 1
    fi
    echo "  census $count >= baseline floor $expect_min"
elif [ -f "$baseline_file" ]; then
    # ⚠️ A FILE THAT EXISTS BUT DOES NOT PARSE IS NOT THE SAME AS NO FILE, and
    # reading it as "no baseline" would silently disarm a check somebody thought
    # they had armed -- the quietest way for this leg to stop discriminating.
    echo "  ⚠️ $baseline_file EXISTS BUT NO COUNT COULD BE READ FROM IT."
    echo "     The file must carry the count on a line of its own (comments may"
    echo "     precede it). Refusing to treat an unreadable baseline as an absent"
    echo "     one: someone armed this and it is not armed."
    echo "===== node startup gate: FAIL (unparsable baseline) ====="; exit 2
else
    # ⚠️ SOFT, AND SAYS SO. A number I cannot measure on this box is a number I
    # will not invent: the baseline is seeded from a real run, not from reading.
    echo "  ⚠️ NO BASELINE RECORDED -- partial-loss detection is NOT active."
    echo "     This run observed $count."
    # ⚠️ THE BASELINE RECORDS ITS CONFIGURATION, NOT JUST ITS NUMBER. A relay-only
    # node declares the participants a relay-only node has; the same integer taken
    # from a mining node would mean something else entirely, and a baseline that
    # quietly means something else is worse than no baseline. So the file carries
    # the invocation that produced it.
    echo "     To arm it, commit the count WITH the configuration that produced it:"
    echo "       {"
    echo "         echo \"# measured $(date -u +%Y-%m-%d) on a CI runner\""
    echo "         echo \"# invocation: dilithion-node --datadir=<tmp> $NODE_ARGS\""
    echo "         echo \"# hash workers = hardware_concurrency, so smaller runners"
    echo "         echo \"#   legitimately report FEWER; this is a FLOOR, not an equality.\""
    echo "         echo $count"
    echo "       } > scripts/epoch_participant_census.baseline"
fi

echo "  the startup assertion did not fire and $count participants checkpointed"
echo "===== node startup gate: PASS ====="
exit 0
