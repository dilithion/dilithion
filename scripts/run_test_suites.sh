#!/usr/bin/env bash
# ============================================================================
# run_test_suites.sh — execute the standalone (non-Boost) test binaries.
#
# WHY THIS EXISTS
# ---------------
# Until this script landed, `make tests` had a one-line recipe:
#     @echo "✓ All tests built successfully"
# It BUILT ~44 test binaries and executed NONE of them. CI (.github/workflows/
# ci.yml) never invoked `make tests` at all — it built and ran only
# test_dilithion (the Boost suite) and wallet_load_guard_test. Net effect: the
# entire standalone-test corpus had never been executed by any automated
# process. Several suites had bit-rotted to the point of not compiling.
#
# This script is the single source of truth for:
#   * WHICH standalone suites exist,
#   * WHICH tier each runs in (fast = PR-gating, full = scheduled),
#   * WHICH are QUARANTINED and the written reason why,
#   * the per-suite timeout.
#
# The Makefile derives its build lists from `--list <tier>` so the roster
# cannot drift from what gets built.
#
# RULES FOR EDITING THE ROSTER
#   * Never make a suite green by weakening its assertions. Quarantine it with
#     a reason instead — a quarantine is loud and auditable, a loosened
#     assertion is silent.
#   * A quarantine entry MUST carry a reason string. Empty reason = live.
#   * NO APOSTROPHES IN A REASON. ROSTER is a single-quoted shell string, so a
#     lone ' closes it and the script dies with a syntax error. Write "the X
#     abort", not "X's abort". A syntax error here makes `--list` print
#     nothing, which the Makefile turns into a hard error rather than an
#     empty (vacuously green) build list.
#   * NO PIPES IN A REASON either, now that a fifth field exists: `read` puts
#     the remainder in the LAST variable, so a stray | silently truncates the
#     reason and turns its tail into ARGS. validate_roster() rejects it.
#   * Removing a quarantine requires the suite to actually pass.
#
# USAGE
#   scripts/run_test_suites.sh [--list] [--fail-fast] [--check-roster]
#                              [fast|full|all]
#     --list          print the suite names in the tier (build-list generation)
#     --fail-fast     stop at the first failing suite (default: run all, then
#                     report the full roster and exit non-zero)
#     --check-roster  validate the roster, print the live/partial/quarantined
#                     census, and exit. Runs nothing.
# ============================================================================

set -u

# ---------------------------------------------------------------------------
# ROSTER: tier|suite|timeout_seconds|reason|args
#
# tier:    fast = runs on every PR;  full = scheduled/nightly + on demand
#
# ONE INVARIANT governs the reason field, and every rule below is a consequence
# of it: A NON-EMPTY REASON MEANS SOMETHING IN THIS ROW IS NOT RUN.
#
#   reason EMPTY               -> LIVE. The whole suite runs. ARGS must be
#                                 empty; there is nothing to say about scope.
#   reason "partial: <text>"   -> LIVE WITH ARGS. The suite RUNS, but only the
#                                 part ARGS selects; <text> says what is
#                                 excluded and why. ARGS must be NON-EMPTY.
#                                 A partial row is NOT excused from failing.
#   reason anything else       -> QUARANTINED. Nothing runs. It is still BUILT
#                                 (so it cannot rot further) and the reason is
#                                 printed. ARGS must be empty.
#
# WHY `partial:` EXISTS. Every suite in this roster is a hand-written main()
# calling scenario functions in sequence -- censused 2026-09-07, 51 rows, zero
# Boost -- and 24 of them assert(). assert() aborts the PROCESS, so on a failing
# suite only the FIRST failure is ever observed and every later scenario in the
# file has never executed at all. Two consequences, both bad:
#   * every quarantine reason of the form "N assertions fail" is a systematic
#     UNDERCOUNT -- N is the number seen before the abort, not the number that
#     fail;
#   * quarantine is all-or-nothing, so one broken scenario removes the whole
#     file from the gate, including the scenarios that were passing. That is
#     coverage lost to a bookkeeping limitation, not to a defect.
# `partial:` is the narrower instrument: exclude the broken scenario in writing,
# keep the rest gating. The suites cooperate via src/test/test_only_selector.h,
# which gives a hand-written main a `--only=<name>` selector that exits non-zero
# on an unknown name (so a typo in ARGS fails loudly instead of silently running
# nothing).
#
# ARGS is word-split into separate argv entries. It is not a shell: no quoting,
# no globbing, no substitution.
# ---------------------------------------------------------------------------
# A quarantine reason prefixed NOBUILD: additionally excludes the suite from
# --list, i.e. it is not even compiled. Use ONLY for suites whose source no
# longer compiles against current APIs — everything else stays in the build so
# further rot is caught immediately.
#
# Every entry below was measured by executing the binary (Windows/MSYS2,
# 2026-08-08, commit 0129850b). Status of every suite is recorded in the F4 PR
# body. NOTHING here was made green by weakening an assertion.
#
# RE-MEASURED 2026-08-10 after merging main (Windows/MSYS2): fast tier 32/32
# pass in 72s wall, full tier's live suites pass. dfmp_mik_tests came off
# quarantine because #156 landed and it now passes. wallet_load_guard_tests was
# added -- it was in main's old hand-maintained `tests:` list and the derived
# build list would otherwise have silently stopped building it. The gate was
# confirmed discriminating by injecting a deliberately-failing suite: the runner
# exited 1 and `make tests-fast` exited 2; both returned to 0 on its removal.
#
# ADDED 2026-09-05 (Windows/MSYS2, measured by executing both binaries):
# vdf_consensus_test (25/25 pass, 0.9s) and vdf_lottery_test (11/11 pass). Both
# were ORPHANED -- built by the Makefile, named by no roster row, no aggregate
# make target and no workflow, so `make tests` had never run either. The whole
# DilV VDF test surface was unrun. Registration proved live by a discriminating
# check, not by absence of error: `make -n tests-build` mentioned neither suite
# before their sources were touched and both after. COUNTED, not derived: the
# fast tier is now 41 rows, 37 of them live (4 quarantined). The "32/32 in 72s"
# figure above is the 2026-08-10 measurement and is no longer the current count.
#
# PARTIAL 2026-09-07: chain_case_2_5_equivalence_tests, the first row to use it,
# and it immediately found what the mechanism was built to find. Measured on
# Linux (WSL Ubuntu-24.04, the platform every runs-on: in ci.yml uses), each
# scenario run ALONE via --only=:
#     scenario_1  exit 0        scenario_2  exit 134 (assert, :305)
#     scenario_3  exit 0        scenario_4  exit 134 (assert, :392)
#     scenario_5  exit 0
# SCENARIO 4 HAD NEVER BEEN OBSERVED FAILING. Its assert is unreachable behind
# scenario_2, which aborts the process first, so 3, 4 and 5 had never executed
# in any run of this suite -- and the quarantine reason named scenario_2 alone,
# because that is genuinely all anyone could see. The two failures share one
# cause: both assert ok=true after a ConnectTip failure that follows a committed
# disconnect, and ActivateBestChainStep now truncates and triggers auto_rebuild.
# Selection 1+3+5 passes 5/5 deterministically and now GATES, where previously
# the whole file was quarantined and nothing in it ran at all.
#
# QUARANTINE LIFTED 2026-09-07: rpc_tests. Measured on Linux (WSL Ubuntu-24.04,
# which is the platform every `runs-on:` in ci.yml uses), N=20 with the
# exit-code histogram, using scripts/measure_suite_stability.sh:
#     BEFORE  PASS=0  FAIL=20  HANG=0   histogram: 1 x20
#     AFTER   PASS=20 FAIL=0   HANG=0   histogram: 0 x20
# A DETERMINISTIC failure, not a hang -- which is why the quarantine was lifted
# rather than its timeout raised. The stated reason was accurate but incomplete:
# it named the auth/permissions init, and fixing that revealed two further real
# requirements the never-starting server had hidden (the X-Dilithion-RPC CSRF
# header, then HTTP Basic credentials). The quarantine was covering three
# defects, not one.
#
# integration_tests was NOT quarantined and needs its own note, because its exit
# code cannot show what changed: it exited 0 BEFORE and 0 AFTER. It had been
# passing while its RPC server never started once -- Start() failed, the test
# printed "may be port conflict or system limitation" and returned true. Proven
# by MUTATION rather than by exit code: with the permissions init removed the
# suite now exits 1 (mutant dies), so the fix is load-bearing.
#
# Negative controls were added at the same time and are the reason the lift is
# worth anything: before them, deleting the CSRF check in server.cpp left every
# suite in this roster green. Verified load-bearing by disabling that gate --
# rpc_tests exits 1 -- and restored.
#
# TIER: rpc_tests is fast, NOT full, and that is load-bearing rather than a
# preference. It is the only suite that pins the CSRF and auth gates by asserting
# they REJECT. In the full tier those pins run nightly and on roster-touching PRs
# only -- so a PR that deleted the CSRF block in server.cpp would merge GREEN,
# which is the exact hole the negative controls were written to close. A gate that
# does not run on the PR that breaks it is not a gate. Cost is ~6s.
ROSTER='
fast|rpc_auth_tests|120||
fast|rpc_host_header_tests|60||
fast|http_server_wallet_gate_tests|60||
fast|ratelimiter_tests|180||
fast|crypter_tests|300||
fast|script_tests|180||
fast|addrman_v2_tests|180||
fast|peer_scorer_tests|180||
fast|peer_scorer_banman_integration_tests|180||
fast|header_proof_checker_tests|180||
fast|chain_selector_tests|180||
fast|getchaintips_equivalence_tests|180||
fast|chain_work_smoke_tests|180||
fast|competing_sibling_below_checkpoint_tests|180||
fast|headers_manager_to_chain_selector_wiring_tests|180||
fast|fast_path_2_boundary_tests|180||
fast|v4_1_checkpoint_enforcement_tests|180||
fast|v4_1_chain_selector_suppression_tests|180||
fast|auto_rebuild_marker_mode_symmetry_tests|180||
fast|add_block_index_flag_merge_tests|180||
fast|port_chain_selector_invariants_tests|180||
fast|legacy_vs_port_differential_tests|180||
fast|magnet_canonical_health_tests|180||
fast|bug_003_block_size_tests|180||
fast|dfmp_heat_overflow_tests|300||
fast|mik_registration_persistence_tests|300||
fast|dna_propagation_tests|300||
fast|chainstate_integrity_tests|300||
fast|reorg_wal_crash_injection_tests|300||
fast|wallet_persistence_tests|300||
fast|wallet_load_guard_tests|120||
fast|wallet_encryption_integration_tests|600||
fast|genesis_all_networks_tests|600||
fast|shutdown_disarm_ownership_tests|60||
fast|test_only_selector_selftest|60||
fast|phase1_test|120|STALE TEST (diagnosed, fix deliberately NOT taken here): phase1_simple_test.cpp:25 hard-codes "MIN_TX_FEE = 50000, FEE_PER_BYTE = 25"; the live values in consensus/fees.h:14,17 are MIN_TX_FEE = 0 and FEE_PER_BYTE = 5, so both the fee assert (:26) and the rate assert (:30, expects 25..50 ions/byte, actual 5.0) fail. NOTE FOR WHOEVER FIXES IT: do not just substitute the current constants -- CalculateMinFee IS "MIN_TX_FEE + size*FEE_PER_BYTE" (fees.cpp:10), so an expectation written that way is a tautology that restates the implementation and covers nothing. Un-quarantine only with assertions that hold independently of the formula (e.g. rate == FEE_PER_BYTE exactly, which catches a flat base being reintroduced; strict monotonicity in tx size).|
fast|timestamp_tests|120||
fast|seed_attestation_key_tests|180|UNTRIAGED: 3 of ~40 checks fail around key-file MAC verification / migration. Needs the seed-attestation owner; failure mode is not obviously stale.|
fast|test_passphrase_validator|60|SUSPECTED REAL (policy): 2 of 16 cases -- two passphrases the suite expects REJECTED are now ACCEPTED at "Moderate (57/100)". Either the strength policy was deliberately loosened (then fix the expectations, with a reason) or it regressed. Do not just flip the expectations.|
fast|chain_case_2_5_equivalence_tests|180|partial: scenarios 2 and 4 are excluded, both on ONE behaviour change: each asserts ok=true after a ConnectTip failure that FOLLOWS a committed disconnect (:305 and :392), and ActivateBestChainStep now truncates the chain and triggers auto_rebuild, so ok=false. Needs a chainstate owner to say which side is right. Scenario 4 had NEVER been observed failing: scenario_2 aborts the process first, so 3, 4 and 5 had never executed in any run and the old quarantine reason named only scenario_2. Scenarios 1, 3 and 5 pass deterministically (5/5, Linux/WSL 2026-09-07) and gate here.|--only=scenario_1_replacement_succeeds --only=scenario_3_disconnect_old_tip_fails --only=scenario_5_write_best_block_fails_triggers_rebuild
fast|vdf_consensus_test|300||
fast|vdf_lottery_test|300||
fast|rpc_tests|300||
full|miner_tests|900|PRE-EXISTING, UNOWNED: 4 assertions fail -- "Failed to start mining", "No hashes computed", "No block found", "No hashes after mining". The mining controller does not start under the test harness. Flagged before F4; still unowned.|
full|wallet_tests|300|STALE TEST (likely): 4 assertions fail on coin selection / minimum relay fee / coinbase maturity -- e.g. builds a tx at 0.00001000 DIL against a 0.00010000 DIL minimum. Expectations predate the current fee and maturity rules.|
full|integration_tests|600||
full|connman_tests|600|SUSPECTED REAL: high-load throughput test loses messages (pop_count != NUM_MESSAGES, connman_tests.cpp:552). Message loss under load in CConnman is not a stale expectation.|
full|tx_relay_tests|600|WINDOWS-ONLY teardown hang (re-scoped 2026-08-15): all 6 tests PASS, then the process never exits on Windows/MSYS2 (exit 124 at 600s; teardown-path, post-J1/F6). LINUX CONFIRMATION DONE: under TSan on Linux (WSL, gcc, -fsanitize=thread) the binary runs all tests AND EXITS CLEANLY, zero data-race warnings -- so the hang is a Windows-specific teardown path (likely winsock/thread-join semantics), not a portable logic bug. Do NOT lift the quarantine on Windows by raising the timeout; needs a Windows-teardown owner. Linux CI can run this suite ungated.|
full|mining_integration_tests|900|MIXED, ONE SUSPECTED CONSENSUS GAP: (a) coinbase_transaction_creation expects 1 coinbase output and gets 3 -- stale, DFMP splits the coinbase; (b) block_validation_coinbase asserts CheckCoinbase REJECTS a coinbase paying 100 DIL at height 0 and it is ACCEPTED. (b) is a possible missing consensus check and must be triaged by a consensus owner before this quarantine is lifted.|
full|dfmp_mik_tests|600||
full|net_tests|600|NOBUILD: source no longer compiles. References a removed global g_peer_manager and calls CNetMessageProcessor::CreateVersionMessage() with a signature that no longer exists. Needs a P2P owner to port the harness forward.|
full|randomx_mode_test|1800||
full|large_pages_optin_test|2100||
'

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
LIST_ONLY=0
FAIL_FAST=0
CHECK_ONLY=0
TIER="all"
for arg in "$@"; do
    case "$arg" in
        --list)         LIST_ONLY=1 ;;
        --fail-fast)    FAIL_FAST=1 ;;
        --check-roster) CHECK_ONLY=1 ;;
        fast|full|all) TIER="$arg" ;;
        *) echo "run_test_suites.sh: unknown argument '$arg'" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# validate_roster — runs BEFORE anything else, including --list.
#
# --list is what the Makefile derives its build lists from, so a malformed
# roster must BREAK THE BUILD rather than quietly produce a shorter list. A
# build list that silently lost a suite is the failure mode this whole file
# exists to prevent; a roster error that only surfaced at run time would
# reintroduce it one layer down.
#
# It validates the WHOLE roster, not just the selected tier: a broken `full`
# row is still broken when someone runs `fast`, and finding it only on the
# nightly is finding it late.
# ---------------------------------------------------------------------------
validate_roster() {
    local errs=0 line tier suite timeout reason args nfields
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # Field count first: `read a b c d e` puts the remainder in e, so a
        # stray pipe inside a reason truncates the reason and turns its tail
        # into ARGS -- invisible in every output the row then produces.
        nfields=$(( $(printf '%s' "$line" | tr -cd '|' | wc -c) + 1 ))
        if [ "$nfields" -ne 5 ]; then
            echo "ROSTER ERROR: $(printf '%s' "$line" | cut -d'|' -f2) has $nfields fields, expected 5 (tier|suite|timeout|reason|args). A pipe inside a reason does this." >&2
            errs=$((errs + 1))
            continue
        fi
        IFS='|' read -r tier suite timeout reason args <<EOF
$line
EOF
        case "$tier" in
            fast|full) ;;
            *) echo "ROSTER ERROR: $suite has unknown tier '$tier' (expected fast or full)" >&2; errs=$((errs + 1)) ;;
        esac
        case "$timeout" in
            ''|*[!0-9]*) echo "ROSTER ERROR: $suite has a non-numeric timeout '$timeout'" >&2; errs=$((errs + 1)) ;;
        esac
        case "$reason" in
            partial:*)
                # A partial: row with no ARGS excludes nothing while its reason
                # claims it does -- a gate reporting on a scope nobody declared.
                if [ -z "$args" ]; then
                    echo "ROSTER ERROR: $suite is marked partial: but carries no ARGS, so it excludes nothing while its reason says it does. Give it the --only= selectors, or drop the partial: prefix." >&2
                    errs=$((errs + 1))
                fi
                ;;
            *)
                # ARGS on a live row runs something other than what the roster
                # says. ARGS on a quarantined row is inert today and becomes a
                # lie the day the quarantine lifts.
                if [ -n "$args" ]; then
                    if [ -z "$reason" ]; then
                        echo "ROSTER ERROR: $suite is LIVE (empty reason) but carries ARGS '$args'. A row that runs only part of its suite must say so: prefix the reason with partial:." >&2
                    else
                        echo "ROSTER ERROR: $suite is QUARANTINED but carries ARGS '$args'. A quarantined row runs nothing, so the ARGS are inert -- and become wrong silently the day the quarantine lifts." >&2
                    fi
                    errs=$((errs + 1))
                fi
                ;;
        esac
    done <<EOF
$(printf '%s\n' "$ROSTER")
EOF
    if [ "$errs" -gt 0 ]; then
        echo "run_test_suites.sh: $errs roster error(s); refusing to continue." >&2
        return 1
    fi
    return 0
}

validate_roster || exit 2

rows() {
    printf '%s\n' "$ROSTER" | while IFS='|' read -r tier suite timeout reason args; do
        [ -z "${suite:-}" ] && continue
        if [ "$TIER" = "all" ] || [ "$TIER" = "$tier" ]; then
            printf '%s|%s|%s|%s|%s\n' "$tier" "$suite" "$timeout" "$reason" "$args"
        fi
    done
}

if [ "$CHECK_ONLY" -eq 1 ]; then
    # The census COORD asked for: the three states counted separately, because
    # "quarantined=N" alone cannot distinguish a suite that runs in part from
    # one that does not run at all.
    c_live=0; c_partial=0; c_quar=0
    while IFS='|' read -r tier suite timeout reason args; do
        [ -z "${suite:-}" ] && continue
        case "$reason" in
            '')        c_live=$((c_live + 1)) ;;
            partial:*) c_partial=$((c_partial + 1)) ;;
            *)         c_quar=$((c_quar + 1)) ;;
        esac
    done <<EOF
$(rows)
EOF
    echo "roster OK (tier: $TIER)  live=$c_live  partial=$c_partial  quarantined=$c_quar"
    exit 0
fi

if [ "$LIST_ONLY" -eq 1 ]; then
    # NOBUILD: entries are excluded — their source does not compile, so adding
    # them to the build list would break the build for everyone. partial: rows
    # are INCLUDED: they run, so they must be built.
    rows | grep -v '|NOBUILD:' | cut -d'|' -f2 | tr '\n' ' '
    echo
    exit 0
fi

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
LOGDIR="${TEST_SUITE_LOGDIR:-test-suite-logs}"
mkdir -p "$LOGDIR"

RESULTS=""
FAILED=0
QUARANTINED=0
PARTIAL=0
LIVE=0
DEGRADED=0
RAN=0
TOTAL_SEC=0

echo "========================================================================"
echo "Standalone test suites — tier: $TIER"
echo "========================================================================"

while IFS='|' read -r tier suite timeout reason args; do
    [ -z "${suite:-}" ] && continue

    # A partial: row RUNS. It is the one non-empty reason that does not mean
    # "skipped" -- it means "this much of it runs, and here is what does not".
    case "${reason:-}" in
        '')        LIVE=$((LIVE + 1)) ;;
        partial:*) PARTIAL=$((PARTIAL + 1)) ;;
        *)
            printf '  [QUARANTINE] %-52s %s\n' "$suite" "$reason"
            RESULTS="${RESULTS}QUARANTINED|${suite}|0|${reason}\n"
            QUARANTINED=$((QUARANTINED + 1))
            continue
            ;;
    esac

    # ARGS is word-split deliberately: passed as one quoted string a suite sees
    # a single unparseable argv[1], exits non-zero on an unknown selector, and
    # the roster bug reads as a suite failure.
    args_arr=()
    if [ -n "${args:-}" ]; then
        read -r -a args_arr <<EOF
$args
EOF
    fi
    args_note=""
    [ -n "${args:-}" ] && args_note="  args: $args"

    bin=""
    for candidate in "./$suite" "./$suite.exe"; do
        [ -x "$candidate" ] && bin="$candidate" && break
    done
    if [ -z "$bin" ]; then
        printf '  [MISSING   ] %-52s binary not built\n' "$suite"
        RESULTS="${RESULTS}MISSING|${suite}|0|binary not built\n"
        FAILED=$((FAILED + 1))
        [ "$FAIL_FAST" -eq 1 ] && break
        continue
    fi

    log="$LOGDIR/$suite.log"
    start=$(date +%s)
    timeout --preserve-status -k 10 "$timeout" "$bin" ${args_arr[@]+"${args_arr[@]}"} >"$log" 2>&1
    rc=$?
    end=$(date +%s)
    elapsed=$((end - start))
    TOTAL_SEC=$((TOTAL_SEC + elapsed))
    RAN=$((RAN + 1))

    note=""
    # randomx_mode_test is the large-page control. On a host with no hugetlb
    # pool it compares two hashes that both came from standard-page
    # allocations — i.e. a value against itself — and passes while covering
    # nothing. Detect that from the binary's own output and report it as
    # DEGRADED so it can never look like real coverage. The nightly
    # large-page job sets DILITHION_TEST_REQUIRE_LARGE_PAGES=1, which turns
    # the same condition into a hard failure inside the binary.
    if [ "$suite" = "randomx_mode_test" ] && [ "$rc" -eq 0 ]; then
        if grep -q 'Large pages actually engaged: NO' "$log" 2>/dev/null; then
            note="large pages did NOT engage — fallback path only, control is vacuous here"
            DEGRADED=$((DEGRADED + 1))
            printf '  [DEGRADED  ] %-52s %4ds  %s\n' "$suite" "$elapsed" "$note"
            RESULTS="${RESULTS}DEGRADED|${suite}|${elapsed}|${note}\n"
            continue
        fi
    fi

    # The reason travels into the SUMMARY for a partial row, so the written
    # statement of what is NOT covered is printed beside its green tick rather
    # than living only in the roster. A PASS whose scope was reduced and does
    # not say so is the same shape of defect as a stale binary reporting PASS.
    detail=""
    [ -n "${args:-}" ] && detail="$reason"

    if [ "$rc" -eq 0 ]; then
        printf '  [PASS      ] %-52s %4ds%s\n' "$suite" "$elapsed" "$args_note"
        RESULTS="${RESULTS}PASS|${suite}|${elapsed}|${detail}\n"
    elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        printf '  [TIMEOUT   ] %-52s %4ds  (limit %ss)%s\n' "$suite" "$elapsed" "$timeout" "$args_note"
        RESULTS="${RESULTS}TIMEOUT|${suite}|${elapsed}|exceeded ${timeout}s\n"
        FAILED=$((FAILED + 1))
        echo "  ---- tail of $log ----"
        tail -n 30 "$log" | sed 's/^/  | /'
        [ "$FAIL_FAST" -eq 1 ] && break
    else
        printf '  [FAIL      ] %-52s %4ds  (exit %s)%s\n' "$suite" "$elapsed" "$rc" "$args_note"
        RESULTS="${RESULTS}FAIL|${suite}|${elapsed}|exit ${rc}\n"
        FAILED=$((FAILED + 1))
        echo "  ---- tail of $log ----"
        tail -n 40 "$log" | sed 's/^/  | /'
        [ "$FAIL_FAST" -eq 1 ] && break
    fi
done <<EOF
$(rows)
EOF

echo "========================================================================"
echo "SUMMARY (tier: $TIER)"
echo "------------------------------------------------------------------------"
printf '%b' "$RESULTS" | while IFS='|' read -r status suite secs detail; do
    [ -z "${suite:-}" ] && continue
    printf '  %-12s %-52s %4ss %s\n' "$status" "$suite" "$secs" "$detail"
done
echo "------------------------------------------------------------------------"
echo "  ran=$RAN  failed=$FAILED  quarantined=$QUARANTINED  degraded=$DEGRADED  wall=${TOTAL_SEC}s"
# The roster census, separate from the run counts. `quarantined=N` alone cannot
# distinguish a suite that runs in PART from one that does not run at all, and
# conflating them is how partial coverage gets read as full coverage.
echo "  roster census: live=$LIVE  partial=$PARTIAL  quarantined=$QUARANTINED"
if [ "$PARTIAL" -gt 0 ]; then
    echo "  ($PARTIAL suite(s) ran a REDUCED scope — see the partial: reason beside each above)"
fi
echo "  per-suite output: $LOGDIR/<suite>.log"
echo "========================================================================"

if [ "$FAILED" -gt 0 ]; then
    echo "✗ $FAILED suite(s) failed."
    exit 1
fi
echo "✓ All non-quarantined suites in tier '$TIER' passed."
exit 0
