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
#   * Removing a quarantine requires the suite to actually pass.
#
# USAGE
#   scripts/run_test_suites.sh [--list] [--fail-fast] [fast|full|all]
#     --list        print the suite names in the tier (build-list generation)
#     --fail-fast   stop at the first failing suite (default: run all, then
#                   report the full roster and exit non-zero)
# ============================================================================

set -u

# ---------------------------------------------------------------------------
# ROSTER: tier|suite|timeout_seconds|quarantine_reason
#
# tier:    fast = runs on every PR;  full = scheduled/nightly + on demand
# reason:  EMPTY  -> suite is live and its failure fails the run
#          NON-EMPTY -> suite is QUARANTINED; it is still BUILT (so it cannot
#                       rot further) but not run, and the reason is printed.
# ---------------------------------------------------------------------------
# A quarantine reason prefixed NOBUILD: additionally excludes the suite from
# --list, i.e. it is not even compiled. Use ONLY for suites whose source no
# longer compiles against current APIs — everything else stays in the build so
# further rot is caught immediately.
#
# Every entry below was measured by executing the binary (Windows/MSYS2,
# 2026-08-08, commit 0129850b). Status of every suite is recorded in the F4 PR
# body. NOTHING here was made green by weakening an assertion.
ROSTER='
fast|rpc_auth_tests|120|
fast|rpc_host_header_tests|60|
fast|http_server_wallet_gate_tests|60|
fast|ratelimiter_tests|180|
fast|crypter_tests|300|
fast|script_tests|180|
fast|addrman_v2_tests|180|
fast|peer_scorer_tests|180|
fast|peer_scorer_banman_integration_tests|180|
fast|header_proof_checker_tests|180|
fast|chain_selector_tests|180|
fast|getchaintips_equivalence_tests|180|
fast|chain_work_smoke_tests|180|
fast|competing_sibling_below_checkpoint_tests|180|
fast|headers_manager_to_chain_selector_wiring_tests|180|
fast|fast_path_2_boundary_tests|180|
fast|v4_1_checkpoint_enforcement_tests|180|
fast|v4_1_chain_selector_suppression_tests|180|
fast|auto_rebuild_marker_mode_symmetry_tests|180|
fast|add_block_index_flag_merge_tests|180|
fast|port_chain_selector_invariants_tests|180|
fast|legacy_vs_port_differential_tests|180|
fast|magnet_canonical_health_tests|180|
fast|bug_003_block_size_tests|180|
fast|dfmp_heat_overflow_tests|300|
fast|mik_registration_persistence_tests|300|
fast|dna_propagation_tests|300|
fast|chainstate_integrity_tests|300|
fast|reorg_wal_crash_injection_tests|300|
fast|wallet_persistence_tests|300|
fast|wallet_encryption_integration_tests|600|
fast|phase1_test|120|STALE TEST: asserts a hard-coded fee constant (fee_1in_1out == expected_fee, phase1_simple_test.cpp:26) that the fee schedule moved away from. Un-quarantine by re-deriving the expectation from the live fee code, never by deleting the check.
fast|timestamp_tests|120|SUSPECTED REAL: post-fork min-gap branch computes required=1410859008s (timestamp_tests.cpp:267 -> CheckBlockTimestamp). A ~44-year required inter-block gap is a nonsense value, not a moved goalpost. Needs a consensus owner before this is called stale.
fast|seed_attestation_key_tests|180|UNTRIAGED: 3 of ~40 checks fail around key-file MAC verification / migration. Needs the seed-attestation owner; failure mode is not obviously stale.
fast|test_passphrase_validator|60|SUSPECTED REAL (policy): 2 of 16 cases -- two passphrases the suite expects REJECTED are now ACCEPTED at "Moderate (57/100)". Either the strength policy was deliberately loosened (then fix the expectations, with a reason) or it regressed. Do not just flip the expectations.
fast|chain_case_2_5_equivalence_tests|180|UNTRIAGED: scenario_2 (connect-replacement-fails-then-recovers) now truncates the chain and triggers auto_rebuild instead of recovering (chain_case_2_5_equivalence_tests.cpp:304). Behaviour change in ActivateBestChainStep; needs a chainstate owner to say which side is right.
full|miner_tests|900|PRE-EXISTING, UNOWNED: 4 assertions fail -- "Failed to start mining", "No hashes computed", "No block found", "No hashes after mining". The mining controller does not start under the test harness. Flagged before F4; still unowned.
full|wallet_tests|300|STALE TEST (likely): 4 assertions fail on coin selection / minimum relay fee / coinbase maturity -- e.g. builds a tx at 0.00001000 DIL against a 0.00010000 DIL minimum. Expectations predate the current fee and maturity rules.
full|rpc_tests|300|STALE TEST: the harness calls CRPCServer::Start() without RPCAuth::InitializeAuth(), which the server now refuses by design. The test needs to initialise auth; the refusal itself is correct behaviour.
full|integration_tests|600|REAL DEFECT (shutdown): every assertion passes, then the process aborts with "terminate called without an active exception" -- a thread destroyed while joinable at exit. Exit code 3. Fix the shutdown path, not the test.
full|connman_tests|600|SUSPECTED REAL: high-load throughput test loses messages (pop_count != NUM_MESSAGES, connman_tests.cpp:552). Message loss under load in CConnman is not a stale expectation.
full|tx_relay_tests|600|REAL HANG: all 6 tests print PASSED, then the process never exits -- killed at the 600s timeout. Hang is after the last test, i.e. in teardown. Observed on Windows/MSYS2; needs a Linux confirmation run.
full|mining_integration_tests|900|MIXED, ONE SUSPECTED CONSENSUS GAP: (a) coinbase_transaction_creation expects 1 coinbase output and gets 3 -- stale, DFMP splits the coinbase; (b) block_validation_coinbase asserts CheckCoinbase REJECTS a coinbase paying 100 DIL at height 0 and it is ACCEPTED. (b) is a possible missing consensus check and must be triaged by a consensus owner before this quarantine is lifted.
full|dfmp_mik_tests|600|IN PROGRESS ELSEWHERE: 5 of 10 fail. Being fixed in draft PR #156 -- do not duplicate that work. REMOVE THIS QUARANTINE when #156 merges.
full|net_tests|600|NOBUILD: source no longer compiles. References a removed global g_peer_manager and calls CNetMessageProcessor::CreateVersionMessage() with a signature that no longer exists. Needs a P2P owner to port the harness forward.
full|randomx_mode_test|1800|
'

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
LIST_ONLY=0
FAIL_FAST=0
TIER="all"
for arg in "$@"; do
    case "$arg" in
        --list)      LIST_ONLY=1 ;;
        --fail-fast) FAIL_FAST=1 ;;
        fast|full|all) TIER="$arg" ;;
        *) echo "run_test_suites.sh: unknown argument '$arg'" >&2; exit 2 ;;
    esac
done

rows() {
    printf '%s\n' "$ROSTER" | while IFS='|' read -r tier suite timeout reason; do
        [ -z "${suite:-}" ] && continue
        if [ "$TIER" = "all" ] || [ "$TIER" = "$tier" ]; then
            printf '%s|%s|%s|%s\n' "$tier" "$suite" "$timeout" "$reason"
        fi
    done
}

if [ "$LIST_ONLY" -eq 1 ]; then
    # NOBUILD: entries are excluded — their source does not compile, so adding
    # them to the build list would break the build for everyone.
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
DEGRADED=0
RAN=0
TOTAL_SEC=0

echo "========================================================================"
echo "Standalone test suites — tier: $TIER"
echo "========================================================================"

while IFS='|' read -r tier suite timeout reason; do
    [ -z "${suite:-}" ] && continue

    if [ -n "${reason:-}" ]; then
        printf '  [QUARANTINE] %-52s %s\n' "$suite" "$reason"
        RESULTS="${RESULTS}QUARANTINED|${suite}|0|${reason}\n"
        QUARANTINED=$((QUARANTINED + 1))
        continue
    fi

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
    timeout --preserve-status -k 10 "$timeout" "$bin" >"$log" 2>&1
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

    if [ "$rc" -eq 0 ]; then
        printf '  [PASS      ] %-52s %4ds\n' "$suite" "$elapsed"
        RESULTS="${RESULTS}PASS|${suite}|${elapsed}|\n"
    elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        printf '  [TIMEOUT   ] %-52s %4ds  (limit %ss)\n' "$suite" "$elapsed" "$timeout"
        RESULTS="${RESULTS}TIMEOUT|${suite}|${elapsed}|exceeded ${timeout}s\n"
        FAILED=$((FAILED + 1))
        echo "  ---- tail of $log ----"
        tail -n 30 "$log" | sed 's/^/  | /'
        [ "$FAIL_FAST" -eq 1 ] && break
    else
        printf '  [FAIL      ] %-52s %4ds  (exit %s)\n' "$suite" "$elapsed" "$rc"
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
echo "  per-suite output: $LOGDIR/<suite>.log"
echo "========================================================================"

if [ "$FAILED" -gt 0 ]; then
    echo "✗ $FAILED suite(s) failed."
    exit 1
fi
echo "✓ All non-quarantined suites in tier '$TIER' passed."
exit 0
