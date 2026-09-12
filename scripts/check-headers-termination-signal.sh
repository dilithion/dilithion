#!/bin/bash
# LP-10 F5/D-1 structural guard: the ONLY caller of ProcessNextHeaders must
# DERIVE full_headers_available, never hand it a literal.
#
# WHY THIS IS STRUCTURAL AND NOT A RUNTIME ARM — the honest version.
#
# full_headers_available is the sync-termination signal. A NON-full headers
# message means the peer's chain has ended (PRESYNC) or the peer is declining to
# re-serve the chain it claimed (REDOWNLOAD), and HeadersSyncState aborts on it.
# headerssync_termination_tests drives those aborts directly and mutation-kills
# four ways.
#
# The CALLER is a different matter. CHeadersManager::ProcessHeadersWithDoSProtection
# passed a hardcoded `true`, so the signal could never fire in production no
# matter how correct the callee was. That is the defect this guard protects.
#
# ⛔ A RUNTIME ARM FOR IT CANNOT BE WRITTEN ON THIS BRANCH, and the reason is
# itself a defect, MEASURED rather than assumed (probe, 2026-09-11):
#
#     n=3     init=1  before=PRESYNC  ret=0  after=NONE(erased)
#     n=2000  init=1  before=PRESYNC  ret=0  after=NONE(erased)
#
# Identical outcomes for a short batch and a protocol-maximum batch, so the
# signal is unobservable through the manager. The cause is NOT the signal: the
# manager selects its proof checker on IsDilV(), so REGTEST is handed
# RandomXHeaderProofChecker, which rejects every synthesisable header ("Invalid
# proof for header ...") long before the termination signal is consulted. Any
# manager-level header test on regtest dies at the same wall — which is exactly
# why the existing gate-arming suite drives the manager with an EMPTY vector.
#
# ⛔ THAT BLOCKER IS GONE, AND THIS COMMENT SAID OTHERWISE FOR ONE ROUND TOO LONG.
# fix/lp10-vdf-checker-selection MERGED as main 8d8b9b8e and routes regtest to the
# VDF checker, so the wall described above no longer exists. The arm this comment
# promised is now WRITTEN, not pending:
#
#   src/test/headerssync_gate_arming_tests.cpp
#     test_manager_short_batch_terminates_and_full_batch_continues
#       batch of 1    -> abort, state erased, GetHeadersSyncPhase == nullopt
#       batch of 2000 -> no abort, GetHeadersSyncPhase == PRESYNC
#     both at a threshold the peer cannot reach, so neither arm can be explained
#     by promotion -- only the batch's FULLNESS differs.
#
#   Mutation-verified: reverting the caller's full_headers_available to a constant
#   `true` makes that arm FAIL on its own (isolated run, exit 3), then restored
#   from an out-of-tree baseline, sha256-matched, rebuilt, green.
#
# THIS GUARD STAYS ANYWAY, and the reason is not sentiment. The arm proves the
# behaviour of the code as written; the guard proves the SHAPE -- that exactly one
# production caller exists and that it derives the flag rather than passing a
# constant. A future second caller passing `true` would leave the arm green, since
# the arm drives the caller that behaves. Different questions, both worth asking.
# What has changed is that this file is no longer a stand-in for missing coverage.
#
# Exit 0 = invariant holds. Exit 1 = it does not. Exit 2 = the guard could not run.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

FILE="src/net/headers_manager.cpp"
[ -f "$FILE" ] || { echo "GUARD ERROR: $FILE not found — cannot verify, failing closed"; exit 2; }
command -v grep >/dev/null 2>&1 || { echo "GUARD ERROR: grep unavailable — failing closed"; exit 2; }

rc=0

# 1. The literal must be gone. This is the exact text that shipped.
literal=$(grep -c 'ProcessNextHeaders(headers, true)' "$FILE" || true)
if [ "$literal" -ne 0 ]; then
    echo "FAIL: $FILE passes a LITERAL true for full_headers_available ($literal site(s))."
    echo "      The sync-termination aborts cannot fire. Derive it as Core does:"
    echo "      headers.size() == Consensus::MAX_HEADERS_RESULTS   (net_processing.cpp:2787)"
    rc=1
fi

# 2. The derivation must be present. Asserted AFFIRMATIVELY — absence of the
#    literal is not evidence the right thing replaced it; it could have been
#    deleted, renamed, or replaced with a different constant.
derived=$(grep -c 'headers.size() == Consensus::MAX_HEADERS_RESULTS' "$FILE" || true)
if [ "$derived" -lt 1 ]; then
    echo "FAIL: $FILE does not derive full_headers_available from the batch size."
    echo "      Expected: headers.size() == Consensus::MAX_HEADERS_RESULTS"
    rc=1
fi

# 3. Exactly one caller. If a second appears, this guard has stopped covering
#    the population and must be widened rather than trusted.
# ⚠️ COMMENT LINES ARE EXCLUDED, and the first version of this guard did not do
# that — it counted the Core citation two lines above the call and reported "2
# callers". `grep -c` counting a comment as a call site is the same error this
# mission has now made three times; the guard that exists to prevent it is not
# exempt from it.
callers=$(grep -n 'ProcessNextHeaders(' "$FILE" | grep -vE '^[0-9]+: *(//|\*|/\*)' | grep -c . || true)
if [ "$callers" -ne 1 ]; then
    echo "FAIL: expected exactly 1 ProcessNextHeaders call in $FILE, found $callers."
    echo "      A new caller must derive the signal too. Widen this guard."
    rc=1
fi

if [ "$rc" -eq 0 ]; then
    echo "check-headers-termination-signal: OK (literal=0, derived=$derived, callers=$callers)"
fi
exit $rc
