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
# So a behavioural arm here is BLOCKED ON THE CHECKER-SELECTION FIX (the branch
# fix/lp10-vdf-checker-selection, which routes regtest to the VDF checker whose
# rule fabricated headers can satisfy). When that lands, replace this guard with
# the real arm: short batch -> phase FINAL, MAX_HEADERS_RESULTS batch -> phase
# PRESYNC, via CHeadersManager::GetHeadersSyncPhase.
#
# Until then this is a structural property with a structural check, stated as
# such rather than dressed up as coverage.
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
