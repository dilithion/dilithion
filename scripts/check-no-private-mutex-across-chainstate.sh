#!/bin/bash
# P2P-17 guard: no private mutex held across a call into the chainstate.
#
# WHY. A CChainState accessor that takes cs_main, called while a class holds its
# own mutex, creates a <private mutex> -> cs_main edge. Block connect/disconnect
# callbacks create the opposite edge (they fire with cs_main HELD — see
# chain.cpp's DisconnectTip comment), so the pair is an AB-BA between the reorg
# thread and whichever thread takes the private mutex first.
#
# Register P2P-17 is exactly that, in CCoinStatsIndex::WriteBlock. NOTE the
# severity, corrected on review: that pair was LATENT, not live — both of its
# edges are gated on IsSynced() and are therefore temporally exclusive. The fix
# makes the inversion structurally impossible instead of gate-dependent, which is
# what this guard preserves.
#
# SCOPE, so it is not over-trusted: this detects a LOCK HELD ACROSS A CALL. It
# does NOT detect the released-pointer/lifetime class (P2P-16), where the
# accessor is called holding nothing and the pointer is dereferenced later —
# check-headers-manager-no-chainstate-pointer.sh covers that one. Verified by
# running this audit on the pre-P2P-16 head, where it correctly reports CLEAN for
# GetLocator. Different defects, different instruments, neither subsumes the other.
#
# Exit 0 = no private mutex held across a chainstate call. Exit 1 = at least one.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

# A missing interpreter must FAIL, not skip. Review fix: the first version exited
# 0 with a SKIP notice, which is a silent pass — the precise shape of every
# "absence of failure is not evidence" defect this repo has already paid for.
PY=$(command -v python3 || command -v python) || {
    echo "FAIL: no python interpreter found, so the lock-scope audit COULD NOT RUN."
    echo "      This is a hard failure on purpose: a check that cannot run must"
    echo "      not report success. Install python or fix PATH."
    exit 1
}

out=$("$PY" scripts/lock_scope_audit.py . 2>&1); rc=$?
if [ "$rc" -ge 2 ]; then
    echo "FAIL: the lock-scope audit errored (rc=$rc):"; printf '%s\n' "$out"; exit 1
fi

# KNOWN-SAFE allowlist. Each entry is a site where a private mutex IS held across
# a cs_main-taking call and that is argued safe — with the argument, not a name.
# Anything NOT listed fails. Complete by construction: a new site fails until
# someone classifies it.
#
#   headers_manager.cpp OnBlockActivated (cs_headers)
#     P2P-14/15 removed the cs_main -> cs_headers direction (chain.cpp:2637), so
#     only one direction exists and there is no cycle to close.
#   dilithion-node.cpp / dilv-node.cpp (g_pendingMinerWinsMutex)
#     The sharper argument, from the #197 reader, and it is the one to keep:
#     EVERY OTHER holder of this mutex is a bare push_back (dilithion-node :6441,
#     :6653 and the dilv twins) that touches no chainstate at all. So no thread
#     ever waits on cs_main while holding g_pendingMinerWinsMutex unless it
#     ALREADY owns cs_main — the only holder that reaches the chainstate is
#     itself inside a block-connect callback, where cs_main is held and recursive.
#     There is therefore no thread that can supply the opposite order.
#     (My first argument — "both acquisitions are inside callbacks" — was true but
#     weaker: it described two sites instead of the property of all of them.)
#
# NOT a site, recorded so it is not re-derived as one: peers.cpp:1038 holds a
# private mutex across g_chainstate.GetHeight(), but GetHeight is LOCK-FREE (an
# atomic read, BUG #74) and takes no cs_main. Same shape as headers_manager:2885.
# The generated accessor list excludes both automatically — which is the point of
# generating it rather than hand-writing six names.
ALLOWED='^(src/net/headers_manager\.cpp|src/node/dilithion-node\.cpp|src/node/dilv-node\.cpp)$'

fail=0
while IFS= read -r line; do
    case "$line" in
        '*** '*)
            f=${line#'*** '}; f=${f%%:*}
            if ! printf '%s' "$f" | grep -qE "$ALLOWED"; then
                echo "FAIL: $f holds a private mutex across a cs_main-taking chainstate call."
                echo "      That is one half of an AB-BA with the cs_main -> <private mutex>"
                echo "      edge the block connect/disconnect callbacks create (P2P-17)."
                echo "      Fix: unique_lock + unlock() across the call, as"
                echo "      CCoinStatsIndex::WriteBlock, its Init(), and tx_index.cpp:520 do."
                echo "      If it is genuinely safe, add it to ALLOWED **with the argument**."
                fail=1
            fi
            ;;
    esac
done <<< "$out"

if [ "$fail" -eq 0 ]; then
    echo "PASS: no UNCLASSIFIED private mutex held across a chainstate call"
    printf '%s\n' "$out" | grep -E 'accessors generated|files scanned' | sed 's/^/  /'
else
    printf '%s\n' "$out"
fi
exit "$fail"
