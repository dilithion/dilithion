#!/bin/bash
# P2P-16 structural guard: no released chainstate pointer in the headers manager.
#
# WHY THIS EXISTS.
#
# CChainState::GetTip() takes cs_main, reads pindexTip, and RELEASES cs_main
# before returning. The CBlockIndex it points at is owned by mapBlockIndex and
# can be destroyed by EvictLowestWorkNotOnBestChain at any moment afterwards.
#
# CHeadersManager used to call GetTip() and then walk the result
# (pTip->GetAncestor(height)) while holding cs_headers and NOT cs_main — a
# use-after-free an inbound peer could drive, since peers trigger locator
# construction. Both external cross-family seats on the merged P2P-14/15 diff
# found it independently (register P2P-16).
#
# The obvious repair is forbidden: taking cs_main under cs_headers is the exact
# lock-order inversion P2P-14/15 closed. So the fix moves the DATA out of the
# lock instead of the pointer — CChainState::GetAncestorHashes() resolves
# height->hash under cs_main and returns copies.
#
# That fix is one edit away from being undone, and undoing it would be SILENT:
# every test would still pass, because the failure needs an eviction to land
# inside a specific window. So the invariant gets a structural check.
#
# THE INVARIANT, chosen to be complete by construction rather than by search:
# GetTip() is the only way a released chainstate pointer enters this file. If it
# is never CALLED here, no such pointer can exist here — no matter what future
# code does. That is a stronger claim than "no dereference looks unsafe".
#
# Exit 0 = invariant holds. Exit 1 = it does not.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

HM="src/net/headers_manager.cpp"
HH="src/net/headers_manager.h"
fail=0

if [ ! -f "$HM" ] || [ ! -f "$HH" ]; then
    echo "FAIL: $HM or $HH missing — this guard cannot check what it claims"
    exit 1
fi

# Strip comments before looking for CALLS, so the explanatory comments in this
# file (which necessarily name GetTip and GetAncestor) are not read as code.
# Removes //-to-end-of-line and whole-line /* */ blocks; good enough for a
# call-site check and deliberately simple enough to audit by eye.
code_only() {
    sed -e 's://.*::' -e '/^[[:space:]]*\/\*/,/\*\//d' "$1"
}

# 1. GetTip() must not be CALLED in the headers manager. This is the entry
#    point for the whole released-pointer class; close it and the class cannot
#    appear in this translation unit at all.
hits=$(code_only "$HM" | grep -cE '\bGetTip[[:space:]]*\(')
if [ "$hits" -ne 0 ]; then
    echo "FAIL: headers_manager.cpp CALLS GetTip() ($hits site(s))."
    echo "      GetTip() releases cs_main before returning, so the CBlockIndex*"
    echo "      it hands back can be freed by eviction at any time. Walking it"
    echo "      without cs_main is P2P-16, a peer-triggerable use-after-free."
    echo "      Use CChainState::GetAncestorHashes() — it returns VALUES."
    code_only "$HM" | grep -nE '\bGetTip[[:space:]]*\(' | head -5
    fail=1
fi

# 2. No CBlockIndex ancestor/parent walk in this file. Even reached by some
#    other route, such a walk belongs under cs_main in chain.cpp, not here.
walks=$(code_only "$HM" | grep -cE '\->(GetAncestor|pprev|pskip)\b')
if [ "$walks" -ne 0 ]; then
    echo "FAIL: headers_manager.cpp walks a CBlockIndex ($walks site(s))."
    echo "      A chain walk must happen under cs_main, inside chain.cpp, and"
    echo "      leave as values. See CChainState::GetAncestorHashes()."
    code_only "$HM" | grep -nE '\->(GetAncestor|pprev|pskip)\b' | head -5
    fail=1
fi

# 3. GetLocatorImpl must keep taking VALUES. Reverting its parameter to a
#    CBlockIndex* is precisely the regression, and it would compile cleanly.
#    NOTE: the declaration spans three lines, and grep is line-based — the
#    first version of this check looked only at single lines and reported the
#    parameter missing on a tree where it was present. Flatten first.
flatten() { tr '\n' ' ' < "$1" | tr -s ' '; }

if flatten "$HH" | grep -qE 'GetLocatorImpl[^;]*CBlockIndex[[:space:]]*\*' \
   || flatten "$HM" | grep -qE 'GetLocatorImpl[^;)]*CBlockIndex[[:space:]]*\*'; then
    echo "FAIL: GetLocatorImpl takes a CBlockIndex* again."
    echo "      It must take resolved height->hash VALUES; a pointer parameter"
    echo "      re-opens P2P-16 with every test still green."
    fail=1
fi
if ! flatten "$HH" | grep -qE 'GetLocatorImpl[^;]*std::map<int,[[:space:]]*uint256>'; then
    echo "FAIL: GetLocatorImpl no longer declares the resolved-values parameter"
    echo "      in $HH — check this guard against the source before trusting it."
    fail=1
fi

# 4. The accessor this fix depends on must still return values, not the
#    pointer someone might restore "for efficiency".
if ! grep -qE 'std::vector<uint256>[[:space:]]+CChainState::GetAncestorHashes' src/consensus/chain.cpp 2>/dev/null; then
    echo "FAIL: CChainState::GetAncestorHashes is missing or no longer returns"
    echo "      std::vector<uint256>. The headers manager depends on it to get"
    echo "      chain data across a lock-free window without a pointer."
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: no released chainstate pointer in the headers manager"
    echo "  - GetTip() is never called there (the class cannot appear in that TU)"
    echo "  - no CBlockIndex ancestor/parent walk in that TU"
    echo "  - GetLocatorImpl still takes resolved values, not a CBlockIndex*"
    echo "  - CChainState::GetAncestorHashes still returns values"
fi
exit "$fail"
