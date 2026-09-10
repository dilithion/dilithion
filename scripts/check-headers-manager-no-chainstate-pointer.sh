#!/bin/bash
# P2P-16 structural guard: the headers manager never CALLS a released-pointer
# accessor. Read "WHAT THIS PROVES" below before relying on it — the claim is
# deliberately narrower than the file name suggests.
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
# WHAT THIS PROVES, AND WHAT IT DOES NOT — measured, not asserted.
#
# The claim here was NARROWED to match a mutant table, because a broad claim
# resting on a grep is the false-confidence failure this PR has already paid for
# twice. One mutant per shape, appended to the real files and run against this
# guard:
#
#   S1  g_chainstate.GetTip() call                 CAUGHT
#   S2  g_chainstate.GetBlockIndex() call          CAUGHT  (added after it MISSED)
#   S6  alias via `auto p = ...GetTip()`           CAUGHT  (still a call)
#   S4  p->GetAncestor(h) walk                     CAUGHT
#   S7  the same call in headers_manager.h         CAUGHT  (added after it MISSED)
#   S3  a bare `CBlockIndex* p` declaration        MISSED
#   S5  a bare `p->nHeight` dereference            MISSED
#
# So this guard proves exactly two things:
#   (1) neither GetTip() nor GetBlockIndex() — the two accessors that RELEASE
#       cs_main and hand back a pointer — is CALLED in headers_manager.{cpp,h};
#   (2) no CBlockIndex ancestor/parent walk appears in the .cpp.
#
# It does NOT prove "no released chainstate pointer can exist here". A pointer
# arriving by another route — a parameter, a member, another object's accessor —
# and dereferenced as `p->nHeight` is INVISIBLE to it (S3, S5). Catching those
# means parsing C++ types rather than grepping: aliases, `auto`, dot-access,
# inline code in headers and `//` inside string literals all have to be handled,
# and a half-correct parser that reports CLEAN is worse than an honest narrow
# check. Claim (1) is complete by construction for the two named entry points,
# which is what makes it worth having at all.
#
# ON THE TWO ARMS, stated precisely because the weaker phrasing overclaims
# (review fold, LOW): the HIT arm of the resolved-value lookup is EXECUTED by the
# equivalence test in chain_tips_cache_invalidation_tests. The MISS arm — a
# pattern height at or below the chainstate tip that is absent from the resolved
# map — needs a gap in the pprev chain below the tip, which the eviction rules
# make unconstructible in production. So the miss arm is provably EQUIVALENT to
# the old "GetAncestor() returned nullptr" behaviour, not EXECUTED. Claiming
# "both arms verified" would be the stronger-sounding and weaker claim.
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
hits=$(( $(code_only "$HM" | grep -cE '\b(GetTip|GetBlockIndex)[[:space:]]*\(') + $(code_only "$HH" | grep -cE '\b(GetTip|GetBlockIndex)[[:space:]]*\(') ))
if [ "$hits" -ne 0 ]; then
    echo "FAIL: the headers manager CALLS GetTip()/GetBlockIndex() ($hits site(s))."
    echo "      GetTip() releases cs_main before returning, so the CBlockIndex*"
    echo "      it hands back can be freed by eviction at any time. Walking it"
    echo "      without cs_main is P2P-16, a peer-triggerable use-after-free."
    echo "      Use CChainState::GetAncestorHashes() — it returns VALUES."
    code_only "$HM" | grep -nE '\b(GetTip|GetBlockIndex)[[:space:]]*\(' | head -5
    code_only "$HH" | grep -nE '\b(GetTip|GetBlockIndex)[[:space:]]*\(' | head -5
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
    echo "PASS: the released-pointer accessors are not called in the headers manager"
    echo "  - GetTip()/GetBlockIndex() never called in headers_manager.{cpp,h}"
    echo "  - no CBlockIndex ancestor/parent walk in that TU"
    echo "  - GetLocatorImpl still takes resolved values, not a CBlockIndex*"
    echo "  - CChainState::GetAncestorHashes still returns values"
fi
exit "$fail"
