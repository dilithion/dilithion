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
# The claim is NARROWED to match a mutant table, because a broad claim resting
# on a grep is the false-confidence failure this PR has already paid for twice.
# One mutant per shape, appended to the real files and run against this guard.
# The results below are from a run, not from reading the regexes:
#
#   S1  g_chainstate.GetTip() call                 CAUGHT
#   S2  g_chainstate.GetBlockIndex() call          CAUGHT  (added after it MISSED)
#   S6  alias via auto p = ...GetTip()             CAUGHT  (still a call)
#   S7  a real GetTip() call in headers_manager.h  CAUGHT
#   S4  p->GetAncestor(h) walk                     CAUGHT
#   S13 p->pprev walk                              CAUGHT
#   S12 p->pskip walk                              CAUGHT
#   S8  newline between GetTip and its open paren  CAUGHT  (added after it MISSED)
#   S9  whitespace after the arrow: p ->  pprev    CAUGHT  (added after it MISSED)
#   S10 a // inside a string literal, on a line    CAUGHT  (added after it MISSED)
#       that also carries a real GetTip() call
#   S11 inline block comment before the paren      CAUGHT  (added after it MISSED)
#   S3  a bare CBlockIndex* p declaration          MISSED
#   S5  a bare p->nHeight dereference              MISSED
#
# Plus a false-FAIL control: the guard must PASS on the clean tree, whose own
# comments name GetTip and GetAncestor throughout.
#
# S7 previously read CAUGHT on the strength of a DEFECTIVE mutant that appended
# a bare comment rather than a call, so it proved nothing. The row above is from
# a real call in the header.
#
# S8..S11 are the regex gaps an external reader predicted by reading this file
# rather than running it. Every one was MISSED when measured. S10 is the
# dangerous direction - a FALSE PASS, the guard reporting the invariant holds
# while the violating call sits in the file - because the old stripper deleted
# the rest of any line containing // inside a string literal.
#
# So this guard proves exactly two things:
#   (1) neither GetTip() nor GetBlockIndex() - the two accessors that RELEASE
#       cs_main and hand back a pointer - is CALLED in headers_manager.{cpp,h},
#       however the call is spelled or split across lines;
#   (2) no CBlockIndex ancestor/parent walk (GetAncestor/pprev/pskip) appears in
#       the .cpp, with or without whitespace around the arrow.
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
CS="src/consensus/chain.cpp"
STRIP="scripts/strip-cxx-comments.awk"
fail=0

for f in "$HM" "$HH" "$CS" "$STRIP"; do
    if [ ! -f "$f" ]; then
        echo "FAIL: $f missing - this guard cannot check what it claims"
        exit 1
    fi
done

# Strip comments and string-literal CONTENTS before looking at anything, so the
# explanatory comments in these files (which necessarily name GetTip and
# GetAncestor) are not read as code, and so a // inside a string literal cannot
# delete a real call from the line before the grep sees it.
#
# The previous stripper was sed 's://.*::' and it failed in BOTH directions:
#   - it deleted everything after the first // on a line, string literals
#     included, hiding a real call on that line (FALSE PASS, mutant S10);
#   - it removed only WHOLE-LINE block comments, so an inline one survived (S11).
# And checks 3 and 4 did not strip at all, so a doc comment could fail a clean
# tree - which is exactly what happened when a comment gained the words "see the
# note in GetLocatorImpl". Every check now reads stripped code.
#
# The stripper exits 3 rather than guess at a construct it cannot parse; that
# must fail this guard, never pass it.
TMPD=$(mktemp -d) || exit 2
trap 'rm -rf "$TMPD"' EXIT
strip_to() {
    if ! awk -f "$STRIP" "$1" > "$2" 2>"$TMPD/strip.err"; then
        echo "FAIL: the comment stripper refused $1 - this guard cannot report CLEAN."
        sed -e 's/^/      /' "$TMPD/strip.err"
        exit 1
    fi
}
strip_to "$HM" "$TMPD/hm"
strip_to "$HH" "$TMPD/hh"
strip_to "$CS" "$TMPD/cs"

# Flattened views. grep is line-based, so GetTip at end of line with its open
# paren on the next line reads as no call at all (mutant S8). Match on the
# joined text; report line numbers from the per-line view as a best effort.
flat() { tr '\n' ' ' < "$1"; }
count_re() { grep -oE "$1" | wc -l | tr -d ' '; }

# 1. GetTip() / GetBlockIndex() must not be CALLED in the headers manager. These
#    are the two accessors that RELEASE cs_main and hand back a pointer, so this
#    is the entry point for the whole released-pointer class; close it and the
#    class cannot appear in this translation unit at all.
CALL_RE='(GetTip|GetBlockIndex)[[:space:]]*\('
hits=$(( $(flat "$TMPD/hm" | count_re "$CALL_RE") + $(flat "$TMPD/hh" | count_re "$CALL_RE") ))
if [ "$hits" -ne 0 ]; then
    echo "FAIL: the headers manager CALLS GetTip()/GetBlockIndex() ($hits site(s))."
    echo "      GetTip() releases cs_main before returning, so the CBlockIndex*"
    echo "      it hands back can be freed by eviction at any time. Walking it"
    echo "      without cs_main is P2P-16, a peer-triggerable use-after-free."
    echo "      Use CChainState::ResolveLocatorHashes() - it returns VALUES."
    grep -nE "$CALL_RE" "$TMPD/hm" "$TMPD/hh" | head -5
    echo "      (nothing listed = the call is split across lines - see the flattened match)"
    fail=1
fi

# 2. No CBlockIndex ancestor/parent walk in this file. Even reached by some
#    other route, such a walk belongs under cs_main in chain.cpp, not here.
#    Whitespace around the arrow is legal C++, so "p ->  pprev" is the same walk
#    and must count (mutant S9). The trailing class stands in for a word
#    boundary: \b was silently written into this file once as a literal control
#    byte, which disabled the whole check while it still looked correct.
WALK_RE='(->|\.)[[:space:]]*(GetAncestor|pprev|pskip)([^A-Za-z0-9_]|$)'
walks=$(flat "$TMPD/hm" | count_re "$WALK_RE")
if [ "$walks" -ne 0 ]; then
    echo "FAIL: headers_manager.cpp walks a CBlockIndex ($walks site(s))."
    echo "      A chain walk must happen under cs_main, inside chain.cpp, and"
    echo "      leave as values. See CChainState::ResolveLocatorHashes()."
    grep -nE "$WALK_RE" "$TMPD/hm" | head -5
    fail=1
fi

# 3. GetLocatorImpl must keep taking VALUES. Reverting its parameter to a
#    CBlockIndex* is precisely the regression, and it would compile cleanly.
#    NOTE: the declaration spans three lines, and grep is line-based - an early
#    version looked only at single lines and reported the parameter missing on a
#    tree where it was present. Flatten first.
if flat "$TMPD/hh" | grep -qE 'GetLocatorImpl[^;]*CBlockIndex[[:space:]]*\*' \
   || flat "$TMPD/hm" | grep -qE 'GetLocatorImpl[^;)]*CBlockIndex[[:space:]]*\*'; then
    echo "FAIL: GetLocatorImpl takes a CBlockIndex* again."
    echo "      It must take resolved height->hash VALUES; a pointer parameter"
    echo "      re-opens P2P-16 with every test still green."
    fail=1
fi
if ! flat "$TMPD/hh" | grep -qE 'GetLocatorImpl[^;]*std::map<int,[[:space:]]*uint256>'; then
    echo "FAIL: GetLocatorImpl no longer declares the resolved-values parameter"
    echo "      in $HH - check this guard against the source before trusting it."
    fail=1
fi

# 4. The accessor this fix depends on must still return values, not the pointer
#    someone might restore "for efficiency".
# F4 (external review r2): this used to pin GetAncestorHashes, which the headers
# manager no longer calls - so reverting ResolveLocatorHashes to the
# probe-then-resolve shape passed the guard. Pin the accessor that is actually
# used, and pin its ONE-ACQUISITION property: exactly one lock_guard in its body.
if ! grep -qE 'std::vector<uint256>[[:space:]]+CChainState::ResolveLocatorHashes' "$TMPD/cs"; then
    echo "FAIL: CChainState::ResolveLocatorHashes is missing or no longer returns"
    echo "      std::vector<uint256>. The headers manager depends on it to get"
    echo "      chain data across a lock-free window without a pointer."
    fail=1
else
    guards=$(awk '/std::vector<uint256> CChainState::ResolveLocatorHashes/,/^}/' "$TMPD/cs" \
             | grep -cE 'lock_guard<std::recursive_mutex>')
    if [ "$guards" -ne 1 ]; then
        echo "FAIL: ResolveLocatorHashes holds cs_main $guards time(s), expected exactly 1."
        echo "      Its whole point is ONE acquisition: a probe-then-resolve shape lets"
        echo "      the tip move between the two, which is the false-coherence defect"
        echo "      this function was written to remove."
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: the released-pointer accessors are not called in the headers manager"
    echo "  - GetTip()/GetBlockIndex() never called in headers_manager.{cpp,h}"
    echo "  - no CBlockIndex ancestor/parent walk in that TU"
    echo "  - GetLocatorImpl still takes resolved values, not a CBlockIndex*"
    echo "  - ResolveLocatorHashes returns values and holds cs_main exactly once"
fi
exit "$fail"
