#!/bin/bash
# P2P-16 structural guard: the headers manager never CALLS a released-pointer
# accessor. Read "WHAT THIS PROVES" below before relying on it — the claim is
# deliberately narrower than the file name suggests.
#
# WHY THIS EXISTS.
#
# CChainState::GetTip() takes cs_main, reads pindexTip, and RELEASES cs_main
# before returning. The CBlockIndex it points at is owned by mapBlockIndex and
# can be destroyed by EvictLowestWorkLeafNotPinned at any moment afterwards.
#
# CHeadersManager used to call GetTip() and then walk the result
# (pTip->GetAncestor(height)) while holding cs_headers and NOT cs_main — a
# use-after-free an inbound peer could drive, since peers trigger locator
# construction. Both external cross-family seats on the merged P2P-14/15 diff
# found it independently (register P2P-16).
#
# The obvious repair is forbidden: taking cs_main under cs_headers is the exact
# lock-order inversion P2P-14/15 closed. So the fix moves the DATA out of the
# lock instead of the pointer — CChainState::ResolveLocatorHashes() resolves
# height->hash under cs_main and returns copies.
#
# That fix is one edit away from being undone, and undoing it would be SILENT:
# every test would still pass, because the failure needs an eviction to land
# inside a specific window. So the invariant gets a structural check.
#
# ==========================================================================
# WHAT THIS PROVES — a LEXICAL claim, measured against a mutant table
# ==========================================================================
#
# This is a TEXT MATCHER over stripped source. It proves things about how the
# file is SPELLED. It is not a type checker and it does not resolve names, so
# state the claim in those terms or it will be believed past its evidence -
# which this guard has already been corrected for twice.
#
# PROVEN (each row is a mutant that was compiled, applied to the real file and
# run against this guard - not a reading of the regexes):
#
#   S1  g_chainstate.GetTip() call                    CAUGHT
#   S2  g_chainstate.GetBlockIndex() call             CAUGHT  (added after MISS)
#   S6  alias via auto p = ...GetTip()                CAUGHT
#   S7  a real GetTip() call in headers_manager.h     CAUGHT
#   S4  p->GetAncestor(h) walk                        CAUGHT
#   S13 p->pprev walk                                 CAUGHT
#   S12 p->pskip walk                                 CAUGHT
#   S8  newline between GetTip and its open paren     CAUGHT  (added after MISS)
#   S9  whitespace after the arrow: p ->  pprev       CAUGHT  (added after MISS)
#   S10 a // inside a string literal, on a line that
#       also carries a real GetTip() call             CAUGHT  (added after MISS)
#   S11 inline block comment before the paren         CAUGHT  (added after MISS)
#   S14 C++14 digit separator (5'000) preceding a
#       real GetTip() call on the same line           CAUGHT  (added after MISS)
#   S22 a u8'a' char-literal prefix on a line that
#       also carries a real GetTip() call             CAUGHT  (added after MISS)
#   S18 qualified member: p->CBlockIndex::pprev       CAUGHT  (added after MISS)
#   S19 a CBlockIndex walk in the .h                  CAUGHT  (added after MISS)
#   S15 unterminated string literal                   REFUSED (guard fails closed)
#   S16 line-spliced token across a backslash         REFUSED (guard fails closed)
#   S20 a SECOND cs_main hold via unique_lock         CAUGHT  (added after MISS)
#
# NOT PROVEN — named, so nobody reads the PASS line as more than it is:
#
#   S3  a bare CBlockIndex* p declaration             MISSED
#   S5  a bare p->nHeight dereference                 MISSED
#   S17 a macro alias: #define TIP GetTip             MISSED
#   S21 pointer-to-member / std::invoke indirection   MISSED
#
# S3/S5/S17/S21 are the same shape: this guard matches TOKENS, and a pointer
# that arrives by parameter, member, macro expansion or indirect call is not
# spelled like a call to GetTip. Catching those needs a compiler front end, and
# a half-correct parser that reports CLEAN is worse than an honest narrow check.
#
# Two rows above are corrections of this guard's own history. S7 previously read
# CAUGHT on the strength of a DEFECTIVE mutant that appended a bare comment
# rather than a call, so it proved nothing. And S8-S11 were gaps an external
# reader predicted by READING this file; every one of them MISSED when run.
# S14 is the same class again, found by a third external round after this
# scanner was already written: C++14 digit separators are apostrophes, the
# scanner treated 5'000 as a char literal, blanked forward and swallowed a real
# call. S22 is the SAME class a THIRD time, found by the in-house read of the fix
# for S14: a u8'a' char-literal prefix reads as <hexdigit>'<hexdigit>, so the
# separator rule claimed it, the closing quote then opened a run, and
#     char c = u8'a'; auto* t = g_chainstate.GetTip(); int z = 1'000;
# came out with the call erased and exit 0.
#
# Three instances of one class, each found by a different reader, is the reason
# the scanner's default is now to REFUSE rather than to guess: every construct
# named below has an explicit rule or exits 3 - see
# scripts/strip-cxx-comments.awk.
#
# So, precisely:
#   (1) neither GetTip() nor GetBlockIndex() is CALLED BY NAME in
#       headers_manager.{cpp,h}, however the call is spelled or split across
#       lines - but not if the name reaches the call site through a macro or an
#       indirect call;
#   (2) no GetAncestor/pprev/pskip member access, qualified or not and with any
#       whitespace around the arrow, appears in EITHER file;
#   (3) GetLocatorImpl still declares resolved VALUES, not a CBlockIndex*;
#   (4) ResolveLocatorHashes exists and TRIPS if the number of textual cs_main
#       acquisitions in its body is not exactly one. Check 4 is a TRIPWIRE, not
#       a proof of single acquisition: it counts spellings (lock_guard,
#       unique_lock, scoped_lock, cs_main.lock(), std::lock) inside a
#       brace-counted body. A hold introduced by a helper it calls, or by a
#       spelling not in that list, is invisible to it.
#
# ON THE TWO ARMS, stated precisely because the weaker phrasing overclaims: the
# HIT arm of the resolved-value lookup is EXECUTED by the equivalence test in
# chain_tips_cache_invalidation_tests. The MISS arm — a pattern height at or
# below the chainstate tip that is absent from the resolved map — needs a gap in
# the pprev chain below the tip, which the eviction rules make unconstructible
# in production. So the miss arm is provably EQUIVALENT to the old
# "GetAncestor() returned nullptr" behaviour, not EXECUTED. Claiming "both arms
# verified" would be the stronger-sounding and weaker claim.
#
# Exit 0 = the lexical invariant holds. Exit 1 = it does not, or the scanner
# refused to parse the input.

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
# Checks 3 and 4 once did not strip at all, which is the opposite failure: a doc
# comment that gained the words "see the note in GetLocatorImpl" FAILED A CLEAN
# TREE. Every check reads stripped code now.
#
# The scanner exits 3 rather than guess at a construct it cannot tokenise; that
# must FAIL this guard, never pass it.
TMPD=$(mktemp -d) || exit 2
trap 'rm -rf "$TMPD"' EXIT
strip_to() {
    if ! awk -f "$STRIP" "$1" > "$2" 2>"$TMPD/strip.err"; then
        echo "FAIL: the comment scanner refused $1 - this guard cannot report CLEAN."
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

# 1. GetTip() / GetBlockIndex() must not be CALLED BY NAME in the headers
#    manager. These are the two accessors that RELEASE cs_main and hand back a
#    pointer, so this is the entry point for the whole released-pointer class.
#    A macro alias or an indirect call is NOT caught - see S17/S21 above.
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

# 2. No CBlockIndex ancestor/parent walk in EITHER file. An earlier version
#    scanned only the .cpp while the PASS line claimed "in that TU", so an
#    inline walk in the header passed (S19). Whitespace around the arrow is
#    legal C++ (S9), and so is an explicit qualifier - p->CBlockIndex::pprev
#    walked straight past the old pattern (S18). The trailing class stands in
#    for a word boundary: \b was once written into this file as a literal
#    control byte, which disabled the whole check while it still looked right.
WALK_RE='(->|\.)[[:space:]]*([A-Za-z_][A-Za-z0-9_]*[[:space:]]*::[[:space:]]*)*(GetAncestor|pprev|pskip)([^A-Za-z0-9_]|$)'
walks=$(( $(flat "$TMPD/hm" | count_re "$WALK_RE") + $(flat "$TMPD/hh" | count_re "$WALK_RE") ))
if [ "$walks" -ne 0 ]; then
    echo "FAIL: the headers manager walks a CBlockIndex ($walks site(s))."
    echo "      A chain walk must happen under cs_main, inside chain.cpp, and"
    echo "      leave as values. See CChainState::ResolveLocatorHashes()."
    grep -nE "$WALK_RE" "$TMPD/hm" "$TMPD/hh" | head -5
    fail=1
fi

# 3. GetLocatorImpl must keep taking VALUES. Reverting its parameter to a
#    CBlockIndex* is precisely the regression, and it would compile cleanly.
#    The declaration spans three lines and grep is line-based, so flatten first:
#    an early version looked only at single lines and reported the parameter
#    missing on a tree where it was present.
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

# 4. TRIPWIRE, not a proof. ResolveLocatorHashes must exist, and the number of
#    textual cs_main acquisitions in its body must be exactly one.
#
# F4 (external review r2): this once pinned GetAncestorHashes, which the headers
# manager no longer calls, so reverting ResolveLocatorHashes to the
# probe-then-resolve shape PASSED. It now pins the accessor actually used.
#
# G3 (external review r3): it also counted LINES matching a single spelling
# (lock_guard) inside an awk range ending at the first column-0 brace. That had
# both failure directions - a second hold taken with unique_lock or
# cs_main.lock() was invisible (FALSE PASS, mutant S20), and rewriting the one
# guard as a unique_lock counted zero (FALSE FAIL). Now: brace-counted body, and
# every acquisition spelling counted.
#
# What it still cannot see: a hold taken inside a helper this function calls, a
# macro-wrapped lock, or any spelling not listed. It is a tripwire on the shape
# of THIS function body, and the PASS line says so.
body_file="$TMPD/rlh_body"
awk '
    /std::vector<uint256> CChainState::ResolveLocatorHashes/ { inf = 1 }
    inf {
        print
        n = gsub(/\{/, "{"); m = gsub(/\}/, "}")
        depth += n - m
        if (started && depth <= 0) exit
        if (n > 0) started = 1
    }
' "$TMPD/cs" > "$body_file"

if ! grep -qE 'std::vector<uint256>[[:space:]]+CChainState::ResolveLocatorHashes' "$TMPD/cs"; then
    echo "FAIL: CChainState::ResolveLocatorHashes is missing or no longer returns"
    echo "      std::vector<uint256>. The headers manager depends on it to get"
    echo "      chain data across a lock-free window without a pointer."
    fail=1
elif [ ! -s "$body_file" ]; then
    echo "FAIL: could not extract the ResolveLocatorHashes body - this guard"
    echo "      cannot report CLEAN on a function it did not read."
    fail=1
else
    ACQ_RE='(lock_guard|unique_lock|scoped_lock)[^;]*\([[:space:]]*cs_main|cs_main[[:space:]]*\.[[:space:]]*lock[[:space:]]*\(|std::lock[[:space:]]*\([^;]*cs_main'
    acq=$(flat "$body_file" | count_re "$ACQ_RE")
    if [ "$acq" -ne 1 ]; then
        echo "FAIL: ResolveLocatorHashes takes cs_main $acq time(s) textually, expected exactly 1."
        echo "      Its whole point is ONE acquisition: a probe-then-resolve shape lets"
        echo "      the tip move between the two, which is the false-coherence defect"
        echo "      this function was written to remove."
        flat "$body_file" | grep -oE "$ACQ_RE" | head -5
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: the released-pointer accessors are not called by name in the headers manager"
    echo "  - GetTip()/GetBlockIndex() never called BY NAME in headers_manager.{cpp,h}"
    echo "    (a macro alias or an indirect call would not be seen - see S17/S21)"
    echo "  - no GetAncestor/pprev/pskip member access in either file"
    echo "  - GetLocatorImpl still takes resolved values, not a CBlockIndex*"
    echo "  - ResolveLocatorHashes body shows exactly one textual cs_main acquisition"
fi
exit "$fail"
