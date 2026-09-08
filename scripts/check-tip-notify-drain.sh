#!/bin/bash
# P2P-14/15 structural guard: every NotifyTipUpdate must be drained.
#
# WHY THIS EXISTS, AND WHY IT IS NOT FOUR RUNTIME TESTS.
#
# The fix for the cs_main <-> cs_headers lock-order cycle is a single choke
# point: NotifyTipUpdate SNAPSHOTS into m_pendingTipNotifications under cs_main,
# and one TipNotifyDrain -- declared before the lock_guard in ActivateBestChain,
# so it destructs after it -- fires them with the lock released.
#
# All four call sites (Case 2, Case 2.5, Case 3, and the opt-in chain-selector
# path) funnel through that ONE queue and ONE drain. Driving all four at runtime
# would exercise the same mechanism four times; it would not test four things.
# What it would NOT catch is the failure that actually threatens this design:
#
#   someone adds a FIFTH NotifyTipUpdate call site, in a scope that has no
#   TipNotifyDrain. That notification is queued and never fired. A tip update is
#   silently dropped, the queue grows without bound, and nothing fails -- no
#   crash, no red test, just a consumer that quietly stops being told about new
#   tips.
#
# That is a structural property, so it gets a structural check. The runtime half
# is the growth canary in NotifyTipUpdate (chain.cpp), which makes the symptom
# loud if this guard is ever bypassed.
#
# Exit 0 = invariant holds. Exit 1 = it does not.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

CHAIN_CPP="src/consensus/chain.cpp"
fail=0

# 1. NotifyTipUpdate is called ONLY from chain.cpp. A call from another
#    translation unit cannot be covered by ActivateBestChain's drain.
outside=$(grep -rn "NotifyTipUpdate(" src/ --include=*.cpp --include=*.h 2>/dev/null \
          | grep -v "^src/consensus/chain.cpp:" \
          | grep -v "^src/consensus/chain.h:" \
          | grep -v "src/test/")
if [ -n "$outside" ]; then
    echo "FAIL: NotifyTipUpdate called outside chain.cpp — it cannot be drained there:"
    echo "$outside"
    fail=1
fi

# 2. Exactly ONE TipNotifyDrain instantiation. More than one means a second
#    drain point exists and this guard's reasoning no longer holds; zero means
#    the fix has been reverted and every notification leaks.
# ⚠️ TYPE-coupled, not NAME-coupled (confirmation-read MEDIUM-3, demonstrated).
#
# This used to be `grep -c "TipNotifyDrain drain("` — it counted only
# instantiations literally named `drain` and constructed with `(`. A reviewer
# mutation placed a SECOND drain named `d2` INSIDE a cs_main scope at
# chain.cpp:2018 — which fires the callbacks with cs_main HELD and restores the
# exact deadlock this branch removes — and this check printed
# "PASS: ... exactly one TipNotifyDrain". The guard's stated claim was not the
# property it enforced, in the line the branch itself calls the most fragile in
# the fix.
#
# Now matches any identifier and both `(` and `{` initialisation, so a second
# drain under any name is counted wherever it appears.
drains=$(grep -cE 'TipNotifyDrain[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[({]' "$CHAIN_CPP" 2>/dev/null)
if [ "$drains" -ne 1 ]; then
    echo "FAIL: expected exactly 1 TipNotifyDrain instantiation in $CHAIN_CPP, found $drains"
    echo "      (0 = fix reverted, notifications leak; >1 = re-verify the reasoning in this script)"
    fail=1
fi

# 3. The drain must be declared BEFORE the cs_main lock_guard in
#    ActivateBestChain. C++ destroys locals in reverse declaration order, so if
#    these two lines are swapped the drain fires while cs_main is still held and
#    the deadlock returns -- silently, with every test still green. This is the
#    single most fragile line in the fix.
drain_line=$(grep -nE "TipNotifyDrain[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[({]" "$CHAIN_CPP" | head -1 | cut -d: -f1)
abc_line=$(grep -n "bool CChainState::ActivateBestChain" "$CHAIN_CPP" | head -1 | cut -d: -f1)
if [ -n "$drain_line" ] && [ -n "$abc_line" ]; then
    guard_line=$(awk -v s="$abc_line" 'NR>s && /lock_guard<std::recursive_mutex> lock\(cs_main\)/ {print NR; exit}' "$CHAIN_CPP")
    if [ -z "$guard_line" ]; then
        echo "FAIL: could not locate ActivateBestChain's cs_main guard — check this script against the source"
        fail=1
    elif [ "$drain_line" -ge "$guard_line" ]; then
        echo "FAIL: TipNotifyDrain (line $drain_line) is declared AT OR AFTER the cs_main guard (line $guard_line)."
        echo "      Reverse-order destruction means the drain would fire with cs_main STILL HELD."
        echo "      That silently restores the deadlock while every test stays green. See P2P-14/15."
        fail=1
    fi
fi

# 4. The callback must not carry a CBlockIndex*. Reverting to a pointer
#    reintroduces the use-after-free (CBlockIndex objects are destroyed by
#    EvictLowestWorkNotOnBestChain, driven by the headers thread) and re-opens
#    the cycle the moment a consumer takes a lock.
if grep -q "using TipUpdateCallback = std::function<void(const CBlockIndex\*)>" src/consensus/chain.h 2>/dev/null; then
    echo "FAIL: TipUpdateCallback passes a CBlockIndex* again. It must pass VALUES."
    echo "      A pointer handed to a callback that runs after the lock is released is a UAF."
    fail=1
fi

# 5. THE CENSUS PREMISE: the three locks must stay PRIVATE with no friends.
#
#    docs/p2p14-lock-inversion/CENSUS_cs_headers_edges.md argues that every edge
#    into cs_headers is accounted for, and that argument is "complete by
#    construction" ONLY because cs_vNodes, cs_peers and cs_main are private
#    members with zero friend declarations — so only connman.cpp, peers.cpp and
#    chain.cpp can hold them, and no other translation unit can create an
#    inverted edge.
#
#    Add a `friend` or a public accessor returning one of these mutexes and the
#    census silently stops being complete: any TU could then hold the lock and
#    reach cs_headers, and nothing else in this repo would notice. That is the
#    failure this check exists for — the premise is load-bearing and invisible.
for hdr in src/net/connman.h src/net/peers.h src/consensus/chain.h; do
    if [ ! -f "$hdr" ]; then
        echo "FAIL: $hdr missing — census premise cannot be checked"
        fail=1
        continue
    fi
    # LOW-2: match `friend` ANYWHERE on the line — `public: friend class X;`
    # escaped the old ^\s*friend anchor (reviewer mutation M11).
    if grep -qE '(^|[[:space:]:{])friend[[:space:]]' "$hdr"; then
        echo "FAIL: $hdr introduces a 'friend' declaration."
        echo "      The cs_headers edge census is 'complete by construction' ONLY while"
        echo "      cs_vNodes / cs_peers / cs_main are unreachable outside their own class."
        echo "      A friend breaks that premise — re-run the census before proceeding."
        echo "      See docs/p2p14-lock-inversion/CENSUS_cs_headers_edges.md §1."
        fail=1
    fi
done

# A public accessor handing out one of the mutexes breaks the premise the same way.
# LOW-2: match BOTH `&` and `*`. A mutex handed out by POINTER escaped the
# original reference-only regex (reviewer mutation M12 survived it).
if grep -nE '(std::)?(recursive_)?mutex[[:space:]]*[&*][[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(' \
        src/net/connman.h src/net/peers.h src/consensus/chain.h 2>/dev/null; then
    echo "FAIL: a header above appears to expose a mutex by reference."
    echo "      Same premise break as a friend declaration — see CENSUS §1."
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: tip-notification drain invariant holds"
    echo "  - census premise intact: cs_vNodes / cs_peers / cs_main private, no friends, not exposed"
    echo "  - NotifyTipUpdate confined to chain.cpp"
    echo "  - exactly one TipNotifyDrain, declared before the cs_main guard"
    echo "  - TipUpdateCallback passes values, not a CBlockIndex*"
fi
exit "$fail"
