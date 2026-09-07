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
drains=$(grep -c "TipNotifyDrain drain(" "$CHAIN_CPP" 2>/dev/null)
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
drain_line=$(grep -n "TipNotifyDrain drain(" "$CHAIN_CPP" | head -1 | cut -d: -f1)
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

if [ "$fail" -eq 0 ]; then
    echo "PASS: tip-notification drain invariant holds"
    echo "  - NotifyTipUpdate confined to chain.cpp"
    echo "  - exactly one TipNotifyDrain, declared before the cs_main guard"
    echo "  - TipUpdateCallback passes values, not a CBlockIndex*"
fi
exit "$fail"
