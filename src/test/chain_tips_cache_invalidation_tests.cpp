// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// GetChainTips() STALE-CACHE DEFENCE
// ==================================
//
// CChainState::GetChainTips() is memoised behind `m_chainTipsCacheDirty`
// (perf fix 2026-07-12: the recompute was 44% of sampled CPU on a DilV seed
// with a 161K-entry mapBlockIndex). Correctness of that cache rests entirely
// on 14 invalidation sites — 12 in consensus/chain.cpp, 2 in consensus/chain.h.
//
// A mutation run showed every one of those 14 sites was UNDEFENDED: deleting
// any single `m_chainTipsCacheDirty = true;` — and even deleting ALL FOURTEEN
// at once — left getchaintips_equivalence_tests, chain_selector_tests and
// competing_sibling_below_checkpoint_tests fully green.
//
// The structural reason is that the flag initialises to `true`, and every
// pre-existing test builds a fresh CChainState, mutates it, and then calls
// GetChainTips() EXACTLY ONCE. A cache that is never re-read cannot be
// observed to be stale, whatever you delete.
//
// This suite is the missing shape:  call -> mutate -> call again -> assert the
// second answer CHANGED.  Each case targets exactly one invalidation site, so
// deleting that one site turns exactly that one case red.
//
// Impact of the underlying bug is a stale `getchaintips` RPC — explorers and
// operators shown a wrong fork/reorg picture — not consensus. Hence tests, not
// a redesign.
//
// SITE COVERAGE (site -> case):
//   chain.cpp:67    Cleanup()                         -> cleanup_*
//   chain.cpp:157   AddBlockIndex (flag-merge path)   -> add_block_index_merge_*
//   chain.cpp:181   AddBlockIndex (first-time add)    -> add_block_index_new_*
//   chain.cpp:463   EvictLowestWorkLeafNotPinned()    -> evict_*
//   chain.cpp:2692  SetTip()                          -> set_tip_*
//   chain.cpp:3048  MarkBlockAsFailed()               -> mark_failed_*
//   chain.cpp:3086  MarkBlockAsValid()                -> mark_valid_*
//   chain.h:591     SetTipForTest()                   -> set_tip_for_test_*
//   chain.h:911     InvalidateChainTipsCache()        -> explicit_invalidate_*
//
// The remaining 5 sites (chain.cpp:587 ActivateBestChain, :2180 DisconnectTip,
// :2346 DisconnectToHeight, :3225 FindMostWorkChainImpl, :3281
// ActivateBestChainStep) sit on paths that need a live CBlockchainDB and real
// blocks; they are not reachable from a unit fixture. They remain covered only
// collectively (an all-sites deletion is killed by every case here).
//
// NOTE: every line number above was re-measured against THIS tree. The merge
// that brought the leaf-only eviction fix in shifted chain.cpp by ~350 lines,
// so the original table pointed at unrelated code. One ATTRIBUTION also
// changed, not just an offset: the 5th uncovered site is the dirty-flip inside
// FindMostWorkChainImpl, not an 'InvalidateBlock descendant walk'.
// InvalidateBlockImpl (chain.cpp:3655) has no invalidation of its own — it
// reaches the cache through MarkBlockAsFailed(), which mark_failed_* already
// covers, so the 14-site total and this suite's coverage are both unchanged.

#include <boost/test/unit_test.hpp>

#include <consensus/chain.h>
#include <node/block_index.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::unique_ptr<CBlockIndex> MakeIndex(uint8_t hash_seed,
                                       CBlockIndex* parent,
                                       int height,
                                       uint32_t status,
                                       uint8_t work_seed)
{
    auto pindex = std::make_unique<CBlockIndex>();
    pindex->pprev = parent;
    pindex->nHeight = height;
    pindex->nStatus = status;
    pindex->nSequenceId = static_cast<uint32_t>(hash_seed);

    std::memset(pindex->phashBlock.data, 0, 32);
    pindex->phashBlock.data[0] = hash_seed;

    std::memset(pindex->nChainWork.data, 0, 32);
    pindex->nChainWork.data[0] = work_seed;

    return pindex;
}

// Total-order rendering of a GetChainTips() answer. GetChainTips() sorts by
// (active-first, height desc) which is not a strict weak ordering across equal
// heights, so the vector order for same-height siblings is unspecified —
// render into a sorted multiset-of-strings so the comparison is order-stable
// and any real difference (membership, status, branchlen) still shows up.
std::string RenderTips(const std::vector<CChainState::ChainTip>& tips)
{
    std::vector<std::string> lines;
    lines.reserve(tips.size());
    for (const auto& t : tips) {
        std::ostringstream os;
        os << "h=" << t.height
           << " hash=" << t.hash.GetHex()
           << " status=" << t.status
           << " branchlen=" << t.branchlen;
        lines.push_back(os.str());
    }
    std::sort(lines.begin(), lines.end());
    std::ostringstream out;
    for (const auto& l : lines) out << l << "\n";
    return out.str();
}

std::string Tips(const CChainState& chainstate)
{
    return RenderTips(chainstate.GetChainTips());
}

// Fixture: genesis A, two children B and C, active tip = B.
//   GetChainTips() => B "active" (branchlen 0), C "valid-fork" (branchlen 1).
struct ForkFixture {
    CChainState chainstate;
    uint256 hA, hB, hC;
    CBlockIndex *A = nullptr, *B = nullptr, *C = nullptr;

    ForkFixture()
    {
        auto pA = MakeIndex(0x01, nullptr, 0, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1);
        hA = pA->GetBlockHash();
        BOOST_REQUIRE(chainstate.AddBlockIndex(hA, std::move(pA)));
        A = chainstate.GetBlockIndex(hA);
        BOOST_REQUIRE(A != nullptr);

        auto pB = MakeIndex(0x02, A, 1, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20);
        hB = pB->GetBlockHash();
        BOOST_REQUIRE(chainstate.AddBlockIndex(hB, std::move(pB)));
        B = chainstate.GetBlockIndex(hB);
        BOOST_REQUIRE(B != nullptr);

        // C carries LESS work than B so it is the unambiguous eviction victim.
        auto pC = MakeIndex(0x03, A, 1, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10);
        hC = pC->GetBlockHash();
        BOOST_REQUIRE(chainstate.AddBlockIndex(hC, std::move(pC)));
        C = chainstate.GetBlockIndex(hC);
        BOOST_REQUIRE(C != nullptr);

        chainstate.SetTip(B);
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(chain_tips_cache_invalidation_tests)

// ---------------------------------------------------------------------------
// Guard 0: the fixture itself must produce the two-tip picture the cases below
// assume. If this drifts, every "changed" assertion below could pass for the
// wrong reason.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(fixture_baseline_is_two_tips)
{
    ForkFixture f;
    auto tips = f.chainstate.GetChainTips();
    BOOST_REQUIRE_EQUAL(tips.size(), 2u);

    bool sawActiveB = false, sawForkC = false;
    for (const auto& t : tips) {
        if (t.hash == f.hB) { sawActiveB = (t.status == "active"); }
        if (t.hash == f.hC) { sawForkC   = (t.status == "valid-fork"); }
    }
    BOOST_CHECK(sawActiveB);
    BOOST_CHECK(sawForkC);

    // And the cache must be transparent: two back-to-back calls with NO
    // mutation in between agree. (This is the half the old tests did cover;
    // it is here so a "just always recompute" regression is still described.)
    BOOST_CHECK_EQUAL(Tips(f.chainstate), Tips(f.chainstate));
}

// ---------------------------------------------------------------------------
// chain.cpp:181 — AddBlockIndex, first-time add.
// Adding D under C makes D a tip and un-tips C.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(add_block_index_new_entry_invalidates_cache)
{
    ForkFixture f;
    const std::string before = Tips(f.chainstate);   // populates the cache

    auto pD = MakeIndex(0x04, f.C, 2, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 30);
    uint256 hD = pD->GetBlockHash();
    BOOST_REQUIRE(f.chainstate.AddBlockIndex(hD, std::move(pD)));

    const std::string after = Tips(f.chainstate);
    BOOST_CHECK_MESSAGE(before != after,
        "GetChainTips() served a STALE cache after AddBlockIndex added a new "
        "tip D and un-tipped its parent C. Answer both before and after:\n" + before);

    // Positive shape check, so this cannot pass on an unrelated difference.
    BOOST_CHECK(after.find(hD.GetHex()) != std::string::npos);
    BOOST_CHECK(after.find(f.hC.GetHex()) == std::string::npos);
}

// ---------------------------------------------------------------------------
// chain.cpp:157 — AddBlockIndex, flag-merge path (hash already present).
// Re-adding C with BLOCK_FAILED_VALID ORs the bit in: C's reported tip status
// must move "valid-fork" -> "invalid".
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(add_block_index_merge_invalidates_cache)
{
    ForkFixture f;
    const std::string before = Tips(f.chainstate);
    BOOST_REQUIRE(before.find("status=valid-fork") != std::string::npos);

    auto pC2 = MakeIndex(0x03, f.A, 1,
                         CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                             CBlockIndex::BLOCK_FAILED_VALID,
                         10);
    BOOST_REQUIRE(f.chainstate.AddBlockIndex(f.hC, std::move(pC2)));
    BOOST_REQUIRE(f.C->IsInvalid());   // the merge really happened

    const std::string after = Tips(f.chainstate);
    BOOST_CHECK_MESSAGE(before != after,
        "GetChainTips() served a STALE cache after an AddBlockIndex flag-merge "
        "turned tip C invalid. Answer both before and after:\n" + before);
    BOOST_CHECK(after.find("status=invalid") != std::string::npos);
}

// ---------------------------------------------------------------------------
// chain.cpp:463 — EvictLowestWorkLeafNotPinned(): erases a tip outright.
//
// The eviction API was RENAMED and RE-SIGNATURED by the leaf-only cap fix
// (was: EvictLowestWorkNotOnBestChain(), no arguments, 'lowest-work entry not
// on the best chain'). The policy this case now drives is strictly narrower:
// it frees ONLY UNPINNED LEAVES — in-degree 0 in the pprev graph — lowest
// nChainWork first, multi-pass, until mapBlockIndex.size() <= target_max.
// PINNED (never evicted) are: (a) every ancestor of pindexTip; (b) every
// m_setBlockIndexCandidates member and all of its pprev ancestors; (c) every
// entry with BLOCK_HAVE_DATA that has not yet reached BLOCK_VALID_TRANSACTIONS;
// (d) every hash the pending-block provider reports, plus its ancestors.
//
// Why ForkFixture still drives a REAL eviction under that policy — this is
// what keeps the BOOST_REQUIRE below reachable instead of vacuously red:
//   * A is INTERIOR (in-degree 2: B and C both name it as pprev) — not a leaf.
//   * B is a leaf but is PINNED by clause (a): SetTip(B) makes it pindexTip.
//   * C is a leaf (nothing names it as pprev) and is pinned by NOTHING.
//     m_setBlockIndexCandidates is empty in this fixture: the only add-path
//     writer is ActivateBestChain (chain.cpp:739), which the fixture never
//     calls — AddBlockIndex and SetTip do not touch the candidate set, so
//     clause (b) pins nothing. C's nStatus is BLOCK_VALID_TRANSACTIONS with no
//     BLOCK_HAVE_DATA, so clause (c) does not match. No pending-block provider
//     is installed, so clause (d) is inert. C also carries LESS work than B,
//     so it is the lowest-work eligible leaf.
// C is therefore the unique eviction victim, exactly as it was under the old
// policy — the SCENARIO (erasing a fork tip must invalidate the memoised
// tip set) is preserved, not weakened to fit the new signature.
//
// target_max follows the production call pattern used by the sibling wiring
// test (headers_manager_to_chain_selector_wiring_tests.cpp:407): size_before-1,
// i.e. 'make room for exactly one new header'. That bounds the run to a single
// eviction, so the assertions below describe one specific erasure rather than a
// drain. (target_max == 0 means 'drain EVERY eligible leaf' — explicitly
// test/diagnostic-only per the contract in chain.h, and it would not pin down
// WHICH entries went.)
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(evict_invalidates_cache)
{
    ForkFixture f;
    const std::string before = Tips(f.chainstate);
    BOOST_REQUIRE(before.find(f.hC.GetHex()) != std::string::npos);

    const size_t size_before = f.chainstate.GetBlockIndexSize();
    BOOST_REQUIRE_EQUAL(size_before, 3u);  // A + B + C

    BOOST_REQUIRE(f.chainstate.EvictLowestWorkLeafNotPinned(size_before - 1));
    BOOST_REQUIRE_EQUAL(f.chainstate.GetBlockIndexSize(), size_before - 1);
    BOOST_REQUIRE(f.chainstate.GetBlockIndex(f.hC) == nullptr);  // C really went

    // The pinned entries survived: the policy evicted the unpinned LEAF, not
    // merely 'the lowest-work entry'. If either of these ever fires, this case
    // is no longer exercising the scenario its comment claims.
    BOOST_REQUIRE(f.chainstate.GetBlockIndex(f.hB) != nullptr);  // active tip, pinned (a)
    BOOST_REQUIRE(f.chainstate.GetBlockIndex(f.hA) != nullptr);  // interior, in-degree 2

    const std::string after = Tips(f.chainstate);
    BOOST_CHECK_MESSAGE(before != after,
        "GetChainTips() served a STALE cache after EvictLowestWorkLeafNotPinned() "
        "erased unpinned leaf tip C. Answer both before and after:\n" + before);
    BOOST_CHECK(after.find(f.hC.GetHex()) == std::string::npos);
}

// ---------------------------------------------------------------------------
// chain.cpp:2336 — SetTip(): which tip is "active" is derived from pindexTip
// alone, with no mapBlockIndex membership change at all.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(set_tip_invalidates_cache)
{
    ForkFixture f;
    const std::string before = Tips(f.chainstate);

    f.chainstate.SetTip(f.C);

    const std::string after = Tips(f.chainstate);
    BOOST_CHECK_MESSAGE(before != after,
        "GetChainTips() served a STALE cache after SetTip() moved the active "
        "tip from B to C. Answer both before and after:\n" + before);

    // C must now be the active one.
    for (const auto& t : f.chainstate.GetChainTips()) {
        if (t.hash == f.hC) BOOST_CHECK_EQUAL(t.status, "active");
        if (t.hash == f.hB) BOOST_CHECK(t.status != "active");
    }
}

// ---------------------------------------------------------------------------
// chain.h:573 — SetTipForTest(): the test-only tip setter carries its own
// copy of the invalidation and must keep it.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(set_tip_for_test_invalidates_cache)
{
    ForkFixture f;
    const std::string before = Tips(f.chainstate);

    f.chainstate.SetTipForTest(f.C);

    const std::string after = Tips(f.chainstate);
    BOOST_CHECK_MESSAGE(before != after,
        "GetChainTips() served a STALE cache after SetTipForTest() moved the "
        "active tip from B to C. Answer both before and after:\n" + before);
}

// ---------------------------------------------------------------------------
// chain.cpp:2684 — MarkBlockAsFailed(): flips nStatus on an already-indexed
// entry, outside AddBlockIndex's hook.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mark_block_as_failed_invalidates_cache)
{
    ForkFixture f;
    const std::string before = Tips(f.chainstate);
    BOOST_REQUIRE(before.find("status=valid-fork") != std::string::npos);

    f.chainstate.MarkBlockAsFailed(f.C);
    BOOST_REQUIRE(f.C->IsInvalid());

    const std::string after = Tips(f.chainstate);
    BOOST_CHECK_MESSAGE(before != after,
        "GetChainTips() served a STALE cache after MarkBlockAsFailed(C). "
        "Answer both before and after:\n" + before);
    BOOST_CHECK(after.find("status=invalid") != std::string::npos);
}

// ---------------------------------------------------------------------------
// chain.cpp:2722 — MarkBlockAsValid(): the reconsider direction.
// The cache is populated on the ALREADY-FAILED picture, so only
// MarkBlockAsValid's own invalidation can clear it.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mark_block_as_valid_invalidates_cache)
{
    ForkFixture f;
    f.chainstate.MarkBlockAsFailed(f.C);

    const std::string before = Tips(f.chainstate);   // caches the "invalid" picture
    BOOST_REQUIRE(before.find("status=invalid") != std::string::npos);

    f.chainstate.MarkBlockAsValid(f.C);
    BOOST_REQUIRE(!f.C->IsInvalid());

    const std::string after = Tips(f.chainstate);
    BOOST_CHECK_MESSAGE(before != after,
        "GetChainTips() served a STALE cache after MarkBlockAsValid(C) "
        "reconsidered the block. Answer both before and after:\n" + before);
    BOOST_CHECK(after.find("status=valid-fork") != std::string::npos);
}

// ---------------------------------------------------------------------------
// chain.h:759 — InvalidateChainTipsCache(): the escape hatch for code that
// mutates an indexed CBlockIndex directly. Mutate nStatus behind the
// chainstate's back, then call it; the next answer must reflect the change.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(explicit_invalidate_chain_tips_cache_works)
{
    ForkFixture f;
    const std::string before = Tips(f.chainstate);
    BOOST_REQUIRE(before.find("status=valid-fork") != std::string::npos);

    // Direct mutation — deliberately bypasses every internal hook.
    f.C->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;

    // Sanity: without the escape hatch the cache is (correctly) still stale.
    BOOST_CHECK_EQUAL(Tips(f.chainstate), before);

    f.chainstate.InvalidateChainTipsCache();

    const std::string after = Tips(f.chainstate);
    BOOST_CHECK_MESSAGE(before != after,
        "InvalidateChainTipsCache() did not force a recompute. "
        "Answer both before and after:\n" + before);
    BOOST_CHECK(after.find("status=invalid") != std::string::npos);
}

// ---------------------------------------------------------------------------
// chain.cpp:67 — Cleanup(): clears mapBlockIndex and nulls pindexTip.
// A stale cache here would report tips for blocks that have been destroyed.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(cleanup_invalidates_cache)
{
    ForkFixture f;
    const std::string before = Tips(f.chainstate);
    BOOST_REQUIRE(!before.empty());

    f.chainstate.Cleanup();

    const std::string after = Tips(f.chainstate);
    BOOST_CHECK_MESSAGE(after.empty(),
        "GetChainTips() served a STALE cache after Cleanup() — it reported tips "
        "for CBlockIndex objects that no longer exist:\n" + after);
    BOOST_CHECK(before != after);
}

BOOST_AUTO_TEST_SUITE_END()
