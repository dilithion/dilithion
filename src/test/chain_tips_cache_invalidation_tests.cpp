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
#include <net/headers_manager.h>   // PR #194 regression test: GetLocatorImplForTest

extern CChainState g_chainstate;   // defined in src/core/globals.cpp
#include <core/chainparams.h>

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


// ============================================================================
// P2P-16: CChainState::GetAncestorHashes equivalence.
//
// The locator path used to do pTip->GetAncestor(height)->GetBlockHash() on a
// pointer from GetTip(), which releases cs_main before returning — so the walk
// ran while the header thread could evict that CBlockIndex. The repair resolves
// the same question under cs_main and returns VALUES.
//
// That repair is only correct if the values are the SAME values. Nothing else in
// the P2P-16 diff pins that: an off-by-one or a reordered result would hand peers
// a wrong locator and still pass the build, the structural guard, and every
// existing suite. So assert the new API against the walk it replaced, on the same
// chainstate, plus the edges.
//
// A chain deeper than the fork fixture is built here so "order is preserved" and
// "out of range" are distinguishable rather than degenerate.
// ============================================================================
BOOST_AUTO_TEST_CASE(p2p16_get_ancestor_hashes_matches_the_walk_it_replaced)
{
    CChainState chainstate;

    // A linear chain 0..5, each block more work than the last.
    std::vector<uint256> hashes;
    CBlockIndex* prev = nullptr;
    for (int h = 0; h <= 5; ++h) {
        auto p = MakeIndex(static_cast<uint8_t>(0x10 + h), prev, h,
                           CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10 * (h + 1));
        const uint256 hash = p->GetBlockHash();
        BOOST_REQUIRE(chainstate.AddBlockIndex(hash, std::move(p)));
        prev = chainstate.GetBlockIndex(hash);
        BOOST_REQUIRE(prev != nullptr);
        hashes.push_back(hash);
    }
    chainstate.SetTip(prev);

    // --- EQUIVALENCE: the new API vs the old pointer walk, same heights. ---
    const std::vector<int> heights{5, 4, 3, 2, 1, 0};
    const std::vector<uint256> got = chainstate.GetAncestorHashes(heights);
    BOOST_REQUIRE_EQUAL(got.size(), heights.size());

    CBlockIndex* tip = chainstate.GetTip();
    BOOST_REQUIRE(tip != nullptr);
    for (size_t i = 0; i < heights.size(); ++i) {
        CBlockIndex* viaWalk = tip->GetAncestor(heights[i]);
        BOOST_REQUIRE_MESSAGE(viaWalk != nullptr, "fixture: no ancestor at height " << heights[i]);
        BOOST_CHECK_MESSAGE(got[i] == viaWalk->GetBlockHash(),
            "GetAncestorHashes disagrees with GetAncestor()->GetBlockHash() at height "
            << heights[i] << " (index " << i << ") — a wrong locator would ship silently");
    }

    // --- ORDER IS PRESERVED, not merely "the right set". A locator is ordered;
    // returning the same hashes in a different order would pass a set comparison
    // and still be wrong on the wire. Ascending input must come back ascending.
    const std::vector<int> ascending{0, 1, 2, 3, 4, 5};
    const std::vector<uint256> asc = chainstate.GetAncestorHashes(ascending);
    BOOST_REQUIRE_EQUAL(asc.size(), ascending.size());
    for (size_t i = 0; i < ascending.size(); ++i) {
        BOOST_CHECK_MESSAGE(asc[i] == hashes[ascending[i]],
            "order not preserved at index " << i);
    }

    // --- EDGES. Each must behave exactly as GetAncestor() returning nullptr did:
    // a null hash, never a throw and never a neighbouring height's hash.
    const std::vector<int> edges{6, 99, -1, 0};
    const std::vector<uint256> e = chainstate.GetAncestorHashes(edges);
    BOOST_REQUIRE_EQUAL(e.size(), edges.size());
    BOOST_CHECK_MESSAGE(e[0].IsNull(), "height above the tip must be null, not clamped to the tip");
    BOOST_CHECK_MESSAGE(e[1].IsNull(), "far above the tip must be null");
    BOOST_CHECK_MESSAGE(e[2].IsNull(), "negative height must be null, not genesis");
    BOOST_CHECK_MESSAGE(e[3] == hashes[0], "genesis must still resolve alongside invalid entries");

    // --- EMPTY INPUT: empty out, no crash. The locator helper can legitimately
    // produce an empty height list (startHeight <= 0).
    BOOST_CHECK(chainstate.GetAncestorHashes({}).empty());
}


// ============================================================================
// PR #194 external review, convergent HIGH: the locator must not silently drop
// entries when the header height ADVANCES between the prefetch and the walk.
//
// The defect: GetLocator peeked the headers height, resolved the chainstate
// hashes against the pattern from that start, then GetLocatorImpl RE-DERIVED the
// start under cs_headers and walked its own loop. Any advance in between made
// the two walks visit different heights, so every lookup below the chainstate
// tip missed and those entries vanished from the locator — on every advancing
// batch during IBD, silently, with no error path.
//
// This pins the invariant that makes that impossible: the walk visits exactly
// the heights the pattern names for the start it was GIVEN. If someone
// re-introduces a second derivation, the two walks diverge and this goes red.
// ============================================================================
BOOST_AUTO_TEST_CASE(p2p16_locator_pattern_is_one_walk_not_two)
{
    // The schedule is deterministic: 10 linear steps, then doubling, and every
    // height it names must be <= the start and strictly descending.
    for (int start : {0, 1, 9, 10, 11, 50, 1000, 250000}) {
        const std::vector<int> pattern = hdrtest::LocatorHeightPatternForTest(start);

        if (start == 0) {
            BOOST_REQUIRE_MESSAGE(pattern.size() == 1 && pattern[0] == 0,
                "a genesis-only chain (start 0) must still yield the genesis entry, got "
                << pattern.size() << " entries");
            continue;
        }

        BOOST_REQUIRE_MESSAGE(!pattern.empty(), "empty pattern for start " << start);
        BOOST_CHECK_EQUAL(pattern.front(), start);
        // NOT asserted: "reaches genesis". The schedule caps at 64 heights and
        // the walk caps at 32 ENTRIES, so terminating above 0 is the contract,
        // not a defect. My first version asserted my expectation instead of the
        // contract and went red on a correct tree.
        BOOST_CHECK_MESSAGE(pattern.size() <= 64,
            "the schedule must stay within its cap for start " << start
            << ", got " << pattern.size());

        for (size_t i = 1; i < pattern.size(); ++i) {
            BOOST_REQUIRE_MESSAGE(pattern[i] < pattern[i - 1],
                "pattern must strictly descend (start " << start << ", index " << i << ")");
            BOOST_REQUIRE_MESSAGE(pattern[i] >= 0,
                "pattern must not go below genesis (start " << start << ")");
        }
    }

    // ---- THE WIRING, which is the actual defect. ----
    //
    // My first version of this test asserted properties of the height schedule
    // alone. Its RED arm SURVIVED: mutating the call site inside GetLocatorImpl
    // (walk from startHeight + 7) left a pure-function test completely unmoved.
    // A test that cannot see the defect is not a regression test, so this one
    // goes through the real code path instead.
    //
    // Construction: resolve a map for start S, then ask the walk to run with
    // start S. Every chainstate-side entry it emits must come from that map. If
    // the walk consumes a DIFFERENT start — which is what the bug did, by
    // re-deriving it under cs_headers — it looks up heights the map never
    // resolved, those lookups miss, and the entries are silently dropped.
    // CHeadersManager reaches chainparams during construction/use.
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    }
    CHeadersManager mgr;
    const int kStart = 1000;
    const int kChainstateHeight = 1000;

    std::map<int, uint256> resolved;
    for (int h : hdrtest::LocatorHeightPatternForTest(kStart)) {
        if (h <= kChainstateHeight) {
            uint256 fake;
            fake.data[0] = static_cast<uint8_t>(h & 0xff);
            fake.data[1] = static_cast<uint8_t>((h >> 8) & 0xff);
            fake.data[31] = 0x7f;                 // never null
            resolved[h] = fake;
        }
    }
    BOOST_REQUIRE(!resolved.empty());

    const std::vector<uint256> loc =
        mgr.GetLocatorImplForTest(uint256(), kStart, resolved, kChainstateHeight);

    BOOST_CHECK_MESSAGE(!loc.empty(),
        "the walk produced NO entries from a fully-resolved map — it is not using "
        "the start it was given");

    // Every emitted entry must be one we resolved. A walk on a different start
    // would either drop entries (shorter) or emit something we never supplied.
    size_t fromMap = 0;
    for (const uint256& e : loc) {
        for (const auto& kv : resolved) {
            if (kv.second == e) { ++fromMap; break; }
        }
    }
    BOOST_CHECK_MESSAGE(fromMap == loc.size(),
        "every chainstate-side locator entry must come from the resolved map; "
        << (loc.size() - fromMap) << " of " << loc.size() << " did not — the walk "
        "and the resolver disagree about the start");

    BOOST_CHECK_MESSAGE(loc.size() == resolved.size(),
        "the walk emitted " << loc.size() << " entries from a map of "
        << resolved.size() << " fully-resolved heights — a shortfall is exactly "
        "the silent dropped-entry bug (walk start != resolve start)");
}


// ============================================================================
// PR #194 LOW fold: the RESOLVER arm.
//
// The two cases above pin the height schedule and the WALK. Neither one ever
// enters the resolver, so the half of the fix that actually holds cs_main was
// unexercised: ResolveLocatorHashes could have been reverted to the
// probe-then-resolve shape, or had its single descending walk broken, with both
// existing cases still green.
//
// SCOPE, stated rather than implied. This targets CChainState::ResolveLocatorHashes,
// not CHeadersManager::ResolveChainstateHashes. The wrapper reads the GLOBAL
// g_chainstate, and every case in this file builds a LOCAL CChainState on
// purpose; populating the global to reach the wrapper would leak fixture state
// into every other suite in this binary. So what stays unpinned here is the
// wrapper's own three behaviours - the F3 tip mapping (-1 to 0), the
// size-mismatch degradation, and dropping null hashes - and they are unpinned
// deliberately, not by oversight.
//
// The load-bearing property is EQUIVALENCE. Up-to-64 independent GetAncestor()
// calls were replaced with ONE descending pprev walk, after GetAncestor turned
// out to be linear here (pskip is inert), so 64 calls under cs_main would have
// moved real work into the lock. An optimisation is only allowed if it returns
// identical answers, and nothing else in this diff checks that.
// ============================================================================
BOOST_AUTO_TEST_CASE(p2p16_resolver_one_walk_equals_many_getancestor_calls)
{
    CChainState chainstate;

    // Deep enough that the schedule leaves the linear phase and starts doubling,
    // so the descending walk has to skip over heights rather than step one back.
    const int kTipHeight = 40;
    std::vector<uint256> hashes;
    CBlockIndex* prev = nullptr;
    for (int h = 0; h <= kTipHeight; ++h) {
        auto p = MakeIndex(static_cast<uint8_t>(0x40 + (h & 0x3f)), prev, h,
                           CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10 * (h + 1));
        const uint256 hash = p->GetBlockHash();
        BOOST_REQUIRE(chainstate.AddBlockIndex(hash, std::move(p)));
        prev = chainstate.GetBlockIndex(hash);
        BOOST_REQUIRE(prev != nullptr);
        hashes.push_back(hash);
    }
    chainstate.SetTip(prev);

    std::vector<int> heights;
    int tipHeight = -99;
    const std::vector<uint256> got =
        chainstate.ResolveLocatorHashes(0, &hdrtest::LocatorHeightPatternForTest,
                                        heights, tipHeight);

    BOOST_CHECK_EQUAL(tipHeight, kTipHeight);
    BOOST_REQUIRE_EQUAL(got.size(), heights.size());
    BOOST_REQUIRE_MESSAGE(!heights.empty(), "resolver returned nothing for a 40-block chain");

    // 1. EQUIVALENCE with the walk it replaced: one descending pass must agree
    //    with an independent GetAncestor() per height, hash for hash.
    CBlockIndex* tip = chainstate.GetTip();
    BOOST_REQUIRE(tip != nullptr);
    for (size_t i = 0; i < heights.size(); ++i) {
        CBlockIndex* viaWalk = tip->GetAncestor(heights[i]);
        BOOST_REQUIRE_MESSAGE(viaWalk != nullptr,
            "fixture: no ancestor at height " << heights[i]);
        BOOST_CHECK_MESSAGE(got[i] == viaWalk->GetBlockHash(),
            "single-walk resolver disagrees with GetAncestor() at height "
            << heights[i] << " (index " << i << ") - the optimisation changed answers");
    }

    // 2. The walk consumes the SCHEDULE, in order, descending. The single-pass
    //    implementation only works because the heights are sorted descending
    //    first; if that sort is lost, the walk passes a height and can never go
    //    back, so entries silently vanish.
    for (size_t i = 1; i < heights.size(); ++i) {
        BOOST_REQUIRE_MESSAGE(heights[i] < heights[i - 1],
            "resolved heights must strictly descend (index " << i << ")");
    }
    BOOST_CHECK_MESSAGE(heights.front() == kTipHeight,
        "the schedule starts at the tip when headers are not ahead, got " << heights.front());

    // 3. Nothing above the tip is emitted, and nothing below genesis.
    for (int h : heights) {
        BOOST_REQUIRE_MESSAGE(h >= 0 && h <= kTipHeight,
            "resolver emitted out-of-range height " << h);
    }

    // 4. HEADERS AHEAD OF THE CHAINSTATE - the IBD state this whole path exists
    //    for. The schedule is taken from the headers height, but only heights at
    //    or below the chainstate tip may come back. Emitting an above-tip height
    //    would pair a real hash with the wrong height on the wire.
    std::vector<int> aheadHeights;
    int aheadTip = -99;
    const std::vector<uint256> ahead =
        chainstate.ResolveLocatorHashes(kTipHeight + 500, &hdrtest::LocatorHeightPatternForTest,
                                        aheadHeights, aheadTip);
    BOOST_CHECK_EQUAL(aheadTip, kTipHeight);
    BOOST_REQUIRE_EQUAL(ahead.size(), aheadHeights.size());
    for (int h : aheadHeights) {
        BOOST_REQUIRE_MESSAGE(h <= kTipHeight,
            "a headers height ahead of the chainstate must not produce above-tip entries, got " << h);
    }
    BOOST_CHECK_MESSAGE(!aheadHeights.empty(),
        "headers ahead of the chainstate must still yield the chainstate side, not nothing");

    // 5. A null pattern must be empty and harmless, not a crash under cs_main.
    std::vector<int> nullHeights;
    int nullTip = -99;
    BOOST_CHECK(chainstate.ResolveLocatorHashes(0, nullptr, nullHeights, nullTip).empty());
    BOOST_CHECK(nullHeights.empty());
    BOOST_CHECK_EQUAL(nullTip, kTipHeight);
}

// F3, the distinction a single "is there a tip" test cannot make: an empty
// chainstate and a genesis-only chainstate are different states, and collapsing
// them is how a height-0 node silently emitted an EMPTY locator and could never
// start syncing.
BOOST_AUTO_TEST_CASE(p2p16_resolver_distinguishes_no_tip_from_genesis_only)
{
    {
        CChainState empty;
        std::vector<int> heights;
        int tipHeight = -99;
        const std::vector<uint256> got =
            empty.ResolveLocatorHashes(0, &hdrtest::LocatorHeightPatternForTest,
                                       heights, tipHeight);
        BOOST_CHECK_MESSAGE(tipHeight == -1,
            "no tip must report -1, not 0 - 0 is a real chain at genesis, got " << tipHeight);
        BOOST_CHECK(got.empty());
        BOOST_CHECK(heights.empty());
    }
    {
        CChainState genesisOnly;
        auto p = MakeIndex(0x77, nullptr, 0, CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10);
        const uint256 hash = p->GetBlockHash();
        BOOST_REQUIRE(genesisOnly.AddBlockIndex(hash, std::move(p)));
        genesisOnly.SetTip(genesisOnly.GetBlockIndex(hash));

        std::vector<int> heights;
        int tipHeight = -99;
        const std::vector<uint256> got =
            genesisOnly.ResolveLocatorHashes(0, &hdrtest::LocatorHeightPatternForTest,
                                             heights, tipHeight);
        BOOST_CHECK_EQUAL(tipHeight, 0);
        BOOST_REQUIRE_MESSAGE(got.size() == 1 && heights.size() == 1,
            "a genesis-only chain must still yield its genesis entry, got " << got.size());
        BOOST_CHECK_EQUAL(heights[0], 0);
        BOOST_CHECK_MESSAGE(got[0] == hash, "genesis entry must be the genesis hash");
    }
}


// ============================================================================
// External review r3, G4: a REJECTED header batch must never reach the chain
// walk.
//
// ProcessHeaders used to resolve the chainstate side of the locator BEFORE it
// checked the per-peer header budget, the empty case and the size cap. The
// resolve is a descending walk of the active chain under cs_main - at DilV's
// height that is ~131,000 pprev dereferences - so a peer already over its
// budget could make the node pay for a full walk on every batch it was about
// to throw away.
//
// The reorder is invisible to every other test: source order is not behaviour.
// chaintest::ResolveLocatorHashesCallCount() is the instrument that makes it
// behaviour, counting entries to the only function on this path that walks
// pprev under cs_main.
//
// Core does the same thing and says so. net_processing.cpp caps the count at
// the message boundary before the headers are even deserialised ("Bypass the
// normal CBlock deserialization, as we don't want to risk deserializing 2000
// full blocks", then `if (nCount > m_opts.max_headers_result) { Misbehaving;
// return; }`), ProcessHeadersMessage returns immediately on `nCount == 0`, and
// only then runs CheckHeadersPoW under the comment "Before we do any
// processing, make sure these pass basic sanity checks." Nothing touches
// cs_main until GetAntiDoSWorkThreshold, well after all of it. This ordering is
// ported, not invented.
// ============================================================================
BOOST_AUTO_TEST_CASE(p2p16_rejected_batch_never_walks_the_chain)
{
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    }
    CHeadersManager mgr;

    // POSITIVE CONTROL FIRST. Without it this whole case passes if the counter
    // is simply never incremented - the instrument would be broken and the
    // assertions below would be vacuous. An accepted batch MUST reach the walk.
    const uint64_t c0 = chaintest::ResolveLocatorHashesCallCount();
    std::vector<CBlockHeader> small(2);
    mgr.ProcessHeaders(/*peer=*/101, small);
    const uint64_t c1 = chaintest::ResolveLocatorHashesCallCount();
    BOOST_REQUIRE_MESSAGE(c1 > c0,
        "instrument is dead: an accepted batch did not reach ResolveLocatorHashes, "
        "so the negative assertions below would prove nothing");

    // OVERSIZE: rejected on size, must not walk.
    //
    // MAX_HEADERS_BUFFER is private, so 2001 is a literal here. A literal can
    // drift away from the constant and leave this testing nothing, so the
    // boundary is pinned BEHAVIOURALLY as well: exactly 2000 must be accepted
    // (and therefore reach the walk), 2001 must not. If the constant moves,
    // one of these two goes red rather than both quietly passing.
    const uint64_t cb = chaintest::ResolveLocatorHashesCallCount();
    std::vector<CBlockHeader> atLimit(2000);
    mgr.ProcessHeaders(/*peer=*/104, atLimit);
    BOOST_CHECK_MESSAGE(chaintest::ResolveLocatorHashesCallCount() > cb,
        "a batch of exactly 2000 must NOT be rejected on size - if this fails, "
        "MAX_HEADERS_BUFFER moved and the 2001 below no longer tests the boundary");

    std::vector<CBlockHeader> huge(2001);
    const uint64_t c2 = chaintest::ResolveLocatorHashesCallCount();
    BOOST_CHECK_MESSAGE(!mgr.ProcessHeaders(/*peer=*/102, huge),
        "an over-size batch must be rejected");
    BOOST_CHECK_MESSAGE(chaintest::ResolveLocatorHashesCallCount() == c2,
        "an over-size batch reached the chain walk - the admission checks are "
        "back behind the resolve, and a peer can drive a full cs_main walk per "
        "rejected batch");

    // EMPTY: accepted as a no-op, must not walk either.
    std::vector<CBlockHeader> none;
    const uint64_t c3 = chaintest::ResolveLocatorHashesCallCount();
    BOOST_CHECK_MESSAGE(mgr.ProcessHeaders(/*peer=*/103, none),
        "an empty batch is valid (end-of-chain reply) and must return true");
    BOOST_CHECK_MESSAGE(chaintest::ResolveLocatorHashesCallCount() == c3,
        "an empty batch reached the chain walk");
}

// ============================================================================
// External review r3, G8: pin the WRAPPER, not only the resolver.
//
// The resolver cases above call CChainState::ResolveLocatorHashes directly on a
// LOCAL chainstate. The thing production calls is
// CHeadersManager::ResolveChainstateHashes, which adds three behaviours of its
// own that no test touched: the F3 remap of "no tip" (-1) to a chainstate
// height of 0, dropping null hashes from the map, and degrading to an empty map
// if the resolver ever returns mismatched vectors.
//
// This asserts the wrapper against ONE snapshot of the resolver taken on the
// SAME chainstate, so it holds whatever state g_chainstate happens to be in
// when the suite runs - no fixture ordering assumption, and no populating of a
// global that other suites share.
// ============================================================================
BOOST_AUTO_TEST_CASE(p2p16_wrapper_agrees_with_one_resolver_snapshot)
{
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    }
    CHeadersManager mgr;

    for (int headersHeight : {0, 5, 1000}) {
        std::vector<int> heights;
        int tipHeight = -99;
        const std::vector<uint256> direct =
            g_chainstate.ResolveLocatorHashes(headersHeight,
                                              &hdrtest::LocatorHeightPatternForTest,
                                              heights, tipHeight);
        BOOST_REQUIRE_EQUAL(direct.size(), heights.size());

        int wrapperHeight = -99;
        const std::map<int, uint256> viaWrapper =
            mgr.ResolveChainstateHashesForTest(headersHeight, &wrapperHeight);

        // F3: -1 means NO TIP and must surface as 0; 0 means a real genesis-only
        // chain. Collapsing the two is how a height-0 node emitted an empty
        // locator and could never start syncing. This is the assertion that
        // makes that remap machine-held instead of comment-held.
        BOOST_CHECK_MESSAGE(wrapperHeight == (tipHeight < 0 ? 0 : tipHeight),
            "wrapper reported chainstate height " << wrapperHeight
            << " for a resolver tip of " << tipHeight
            << " (headersHeight=" << headersHeight << ")");

        // The map is exactly the non-null entries of that snapshot, keyed by the
        // heights the resolver named. Not a subset, not a superset.
        std::map<int, uint256> expected;
        for (size_t k = 0; k < heights.size(); ++k) {
            if (!direct[k].IsNull()) expected[heights[k]] = direct[k];
        }
        BOOST_CHECK_MESSAGE(viaWrapper.size() == expected.size(),
            "wrapper map has " << viaWrapper.size() << " entries, the resolver "
            "snapshot implies " << expected.size() << " (headersHeight="
            << headersHeight << ")");
        for (const auto& kv : expected) {
            auto it = viaWrapper.find(kv.first);
            BOOST_REQUIRE_MESSAGE(it != viaWrapper.end(),
                "wrapper dropped height " << kv.first);
            BOOST_CHECK_MESSAGE(it->second == kv.second,
                "wrapper hash disagrees with the resolver at height " << kv.first);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
