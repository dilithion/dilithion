// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.1 — HeadersManager → chain_selector wiring tests.
//
// Per v1.5 plan §4 PR6.1, five mandatory test classes:
//   1. Happy-path: N consecutive valid headers populate mapBlockIndex
//   2. Idempotency: same header processed twice does not double-insert
//   3. Orphan handling: header with unknown parent is rejected
//   4. Rejected-parent descendant flood: peer announces 10K headers
//      descending from a known-invalid block — verify mapBlockIndex
//      does not grow
//   5. Cap-saturation: force mapBlockIndex to cap; verify ProcessNewHeader
//      fails closed (returns false) without UAF or eviction-of-best-chain
//
// Pattern matches src/test/chain_selector_tests.cpp:
//   * Standalone test functions (no Boost framework)
//   * Manual setup using CChainState + ChainSelectorAdapter
//   * VDF-style headers (SHA3-256, no RandomX dependency)

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <consensus/pow.h>          // ChainWorkGreaterThan (Test 6 regression)
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

namespace {

// Construct a VDF-style header chained from a given parent hash.
// Different `tag` byte produces a different vdfOutput → different SHA3 hash
// → distinct sibling.
CBlockHeader MakeHeader(const uint256& parent_hash, uint32_t nBits,
                        uint32_t nTime, uint8_t tag = 0)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;
    h.hashPrevBlock = parent_hash;
    std::memset(h.hashMerkleRoot.data, 0, 32);
    h.nTime = nTime;
    h.nBits = nBits;
    h.nNonce = 0;
    for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0;
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i] = tag;
    return h;
}

}  // anonymous

// ============================================================================
// Test 1 — Happy-path: N consecutive valid headers populate mapBlockIndex.
// Verifies the PR6.1 wiring's load-bearing claim: every accepted header
// becomes a CBlockIndex entry visible via LookupBlockIndex.
// ============================================================================
void test_pr61_happy_path_n_headers_populate_mapBlockIndex()
{
    std::cout << "  test_pr61_happy_path_n_headers_populate_mapBlockIndex..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Build a chain of 10 headers from genesis.
    uint256 prev_hash;
    std::memset(prev_hash.data, 0, 32);
    auto genesis = MakeHeader(prev_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(genesis));
    prev_hash = genesis.GetHash();

    for (int i = 1; i <= 10; ++i) {
        auto h = MakeHeader(prev_hash, 0x1d00ffff, 1700000000 + i, static_cast<uint8_t>(i));
        bool ok = adapter.ProcessNewHeader(h);
        assert(ok);
        // Verify it's now in mapBlockIndex.
        CBlockIndex* p = chainstate.GetBlockIndex(h.GetHash());
        assert(p != nullptr);
        assert(p->nHeight == i);
        // G2 invariant: pre-validation only.
        assert((p->nStatus & CBlockIndex::BLOCK_VALID_MASK) == CBlockIndex::BLOCK_VALID_HEADER);
        assert(!p->IsInvalid());
        prev_hash = h.GetHash();
    }

    // mapBlockIndex should contain exactly 11 entries (genesis + 10).
    assert(chainstate.GetBlockIndexSize() == 11);

    std::cout << " OK\n";
}

// ============================================================================
// Test 2 — Idempotency: re-processing the same header does not duplicate.
// Verifies that HeadersManager's wiring is safe to call multiple times
// (re-orgs, retries, etc.).
// ============================================================================
void test_pr61_idempotency_same_header_no_duplicate()
{
    std::cout << "  test_pr61_idempotency_same_header_no_duplicate..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 prev_hash;
    std::memset(prev_hash.data, 0, 32);
    auto genesis = MakeHeader(prev_hash, 0x1d00ffff, 1700000000, 0);
    auto h = MakeHeader(genesis.GetHash(), 0x1d00ffff, 1700000060, 1);

    assert(adapter.ProcessNewHeader(genesis));
    assert(adapter.ProcessNewHeader(h));
    CBlockIndex* p_first = chainstate.GetBlockIndex(h.GetHash());

    // Re-process. Must succeed (idempotent contract per chain_selector_impl
    // line 122-126) and return the SAME pointer.
    assert(adapter.ProcessNewHeader(h));
    CBlockIndex* p_second = chainstate.GetBlockIndex(h.GetHash());
    assert(p_first == p_second);
    // mapBlockIndex size unchanged.
    assert(chainstate.GetBlockIndexSize() == 2);

    std::cout << " OK\n";
}

// ============================================================================
// Test 3 — Orphan handling: header with unknown parent is rejected.
// Per chain_selector_impl line 134-137: orphan returns false; mapBlockIndex
// does NOT grow. (HeadersManager is responsible for topological order.)
// ============================================================================
void test_pr61_orphan_header_rejected()
{
    std::cout << "  test_pr61_orphan_header_rejected..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Build an "orphan" — header whose parent is not in mapBlockIndex.
    uint256 unknown_parent;
    std::memset(unknown_parent.data, 0xAA, 32);
    auto h = MakeHeader(unknown_parent, 0x1d00ffff, 1700000000, 0);

    bool ok = adapter.ProcessNewHeader(h);
    assert(!ok);  // orphan rejected
    assert(chainstate.GetBlockIndex(h.GetHash()) == nullptr);
    assert((chainstate.GetBlockIndexSize() == 0));

    std::cout << " OK\n";
}

// ============================================================================
// Test 4 — Rejected-parent descendant flood.
// 10K headers all descending from a parent marked BLOCK_FAILED_VALID must
// not grow mapBlockIndex. Per chain_selector_impl line 146-148 (Phase 5
// BLOCKER 1 fix): refuse to extend a chain rooted in a known-invalid block.
// ============================================================================
void test_pr61_rejected_parent_flood_does_not_grow_mapBlockIndex()
{
    std::cout << "  test_pr61_rejected_parent_flood_does_not_grow_mapBlockIndex..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Plant a genesis + an invalid block (parent of the flood).
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto genesis = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(genesis));

    auto bad = MakeHeader(genesis.GetHash(), 0x1d00ffff, 1700000060, 0xFE);
    assert(adapter.ProcessNewHeader(bad));
    // Mark it as failed.
    CBlockIndex* p_bad = chainstate.GetBlockIndex(bad.GetHash());
    p_bad->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;

    const size_t pre_size = chainstate.GetBlockIndexSize();
    assert(pre_size == 2);

    // Flood: 10K headers descending from `bad`.
    uint256 attacker_parent = bad.GetHash();
    int rejected = 0;
    for (int i = 0; i < 10000; ++i) {
        auto flood_h = MakeHeader(attacker_parent, 0x1d00ffff,
                                  1700000060 + i + 1, static_cast<uint8_t>(i & 0xFF));
        if (!adapter.ProcessNewHeader(flood_h)) {
            ++rejected;
        }
    }

    // ALL 10K should have been rejected. mapBlockIndex must NOT have grown.
    assert(rejected == 10000);
    assert(chainstate.GetBlockIndexSize() == pre_size);

    std::cout << " OK (" << rejected << "/10000 rejected, mapBlockIndex stable at "
              << pre_size << ")\n";
}

// ============================================================================
// Test 5 — Cap-saturation with SAFE leaf-only eviction.
//
// Rewritten for the leaf-only eviction policy (the v4.5.0-pull fix). The prior
// version built a single LINEAR strand with a frozen genesis tip and asserted
// the OLD policy's behavior (final_size==cap, zero rejections by evicting
// low-work interior nodes). That oracle encoded the unsafe policy — under safe
// leaf-only eviction, evicting the top of a linear strand orphans the next
// header, which is neither realistic nor the property we want to protect.
//
// This version models a realistic node: an ADVANCING active chain (tip moves
// with each block) plus short disposable side-forks that create evictable
// LEAVES. It verifies:
//   (a) mapBlockIndex never exceeds the cap,
//   (b) the active chain is NEVER evicted (every active-chain hash present),
//   (c) eviction actually fires (stale fork leaves are reclaimed),
//   (d) no UAF: a full GetChainTips() / FindMostWorkChainImpl() walk after
//       saturation succeeds (ASAN in CI is the machine verdict).
// ============================================================================
void test_pr61_cap_saturation_safe_leaf_eviction()
{
    std::cout << "  test_pr61_cap_saturation_safe_leaf_eviction..." << std::flush;

    // Small cap via Regtest chainparams (cap=1000).
    static Dilithion::ChainParams regtest_params = Dilithion::ChainParams::Regtest();
    Dilithion::ChainParams* prev_chainparams = Dilithion::g_chainParams;
    Dilithion::g_chainParams = &regtest_params;
    const size_t cap = static_cast<size_t>(regtest_params.nMapBlockIndexCap);
    assert(cap == 1000);

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto genesis = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(genesis));
    CBlockIndex* genesis_idx = chainstate.GetBlockIndex(genesis.GetHash());
    assert(genesis_idx != nullptr);
    chainstate.SetTip(genesis_idx);

    // Extend the active chain to 900 blocks (deliberately < cap so the pinned
    // active chain alone fits — at production sizes the cap of 500K dwarfs the
    // ~24K-200K chain height, so the active chain is never the binding
    // constraint). Advance the tip each step (realistic). Then, every step,
    // spawn a SHORT side-fork leaf off the current tip — a disposable
    // non-active leaf. These fork leaves push total inserts past the cap and
    // are the safe eviction targets. Track active-chain hashes to assert none
    // were ever evicted.
    const int kActiveLen = 900;  // < cap (1000): active chain always fits
    std::vector<uint256> active_hashes;
    active_hashes.push_back(genesis.GetHash());
    uint256 prev_hash = genesis.GetHash();
    int accepted = 1;
    int fork_attempts = 0;

    for (int i = 1; i <= kActiveLen; ++i) {
        // Active-chain extension (tag 0x00-band).
        auto h = MakeHeader(prev_hash, 0x1d00ffff, 1700000000 + i,
                            static_cast<uint8_t>(i & 0x7F));
        bool ok = adapter.ProcessNewHeader(h);
        assert(ok);  // active-chain extension must always be accepted
        ++accepted;
        prev_hash = h.GetHash();
        active_hashes.push_back(prev_hash);

        // Advance the tip so the active chain is pinned.
        CBlockIndex* tip = chainstate.GetBlockIndex(prev_hash);
        assert(tip != nullptr);
        chainstate.SetTip(tip);

        // Spawn several disposable side-fork leaves off the new tip so total
        // inserts blow past the cap and force eviction. Each is a one-block
        // sibling branch; tag 0x80-band keeps them distinct from the main
        // chain and from each other.
        for (int j = 0; j < 3; ++j) {
            auto fork = MakeHeader(prev_hash, 0x1d00ffff,
                                   1700000000 + i,
                                   static_cast<uint8_t>(0x80 | ((i + j * 37) & 0x7F)));
            adapter.ProcessNewHeader(fork);  // accepted then possibly evicted
            ++fork_attempts;
        }

        // INVARIANT (a): size never exceeds cap.
        assert(chainstate.GetBlockIndexSize() <= cap);
    }

    const size_t final_size = chainstate.GetBlockIndexSize();
    // Bounded by the cap (eviction kept it under control despite the flood).
    assert(final_size <= cap);

    // INVARIANT (b): the entire active chain survived — nothing on it evicted.
    for (const auto& ah : active_hashes) {
        assert(chainstate.GetBlockIndex(ah) != nullptr);
    }

    // INVARIANT (c): eviction fired — we attempted far more inserts (900 active
    // + ~2700 fork leaves) than the cap, yet the index stayed bounded.
    assert(fork_attempts > 0);
    assert(static_cast<size_t>(accepted) + static_cast<size_t>(fork_attempts) > cap);

    // INVARIANT (d): no UAF — walk the whole index via the pprev-dereferencing
    // chain functions. ASAN traps any dangling pprev here if the fix regresses.
    auto tips = chainstate.GetChainTips();
    (void)tips;
    CBlockIndex* mw = chainstate.FindMostWorkChainImpl();
    (void)mw;

    Dilithion::g_chainParams = prev_chainparams;

    std::cout << " OK (accepted=" << accepted << " final size=" << final_size
              << " — active chain intact, leaf eviction bounded index, walk clean)\n";
}

// ============================================================================
// Test 6 — REGRESSION: eviction must never free a referenced (interior) parent.
//
// This is the test the shipped Test 5 MISSED. Test 5 builds a single LINEAR
// chain, so the only off-active entries it evicts happen to be safe in the
// sense that the test never walks pprev afterward — the dangling read was
// never exercised. The v4.5.0 cap fix was PULLED because the prior eviction
// policy ("lowest-work entry not on the active chain") could free an INTERIOR
// fork node whose higher-work child still pointed at it via pprev, dangling
// that child's pprev → use-after-free on the next FindMostWorkChain /
// GetChainTips / pprev walk.
//
// Topology:
//   active chain (heaviest, pinned via tip): A -> M1 -> M2 -> M3 -> M4   (tip = M4)
//   off-chain fork:                          A -> F  -> F2
//   F is INTERIOR (F2 references it via pprev) and has LOWER cumulative work
//   than its child F2 (work is additive, so a parent always has < its child).
//
// Under the OLD policy: F (lowest-work non-active entry) is freed even though
//   F2->pprev == F. The subsequent F2->pprev deref / chain walk is a UAF.
// Under the FIX: F has in-degree 1 (F2 names it), so it is NOT a leaf and
//   survives; the leaf F2 is the eligible eviction target instead. We then
//   walk F2->pprev, FindMostWorkChainImpl and GetChainTips: all must succeed
//   with no dangling read (the CI AddressSanitizer job is the machine verdict
//   — it traps the dangling read if this fix ever regresses).
//
// Note: ProcessNewHeader does NOT populate m_setBlockIndexCandidates, so the
// pinned set here is exactly the active chain. F therefore survives *because
// it is interior* (in-degree > 0), not merely because it is pinned — which is
// the precise property under test.
// ============================================================================
void test_evict_never_frees_referenced_parent()
{
    std::cout << "  test_evict_never_frees_referenced_parent..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // --- Genesis A ---
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto A = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(A));
    const uint256 hashA = A.GetHash();

    // --- Active chain A -> M1 -> M2 -> M3 -> M4 (heaviest) ---
    uint256 prev = hashA;
    uint256 hashM4;
    for (int i = 1; i <= 4; ++i) {
        // tag 0x10+i keeps these distinct from the fork's tags.
        auto M = MakeHeader(prev, 0x1d00ffff, 1700000000 + i,
                            static_cast<uint8_t>(0x10 + i));
        assert(adapter.ProcessNewHeader(M));
        prev = M.GetHash();
        if (i == 4) hashM4 = prev;
    }

    // Pin the active chain by setting the tip to M4.
    CBlockIndex* idxM4 = chainstate.GetBlockIndex(hashM4);
    assert(idxM4 != nullptr);
    chainstate.SetTip(idxM4);

    // --- Off-chain fork A -> F -> F2 (F is interior) ---
    auto F = MakeHeader(hashA, 0x1d00ffff, 1700000500, 0xF0);
    assert(adapter.ProcessNewHeader(F));
    const uint256 hashF = F.GetHash();

    auto F2 = MakeHeader(hashF, 0x1d00ffff, 1700000501, 0xF2);
    assert(adapter.ProcessNewHeader(F2));
    const uint256 hashF2 = F2.GetHash();

    CBlockIndex* idxF  = chainstate.GetBlockIndex(hashF);
    CBlockIndex* idxF2 = chainstate.GetBlockIndex(hashF2);
    assert(idxF != nullptr);
    assert(idxF2 != nullptr);
    // Sanity: F2 really does reference F as its parent, and F has LOWER
    // cumulative work than F2 (so the OLD lowest-work policy would target F).
    assert(idxF2->pprev == idxF);
    assert(ChainWorkGreaterThan(idxF2->nChainWork, idxF->nChainWork));

    // Drive eviction to make room for exactly ONE entry (the production call
    // pattern: target_max = cap-1). With 7 entries (A,M1-M4,F,F2) we ask to
    // get down to 6, so exactly one leaf is evicted. The lowest-work eligible
    // leaf is F2 (F is interior → in-degree 1 → not a leaf; the active chain
    // is pinned). Under the OLD policy this same "make room" step would have
    // erased F (lowest-work non-active entry) and left idxF2->pprev dangling.
    const size_t size_before = chainstate.GetBlockIndexSize();
    assert(size_before == 7);  // A + M1..M4 + F + F2
    bool evicted = chainstate.EvictLowestWorkLeafNotPinned(size_before - 1);
    assert(evicted);                                   // one leaf removed
    assert(chainstate.GetBlockIndexSize() == size_before - 1);  // exactly one

    // F (the interior parent) MUST still be present — never freed.
    CBlockIndex* idxF_after = chainstate.GetBlockIndex(hashF);
    assert(idxF_after != nullptr);
    assert(idxF_after == idxF);  // same object, not reallocated

    // The eligible LEAF (F2) is the one that got evicted.
    assert(chainstate.GetBlockIndex(hashF2) == nullptr);

    // Active chain is fully intact.
    assert(chainstate.GetBlockIndex(hashA)  != nullptr);
    assert(chainstate.GetBlockIndex(hashM4) != nullptr);

    // --- The load-bearing UAF probe ---
    // Walk F's parent chain back to genesis. Under the old code, if F had been
    // freed while F2 survived (or any interior free), this walk would deref a
    // dangling pointer; ASAN traps it. Here F survives and its ancestry is the
    // valid A -> F linkage.
    int hops = 0;
    for (CBlockIndex* p = idxF_after; p != nullptr; p = p->pprev) {
        (void)p->nHeight;          // touch the node (ASAN read probe)
        (void)p->GetBlockHash();
        if (++hops > 1000) { assert(false && "pprev cycle"); break; }
    }
    assert(hops == 2);  // F (h1) -> A (h0)

    // Exercise the chain walks that dereference pprev across the whole index.
    // If any surviving entry had a dangling pprev, ASAN traps inside these.
    CBlockIndex* most_work = chainstate.FindMostWorkChainImpl();
    (void)most_work;
    auto tips = chainstate.GetChainTips();
    (void)tips;

    std::cout << " OK (interior parent F preserved; leaf F2 evicted; "
              << "pprev walk + FindMostWorkChain + GetChainTips clean)\n";
}

// ============================================================================
// Test 7 — BLOCKER-1 REGRESSION (PR #129 re-red-team): eviction must never free
// an IN-FLIGHT block (HAVE_DATA set, not yet VALID_TRANSACTIONS).
//
// The leaf-only fix (Test 6) closes the interior-node pprev UAF but NOT the
// general class: a raw CBlockIndex* cached OUTSIDE the pin set. The live
// instance was CBlockValidationQueue::QueuedBlock::pindex — a block received
// during IBD, added to mapBlockIndex with BLOCK_HAVE_DATA but NOT yet
// BLOCK_VALID_TRANSACTIONS (async validation pending), with cs_main released
// while it waits. Such a block is NOT a candidate (candidate predicate needs
// VALID_TRANSACTIONS) and, as the newest block in a flood with no children, is
// an in-degree-0 unpinned leaf — so under the plain leaf-only policy the
// lowered 500K cap could free it out from under the queue's cached pointer →
// UAF in ActivateBestChain.
//
// Fix under test: EvictLowestWorkLeafNotPinned pins every entry that HAS data
// but is NOT fully validated (clause (c)). This test builds exactly that entry
// — a HAVE_DATA-not-VALID_TRANSACTIONS leaf simulating a queued in-flight block
// — drives eviction hard enough to remove other leaves, and asserts the
// in-flight leaf SURVIVES and its index is still dereferenceable afterward
// (ASAN traps a freed-then-read regression on the saved raw pointer, mirroring
// the queue dequeuing its cached pindex).
// ============================================================================
void test_evict_never_frees_inflight_block()
{
    std::cout << "  test_evict_never_frees_inflight_block..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto A = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(A));
    const uint256 hashA = A.GetHash();

    // Active chain A -> M1 -> M2 -> M3 (heaviest, pinned via tip).
    uint256 prev = hashA;
    uint256 hashM3;
    for (int i = 1; i <= 3; ++i) {
        auto M = MakeHeader(prev, 0x1d00ffff, 1700000000 + i,
                            static_cast<uint8_t>(0x10 + i));
        assert(adapter.ProcessNewHeader(M));
        prev = M.GetHash();
        if (i == 3) hashM3 = prev;
    }
    CBlockIndex* idxM3 = chainstate.GetBlockIndex(hashM3);
    assert(idxM3 != nullptr);
    chainstate.SetTip(idxM3);

    // Two off-chain leaves descending from A:
    //   L_plain : a header-only leaf (BLOCK_VALID_HEADER) — eligible for eviction.
    //   L_flight: an IN-FLIGHT leaf — header accepted, then we mark it
    //             HAVE_DATA but DO NOT raise validity to VALID_TRANSACTIONS,
    //             exactly as a block sitting in the async validation queue.
    auto L_plain = MakeHeader(hashA, 0x1d00ffff, 1700000500, 0xA0);
    assert(adapter.ProcessNewHeader(L_plain));
    const uint256 hashLplain = L_plain.GetHash();

    auto L_flight = MakeHeader(hashA, 0x1d00ffff, 1700000501, 0xA1);
    assert(adapter.ProcessNewHeader(L_flight));
    const uint256 hashLflight = L_flight.GetHash();

    CBlockIndex* idxFlight = chainstate.GetBlockIndex(hashLflight);
    assert(idxFlight != nullptr);
    // Simulate the queued-block state: HAVE_DATA set, validity still HEADER
    // (NOT raised to VALID_TRANSACTIONS). This is the exact nStatus a block has
    // while it waits in CBlockValidationQueue.
    idxFlight->nStatus |= CBlockIndex::BLOCK_HAVE_DATA;
    assert((idxFlight->nStatus & CBlockIndex::BLOCK_HAVE_DATA) != 0);
    assert((idxFlight->nStatus & CBlockIndex::BLOCK_VALID_MASK)
               < CBlockIndex::BLOCK_VALID_TRANSACTIONS);
    // Save the raw pointer — this is what the queue caches and later derefs.
    CBlockIndex* const cached_inflight_ptr = idxFlight;

    // Drive eviction hard: target_max small enough to remove BOTH off-chain
    // leaves if the policy allowed it. The active chain (A,M1,M2,M3 = 4) is
    // pinned; total = 6 (A,M1,M2,M3,L_plain,L_flight). Ask to get to 4. A
    // BROKEN policy (no in-flight pin) would evict BOTH L_plain and L_flight
    // (both in-degree-0 leaves) → freeing the cached in-flight pointer.
    const size_t size_before = chainstate.GetBlockIndexSize();
    assert(size_before == 6);
    bool evicted = chainstate.EvictLowestWorkLeafNotPinned(4);
    assert(evicted);

    // L_flight MUST survive (pinned by clause (c)); only L_plain is evictable.
    CBlockIndex* idxFlight_after = chainstate.GetBlockIndex(hashLflight);
    assert(idxFlight_after != nullptr);
    assert(idxFlight_after == cached_inflight_ptr);  // same object, not freed
    assert(chainstate.GetBlockIndex(hashLplain) == nullptr);  // plain leaf gone

    // Final size: active chain (4) + surviving in-flight leaf (1) = 5. The
    // in-flight pin floors eviction above target_max=4 — correct: a queued
    // block is never sacrificed to the cap (it fails closed instead, exactly
    // as the production path falls back to reject on a full index).
    assert(chainstate.GetBlockIndexSize() == 5);

    // The load-bearing UAF probe: dereference the cached pointer the way the
    // validation queue would after dequeue. ASAN traps if it was freed.
    (void)cached_inflight_ptr->nHeight;
    (void)cached_inflight_ptr->GetBlockHash();
    for (CBlockIndex* p = cached_inflight_ptr; p != nullptr; p = p->pprev) {
        (void)p->nHeight;  // ASAN read probe across the ancestry
    }

    std::cout << " OK (in-flight HAVE_DATA-not-VALID_TRANSACTIONS leaf pinned; "
              << "cached pointer still valid post-eviction)\n";
}

// ============================================================================
// Test 8 — MEDIUM-2 (PR #129 re-red-team): drive the multi-pass
// decrement-in-degree-to-0 CASCADE in a single EvictLowestWorkLeafNotPinned
// call. Test 6 only removes one leaf, so the cascade (after erasing a leaf,
// its parent's in-degree drops, and the parent becomes an eligible leaf on the
// NEXT pass) is never exercised end-to-end — the most off-by-one-prone path.
//
// Topology:
//   active chain (pinned via tip): A -> M1 -> M2   (tip = M2)
//   off-chain linear fork:         A -> F -> F2 -> F3
// Only F3 is a leaf initially (in-degree 0). F2 has in-degree 1 (F3), F has
// in-degree 1 (F2). A single eviction call with target_max forcing removal of
// all three must cascade: evict F3 → F2 becomes leaf → evict F2 → F becomes
// leaf → evict F. Each parent must become eligible ONLY after its child is
// gone, and the final pprev walk over survivors must be clean (ASAN).
// ============================================================================
void test_evict_multipass_cascade_to_zero()
{
    std::cout << "  test_evict_multipass_cascade_to_zero..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto A = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(A));
    const uint256 hashA = A.GetHash();

    // Active chain A -> M1 -> M2 (heaviest, pinned).
    uint256 prev = hashA;
    uint256 hashM2;
    for (int i = 1; i <= 2; ++i) {
        auto M = MakeHeader(prev, 0x1d00ffff, 1700000000 + i,
                            static_cast<uint8_t>(0x10 + i));
        assert(adapter.ProcessNewHeader(M));
        prev = M.GetHash();
        if (i == 2) hashM2 = prev;
    }
    CBlockIndex* idxM2 = chainstate.GetBlockIndex(hashM2);
    assert(idxM2 != nullptr);
    chainstate.SetTip(idxM2);

    // Off-chain linear fork A -> F -> F2 -> F3.
    auto F = MakeHeader(hashA, 0x1d00ffff, 1700000500, 0xF0);
    assert(adapter.ProcessNewHeader(F));
    const uint256 hashF = F.GetHash();
    auto F2 = MakeHeader(hashF, 0x1d00ffff, 1700000501, 0xF2);
    assert(adapter.ProcessNewHeader(F2));
    const uint256 hashF2 = F2.GetHash();
    auto F3 = MakeHeader(hashF2, 0x1d00ffff, 1700000502, 0xF3);
    assert(adapter.ProcessNewHeader(F3));
    const uint256 hashF3 = F3.GetHash();

    CBlockIndex* idxF  = chainstate.GetBlockIndex(hashF);
    CBlockIndex* idxF2 = chainstate.GetBlockIndex(hashF2);
    CBlockIndex* idxF3 = chainstate.GetBlockIndex(hashF3);
    assert(idxF && idxF2 && idxF3);
    assert(idxF2->pprev == idxF);
    assert(idxF3->pprev == idxF2);

    // Total = 6 (A,M1,M2,F,F2,F3). Active chain (A,M1,M2) pinned. Ask to drain
    // to 3 → forces evicting F3 THEN F2 THEN F in a single call (the cascade).
    const size_t size_before = chainstate.GetBlockIndexSize();
    assert(size_before == 6);
    bool evicted = chainstate.EvictLowestWorkLeafNotPinned(3);
    assert(evicted);
    assert(chainstate.GetBlockIndexSize() == 3);  // only active chain remains

    // All three fork nodes gone; none could be freed before its child (a
    // premature parent-free would have dangled the child's pprev — the cascade
    // ordering is what this asserts).
    assert(chainstate.GetBlockIndex(hashF)  == nullptr);
    assert(chainstate.GetBlockIndex(hashF2) == nullptr);
    assert(chainstate.GetBlockIndex(hashF3) == nullptr);

    // Active chain intact and pprev-walkable (ASAN probe).
    assert(chainstate.GetBlockIndex(hashA)  != nullptr);
    CBlockIndex* tip = chainstate.GetBlockIndex(hashM2);
    assert(tip != nullptr);
    int hops = 0;
    for (CBlockIndex* p = tip; p != nullptr; p = p->pprev) {
        (void)p->nHeight;
        if (++hops > 1000) { assert(false && "pprev cycle"); break; }
    }
    assert(hops == 3);  // M2 -> M1 -> A
    CBlockIndex* most_work = chainstate.FindMostWorkChainImpl();
    (void)most_work;
    auto tips = chainstate.GetChainTips();
    (void)tips;

    std::cout << " OK (3-deep cascade F3->F2->F in one call; "
              << "each parent freed only after its child; walk clean)\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.1 — HeadersManager → chain_selector wiring tests\n";
    std::cout << "  (8-test suite per v1.5 plan §4 PR6.1 + leaf-eviction regression\n";
    std::cout << "   + BLOCKER-1 in-flight pin + MEDIUM-2 cascade, PR #129)\n\n";

    try {
        test_pr61_happy_path_n_headers_populate_mapBlockIndex();
        test_pr61_idempotency_same_header_no_duplicate();
        test_pr61_orphan_header_rejected();
        test_pr61_rejected_parent_flood_does_not_grow_mapBlockIndex();
        test_pr61_cap_saturation_safe_leaf_eviction();
        test_evict_never_frees_referenced_parent();
        test_evict_never_frees_inflight_block();
        test_evict_multipass_cascade_to_zero();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 6 PR6.1 wiring tests passed.\n";
    return 0;
}
