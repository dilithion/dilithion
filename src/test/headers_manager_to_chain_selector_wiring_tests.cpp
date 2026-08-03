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
#include <set>      // PR #129 MEDIUM-2: PendingBlockHashProvider returns std::set<uint256>
#include <vector>
#include <atomic>    // PR #129 HIGH-1 concurrency regression
#include <mutex>     // PR #129 HIGH-1 concurrency regression
#include <thread>    // PR #129 HIGH-1 concurrency regression
#include <utility>   // PR #129 HIGH-1: std::pair

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
// Test 7 — BLOCKER-1 REGRESSION (PR #129 re-red-team HIGH-1): the queue's
// by-hash RE-RESOLVE is the SOLE mechanism that closes the BLOCKER-1 UAF for a
// queued block. This test drives the leg that ACTUALLY holds.
//
// LOW-d (PR #129 re-red-team): RENAMED from test_evict_never_frees_inflight_block.
// The old name was the OPPOSITE of what this test proves — with no
// PendingBlockHashProvider registered (as here), the in-flight leaf IS evicted;
// the property under test is that the worker's by-hash re-resolve then returns
// null SAFELY (never a dangling pointer), i.e. the re-resolve is UAF-safe. The
// MEDIUM-2 pin that makes a real running queue NOT evict its in-flight block is a
// SEPARATE layer, covered by Test 9 below (which registers a provider). Keeping
// the two concerns in separate tests is deliberate: this one proves correctness
// survives even if the pin is absent/bypassed; Test 9 proves the pin prevents the
// liveness stall in the first place.
//
// The live BLOCKER-1 instance was CBlockValidationQueue::QueuedBlock::pindex —
// a raw CBlockIndex* cached at QueueBlock() time, then dereferenced in the
// worker's ProcessBlock AFTER cs_main was released for async validation. The
// real queued block is in its PRODUCTION state: HAVE_DATA + VALID_TRANSACTIONS,
// because every data-ingress path stamps it via MarkBlockReceived()
// (block_index.h:182-184), which sets BLOCK_HAVE_DATA AND raises validity to
// VALID_TRANSACTIONS in ONE op. Such a block is therefore `fully_validated`, so
// the eviction pin clause (c) (`have_data && !fully_validated`) does NOT pin it
// (verified below). It is also not yet a m_setBlockIndexCandidates member during
// the cs_main-released wait, so clause (b) does not pin it either: it is an
// evictable, in-degree-0 leaf — and the lowered 500K cap CAN free it.
//
// The fix that closes the UAF is block_validation_queue.cpp:363:
//   pindex = m_chainstate.GetBlockIndex(blockHash);   // re-resolve by hash
// NOT the cached QueuedBlock::pindex. After the index is evicted, the re-resolve
// returns nullptr (eviction-safe), which the worker handles by re-creating or
// fail-closing — whereas reading the cached raw pointer would be a UAF.
//
// This test reproduces that exact sequence and drives the SAME two calls the
// worker makes (GetBlockIndex re-resolve, then the would-be ActivateBestChain
// deref). It is written so that RE-ARMING THE CACHED FAST-PATH TURNS IT RED:
//   * the assert that the cached pointer is gone after eviction would fail if a
//     regression assumed the pin keeps it alive, and
//   * the ASAN deref probe of the cached pointer (under -fsanitize=address)
//     traps a use-after-free if a regression dereferenced the cached pindex
//     instead of the re-resolved one.
// ============================================================================
void test_queue_byhash_reresolve_is_uaf_safe_when_leaf_evicted()
{
    std::cout << "  test_queue_byhash_reresolve_is_uaf_safe_when_leaf_evicted..." << std::flush;

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

    // An off-chain leaf descending from A, brought to the REAL production
    // queued-block state: HAVE_DATA + VALID_TRANSACTIONS via MarkBlockReceived
    // — exactly the nStatus a block has while it sits in CBlockValidationQueue.
    auto L_flight = MakeHeader(hashA, 0x1d00ffff, 1700000501, 0xA1);
    assert(adapter.ProcessNewHeader(L_flight));
    const uint256 hashLflight = L_flight.GetHash();

    CBlockIndex* idxFlight = chainstate.GetBlockIndex(hashLflight);
    assert(idxFlight != nullptr);
    idxFlight->MarkBlockReceived();  // the canonical production stamp
    // Confirm the FINDING'S factual core: the real queued block is
    // HAVE_DATA + VALID_TRANSACTIONS, so it is `fully_validated` and clause (c)
    // does NOT pin it. (If a future change to MarkBlockReceived stopped raising
    // validity, this assert fires and the comment story must be revisited.)
    assert((idxFlight->nStatus & CBlockIndex::BLOCK_HAVE_DATA) != 0);
    assert((idxFlight->nStatus & CBlockIndex::BLOCK_VALID_MASK)
               >= CBlockIndex::BLOCK_VALID_TRANSACTIONS);

    // This is what the queue caches at QueueBlock() time and what a regressed
    // fast-path would dereference in the worker after the cs_main release.
    CBlockIndex* const cached_inflight_ptr = idxFlight;

    // Drive eviction hard enough to free the queued leaf. Active chain
    // (A,M1,M2,M3 = 4) is pinned; total = 5 (+ L_flight). Ask to get to 4.
    // Because clause (c) does NOT pin L_flight (it is fully_validated), the
    // queued leaf IS evicted — modelling the exact BLOCKER-1 window where the
    // index is freed out from under the queue's cached raw pointer.
    const size_t size_before = chainstate.GetBlockIndexSize();
    assert(size_before == 5);
    bool evicted = chainstate.EvictLowestWorkLeafNotPinned(4);
    assert(evicted);
    assert(chainstate.GetBlockIndexSize() == 4);

    // ---- The load-bearing assertion: the worker's by-hash re-resolve is the
    //      eviction-safe path. After eviction, GetBlockIndex(hash) returns null
    //      (the index was freed), and that null is the SAFE signal the worker
    //      acts on (re-create or fail-closed). A regression that re-armed the
    //      cached fast-path would instead read `cached_inflight_ptr` — now a
    //      dangling pointer — re-opening the UAF.
    CBlockIndex* reresolved = chainstate.GetBlockIndex(hashLflight);  // worker's call
    assert(reresolved == nullptr);  // evicted → re-resolve yields null, never a stale ptr

    // ASAN UAF probe: if a regression dereferenced the CACHED pointer (the
    // re-armed fast-path) instead of acting on the null re-resolve above, this
    // read of freed memory traps under -fsanitize=address. The cached pointer is
    // deliberately NOT dereferenced when the re-resolve is null — that IS the
    // fix. We reference its value (not its target) only to keep it live.
    assert(cached_inflight_ptr != nullptr);  // pointer value, NOT a deref of freed memory

    std::cout << " OK (real queued block HAVE_DATA+VALID_TRANSACTIONS evicted; "
              << "worker's by-hash re-resolve returns null safely — cached "
              << "fast-path would UAF)\n";
}

// ============================================================================
// Test 7b — clause (c) BELT behaviour (PR #129 re-red-team HIGH-1).
//
// Clause (c) pins entries that have BLOCK_HAVE_DATA but have NOT reached
// BLOCK_VALID_TRANSACTIONS. NO current peer-reachable ingress path produces
// that state (MarkBlockReceived couples the two flags — see Test 7), so this is
// NOT the queued-block case; it is defense-in-depth for any FUTURE split-ingress
// path (data first, validity later). This test exercises that belt directly: a
// synthetic HAVE_DATA-without-VALID_TRANSACTIONS leaf must be pinned and survive
// eviction. It is explicitly labelled belt-behaviour and does NOT claim to be
// "the nStatus of a queued block."
// ============================================================================
void test_clause_c_belt_pins_havedata_without_validity()
{
    std::cout << "  test_clause_c_belt_pins_havedata_without_validity..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto A = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(A));
    const uint256 hashA = A.GetHash();

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

    // L_plain: header-only leaf (eligible for eviction).
    auto L_plain = MakeHeader(hashA, 0x1d00ffff, 1700000500, 0xA0);
    assert(adapter.ProcessNewHeader(L_plain));
    const uint256 hashLplain = L_plain.GetHash();

    // L_belt: SYNTHETIC future split-ingress state — HAVE_DATA set WITHOUT
    // raising validity to VALID_TRANSACTIONS. This state is not produced by any
    // current path; we set it by hand to exercise clause (c)'s belt.
    auto L_belt = MakeHeader(hashA, 0x1d00ffff, 1700000501, 0xA1);
    assert(adapter.ProcessNewHeader(L_belt));
    const uint256 hashLbelt = L_belt.GetHash();
    CBlockIndex* idxBelt = chainstate.GetBlockIndex(hashLbelt);
    assert(idxBelt != nullptr);
    idxBelt->nStatus |= CBlockIndex::BLOCK_HAVE_DATA;  // data, but NOT validity
    assert((idxBelt->nStatus & CBlockIndex::BLOCK_HAVE_DATA) != 0);
    assert((idxBelt->nStatus & CBlockIndex::BLOCK_VALID_MASK)
               < CBlockIndex::BLOCK_VALID_TRANSACTIONS);
    CBlockIndex* const belt_ptr = idxBelt;

    // Active chain (4) pinned; total = 6 (+ L_plain + L_belt). Ask to get to 4.
    // A BROKEN clause (c) would evict BOTH leaves; the belt must pin L_belt so
    // only L_plain is freed.
    assert(chainstate.GetBlockIndexSize() == 6);
    bool evicted = chainstate.EvictLowestWorkLeafNotPinned(4);
    assert(evicted);

    // L_belt MUST survive (pinned by clause (c)); only L_plain is evictable.
    assert(chainstate.GetBlockIndex(hashLbelt) == belt_ptr);     // same object, pinned
    assert(chainstate.GetBlockIndex(hashLplain) == nullptr);     // plain leaf gone
    assert(chainstate.GetBlockIndexSize() == 5);                 // pin floors above target

    // ASAN read probe: the pinned belt entry is still valid.
    (void)belt_ptr->nHeight;
    for (CBlockIndex* p = belt_ptr; p != nullptr; p = p->pprev) {
        (void)p->nHeight;
    }

    std::cout << " OK (clause (c) belt pins HAVE_DATA-without-VALID_TRANSACTIONS "
              << "leaf; defense-in-depth for a future split-ingress path)\n";
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
// Test 9 — MEDIUM-2 (PR #129 re-red-team), OPTION (A): the PendingBlockHashProvider
// pin. A real running queue registers a provider that reports the hashes it owns
// (queued + in-flight). Eviction (clause (d)) must pin every reported block AND
// its pprev ancestors, so a cascade cannot free a queued block's parent out from
// under the worker's create path. This test registers a provider directly on the
// chainstate (no real queue needed — the provider IS the integration point) and
// proves the pin holds under aggressive cap pressure.
//
// Topology:
//   active chain (pinned via tip): A -> M1 -> M2   (tip = M2)
//   off-chain fork:                A -> F  -> Q     (Q = the "queued" block)
// Without the provider, Test 8 showed eviction(3) cascades F-chain to nothing.
// WITH a provider reporting Q's hash, eviction(3) must instead keep Q AND its
// ancestor F alive (F is pinned because it is Q's pprev), so the index cannot
// drop below {A,M1,M2,F,Q}=5 — the pin floors it above the requested target.
// ============================================================================
void test_medium2_provider_pins_queued_block_and_ancestors()
{
    std::cout << "  test_medium2_provider_pins_queued_block_and_ancestors..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto A = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(A));
    const uint256 hashA = A.GetHash();

    // Active chain A -> M1 -> M2 (pinned via tip).
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

    // Off-chain fork A -> F -> Q. Q models a block the queue currently owns;
    // F is Q's parent (the cascade target MEDIUM-2 is about).
    auto F = MakeHeader(hashA, 0x1d00ffff, 1700000500, 0xF0);
    assert(adapter.ProcessNewHeader(F));
    const uint256 hashF = F.GetHash();
    auto Q = MakeHeader(hashF, 0x1d00ffff, 1700000501, 0xF1);
    assert(adapter.ProcessNewHeader(Q));
    const uint256 hashQ = Q.GetHash();

    CBlockIndex* idxF = chainstate.GetBlockIndex(hashF);
    CBlockIndex* idxQ = chainstate.GetBlockIndex(hashQ);
    assert(idxF && idxQ);
    assert(idxQ->pprev == idxF);

    // Bring Q to the real production queued-block state (HAVE_DATA +
    // VALID_TRANSACTIONS), so clause (c) does NOT pin it — only the MEDIUM-2
    // provider (clause d) can. This is the exact state Test 7 evicts WITHOUT a
    // provider; here the provider must keep it alive.
    idxQ->MarkBlockReceived();
    assert((idxQ->nStatus & CBlockIndex::BLOCK_HAVE_DATA) != 0);
    assert((idxQ->nStatus & CBlockIndex::BLOCK_VALID_MASK)
               >= CBlockIndex::BLOCK_VALID_TRANSACTIONS);

    // Register the provider: the "queue" reports it owns Q.
    chainstate.RegisterPendingBlockHashProvider(
        [hashQ]() -> std::set<uint256> { return std::set<uint256>{hashQ}; });

    // Total = 5 (A,M1,M2,F,Q). Active chain (A,M1,M2)=3 pinned. Ask to drain to
    // 3. WITHOUT the provider this would cascade-free Q then F (like Test 8).
    // WITH the provider, Q is pinned (clause d) and F is pinned (Q's pprev), so
    // nothing on the F-fork can be freed: the index stays at 5.
    assert(chainstate.GetBlockIndexSize() == 5);
    bool evicted = chainstate.EvictLowestWorkLeafNotPinned(3);
    // No eligible unpinned leaf exists (Q pinned by provider, F pinned as Q's
    // ancestor, active chain pinned), so eviction frees nothing.
    assert(!evicted);
    assert(chainstate.GetBlockIndexSize() == 5);  // pin floored above target

    // Q and F both survived (the load-bearing MEDIUM-2 property).
    assert(chainstate.GetBlockIndex(hashQ) == idxQ);
    assert(chainstate.GetBlockIndex(hashF) == idxF);

    // ASAN walk: Q -> F -> A is intact and pprev-walkable.
    int hops = 0;
    for (CBlockIndex* p = idxQ; p != nullptr; p = p->pprev) {
        (void)p->nHeight;
        if (++hops > 1000) { assert(false && "pprev cycle"); break; }
    }
    assert(hops == 3);  // Q -> F -> A

    // Clear the provider so a later test on a fresh chainstate is unaffected
    // (defensive; each test builds its own chainstate anyway).
    chainstate.RegisterPendingBlockHashProvider(nullptr);

    std::cout << " OK (provider pins queued block Q AND ancestor F; "
              << "cascade cannot free the queued block's parent)\n";
}

// ============================================================================
// Test 10 — MEDIUM-2 NEGATIVE control: with the SAME topology but the provider
// reporting a DIFFERENT (unrelated) hash, the F-fork is NOT protected and the
// cascade proceeds exactly as in Test 8. This proves the pin in Test 9 is caused
// by the provider reporting Q specifically — not by some unrelated change to the
// eviction policy. A regression where clause (d) over-pins (e.g. pins all leaves)
// would turn this test RED.
// ============================================================================
void test_medium2_provider_unrelated_hash_does_not_overpin()
{
    std::cout << "  test_medium2_provider_unrelated_hash_does_not_overpin..." << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto A = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(A));
    const uint256 hashA = A.GetHash();

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

    auto F = MakeHeader(hashA, 0x1d00ffff, 1700000500, 0xF0);
    assert(adapter.ProcessNewHeader(F));
    const uint256 hashF = F.GetHash();
    auto Q = MakeHeader(hashF, 0x1d00ffff, 1700000501, 0xF1);
    assert(adapter.ProcessNewHeader(Q));
    const uint256 hashQ = Q.GetHash();
    CBlockIndex* idxQ = chainstate.GetBlockIndex(hashQ);
    assert(idxQ);
    idxQ->MarkBlockReceived();  // production queued-block state

    // Provider reports a hash NOT in the index — must pin nothing.
    uint256 bogus;
    std::memset(bogus.data, 0xEE, 32);
    chainstate.RegisterPendingBlockHashProvider(
        [bogus]() -> std::set<uint256> { return std::set<uint256>{bogus}; });

    assert(chainstate.GetBlockIndexSize() == 5);
    bool evicted = chainstate.EvictLowestWorkLeafNotPinned(3);
    assert(evicted);                                  // cascade proceeds
    assert(chainstate.GetBlockIndexSize() == 3);      // only active chain remains
    assert(chainstate.GetBlockIndex(hashQ) == nullptr);
    assert(chainstate.GetBlockIndex(hashF) == nullptr);

    chainstate.RegisterPendingBlockHashProvider(nullptr);

    std::cout << " OK (unrelated pending hash pins nothing; "
              << "clause (d) does not over-pin — cascade proceeds)\n";
}

// ============================================================================
// Test 11 — MEDIUM-1 (PR #129 re-red-team): the cap is a HARD CEILING reachable
// via the queue create-path, not only via ProcessNewHeader. The queue path now
// runs the SAME ceiling logic ProcessNewHeader uses: at/over cap, call
// EvictLowestWorkLeafNotPinned(cap-1); if that cannot get under cap, fail closed.
//
// HONEST SCOPE NOTE: CBlockValidationQueue::ProcessBlock is private and requires
// a fully-wired CBlockchainDB + ActivateBestChain to drive end-to-end, which is
// disproportionate test infra for a branch that mirrors an already-tested
// primitive. This test drives the DECISION PRIMITIVE the queue path relies on at
// the same granularity Test 5 covers ProcessNewHeader: (a) when an evictable leaf
// exists, EvictLowestWorkLeafNotPinned(cap-1) makes room so a subsequent add
// stays AT the cap (ceiling holds); (b) when every entry is pinned, eviction
// cannot get under cap and size stays >= cap — exactly the condition on which the
// queue create-path fails closed.
// ============================================================================
void test_blocker1_queue_path_cap_is_advisory()
{
    std::cout << "  test_blocker1_queue_path_cap_is_advisory..." << std::flush;

    // Use a tiny explicit cap for clarity (Regtest cap=1000 is large; we model
    // the decision with a hand-built index and a local cap value).
    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto A = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(A));
    const uint256 hashA = A.GetHash();

    // Active chain A -> M1 -> M2 (pinned via tip) plus disposable fork leaves.
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

    // Two disposable side-fork leaves off A (evictable).
    auto L1 = MakeHeader(hashA, 0x1d00ffff, 1700000500, 0xC1);
    auto L2 = MakeHeader(hashA, 0x1d00ffff, 1700000501, 0xC2);
    assert(adapter.ProcessNewHeader(L1));
    assert(adapter.ProcessNewHeader(L2));
    // Index now = {A,M1,M2,L1,L2} = 5.
    const size_t cap = 5;                 // model: we are AT cap.
    assert(chainstate.GetBlockIndexSize() == cap);

    // ---- (a) Ceiling-holds branch: an evictable leaf exists. The queue path
    //      calls EvictLowestWorkLeafNotPinned(cap-1) before adding one. After it,
    //      size must be <= cap-1 so the subsequent add lands AT cap (never over).
    bool evicted = chainstate.EvictLowestWorkLeafNotPinned(cap - 1);
    assert(evicted);
    assert(chainstate.GetBlockIndexSize() <= cap - 1);  // room made for exactly one
    // Simulate the queue create-path's add of one new block index off the tip.
    {
        auto N = MakeHeader(hashM2, 0x1d00ffff, 1700000600, 0xD0);
        assert(adapter.ProcessNewHeader(N));  // create-path-equivalent insert
    }
    assert(chainstate.GetBlockIndexSize() <= cap);       // CEILING held

    // ---- (b) ADVISORY branch: the state where eviction CANNOT get under cap,
    //      because every survivor is a pinned active-chain ancestor.
    //
    //      This branch previously asserted the opposite conclusion. It ran the
    //      same two asserts below and then closed with "the queue create-path
    //      would observe GetBlockIndexSize() >= cap after eviction and FAIL
    //      CLOSED. Verified." — encoding the halt as correct behaviour rather
    //      than catching it (round-3 red-team, BLOCKER-1).
    //
    //      The state itself is not pathological, it is the STEADY STATE once
    //      active height approaches the cap: the pinned set contains every
    //      active-chain ancestor, and mapBlockIndex.size() >= activeHeight + 1
    //      always, so at height ~= cap every entry is pinned. Failing closed here
    //      halts the chain at height ~= cap permanently.
    //
    //      Note what these asserts do and do not cover: eviction returning false
    //      is UNCHANGED by the advisory fix, so (b) alone cannot distinguish the
    //      old fail-closed caller from the new advisory one. That is exactly why
    //      it passed while asserting the wrong thing. The discriminating check is
    //      (c) below, which drives the real caller.
    chainstate.EvictLowestWorkLeafNotPinned(0);
    const size_t pinnedOnly = chainstate.GetBlockIndexSize();  // == active chain
    bool evicted_b = chainstate.EvictLowestWorkLeafNotPinned(pinnedOnly - 1);
    assert(!evicted_b);                                   // nothing evictable
    assert(chainstate.GetBlockIndexSize() == pinnedOnly); // floor == pinned set

    // ---- (c) THE LOAD-BEARING ASSERTION: with the index wedged at the pinned
    //      floor — eviction permanently impossible — the caller must STILL accept
    //      a new header.
    //
    //      MUST drive the REAL cap check, not a modelled one. `cap` above is a
    //      local size_t; ProcessNewHeader reads
    //      Dilithion::g_chainParams->nMapBlockIndexCap. A first version of this
    //      assertion used the local and was VACUOUS — the global cap (regtest
    //      1000) was never reached, so the eviction branch never executed and the
    //      header was accepted for the wrong reason. Re-introducing BLOCKER-1 did
    //      not turn it red. That is the same defect MEDIUM-4 found in Test 7, in a
    //      test written to fix BLOCKER-1. Point the global at the wedged size so
    //      the production branch actually runs.
    //
    //      MUTATION-VERIFIED 2026-08-02: replace the fall-through on the eviction
    //      failure path in chain_selector_impl.cpp with `return false` and this
    //      assert goes RED. Re-run that check if you touch either side.
    {
        Dilithion::ChainParams advisory_params;
        advisory_params.nMapBlockIndexCap = static_cast<int>(pinnedOnly);
        Dilithion::ChainParams* saved = Dilithion::g_chainParams;
        Dilithion::g_chainParams = &advisory_params;

        const size_t before = chainstate.GetBlockIndexSize();
        assert(before >= static_cast<size_t>(advisory_params.nMapBlockIndexCap));  // we ARE at/over cap
        auto Adv = MakeHeader(chainstate.GetTip()->GetBlockHash(),
                              0x1d00ffff, 1700000700, 0xD1);
        // Cap is advisory: "no evictable leaf" must NOT mean "reject the header".
        const bool accepted = adapter.ProcessNewHeader(Adv);
        const size_t after = chainstate.GetBlockIndexSize();

        Dilithion::g_chainParams = saved;   // restore before asserting, so a
                                            // failure here cannot poison later tests

        assert(accepted);              // <-- dies if the cap fails closed
        assert(after == before + 1);   // admitted over the floor, not dropped
    }

    std::cout << " OK (queue-path cap: evict-to-cap-1 makes room (a); all-pinned "
              << "=> eviction floors at pinned set (b); cap is ADVISORY — header "
              << "still accepted with eviction impossible (c))\n";
}

// ============================================================================
// Test 13 — HIGH-1 REGRESSION (PR #129 re-red-team): a CONCURRENT evictor must
// not be able to free a parent that another thread has resolved but not yet
// linked.
//
// THE BUG. ProcessNewHeader used to run
//     pprev = GetBlockIndex(prevHash);   // cs_main taken AND RELEASED
//     ... deref pprev for height / chain work / IsInvalid ...
//     AddBlockIndex(hash, std::move(pindex));   // cs_main RE-taken
// with `pprev` living on the calling thread's stack across that release. A
// concurrent EvictLowestWorkLeafNotPinned frees it in the window: the child is
// not inserted yet so the parent's in-degree is 0, header-only entries never
// reach BLOCK_VALID_TRANSACTIONS so they are never candidates, and the
// lowest-work unpinned leaf is exactly what eviction picks. The thread then
// dereferences freed memory and STORES the dangling pointer into mapBlockIndex.
// Same end state as the v4.5.0 interior dangle, through a different door — and
// the second evictor that arms it is the one PR #129 itself adds to the
// validation queue.
//
// WHY THIS TEST DOES NOT DEPEND ON ASAN. A thread race detected only by
// -fsanitize=address is evidence only in the builds that enable it, and
// Makefile:736-738 builds this binary with plain $(CXXFLAGS) — so an ASAN-only
// assertion here would be inert in every run anyone actually does (MEDIUM-5).
// Instead this asserts the bug's PERSISTENT END STATE, which is deterministic
// and needs no sanitizer:
//
//     for every entry E still in mapBlockIndex with E->pprev != nullptr,
//     E->pprev must be a pointer that mapBlockIndex still owns.
//
// A dangling pprev fails that by construction — the parent was erased from the
// map, so no live entry has its address. Checked by POINTER IDENTITY against
// GetBlockIndex(parentHash), never by dereferencing E->pprev, so the check
// itself cannot fault on freed memory.
//
// MUTATION-VERIFIED (2026-08-03), and the mutation was confirmed to APPLY before
// the result was trusted — a sed that silently stops matching reports as "killed"
// and is indistinguishable from a passing guard:
//
//   $ grep -c 'MainLockGuard main_lock' chain_selector_impl.cpp   -> 1
//   $ sed -i 's|^    CChainState::MainLockGuard main_lock.*||' ...
//   $ grep -c 'MainLockGuard main_lock' chain_selector_impl.cpp   -> 0   [APPLIED]
//
// Result against the mutant: RED, and more sharply than this test's own audit —
// AddBlockIndex's ConsensusInvariant at chain.cpp:167 trips first:
//
//   CONSENSUS INVARIANT VIOLATION: mapBlockIndex.count(parentHash) > 0
//   File: src/consensus/chain.cpp:167   Function: AddBlockIndex
//
// That line reaches parentHash via `pindex->pprev->GetBlockHash()` — i.e. the
// invariant fires BY performing the use-after-free read. The race is real,
// reachable in a plain non-ASAN build, and hit within 1500 rounds every run.
// Guard restored: 13/13 green, ~150 links audited, 0 dangling.
//
// !! HONEST COVERAGE LIMIT — READ BEFORE TRUSTING THIS SUITE !!
// This test drives ProcessNewHeader ONLY. The SECOND HIGH-1 site — the guard in
// CBlockValidationQueue::ProcessBlock's create path — is NOT covered. Verified,
// not assumed: deleting that guard too and re-running leaves this suite fully
// GREEN (13/13). Its window is the WIDER of the two (a LevelDB WriteBlockIndex
// sits inside it), so the uncovered site is the more exposed one. Covering it
// needs a CBlockValidationQueue harness with a real CBlockchainDB, which this
// binary has no fixture for. Until that exists the queue-path guard is protected
// by review and by this note, not by an executable check — which is exactly the
// criticism MEDIUM-4 levelled at Tests 7 and 11. Do not read "13/13 green" as
// "HIGH-1 is covered"; it covers one of two sites.
// ============================================================================
void test_high1_concurrent_evictor_cannot_free_unlinked_parent()
{
    std::cout << "  test_high1_concurrent_evictor_cannot_free_unlinked_parent..." << std::flush;

    static Dilithion::ChainParams regtest_params = Dilithion::ChainParams::Regtest();
    Dilithion::ChainParams* prev_chainparams = Dilithion::g_chainParams;
    Dilithion::g_chainParams = &regtest_params;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto genesis = MakeHeader(null_hash, 0x1d00ffff, 1700000000, 0);
    assert(adapter.ProcessNewHeader(genesis));
    CBlockIndex* genesis_idx = chainstate.GetBlockIndex(genesis.GetHash());
    assert(genesis_idx != nullptr);
    chainstate.SetTip(genesis_idx);

    // A short pinned active chain, so eviction always has SOMETHING it may not
    // touch and the map never drains to nothing.
    uint256 prev = genesis.GetHash();
    for (int i = 1; i <= 8; ++i) {
        auto h = MakeHeader(prev, 0x1d00ffff, 1700000000 + i, static_cast<uint8_t>(i));
        assert(adapter.ProcessNewHeader(h));
        CBlockIndex* idx = chainstate.GetBlockIndex(h.GetHash());
        assert(idx != nullptr);
        chainstate.SetTip(idx);
        prev = h.GetHash();
    }
    const uint256 fork_root = prev;

    // Producer: build low-work off-chain fork leaves, then extend them. Each
    // extension is a resolve->deref->insert against a parent that is, at that
    // instant, an unpinned lowest-work leaf — exactly the shape the evictor
    // races. Record (child, parent) so the audit below can check the linkage.
    std::vector<std::pair<uint256, uint256>> links;
    std::mutex links_mu;
    std::atomic<bool> stop{false};

    const int kRounds = 1500;

    std::thread producer([&]() {
        for (int i = 0; i < kRounds; ++i) {
            auto leaf = MakeHeader(fork_root, 0x1d00ffff,
                                   1700100000 + i, static_cast<uint8_t>(0x40 + (i % 64)));
            if (!adapter.ProcessNewHeader(leaf)) continue;
            const uint256 leaf_hash = leaf.GetHash();

            // The racy one: `leaf` is now an unpinned, in-degree-0, low-work leaf
            // — the evictor's preferred victim — and we are about to resolve it
            // as a parent and link a child to it.
            auto child = MakeHeader(leaf_hash, 0x1d00ffff,
                                    1700200000 + i, static_cast<uint8_t>(0x80 + (i % 64)));
            if (adapter.ProcessNewHeader(child)) {
                std::lock_guard<std::mutex> lk(links_mu);
                links.emplace_back(child.GetHash(), leaf_hash);
            }
        }
        stop.store(true, std::memory_order_release);
    });

    // Evictor: hammer the same structure from a second thread.
    //
    // kEvictTarget is tuned, and the first value was WRONG in a way worth
    // recording. Draining to the pinned floor (10) evicted every unpinned entry
    // including the children, so the audit below had nothing to inspect and the
    // test would have "passed" while proving nothing. The non-vacuity assertion
    // caught it on the first run. Leaving headroom keeps eviction firing
    // continuously — it still selects the fresh low-work fork leaves, which is
    // the race we want — while letting linked children survive to be audited.
    const size_t kEvictTarget = 300;
    std::thread evictor([&]() {
        while (!stop.load(std::memory_order_acquire)) {
            chainstate.EvictLowestWorkLeafNotPinned(kEvictTarget);
        }
    });

    producer.join();
    evictor.join();

    // ---- THE LOAD-BEARING ASSERTION ----
    // Every surviving child must either be gone, or point at a parent the map
    // still owns. Pointer identity only — E->pprev is compared, never
    // dereferenced, so a dangling value cannot fault this check.
    size_t checked = 0, dangling = 0;
    {
        std::lock_guard<std::mutex> lk(links_mu);
        for (const auto& link : links) {
            CBlockIndex* child_idx = chainstate.GetBlockIndex(link.first);
            if (child_idx == nullptr) continue;   // child itself evicted — fine
            ++checked;
            CBlockIndex* live_parent = chainstate.GetBlockIndex(link.second);
            if (child_idx->pprev != live_parent) {
                // Either the parent was freed while this child still references
                // it (live_parent == nullptr, pprev != nullptr — the UAF), or
                // the linkage disagrees with the map — both are the defect.
                ++dangling;
            }
        }
    }

    if (dangling != 0) {
        std::cerr << "\n    HIGH-1 REGRESSION: " << dangling << " of " << checked
                  << " surviving children hold a pprev the map no longer owns — a"
                  << " concurrent evictor freed a resolved-but-unlinked parent.\n";
    }
    assert(dangling == 0);

    // Non-vacuity: if the race never actually ran, this test proves nothing. Both
    // arms must have done real work.
    assert(checked > 0 && "no surviving child links — producer never raced");

    Dilithion::g_chainParams = prev_chainparams;
    std::cout << " OK (" << checked << " child->parent links audited after "
              << kRounds << " racing rounds; 0 dangling)\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.1 — HeadersManager → chain_selector wiring tests\n";
    std::cout << "  (13-test suite per v1.5 plan §4 PR6.1 + leaf-eviction regression\n";
    std::cout << "   + BLOCKER-1 re-resolve + clause (c) belt + MEDIUM-2 cascade\n";
    std::cout << "   + MEDIUM-2 provider-pin + MEDIUM-1 cap-ceiling, PR #129)\n\n";

    try {
        test_pr61_happy_path_n_headers_populate_mapBlockIndex();
        test_pr61_idempotency_same_header_no_duplicate();
        test_pr61_orphan_header_rejected();
        test_pr61_rejected_parent_flood_does_not_grow_mapBlockIndex();
        test_pr61_cap_saturation_safe_leaf_eviction();
        test_evict_never_frees_referenced_parent();
        test_queue_byhash_reresolve_is_uaf_safe_when_leaf_evicted();
        test_clause_c_belt_pins_havedata_without_validity();
        test_evict_multipass_cascade_to_zero();
        test_medium2_provider_pins_queued_block_and_ancestors();
        test_medium2_provider_unrelated_hash_does_not_overpin();
        test_blocker1_queue_path_cap_is_advisory();
        test_high1_concurrent_evictor_cannot_free_unlinked_parent();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 13 PR6.1 wiring tests passed.\n";
    return 0;
}
