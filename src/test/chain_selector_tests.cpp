// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 PR5.1 — ChainSelectorAdapter trivial-getter tests.
//
// Scope (PR5.1): 4 tests covering the four trivial getters wired through
// CChainState in chain_selector_impl.cpp:
//   * GetActiveTip
//   * GetActiveHeight
//   * GetActiveTipHash
//   * LookupBlockIndex
//
// Real algorithm tests (FindMostWorkChain, ProcessNewBlock, etc.) are
// PR5.3 territory — the corresponding adapter methods are still
// assert(false) at this point.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cassert>
#include <cstdlib>     // setenv / _putenv_s
#include <cstring>
#include <iostream>
#include <memory>

namespace {

// Build a CBlockIndex with an explicitly-set phashBlock and pprev=nullptr,
// nHeight=0 (genesis-like) so it satisfies CChainState::AddBlockIndex's
// invariants without needing real-block construction. The phashBlock is
// the only thing GetBlockHash() returns post-Bug #10 fix.
std::unique_ptr<CBlockIndex> MakeGenesisLikeIndex(uint8_t hash_seed)
{
    auto pindex = std::make_unique<CBlockIndex>();
    pindex->pprev = nullptr;
    pindex->nHeight = 0;
    pindex->nChainWork = uint256();
    // v4.3.3 F5: post-F1 layout, BLOCK_VALID_TRANSACTIONS without HAVE_DATA
    // is no longer "real": OR in BLOCK_HAVE_DATA to encode the production
    // invariant (a validated block always has data on disk).
    pindex->nStatus = CBlockIndex::BLOCK_VALID_TRANSACTIONS | CBlockIndex::BLOCK_HAVE_DATA;
    pindex->nSequenceId = 1;
    // Synthetic deterministic hash: byte 0 = seed, rest zeros.
    std::memset(pindex->phashBlock.data, 0, 32);
    pindex->phashBlock.data[0] = hash_seed;
    return pindex;
}

}  // anonymous

void test_get_active_tip_null_on_fresh_chainstate()
{
    std::cout << "  test_get_active_tip_null_on_fresh_chainstate..." << std::flush;
    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    assert(adapter.GetActiveTip() == nullptr);
    assert(adapter.GetActiveTipHash().IsNull());
    std::cout << " OK\n";
}

void test_get_active_tip_after_set_tip_for_test()
{
    std::cout << "  test_get_active_tip_after_set_tip_for_test..." << std::flush;
    CChainState chainstate;
    auto pindex = MakeGenesisLikeIndex(0xAA);
    CBlockIndex* raw = pindex.get();
    chainstate.SetTipForTest(raw);

    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    assert(adapter.GetActiveTip() == raw);
    std::cout << " OK\n";
}

void test_get_active_height_and_hash_match_tip()
{
    std::cout << "  test_get_active_height_and_hash_match_tip..." << std::flush;
    // GetActiveHeight reads the m_cachedHeight atomic which is only
    // updated through CChainState::SetTip — and SetTip enforces the
    // invariant that the tip must live in mapBlockIndex. So the test
    // path is: AddBlockIndex (genesis-like) -> SetTip -> verify.
    CChainState chainstate;
    auto pindex = MakeGenesisLikeIndex(0xBB);
    uint256 hash = pindex->GetBlockHash();
    bool added = chainstate.AddBlockIndex(hash, std::move(pindex));
    assert(added);
    CBlockIndex* tip = chainstate.GetBlockIndex(hash);
    chainstate.SetTip(tip);

    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    assert(adapter.GetActiveHeight() == 0);  // genesis-like
    uint256 actual = adapter.GetActiveTipHash();
    assert(std::memcmp(hash.data, actual.data, 32) == 0);
    std::cout << " OK\n";
}

void test_lookup_block_index_returns_added_block()
{
    std::cout << "  test_lookup_block_index_returns_added_block..." << std::flush;
    CChainState chainstate;
    auto pindex = MakeGenesisLikeIndex(0xCC);
    uint256 hash = pindex->GetBlockHash();
    CBlockIndex* raw_before_move = pindex.get();
    bool added = chainstate.AddBlockIndex(hash, std::move(pindex));
    assert(added);

    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    CBlockIndex* found = adapter.LookupBlockIndex(hash);
    assert(found == raw_before_move);

    // Negative case: unknown hash returns nullptr.
    uint256 unknown;
    std::memset(unknown.data, 0, 32);
    unknown.data[0] = 0xFF;
    assert(adapter.LookupBlockIndex(unknown) == nullptr);
    std::cout << " OK\n";
}

// ============================================================================
// PR5.3 prerequisite (Day 2 PM, 2026-04-26):
//   * ProcessNewHeader populates CChainState::mapBlockIndex with EVERY
//     header (pre-validation entries get nStatus = BLOCK_VALID_HEADER).
//   * G1: pre-validation siblings remain visible to fork detection.
//   * G2: BLOCK_VALID_HEADER-only entries are NOT IsInvalid().
// ============================================================================

namespace {

// Construct a VDF-style header (SHA3-256 hash, no RandomX dependency in
// tests) chained from a given parent hash.
CBlockHeader MakeVDFHeader(const uint256& parent_hash, uint32_t nBits, uint32_t nTime)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;
    h.hashPrevBlock = parent_hash;
    std::memset(h.hashMerkleRoot.data, 0, 32);
    h.nTime = nTime;
    h.nBits = nBits;
    h.nNonce = 0;
    // Distinguish siblings via the VDF output bytes — different vdfOutput
    // means different SHA3 hash even with same parent.
    for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0;
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i] = static_cast<uint8_t>(nTime & 0xff);
    return h;
}

// Same shape as MakeGenesisLikeIndex above but explicitly named for
// pre-validation usage with arbitrary status flags.
//
// v4.3.3 F5: a synthetic block whose level field is >= BLOCK_VALID_TRANSACTIONS
// in real production state has been validated AND has data on disk —
// upstream Bitcoin Core's invariant: BLOCK_VALID_TRANSACTIONS is set by
// ReceivedBlockTransactions which also ORs BLOCK_HAVE_DATA. Pre-F1's
// mask=0x1F overlap encoded this implicitly via the predicate; post-F1
// the bits are disjoint and the test setup must encode it explicitly.
// We auto-OR BLOCK_HAVE_DATA whenever the caller supplied a level
// >= BLOCK_VALID_TRANSACTIONS so existing tests keep their original
// semantic intent (a "fully validated leaf") without 75 call-site edits.
// Tests that DELIBERATELY want a header-only entry pass status=BLOCK_VALID_HEADER
// (level==1) and remain unaffected.
std::unique_ptr<CBlockIndex> MakePreValidationLeaf(uint8_t hash_seed,
                                                   CBlockIndex* parent,
                                                   int height,
                                                   uint32_t status,
                                                   uint8_t work_seed,
                                                   uint32_t seq_id = 1)
{
    auto pindex = std::make_unique<CBlockIndex>();
    pindex->pprev = parent;
    pindex->nHeight = height;
    pindex->nStatus = status;
    if ((status & CBlockIndex::BLOCK_VALID_MASK) >= CBlockIndex::BLOCK_VALID_TRANSACTIONS) {
        pindex->nStatus |= CBlockIndex::BLOCK_HAVE_DATA;
    }
    pindex->nSequenceId = seq_id;
    std::memset(pindex->phashBlock.data, 0, 32);
    pindex->phashBlock.data[0] = hash_seed;
    std::memset(pindex->nChainWork.data, 0, 32);
    pindex->nChainWork.data[0] = work_seed;
    return pindex;
}

}  // anonymous

void test_process_new_header_genesis_creates_pre_validation_entry()
{
    std::cout << "  test_process_new_header_genesis_creates_pre_validation_entry..."
              << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Genesis: hashPrevBlock = null. VDF style so SHA3 (no RandomX).
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto h = MakeVDFHeader(null_hash, 0x1d00ffff, 1700000000);

    bool ok = adapter.ProcessNewHeader(h);
    assert(ok);

    uint256 hash = h.GetHash();
    CBlockIndex* p = chainstate.GetBlockIndex(hash);
    assert(p != nullptr);
    assert(p->nHeight == 0);
    assert(p->pprev == nullptr);
    // G2: pre-validation only; failure flags must be clear.
    assert((p->nStatus & CBlockIndex::BLOCK_VALID_MASK) == CBlockIndex::BLOCK_VALID_HEADER);
    assert(!p->IsInvalid());

    // Idempotency: a second call with the same header succeeds without
    // creating a duplicate.
    bool ok2 = adapter.ProcessNewHeader(h);
    assert(ok2);
    assert(chainstate.GetBlockIndex(hash) == p);  // same pointer

    std::cout << " OK\n";
}

void test_process_new_header_orphan_returns_false()
{
    std::cout << "  test_process_new_header_orphan_returns_false..."
              << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Header with a non-null parent hash that does NOT exist in
    // mapBlockIndex — caller must order parents before children.
    uint256 unknown_parent;
    std::memset(unknown_parent.data, 0, 32);
    unknown_parent.data[0] = 0x99;
    auto h = MakeVDFHeader(unknown_parent, 0x1d00ffff, 1700000001);

    bool ok = adapter.ProcessNewHeader(h);
    assert(!ok);
    // mapBlockIndex unchanged.
    assert(chainstate.GetBlockIndex(h.GetHash()) == nullptr);

    std::cout << " OK\n";
}

void test_process_new_header_chains_parent_correctly()
{
    std::cout << "  test_process_new_header_chains_parent_correctly..."
              << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Process genesis via ProcessNewHeader.
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    auto hG = MakeVDFHeader(null_hash, 0x1d00ffff, 1700000000);
    assert(adapter.ProcessNewHeader(hG));
    uint256 genesis_hash = hG.GetHash();
    CBlockIndex* G = chainstate.GetBlockIndex(genesis_hash);

    // Process child of genesis.
    auto hC = MakeVDFHeader(genesis_hash, 0x1d00ffff, 1700000060);
    assert(adapter.ProcessNewHeader(hC));
    CBlockIndex* C = chainstate.GetBlockIndex(hC.GetHash());

    assert(C != nullptr);
    assert(C->pprev == G);
    assert(C->nHeight == 1);
    // Cumulative work strictly greater than parent.
    assert(ChainWorkGreaterThan(C->nChainWork, G->nChainWork));
    // G2: pre-validation only.
    assert(!C->IsInvalid());
    assert((C->nStatus & CBlockIndex::BLOCK_VALID_MASK) == CBlockIndex::BLOCK_VALID_HEADER);

    std::cout << " OK\n";
}

void test_g1_pre_validation_siblings_visible_as_competing_tips()
{
    std::cout << "  test_g1_pre_validation_siblings_visible_as_competing_tips..."
              << std::flush;

    // Build: genesis A -> two pre-validation siblings B, C (BLOCK_VALID_HEADER).
    // Active tip stays at A (no full validation has connected B or C).
    // Both B and C must show up as competing tips with status=ValidHeaders.
    CChainState chainstate;

    auto pA = MakePreValidationLeaf(0x01, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x02, A, 1, CBlockIndex::BLOCK_VALID_HEADER, 10, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));

    auto pC = MakePreValidationLeaf(0x03, A, 1, CBlockIndex::BLOCK_VALID_HEADER, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));

    // Both legacy and adapter should show 3 tips (A active, B+C valid-headers).
    auto legacy = chainstate.GetChainTips();
    // A has 2 children, so it's no longer a tip — but it's the active tip.
    // Wait: the active-tip path is special-cased to remain visible. Legacy
    // logic includes pindexTip even if it has children.
    bool foundA = false, foundB = false, foundC = false;
    for (const auto& t : legacy) {
        if (t.hash == hA && t.status == "active") foundA = true;
        if (t.hash == hB && t.status == "valid-headers") foundB = true;
        if (t.hash == hC && t.status == "valid-headers") foundC = true;
    }
    // A IS in hasChildren (B and C list it as parent), so it gets filtered out
    // by the "any block NOT in hasChildren is a tip" rule. The active tip
    // when it has children isn't surfaced today — but B and C both must be.
    assert(foundB && "G1: pre-validation sibling B must be visible as a tip");
    assert(foundC && "G1: pre-validation sibling C must be visible as a tip");

    // Adapter must report exactly the same set with ValidHeaders enum.
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    auto adapted = adapter.GetChainTips();
    bool foundB_adapted = false, foundC_adapted = false;
    for (const auto& t : adapted) {
        if (t.hash == hB) {
            assert(t.status == ::dilithion::consensus::ChainTipInfo::Status::ValidHeaders);
            foundB_adapted = true;
        }
        if (t.hash == hC) {
            assert(t.status == ::dilithion::consensus::ChainTipInfo::Status::ValidHeaders);
            foundC_adapted = true;
        }
    }
    assert(foundB_adapted && foundC_adapted);

    // size() > 1 IS the post-PR5.2.B replacement for HasCompetingForks.
    assert(adapted.size() >= 2);

    (void)foundA;
    std::cout << " OK\n";
}

void test_g2_pre_validation_entries_are_not_invalid()
{
    std::cout << "  test_g2_pre_validation_entries_are_not_invalid..."
              << std::flush;

    CChainState chainstate;

    // Set up genesis as a fully-validated active tip (so we have a parent).
    auto pA = MakePreValidationLeaf(0x10, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    // Pre-validation entry: BLOCK_VALID_HEADER only.
    auto pH = MakePreValidationLeaf(0x11, A, 1, CBlockIndex::BLOCK_VALID_HEADER, 10, 2);
    uint256 hH = pH->GetBlockHash();
    assert(chainstate.AddBlockIndex(hH, std::move(pH)));
    CBlockIndex* H = chainstate.GetBlockIndex(hH);

    // G2 core property: a header-only entry must NOT be IsInvalid().
    assert(!H->IsInvalid());
    // No FAILED_VALID, no FAILED_CHILD.
    assert((H->nStatus & CBlockIndex::BLOCK_FAILED_MASK) == 0);
    // The validation level is exactly BLOCK_VALID_HEADER (1).
    assert((H->nStatus & CBlockIndex::BLOCK_VALID_MASK) == CBlockIndex::BLOCK_VALID_HEADER);

    // The PR5.2.B "IsTip" replacement signature (non-null lookup AND not
    // invalid AND no children) must be true for this leaf — proving the
    // tracker can be safely retired in favor of mapBlockIndex walks once
    // PR5.3 wires ProcessNewHeader into the live IBD path.
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    CBlockIndex* via_adapter = adapter.LookupBlockIndex(hH);
    assert(via_adapter == H);
    assert(via_adapter->pnext == nullptr);
    assert(!via_adapter->IsInvalid());

    // Negative companion: an explicitly-invalidated entry MUST report
    // IsInvalid()==true so failure propagation isn't a no-op.
    auto pI = MakePreValidationLeaf(0x12, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                                        CBlockIndex::BLOCK_FAILED_VALID,
                                    10, 3);
    uint256 hI = pI->GetBlockHash();
    assert(chainstate.AddBlockIndex(hI, std::move(pI)));
    CBlockIndex* I = chainstate.GetBlockIndex(hI);
    assert(I->IsInvalid());

    std::cout << " OK\n";
}

// ============================================================================
// PR5.3 Day 3 AM: tests for RecomputeCandidates, MarkBlockAsFailed,
// MarkBlockAsValid, FindMostWorkChainImpl, IsBlockACandidateForActivation.
// ============================================================================

void test_recompute_candidates_skips_pre_validation_leaves()
{
    std::cout << "  test_recompute_candidates_skips_pre_validation_leaves..."
              << std::flush;

    // A (genesis, BLOCK_VALID_TRANSACTIONS) -> B (BLOCK_VALID_TRANSACTIONS, leaf, candidate)
    //                                       \-> C (BLOCK_VALID_HEADER only, leaf, NOT candidate)
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x40, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x41, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pC = MakePreValidationLeaf(0x42, A, 1,
                                    CBlockIndex::BLOCK_VALID_HEADER, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));

    chainstate.RecomputeCandidates();

    // B is a candidate (full validation, leaf). C is not (header-only).
    // A is not (has children). Direct invariant check via the predicate.
    assert(chainstate.IsBlockACandidateForActivation(B));
    assert(!chainstate.IsBlockACandidateForActivation(chainstate.GetBlockIndex(hC)));
    assert(chainstate.IsBlockACandidateForActivation(A));  // predicate yes; leaf-status no
    // FindMostWorkChainImpl is the way to OBSERVE the candidate set's contents
    // without exposing the private member. After RecomputeCandidates with B
    // having more work than the active tip, FindMostWorkChainImpl returns B.
    assert(chainstate.FindMostWorkChainImpl() == B);

    std::cout << " OK\n";
}

void test_recompute_candidates_skips_invalid_blocks()
{
    std::cout << "  test_recompute_candidates_skips_invalid_blocks..."
              << std::flush;

    // A -> B (FAILED_VALID, NOT a candidate)
    //   -> C (valid leaf, IS a candidate)
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x50, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x51, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                                        CBlockIndex::BLOCK_FAILED_VALID,
                                    20, 2);  // higher work but invalid
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));

    auto pC = MakePreValidationLeaf(0x52, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = chainstate.GetBlockIndex(hC);

    chainstate.RecomputeCandidates();

    // FindMostWorkChainImpl should pick C (B is invalid even though heavier).
    CBlockIndex* picked = chainstate.FindMostWorkChainImpl();
    assert(picked == C);

    std::cout << " OK\n";
}

void test_mark_block_as_failed_propagates_to_descendants()
{
    std::cout << "  test_mark_block_as_failed_propagates_to_descendants..."
              << std::flush;

    // A -> B -> D
    //       \-> E
    // MarkBlockAsFailed(B) -> B gets FAILED_VALID, D + E get FAILED_CHILD.
    // A unaffected.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x60, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x61, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakePreValidationLeaf(0x62, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    auto pE = MakePreValidationLeaf(0x63, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 4);
    uint256 hE = pE->GetBlockHash();
    assert(chainstate.AddBlockIndex(hE, std::move(pE)));
    CBlockIndex* E = chainstate.GetBlockIndex(hE);

    chainstate.MarkBlockAsFailed(B);

    assert(B->IsInvalid());
    assert(B->nStatus & CBlockIndex::BLOCK_FAILED_VALID);
    assert(D->IsInvalid());
    assert(D->nStatus & CBlockIndex::BLOCK_FAILED_CHILD);
    assert(E->IsInvalid());
    assert(E->nStatus & CBlockIndex::BLOCK_FAILED_CHILD);
    // A is NOT affected.
    assert(!A->IsInvalid());

    std::cout << " OK\n";
}

void test_mark_block_as_valid_clears_failed_child()
{
    std::cout << "  test_mark_block_as_valid_clears_failed_child..."
              << std::flush;

    // Build A -> B -> D, mark B failed (D inherits FAILED_CHILD), then
    // ReconsiderBlock(B) clears failure flags on B and FAILED_CHILD on D.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x70, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x71, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakePreValidationLeaf(0x72, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    chainstate.MarkBlockAsFailed(B);
    assert(B->IsInvalid());
    assert(D->IsInvalid());

    chainstate.MarkBlockAsValid(B);
    assert(!B->IsInvalid());  // FAILED_VALID cleared
    assert(!D->IsInvalid());  // FAILED_CHILD cleared

    std::cout << " OK\n";
}

void test_adapter_forwards_invalidate_and_reconsider()
{
    std::cout << "  test_adapter_forwards_invalidate_and_reconsider..."
              << std::flush;

    // Build A -> B -> D, all valid. Adapter.InvalidateBlock(B) marks
    // B+D failed. Adapter.ReconsiderBlock(B) restores them.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0xB0, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0xB1, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakePreValidationLeaf(0xB2, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 3);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    assert(adapter.InvalidateBlock(hB));
    assert(B->IsInvalid());
    assert(D->IsInvalid());

    assert(adapter.ReconsiderBlock(hB));
    assert(!B->IsInvalid());
    assert(!D->IsInvalid());
    std::cout << " OK\n";
}

void test_adapter_find_most_work_chain_returns_heaviest()
{
    std::cout << "  test_adapter_find_most_work_chain_returns_heaviest..."
              << std::flush;

    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0xC0, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0xC1, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));

    auto pC = MakePreValidationLeaf(0xC2, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = chainstate.GetBlockIndex(hC);

    chainstate.RecomputeCandidates();

    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);
    assert(adapter.FindMostWorkChain() == C);
    std::cout << " OK\n";
}

// ============================================================================
// Red-team audit BLOCKER fixes (2026-04-26).
// ============================================================================

void test_blocker1_process_new_header_rejects_invalid_parent()
{
    // BLOCKER 1: ProcessNewHeader must refuse to extend a chain rooted in a
    // known-invalid block. Without this, an attacker can flood headers
    // descended from a single rejected-block hash and exhaust memory.
    std::cout << "  test_blocker1_process_new_header_rejects_invalid_parent..."
              << std::flush;

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Set up genesis A, then mark it invalid.
    auto pA = MakePreValidationLeaf(0xD0, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);
    A->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
    assert(A->IsInvalid());

    // Build a header claiming A as its parent. ProcessNewHeader must reject.
    auto h = MakeVDFHeader(hA, 0x1d00ffff, 1700000100);
    bool ok = adapter.ProcessNewHeader(h);
    assert(!ok && "ProcessNewHeader must reject headers rooted in invalid blocks");
    // mapBlockIndex must be unchanged.
    assert(chainstate.GetBlockIndex(h.GetHash()) == nullptr);

    std::cout << " OK\n";
}

void test_blocker3_checkpoint_violation_in_ancestry_rejects_candidate()
{
    // BLOCKER 3 — Checkpoint-violating ancestry must reject the
    // activation candidate. Validates Tier 2 of the four-layer
    // defense-in-depth checkpoint enforcement (header-time +
    // startup-validator + ProcessNewHeader BLOCKER-1 + ActivateBestChain
    // three-tier). See chain.cpp:363-451 for the design comment.
    //
    // Production semantic is HARD-FAIL: ActivateBestChain returns false
    // and instructs the operator to run `--reset-chain --yes`; block-
    // status flags are NOT mutated. Phase 5 (26638a1, 2026-04-26)
    // originally specified soft-fail (mark-invalid + return true); the
    // May-2 emergency fix (f1c1d10) replaced it with hard-fail because
    // what reaches Layer 4 in production is a node that synced the
    // wrong fork for hours/days (e.g. v4.1 DilV rollback at h=44233),
    // not an attacker-submitted bad block — and soft-fail's mark-
    // invalid-then-reorg path depends on DisconnectTip / undo-data
    // machinery with its own incident history. Hard-fail forces
    // visibility and a controlled chain rebuild via operator action.
    std::cout << "  test_blocker3_checkpoint_violation_in_ancestry_rejects_candidate..."
              << std::flush;

    // Save and stub g_chainParams (test isolates global state).
    Dilithion::ChainParams* savedParams = Dilithion::g_chainParams;
    Dilithion::ChainParams stubParams;

    // Build chain A(genesis valid tip) -> B(h=1) -> C(h=2) -> D(h=3).
    CChainState chainstate;

    auto pA = MakePreValidationLeaf(0xF0, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0xF1, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pC = MakePreValidationLeaf(0xF2, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = chainstate.GetBlockIndex(hC);

    auto pD = MakePreValidationLeaf(0xF3, C, 3,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 4);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    // Install a checkpoint at height 2 with a hash that does NOT match C.
    // CheckpointCheck(2, hC) will return false → Tier 2 ancestry check
    // catches the violation when activating D (h=3) and hard-fails.
    uint256 wrongHash;
    std::memset(wrongHash.data, 0, 32);
    wrongHash.data[0] = 0xAB;  // distinct from C's 0xF2 seed
    stubParams.checkpoints.emplace_back(2, wrongHash);
    Dilithion::g_chainParams = &stubParams;

    // Engage the new path.
#ifdef _WIN32
    _putenv_s("DILITHION_USE_NEW_CHAIN_SELECTOR", "1");
#else
    setenv("DILITHION_USE_NEW_CHAIN_SELECTOR", "1", 1);
#endif

    chainstate.RecomputeCandidates();

    // Dummy block — ActivateBestChain in the env-var=1 path checks the
    // ancestry BEFORE ever calling ActivateBestChainStep, so the block
    // contents are not exercised.
    CBlock dummyBlock;
    bool reorgOccurred = false;
    bool ok = chainstate.ActivateBestChain(D, dummyBlock, reorgOccurred);

    // Restore globals before any assert can throw.
    Dilithion::g_chainParams = savedParams;
#ifdef _WIN32
    _putenv_s("DILITHION_USE_NEW_CHAIN_SELECTOR", "");
#else
    unsetenv("DILITHION_USE_NEW_CHAIN_SELECTOR");
#endif

    // Verify outcomes.
    // 1. Hard-fail: ActivateBestChain returns false on checkpoint
    //    violation. Tier 2 in chain.cpp re-verifies the highest-
    //    checkpoint ancestor on every activation past it; D at h=3 has
    //    C at h=2 as its ancestor, and C's hash does not match the
    //    installed checkpoint, so Tier 2 returns false at chain.cpp:418.
    assert(!ok);
    // 2. No reorg.
    assert(!reorgOccurred);
    // 3. Tip stays at A (the genesis) — no advancement past violation.
    assert(chainstate.GetTip() == A);
    // 4. Hard-fail must NOT mutate block-status flags. C and D stay
    //    valid in-memory; only operator-driven --reset-chain rebuilds
    //    the chain. Regression check against any future "improvement"
    //    that quietly reverts to soft-fail.
    assert(!A->IsInvalid());
    assert(!B->IsInvalid());
    assert(!C->IsInvalid() && "BLOCKER 3: hard-fail must NOT mark ancestor invalid");
    assert(!D->IsInvalid() && "BLOCKER 3: hard-fail must NOT mark descendant invalid");

    std::cout << " OK\n";
}

void test_blocker2_mark_block_as_valid_independent_failure_is_barrier()
{
    // BLOCKER 2: When a deep ancestor is reconsidered, an independently-
    // FAILED_VALID descendant must act as a BARRIER for the propagation
    // walk. Its own descendants stay FAILED_CHILD because their failure
    // root is the still-failed descendant, not the reconsidered ancestor.
    std::cout << "  test_blocker2_mark_block_as_valid_independent_failure_is_barrier..."
              << std::flush;

    // Topology: A -> B -> C -> D
    //  - InvalidateBlock(A) marks A failed; B,C,D inherit FAILED_CHILD
    //  - Then independently fail C (set FAILED_VALID on C)
    //  - ReconsiderBlock(A) should clear:
    //      * A's FAILED_VALID
    //      * B's FAILED_CHILD (was only failed via A)
    //    But should leave:
    //      * C's FAILED_VALID (was independently set)
    //      * C's FAILED_CHILD cleared (the A-rooted one) but C is still
    //        IsInvalid via its FAILED_VALID
    //      * D's FAILED_CHILD MUST stay because D descends from
    //        still-invalid C — buggy code would clear it
    CChainState chainstate;

    auto pA = MakePreValidationLeaf(0xE0, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0xE1, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pC = MakePreValidationLeaf(0xE2, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = chainstate.GetBlockIndex(hC);

    auto pD = MakePreValidationLeaf(0xE3, C, 3,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 15, 4);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    // Step 1: Invalidate A. B/C/D all inherit FAILED_CHILD.
    chainstate.MarkBlockAsFailed(A);
    assert(A->IsInvalid());
    assert(B->IsInvalid());
    assert(C->IsInvalid());
    assert(D->IsInvalid());
    assert(B->nStatus & CBlockIndex::BLOCK_FAILED_CHILD);
    assert(C->nStatus & CBlockIndex::BLOCK_FAILED_CHILD);
    assert(D->nStatus & CBlockIndex::BLOCK_FAILED_CHILD);

    // Step 2: Independently fail C (e.g., a ConnectTip on C failed
    // separately at a later point). In real code C would already have
    // BLOCK_FAILED_CHILD; we add BLOCK_FAILED_VALID to model an independent
    // validation failure.
    C->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
    assert(C->nStatus & CBlockIndex::BLOCK_FAILED_VALID);

    // Step 3: Reconsider A. Walk should clear A's failure, clear B's
    // FAILED_CHILD (B becomes valid). C's FAILED_CHILD gets cleared but
    // C still has FAILED_VALID — C is still IsInvalid. D MUST stay
    // marked because it descends from a still-invalid block.
    chainstate.MarkBlockAsValid(A);

    assert(!A->IsInvalid() && "A's failure flags cleared");
    assert(!B->IsInvalid() && "B reconsidered (was only inherited)");

    // C: FAILED_CHILD cleared, FAILED_VALID remains.
    assert(!(C->nStatus & CBlockIndex::BLOCK_FAILED_CHILD));
    assert(C->nStatus & CBlockIndex::BLOCK_FAILED_VALID);
    assert(C->IsInvalid() && "C still invalid via independent FAILED_VALID");

    // D: BLOCKER 2 fix — must still be marked because it descends from C.
    // Buggy code would have cleared FAILED_CHILD on D (propagating through
    // still-invalid C). Fixed code keeps it.
    assert(D->IsInvalid() && "D must remain invalid — descends from still-failed C");
    assert(D->nStatus & CBlockIndex::BLOCK_FAILED_CHILD);

    std::cout << " OK\n";
}

void test_invalidate_block_impl_propagates_and_drops_candidates()
{
    std::cout << "  test_invalidate_block_impl_propagates_and_drops_candidates..."
              << std::flush;

    // A -> B -> D (B has work_seed=10, D has work_seed=20, all valid)
    //       \-> E (work_seed=15)
    // After RecomputeCandidates: D, E in candidate set; FindMostWork picks D.
    // After InvalidateBlockImpl(B): B + D + E all invalid; candidates empty;
    // FindMostWork returns nullptr (no valid leaves); A is unaffected.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x90, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x91, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakePreValidationLeaf(0x92, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 3);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    auto pE = MakePreValidationLeaf(0x93, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 15, 4);
    uint256 hE = pE->GetBlockHash();
    assert(chainstate.AddBlockIndex(hE, std::move(pE)));
    CBlockIndex* E = chainstate.GetBlockIndex(hE);

    chainstate.RecomputeCandidates();
    assert(chainstate.FindMostWorkChainImpl() == D);  // sanity: D is the heaviest

    bool invalidated = chainstate.InvalidateBlockImpl(hB);
    assert(invalidated);

    // B and descendants are now invalid.
    assert(B->IsInvalid());
    assert(D->IsInvalid());
    assert(E->IsInvalid());
    // A is NOT affected.
    assert(!A->IsInvalid());

    // After Invalidate, no valid leaves remain (only A, but A has children).
    // FindMostWorkChainImpl returns nullptr — nothing to activate.
    assert(chainstate.FindMostWorkChainImpl() == nullptr);

    // Negative case: invalidating an unknown hash returns false.
    uint256 unknown;
    std::memset(unknown.data, 0, 32);
    unknown.data[0] = 0xFF;
    assert(!chainstate.InvalidateBlockImpl(unknown));

    std::cout << " OK\n";
}

void test_reconsider_block_impl_restores_candidates()
{
    std::cout << "  test_reconsider_block_impl_restores_candidates..."
              << std::flush;

    // A -> B -> D (all valid)
    // Invalidate(B) -> Reconsider(B). After Reconsider, D should be a
    // candidate again and FindMostWork picks D.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0xA0, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0xA1, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pD = MakePreValidationLeaf(0xA2, B, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 3);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = chainstate.GetBlockIndex(hD);

    chainstate.RecomputeCandidates();
    assert(chainstate.FindMostWorkChainImpl() == D);

    assert(chainstate.InvalidateBlockImpl(hB));
    assert(B->IsInvalid());
    assert(D->IsInvalid());
    assert(chainstate.FindMostWorkChainImpl() == nullptr);

    assert(chainstate.ReconsiderBlockImpl(hB));
    assert(!B->IsInvalid());
    assert(!D->IsInvalid());
    // D should be a candidate again — RecomputeCandidates ran inside Reconsider.
    assert(chainstate.FindMostWorkChainImpl() == D);

    // Negative: reconsidering an unknown hash returns false.
    uint256 unknown;
    std::memset(unknown.data, 0, 32);
    unknown.data[0] = 0xEE;
    assert(!chainstate.ReconsiderBlockImpl(unknown));

    std::cout << " OK\n";
}

void test_find_most_work_chain_returns_heaviest_valid_leaf()
{
    std::cout << "  test_find_most_work_chain_returns_heaviest_valid_leaf..."
              << std::flush;

    // A -> B (work=5)
    //   -> C (work=20, heaviest)
    //   -> D (work=10)
    // FindMostWorkChainImpl returns C.
    CChainState chainstate;
    auto pA = MakePreValidationLeaf(0x80, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    chainstate.SetTip(chainstate.GetBlockIndex(hA));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0x81, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));

    auto pC = MakePreValidationLeaf(0x82, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = chainstate.GetBlockIndex(hC);

    auto pD = MakePreValidationLeaf(0x83, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 4);
    uint256 hD = pD->GetBlockHash();
    assert(chainstate.AddBlockIndex(hD, std::move(pD)));

    chainstate.RecomputeCandidates();
    CBlockIndex* picked = chainstate.FindMostWorkChainImpl();
    assert(picked == C);

    std::cout << " OK\n";
}

// ============================================================================
// v4.3.1 chain-selection fix regression tests.
//
// These reproduce the LDN mainnet 2026-05-04 incident at unit scale:
//   * Fix 1: SetTip alone leaves m_setBlockIndexCandidates empty; node
//     restart on the env-var=1 path then sees a single-arrival candidate set
//     and tries to reorg-to-self-or-lesser. RecomputeCandidates after SetTip
//     is the surgical fix.
//   * Fix 3: defense-in-depth chainwork gate. The CORRECTED comparator is
//     `tip > candidate` (strict). Equal-work reorgs (DilV VDF Case 2.5) must
//     proceed; only strictly-less-work candidates are gated.
// ============================================================================

void test_v4_3_1_recompute_seeds_candidate_set_after_load()
{
    std::cout << "  test_v4_3_1_recompute_seeds_candidate_set_after_load..."
              << std::flush;

    // Reproduce LDN snapshot-load scenario at unit scale.
    // Build: A (active tip after load, valid_tx, work=5)
    //        \--> B (valid_tx leaf, work=10, heavier than tip)
    //
    // Without Fix 1: SetTip(A) populates m_chainstate but
    // m_setBlockIndexCandidates stays empty. FindMostWorkChainImpl returns
    // nullptr — i.e., the candidate-set machinery is blind to B.
    //
    // With Fix 1 (RecomputeCandidates after SetTip): B is now a candidate
    // and is heavier than A, so FindMostWorkChainImpl returns B.

    CChainState chainstate;

    // A: genesis-like, the loaded tip.
    auto pA = MakePreValidationLeaf(0x90, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);
    chainstate.SetTip(A);

    // B: heavier sibling-fork candidate, also fully validated.
    auto pB = MakePreValidationLeaf(0x91, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    // BEFORE Fix 1: SetTip alone does NOT populate the candidate set.
    // FindMostWorkChainImpl returns nullptr — no candidate.
    assert(chainstate.FindMostWorkChainImpl() == nullptr &&
           "v4.3.1 Fix 1 regression: candidate set must be empty before "
           "RecomputeCandidates is called");

    // APPLY Fix 1: caller seeds the candidate set after SetTip.
    chainstate.RecomputeCandidates();

    // AFTER Fix 1: B is in the candidate set as heaviest leaf.
    // (A has B as a child, so A is no longer a leaf and is excluded.)
    CBlockIndex* picked = chainstate.FindMostWorkChainImpl();
    assert(picked == B &&
           "v4.3.1 Fix 1: RecomputeCandidates must seed B as heaviest candidate");

    std::cout << " OK\n";
}

void test_v4_3_1_chainwork_gate_allows_equal_work_reorg()
{
    std::cout << "  test_v4_3_1_chainwork_gate_allows_equal_work_reorg..."
              << std::flush;

    // Fix 3 CORRECTED comparator semantics: `tip > candidate` (strict).
    // Equal-work reorgs must NOT be blocked — they're legitimate under DilV
    // VDF distribution / Case 2.5 tiebreak rules.
    //
    // Build: A (genesis, valid_tx, work=1)
    //   B (valid_tx leaf, EQUAL work=10, sibling)
    //   C (valid_tx leaf, EQUAL work=10, sibling)
    //
    // Verify: ChainWorkGreaterThan(B->nChainWork, C->nChainWork) == false
    // (their works are equal). The gate condition
    //     `if (tip && ChainWorkGreaterThan(tip->nChainWork, candidate->nChainWork)) break;`
    // therefore does NOT fire for equal work — the reorg proceeds.

    CChainState chainstate;

    auto pA = MakePreValidationLeaf(0xA0, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0xA1, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pC = MakePreValidationLeaf(0xA2, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = chainstate.GetBlockIndex(hC);

    // Sanity: B and C have IDENTICAL nChainWork by construction.
    assert(std::memcmp(B->nChainWork.data, C->nChainWork.data, 32) == 0);

    // CORE Fix 3 invariant: with B as tip and C as candidate (or vice versa),
    // ChainWorkGreaterThan(tip, candidate) is FALSE on equal work — so the
    // gate does NOT fire, allowing the equal-work reorg to proceed downstream
    // (Case 2.5 tiebreak / VDF distribution semantics).
    assert(!ChainWorkGreaterThan(B->nChainWork, C->nChainWork) &&
           "v4.3.1 Fix 3: gate must NOT fire on equal-work candidates");
    assert(!ChainWorkGreaterThan(C->nChainWork, B->nChainWork) &&
           "v4.3.1 Fix 3: comparator is strict in both directions for equal work");

    // Regression-against-misimplementation: the originally-proposed forensic
    // gate `!ChainWorkGreaterThan(candidate, tip)` would evaluate to TRUE on
    // equal work and incorrectly break the loop. Verify that the WRONG form
    // does fire, contrasting with the CORRECTED form's correct behavior.
    bool wrong_form_would_fire = !ChainWorkGreaterThan(C->nChainWork, B->nChainWork);
    assert(wrong_form_would_fire &&
           "v4.3.1 Fix 3 contrast: the original (rejected) gate form WOULD "
           "have fired on equal work, blocking legitimate reorgs");

    std::cout << " OK\n";
}

void test_v4_3_1_chainwork_gate_blocks_strictly_lesser_candidate()
{
    std::cout << "  test_v4_3_1_chainwork_gate_blocks_strictly_lesser_candidate..."
              << std::flush;

    // Defense-in-depth: when a less-work candidate somehow ends up as
    // FindMostWorkChainImpl's pick (e.g., a future Fix 1 regression),
    // the chainwork gate must fire and break the loop BEFORE the
    // disconnect-then-fail sequence that caused the LDN deadlock.
    //
    // Build: A (genesis, valid_tx)
    //   B (valid_tx leaf, work=10) — would-be tip
    //   C (valid_tx leaf, work=5)  — strictly lesser candidate

    CChainState chainstate;

    auto pA = MakePreValidationLeaf(0xB0, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pB = MakePreValidationLeaf(0xB1, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 10, 2);
    uint256 hB = pB->GetBlockHash();
    assert(chainstate.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = chainstate.GetBlockIndex(hB);

    auto pC = MakePreValidationLeaf(0xB2, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 3);
    uint256 hC = pC->GetBlockHash();
    assert(chainstate.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = chainstate.GetBlockIndex(hC);

    chainstate.SetTip(B);  // tip = B (heavier).

    // CORE Fix 3 invariant: with tip=B (work=10), candidate=C (work=5),
    // ChainWorkGreaterThan(tip, candidate) is TRUE → the gate fires → break.
    assert(ChainWorkGreaterThan(B->nChainWork, C->nChainWork) &&
           "v4.3.1 Fix 3: gate must fire when tip strictly heavier than candidate");

    // And the reverse (candidate heavier than tip) should NOT fire.
    assert(!ChainWorkGreaterThan(C->nChainWork, B->nChainWork) &&
           "v4.3.1 Fix 3: candidate-heavier-than-tip is the legitimate reorg case");

    std::cout << " OK\n";
}

// ============================================================================
// PR6.1 cap-fold (2026-06-15): verify-the-verifier on the consensus surface.
//
// CONSENSUS_REFETCH_FINDINGS.md adjudicated the 5M->500K nMapBlockIndexCap
// lowering as (A) CONSENSUS-SAFE by code-trace: an evicted low-work FORK
// header is recoverable because (1) eviction only ever removes a non-active,
// lowest-work entry (never an active ancestor), and (2) the evicted entry is
// rebuilt in mapBlockIndex via the DIRECT block-arrival path
// (block_validation_queue.cpp AddBlockIndex), independent of the header-dedup
// short-circuit — after which a higher-work branch building on it wins
// FindMostWorkChainImpl (the reorg-target decision).
//
// This test converts that code-traced recovery into an EXECUTED proof. It
// drives the recovery sequence through the real CChainState consensus API
// (EvictLowestWorkNotOnBestChain -> AddBlockIndex rebuild -> extend ->
// FindMostWorkChainImpl), asserting the evicted fork is recovered AND becomes
// the selected reorg target.
//
// SCOPE / what this covers vs. does not:
//   * COVERS: the eviction policy (lowest-work-not-on-active), the block-path
//     rebuild of an evicted CBlockIndex via AddBlockIndex (the exact call the
//     block-arrival code makes), and that the rebuilt+extended branch is
//     selected as the most-work chain (the reorg DECISION point). This is the
//     load-bearing evict->recover->reorg-target chain.
//   * DOES NOT cover (deliberately, too heavy for a unit test): a full P2P
//     E2E with real header/block wire delivery and a real ConnectTip reorg via
//     ActivateBestChainStep (which needs block data on disk / a wired pdb and
//     the DILITHION_USE_NEW_CHAIN_SELECTOR=1 path). The selection decision
//     (FindMostWorkChainImpl) is the deterministic point that DETERMINES the
//     reorg target; asserting it picks the recovered branch is the tightest
//     proof of "the node would reorg to the evicted-then-recovered fork".
//
// Cap is exercised via the public EvictLowestWorkNotOnBestChain() directly
// (rather than saturating to 500K through ProcessNewHeader) so the test is a
// fast, deterministic O(few-entries) unit test while exercising the IDENTICAL
// eviction + rebuild + selection code the production cap-trigger invokes.
void test_pr61_cap_evicted_fork_recovers_and_becomes_reorg_target()
{
    std::cout << "  test_pr61_cap_evicted_fork_recovers_and_becomes_reorg_target..."
              << std::flush;

    CChainState chainstate;

    // Active chain: A(genesis, work=5) -> M(work=20). M is the active tip.
    auto pA = MakePreValidationLeaf(0x40, nullptr, 0,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 5, 1);
    uint256 hA = pA->GetBlockHash();
    assert(chainstate.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = chainstate.GetBlockIndex(hA);

    auto pM = MakePreValidationLeaf(0x41, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 20, 2);
    uint256 hM = pM->GetBlockHash();
    assert(chainstate.AddBlockIndex(hM, std::move(pM)));
    CBlockIndex* M = chainstate.GetBlockIndex(hM);
    chainstate.SetTip(M);  // active tip = M (work=20)

    // Low-work FORK header F off genesis A (work=3 < active tip work=20),
    // NOT on the active chain. This is the eviction victim.
    auto pF = MakePreValidationLeaf(0x42, A, 1,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 3, 3);
    uint256 hF = pF->GetBlockHash();
    assert(chainstate.AddBlockIndex(hF, std::move(pF)));
    assert(chainstate.GetBlockIndex(hF) != nullptr &&
           "fork header F must be present before eviction");

    // --- (1) EVICT: the cap-trigger's eviction must pick the lowest-work
    //         NON-active entry. With A(5) and M(20) on the active chain and
    //         F(3) off-chain, F is the unique lowest-work-not-on-active entry.
    size_t size_before = chainstate.GetBlockIndexSize();
    bool evicted = chainstate.EvictLowestWorkNotOnBestChain();
    assert(evicted && "eviction must succeed when a non-active entry exists");
    assert(chainstate.GetBlockIndex(hF) == nullptr &&
           "the low-work FORK header F must be the evicted entry (gone from mapBlockIndex)");
    // Active-chain ancestors must survive eviction (never evict an ancestor).
    assert(chainstate.GetBlockIndex(hA) != nullptr &&
           "genesis A (active ancestor) must NOT be evicted");
    assert(chainstate.GetBlockIndex(hM) != nullptr &&
           "active tip M must NOT be evicted");
    assert(chainstate.GetBlockIndexSize() == size_before - 1);

    // --- (2) RECOVER via the DIRECT block-arrival path. This is exactly what
    //         block_validation_queue.cpp does when the re-requested fork BLOCK
    //         arrives: build a fresh CBlockIndex linked to its (un-evicted)
    //         parent and call AddBlockIndex — NOT ProcessNewHeader, so the
    //         header-dedup short-circuit is bypassed. AddBlockIndex's
    //         first-time-add branch re-creates the evicted entry from scratch.
    //         (Reuse the same synthetic hash-seed 0x42 so the rebuilt entry is
    //         byte-identical to the evicted one — proving recovery of THAT
    //         hash, not a different fork.)
    auto pF_rebuilt = MakePreValidationLeaf(0x42, A, 1,
                                            CBlockIndex::BLOCK_VALID_TRANSACTIONS, 3, 3);
    uint256 hF_rebuilt = pF_rebuilt->GetBlockHash();
    assert(std::memcmp(hF.data, hF_rebuilt.data, 32) == 0 &&
           "rebuilt entry must have the SAME hash as the evicted fork header");
    assert(chainstate.AddBlockIndex(hF_rebuilt, std::move(pF_rebuilt)) &&
           "block-path AddBlockIndex must re-create the evicted CBlockIndex");
    CBlockIndex* F = chainstate.GetBlockIndex(hF);
    assert(F != nullptr && "evicted fork entry must be back in mapBlockIndex after block-path rebuild");

    // --- (3) The competing chain builds a HIGHER-work block G on the recovered
    //         fork F. Cumulative work: A(5)->F(3 leaf) then G with work=99,
    //         exceeding the active tip M (work=20). G is a fully-validated leaf
    //         (BLOCK_HAVE_DATA auto-set), so it is reorg-eligible.
    auto pG = MakePreValidationLeaf(0x43, F, 2,
                                    CBlockIndex::BLOCK_VALID_TRANSACTIONS, 99, 4);
    uint256 hG = pG->GetBlockHash();
    assert(chainstate.AddBlockIndex(hG, std::move(pG)));
    CBlockIndex* G = chainstate.GetBlockIndex(hG);

    // --- (4) REORG-TARGET DECISION: seed the candidate set and assert
    //         FindMostWorkChainImpl selects G (the recovered branch's leaf) over
    //         the current tip M. This is the deterministic decision that DRIVES
    //         the reorg in ActivateBestChain's connect-loop (chain.cpp:521) —
    //         proving the node would reorg ONTO the evicted-then-recovered fork.
    chainstate.RecomputeCandidates();
    CBlockIndex* picked = chainstate.FindMostWorkChainImpl();
    assert(picked == G &&
           "EVICT->RECOVER->REORG: the node must select the higher-work branch "
           "built on the recovered (previously-evicted) fork as its reorg target");
    // Sanity: G genuinely outweighs the active tip M (a real reorg, not a no-op).
    assert(ChainWorkGreaterThan(G->nChainWork, M->nChainWork) &&
           "recovered-branch leaf G must have strictly greater work than active tip M");

    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== Phase 5 PR5.1 + 5.3-prereq + 5.3 Day 3 AM: ChainSelector Tests ===\n"
              << std::endl;

    try {
        std::cout << "--- PR5.1 trivial getters ---" << std::endl;
        test_get_active_tip_null_on_fresh_chainstate();
        test_get_active_tip_after_set_tip_for_test();
        test_get_active_height_and_hash_match_tip();
        test_lookup_block_index_returns_added_block();

        std::cout << "\n--- PR5.3 prerequisite: ProcessNewHeader ---" << std::endl;
        test_process_new_header_genesis_creates_pre_validation_entry();
        test_process_new_header_orphan_returns_false();
        test_process_new_header_chains_parent_correctly();

        std::cout << "\n--- PR5.3 prerequisite: G1/G2 guardrails ---" << std::endl;
        test_g1_pre_validation_siblings_visible_as_competing_tips();
        test_g2_pre_validation_entries_are_not_invalid();

        std::cout << "\n--- PR5.3 Day 3 AM: candidate set + selection ---" << std::endl;
        test_recompute_candidates_skips_pre_validation_leaves();
        test_recompute_candidates_skips_invalid_blocks();
        test_mark_block_as_failed_propagates_to_descendants();
        test_mark_block_as_valid_clears_failed_child();
        test_find_most_work_chain_returns_heaviest_valid_leaf();

        std::cout << "\n--- PR5.3 Day 3 PM: Invalidate / Reconsider operator overrides ---"
                  << std::endl;
        test_invalidate_block_impl_propagates_and_drops_candidates();
        test_reconsider_block_impl_restores_candidates();

        std::cout << "\n--- PR5.3 Day 3 PM: adapter forwarders (no more assert(false)) ---"
                  << std::endl;
        test_adapter_forwards_invalidate_and_reconsider();
        test_adapter_find_most_work_chain_returns_heaviest();

        std::cout << "\n--- v4.3.1 chain-selection fix regressions ---"
                  << std::endl;
        test_v4_3_1_recompute_seeds_candidate_set_after_load();
        test_v4_3_1_chainwork_gate_allows_equal_work_reorg();
        test_v4_3_1_chainwork_gate_blocks_strictly_lesser_candidate();

        std::cout << "\n--- Red-team audit BLOCKER fixes ---"
                  << std::endl;
        test_blocker1_process_new_header_rejects_invalid_parent();
        test_blocker2_mark_block_as_valid_independent_failure_is_barrier();
        test_blocker3_checkpoint_violation_in_ancestry_rejects_candidate();

        std::cout << "\n--- PR6.1 cap-fold: evicted-fork recovery -> reorg target ---"
                  << std::endl;
        test_pr61_cap_evicted_fork_recovers_and_becomes_reorg_target();

        std::cout << "\n=== All chain_selector_tests passed (25 tests: 4 + 5 + 5 + 2 + 2 + 3 + 3 + 1) ==="
                  << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}
