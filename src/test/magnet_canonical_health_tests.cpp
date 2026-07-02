// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Magnet v1a (fork-resistance, OBSERVABILITY ONLY) — canonical node-health
// accessor tests.
//
// SCOPE: unit-level verification of CChainState::IsOnCanonical() /
// OffCanonicalReason() / the off-canonical edge-trigger latch. These are
// pure read-and-report accessors added by magnet v1a: they change NO
// consensus / reorg / mining behavior, so the harness only needs to drive
// the existing chainstate signals (m_chain_needs_rebuild + reason via
// FlagChainRebuild, and the m_setBlockIndexCandidates vs tip work relation)
// and assert the accessor's verdict.
//
// Cases:
//   M1  Fresh chainstate (no rebuild flagged, no candidates)  → on-canonical.
//   M2  DepthRejection rebuild flagged                        → off-canonical,
//                                                                reason
//                                                                "depth-rejection".
//   M3  Non-depth rebuild cause (UndoFailure) flagged         → still
//                                                                on-canonical
//                                                                (v1a signals
//                                                                only the
//                                                                off-best-chain
//                                                                cause, not
//                                                                every rebuild).
//   M4  Heavier candidate leaf than active tip, not adopted   → off-canonical,
//                                                                reason
//                                                                "work-drift".
//   M5  Edge-trigger latch: LogOffCanonicalTransition emits once, is re-armed
//       by ClearChainRebuildFlag, then emits again — verified via the public
//       on/off verdict flipping back and forth (latch state is private; we
//       assert the observable flag transitions the latch guards).

#include <consensus/chain.h>
#include <consensus/pow.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

namespace {

// Mirror of the MakeIdx helper used by the port chain-selector suite: build a
// synthetic CBlockIndex with a uniqueness-guaranteed hash and an explicit
// little-endian chainwork.
std::unique_ptr<CBlockIndex> MakeIdx(uint8_t chain_id,
                                     CBlockIndex* parent,
                                     int height,
                                     uint32_t status,
                                     uint32_t work,
                                     uint32_t seq_id)
{
    auto p = std::make_unique<CBlockIndex>();
    p->pprev = parent;
    p->nHeight = height;
    p->nStatus = status;
    p->nSequenceId = seq_id;
    p->nVersion = CBlockHeader::VDF_VERSION;
    p->nTime = 1700000000 + height * 240;
    p->nBits = 0x1d00ffff;

    std::memset(p->phashBlock.data, 0, 32);
    p->phashBlock.data[0] = chain_id;
    p->phashBlock.data[1] = static_cast<uint8_t>(height & 0xff);
    p->phashBlock.data[2] = static_cast<uint8_t>((height >> 8) & 0xff);

    std::memset(p->nChainWork.data, 0, 32);
    p->nChainWork.data[0] = static_cast<uint8_t>(work & 0xff);
    p->nChainWork.data[1] = static_cast<uint8_t>((work >> 8) & 0xff);
    p->nChainWork.data[2] = static_cast<uint8_t>((work >> 16) & 0xff);
    p->nChainWork.data[3] = static_cast<uint8_t>((work >> 24) & 0xff);

    std::memset(p->header.vdfOutput.data, 0, 32);
    p->header.vdfOutput.data[31] = chain_id;
    p->header.hashPrevBlock = parent ? parent->GetBlockHash() : uint256();

    return p;
}

// Build an active chain of `length+1` blocks (h=0..length), full data, work =
// h+1, SetTip to the leaf. Returns the tip pointer.
CBlockIndex* BuildActiveChain(CChainState& cs, uint8_t chain_id, int length)
{
    CBlockIndex* prev = nullptr;
    CBlockIndex* tip = nullptr;
    for (int h = 0; h <= length; ++h) {
        auto p = MakeIdx(chain_id, prev, h,
                         CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                         CBlockIndex::BLOCK_HAVE_DATA,
                         /*work=*/static_cast<uint32_t>(h + 1),
                         /*seq=*/static_cast<uint32_t>(h + 1));
        uint256 hh = p->GetBlockHash();
        bool added = cs.AddBlockIndex(hh, std::move(p));
        assert(added);
        CBlockIndex* now = cs.GetBlockIndex(hh);
        if (h > 0) prev->pnext = now;
        prev = now;
        tip = now;
    }
    cs.SetTip(tip);
    return tip;
}

}  // namespace

// ---------------------------------------------------------------------------
// M1 — fresh chainstate is on-canonical.
// ---------------------------------------------------------------------------
void test_m1_fresh_chainstate_is_on_canonical()
{
    std::cout << "  test_m1_fresh_chainstate_is_on_canonical..." << std::flush;
    CChainState cs;
    BuildActiveChain(cs, /*chain_id=*/0x10, /*length=*/5);

    assert(cs.IsOnCanonical());
    assert(cs.OffCanonicalReason().empty());

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// M2 — DepthRejection rebuild flagged → off-canonical, "depth-rejection".
// ---------------------------------------------------------------------------
void test_m2_depth_rejection_is_off_canonical()
{
    std::cout << "  test_m2_depth_rejection_is_off_canonical..." << std::flush;
    CChainState cs;
    BuildActiveChain(cs, /*chain_id=*/0x20, /*length=*/5);

    // Simulate the DepthRejection rebuild-flag site (chain.cpp): a strictly-
    // better chain exists beyond MAX_REORG_DEPTH.
    cs.FlagChainRebuild(CChainState::ChainRebuildReason::DepthRejection);

    assert(!cs.IsOnCanonical());
    assert(cs.OffCanonicalReason() == "depth-rejection");

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// M3 — a NON-depth rebuild cause does NOT trip the off-canonical signal.
// v1a reports "off the best chain", not "any rebuild pending".
// ---------------------------------------------------------------------------
void test_m3_non_depth_rebuild_stays_on_canonical()
{
    std::cout << "  test_m3_non_depth_rebuild_stays_on_canonical..." << std::flush;
    CChainState cs;
    BuildActiveChain(cs, /*chain_id=*/0x30, /*length=*/5);

    // A local storage/undo failure flags a rebuild but is NOT a "better chain
    // exists" condition — must remain on-canonical.
    cs.FlagChainRebuild(CChainState::ChainRebuildReason::UndoFailure);

    assert(cs.IsOnCanonical());
    assert(cs.OffCanonicalReason().empty());

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// M4 — a heavier candidate leaf than the active tip (not adopted) → drift.
// ---------------------------------------------------------------------------
void test_m4_heavier_unadopted_candidate_is_work_drift()
{
    std::cout << "  test_m4_heavier_unadopted_candidate_is_work_drift..." << std::flush;
    CChainState cs;
    CBlockIndex* tip = BuildActiveChain(cs, /*chain_id=*/0x40, /*length=*/5);
    // Active tip has work = 6 (length 5 → h=5 → work h+1). On-canonical first.
    assert(cs.IsOnCanonical());

    // Add a sibling leaf off genesis with strictly greater chainwork that is
    // NOT the active tip. RecomputeCandidates places it (heaviest) at the
    // front of m_setBlockIndexCandidates without adopting it as the tip.
    CBlockIndex* genesis = tip;
    while (genesis->pprev) genesis = genesis->pprev;

    auto sib = MakeIdx(/*chain_id=*/0x41, genesis, /*height=*/1,
                       CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                       CBlockIndex::BLOCK_HAVE_DATA,
                       /*work=*/999,          // strictly > tip work (6)
                       /*seq=*/500);
    uint256 sh = sib->GetBlockHash();
    assert(cs.AddBlockIndex(sh, std::move(sib)));
    cs.RecomputeCandidates();

    // Tip unchanged (we did not run activation) — a heavier candidate is known
    // but not adopted: the drift signal.
    assert(cs.GetTip() == tip);
    assert(!cs.IsOnCanonical());
    assert(cs.OffCanonicalReason() == "work-drift");

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// M5 — off→on→off verdict cycle (the state the edge-trigger latch guards).
// LogOffCanonicalTransition is edge-triggered; ClearChainRebuildFlag re-arms.
// ---------------------------------------------------------------------------
void test_m5_off_canonical_clears_and_re_enters()
{
    std::cout << "  test_m5_off_canonical_clears_and_re_enters..." << std::flush;
    CChainState cs;
    BuildActiveChain(cs, /*chain_id=*/0x50, /*length=*/5);

    // Enter off-canonical.
    cs.FlagChainRebuild(CChainState::ChainRebuildReason::DepthRejection);
    assert(!cs.IsOnCanonical());
    // Emitting twice in one episode is a no-op edge-trigger (does not throw /
    // corrupt state); the accessor verdict is unchanged.
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/9);
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/9);
    assert(!cs.IsOnCanonical());

    // Recovery initiated → clear the rebuild flag → back on-canonical AND the
    // edge-trigger latch re-armed for a future episode.
    cs.ClearChainRebuildFlag();
    assert(cs.IsOnCanonical());
    assert(cs.OffCanonicalReason().empty());

    // Re-enter off-canonical: verdict flips again (latch was re-armed).
    cs.FlagChainRebuild(CChainState::ChainRebuildReason::DepthRejection);
    assert(!cs.IsOnCanonical());
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/9);

    std::cout << " OK\n";
}

int main()
{
    std::cout << "=== Magnet v1a canonical node-health accessor tests ===\n";
    std::cout << "    (observability-only: read + report, no behavior change)\n";

    test_m1_fresh_chainstate_is_on_canonical();
    test_m2_depth_rejection_is_off_canonical();
    test_m3_non_depth_rebuild_stays_on_canonical();
    test_m4_heavier_unadopted_candidate_is_work_drift();
    test_m5_off_canonical_clears_and_re_enters();

    std::cout << "\n=== All 5 magnet v1a tests passed ===\n";
    return 0;
}
