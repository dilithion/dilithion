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
//   M4  Heavier candidate leaf than active tip, NOT in a depth-rejection
//       rebuild → still ON-canonical. v1a dropped the "work-drift" signal
//       (red-team MED-1): a heavier candidate that is not a depth-rejection
//       does NOT drive off-canonical.
//   M5  Edge-trigger latch: LogOffCanonicalTransition emits EXACTLY ONCE per
//       episode, is re-armed by ClearChainRebuildFlag, then emits again —
//       verified DIRECTLY via OffCanonicalEmitCount() (not just the on/off
//       verdict, which does not depend on the latch). Non-vacuous: fails if
//       the latch double-logs or fails to re-arm.
//   M6  MED-1 guard: a node holding a strictly-heavier candidate leaf (e.g. a
//       correctly-rejected fork re-added by RecomputeCandidates on restart) but
//       NOT in a depth-rejection rebuild reports on_canonical == true — locks
//       in the corrected cry-wolf-free semantics.

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
// M4 — a heavier candidate leaf than the active tip, but NO depth-rejection
// rebuild, does NOT drive off-canonical. v1a dropped "work-drift" (MED-1):
// a heavier candidate alone is no longer an off-canonical signal.
// ---------------------------------------------------------------------------
void test_m4_heavier_candidate_without_depth_rejection_stays_on_canonical()
{
    std::cout << "  test_m4_heavier_candidate_without_depth_rejection_stays_on_canonical..." << std::flush;
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

    // A heavier candidate is known but not adopted, and there is NO
    // depth-rejection rebuild pending. Post-MED-1 this is ON-canonical:
    // work-drift no longer signals off-canonical.
    assert(cs.GetTip() == tip);
    assert(cs.IsOnCanonical());
    assert(cs.OffCanonicalReason().empty());

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// M5 — edge-trigger latch, verified DIRECTLY via OffCanonicalEmitCount().
// LogOffCanonicalTransition must emit exactly once per off-canonical episode;
// ClearChainRebuildFlag must re-arm it. This asserts on the emit counter (not
// just the on/off verdict, which is driven by the rebuild flag and would pass
// even if the latch were broken) — so it FAILS on a double-log or a missed
// re-arm.
// ---------------------------------------------------------------------------
void test_m5_latch_emits_once_per_episode_and_rearms()
{
    std::cout << "  test_m5_latch_emits_once_per_episode_and_rearms..." << std::flush;
    CChainState cs;
    BuildActiveChain(cs, /*chain_id=*/0x50, /*length=*/5);

    assert(cs.OffCanonicalEmitCount() == 0);

    // Episode 1: enter off-canonical, emit twice — the edge-trigger must
    // collapse both into a SINGLE emit.
    cs.FlagChainRebuild(CChainState::ChainRebuildReason::DepthRejection);
    assert(!cs.IsOnCanonical());
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/9);
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/9);
    assert(cs.OffCanonicalEmitCount() == 1);  // exactly one emit, not two
    assert(!cs.IsOnCanonical());

    // Recovery: clear the rebuild flag → back on-canonical AND latch re-armed.
    // Re-arm must NOT itself emit.
    cs.ClearChainRebuildFlag();
    assert(cs.IsOnCanonical());
    assert(cs.OffCanonicalReason().empty());
    assert(cs.OffCanonicalEmitCount() == 1);  // clearing does not emit

    // Episode 2: re-enter off-canonical → the re-armed latch emits AGAIN
    // (count advances to 2). A latch that failed to re-arm would stay at 1.
    cs.FlagChainRebuild(CChainState::ChainRebuildReason::DepthRejection);
    assert(!cs.IsOnCanonical());
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/9);
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/9);
    assert(cs.OffCanonicalEmitCount() == 2);  // re-armed: exactly one more

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// M7 — v4.6 fold (A/HIGH-2): a LATCH-ONLY episode drives the signal. The
// legacy activation path rejects a too-deep reorg without flagging a rebuild,
// so its depth-rejection site emits the latch transition alone. The signal
// must go off-canonical on the latch, stay off for the episode, and clear on
// recovery — with the emit counter proving the edge-trigger still holds.
// Before this fold the latch did NOT feed OffCanonicalReason and this exact
// sequence reported on_canonical == true throughout: the green-by-construction
// defect, pinned here so it cannot return.
// ---------------------------------------------------------------------------
void test_m7_latch_only_episode_drives_signal()
{
    std::cout << "  test_m7_latch_only_episode_drives_signal..." << std::flush;
    CChainState cs;
    BuildActiveChain(cs, /*chain_id=*/0x70, /*length=*/5);

    assert(cs.IsOnCanonical());
    assert(cs.OffCanonicalReason().empty());

    // Legacy-path episode: emitter fires with NO rebuild flag.
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/104);
    assert(!cs.IsOnCanonical());
    assert(cs.OffCanonicalReason() == "depth-rejection");
    assert(cs.OffCanonicalEmitCount() == 1);

    // Repeat emit inside the episode: signal stays off, no double emit.
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/105);
    assert(!cs.IsOnCanonical());
    assert(cs.OffCanonicalEmitCount() == 1);

    // Recovery re-arms and clears the signal.
    cs.ClearChainRebuildFlag();
    assert(cs.IsOnCanonical());
    assert(cs.OffCanonicalReason().empty());
    assert(cs.OffCanonicalEmitCount() == 1);

    // A second episode fires again (latch re-armed).
    cs.LogOffCanonicalTransition("depth-rejection", /*best_known_ht=*/110);
    assert(!cs.IsOnCanonical());
    assert(cs.OffCanonicalEmitCount() == 2);

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// M6 — MED-1 guard: a node holding a strictly-heavier candidate leaf (as a
// correctly-rejected fork would be after RecomputeCandidates re-adds it on
// restart) but NOT in a depth-rejection rebuild reports on_canonical == true.
// This is the exact cry-wolf case the old work-drift signal false-alarmed on;
// this test proves removing work-drift fixed it, and guards against regression.
// ---------------------------------------------------------------------------
void test_m6_med1_heavier_rejected_fork_on_restart_stays_on_canonical()
{
    std::cout << "  test_m6_med1_heavier_rejected_fork_on_restart_stays_on_canonical..." << std::flush;
    CChainState cs;
    CBlockIndex* tip = BuildActiveChain(cs, /*chain_id=*/0x60, /*length=*/8);
    assert(cs.IsOnCanonical());

    // Model the restart RecomputeCandidates re-scan picking up a persisted
    // heavier fork the node had correctly rejected (checkpoint/depth): the
    // block is BLOCK_VALID_TRANSACTIONS + HAVE_DATA (not BLOCK_FAILED_VALID),
    // strictly heavier than the tip, and re-enters candidates.
    CBlockIndex* genesis = tip;
    while (genesis->pprev) genesis = genesis->pprev;

    auto rejected = MakeIdx(/*chain_id=*/0x61, genesis, /*height=*/1,
                            CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                            CBlockIndex::BLOCK_HAVE_DATA,
                            /*work=*/1000000,     // strictly > tip work (9)
                            /*seq=*/700);
    uint256 rh = rejected->GetBlockHash();
    assert(cs.AddBlockIndex(rh, std::move(rejected)));
    cs.RecomputeCandidates();

    // Node is on the correct network-canonical chain (no depth-rejection
    // rebuild pending). Must report ON-canonical — NO cry-wolf. Also verify
    // the edge-triggered ERROR log never fired for this healthy state.
    assert(cs.GetTip() == tip);
    assert(cs.IsOnCanonical());
    assert(cs.OffCanonicalReason().empty());
    assert(cs.OffCanonicalEmitCount() == 0);

    std::cout << " OK\n";
}

int main()
{
    std::cout << "=== Magnet v1a canonical node-health accessor tests ===\n";
    std::cout << "    (observability-only: read + report, no behavior change)\n";

    test_m1_fresh_chainstate_is_on_canonical();
    test_m2_depth_rejection_is_off_canonical();
    test_m3_non_depth_rebuild_stays_on_canonical();
    test_m4_heavier_candidate_without_depth_rejection_stays_on_canonical();
    test_m5_latch_emits_once_per_episode_and_rearms();
    test_m7_latch_only_episode_drives_signal();
    test_m6_med1_heavier_rejected_fork_on_restart_stays_on_canonical();

    std::cout << "\n=== All 6 magnet v1a tests passed ===\n";
    return 0;
}
