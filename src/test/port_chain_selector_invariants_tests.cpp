// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// v4.3.3 — port-path chain-selection invariants regression suite (T1).
//
// SCOPE: synthetic harness reproducing the canary-3 LDN failure shape and
// verifying the v4.3.3 F1-F6 fixes close it. Each test would FAIL on the
// `feaf001` (v4.3.2-M1) baseline and PASS post-fix.
//
// Cases (one per fix F3-F6 plus F1 literal-validity and the canary-3
// reproduction itself):
//
//   T1.1 Canary-3 reproduction:
//        Active chain at h=N. 1000 header-only entries h=N+1..N+1000 with
//        BLOCK_VALID_HEADER and NO BLOCK_HAVE_DATA. ONE leaf at h=N+1000
//        with full data on disk. Assert: chain stays at h=N, no
//        m_chain_needs_rebuild, no [CRITICAL] log lines, no MarkBlockAsFailed
//        on the active tip. F5 catches the missing-data ancestors.
//
//   T1.2 Reorg-depth cap:
//        Active to h=200. Sibling chain to h=350 forking at genesis with
//        ALL ancestors having BLOCK_HAVE_DATA. F4 rejects the 200-deep
//        reorg cleanly.
//
//   T1.3 Pre-validation atomicity:
//        Active to h=20. Sibling chain forks at h=15, leaf at h=25.
//        ReadBlock fails for one specific intermediate block — F3 catches
//        BEFORE any disconnect is committed. No m_chain_needs_rebuild.
//
//   T1.4 Bit-mask literal validity:
//        Construct CBlockIndex with nStatus = BLOCK_HAVE_DATA only (no
//        BLOCK_VALID_TRANSACTIONS in the level field). Assert
//        IsBlockACandidateForActivation returns FALSE post-F1. (Pre-F1 it
//        returned TRUE because of the mask=0x1F overlap.)
//
//   T1.5 PruneBlockIndexCandidates correctness:
//        Active chain past several siblings. Activate; assert candidate
//        set contains only entries with chainwork >= tip post-F6.
//
//   T1.6 Per-ancestor data gate:
//        Active to h=N. Sibling chain to h=N+5 with full data on the leaf
//        AND all ancestors except h=N+3 (which lacks BLOCK_HAVE_DATA).
//        F5 walks ancestry, hits h=N+3, drops the leaf. FindMostWorkChainImpl
//        does NOT return the sibling leaf.

#include <consensus/chain.h>
#include <consensus/pow.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

// Build a synthetic CBlockIndex with a uniqueness-guaranteed hash:
//   byte 0      = chain_id  (callers pick disjoint values per test)
//   bytes 1-2   = height (LE)
//   bytes 3-4   = disambiguator (default 0)
// chainwork = 4 LE bytes from the `work` parameter.
std::unique_ptr<CBlockIndex> MakeIdx(uint8_t chain_id,
                                     CBlockIndex* parent,
                                     int height,
                                     uint32_t status,
                                     uint32_t work,
                                     uint32_t seq_id,
                                     uint16_t disambiguator = 0)
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
    p->phashBlock.data[3] = static_cast<uint8_t>(disambiguator & 0xff);
    p->phashBlock.data[4] = static_cast<uint8_t>((disambiguator >> 8) & 0xff);

    std::memset(p->nChainWork.data, 0, 32);
    p->nChainWork.data[0] = static_cast<uint8_t>(work & 0xff);
    p->nChainWork.data[1] = static_cast<uint8_t>((work >> 8) & 0xff);
    p->nChainWork.data[2] = static_cast<uint8_t>((work >> 16) & 0xff);
    p->nChainWork.data[3] = static_cast<uint8_t>((work >> 24) & 0xff);

    std::memset(p->header.vdfOutput.data, 0, 32);
    p->header.vdfOutput.data[31] = chain_id;
    p->header.vdfOutput.data[30] = static_cast<uint8_t>(height & 0xff);
    p->header.vdfOutput.data[29] = static_cast<uint8_t>((height >> 8) & 0xff);
    p->header.hashPrevBlock = parent ? parent->GetBlockHash() : uint256();

    return p;
}

// Build an active chain of `length+1` blocks (genesis at h=0 ... h=length),
// each with BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA, work = h+1, pnext
// wired so IsOnMainChain() returns true on every non-tip block. SetTip to
// the leaf. Returns: { genesis, tip }.
struct ActiveChain {
    CBlockIndex* genesis{nullptr};
    CBlockIndex* tip{nullptr};
    std::vector<CBlockIndex*> all;
};

ActiveChain BuildActiveChain(CChainState& cs, uint8_t chain_id, int length)
{
    ActiveChain a;
    CBlockIndex* prev = nullptr;
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
        a.all.push_back(now);
        if (h > 0) prev->pnext = now;
        if (h == 0) a.genesis = now;
        prev = now;
    }
    a.tip = prev;
    cs.SetTip(a.tip);
    return a;
}

void EngageNewPath()
{
#ifdef _WIN32
    _putenv_s("DILITHION_USE_NEW_CHAIN_SELECTOR", "1");
#else
    setenv("DILITHION_USE_NEW_CHAIN_SELECTOR", "1", 1);
#endif
}

void DisengagePath()
{
#ifdef _WIN32
    _putenv_s("DILITHION_USE_NEW_CHAIN_SELECTOR", "");
#else
    unsetenv("DILITHION_USE_NEW_CHAIN_SELECTOR");
#endif
}

// Capture stderr to scan for [CRITICAL] log lines.
struct StderrCapture {
    std::stringstream buf;
    std::streambuf* old;
    StderrCapture() { old = std::cerr.rdbuf(buf.rdbuf()); }
    ~StderrCapture() { std::cerr.rdbuf(old); }
    std::string str() const { return buf.str(); }
};

}  // namespace

// ---------------------------------------------------------------------------
// T1.1 — Canary-3 reproduction.
// ---------------------------------------------------------------------------
void test_t1_1_canary_3_header_only_chain_with_bait_leaf()
{
    std::cout << "  test_t1_1_canary_3_header_only_chain_with_bait_leaf..." << std::flush;

    EngageNewPath();
    CChainState cs;

    // Active chain at h=N=10.
    const int N = 10;
    ActiveChain active = BuildActiveChain(cs, /*chain_id=*/0x10, N);
    CBlockIndex* activeTip = active.tip;

    // Inject 1000 header-only entries at h=N+1..N+1000 (no BLOCK_HAVE_DATA),
    // chained off the active tip.
    CBlockIndex* hdrPrev = activeTip;
    for (int i = 1; i <= 1000; ++i) {
        auto p = MakeIdx(/*chain_id=*/0x20, hdrPrev, N + i,
                         CBlockIndex::BLOCK_VALID_HEADER,  // no HAVE_DATA
                         /*work=*/static_cast<uint32_t>(N + i + 1),
                         /*seq=*/static_cast<uint32_t>(100 + i));
        uint256 hh = p->GetBlockHash();
        assert(cs.AddBlockIndex(hh, std::move(p)));
        hdrPrev = cs.GetBlockIndex(hh);
    }

    // Bait leaf at h=N+1000: full data, chainwork far higher than active tip.
    hdrPrev->nStatus = CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                       CBlockIndex::BLOCK_HAVE_DATA;
    std::memset(hdrPrev->nChainWork.data, 0, 32);
    hdrPrev->nChainWork.data[0] = 0xff;
    hdrPrev->nChainWork.data[1] = 0xff;
    hdrPrev->nChainWork.data[2] = 0xff;

    cs.RecomputeCandidates();

    // Capture stderr while we run FindMostWorkChainImpl.
    StderrCapture cap;
    {
        // Per F5: walks back from the bait leaf, hits header-only ancestor
        // at h=N+999 (no HAVE_DATA, IsOnMainChain false because off main
        // chain), drops the candidate. Repeats for any other header-only
        // leaves, eventually returns either nullptr or the active tip.
        CBlockIndex* picked = cs.FindMostWorkChainImpl();
        assert(picked == nullptr || picked == activeTip);
    }
    const std::string err = cap.str();

    // Chain unchanged.
    assert(cs.GetTip() == activeTip);
    assert(cs.GetTip()->nHeight == N);

    // No m_chain_needs_rebuild marker fired.
    assert(!cs.NeedsChainRebuild());

    // No [CRITICAL] log lines.
    assert(err.find("[CRITICAL]") == std::string::npos);

    // Active tip not marked failed.
    assert(!(activeTip->nStatus & CBlockIndex::BLOCK_FAILED_VALID));

    DisengagePath();
    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// T1.2 — Reorg-depth cap.
// ---------------------------------------------------------------------------
void test_t1_2_reorg_depth_cap_rejects_deep_sibling()
{
    std::cout << "  test_t1_2_reorg_depth_cap_rejects_deep_sibling..." << std::flush;

    EngageNewPath();
    CChainState cs;

    // Active chain to h=200 (full data).
    ActiveChain active = BuildActiveChain(cs, /*chain_id=*/0x70, 200);
    CBlockIndex* activeTip = active.tip;
    CBlockIndex* genesis = active.genesis;

    // Sibling chain forking at genesis (h=0), walking to h=350. Reorg depth
    // when activating sibling-leaf: tip(200) - fork(0) = 200 > MAX_REORG_DEPTH
    // (60). F4 trips. ALL ancestors have BLOCK_HAVE_DATA so F5 wouldn't
    // reject — F4 must.
    CBlockIndex* sibPrev = genesis;
    for (int h = 1; h <= 350; ++h) {
        auto p = MakeIdx(/*chain_id=*/0x80, sibPrev, h,
                         CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                         CBlockIndex::BLOCK_HAVE_DATA,
                         /*work=*/static_cast<uint32_t>(h + 1000),
                         /*seq=*/static_cast<uint32_t>(2000 + h));
        uint256 hh = p->GetBlockHash();
        assert(cs.AddBlockIndex(hh, std::move(p)));
        sibPrev = cs.GetBlockIndex(hh);
    }
    // Bump leaf chainwork over active tip to force selection.
    std::memset(sibPrev->nChainWork.data, 0, 32);
    sibPrev->nChainWork.data[0] = 0xff;
    sibPrev->nChainWork.data[1] = 0xff;
    sibPrev->nChainWork.data[2] = 0xff;
    sibPrev->nChainWork.data[3] = 0xff;

    cs.RecomputeCandidates();

    CBlockIndex* picked = cs.FindMostWorkChainImpl();
    assert(picked == sibPrev);  // sibling is heaviest, ancestors all have data

    bool fInvalidFound = false;
    bool ok = cs.ActivateBestChainStep(picked, /*pblock_optional=*/nullptr,
                                       fInvalidFound);

    // F4 (post-F8 semantics, Layer-3 HIGH-2 + state-replay S3): depth
    // 200 > MAX_REORG_DEPTH (60) → erase from candidates (NOT MarkBlockAsFailed) + set
    // m_chain_needs_rebuild for wrapper-driven recovery via the
    // v4.3.2-M1 main-loop helper.
    assert(!ok);
    assert(cs.GetTip() == activeTip);
    assert(cs.GetTip()->nHeight == 200);

    // F8 HIGH-2 fix: candidate is NOT marked failed (depth ≠ invalid).
    // The canonical chain remains eligible for re-consideration when the
    // operator runs reconsiderblock or after wipe-and-IBD.
    assert(!(sibPrev->nStatus & CBlockIndex::BLOCK_FAILED_VALID));
    assert(!(sibPrev->nStatus & CBlockIndex::BLOCK_FAILED_CHILD));

    // F8 S3 follow-on: rebuild flagged for the M1 main-loop helper to
    // observe, write auto_rebuild marker via config.datadir, and trigger
    // wrapper restart with wipe-and-IBD recovery.
    assert(cs.NeedsChainRebuild());

    // F11 (Layer-3 round 2 MEDIUM-1): the cause must be DepthRejection so
    // the M1 helper emits the correct banner instead of the legacy
    // "Persistent UndoBlock failure" text.
    assert(cs.GetChainRebuildReason() ==
           CChainState::ChainRebuildReason::DepthRejection);

    DisengagePath();
    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// T1.3 — Pre-validation atomicity.
// ---------------------------------------------------------------------------
void test_t1_3_pre_validation_atomicity_no_disconnect_on_unreadable()
{
    std::cout << "  test_t1_3_pre_validation_atomicity_no_disconnect_on_unreadable..."
              << std::flush;

    EngageNewPath();
    CChainState cs;

    const int N = 20;
    ActiveChain active = BuildActiveChain(cs, /*chain_id=*/0x90, N);
    CBlockIndex* activeTip = active.tip;
    CBlockIndex* fork_anchor = active.all[N - 5];  // fork at h=15

    // Sibling chain h=N-4..N+5 with full data on flags. We'll mark one
    // intermediate as "unreadable" via the test override.
    CBlockIndex* sibPrev = fork_anchor;
    CBlockIndex* unreadable = nullptr;
    for (int h = N - 4; h <= N + 5; ++h) {
        auto p = MakeIdx(/*chain_id=*/0xA0, sibPrev, h,
                         CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                         CBlockIndex::BLOCK_HAVE_DATA,
                         /*work=*/static_cast<uint32_t>(h + 50),
                         /*seq=*/static_cast<uint32_t>(3000 + h));
        uint256 hh = p->GetBlockHash();
        assert(cs.AddBlockIndex(hh, std::move(p)));
        sibPrev = cs.GetBlockIndex(hh);
        if (h == N) unreadable = sibPrev;
    }
    assert(unreadable != nullptr);
    // Bump leaf chainwork over active tip.
    std::memset(sibPrev->nChainWork.data, 0, 32);
    sibPrev->nChainWork.data[0] = 0xff;
    sibPrev->nChainWork.data[1] = 0xff;
    sibPrev->nChainWork.data[2] = 0xff;

    cs.RecomputeCandidates();

    // ReadBlock override: fail for `unreadable`, succeed empty otherwise.
    uint256 hUnreadable = unreadable->GetBlockHash();
    cs.SetTestReadBlockOverride(
        [hUnreadable](const uint256& hash, CBlock& out) {
            if (std::memcmp(hash.data, hUnreadable.data, 32) == 0) return false;
            out = CBlock();
            return true;
        });

    auto disconnectCount = std::make_shared<int>(0);
    cs.SetTestDisconnectTipOverride([disconnectCount](CBlockIndex*) {
        ++(*disconnectCount);
        return true;
    });

    CBlockIndex* picked = cs.FindMostWorkChainImpl();
    assert(picked == sibPrev);

    bool fInvalidFound = false;
    bool ok = cs.ActivateBestChainStep(picked, /*pblock_optional=*/nullptr,
                                       fInvalidFound);

    // F3 catches the unreadable block in pre-validation BEFORE any disconnect.
    assert(!ok);
    assert(*disconnectCount == 0);
    assert(!cs.NeedsChainRebuild());
    assert(cs.GetTip() == activeTip);

    DisengagePath();
    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// T1.4 — Bit-mask literal validity (F1).
// ---------------------------------------------------------------------------
void test_t1_4_bit_mask_have_data_only_is_not_candidate()
{
    std::cout << "  test_t1_4_bit_mask_have_data_only_is_not_candidate..." << std::flush;

    CChainState cs;

    // Genesis with full status.
    auto pA = MakeIdx(/*chain_id=*/0xB0, nullptr, 0,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(cs.AddBlockIndex(hA, std::move(pA)));
    cs.SetTip(cs.GetBlockIndex(hA));

    // Bad block: nStatus = BLOCK_HAVE_DATA only (no level bits).
    // Pre-F1 (mask=0x1F): (8 & 0x1F) = 8 ≥ 3 → predicate TRUE.
    // Post-F1 (mask=0x07): (8 & 0x07) = 0 < 3 → predicate FALSE.
    auto pBad = MakeIdx(/*chain_id=*/0xB1, cs.GetBlockIndex(hA), 1,
                        /*status=*/CBlockIndex::BLOCK_HAVE_DATA,
                        /*work=*/10, /*seq=*/2);
    uint256 hBad = pBad->GetBlockHash();
    assert(cs.AddBlockIndex(hBad, std::move(pBad)));
    CBlockIndex* bad = cs.GetBlockIndex(hBad);

    // Post-F1: predicate must say NOT a candidate.
    assert(!cs.IsBlockACandidateForActivation(bad));

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// T1.7 — F7 (Layer-3 HIGH-1): RaiseValidity after HAVE_DATA OR makes the
// block a candidate. This regression test simulates the EXACT production
// sequence at every block-arrival site (block_processing.cpp:1083 etc.):
//
//   pblockIndex->nStatus |= CBlockIndex::BLOCK_HAVE_DATA;          // F1
//   pblockIndex->RaiseValidity(CBlockIndex::BLOCK_VALID_TRANSACTIONS);  // F7
//
// Step 1 alone (pre-F7 production state under post-F1 mask 0x07) leaves
// the block at validLevel=0, predicate FALSE. Step 2 raises it to 3,
// predicate TRUE. T1.4 proves the negative; T1.7 proves the positive AND
// that RaiseValidity actually mutates correctly.
//
// Without this test: future code changes that remove the F7 RaiseValidity
// call at any of the 5 production sites would silently revert v4.3.3 to
// the chain-stalling state Layer-3 caught. T1.4 alone would not catch it
// (T1.4 tests the negative case). T1/T2 helpers auto-OR HAVE_DATA when
// level >= TRANSACTIONS, so they cannot reproduce the production gap.
// ---------------------------------------------------------------------------
void test_t1_7_raise_validity_after_have_data_makes_candidate()
{
    std::cout << "  test_t1_7_raise_validity_after_have_data_makes_candidate..." << std::flush;

    CChainState cs;

    // Genesis with full status (just to satisfy SetTip).
    auto pG = MakeIdx(/*chain_id=*/0xE0, nullptr, 0,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 1, 1);
    uint256 hG = pG->GetBlockHash();
    assert(cs.AddBlockIndex(hG, std::move(pG)));
    cs.SetTip(cs.GetBlockIndex(hG));

    // Step 1: build a CBlockIndex the way production does — nStatus=0
    // initially (default-constructed), then OR-merge BLOCK_HAVE_DATA (F1).
    // Crucially: NO automatic raise of the level field.
    auto pNew = MakeIdx(/*chain_id=*/0xE1, cs.GetBlockIndex(hG), 1,
                        /*status=*/0,
                        /*work=*/10, /*seq=*/2);
    pNew->nStatus |= CBlockIndex::BLOCK_HAVE_DATA;

    // Pre-F7 state: HAVE_DATA flag set, but level field = 0. Predicate
    // must say NOT a candidate (post-F1 mask). This is the chain-stalling
    // bug Layer-3 caught.
    assert((pNew->nStatus & CBlockIndex::BLOCK_VALID_MASK) == 0);
    assert(pNew->nStatus & CBlockIndex::BLOCK_HAVE_DATA);
    uint256 hNew = pNew->GetBlockHash();
    assert(cs.AddBlockIndex(hNew, std::move(pNew)));
    CBlockIndex* arrived = cs.GetBlockIndex(hNew);
    assert(!cs.IsBlockACandidateForActivation(arrived));  // pre-F7: FALSE

    // Step 2: apply F7 — RaiseValidity to BLOCK_VALID_TRANSACTIONS. The
    // helper must mutate nStatus correctly and return true (raised).
    const bool raised = arrived->RaiseValidity(CBlockIndex::BLOCK_VALID_TRANSACTIONS);
    assert(raised);
    assert((arrived->nStatus & CBlockIndex::BLOCK_VALID_MASK)
           == CBlockIndex::BLOCK_VALID_TRANSACTIONS);
    // HAVE_DATA preserved.
    assert(arrived->nStatus & CBlockIndex::BLOCK_HAVE_DATA);
    // Predicate now TRUE — block enters the candidate set.
    assert(cs.IsBlockACandidateForActivation(arrived));

    // Idempotency: second RaiseValidity at the same level returns false
    // and does not mutate.
    const bool raised_again = arrived->RaiseValidity(CBlockIndex::BLOCK_VALID_TRANSACTIONS);
    assert(!raised_again);
    assert((arrived->nStatus & CBlockIndex::BLOCK_VALID_MASK)
           == CBlockIndex::BLOCK_VALID_TRANSACTIONS);

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// T1.8 — F14 (Layer-3 round 2 LOW-2 / MEDIUM-3): canonical block-receipt
// flag-setter regression test.
//
// Layer-3 round 2 flagged that T1.7 verifies the RaiseValidity helper
// in isolation but would NOT catch removal of the F7 RaiseValidity call
// at any of the 5 production block-arrival sites — silent regression
// to the canary-3 chain-stall state.
//
// F14 closes the gap by extracting the F1+F7 pattern into a single
// CBlockIndex::MarkBlockReceived helper called from all 5 production
// sites. T1.8 exercises that helper and asserts:
//   * Post-MarkBlockReceived: HAVE_DATA bit set, validLevel = TRANSACTIONS.
//   * Post-MarkBlockReceived: IsBlockACandidateForActivation returns TRUE.
//   * Idempotency: second MarkBlockReceived call leaves nStatus unchanged.
//   * Pre-MarkBlockReceived (default-constructed CBlockIndex):
//     IsBlockACandidateForActivation returns FALSE — confirms the gate is
//     real. (Identical assertion to T1.4's negative case but framed
//     adjacent to the positive case for clarity.)
//
// Future regression-prevention: any site that records a block-receipt
// MUST call MarkBlockReceived. If a developer open-codes
// `nStatus |= BLOCK_HAVE_DATA` without raising validity, the production
// chain stalls under --usenewpeerman=1 — and a code reviewer scanning
// for the helper-call pattern will catch the deviation immediately.
// ---------------------------------------------------------------------------
void test_t1_8_mark_block_received_canonical_flag_setter()
{
    std::cout << "  test_t1_8_mark_block_received_canonical_flag_setter..." << std::flush;

    CChainState cs;

    // Genesis with full status.
    auto pG = MakeIdx(/*chain_id=*/0xF0, nullptr, 0,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 1, 1);
    uint256 hG = pG->GetBlockHash();
    assert(cs.AddBlockIndex(hG, std::move(pG)));
    cs.SetTip(cs.GetBlockIndex(hG));

    // Pre-receipt: build a CBlockIndex the way production does — default-
    // constructed and not-yet-flagged. Predicate must say NOT a candidate.
    auto pNew = MakeIdx(/*chain_id=*/0xF1, cs.GetBlockIndex(hG), 1,
                        /*status=*/0,
                        /*work=*/10, /*seq=*/2);
    assert((pNew->nStatus & CBlockIndex::BLOCK_VALID_MASK) == 0);
    assert(!(pNew->nStatus & CBlockIndex::BLOCK_HAVE_DATA));
    uint256 hNew = pNew->GetBlockHash();
    assert(cs.AddBlockIndex(hNew, std::move(pNew)));
    CBlockIndex* arrived = cs.GetBlockIndex(hNew);
    assert(!cs.IsBlockACandidateForActivation(arrived));

    // F14: call the canonical block-receipt flag-setter. Must atomically
    // set HAVE_DATA and raise validity to TRANSACTIONS.
    arrived->MarkBlockReceived();
    assert(arrived->nStatus & CBlockIndex::BLOCK_HAVE_DATA);
    assert((arrived->nStatus & CBlockIndex::BLOCK_VALID_MASK)
           == CBlockIndex::BLOCK_VALID_TRANSACTIONS);
    // Predicate now TRUE — block enters the candidate set.
    assert(cs.IsBlockACandidateForActivation(arrived));

    // Idempotency: second call leaves state unchanged.
    const uint32_t status_after_first = arrived->nStatus;
    arrived->MarkBlockReceived();
    assert(arrived->nStatus == status_after_first);
    assert(cs.IsBlockACandidateForActivation(arrived));

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// T1.9 — F10 + F15 (Layer-3 round 3 HIGH-1): VDF grace-period anchor must
// fire ONLY on first arrival at a height. Layer-3 round 3 caught that
// pre-F15 the connect-loop anchor reset on every successful ConnectTip,
// including reorg-replacement connects — perpetuating replacements
// indefinitely while legacy seeds settle on first arrival. T1.9 asserts
// the post-F15 first-arrival-only semantics.
//
// Cases:
//   * Anchor fires once at h=N (first arrival): returns true, fields updated.
//   * Re-call with same-height sibling (Case 2.5 replacement): returns
//     false, fields UNCHANGED — proves the F15 predicate.
//   * Forward progress to h=N+1: returns true, fields updated to new height.
//   * Pre-VDF-activation block (height < activation): returns false.
//   * Non-VDF-version block (nVersion < 4): returns false.
//   * Null block: returns false.
//
// Without F15 the same-height-sibling case would re-anchor and the test
// fails; with F15 the test passes.
// ---------------------------------------------------------------------------
void test_t1_9_grace_period_anchor_first_arrival_only()
{
    std::cout << "  test_t1_9_grace_period_anchor_first_arrival_only..." << std::flush;

    // Stub ChainParams with VDF activation at h=0 so any block post-genesis
    // qualifies. Save + restore globally so other tests aren't affected.
    Dilithion::ChainParams* savedParams = Dilithion::g_chainParams;
    Dilithion::ChainParams stub;
    stub.vdfLotteryActivationHeight = 0;
    Dilithion::g_chainParams = &stub;

    CChainState cs;

    // Genesis-like block at h=0 (VDF version, full status).
    auto pG = MakeIdx(/*chain_id=*/0xD0, nullptr, 0,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 1, 1);
    uint256 hG = pG->GetBlockHash();
    assert(cs.AddBlockIndex(hG, std::move(pG)));
    cs.SetTip(cs.GetBlockIndex(hG));

    // Block A at h=1 (first arrival; AddBlockIndex enforces
    // height == prev->height+1, so we use consecutive heights here).
    auto pA = MakeIdx(/*chain_id=*/0xD1, cs.GetBlockIndex(hG), 1,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 100, 2);
    uint256 hA = pA->GetBlockHash();
    assert(cs.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = cs.GetBlockIndex(hA);

    // Pre-anchor state: m_vdfTipAcceptHeight = -1 (default).
    assert(cs.m_vdfTipAcceptHeight == -1);

    // Case 1: first arrival at h=1. Anchor MUST fire.
    const bool first = cs.MaybeAnchorVdfGrace(A);
    assert(first == true);
    assert(cs.m_vdfTipAcceptHeight == 1);
    const auto t_A = cs.m_vdfTipAcceptTime;
    assert(t_A != std::chrono::steady_clock::time_point{});

    // Case 2: sibling B at h=1 (Case 2.5 replacement). Must NOT re-anchor.
    auto pB = MakeIdx(/*chain_id=*/0xD2, cs.GetBlockIndex(hG), 1,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 100, 3);
    uint256 hB = pB->GetBlockHash();
    assert(cs.AddBlockIndex(hB, std::move(pB)));
    CBlockIndex* B = cs.GetBlockIndex(hB);

    // Sleep a non-zero interval so any erroneous re-anchor would advance the
    // timestamp, allowing equality assertion below to detect the regression.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    const bool replacement = cs.MaybeAnchorVdfGrace(B);
    assert(replacement == false);
    assert(cs.m_vdfTipAcceptHeight == 1);
    assert(cs.m_vdfTipAcceptTime == t_A);  // UNCHANGED — F15 invariant

    // Case 3: forward progress to h=2. Anchor MUST re-fire at new height.
    auto pC = MakeIdx(/*chain_id=*/0xD3, A, 2,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 200, 4);
    uint256 hC = pC->GetBlockHash();
    assert(cs.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = cs.GetBlockIndex(hC);

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    const bool forward = cs.MaybeAnchorVdfGrace(C);
    assert(forward == true);
    assert(cs.m_vdfTipAcceptHeight == 2);
    assert(cs.m_vdfTipAcceptTime != t_A);  // updated

    // Case 4: pre-VDF-activation block (lift activation height higher than
    // block height). Must NOT anchor.
    stub.vdfLotteryActivationHeight = 100;
    auto pD = MakeIdx(/*chain_id=*/0xD4, C, 3,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 300, 5);
    uint256 hD = pD->GetBlockHash();
    assert(cs.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = cs.GetBlockIndex(hD);
    const bool pre_vdf = cs.MaybeAnchorVdfGrace(D);
    assert(pre_vdf == false);
    assert(cs.m_vdfTipAcceptHeight == 2);  // unchanged from Case 3

    // Restore activation height.
    stub.vdfLotteryActivationHeight = 0;

    // Case 5: non-VDF-version block (manually downgrade nVersion). Must NOT
    // anchor.
    D->nVersion = 3;  // pre-VDF era
    const bool non_vdf = cs.MaybeAnchorVdfGrace(D);
    assert(non_vdf == false);
    assert(cs.m_vdfTipAcceptHeight == 2);

    // Case 6: null pointer. Must return false safely.
    const bool null_block = cs.MaybeAnchorVdfGrace(nullptr);
    assert(null_block == false);

    // Restore global chainparams.
    Dilithion::g_chainParams = savedParams;

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// T1.5 — PruneBlockIndexCandidates correctness.
// ---------------------------------------------------------------------------
void test_t1_5_prune_candidates_keeps_only_geq_tip_work()
{
    std::cout << "  test_t1_5_prune_candidates_keeps_only_geq_tip_work..." << std::flush;

    CChainState cs;

    // Tree: genesis A at work=1. Three siblings B(5), C(10), D(20) all
    // off A. Tip set to C.
    auto pA = MakeIdx(/*chain_id=*/0xC0, nullptr, 0,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 1, 1);
    uint256 hA = pA->GetBlockHash();
    assert(cs.AddBlockIndex(hA, std::move(pA)));
    CBlockIndex* A = cs.GetBlockIndex(hA);

    auto pB = MakeIdx(/*chain_id=*/0xC1, A, 1,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 5, 2);
    uint256 hB = pB->GetBlockHash();
    assert(cs.AddBlockIndex(hB, std::move(pB)));

    auto pC = MakeIdx(/*chain_id=*/0xC2, A, 1,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 10, 3);
    uint256 hC = pC->GetBlockHash();
    assert(cs.AddBlockIndex(hC, std::move(pC)));
    CBlockIndex* C = cs.GetBlockIndex(hC);

    auto pD = MakeIdx(/*chain_id=*/0xC3, A, 1,
                      CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                      CBlockIndex::BLOCK_HAVE_DATA, 20, 4);
    uint256 hD = pD->GetBlockHash();
    assert(cs.AddBlockIndex(hD, std::move(pD)));
    CBlockIndex* D = cs.GetBlockIndex(hD);

    cs.SetTip(C);  // tip work=10
    cs.RecomputeCandidates();

    // Pre-prune: candidates = {B, C, D}. FindMostWork picks D (heaviest).
    assert(cs.FindMostWorkChainImpl() == D);

    cs.PruneBlockIndexCandidates();

    // Post-prune: B (work=5 < 10=tip) erased. C and D remain.
    // FindMostWork still returns D (heaviest among kept).
    assert(cs.FindMostWorkChainImpl() == D);

    // STRONG PROBE: invalidate D AND C in turn. After both are failed:
    //   * Pre-F6 (no prune): B was still in the set; FindMostWork returns B.
    //   * Post-F6 (pruned):  B was erased; FindMostWork returns nullptr.
    //
    // This single observation distinguishes pre/post F6 even though F6's
    // immediate effect (set bound) is private state.
    cs.MarkBlockAsFailed(D);
    cs.MarkBlockAsFailed(C);
    CBlockIndex* picked = cs.FindMostWorkChainImpl();
    // Post-F6: B was pruned → nullptr returned.
    assert(picked == nullptr);

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// T1.6 — Per-ancestor data gate (F5).
// ---------------------------------------------------------------------------
void test_t1_6_per_ancestor_data_gate_drops_leaf_with_missing_intermediate()
{
    std::cout << "  test_t1_6_per_ancestor_data_gate_drops_leaf_with_missing_intermediate..."
              << std::flush;

    EngageNewPath();
    CChainState cs;

    const int N = 10;
    ActiveChain active = BuildActiveChain(cs, /*chain_id=*/0xD0, N);
    CBlockIndex* fork_anchor = active.tip;  // fork off the active tip

    // Sibling chain h=N+1..N+5 with full data EXCEPT h=N+3 lacks BLOCK_HAVE_DATA.
    CBlockIndex* sibPrev = fork_anchor;
    for (int h = N + 1; h <= N + 5; ++h) {
        const uint32_t status = (h == N + 3)
            ? CBlockIndex::BLOCK_VALID_HEADER  // missing data
            : (CBlockIndex::BLOCK_VALID_TRANSACTIONS |
               CBlockIndex::BLOCK_HAVE_DATA);
        auto p = MakeIdx(/*chain_id=*/0xE0, sibPrev, h,
                         status,
                         /*work=*/static_cast<uint32_t>(h + 50),
                         /*seq=*/static_cast<uint32_t>(4000 + h));
        uint256 hh = p->GetBlockHash();
        assert(cs.AddBlockIndex(hh, std::move(p)));
        sibPrev = cs.GetBlockIndex(hh);
    }
    // Bump leaf to be heavier than active tip.
    std::memset(sibPrev->nChainWork.data, 0, 32);
    sibPrev->nChainWork.data[0] = 0xff;
    sibPrev->nChainWork.data[1] = 0xff;
    // Force the leaf's status to "fully validated" + HAVE_DATA so the
    // candidate predicate accepts it.
    sibPrev->nStatus = CBlockIndex::BLOCK_VALID_TRANSACTIONS |
                       CBlockIndex::BLOCK_HAVE_DATA;

    cs.RecomputeCandidates();

    // F5 walks ancestry from sibling leaf, hits h=N+3 (no HAVE_DATA), drops
    // the candidate. The leaf must NOT be returned by FindMostWorkChainImpl.
    CBlockIndex* picked = cs.FindMostWorkChainImpl();
    assert(picked != sibPrev);

    // Tip unchanged.
    assert(cs.GetTip()->nHeight == N);

    DisengagePath();
    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------

int main()
{
    std::cout << "=== v4.3.3 port chain-selector invariants regression suite ===\n";
    std::cout << "    (T1.1-T1.9 — synthetic harness for F1-F15 fixes)\n";

    test_t1_4_bit_mask_have_data_only_is_not_candidate();
    test_t1_5_prune_candidates_keeps_only_geq_tip_work();
    test_t1_2_reorg_depth_cap_rejects_deep_sibling();
    test_t1_3_pre_validation_atomicity_no_disconnect_on_unreadable();
    test_t1_6_per_ancestor_data_gate_drops_leaf_with_missing_intermediate();
    test_t1_1_canary_3_header_only_chain_with_bait_leaf();
    test_t1_7_raise_validity_after_have_data_makes_candidate();
    test_t1_8_mark_block_received_canonical_flag_setter();
    test_t1_9_grace_period_anchor_first_arrival_only();

    std::cout << "\n=== All 9 T1 tests passed ===\n";
    return 0;
}
