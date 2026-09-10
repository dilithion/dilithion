// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_BLOCK_INDEX_H
#define DILITHION_NODE_BLOCK_INDEX_H

#include <primitives/block.h>
#include <cstdint>
#include <string>

namespace bitest {
// TEST-ONLY. See the definitions in block_index.cpp: the skip-height schedule is
// file-static, and the GetAncestor regression test needs the real one.
int GetSkipHeightForTest(int height);
int InvertLowestOneForTest(int n);
}  // namespace bitest

class CBlockIndex
{
public:
    CBlockHeader header;
    CBlockIndex* pprev;      // Pointer to previous block in chain
    CBlockIndex* pnext;      // Pointer to next block in MAIN chain (nullptr if not on main chain)
    CBlockIndex* pskip;      // Skip pointer for faster chain traversal
    int nHeight;
    int nFile;
    unsigned int nDataPos;
    unsigned int nUndoPos;
    uint256 nChainWork;      // Total cumulative chain work up to and including this block
    unsigned int nTx;
    uint32_t nStatus;
    uint32_t nSequenceId;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;
    int32_t nVersion;
    mutable uint256 phashBlock;

    CBlockIndex();
    explicit CBlockIndex(const CBlockHeader& block);

    /**
     * BUG #70 FIX: Explicit copy constructor to ensure header.hashMerkleRoot is copied
     * The implicit copy constructor should work, but we add explicit for safety and clarity
     */
    CBlockIndex(const CBlockIndex& other);

    uint256 GetBlockHash() const;
    bool IsValid() const;
    bool HaveData() const;
    std::string ToString() const;

    /**
     * Calculate the proof-of-work for this block
     * Work is defined as: ~uint256(0) / (target + 1)
     * Approximated as: 2^256 / (target + 1)
     */
    uint256 GetBlockProof() const;

    /**
     * Check if this block is on the main (active) chain
     * A block is on main chain if pnext is set OR if it's the current tip
     */
    bool IsOnMainChain() const { return pnext != nullptr; }

    /**
     * Build chain work from parent
     * Called during block index initialization
     */
    void BuildChainWork();

    /**
     * Get ancestor at specific height
     * Uses pskip pointers for efficient traversal
     */
    CBlockIndex* GetAncestor(int height);
    const CBlockIndex* GetAncestor(int height) const;

    // v4.3.3 F1 (audit modality 1 I4 / modality 2 LOW-15): bit-layout fix.
    // Pre-fix: BLOCK_VALID_MASK = 0x1F (5 bits). The mask covered the slot
    // BLOCK_HAVE_DATA = 0x08 was assigned to, so a block with only the
    // BLOCK_HAVE_DATA bit set evaluated to validLevel == 8 ≥ 3 ==
    // BLOCK_VALID_TRANSACTIONS, accidentally satisfying
    // IsBlockACandidateForActivation when the block had only data, no
    // validation. This let header-only-with-stale-HAVE-DATA leaves into
    // the candidate set; combined with the missing per-ancestor data gate
    // (F5), it produced the canary-3 chain-truncation incident.
    //
    // Post-fix: BLOCK_VALID_MASK = 0x07 (3 bits) — disjoint from data /
    // failure flags. validLevel literally is 0..5 again. Mirrors upstream
    // Bitcoin Core's `chain.h` enum (BLOCK_VALID_MASK covers 1|2|3|4|5,
    // i.e. the level field, NOT the higher flag bits).
    enum BlockStatus : uint32_t {
        BLOCK_VALID_UNKNOWN      = 0,
        BLOCK_VALID_HEADER       = 1,
        BLOCK_VALID_TREE         = 2,
        BLOCK_VALID_TRANSACTIONS = 3,
        BLOCK_VALID_CHAIN        = 4,
        BLOCK_VALID_SCRIPTS      = 5,
        // v4.3.3 F1: 0x07 covers values 0..5 only; HAVE/FAILED flags are
        // now strictly outside the level field.
        BLOCK_VALID_MASK         = 0x07,
        BLOCK_HAVE_DATA          = 0x08,
        BLOCK_HAVE_UNDO          = 0x10,

        // BUG #255: Failed block tracking (Bitcoin-style)
        // These flags prevent infinite retry loops for invalid blocks.
        // IMPORTANT: Only set during authoritative validation (ConnectTip)
        // where parent is on active chain and state is correct.
        // NEVER set during ProcessNewBlock, async queue, or fork staging.
        BLOCK_FAILED_VALID       = 0x20,  // Block failed validation in ConnectTip
        BLOCK_FAILED_CHILD       = 0x40,  // Descends from a BLOCK_FAILED_VALID block
        BLOCK_FAILED_MASK        = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
    };

    //! Check if this block or an ancestor failed validation
    bool IsInvalid() const { return (nStatus & BLOCK_FAILED_MASK) != 0; }

    //! Raise the validity level if it is currently lower than the requested
    //! level. Leaves data / failure flag bits untouched. Mirrors upstream
    //! Bitcoin Core's `CBlockIndex::RaiseValidity(BlockStatus level)` at
    //! `src/chain.h` (used by `ReceivedBlockTransactions` to mark a block
    //! eligible for activation once its data has been received).
    //!
    //! Returns true iff the level was actually raised (caller may use this
    //! to gate downstream side-effects such as setBlockIndexCandidates
    //! insertion).
    //!
    //! v4.3.3 F7 (Layer-3 HIGH-1): introduced after F1 made BLOCK_VALID_MASK
    //! disjoint from BLOCK_HAVE_DATA. Pre-F1 the bit overlap meant
    //! BLOCK_HAVE_DATA-only blocks accidentally satisfied the candidate
    //! predicate; post-F1 they don't, and this helper supplies the explicit
    //! invariant at the production block-arrival sites.
    bool RaiseValidity(uint32_t level) {
        // v4.3.3 F12 (Layer-3 round 2 LOW-1): defensive guard against an
        // OOB level argument. Pre-guard, passing BLOCK_HAVE_DATA(=8) by
        // mistake would silently destroy validLevel (the OR step writes
        // 8 into the status, but post-F1 mask=0x07 reads it back as 0).
        // No current caller does this, but we mask the input to ensure
        // any future caller misuse fails closed (level clamped to mask).
        level &= BLOCK_VALID_MASK;
        if ((nStatus & BLOCK_VALID_MASK) < level) {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | level;
            return true;
        }
        return false;
    }

    //! v4.3.3 F14 (Layer-3 round 2 LOW-2 / MEDIUM-3): canonical block-receipt
    //! flag-setter. Call this AT EVERY production site that records a newly-
    //! arrived full block (P2P receipt, validation queue, orphan-resolve, local
    //! mining, etc.). Combines the F1 OR-merge of BLOCK_HAVE_DATA with the F7
    //! RaiseValidity to BLOCK_VALID_TRANSACTIONS into ONE atomic-meaning op.
    //!
    //! Why a helper: pre-F14 the F1+F7 pattern was open-coded at 5 production
    //! sites (block_processing, block_validation_queue ×2, dilithion-node ×2,
    //! dilv-node). Layer-3 round 2 flagged that future code changes could
    //! remove the F7 RaiseValidity call without breaking T1.7 (which tests
    //! the helper, not the call sites) — silent regression to the canary-3
    //! chain-stall state. F14 makes the contract explicit: "call this; both
    //! flags get set together; never duplicate the pattern."
    //!
    //! Idempotent: second call sees BLOCK_HAVE_DATA already set and validity
    //! already at TRANSACTIONS, so no mutation. Safe under retry / replay.
    //!
    //! ENFORCEMENT POLICY (Cursor v4.3.3 review S13 LOW, 2026-05-04):
    //! Future block-receipt sites: DO NOT open-code
    //! `nStatus |= BLOCK_HAVE_DATA`. Always call
    //! `pindex->MarkBlockReceived()`. The ONLY legitimate places that
    //! still write the HAVE_DATA bit directly are:
    //!   1. `dilithion-node.cpp:2507` / `dilv-node.cpp:2394` — genesis
    //!      bootstrap (`nStatus = BLOCK_VALID_CHAIN | BLOCK_HAVE_DATA`).
    //!      Genesis is a one-shot bootstrap event, not a "received" event;
    //!      validity is BLOCK_VALID_CHAIN by definition (the active-chain
    //!      block at h=0). Do NOT replace these with MarkBlockReceived.
    //!   2. `chain.cpp:1718` / F2 — `ConnectTip` ORs HAVE_DATA on
    //!      successful connect AS A BACKSTOP for header-first paths
    //!      where MarkBlockReceived didn't fire (e.g., ProcessNewHeader
    //!      created the index). This is intentional defense-in-depth.
    //!
    //! Code review for any change touching block_processing.cpp,
    //! block_validation_queue.cpp, dilithion-node.cpp, dilv-node.cpp, or
    //! any new block-ingress path MUST verify MarkBlockReceived is the
    //! ONLY way HAVE_DATA reaches a freshly-allocated CBlockIndex. The
    //! 3 exceptions above are exhaustive.
    //!
    //! If you need a different validity level (rare), use
    //! `RaiseValidity(level)` directly with a comment explaining why.
    void MarkBlockReceived() {
        nStatus |= BLOCK_HAVE_DATA;
        RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    }
};

#endif
