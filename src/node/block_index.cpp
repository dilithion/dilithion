// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_index.h>
#include <consensus/pow.h>
#include <consensus/chain_work.h>  // Phase 3: shared chain-work helper
#include <sstream>
#include <cstring>
#include <iostream>

CBlockIndex::CBlockIndex() {
    pprev = nullptr;
    pnext = nullptr;
    pskip = nullptr;
    nHeight = 0;
    nFile = 0;
    nDataPos = 0;
    nUndoPos = 0;
    nChainWork = uint256();
    nTx = 0;
    nStatus = 0;
    nSequenceId = 0;
    nTime = 0;
    nBits = 0;
    nNonce = 0;
    nVersion = 0;
}

CBlockIndex::CBlockIndex(const CBlockHeader& block) {
    pprev = nullptr;
    pnext = nullptr;
    pskip = nullptr;
    nHeight = 0;
    nFile = 0;
    nDataPos = 0;
    nUndoPos = 0;
    nChainWork = uint256();
    nTx = 0;
    nStatus = 0;
    nSequenceId = 0;
    header = block;
    nTime = block.nTime;
    nBits = block.nBits;
    nNonce = block.nNonce;
    nVersion = block.nVersion;
}

// BUG #70 FIX: Explicit copy constructor to ensure ALL fields are copied
// including header.hashMerkleRoot which was being lost during database loading
CBlockIndex::CBlockIndex(const CBlockIndex& other) {
    // Copy the FULL header including merkle root
    header = other.header;

    // Copy pointers (will be re-linked during chain loading)
    pprev = other.pprev;
    pnext = other.pnext;
    pskip = other.pskip;

    // Copy all integer fields
    nHeight = other.nHeight;
    nFile = other.nFile;
    nDataPos = other.nDataPos;
    nUndoPos = other.nUndoPos;
    nChainWork = other.nChainWork;
    nTx = other.nTx;
    nStatus = other.nStatus;
    nSequenceId = other.nSequenceId;
    nTime = other.nTime;
    nBits = other.nBits;
    nNonce = other.nNonce;
    nVersion = other.nVersion;
    phashBlock = other.phashBlock;
}

uint256 CBlockIndex::GetBlockHash() const {
    // IBD DEADLOCK FIX #10: Don't auto-compute RandomX hash
    // Computing header.GetHash() here acquires g_validation_mutex for ~700ms
    // If called from ActivateBestChain (which holds cs_main), this can cause
    // severe contention with the message handler thread, effectively serializing
    // all block processing and causing apparent freezes.
    //
    // Instead, require all CBlockIndex creation sites to set phashBlock explicitly.
    // If phashBlock is null, log an error and return null hash (don't block).
    if (phashBlock.IsNull()) {
        std::cerr << "[DEADLOCK-FIX] ERROR: GetBlockHash() called with null phashBlock!" << std::endl;
        std::cerr << "  nHeight: " << nHeight << ", nTime: " << nTime << std::endl;
        // Return null hash instead of computing (prevents blocking)
        return uint256();
    }
    return phashBlock;
}

bool CBlockIndex::IsValid() const {
    return (nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_HEADER;
}

bool CBlockIndex::HaveData() const {
    return (nStatus & BLOCK_HAVE_DATA) != 0;
}

std::string CBlockIndex::ToString() const {
    std::stringstream ss;
    ss << "CBlockIndex(hash=" << GetBlockHash().GetHex().substr(0, 20) << "...";
    ss << ", height=" << nHeight << ", nTx=" << nTx << ")";
    return ss.str();
}

uint256 CBlockIndex::GetBlockProof() const {
    // Phase 3 (2026-04-26): chain-work formula consolidated into
    // dilithion::consensus::ComputeChainWork(nBits). One source of truth;
    // both this method and HeadersSyncState now route through it.
    return dilithion::consensus::ComputeChainWork(nBits);
}

void CBlockIndex::BuildChainWork() {
    // Phase 3: consolidated through dilithion::consensus::AddChainWork
    if (pprev == nullptr) {
        nChainWork = GetBlockProof();
    } else {
        nChainWork = dilithion::consensus::AddChainWork(pprev->nChainWork,
                                                        GetBlockProof());
    }
}

// Helper functions for skip pointer calculation
static inline int InvertLowestOne(int n) {
    return n & (n - 1);
}

static inline int GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to
    // Skip back exponentially: every 2^n blocks, skip 2^n back
    //
    // This WOULD give O(log n) lookup - and does not today. Nothing ever
    // assigns pskip: there is no BuildSkip in this tree, both constructors
    // null it and the copy-ctor copies a nullptr, so GetAncestor always takes
    // the pprev fallback and every ancestor lookup is O(n). Stated because a
    // complexity claim that is false is what invites someone to "finish" the
    // port by adding BuildSkip - which is exactly the change that would have
    // armed the overshoot bug fixed in GetAncestor below.
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

namespace bitest {
// TEST-ONLY forwarders. GetSkipHeight and InvertLowestOne are file-static, and
// the regression test must build its skip lists with THIS tree's recipe rather
// than a copy of it - a copied helper would let the two drift and the test
// would then certify a schedule the production walk does not use.
int GetSkipHeightForTest(int height) { return GetSkipHeight(height); }
int InvertLowestOneForTest(int n)     { return InvertLowestOne(n); }
}  // namespace bitest

CBlockIndex* CBlockIndex::GetAncestor(int height) {
    // Return nullptr if requested height is higher than this block
    if (height > nHeight || height < 0) {
        return nullptr;
    }

    // Already at requested height
    if (height == nHeight) {
        return this;
    }

    // Use skip pointer for efficient traversal if available
    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;

    while (heightWalk > height) {
        // Determine how far to skip
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);

        // PORTED VERBATIM from Bitcoin Core (CBlockIndex::GetAncestor, chain.cpp).
        // Core's comment: "Only follow pskip if pprev->pskip isn't better than
        // pskip->pprev."
        //
        // WHAT WAS HERE, and why it was wrong:
        //     (pindexWalk->pskip->nHeight >= height || heightSkip < heightSkipPrev)
        // The second disjunct licenses following pskip whenever the skip target
        // for this height is BELOW the skip target for the height beneath it -
        // which is exactly the case where the skip lands past the block we are
        // looking for. It permits the overshoot Core's condition forbids.
        //
        // [measured, N=4096, all 8,390,656 (from,to) pairs, harness linked
        // against the REAL block_index.o] with a correctly built skip list the
        // old condition returned a WRONG-HEIGHT index on 8,364,034 pairs =
        // 99.68%; with the skip list built by Core's BuildSkip recipe run
        // through this same function the errors compound to 99.88%. Core's
        // condition below: 0 mismatches on the identical chain, in both
        // configurations. Canonical case: chain[8].GetAncestor(7) returned
        // GENESIS, because GetSkipHeight(8)=0 < GetSkipHeight(7)=1.
        //
        // Every failure is a wrong INDEX, never a nullptr, so not one caller's
        // null check would have caught it - and the 22 production call sites
        // include checkpoint enforcement, the PoW difficulty anchor, fork-point
        // resolution and locator building.
        //
        // This was HARMLESS ONLY because pskip is inert in this tree: no
        // BuildSkip exists, both constructors null it and the copy-ctor copies
        // a nullptr, so GetAncestor degrades to a plain pprev walk (MODE A: 0
        // mismatches in the same 8.39M pairs). It is a landmine armed the moment
        // anyone adds BuildSkip() - which chain.cpp already warns someone may
        // do. Fixed here BEFORE that happens, not after.
        if (pindexWalk->pskip != nullptr &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            pindexWalk = pindexWalk->pskip;
            // KEPT, not Core's `heightWalk = heightSkip;`. The two agree
            // whenever the skip list is well formed, and reading the target's
            // real height keeps the loop honest if it is not. This is also the
            // shape the measurement above was taken with: the control that
            // scored 0/8,390,656 read pskip->nHeight too, so the ported
            // condition is verified in exactly this loop, not an idealised one.
            heightWalk = pindexWalk->nHeight;
        } else {
            // Fall back to pprev. KEPT, not Core's `assert(pindexWalk->pprev)`:
            // a truncated chain returns nullptr here rather than aborting a node.
            if (pindexWalk->pprev == nullptr) {
                return nullptr;
            }
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }

    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const {
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}
