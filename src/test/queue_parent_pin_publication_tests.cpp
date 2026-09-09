// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// queue_parent_pin_publication_tests — the PRODUCER half of the clause-(d)
// parent pin: does CBlockValidationQueue actually PUBLISH a queued block's
// parent hash?
//
// ⚠️ WHY THIS FILE EXISTS, AND IT IS A COVERAGE FAILURE IN MY OWN TEST.
//
// PR #129 round 2 made GetPendingBlockHashes report each pending block's
// hashPrevBlock, so eviction clause (d) can pin the parent of a queued block that
// is not yet in mapBlockIndex — the create-path case, where the child pins
// nothing because `mapBlockIndex.find(child)` misses and the ancestor walk never
// runs.
//
// Round 3's Test 14 (headers_manager_to_chain_selector_wiring_tests) was written
// to cover that and DOES NOT. It registers its own provider lambda directly on
// the chainstate, so it proves the EVICTOR honours parent hashes it is handed —
// it never exercises the code that PRODUCES them. A reviewer deleted the parent
// reporting from GetPendingBlockHashes and all four suites stayed green: the
// mutant survived 0/0/0/0. That is "unreached, not unwritten" — a correct check
// that nothing routes the real producer through.
//
// So this suite drives the REAL CBlockValidationQueue::QueueBlock and reads the
// REAL GetPendingBlockHashes. Deleting the parent-reporting lines fails it.
//
// WHAT IT DELIBERATELY DOES NOT COVER. The worker is never started, so the
// queued→in-flight handoff and the pop-side multiset erase are not exercised
// here; ProcessBlock is private and needs a wired DB plus ActivateBestChain to
// drive end-to-end. The sibling-parent arm below pins the multiset's COUNTING
// contract as far as the public surface allows. The end-to-end queue harness is
// a #193 deliverable and is named as one rather than implied to exist.

#include <consensus/chain.h>
#include <core/chainparams.h>
#include <node/block_validation_queue.h>
#include <node/blockchain_storage.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <set>
#include <string>

namespace {

int g_failed = 0;
void chk(const std::string& what, bool ok)
{
    std::cout << (ok ? "   PASS  " : "   FAIL  ") << what << std::endl;
    if (!ok) ++g_failed;
}

// A VDF-style block. IsVDFBlock() short-circuits QueueBlock's basic PoW check
// (block_validation_queue.cpp: `!block.IsVDFBlock() && !CheckProofOfWork(...)`),
// which is what lets a synthetic block reach the queue without mining one.
CBlock MakeVdfBlock(const uint256& parent_hash, uint32_t nTime, uint8_t tag)
{
    CBlock b;
    b.nVersion = CBlockHeader::VDF_VERSION;
    b.hashPrevBlock = parent_hash;
    std::memset(b.hashMerkleRoot.data, 0, 32);
    b.nTime = nTime;
    b.nBits = 0x1d00ffff;
    b.nNonce = 0;
    std::memset(b.vdfProofHash.data, 0, 32);
    for (int i = 0; i < 32; ++i) b.vdfOutput.data[i] = tag;
    return b;
}

uint256 TaggedHash(uint8_t tag)
{
    uint256 h;
    std::memset(h.data, tag, 32);
    return h;
}

}  // namespace

int main()
{
    std::cout << "\n=== queue parent-pin publication (the PRODUCER side) ===\n" << std::endl;

    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::ChainParams params = Dilithion::ChainParams::Regtest();
    Dilithion::g_chainParams = &params;

    CChainState chainstate;

    // QueueBlock never touches m_db (only ProcessBlock does), but the queue holds
    // a reference, so it needs a real object. Opened on a temp path.
    CBlockchainDB db;
    const std::string dbpath = "/tmp/dil_queue_pin_test_db";
    if (!db.Open(dbpath, true)) {
        std::cerr << "  FATAL: could not open test DB at " << dbpath << std::endl;
        Dilithion::g_chainParams = saved;
        return 2;
    }

    CBlockValidationQueue queue(chainstate, db);
    // Deliberately NOT Start()ed: the worker would consume the queue and the
    // point here is what the PRODUCER published, not what the consumer did with
    // it. (Start() also now refuses without a registered provider — a separate
    // guard, and not what this suite is testing.)

    // ---- ARM 1: an UNINDEXED child must still publish its parent -------------
    //
    // The parent hash is NOT in mapBlockIndex and neither is the child. This is
    // exactly the create-path state in which the child pins nothing on its own.
    const uint256 parentA = TaggedHash(0xA1);
    CBlock childA = MakeVdfBlock(parentA, 1700000100, 0x01);
    const uint256 childA_hash = childA.GetHash();

    chk("precondition: the child is not in mapBlockIndex",
        chainstate.GetBlockIndex(childA_hash) == nullptr);
    chk("precondition: the parent is not in mapBlockIndex",
        chainstate.GetBlockIndex(parentA) == nullptr);

    const bool queued = queue.QueueBlock(/*peer_id=*/1, childA, /*expected_height=*/1,
                                         childA_hash, /*pindex=*/nullptr);
    chk("the block is admitted to the queue", queued);

    std::set<uint256> pending = queue.GetPendingBlockHashes();
    chk("GetPendingBlockHashes reports the queued CHILD", pending.count(childA_hash) == 1);

    // THE ASSERTION THIS FILE EXISTS FOR. Deleting the parent-reporting lines
    // from GetPendingBlockHashes / QueueBlock turns this red; before round 2 it
    // was red, and no suite noticed.
    chk("GetPendingBlockHashes reports the queued block's PARENT "
        "(clause (d) can then pin it by hash)", pending.count(parentA) == 1);

    // ---- ARM 2: two siblings sharing one parent -----------------------------
    //
    // The parent is held in a MULTISET so that popping one sibling cannot unpin a
    // parent the other still needs. The public surface returns a SET, so what is
    // observable here is that one shared parent is reported once while both
    // children are reported — the de-duplication is in the reporting, not in the
    // accounting. The counting contract itself (erase(find(x)), not erase(x)) is
    // exercised on the pop path, which needs the worker; named as uncovered
    // rather than implied.
    CBlock siblingB = MakeVdfBlock(parentA, 1700000200, 0x02);
    const uint256 siblingB_hash = siblingB.GetHash();
    chk("the two siblings are distinct blocks", siblingB_hash != childA_hash);

    const bool queued2 = queue.QueueBlock(/*peer_id=*/1, siblingB, /*expected_height=*/1,
                                          siblingB_hash, /*pindex=*/nullptr);
    chk("the sibling is admitted too", queued2);

    pending = queue.GetPendingBlockHashes();
    chk("both siblings are reported", pending.count(childA_hash) == 1 &&
                                      pending.count(siblingB_hash) == 1);
    chk("their shared parent is still reported", pending.count(parentA) == 1);
    chk("the reported set is exactly {childA, siblingB, sharedParent}",
        pending.size() == 3);

    // ---- ARM 3: a different parent is reported separately --------------------
    const uint256 parentC = TaggedHash(0xC3);
    CBlock childC = MakeVdfBlock(parentC, 1700000300, 0x03);
    const uint256 childC_hash = childC.GetHash();
    const bool queued3 = queue.QueueBlock(/*peer_id=*/1, childC, /*expected_height=*/1,
                                          childC_hash, /*pindex=*/nullptr);
    chk("a block on a different parent is admitted", queued3);

    pending = queue.GetPendingBlockHashes();
    chk("the second, distinct parent is reported as well", pending.count(parentC) == 1);
    chk("the reported set is now exactly 5 hashes (3 children + 2 parents)",
        pending.size() == 5);

    Dilithion::g_chainParams = saved;

    std::cout << "\n  ===== queue parent-pin publication: "
              << (g_failed == 0 ? "PASS" : "FAIL") << " (" << g_failed
              << " failed) =====\n" << std::endl;
    return g_failed == 0 ? 0 : 1;
}
