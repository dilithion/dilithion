// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// deferred_reclamation_tests — a pointer resolved before an eviction must stay
// VALID until every participating thread has passed the eviction's epoch.
//
// WHAT THIS IS FOR. The census found 62 sites that resolve a CBlockIndex* under
// cs_main and use it after the lock is released. Guarding all 62 is a fix aimed at
// consumers when the defect has one producer, so eviction now UNLINKS immediately
// and defers the FREE to a quiescent point. This suite pins the three properties
// that makes correct:
//
//   1. UNLINK IS IMMEDIATE — a by-hash re-resolve returns null the moment the
//      entry is evicted, exactly as before. Deferral must not make a dead entry
//      look alive to anyone who asks properly.
//   2. THE MEMORY SURVIVES — a pointer resolved BEFORE the eviction is still
//      readable after it, which is the whole point.
//   3. THE DRAIN IS GATED — nothing is freed while a registered thread has not
//      passed the epoch, and a thread that has never checkpointed pins everything.
//
// ⚠️ WHAT THIS SUITE CANNOT PROVE. It cannot demonstrate the use-after-free that
// deferral prevents: reading freed memory is undefined behaviour, and a test that
// "passes" by reading it is testing the allocator's mood. That evidence has to
// come from ASan, and the CI AddressSanitizer job is the named machine verdict.
// Stated here so nobody reads a green run as proof of memory safety -- it is proof
// of the LIFETIME RULES, which is a different and weaker claim.

#include <consensus/chain.h>
#include <consensus/port/chain_selector_impl.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

int g_failed = 0;
void chk(const std::string& what, bool ok)
{
    std::cout << (ok ? "   PASS  " : "   FAIL  ") << what << std::endl;
    if (!ok) ++g_failed;
}

CBlockHeader MakeHeader(const uint256& parent, uint32_t nTime, uint8_t tag)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;
    h.hashPrevBlock = parent;
    std::memset(h.hashMerkleRoot.data, 0, 32);
    h.nTime = nTime;
    h.nBits = 0x1d00ffff;
    h.nNonce = 0;
    std::memset(h.vdfProofHash.data, 0, 32);
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i] = tag;
    return h;
}

}  // namespace

int main()
{
    std::cout << "\n=== deferred reclamation: unlink now, free at quiescence ===\n"
              << std::endl;

    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::ChainParams params = Dilithion::ChainParams::Regtest();
    Dilithion::g_chainParams = &params;

    CChainState cs;
    ::dilithion::consensus::port::ChainSelectorAdapter ad(cs);

    uint256 zero;
    std::memset(zero.data, 0, 32);
    auto g = MakeHeader(zero, 1700500000, 0x01);
    if (!ad.ProcessNewHeader(g)) { std::cerr << "genesis rejected" << std::endl; return 2; }
    const uint256 gh = g.GetHash();

    // A main chain to hold the tip, plus a low-work sibling leaf to evict.
    uint256 prev = gh;
    for (int i = 1; i <= 4; ++i) {
        auto h = MakeHeader(prev, static_cast<uint32_t>(1700500000 + i),
                            static_cast<uint8_t>(0x10 + i));
        if (!ad.ProcessNewHeader(h)) { std::cerr << "chain rejected" << std::endl; return 2; }
        prev = h.GetHash();
    }
    CBlockIndex* tip = cs.GetBlockIndex(prev);
    chk("setup: tip resolved", tip != nullptr);
    cs.SetTip(tip);

    auto victimHdr = MakeHeader(gh, 1700500099, 0x99);
    if (!ad.ProcessNewHeader(victimHdr)) { std::cerr << "victim rejected" << std::endl; return 2; }
    const uint256 victimHash = victimHdr.GetHash();

    // THE RESOLVE THAT THE 62 SITES DO: obtain the pointer, then let cs_main go.
    CBlockIndex* held = cs.GetBlockIndex(victimHash);
    chk("setup: the victim resolved before eviction", held != nullptr);
    const int height_before = held ? held->nHeight : -1;

    // Checkpoint once so this thread is a REGISTERED participant. Before this it
    // has made no promise, and the drain must therefore free nothing.
    cs.EpochCheckpoint();

    const size_t before = cs.GetBlockIndexSize();
    cs.EvictLowestWorkLeafNotPinned(before - 1);

    // ---- 1. UNLINK IS IMMEDIATE -------------------------------------------
    chk("unlink: a by-hash re-resolve returns null immediately after eviction",
        cs.GetBlockIndex(victimHash) == nullptr);
    chk("unlink: the map shrank", cs.GetBlockIndexSize() == before - 1);
    chk("unlink: the entry is in the graveyard, not freed", cs.GraveyardSize() == 1);

    // ---- 2. THE MEMORY SURVIVES -------------------------------------------
    // This read is the reason the whole mechanism exists. Before deferral it was
    // a use-after-free; now the object is unlinked but alive.
    chk("survival: the pointer resolved BEFORE eviction is still readable",
        held != nullptr && held->nHeight == height_before);

    // ---- 3. THE DRAIN IS GATED --------------------------------------------
    // This thread has not checkpointed since the eviction, so it may still hold
    // the pointer (it does — `held`). Nothing may be freed.
    chk("gating: a drain frees nothing while this thread has not passed the epoch",
        cs.DrainGraveyard() == 0);
    chk("gating: the entry is still in the graveyard", cs.GraveyardSize() == 1);
    chk("gating: and it is still readable", held->nHeight == height_before);

    // Now pass the boundary — the point at which this thread promises it holds no
    // CBlockIndex*. In production this is the top of a message dispatch / worker
    // iteration / RPC completion (see the quiescence proof).
    cs.EpochCheckpoint();

    const size_t freed = cs.DrainGraveyard();
    chk("drain: after the checkpoint the entry is freed", freed == 1);
    chk("drain: the graveyard is empty", cs.GraveyardSize() == 0);
    // `held` is now dangling BY DESIGN and is deliberately not read again.

    // ---- the active chain is untouched throughout --------------------------
    chk("the tip survived", cs.GetBlockIndex(prev) != nullptr);
    chk("genesis survived", cs.GetBlockIndex(gh) != nullptr);

    // ---- REGISTRATION CENSUS: a thread that never checkpoints is a LEAK ------
    //
    // A non-participating thread pins the graveyard for the process lifetime.
    // That is the SAFE direction — nothing is freed on the account of a thread
    // that made no promise — but it is a silent unbounded leak: the node behaves
    // correctly and memory grows. Worst possible shape for a defect, so the
    // registration is asserted rather than assumed.
    {
        std::string why;
        // This test process has exactly one participating thread (main), which
        // has checkpointed above.
        chk("registration: at least one thread has registered",
            cs.RegisteredEpochThreads() >= 1);
        chk("registration: the census passes when the expectation is met",
            cs.EpochRegistrationComplete(1, why));

        // And it must FAIL loudly, with a diagnostic, when a participant is
        // missing — the ninth-thread-added-later case.
        why.clear();
        const bool ok = cs.EpochRegistrationComplete(99, why);
        chk("registration: a missing participant FAILS the census", !ok);
        chk("registration: and the failure explains the leak, not just a count",
            !why.empty() && why.find("PINS THE GRAVEYARD") != std::string::npos);
    }

    Dilithion::g_chainParams = saved;

    std::cout << "\n  ===== deferred reclamation: "
              << (g_failed == 0 ? "PASS" : "FAIL") << " (" << g_failed
              << " failed) =====\n" << std::endl;
    return g_failed == 0 ? 0 : 1;
}
