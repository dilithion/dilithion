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
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

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
    // Corroborate the cheap in-degree check with the exhaustive scan: the suites
    // are where the O(map)-per-entry version is affordable, and where it is the
    // check that validates m_inDegree rather than trusting it.
    cs.SetDeepDrainInvariantsForTest(true);
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

    // ---- 0. NOBODY HAS CHECKPOINTED YET: THE DRAIN MUST FREE NOTHING ---------
    //
    // ⚠️ THIS ARM EXISTS BECAUSE THE CODE DID THE OPPOSITE, AND EVERY TEST IN THIS
    // FILE MISSED IT. `safe_epoch` started at the global epoch and was only ever
    // LOWERED by a registered slot, so with NO registered threads nothing lowered
    // it and the drain freed the entire graveyard on the spot — while a thread
    // that had resolved a pointer without checkpointing was still holding one.
    // The suite missed it because its very first act was to checkpoint the main
    // thread, so the registry was never empty by the time anything was measured.
    //
    // It therefore has to run FIRST: the registry is process-global and a single
    // checkpoint anywhere populates it for the life of the process.
    {
        const size_t n_before = cs.GetBlockIndexSize();
        CBlockIndex* early = cs.GetBlockIndex(victimHash);
        chk("empty registry: setup, the victim resolves before anyone checkpoints",
            early != nullptr);
        const bool evicted_early = cs.EvictLowestWorkLeafNotPinned(n_before - 1);
        chk("empty registry: setup, the eviction happened", evicted_early);
        chk("empty registry: the entry is in the graveyard", cs.GraveyardSize() == 1);
        chk("empty registry: A DRAIN WITH NO REGISTERED THREADS FREES NOTHING",
            cs.DrainGraveyard() == 0);
        chk("empty registry: and the entry is still there", cs.GraveyardSize() == 1);
        chk("empty registry: so the pointer resolved before it is still readable",
            early != nullptr && early->nHeight == 1);
    }

    // Re-add the victim for the rest of the suite (the arm above evicted it), then
    // clear the graveyard so the assertions below count only their own entry. This
    // thread checkpoints first, which is honest here: `early` above is not read
    // again, so the promise it publishes is true.
    if (!ad.ProcessNewHeader(victimHdr)) {
        std::cerr << "victim re-add rejected" << std::endl; return 2;
    }
    cs.EpochCheckpoint();
    cs.DrainGraveyard();
    chk("empty registry: once a thread HAS registered and passed, the entry drains",
        cs.GraveyardSize() == 0);

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

    // ---- A THREAD THAT EXITS MUST NOT PIN THE GRAVEYARD FOREVER -------------
    //
    // ⚠️ FOUND BY THE OCCUPANCY BENCH, NOT BY READING. Epoch slots are leaked on
    // purpose so a drain can read them after their owner exits — but a DEAD
    // thread's slot kept its last published epoch, and the drain takes the MINIMUM
    // across all slots, so the minimum froze at that value and NOTHING WAS EVER
    // FREED AGAIN. The bench ended a run with 24,936 entries in the graveyard and
    // a final drain, with every thread quiescent, freeing zero.
    //
    // This is not an exotic case: the miner threads exit when mining stops, the
    // index sync loops exit when they finish, the RPC and websocket threads exit
    // on Stop(). Any one of them would freeze reclamation for the process
    // lifetime — the same silent unbounded growth as a thread that never
    // checkpoints, reached from the opposite direction.
    {
        // A short-lived participant: checkpoints once, then exits.
        std::thread transient([&cs]() { cs.EpochCheckpoint("transient-thread"); });
        transient.join();

        // Evict a fresh victim while that thread is already gone.
        auto v2hdr = MakeHeader(gh, 1700500123, 0x77);
        if (!ad.ProcessNewHeader(v2hdr)) { std::cerr << "v2 rejected" << std::endl; return 2; }
        const size_t n_before = cs.GetBlockIndexSize();
        chk("exited thread: setup, the eviction happened",
            cs.EvictLowestWorkLeafNotPinned(n_before - 1));
        chk("exited thread: the entry is in the graveyard", cs.GraveyardSize() == 1);

        cs.EpochCheckpoint();      // this thread promises, honestly
        chk("exited thread: A THREAD THAT HAS EXITED DOES NOT PIN THE GRAVEYARD",
            cs.DrainGraveyard() == 1);
        chk("exited thread: the graveyard is empty again", cs.GraveyardSize() == 0);
    }

    // ---- REGISTRATION CENSUS: a thread that never checkpoints is a LEAK ------
    //
    // A non-participating thread pins the graveyard for the process lifetime.
    // That is the SAFE direction — nothing is freed on the account of a thread
    // that made no promise — but it is a silent unbounded leak: the node behaves
    // correctly and memory grows. Worst possible shape for a defect, so the
    // registration is asserted at startup rather than assumed.
    //
    // ⚠️ TWO MECHANISMS, AND THE SECOND IS THE ONE THAT MATTERS. Comparing a
    // declared set against a registered set catches a WIRED thread that never
    // reached its checkpoint. It cannot catch the thread nobody wrote down —
    // whoever adds a thread and forgets the checkpoint also forgets the
    // declaration. So a resolve-time detector records any thread that obtains a
    // CBlockIndex* while never having checkpointed, which needs no list at all.
    {
        std::string why;

        // (0) Clean baseline: this thread has checkpointed, nothing is declared.
        chk("registration: the census passes with no declared participants",
            cs.EpochRegistrationComplete(why));

        // (1) DECLARED BUT NEVER CHECKPOINTED — named, not merely counted.
        cs.DeclareEpochParticipant("ghost-thread");
        why.clear();
        chk("registration: a declared thread that never checkpoints FAILS",
            !cs.EpochRegistrationComplete(why));
        chk("registration: the diagnostic NAMES the missing thread",
            why.find("ghost-thread") != std::string::npos);
        chk("registration: and it explains the leak, not just a count",
            why.find("PINS THE GRAVEYARD") != std::string::npos);

        // The startup gate polls to a deadline (threads start asynchronously) and
        // must still return false rather than hanging.
        const auto t0 = std::chrono::steady_clock::now();
        why.clear();
        const bool awaited = cs.AwaitEpochRegistration(300, why);
        const auto waited_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        chk("startup gate: AwaitEpochRegistration fails when a participant is missing",
            !awaited && why.find("ghost-thread") != std::string::npos);
        chk("startup gate: it respects its deadline instead of hanging",
            waited_ms >= 300 && waited_ms < 5000);

        // (2) The declared thread checkpoints => the census passes.
        std::thread ghost([&cs]() { cs.EpochCheckpoint("ghost-thread"); });
        ghost.join();
        why.clear();
        chk("registration: once the declared thread checkpoints, the census passes",
            cs.EpochRegistrationComplete(why));

        // (3) THE DETECTOR: a thread that RESOLVES and never checkpoints. Nothing
        // declares it — that is the entire point — and it is caught anyway.
        std::mutex m;
        std::condition_variable cv;
        bool resolved = false, release = false;
        std::thread rogue([&]() {
            CBlockIndex* p = cs.GetBlockIndex(gh);   // holds a pointer, no promise
            {
                std::unique_lock<std::mutex> lk(m);
                resolved = (p != nullptr);
                cv.notify_all();
                cv.wait(lk, [&] { return release; });
            }
            // Withdrawing the accusation is part of the contract: a thread that
            // resolves during startup and checkpoints afterwards is not a leak.
            cs.EpochCheckpoint("rogue-thread-that-came-good");
        });
        {
            std::unique_lock<std::mutex> lk(m);
            cv.wait(lk, [&] { return resolved; });
        }
        std::string detail;
        chk("detector: an unregistered thread that resolved is counted",
            cs.UnregisteredResolverThreads(detail) == 1);
        why.clear();
        chk("detector: and the census FAILS on it with nothing declared",
            !cs.EpochRegistrationComplete(why));
        chk("detector: the diagnostic says a pointer was obtained",
            why.find("obtained a CBlockIndex*") != std::string::npos &&
            why.find("made no promise") != std::string::npos);

        {
            std::lock_guard<std::mutex> lk(m);
            release = true;
        }
        cv.notify_all();
        rogue.join();
        detail.clear();
        chk("detector: the accusation is WITHDRAWN once that thread checkpoints",
            cs.UnregisteredResolverThreads(detail) == 0);
        why.clear();
        chk("detector: and the census passes again",
            cs.EpochRegistrationComplete(why));
    }

    Dilithion::g_chainParams = saved;

    std::cout << "\n  ===== deferred reclamation: "
              << (g_failed == 0 ? "PASS" : "FAIL") << " (" << g_failed
              << " failed) =====\n" << std::endl;
    return g_failed == 0 ? 0 : 1;
}
