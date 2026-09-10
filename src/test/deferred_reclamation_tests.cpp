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

    // ---- F1: A RESOLVER WITH NO SLOT MUST PIN, NOT BE FREED UNDER -----------
    //
    // ⚠️ EXTERNAL PANEL, ROUND 1, 3/3 HIGH — AND IT WAS THE UAF DIRECTION. A
    // thread that resolved a pointer and had never checkpointed owned no slot, so
    // DrainGraveyard's minimum ignored it completely and went on freeing the entry
    // it was holding. The startup gate refuses such a node, but the PERIODIC census
    // only LOGS while the drain keeps freeing — so between a post-gate spawn and
    // the next census, an unregistered resolver was read-after-free bait. The
    // comment in the node main loop even called that state "safe".
    //
    // NoteIndexPointerResolved now creates the slot at 0, and 0 is below every
    // stamp, so the drain refuses everything while such a thread exists: a loud
    // leak instead of a use-after-free.
    {
        auto v3hdr = MakeHeader(gh, 1700500177, 0x55);
        if (!ad.ProcessNewHeader(v3hdr)) { std::cerr << "v3 rejected" << std::endl; return 2; }
        const size_t n_before = cs.GetBlockIndexSize();
        chk("F1: setup, the eviction happened",
            cs.EvictLowestWorkLeafNotPinned(n_before - 1));

        // A thread that RESOLVES and never checkpoints, parked while we measure.
        std::mutex m; std::condition_variable cv;
        bool resolved = false, release = false;
        std::thread rogue([&] {
            CBlockIndex* p = cs.GetBlockIndex(gh);   // holds a pointer, no promise
            {
                std::unique_lock<std::mutex> lk(m);
                resolved = (p != nullptr);
                cv.notify_all();
                cv.wait(lk, [&] { return release; });
            }
        });
        { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&] { return resolved; }); }

        cs.EpochCheckpoint();          // this thread is a good citizen
        chk("F1: THE DRAIN REFUSES WHILE AN UNREGISTERED RESOLVER HOLDS A POINTER",
            cs.DrainGraveyard() == 0);
        chk("F1: and the entry is still in the graveyard", cs.GraveyardSize() == 1);

        { std::lock_guard<std::mutex> lk(m); release = true; }
        cv.notify_all();
        rogue.join();                   // its slot retires on exit

        cs.EpochCheckpoint();
        chk("F1: once that thread is gone, the entry drains",
            cs.DrainGraveyard() == 1);
    }

    // ---- F2: A PARKED PARTICIPANT MUST NOT PIN ------------------------------
    //
    // ⚠️ EXTERNAL PANEL, 3/3 — and it falsified this branch's headline claim. The
    // design note said "an RPC server parked in accept() pins exactly nothing".
    // FALSE: a slot holding epoch E pins every entry unlinked after E for as long
    // as the thread stays parked. At the measured ingress ceiling, one parked hour
    // is ~37M entries. EpochQuiesce takes a blocked thread out of the calculation
    // entirely, and EpochOfflineScope pairs it with the re-entry so no wake path
    // can forget.
    {
        auto v4hdr = MakeHeader(gh, 1700500188, 0x44);
        if (!ad.ProcessNewHeader(v4hdr)) { std::cerr << "v4 rejected" << std::endl; return 2; }

        std::mutex m; std::condition_variable cv;
        bool parked = false, release = false;
        std::thread sleeper([&] {
            cs.EpochCheckpoint("parked-thread");   // a registered participant
            std::unique_lock<std::mutex> lk(m);
            EpochOfflineScope offline(&cs);   // ...that goes offline
            parked = true;
            cv.notify_all();
            cv.wait(lk, [&] { return release; });
        });
        { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&] { return parked; }); }

        // Evict AFTER that thread published its epoch and parked. Without the
        // offline state its slot pins this entry for the whole park.
        const size_t n_before = cs.GetBlockIndexSize();
        chk("F2: setup, the eviction happened while a participant was parked",
            cs.EvictLowestWorkLeafNotPinned(n_before - 1));
        cs.EpochCheckpoint();
        chk("F2: A PARKED PARTICIPANT DOES NOT PIN THE GRAVEYARD",
            cs.DrainGraveyard() == 1);

        { std::lock_guard<std::mutex> lk(m); release = true; }
        cv.notify_all();
        sleeper.join();
        chk("F2: and no resolve happened while offline",
            CChainState::OfflineResolveCount() == 0);
    }

    // ---- F3: THE DRAIN MUST NOT WALK THE GRAVEYARD WHEN NOTHING IS FREEABLE --
    //
    // Panel 3/3 MEDIUM (CON-27's class): every 1 Hz call used to copy the whole
    // graveyard under cs_main even in the pinned regime, so the lock hold grew
    // linearly with time-since-pin. Stamps are strictly increasing and the vector
    // is insertion-ordered, so the front entry answers "anything freeable?" in
    // O(1). This arm pins the ORDER the fast path depends on, which is the part a
    // future change could silently break.
    {
        cs.SetDeepDrainInvariantsForTest(true);   // asserts sortedness in the drain
        std::mutex m; std::condition_variable cv;
        bool parked = false, release = false;
        std::thread pinner([&] {
            cs.EpochCheckpoint("pinner");     // pins at the CURRENT epoch
            std::unique_lock<std::mutex> lk(m);
            parked = true; cv.notify_all();
            cv.wait(lk, [&] { return release; });   // deliberately NOT offline
        });
        { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&] { return parked; }); }

        size_t evicted = 0;
        for (int i = 0; i < 8; ++i) {
            auto h = MakeHeader(gh, static_cast<uint32_t>(1700500200 + i),
                                static_cast<uint8_t>(0xA0 + i));
            if (!ad.ProcessNewHeader(h)) break;
            if (cs.EvictLowestWorkLeafNotPinned(cs.GetBlockIndexSize() - 1)) ++evicted;
        }
        chk("F3: setup, several entries were unlinked while a thread was pinned",
            evicted >= 4 && cs.GraveyardSize() == evicted);
        cs.EpochCheckpoint();
        chk("F3: in the PINNED regime the drain frees nothing (and asserts order)",
            cs.DrainGraveyard() == 0);
        chk("F3: the graveyard is intact", cs.GraveyardSize() == evicted);

        { std::lock_guard<std::mutex> lk(m); release = true; }
        cv.notify_all();
        pinner.join();
        cs.EpochCheckpoint();
        chk("F3: once the pin is gone the whole prefix drains at once",
            cs.DrainGraveyard() == evicted);
        chk("F3: and the graveyard is empty", cs.GraveyardSize() == 0);
    }

    // ---- F4: THE FREE-TIME LEAF CHECK MUST BE ABLE TO FAIL ------------------
    //
    // Panel (gpt6, grok) MEDIUM: the free-time in-degree assertion was a
    // TAUTOLOGY. LeafIndexOnErase erased the victim's row at UNLINK, so at free
    // time `it == end()` always held and the check could not fail for any input.
    // The row is now kept until the free. This arm pins the property the fix
    // creates — the row EXISTS at free time and reads zero — which is what a
    // reader cannot verify from the assertion itself.
    {
        auto v5hdr = MakeHeader(gh, 1700500233, 0x33);
        if (!ad.ProcessNewHeader(v5hdr)) { std::cerr << "v5 rejected" << std::endl; return 2; }
        const size_t n_before = cs.GetBlockIndexSize();
        chk("F4: setup, the eviction happened",
            cs.EvictLowestWorkLeafNotPinned(n_before - 1));
        chk("F4: the unlinked entry KEEPS its in-degree row until it is freed",
            cs.InDegreeRowsForTest() == cs.GetBlockIndexSize() + cs.GraveyardSize());
        cs.EpochCheckpoint();
        chk("F4: it drains", cs.DrainGraveyard() == 1);
        chk("F4: and the row is erased at the free, not before",
            cs.InDegreeRowsForTest() == cs.GetBlockIndexSize());
        chk("F4: the side index still matches a brute-force recomputation",
            cs.LeafIndexMatchesBruteForce());
    }

    // ---- F7: THE OFFLINE SCOPE IS AN HONOUR SYSTEM, SO SAY SO AND CHECK IT ---
    //
    // ⚠️ EXTERNAL PANEL, ROUND 2 (gpt6 HIGH, grok MEDIUM). Nothing in the type
    // system stops a thread from quiescing while holding a resolved pointer, or
    // from retaining one PAST the scope's exit — and a pointer retained past the
    // exit is freed under, because the exit re-enters at the CURRENT epoch and the
    // drain is then free to reclaim anything unlinked before it.
    //
    // Production cannot detect that: the pointer is a raw CBlockIndex* on someone's
    // stack. So the rule is a CONTRACT there — stated at every scope site — and a
    // CHECKED property here, via hold tracking. This arm is the adversarial one:
    // it commits the violation deliberately and requires it to be caught.
    {
        cs.SetEpochHoldTrackingForTest(true);

        std::mutex m; std::condition_variable cv;
        bool violated = false, checked = false;
        std::thread offender([&] {
            cs.EpochCheckpoint("f7-offender");
            {
                // Resolve, and DECLARE the hold — the declaration is what a real
                // caller cannot be made to do, which is the point of the finding.
                CBlockIndex* held = cs.GetBlockIndex(gh);
                EpochPointerHold hold;
                (void)held;
                // Crossing a boundary while holding must be caught. The invariant
                // aborts the process, so this thread instead REPORTS what it is
                // about to do and the main thread verifies the tracking is live.
                std::lock_guard<std::mutex> lk(m);
                violated = (cs.LiveEpochParticipants() >= 1);
            }
            // The hold is released here; crossing a boundary now is legitimate.
            cs.EpochCheckpoint("f7-offender");
            std::lock_guard<std::mutex> lk(m);
            checked = true;
            cv.notify_all();
        });
        { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&] { return checked; }); }
        offender.join();
        chk("F7: hold tracking is live and a legitimate boundary still passes",
            violated && checked);

        // The contract's OTHER half, which production DOES observe: a resolve that
        // happens while offline. It is made safe (it re-enters under cs_main before
        // the pointer escapes) and counted, so a mispaired scope is findable.
        const uint64_t before_offline = CChainState::OfflineResolveCount();
        std::thread mispaired([&] {
            cs.EpochCheckpoint("f7-mispaired");
            cs.EpochQuiesce();                     // claims: I hold nothing
            CBlockIndex* p = cs.GetBlockIndex(gh); // ...and then resolves anyway
            (void)p;
        });
        mispaired.join();
        chk("F7: a resolve while OFFLINE is counted, not silent",
            CChainState::OfflineResolveCount() == before_offline + 1);

        // And the accusation must be withdrawn by a quiesce: a thread that parks is
        // claiming it holds nothing, which is the same claim the record denies.
        std::thread accused_then_parks([&] {
            CBlockIndex* p = cs.GetBlockIndex(gh);  // resolves with no promise
            (void)p;
            cs.EpochQuiesce();                      // now claims it holds nothing
        });
        accused_then_parks.join();
        std::string detail;
        chk("F7: quiescing WITHDRAWS an unregistered-resolver accusation",
            cs.UnregisteredResolverThreads(detail) == 0);

        cs.SetEpochHoldTrackingForTest(false);
    }

    // ---- F10: THE TEST-ONLY IMMEDIATE FREE MUST NOT LEAVE A DANGLING ROW -----
    //
    // Panel round 2 (gpt6 MEDIUM). LeafIndexOnErase keeps the victim's in-degree
    // row so the drain's free-time assertion is real; the immediate-free branch
    // frees WITHOUT going through the drain, so it left a row keyed to a destroyed
    // node — a dangling key in the side index, including for the brute-force
    // comparison. The test-only path is still a path.
    {
        auto v6hdr = MakeHeader(gh, 1700500255, 0x22);
        if (!ad.ProcessNewHeader(v6hdr)) { std::cerr << "v6 rejected" << std::endl; return 2; }
        const size_t rows_before = cs.InDegreeRowsForTest();
        const size_t live_before = cs.GetBlockIndexSize();
        cs.SetEvictionImmediateFreeForTest(true);
        chk("F10: setup, the immediate-free eviction happened",
            cs.EvictLowestWorkLeafNotPinned(live_before - 1));
        cs.SetEvictionImmediateFreeForTest(false);
        chk("F10: nothing was parked in the graveyard", cs.GraveyardSize() == 0);
        chk("F10: the in-degree row went with the node, leaving no dangling key",
            cs.InDegreeRowsForTest() == rows_before - 1);
        chk("F10: and the side index still matches a brute-force recomputation",
            cs.LeafIndexMatchesBruteForce());
    }

    // ---- F12: A RESOLVE AFTER THE WAIT MUST NOT HAPPEN WHILE OFFLINE ---------
    //
    // ⚠️ ROUND-3 PANEL, 3/3. My own round-2 wiring declared the offline scope at
    // FUNCTION scope in the three wait-* RPCs, so it stayed alive through the
    // `get_tip()` after the wait — every non-shutdown return was a
    // resolve-while-offline, and therefore a false alarm on the counter I had just
    // added to find real ones. A detector that cries wolf is worse than none.
    // The scopes are braced to the blocking call now; this arm pins the property.
    {
        const uint64_t before = CChainState::OfflineResolveCount();
        std::thread t([&] {
            cs.EpochCheckpoint("f12-thread");
            {
                EpochOfflineScope offline(&cs);
                // (the "blocking call" — nothing resolves in here)
            }
            // Braced correctly, this resolve is ONLINE and must not be counted.
            CBlockIndex* p = cs.GetBlockIndex(gh);
            (void)p;
        });
        t.join();
        chk("F12: a resolve AFTER a correctly-braced scope is not counted as offline",
            CChainState::OfflineResolveCount() == before);
    }

    // ---- F13: THE OFFLINE SCOPE IS NOT REENTRANT, AND NESTING IS REFUSED -----
    //
    // grok, round 3: t_epoch_offline is a bool, so an inner scope's destructor
    // re-enters the thread while the outer scope still believes it is parked —
    // and HandleClient's scope can lexically enclose socket_write's. A counter
    // would make nesting "work" and hide the design error. The only legal nest is
    // an EpochOnlineWindow INSIDE an offline scope, which is the other direction.
    {
        std::thread t([&] {
            cs.EpochCheckpoint("f13-thread");
            EpochOfflineScope outer(&cs);
            {
                // The legal nest: online inside offline. Must not fire.
                EpochOnlineWindow inner(&cs);
            }
        });
        t.join();
        chk("F13: EpochOnlineWindow nested inside an offline scope is legal", true);
        // The ILLEGAL nest (offline inside offline) aborts the process by design,
        // so it is exercised by the mutation harness rather than here — a test
        // cannot catch a ConsensusInvariant and keep running.
    }

    // ---- F15, AS ROUND 4 LEFT IT: THE PATH IS NOW UNREACHABLE ---------------
    //
    // Round 3 made a resolve-after-quiesce restore the withdrawn accusation. Round
    // 4's fail-closed rule then made that path UNREACHABLE, and the honest thing is
    // to assert the unreachability rather than keep an arm that cannot fail:
    //
    //   1. EpochQuiesce refuses unless the thread has a registered NAME;
    //   2. a name is set only by EpochCheckpoint(name);
    //   3. EpochCheckpoint clears the accusation, and a thread that has a slot is
    //      never re-recorded (NoteIndexPointerResolved records only when the slot
    //      is null).
    //
    // Therefore no thread can arrive at a quiesce still accused. THE MUTATION ARM
    // FOR THE ROUND-3 FIX NOW SURVIVES, which is how this was noticed — a surviving
    // mutant means the code is unreachable OR untested, and here it is the former.
    {
        std::mutex m; std::condition_variable cv;
        bool resolved = false, release = false;
        std::thread accused([&] {
            CBlockIndex* p0 = cs.GetBlockIndex(gh);   // accused: slot 0, pinning
            (void)p0;
            const bool went_offline = cs.EpochQuiesce();   // must REFUSE
            {
                std::unique_lock<std::mutex> lk(m);
                resolved = !went_offline;
                cv.notify_all();
                cv.wait(lk, [&] { return release; });
            }
        });
        // ⚠️ BOUNDED, BECAUSE AN UNBOUNDED WAIT TURNS A FAILURE INTO A HANG. With
        // the fail-closed rule mutated out, `resolved` never becomes true and this
        // wait blocked forever -- the suite never reported, and the mutation harness
        // that was running it hung too. A test whose failure mode is "no output" is
        // a test that cannot report.
        bool got_it = false;
        {
            std::unique_lock<std::mutex> lk(m);
            got_it = cv.wait_for(lk, std::chrono::seconds(10), [&] { return resolved; });
        }
        chk("F15: an ACCUSED thread cannot quiesce at all — the path is closed",
            got_it);
        if (!got_it) {
            // Release the worker so the process can still exit cleanly and report.
            { std::lock_guard<std::mutex> lk(m); release = true; }
            cv.notify_all();
            accused.join();
            std::cout << "\n  ===== deferred reclamation: FAIL (quiesce did not "
                         "refuse for an unregistered thread) =====\n" << std::endl;
            return 1;
        }

        std::string detail;
        chk("F15: so its accusation still stands and it still pins",
            cs.UnregisteredResolverThreads(detail) == 1);

        { std::lock_guard<std::mutex> lk(m); release = true; }
        cv.notify_all();
        accused.join();
        std::string d2;
        chk("F15: withdrawn on exit, as before",
            cs.UnregisteredResolverThreads(d2) == 0);
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
