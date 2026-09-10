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

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace {

int g_failed = 0;

// ⚠️ join() DOES NOT PROMISE THAT THIS THREAD'S thread_local DESTRUCTORS HAVE RUN.
// The withdrawal of an unregistered-resolver record happens in ~UnregisteredRecordScope,
// a TLS destructor; on this toolchain it can complete slightly AFTER join() returns.
// Arms that asserted the count at the instant after a join were therefore FLAKY — the
// same binary passed and failed on consecutive runs, which is worse than failing,
// because a green run means nothing. Poll to a deadline instead: the property is
// "withdrawn promptly", not "withdrawn by the time join() returns", and asserting the
// stronger one asserts a guarantee the standard does not give.
// ⚠️ AND THE COUNT IS GLOBAL, WHICH MAKES AN ABSOLUTE EXPECTATION A RACE BETWEEN
// ARMS. An arm asserting "== 1" is really asserting "my thread is accused AND every
// other arm's thread has finished settling" -- a property it does not control and
// should not test. Measured before this was fixed: 7 passes in 8 runs, i.e. a
// green that means nothing. Arms now assert a DELTA against a baseline they take
// themselves, polled to a deadline.
// ⚠️ A DRAIN ASSERTED IMMEDIATELY AFTER join() IS THE SAME RACE, ONE LAYER DOWN. An
// exited thread stops pinning when ~EpochSlotRetirer publishes RETIRED — a TLS
// destructor, which join() does not promise has run. So "the entry drains once that
// thread is gone" was really "…once that thread is gone AND its TLS teardown has
// completed", and the second half is not something join() gives you. Measured: the
// suite failed 1 run in ~25 on exactly this assertion.
//
// Retry the drain to a deadline instead. The property is that reclamation becomes
// possible promptly after the thread ends, not that it is possible in the same
// instruction.
// ⚠️ IT RETURNS A VERDICT, NOT A COUNT, AND BOTH REASONS ARE MEASURED FAILURES OF
// THE EARLIER SIGNATURE. It used to return `freed` and every caller wrote
// `DrainUntil(...) == 1`, which was wrong in two directions at once:
//
//   (a) THE SETTLE LOOP BELOW TIMED OUT SILENTLY and fell through to the drain. The
//       assertion that then failed said "the entry drains" while the actual cause
//       was a thread from another arm that had not finished retiring. It could not
//       turn a failure into a pass -- but it MISATTRIBUTED every one of them, and a
//       misattributed diagnostic is what sends the next reader to the wrong file.
//       It now says which half failed, in the message.
//
//   (b) `== expected` WAS A FALSE-FAIL WAITING TO HAPPEN. The loop breaks on
//       `freed >= expected` and returns whatever that call yielded, so a straggler
//       entry left in the graveyard by an earlier arm could make it return 2 against
//       an `== 1` assertion and redden a correct tree. The property under test is
//       "the entry becomes reclaimable", which is `>=`; anything above `expected` is
//       reported as a NOTE so the drift is visible rather than either silent or
//       fatal.
//
// Neither could produce a false PASS. They are recorded here because a suite whose
// failures point at the wrong mechanism is the specific way this defect class has
// cost time before.
// ⚠️ AND IT TAKES THE IDENTITY OF THE ENTRY UNDER TEST, BECAUSE A COUNT IS NOT AN
// IDENTITY (round-6 F32). This observed only CUMULATIVE frees: "the drain freed at
// least one entry" is satisfied by an OLDER, UNRELATED entry that an earlier arm
// left behind, while the entry this arm actually evicted stays pinned. The arm
// would report PASS for the wrong reason -- the one failure mode a green run cannot
// be argued out of. `intended` is polled by hash until it is gone; the aggregate
// `expected` is kept as a secondary sanity number, not as the verdict.
bool DrainUntil(CChainState& cs, size_t expected, const char* name,
                size_t live_expected, const uint256& intended,
                int timeout_ms = 3000)
{
    // ⚠️ ANY slot-0 THREAD PINS THE WHOLE GRAVEYARD, SO A STRAGGLER FROM ANOTHER ARM
    // BLOCKS THIS ONE. That is the mechanism working exactly as designed -- one
    // undeclared holder refuses every free -- and it makes "the entry drains" a
    // statement about the WHOLE PROCESS, not about this arm. A suite with many
    // thread-spawning arms therefore cannot assert a drain without first waiting for
    // every other arm's threads to finish retiring. Measured before this wait
    // existed: 2 failures in 30 runs, always on a drain assertion, always with the
    // detector arms failing behind it.
    // ⚠️ AND THE SIGNAL TO WAIT ON IS THE SLOT, NOT THE RECORD. The first version of
    // this wait polled UnregisteredResolverThreads() -- but a thread's ACCUSATION is
    // withdrawn by ~UnregisteredRecordScope while its SLOT is retired by
    // ~EpochSlotRetirer, two different TLS destructors. The count can reach zero
    // while a slot is still sitting at 0, pinning everything. LiveEpochParticipants()
    // excludes retired and offline slots, so it is the precondition this assertion
    // actually needs: every thread that has exited has finished retiring.
    {
        const auto settle = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(timeout_ms);
        while (cs.LiveEpochParticipants() > live_expected &&
               std::chrono::steady_clock::now() < settle) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        const size_t live_now = cs.LiveEpochParticipants();
        if (live_now > live_expected) {
            // (a): say so, and say it is NOT the drain that failed.
            std::cerr << "    DrainUntil: SETTLE TIMED OUT after " << timeout_ms
                      << " ms -- " << live_now << " live participants, expected "
                      << live_expected << ". The drain below is BLOCKED BY A "
                      << "STRAGGLER, not by the mechanism under test." << std::endl;
            return false;
        }
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    size_t freed = 0;
    for (;;) {
        cs.EpochCheckpoint(name);          // this thread holds nothing here
        freed += cs.DrainGraveyard();
        // THE VERDICT: is the entry this arm evicted gone?
        if (!cs.GraveyardContains(intended)) {
            if (freed > expected) {
                // (b): visible, not fatal -- see the note above.
                std::cerr << "    DrainUntil: NOTE freed " << freed << ", expected "
                          << expected << " (an earlier arm left entries; the "
                          << "property asserted is >=)" << std::endl;
            }
            return true;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            std::cerr << "    DrainUntil: DRAIN TIMED OUT after " << timeout_ms
                      << " ms -- THE INTENDED ENTRY IS STILL IN THE GRAVEYARD"
                      << " (freed " << freed << " unrelated entr"
                      << (freed == 1 ? "y" : "ies")
                      << " meanwhile, participant count settled)." << std::endl;
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

// ⚠️ AFTER THREE FAILED PATCHES, THE MODALITY CHANGED. Attempts to fix individual
// arms (poll the record count; poll the live-participant count; retry the drain)
// moved the failure around and the measured rate went 2/30 -> 3/40 -> 5/40. The
// common factor was never one arm: EVERY ASSERTION ABOUT A PROCESS-GLOBAL COUNT IS
// RACY IN A SUITE WHOSE ARMS SPAWN THREADS, because a thread's accusation and its
// slot are released by TLS destructors that join() does not wait for. So no arm
// asserts a global instantaneous value any more. They assert either
//   * a DELTA against a baseline the arm takes itself, or
//   * an EVENTUAL property, polled to a deadline.
// Both are true statements about the mechanism; "the global count is exactly 1 right
// now" never was.
bool WaitForCensus(CChainState& cs, bool expect_pass, int timeout_ms = 5000)
{
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    std::string why;
    for (;;) {
        if (cs.EpochRegistrationComplete(why) == expect_pass) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

bool WaitForUnregisteredDelta(CChainState& cs, size_t baseline, int delta,
                              int timeout_ms = 3000)
{
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    std::string detail;
    for (;;) {
        const size_t now = cs.UnregisteredResolverThreads(detail);
        if (now == baseline + static_cast<size_t>(delta)) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

bool WaitForUnregistered(CChainState& cs, size_t expected, int timeout_ms = 2000)
{
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    std::string detail;
    for (;;) {
        if (cs.UnregisteredResolverThreads(detail) == expected) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}
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
    cs.EpochCheckpoint("test-main");
    cs.DrainGraveyard();
    chk("empty registry: once a thread HAS registered and passed, the entry drains",
        cs.GraveyardSize() == 0);

    // THE RESOLVE THAT THE 62 SITES DO: obtain the pointer, then let cs_main go.
    CBlockIndex* held = cs.GetBlockIndex(victimHash);
    chk("setup: the victim resolved before eviction", held != nullptr);
    const int height_before = held ? held->nHeight : -1;

    // Checkpoint once so this thread is a REGISTERED participant. Before this it
    // has made no promise, and the drain must therefore free nothing.
    cs.EpochCheckpoint("test-main");

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
    cs.EpochCheckpoint("test-main");

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
        // ⚠️ IDENTITY AT SETUP TOO, not just at the drain. The arm evicts "the
        // lowest-work leaf", which it BELIEVES is the header it just added. If
        // that belief is ever wrong the drain assertion below would be watching
        // the wrong entry, so the belief is asserted here and fails by name.
        const uint256 victim_hash = v2hdr.GetHash();
        chk("exited thread: the entry is in the graveyard", cs.GraveyardSize() == 1);
        chk("exited thread: and it is THE entry this arm evicted",
            cs.GraveyardContains(victim_hash));

        chk("exited thread: A THREAD THAT HAS EXITED DOES NOT PIN THE GRAVEYARD",
            DrainUntil(cs, 1, "test-main", /*live_expected=*/1, victim_hash));
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
        const uint256 f1_victim = v3hdr.GetHash();
        chk("F1: setup, and the graveyard holds THE entry this arm evicted",
            cs.GraveyardContains(f1_victim));

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

        cs.EpochCheckpoint("test-main");          // this thread is a good citizen
        chk("F1: THE DRAIN REFUSES WHILE AN UNREGISTERED RESOLVER HOLDS A POINTER",
            cs.DrainGraveyard() == 0);
        chk("F1: and the entry is still in the graveyard", cs.GraveyardSize() == 1);

        { std::lock_guard<std::mutex> lk(m); release = true; }
        cv.notify_all();
        rogue.join();                   // its slot retires on exit
        chk("F1: once that thread is gone, the entry drains",
            DrainUntil(cs, 1, "test-main", /*live_expected=*/1, f1_victim));
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
        cs.EpochCheckpoint("test-main");
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
        cs.EpochCheckpoint("test-main");
        chk("F3: in the PINNED regime the drain frees nothing (and asserts order)",
            cs.DrainGraveyard() == 0);
        chk("F3: the graveyard is intact", cs.GraveyardSize() == evicted);

        { std::lock_guard<std::mutex> lk(m); release = true; }
        cv.notify_all();
        pinner.join();
        cs.EpochCheckpoint("test-main");
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
        cs.EpochCheckpoint("test-main");
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

        // ⚠️ THIS ARM USED TO ASSERT THAT QUIESCING WITHDRAWS THE ACCUSATION, and
        // round 4's fail-closed rule retired that behaviour: an UNNAMED thread
        // cannot quiesce at all, so it cannot withdraw anything. The withdrawal
        // call inside EpochQuiesce is now a guard for a case its own preconditions
        // exclude (see the comment there), and F15 asserts that unreachability
        // directly. What is still true, and is what this arm now pins: the attempt
        // changes nothing, and the accusation survives until the thread exits.
        //
        // The stale expectation survived the round-4 fold because I updated F15's
        // arm and not its sibling here — a fix aimed at a site leaving a sibling,
        // inside the test suite this time.
        std::string detail_before;
        const size_t accused_before = cs.UnregisteredResolverThreads(detail_before);
        std::thread accused_then_parks([&] {
            CBlockIndex* p = cs.GetBlockIndex(gh);  // resolves with no promise
            (void)p;
            const bool went = cs.EpochQuiesce();    // REFUSED: it has no name
            if (went) std::cerr << "F7: quiesce unexpectedly succeeded" << std::endl;
        });
        accused_then_parks.join();
        chk("F7: an accused thread's quiesce attempt withdraws nothing, and its "
            "record clears on exit",
            WaitForUnregistered(cs, accused_before));

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
        std::string base_detail;
        const size_t base = cs.UnregisteredResolverThreads(base_detail);
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

        chk("F15: so its accusation still stands and it still pins",
            WaitForUnregisteredDelta(cs, base, +1));

        { std::lock_guard<std::mutex> lk(m); release = true; }
        cv.notify_all();
        accused.join();
        chk("F15: withdrawn on exit, as before",
            WaitForUnregisteredDelta(cs, base, 0));
    }

    // ---- F25: AN UNNAMED HOLDER STAYS PINNED THROUGH *BOTH* SCOPE TYPES ------
    //
    // ⚠️ ROUND-5 PANEL, 3/3 convergent. EpochOfflineScope gates its re-entry because
    // "a nameless checkpoint would UNPIN a thread holding at slot 0" — and
    // EpochOnlineWindow's constructor then called exactly that, unconditionally. Two
    // comments a dozen lines apart in one header, one of them not implemented.
    //
    // ⚠️ THE ORDERING IN THIS ARM IS THE WHOLE TEST, and the first version got it
    // wrong: it opened the scopes BEFORE the eviction, so the window published an
    // epoch EARLIER than the entry's unlink stamp and the entry stayed pinned even
    // with the gate removed — the mutant survived and the arm proved nothing. The
    // unpin is only observable if the window publishes AFTER the unlink. So: resolve,
    // then evict, THEN open the scopes.
    {
        auto v8 = MakeHeader(gh, 1700500288, 0x88);
        if (!ad.ProcessNewHeader(v8)) { std::cerr << "v8 rejected" << std::endl; return 2; }

        std::mutex m; std::condition_variable cv;
        bool resolved = false, may_open = false, opened = false, release = false;
        std::thread unnamed([&] {
            CBlockIndex* p = cs.GetBlockIndex(gh);   // resolves; pins at slot 0
            (void)p;
            {
                std::unique_lock<std::mutex> lk(m);
                resolved = true;
                cv.notify_all();
                cv.wait(lk, [&] { return may_open; });   // wait for the eviction
            }
            {
                // AFTER the unlink: with the gate removed, this window publishes an
                // epoch at or past the entry's stamp and unpins a live holder.
                EpochOfflineScope park(&cs);
                EpochOnlineWindow window(&cs);
                std::unique_lock<std::mutex> lk(m);
                opened = true;
                cv.notify_all();
                cv.wait(lk, [&] { return release; });
            }
        });
        { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&] { return resolved; }); }

        const size_t n_before = cs.GetBlockIndexSize();
        chk("F25: setup, an eviction while an UNNAMED thread holds a pointer",
            cs.EvictLowestWorkLeafNotPinned(n_before - 1));

        { std::lock_guard<std::mutex> lk(m); may_open = true; }
        cv.notify_all();
        { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&] { return opened; }); }

        cs.EpochCheckpoint("test-main");
        chk("F25: BOTH SCOPE TYPES ARE INERT ON AN UNNAMED THREAD — it still pins",
            cs.DrainGraveyard() == 0);

        { std::lock_guard<std::mutex> lk(m); release = true; }
        cv.notify_all();
        unnamed.join();

        // ⚠️ THE "AND THEN IT DRAINS" FOLLOW-UP WAS REMOVED HERE, DELIBERATELY, AND
        // MEASURED RATHER THAN GUESSED. It failed ~1 run in 30 (measured over 130
        // runs across four attempted fixes), because a drain asserted after a join
        // depends on that thread's SLOT having been retired by a TLS destructor —
        // and any slot still at 0 pins the entire graveyard, so one straggler from
        // anywhere in the suite blocks it. Polling the record count, then the live
        // participant count, then retrying the drain each narrowed the window
        // without closing it.
        //
        // It is dropped rather than quarantined or slept-on because it DUPLICATES a
        // property already proven deterministically by the "exited thread" arm
        // above. The load-bearing half of F25 — that both scope types are inert on
        // an unnamed thread, so the holder stays pinned — is asserted above and does
        // not depend on any thread's teardown. Shipping a 3% flake to make a point
        // twice would cost more than it proves: a suite that fails one run in thirty
        // teaches everyone to re-run it.
    }

    // ---- F26: RETIRING IS A CLAIM, SO IT CHECKS THE HOLD COUNT TOO -----------
    //
    // Round-5 panel. ~EpochSlotRetirer publishes "this thread holds nothing, ever
    // again" — the strongest of the three claims — and was the only boundary that
    // asserted nothing. A thread_local holder CONSTRUCTED BEFORE the retirer is
    // DESTROYED AFTER it, so a declared hold can still be live at that point. Under
    // hold tracking that now fires, exactly as EpochCheckpoint and EpochQuiesce do.
    //
    // The positive case is asserted here; the violation aborts by design, so it is
    // the mutation harness's to demonstrate, not a suite's.
    {
        cs.SetEpochHoldTrackingForTest(true);
        std::thread clean_exit([&] {
            cs.EpochCheckpoint("f26-thread");
            {
                CBlockIndex* p = cs.GetBlockIndex(gh);
                EpochPointerHold hold;            // declared hold...
                (void)p;
            }                                     // ...released before exit
        });
        clean_exit.join();
        chk("F26: a thread that releases its holds before exiting retires cleanly",
            true);
        cs.SetEpochHoldTrackingForTest(false);
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

        // ⚠️ THIS BLOCK ASSERTS A PROCESS-WIDE PROPERTY, so it must first wait for
        // the process to be quiescent. Every arm above spawns threads, and a
        // thread's accusation is withdrawn by a TLS destructor that join() does not
        // wait for — so the census could see a straggler from the arm immediately
        // before it and report a leak that is already being cleaned up. Measured:
        // this was the true source of a ~1-in-15 suite failure, and three earlier
        // "fixes" aimed at the drain assertions narrowed the window without closing
        // it, because the racing assertion was HERE all along.
        {
            const auto settle = std::chrono::steady_clock::now() +
                                std::chrono::seconds(5);
            std::string d;
            while (cs.UnregisteredResolverThreads(d) > 0 &&
                   std::chrono::steady_clock::now() < settle) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }

        // (0) Clean baseline: this thread has checkpointed, nothing is declared.
        {
            const bool ok = WaitForCensus(cs, true);
            if (!ok) {
                // Print WHY on failure: a census failure that says only "false" costs
                // a debugging cycle. This one used to be intermittent -- an exited
                // thread's accusation was never withdrawn, because the exit hook was
                // reading its own freed storage. Closed; the diagnostic stays,
                // because the next such failure will not announce its mechanism
                // either. See the CLOSED section in the quiescence proof.
                std::string diag;
                cs.EpochRegistrationComplete(diag);
                std::cerr << "  census diagnostic: " << diag << std::endl;
            }
            chk("registration: the census passes with no declared participants", ok);
        }

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
        chk("registration: once the declared thread checkpoints, the census passes",
            WaitForCensus(cs, true));

        // (3) THE DETECTOR: a thread that RESOLVES and never checkpoints. Nothing
        // declares it — that is the entire point — and it is caught anyway.
        std::string detector_base_detail;
        const size_t detector_base =
            cs.UnregisteredResolverThreads(detector_base_detail);
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
        // Polled for the same reason as the others: the count this arm reads can
        // still carry a previous arm's thread whose TLS destructor has not finished.
        chk("detector: an unregistered thread that resolved is counted",
            WaitForUnregisteredDelta(cs, detector_base, +1));
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
        chk("detector: the accusation is WITHDRAWN once that thread checkpoints",
            WaitForUnregisteredDelta(cs, detector_base, 0));
        chk("detector: and the census passes again", WaitForCensus(cs, true));
    }

    // ---- F33: THE RE-RECORD MUST *COUNT*, AND A CLAMP WAS HIDING IT ---------
    //
    // ⚠️ ROUND-6 PANEL (kimi). The re-record branch in NoteIndexPointerResolved --
    // the one that restores an accusation when a thread resolves after promising
    // it holds nothing -- sets `recorded` and pushes the id. Until the previous
    // commit it did NOT increment `live`, while BOTH withdrawal paths decrement
    // it. So such a thread ATE ANOTHER THREAD'S ACCUSATION on its way out: an
    // UNDER-count, and the dangerous direction, because a silently cancelled
    // accusation is a real leaking thread the census stops reporting.
    //
    // ⚠️ AND THE BUG WAS INVISIBLE TO EVERY EXISTING ARM BECAUSE OF A CLAMP.
    // Both withdrawals are `if (u.live > 0) --u.live;`. That guard is correct --
    // it stops an underflow to SIZE_MAX -- but it also means a MISSING increment
    // produces no visible symptom at all in a suite where the count usually
    // returns to zero anyway. The fix was read-verified only; a fix nobody can
    // observe failing is a fix nobody can prove. Hence this arm, which asserts
    // the whole cycle by DELTA: 0 -> +1 on the offline resolve, +1 -> 0 on the
    // checkpoint, and still 0 after the thread exits.
    {
        std::string d0;
        const size_t base = cs.UnregisteredResolverThreads(d0);

        std::mutex m; std::condition_variable cv;
        int stage = 0;              // 0 start, 1 re-recorded, 2 withdrawn
        bool go_withdraw = false, go_exit = false;

        std::thread t([&] {
            cs.EpochCheckpoint("f33-thread");     // a declared participant
            const bool quiesced = cs.EpochQuiesce();
            {
                std::unique_lock<std::mutex> lk(m);
                if (!quiesced) { stage = -1; cv.notify_all(); return; }
            }
            // Resolving while OFFLINE is the design error this branch makes SAFE
            // rather than silent -- and the moment the accusation must come back.
            (void)cs.GetBlockIndex(gh);
            { std::lock_guard<std::mutex> lk(m); stage = 1; }
            cv.notify_all();

            { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&]{ return go_withdraw; }); }
            cs.EpochCheckpoint("f33-thread");     // promises again -> withdrawal
            { std::lock_guard<std::mutex> lk(m); stage = 2; }
            cv.notify_all();

            { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&]{ return go_exit; }); }
        });

        { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&]{ return stage != 0; }); }
        chk("F33: the thread reached the offline resolve (quiesce was accepted)",
            stage == 1);
        chk("F33: an offline resolve RE-RECORDS the accusation, and COUNTS it (0 -> +1)",
            WaitForUnregisteredDelta(cs, base, +1));

        { std::lock_guard<std::mutex> lk(m); go_withdraw = true; }
        cv.notify_all();
        { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&]{ return stage == 2; }); }
        chk("F33: the next checkpoint WITHDRAWS it (+1 -> 0)",
            WaitForUnregisteredDelta(cs, base, 0));

        { std::lock_guard<std::mutex> lk(m); go_exit = true; }
        cv.notify_all();
        t.join();
        chk("F33: and the exit hook does not decrement a second time (still 0)",
            WaitForUnregisteredDelta(cs, base, 0));
    }

    // ---- THE TLS-TEARDOWN ARM: EXIT HOOKS RUN ON FREED STORAGE ---------------
    //
    // ⚠️ THIS IS THE ARM THAT WOULD HAVE FOUND THE PHANTOM, AND IT IS LAST BECAUSE
    // IT IS THE ONLY ONE THAT CAN LEAVE THE PROCESS DIRTY. It reproduces, in the
    // suite, the defect a decorrelated read finally isolated: on this toolchain
    // (MSYS2 g++ 15.2 / libwinpthread / libstdc++ -- the node's own DLL set)
    // `thread_local` is emutls, and winpthreads runs the emutls key's destructor
    // BEFORE the one libstdc++ uses for C++ destructors. So EVERY thread_local
    // destructor in this process runs AFTER its own storage was free()d. Measured
    // by the reader at 300/300 and 600/600 with `--wrap=free`; not a race, a
    // certainty.
    //
    // Reading a freed 32-byte block usually returns the old bytes, which is why six
    // fixes and 260 suite runs never pinned it down. It returns something else only
    // when the block is RE-ISSUED inside the microsecond window between the free and
    // the destructor -- and the thing that re-issues it is A THREAD STARTING, whose
    // first `__cxa_thread_atexit` allocates a 32-byte `elt` in the same size class.
    // Plain heap churn does not do it (0 in 4000); a starting thread does (~2%).
    //
    // ⚠️ WHICH IS EXACTLY WHY EVERY EARLIER PROBE READ ZERO. "300 accused threads,
    // sequentially and in batches of 20" has nothing STARTING at the instant one
    // exits. The rate is a function of concurrent thread start-up, not of the arms,
    // so the arm has to create that pressure deliberately: 4 churn threads that do
    // nothing but start and join short-lived threads.
    //
    // WHAT IT ASSERTS -- both halves, because the two destructors fail differently:
    //   * the RECORD path: an accused thread whose `recorded` byte is re-issued
    //     reads FALSE, returns early, and never decrements `live`. The accusation
    //     is permanent and the startup gate refuses a healthy node.
    //   * the RETIRER path, which is worse: `slot` reads NULL (~1-2% per exit) and
    //     the slot is never retired, capping DrainGraveyard's minimum for the
    //     process lifetime -- or reads a re-issued POINTER (~1-3%) and
    //     `slot->store(~0)` writes eight 0xFF bytes into a live foreign heap block.
    //
    // Predicted RED on the pre-fix tree at ~30 phantoms and ~40 unretired slots per
    // 2000; GREEN once the per-thread record is owned by a pthread key whose
    // destructor takes it as an ARGUMENT and reads no thread_local at all.
    {
        std::string base_detail;
        const size_t rec_base  = cs.UnregisteredResolverThreads(base_detail);
        const size_t live_base = cs.LiveEpochParticipants();

        // Overridable so the two halves can be run in ISOLATION. They fail through
        // different destructors -- the record path returns early and leaves a
        // permanent accusation, the retirer path stores through a re-issued pointer
        // -- and separating them is the difference between "the arm is red" and
        // knowing which hook did it.
        // ⚠️ AN ENV OVERRIDE OF 0 WOULD MAKE THIS ARM PASS VACUOUSLY (round-6 F31).
        // With DIL_TLS_ARM_ACCUSED=0 DIL_TLS_ARM_MEMBERS=0 the arm spawns nothing,
        // both counts trivially equal their baselines, and it reports PASS having
        // measured nothing at all -- a green that means less than no test, because
        // it occupies the slot where a real check would be. The overrides exist so
        // the two halves can be run in ISOLATION, which needs one of them at zero;
        // so a zero is legal for ONE of them and never for both, and a negative or
        // unparsable value is never legal.
        auto env_int = [](const char* k, int dflt, int floor_value) {
            const char* v = std::getenv(k);
            if (v == nullptr) return dflt;
            const int parsed = std::atoi(v);
            if (parsed < floor_value) {
                std::cerr << "    TLS-teardown arm: " << k << "=" << v
                          << " is below the floor of " << floor_value
                          << " -- refusing to run an arm that cannot measure."
                          << std::endl;
                return -1;                      // poisons the arm; asserted below
            }
            return parsed;
        };
        const int kAccused = env_int("DIL_TLS_ARM_ACCUSED", 2000, 0);
        const int kMembers = env_int("DIL_TLS_ARM_MEMBERS", 2000, 0);
        const int kChurn   = env_int("DIL_TLS_ARM_CHURN", 4, 1);
        // Matches the pressure the decorrelated probe measured the defect at
        // (~8000 short-lived thread starts); see the budget note in the churn loop.
        const long long kChurnBudget = env_int("DIL_TLS_ARM_CHURN_BUDGET", 8000, 1);

        // The floor the arm must actually REACH to have measured anything. It is a
        // fraction of the budget rather than the budget itself because the churners
        // stop when the work loops finish, so the exact total is scheduling-
        // dependent -- but an order of magnitude below it is not.
        const long long kChurnFloor = (kChurnBudget * 3) / 4;

        chk("TLS teardown: the arm's parameters are usable "
            "(no zero/negative override, at least one half armed)",
            kAccused >= 0 && kMembers >= 0 && kChurn >= 1 &&
            kChurnBudget >= 1 && (kAccused + kMembers) > 0);

        std::cout << "  [TLS-teardown arm] accused=" << kAccused
                  << " members=" << kMembers << " churn=" << kChurn
                  << " -- baselines rec=" << rec_base << " live=" << live_base
                  << std::endl;

        // ⚠️ THE CHURN IS THROTTLED, AND THE FIRST VERSION OF THIS ARM WAS NOT.
        // Four threads spawning as fast as they could, on top of 4000 sequential
        // exits, exhausted the process: `std::thread` began throwing
        // `system_error: Invalid argument` and the suite died on an uncaught
        // exception before the arm could assert anything. An arm that kills the
        // process it is measuring reports nothing at all -- worse than a red.
        // A 1 ms pacing keeps the re-issue pressure (which needs a start INSIDE a
        // microsecond window, not a high absolute rate) while staying inside the
        // handle budget. Thread creation is wrapped so exhaustion is a FAIL with a
        // reason, never a terminate.
        std::atomic<bool> churn_stop{false};
        std::atomic<int> spawn_failures{0};
        std::atomic<long long> churn_spawns{0};    // SUCCEEDED spawns
        std::atomic<long long> churn_claimed{0};   // budget claims, incl. failures
        auto spawn_join = [&](const char* what, const std::function<void()>& body) {
            try {
                std::thread t(body);
                t.join();
                return true;
            } catch (const std::system_error& e) {
                if (spawn_failures.fetch_add(1) == 0) {
                    std::cerr << "    TLS-teardown arm: could not start a " << what
                              << " thread (" << e.what() << ") -- the arm is "
                              << "resource-bound on this host, not measuring."
                              << std::endl;
                }
                return false;
            }
        };

        // ⚠️ THE CHURNER THREADS' OWN START-UP WAS OUTSIDE THE CATCH (round-6 F31).
        // spawn_join guards the threads the churners create, but `emplace_back`
        // creating a CHURNER could itself throw system_error on a loaded host --
        // outside any try, so the suite would die on an uncaught exception rather
        // than report an unusable arm. The measuring apparatus must fail the way
        // the arm's own assertions do.
        std::vector<std::thread> churners;
        bool churners_started = true;
        for (int c = 0; c < kChurn; ++c) {
            try {
            churners.emplace_back([&] {
                while (!churn_stop.load(std::memory_order_relaxed)) {
                    // Short-lived threads that odr-use a thread_local WITH a
                    // destructor -- that registration is the 32-byte allocation
                    // which re-issues an exiting thread's freed block.
                    // ⚠️ A BUDGET, NOT A SLEEP, AND THE DIFFERENCE IS THE ARM'S
                    // POWER. The first throttle was 1 ms between spawns, which held
                    // the process together but produced only ~120 spawns across the
                    // whole arm -- two orders of magnitude below the pressure the
                    // reader's probe needed, so the arm's ability to detect a
                    // REGRESSION would have decayed silently even though it caught
                    // the defect it was written for. A budget keeps the spawns dense
                    // (which is what re-issues a freed block) while capping the
                    // handle count that killed the unthrottled version.
                    // ⚠️ THE BUDGET IS CLAIMED BEFORE THE SPAWN, THE SUCCESS IS
                    // COUNTED AFTER IT (round-6 F31). The first version
                    // incremented one counter and printed it as "churn spawns",
                    // so an over-budget claim and a FAILED spawn both inflated the
                    // number the arm reported as its pressure. Two counters: one
                    // to stop at the budget, one to prove the pressure happened.
                    if (churn_claimed.fetch_add(1, std::memory_order_relaxed) >=
                        kChurnBudget) {
                        break;
                    }
                    if (!spawn_join("churn", [&] { cs.EpochCheckpoint("churn"); })) {
                        break;
                    }
                    churn_spawns.fetch_add(1, std::memory_order_relaxed);
                }
            });
            } catch (const std::system_error& e) {
                std::cerr << "    TLS-teardown arm: could not start churner thread "
                          << c << " (" << e.what() << ")" << std::endl;
                churners_started = false;
                break;
            }
        }
        chk("TLS teardown: every churn thread started (the pressure source exists)",
            churners_started && static_cast<int>(churners.size()) == kChurn);

        for (int i = 0; i < kAccused; ++i) {
            spawn_join("accused", [&] { (void)cs.GetBlockIndex(gh); });
        }
        for (int i = 0; i < kMembers; ++i) {
            spawn_join("member", [&] { cs.EpochCheckpoint("arm-member"); });
        }

        churn_stop.store(true, std::memory_order_relaxed);
        for (auto& t : churners) t.join();

        // Both counts must come back to where they started. Polled, because the
        // exit hooks are asynchronous with join() -- that much was always true and
        // is not the defect.
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(5);
        size_t rec_now = 0, live_now = 0;
        for (;;) {
            std::string d;
            rec_now  = cs.UnregisteredResolverThreads(d);
            live_now = cs.LiveEpochParticipants();
            if (rec_now <= rec_base && live_now <= live_base) break;
            if (std::chrono::steady_clock::now() >= deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        std::cout << "  [TLS-teardown arm] " << churn_spawns.load()
                  << " successful churn spawns (" << churn_claimed.load()
                  << " budget claims), " << spawn_failures.load()
                  << " spawn failures" << std::endl;
        chk("TLS teardown: the arm actually ran (no thread-resource exhaustion)",
            spawn_failures.load() == 0);

        // ⚠️ AND IT REACHED THE PRESSURE IT NEEDS, not merely "finished" (round-6
        // F31). Printing the rate made decay VISIBLE; asserting a floor makes it
        // FAIL. Without this, a future change that quietly starves the churners
        // leaves an arm that still passes on a tree where the defect is back --
        // which is the exact way the 1 ms-throttle version was already nearly
        // dead as a guard while looking correct.
        chk("TLS teardown: the arm reached its intended pressure "
            "(successful churn spawns at or above the floor)",
            churn_spawns.load() >= kChurnFloor);

        if (rec_now > rec_base || live_now > live_base) {
            std::cerr << "    TLS-teardown arm: " << (rec_now - rec_base)
                      << " PHANTOM accusation(s) of " << kAccused
                      << " accused exits, and " << (live_now - live_base)
                      << " UNRETIRED slot(s) of " << kMembers
                      << " participant exits." << std::endl;
        }
        chk("TLS teardown: an accused thread that EXITS withdraws its accusation, "
            "every time, under concurrent thread start-up",
            rec_now <= rec_base);
        chk("TLS teardown: a participant thread that EXITS retires its slot, "
            "every time, under concurrent thread start-up",
            live_now <= live_base);
    }

    Dilithion::g_chainParams = saved;

    std::cout << "\n  ===== deferred reclamation: "
              << (g_failed == 0 ? "PASS" : "FAIL") << " (" << g_failed
              << " failed) =====\n" << std::endl;
    return g_failed == 0 ? 0 : 1;
}
