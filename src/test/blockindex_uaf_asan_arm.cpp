// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// blockindex_uaf_asan_arm — THE MEMORY-SAFETY VERDICT for deferred reclamation.
//
// Every other test in this branch pins the LIFETIME RULES: that unlink is
// immediate, that the drain is gated, that a non-participant pins everything.
// None of them can demonstrate the use-after-free those rules prevent, because
// reading freed memory is undefined behaviour and a test that "passes" by reading
// it is testing the allocator's mood. This file is the one that gets an answer,
// and it only gets it under -fsanitize=address.
//
// ⚠️ IT IS DELIBERATELY THREE ARMS, TWO OF WHICH MUST CRASH. A single clean run
// proves nothing: a harness that never reaches the free is also clean, and that is
// the failure mode a green ASan run hides. So the arms are:
//
//   --arm=deferred   the branch's behaviour: resolve a pointer, let ANOTHER thread
//                    evict it, dereference. MUST BE CLEAN. This is the fix working.
//
//   --arm=immediate  the same fixture with deferral turned off, so the evictor
//                    frees in place — which is what `main` did before this branch
//                    and what every other consumer of a released pointer still
//                    faces. MUST TRAP. This is the defect, reproduced.
//
//   --arm=drained    the branch's behaviour, but this thread CHECKPOINTS while
//                    still holding the pointer — a deliberate lie — so the drain
//                    is permitted to free it. MUST TRAP. This is the inverse
//                    control: it proves the fixture actually reaches the free, so
//                    the clean arm is clean because of the deferral and not
//                    because nothing was ever freed.
//
// A run in which `deferred` is clean and either of the other two is ALSO clean is
// a FAILED run, not a partial pass. scripts/asan_uaf_arms.sh enforces exactly that.
//
// Without ASan every arm exits 0 and proves nothing; the driver refuses to report
// a verdict unless it was built with the sanitizer.

#include <consensus/chain.h>
#include <consensus/port/chain_selector_impl.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <atomic>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

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

// Kept in a volatile sink so no compiler can decide the dereference is dead code
// and delete the very read the sanitizer is meant to catch.
volatile int g_sink = 0;

}  // namespace

int main(int argc, char** argv)
{
    std::string arm = "deferred";
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a.rfind("--arm=", 0) == 0) arm = a.substr(6);
    }

    std::cout << "=== blockindex UAF ASan arm: " << arm << " ===" << std::endl;

    // ⚠️ THE FIRST VERSION OF THIS PRINTED NOTHING ON GCC AND THE DRIVER READ THE
    // SILENCE AS "SANITIZER PRESENT". GCC 15 defines __has_feature, so the
    // `#if defined(__has_feature)` branch was taken, the inner test was false, and
    // no line was emitted at all -- and a driver that greps for the NEGATIVE
    // sentence then certifies a build that cannot detect anything. Both facts are
    // stated affirmatively now, exactly one line always prints, and the driver
    // greps for the POSITIVE.
#if defined(__SANITIZE_ADDRESS__)
#  define DIL_ARM_ASAN 1
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define DIL_ARM_ASAN 1
#  endif
#endif
#ifndef DIL_ARM_ASAN
#  define DIL_ARM_ASAN 0
#endif
#if DIL_ARM_ASAN
    std::cout << "    sanitizer: PRESENT" << std::endl;
#else
    std::cout << "    sanitizer: ABSENT — this run proves NOTHING" << std::endl;
#endif

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

    uint256 prev = gh;
    for (int i = 1; i <= 4; ++i) {
        auto h = MakeHeader(prev, static_cast<uint32_t>(1700500000 + i),
                            static_cast<uint8_t>(0x10 + i));
        if (!ad.ProcessNewHeader(h)) { std::cerr << "chain rejected" << std::endl; return 2; }
        prev = h.GetHash();
    }
    CBlockIndex* tip = cs.GetBlockIndex(prev);
    if (tip == nullptr) { std::cerr << "no tip" << std::endl; return 2; }
    cs.SetTip(tip);

    // The victim: a low-work leaf off genesis, unpinned and therefore evictable.
    auto victimHdr = MakeHeader(gh, 1700500099, 0x99);
    if (!ad.ProcessNewHeader(victimHdr)) { std::cerr << "victim rejected" << std::endl; return 2; }
    const uint256 victimHash = victimHdr.GetHash();

    if (arm == "immediate") {
        // Turn the graveyard off: the evictor frees in place, which is exactly
        // what the code did before this branch. Test-only, and the ONLY difference
        // from the `deferred` arm — one binary, one fixture, one variable.
        cs.SetEvictionImmediateFreeForTest(true);
    }

    // ── THE RESOLVE. This thread checkpoints FIRST, then resolves: the pointer is
    // obtained AFTER its last published epoch, which is precisely the state the
    // whole mechanism exists to protect. (Checkpointing after the resolve would be
    // the lie that the `drained` arm tells on purpose.)
    cs.EpochCheckpoint("asan-arm-holder");
    CBlockIndex* held = cs.GetBlockIndex(victimHash);
    if (held == nullptr) { std::cerr << "victim not resolvable" << std::endl; return 2; }
    const int height_before = held->nHeight;

    // ── THE EVICTION, ON ANOTHER THREAD. Not a helper call on this one: the race
    // this class is about is cross-thread, and a same-thread eviction would let a
    // reviewer object that the fixture is not the real shape.
    const size_t before = cs.GetBlockIndexSize();
    std::atomic<bool> evicted{false};
    std::thread evictor([&] {
        evicted.store(cs.EvictLowestWorkLeafNotPinned(before - 1));
        // The evicting thread passes its own boundary and tries to drain. It holds
        // nothing; the HOLDER thread does. Nothing may be freed on its say-so.
        cs.EpochCheckpoint("asan-arm-evictor");
        cs.DrainGraveyard();
    });
    evictor.join();

    if (!evicted.load()) {
        std::cerr << "FIXTURE BROKEN: nothing was evicted, so this arm proves "
                     "nothing. Refusing to report a verdict." << std::endl;
        return 3;
    }
    if (cs.GetBlockIndex(victimHash) != nullptr) {
        std::cerr << "FIXTURE BROKEN: the victim is still resolvable after eviction"
                  << std::endl;
        return 3;
    }

    if (arm == "drained") {
        // THE LIE, TOLD DELIBERATELY. This thread publishes "I hold no
        // CBlockIndex*" while holding one, which is the one thing a checkpoint
        // must never do. The drain is then within its rights to free the entry —
        // and the dereference below must trap. If it does NOT trap, the drain is
        // not reaching the free and every clean run in this suite is vacuous.
        cs.EpochCheckpoint("asan-arm-holder");
        const size_t freed = cs.DrainGraveyard();
        std::cout << "    drained " << freed << " entr" << (freed == 1 ? "y" : "ies")
                  << " while still holding the pointer" << std::endl;
        if (freed == 0) {
            std::cerr << "FIXTURE BROKEN: the drain freed nothing, so the "
                         "dereference below cannot be a use-after-free." << std::endl;
            return 3;
        }
    }

    // ── THE DEREFERENCE. Clean in `deferred`; a use-after-free in `immediate`
    // (freed at the unlink) and in `drained` (freed by the drain).
    g_sink = held->nHeight;
    const bool intact = (g_sink == height_before);

    std::cout << "    dereference completed, value " << (intact ? "intact" : "CHANGED")
              << std::endl;

    if (arm == "deferred") {
        // Only this arm gets to finish tidily: the holder now genuinely holds
        // nothing, so the entry may be reclaimed.
        cs.EpochCheckpoint("asan-arm-holder");
        const size_t freed = cs.DrainGraveyard();
        std::cout << "    after the honest checkpoint, the drain freed " << freed
                  << std::endl;
        if (freed != 1) {
            std::cerr << "FIXTURE BROKEN: the entry was never freed even after the "
                         "holder checkpointed — the graveyard is not draining."
                      << std::endl;
            return 3;
        }
    }

    Dilithion::g_chainParams = saved;
    std::cout << "    arm '" << arm << "' completed without a sanitizer trap"
              << std::endl;
    return 0;
}
