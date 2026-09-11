// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 deliverable 0b — ARMING THE PRESYNC CHAIN-WORK GATE, and proving the
// armed value reaches it.
//
// WHY THIS EXISTS. Red-team round 2 found that every acceptance arm drafted for
// the gate (A-1/A-2/A-3/A-7/A-8) would be VACUOUS: regtest and testnet both set
// nMinimumChainWork to zero, the field was private with no setter, and at
// threshold zero `ChainWorkGreaterOrEqual(anything, 0)` is unconditionally
// true -- so "a header chain whose work is below the threshold" cannot exist and
// a rejection test rejects nothing. A five-arm suite, green by construction.
// The fix that made it possible was an ARCHITECTURE change, not a test hook:
// CHeadersManager now takes the threshold as an explicit dependency.
//
// WHAT THIS SUITE DOES AND DOES NOT PROVE.
//   DOES: the gate can be armed; the armed value is observable; and it is
//   carried through the REAL public DoS-protected entry points
//   (InitializeDoSProtectedSync -> ProcessHeadersWithDoSProtection), producing
//   OPPOSITE outcomes either side of the threshold.
//   DOES NOT: that the header MESSAGE path reaches those entry points. It does
//   not -- both still have zero PRODUCTION call sites, and the live route is
//   SetHeadersHandler -> QueueRawHeadersForProcessing -> HeaderProcessorThread
//   -> QueueHeadersForValidation. Closing that is §2.1/§3, and its arms build
//   on this one.

#include <net/headers_manager.h>

#include <consensus/chain_work.h>
#include <core/chainparams.h>
#include <node/genesis.h>
#include <primitives/block.h>

#include <iostream>
#include <optional>
#include <vector>

namespace {

// Not assert(), and the REASON matters because the obvious one is WRONG.
//
// The obvious reason -- "this repo ships -DNDEBUG release builds, so assert()
// compiles away" -- does not apply to test objects. The Makefile carries the rule
// `$(OBJ_DIR)/test/%.o: override CXXFLAGS += -UNDEBUG` (:1443 on this branch,
// :1429 on main -- grep the rule, not the line), added precisely so an
// assert-based suite cannot be silently disarmed, and `override` specifically so
// that `make CXXFLAGS=...` cannot drop it. Anything built through this Makefile
// keeps its assertions.
//
// What REQUIRE() actually buys: the -UNDEBUG rule protects only objects built
// THROUGH the Makefile. A suite compiled by another path -- an IDE, a hand-written
// g++ line, a future CMake target -- would strip assert() and print ALL PASS while
// checking nothing. REQUIRE() holds the property for every build path, not just
// the one we control.
void RequireTrue(const char* what, bool ok)
{
    if (!ok) {
        std::cerr << "\n  FAIL " << what << std::endl;
        std::abort();
    }
}
#define REQUIRE(cond) RequireTrue(#cond, (cond))

// Work of the genesis block: what a fresh manager's chain start carries, and
// therefore the value the seeded PRESYNC accumulator begins at.
uint256 GenesisWork()
{
    return dilithion::consensus::ComputeChainWork(
        Dilithion::g_chainParams->genesisNBits);
}

void test_threshold_is_injectable_and_observable()
{
    std::cout << "  test_threshold_is_injectable_and_observable..." << std::flush;

    // Default construction reads chainparams, which on regtest is zero -- this
    // is the state that made every drafted arm vacuous.
    CHeadersManager unarmed;
    REQUIRE(unarmed.GetMinimumChainWork().IsNull());

    // Explicit construction arms it. If this ever silently fell back to
    // chainparams, every arm below would go quietly vacuous again, so it is
    // asserted directly rather than inferred from behaviour.
    const uint256 threshold = GenesisWork();
    CHeadersManager armed(threshold);
    REQUIRE(armed.GetMinimumChainWork() == threshold);
    REQUIRE(!armed.GetMinimumChainWork().IsNull());

    std::cout << " OK" << std::endl;
}

// Drive the REAL DoS-protected entry points with a given threshold and report the
// peer's resulting sync PHASE.
//
// ⛔ RE-DERIVED after #201 merged (main 8d8b9b8e), and BOTH halves of the old arm
// had to change — this is not the same test with a new header.
//
// 1. THE STIMULUS. It used to send an EMPTY vector, because that was the only way
//    this port evaluated the work comparison. LP-10 F5/D-2 removed the invented
//    empty-batch transition (Core refuses an empty batch, headerssync.cpp:74), so
//    the batch is now ONE REAL VDF HEADER linked to the manager's chain start.
//    That is only possible because #201 routes REGTEST to VDFHeaderProofChecker:
//    under the old IsDilV() selection regtest got the RandomX checker and every
//    synthesisable header failed its proof check — measured then as
//    `n=3 ... ret=0 after=NONE(erased)` and `n=2000 ... ret=0`, identical, which is
//    exactly why this suite used an empty vector and why these two arms were
//    SKIPPED OUT LOUD rather than deleted.
//
// 2. THE OBSERVABLE. It used to be ProcessHeadersWithDoSProtection's return value.
//    That no longer discriminates: F5/D-1 makes a PRESYNC abort return
//    success = TRUE (the batch's headers were valid; there is simply nothing more to
//    do), so the manager returns true whether the peer promoted or was terminated.
//    An arm reading the bool would now PASS IN BOTH DIRECTIONS. The observable is
//    the phase — GetHeadersSyncPhase, added in #196 for precisely this reason:
//      promoted        -> REDOWNLOAD (state retained)
//      below threshold -> the abort finalises, and the manager compare-and-erases a
//                         FINAL state on the way out (headers_manager.cpp), so the
//                         phase reads as nullopt/absent.
std::optional<HeadersSyncState::State> PresyncPhase(const uint256& threshold)
{
    CHeadersManager mgr(threshold);
    const NodeId peer = 7;

    if (!mgr.InitializeDoSProtectedSync(peer, mgr.GetMinimumChainWork())) {
        std::cerr << "\n  FAIL InitializeDoSProtectedSync refused to start\n";
        std::abort();
    }
    // Sanity: the session must begin in PRESYNC, or the arm below is measuring
    // something other than a phase TRANSITION.
    REQUIRE(mgr.GetHeadersSyncPhase(peer) == HeadersSyncState::State::PRESYNC);

    uint256 start = mgr.GetBestHeaderHash();
    if (start.IsNull()) start = Genesis::GetGenesisHash();

    // A VDF header the checker accepts: VDF version, both VDF fields non-null, and
    // nBits EQUAL to genesisNBits — that equality is the rule #201 made sound on
    // regtest by mirroring the producer's constant branch.
    CBlockHeader h;
    h.nVersion      = CBlockHeader::VDF_VERSION;
    h.nBits         = Dilithion::g_chainParams->genesisNBits;
    h.nTime         = 1700000000;
    h.nNonce        = 0;
    h.hashPrevBlock = start;
    for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0x42;
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i]    = 0x37;

    mgr.ProcessHeadersWithDoSProtection(peer, std::vector<CBlockHeader>{h});
    return mgr.GetHeadersSyncPhase(peer);
}

// THE DISCRIMINATING PAIR, restored. Same code path, same peer, same single real
// header — ONLY the threshold differs. If both arms landed the same way the suite
// would certify nothing, which is what the SKIP block said out loud for the two
// rounds it stood.
void test_below_threshold_is_rejected_and_at_threshold_is_accepted()
{
    std::cout << "  test_below_threshold_is_rejected_and_at_threshold_is_accepted..." << std::flush;
    using namespace dilithion::consensus;

    // ARM A — ACCEPT. ⚠️ THE THRESHOLD IS **TWO** BLOCKS' WORK, NOT ONE, AND THE
    // REASON IS A REAL INTERACTION BETWEEN TWO GUARDS IN THIS BRANCH — measured,
    // not guessed: with a one-block threshold this arm FAILED with
    //   "PRESYNC: single-header work reaches the minimum-chain-work gate on its own"
    // which is F3's single-header work bound doing exactly its job. That bound
    // refuses any header whose OWN work REACHES nMinimumChainWork, and the old arm
    // set the threshold to precisely one genesis block's work — so one honest
    // genesis-difficulty header hit it.
    //
    // This is the activation prerequisite F3 documented, demonstrated rather than
    // dodged: nMinimumChainWork MUST exceed one block's work at the hardest
    // difficulty. A test that satisfied the gate by setting the threshold to a
    // single block's work was encoding a configuration the bound forbids.
    //
    // The arithmetic, from the manager: InitializeDoSProtectedSync seeds
    // chainStartWork = ComputeChainWork(genesisNBits) = one block's work, so after
    // one header the accumulator is 2x. With the threshold at 2x: the header's own
    // work (1x) is BELOW it, so the bound passes; the accumulator (2x) REACHES it,
    // so PRESYNC promotes. Both guards are satisfied for the right reasons.
    uint256 two_blocks = GenesisWork();
    two_blocks = AddChainWork(two_blocks, GenesisWork());
    REQUIRE(PresyncPhase(two_blocks) == HeadersSyncState::State::REDOWNLOAD);

    // ARM B — REJECT. A threshold far above anything this peer demonstrated: no
    // promotion, and a non-full batch means the peer's chain has ended (Core
    // headerssync.cpp:91), so the sync aborts and the manager erases the session.
    uint256 unreachable = GenesisWork();
    for (int i = 0; i < 5000; ++i)
        unreachable = AddChainWork(unreachable, ComputeChainWork(0x1d00ffff));
    REQUIRE(!PresyncPhase(unreachable).has_value());

    std::cout << " OK" << std::endl;
}

// The vacuity check itself, asserted rather than assumed: at threshold ZERO the
// reject arm is IMPOSSIBLE. This is the original finding encoded as a test, so that
// anyone who later "simplifies" the arming mechanism away sees why it existed.
void test_zero_threshold_makes_rejection_impossible()
{
    std::cout << "  test_zero_threshold_makes_rejection_impossible..." << std::flush;
    uint256 zero;
    REQUIRE(PresyncPhase(zero) == HeadersSyncState::State::REDOWNLOAD);
    std::cout << " OK" << std::endl;
}

}  // namespace


int main()
{
    Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    std::cout << "headerssync_gate_arming_tests" << std::endl;
    test_threshold_is_injectable_and_observable();
    test_below_threshold_is_rejected_and_at_threshold_is_accepted();
    test_zero_threshold_makes_rejection_impossible();
    std::cout << "headerssync_gate_arming_tests: ALL PASS" << std::endl;
    return 0;
}
