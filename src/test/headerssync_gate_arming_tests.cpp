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
#include <vector>

namespace {

// Not assert(): this repo ships -DNDEBUG release builds, under which assert()
// compiles away and this suite would print ALL PASS while checking nothing.
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

// Drive the REAL DoS-protected entry points with a given threshold and report
// whether the peer's sync state survived (promoted) or was finalised+erased.
// Empty headers is the branch that evaluates the work comparison.
bool PeerSurvivesPresync(const uint256& threshold)
{
    CHeadersManager mgr(threshold);
    const NodeId peer = 7;

    // Arming path, exercised end to end: the observable value is what gets
    // passed in, exactly as a §3 wiring call site should do.
    if (!mgr.InitializeDoSProtectedSync(peer, mgr.GetMinimumChainWork())) {
        std::cerr << "\n  FAIL InitializeDoSProtectedSync refused to start\n";
        std::abort();
    }

    // THE OBSERVABLE is this function's own return value, not a debug print and
    // not a second Initialize call. On a PRESYNC work failure ProcessNextHeaders
    // reports !success, the manager erases the peer's state and returns FALSE
    // (headers_manager.cpp, the `if (!result.success)` arm); on promotion to
    // REDOWNLOAD it returns TRUE.
    //
    // (An earlier version of this probe asked whether a SECOND
    // InitializeDoSProtectedSync was refused. That was wrong twice over: the
    // function returns true — not false — when a state already exists, and a
    // rejected peer's state is erased, so a fresh Initialize would also succeed.
    // The probe could not have distinguished the two cases at all.)
    const std::vector<CBlockHeader> no_more_headers;
    return mgr.ProcessHeadersWithDoSProtection(peer, no_more_headers);
}

// THE DISCRIMINATING PAIR. Same code path, same peer, same empty-headers
// message -- only the threshold differs. Both arms are required: if they landed
// the same way the suite would certify nothing.
void test_below_threshold_is_rejected_and_at_threshold_is_accepted()
{
    std::cout << "  test_below_threshold_is_rejected_and_at_threshold_is_accepted..." << std::flush;
    using namespace dilithion::consensus;

    // ARM A — ACCEPT. Threshold equals the work our chain start already has, so
    // the seeded accumulator satisfies it and the peer is promoted.
    REQUIRE(PeerSurvivesPresync(GenesisWork()) == true);

    // ARM B — REJECT. A threshold far above anything this peer demonstrated.
    // This arm is only possible BECAUSE the gate can be armed; at the regtest
    // default of zero it could not exist.
    uint256 unreachable = GenesisWork();
    for (int i = 0; i < 5000; ++i)
        unreachable = AddChainWork(unreachable, ComputeChainWork(0x1d00ffff));
    REQUIRE(PeerSurvivesPresync(unreachable) == false);

    std::cout << " OK" << std::endl;
}

// The vacuity check itself, asserted rather than assumed: at threshold ZERO the
// reject arm is IMPOSSIBLE. This is the finding encoded as a test, so that
// anyone who later "simplifies" the arming mechanism away sees why it existed.
void test_zero_threshold_makes_rejection_impossible()
{
    std::cout << "  test_zero_threshold_makes_rejection_impossible..." << std::flush;
    uint256 zero;
    REQUIRE(PeerSurvivesPresync(zero) == true);
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
