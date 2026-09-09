// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 §2.0 — the PRESYNC chain-work accumulator must be SEEDED from the
// chain start, not zeroed.
//
// THE DEFECT THIS PINS. HeadersSyncState memset m_current_chain_work to zero
// while CHeadersManager::InitializeDoSProtectedSync starts it at our LOCAL TIP
// (hashBestHeader), not at genesis. Upstream Core seeds the accumulator from
// chain_start->nChainWork. With a zeroed accumulator the comparison at
// headerssync.cpp ProcessNextHeaders asks:
//
//     "has this peer supplied a whole threshold's worth of NEW work
//      beyond our tip?"
//
// instead of the intended:
//
//     "does this peer's chain exceed the absolute minimum?"
//
// Against an absolute, from-genesis nMinimumChainWork the first question is
// never true on a node whose tip already carries a threshold's worth of work
// (not "any node with history" -- see chainparams.cpp): PRESYNC never reaches
// REDOWNLOAD,
// pow_validated_headers stays empty, and header sync stalls. Found by red-team,
// not by me, and it would have shipped as "we set two constants".
//
// ⚠️ WHAT THIS SUITE IS NOT. It is NOT evidence that the presync gate is wired.
// It constructs HeadersSyncState directly, and on this tree nothing in
// production constructs it at all -- InitializeDoSProtectedSync and
// ProcessHeadersWithDoSProtection still have zero PRODUCTION call sites (they
// are called from these suites). The contract's
// reject/accept arms must assert the WIRING and are blocked on deliverable 0b
// (a test-only arming mechanism). What this suite proves is narrower and real:
// the constructor now seeds the accumulator, so that WHEN the gate is wired it
// compares absolute work against an absolute threshold.

#include <net/headerssync.h>

#include <consensus/chain_work.h>
#include <core/chainparams.h>
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

const char* StateName(HeadersSyncState::State s)
{
    switch (s) {
        case HeadersSyncState::State::PRESYNC:    return "PRESYNC";
        case HeadersSyncState::State::REDOWNLOAD: return "REDOWNLOAD";
        case HeadersSyncState::State::FINAL:      return "FINAL";
    }
    return "?";
}

// Drive one PRESYNC decision with a given seed, and report where it lands.
// An empty headers message is the branch that evaluates the work comparison
// and either promotes to REDOWNLOAD or finalises the peer.
HeadersSyncState::State RunPresyncDecision(const uint256& chain_start_work,
                                           const uint256& minimum_work)
{
    HeadersSyncParams params;
    uint256 start_hash;
    start_hash.data[0] = 0xA1;  // opaque; this path never dereferences it

    HeadersSyncState state(/*peer_id=*/1, params, start_hash,
                           /*chain_start_height=*/54000,
                           chain_start_work, minimum_work,
                           /*proof_checker=*/nullptr);

    const std::vector<CBlockHeader> no_more_headers;
    state.ProcessNextHeaders(no_more_headers, true);
    return state.GetState();
}

// The discriminating pair. Same threshold, same peer, same empty-headers
// message -- ONLY the seed differs. If both arms landed in the same state the
// test would be certifying nothing, which is the failure mode this whole
// mission exists to close.
void test_seeded_accumulator_clears_an_absolute_threshold()
{
    std::cout << "  test_seeded_accumulator_clears_an_absolute_threshold..." << std::flush;
    using namespace dilithion::consensus;

    // An absolute, from-genesis style threshold: work of ~54,001 blocks.
    uint256 threshold;
    for (int i = 0; i < 1000; ++i)
        threshold = AddChainWork(threshold, ComputeChainWork(0x1d00ffff));

    // ARM A — the honest non-fresh node. Our local tip ALREADY carries at least
    // the threshold's work, which is the normal case for any node with history.
    // Seeded correctly, PRESYNC is satisfied immediately and promotes.
    const HeadersSyncState::State seeded = RunPresyncDecision(threshold, threshold);
    if (seeded != HeadersSyncState::State::REDOWNLOAD) {
        std::cerr << "\n  FAIL seeded arm landed in " << StateName(seeded)
                  << ", expected REDOWNLOAD -- header sync would stall here\n";
        std::abort();
    }

    // ARM B — the CONTROL, and the pre-fix behaviour. Same threshold, but the
    // accumulator starts at zero, as it did when it was memset. The peer is
    // finalised instead of promoted. This arm is what makes arm A meaningful:
    // it proves the promotion in A came from the SEED and not from a threshold
    // that anything would satisfy.
    uint256 zero;
    const HeadersSyncState::State unseeded = RunPresyncDecision(zero, threshold);
    if (unseeded == HeadersSyncState::State::REDOWNLOAD) {
        std::cerr << "\n  FAIL control arm ALSO promoted -- the threshold is not "
                     "discriminating, so arm A proves nothing\n";
        std::abort();
    }
    REQUIRE(unseeded == HeadersSyncState::State::FINAL);

    std::cout << " OK" << std::endl;
}

// A seed at zero must still work when zero is CORRECT -- i.e. a genuinely fresh
// node with a zero threshold. Guards against "fix" by always promoting.
void test_zero_threshold_still_promotes_from_a_zero_seed()
{
    std::cout << "  test_zero_threshold_still_promotes_from_a_zero_seed..." << std::flush;
    uint256 zero;
    REQUIRE(RunPresyncDecision(zero, zero) == HeadersSyncState::State::REDOWNLOAD);
    std::cout << " OK" << std::endl;
}

// The seed must be carried, not merely accepted: a seed BELOW the threshold
// must not promote, or the constructor could be ignoring the argument entirely.
void test_seed_below_threshold_does_not_promote()
{
    std::cout << "  test_seed_below_threshold_does_not_promote..." << std::flush;
    using namespace dilithion::consensus;

    uint256 threshold;
    for (int i = 0; i < 100; ++i)
        threshold = AddChainWork(threshold, ComputeChainWork(0x1d00ffff));

    uint256 small_seed = ComputeChainWork(0x1d00ffff);  // one block's worth
    REQUIRE(RunPresyncDecision(small_seed, threshold) == HeadersSyncState::State::FINAL);
    std::cout << " OK" << std::endl;
}

}  // namespace

int main()
{
    Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    std::cout << "headerssync_accumulator_seeding_tests" << std::endl;
    test_seeded_accumulator_clears_an_absolute_threshold();
    test_zero_threshold_still_promotes_from_a_zero_seed();
    test_seed_below_threshold_does_not_promote();
    std::cout << "headerssync_accumulator_seeding_tests: ALL PASS" << std::endl;
    return 0;
}
