// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 §3 — the presync gate is REACHED FROM THE LIVE HEADER PATH.
//
// This is the arm the whole mission is about. Every other suite here can pass
// on a tree where the gate has no production caller at all: they construct
// HeadersSyncState or CHeadersManager and call the DoS functions directly. That
// is precisely the "correct check that nothing reaches" defect LP-10 exists to
// close, and a reject/accept test built that way is not evidence of wiring.
//
// So this suite drives the REAL entry point — QueueRawHeadersForProcessing,
// which is what the node's SetHeadersHandler lambda calls — and lets the actual
// HeaderProcessorThread pick the batch up. The observable is
// GetGateRoutedBatchCount(), incremented only at the live call site in
// HeaderProcessorThread. Before §3 that counter cannot move, because the DoS
// path had no production caller; after §3 it moves for a peer that trips
// ShouldUseDoSProtection.
//
// POLICY UNDER TEST (contract A-12): the gate applies ONLY to peers that trip
// ShouldUseDoSProtection. A peer that does not is EXPECTED to take the ungated
// path — that is a decided, documented residual, not a bug, so the second arm
// asserts the ungated route rather than a rejection we deliberately do not do.

#include <net/headers_manager.h>

#include <consensus/chain_work.h>
#include <crypto/randomx_hash.h>
#include <core/chainparams.h>
#include <primitives/block.h>

#include <chrono>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

namespace {

void RequireTrue(const char* what, bool ok)
{
    if (!ok) {
        std::cerr << "\n  FAIL " << what << std::endl;
        std::abort();
    }
}
#define REQUIRE(cond) RequireTrue(#cond, (cond))

uint256 GenesisWork()
{
    return dilithion::consensus::ComputeChainWork(Dilithion::g_chainParams->genesisNBits);
}

// One plausible header. Content does not matter for this arm: what is under
// test is WHICH ROUTE the batch takes, decided before any header is inspected.
std::vector<CBlockHeader> OneHeader()
{
    CBlockHeader h;
    h.nVersion = 1;
    h.nBits = 0x1d00ffff;
    h.nTime = 1737158400;
    h.nNonce = 1;
    return {h};
}

// Feed the live entry point and wait for the processor thread to drain it.
// Polls the counter rather than sleeping a fixed time: a fixed sleep either
// flakes under load or wastes seconds, and a poll that times out is reported
// as a timeout rather than silently read as zero.
long long DriveLivePathAndCount(CHeadersManager& mgr, NodeId peer, bool arm_peer)
{
    REQUIRE(mgr.StartValidationThread());

    if (arm_peer) {
        // Give the peer a sync state, which is one of the three conditions
        // ShouldUseDoSProtection accepts. Without this a fresh single-tip node
        // does not trip it and the batch takes the ungated route by design.
        REQUIRE(mgr.InitializeDoSProtectedSync(peer, mgr.GetMinimumChainWork()));
    }

    const long long before = mgr.GetGateRoutedBatchCount();
    REQUIRE(mgr.QueueRawHeadersForProcessing(peer, OneHeader()));

    // Up to ~5s, polled.
    for (int i = 0; i < 500; ++i) {
        if (mgr.GetGateRoutedBatchCount() > before) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Let the batch finish either way, so the counter is stable when read.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    return mgr.GetGateRoutedBatchCount() - before;
}

// ARM 1 — THE WIRING. A DoS-eligible peer's batch must reach the gate through
// the live path. This is the assertion that is FALSE on every tree before §3,
// including one where the gate itself is perfectly correct.
void test_live_path_routes_an_eligible_peer_through_the_gate()
{
    std::cout << "  test_live_path_routes_an_eligible_peer_through_the_gate..." << std::flush;
    CHeadersManager mgr(GenesisWork());
    const long long routed = DriveLivePathAndCount(mgr, /*peer=*/21, /*arm_peer=*/true);
    if (routed <= 0) {
        std::cerr << "\n  FAIL the live header path did NOT reach the gate "
                     "(routed=" << routed << "). The gate is not wired.\n";
        std::abort();
    }
    std::cout << " OK (routed=" << routed << ")" << std::endl;
}

// ARM 2 — THE DECIDED RESIDUAL, asserted rather than assumed. A peer that does
// not trip ShouldUseDoSProtection takes the ungated route. If this arm ever
// started routing, the policy in A-12 would have silently changed and ordinary
// tip announcements would be subject to a cumulative-work floor.
void test_ineligible_peer_takes_the_ungated_route_by_design()
{
    std::cout << "  test_ineligible_peer_takes_the_ungated_route_by_design..." << std::flush;
    CHeadersManager mgr(GenesisWork());
    const long long routed = DriveLivePathAndCount(mgr, /*peer=*/22, /*arm_peer=*/false);
    REQUIRE(routed == 0);
    std::cout << " OK (routed=0, as A-12 decided)" << std::endl;
}

}  // namespace

int main()
{
    Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());

    // The routed batch reaches real header validation, which hashes with
    // RandomX. Without a VM the processor thread throws "RandomX VM not
    // initialized" and std::terminate kills the process before any assertion
    // runs -- a crash that looks nothing like the wiring failure this suite is
    // actually for. LIGHT validation mode is what the other suites use.
    const char* rx_key = "Dilithion-RandomX-v1";
    randomx_init_validation_mode(rx_key, strlen(rx_key));

    std::cout << "headerssync_gate_wiring_tests" << std::endl;
    test_live_path_routes_an_eligible_peer_through_the_gate();
    test_ineligible_peer_takes_the_ungated_route_by_design();
    std::cout << "headerssync_gate_wiring_tests: ALL PASS" << std::endl;
    return 0;
}
