// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 A-9 — TSan harness for the CONCURRENT-DISCONNECT use-after-free on
// CHeadersManager::mapHeadersSyncStates.
//
// THE SCENARIO, NAMED (a TSan run with no named scenario is a false clean):
//
//   thread H (header thread)  ProcessHeadersWithDoSProtection(peer, headers)
//                             -> looks the peer's HeadersSyncState out of
//                                mapHeadersSyncStates and calls
//                                ProcessNextHeaders THROUGH it
//   thread N (net thread)     OnPeerDisconnected(peer)
//                             -> erases that same map entry under cs_headers
//
// Before LP-10 §2.1b the lookup handed out a RAW pointer with the lock already
// released, so N could destroy the object while H was inside the call: a
// use-after-free, not merely a race. §2.1b makes the map hold shared_ptr and
// takes a shared reference under the lock, so an erase drops only the map's
// reference.
//
// WHY A PLAIN TSan RUN OVER THE EXISTING SUITES WOULD BE A FALSE CLEAN: nothing
// in src/test/ drives this pair concurrently, so there is no edge to observe and
// TSan reports nothing. Absence of a report is only evidence if the edge was
// actually driven -- hence the reachability guard below, which EXITS 3 rather
// than reporting a clean run it did not earn.

#include <net/headers_manager.h>

#include <consensus/chain_work.h>
#include <core/chainparams.h>
#include <primitives/block.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

namespace {

std::atomic<long long> g_process_calls{0};
std::atomic<long long> g_disconnect_calls{0};
std::atomic<bool> g_stop{false};

// Rounds of the race. Each round re-arms the peer so both edges can fire again;
// a UAF is timing-dependent, so one round would be a coin flip.
const int kRounds = 400;

uint256 GenesisWork()
{
    return dilithion::consensus::ComputeChainWork(Dilithion::g_chainParams->genesisNBits);
}

void RunRace(CHeadersManager& mgr, NodeId peer)
{
    // Thread H: drive the DoS-protected header path.
    std::thread header_thread([&mgr, peer]() {
        const std::vector<CBlockHeader> empty;
        while (!g_stop.load(std::memory_order_relaxed)) {
            mgr.ProcessHeadersWithDoSProtection(peer, empty);
            g_process_calls.fetch_add(1, std::memory_order_relaxed);
        }
    });

    // Thread N: disconnect the same peer, repeatedly, while H is inside the
    // call above. This is the edge; without it the map is never mutated
    // concurrently and TSan has nothing to find.
    std::thread net_thread([&mgr, peer]() {
        while (!g_stop.load(std::memory_order_relaxed)) {
            mgr.OnPeerDisconnected(peer);
            g_disconnect_calls.fetch_add(1, std::memory_order_relaxed);
            // Re-arm so the next round has a state to race against; without
            // this the map empties and both threads spin over nothing.
            mgr.InitializeDoSProtectedSync(peer, mgr.GetMinimumChainWork());
        }
    });

    for (int i = 0; i < kRounds; ++i) {
        mgr.InitializeDoSProtectedSync(peer, mgr.GetMinimumChainWork());
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
    g_stop.store(true, std::memory_order_relaxed);
    header_thread.join();
    net_thread.join();
}

}  // namespace

int main()
{
    Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());

    // Armed with a real threshold (LP-10 deliverable 0b). At the regtest default
    // of zero every PRESYNC check passes trivially and the state is promoted
    // rather than churned, which exercises fewer of the erase paths.
    CHeadersManager mgr(GenesisWork());
    const NodeId peer = 11;

    std::cout << "headerssync_disconnect_race_tsan: driving "
              << "ProcessHeadersWithDoSProtection || OnPeerDisconnected" << std::endl;

    RunRace(mgr, peer);

    const long long processed = g_process_calls.load();
    const long long disconnected = g_disconnect_calls.load();
    std::cout << "  ProcessHeadersWithDoSProtection calls: " << processed << "\n"
              << "  OnPeerDisconnected calls:              " << disconnected << std::endl;

    // REACHABILITY GUARD. A TSan run that drove neither edge is not a clean
    // result, it is an unrun test -- and it looks identical to a pass. Refuse to
    // let this binary exit 0 unless BOTH sides of the race actually executed
    // many times. Exit 3 is deliberately distinct from TSan's own failure exit.
    if (processed < 100 || disconnected < 100) {
        std::cerr << "\nUNREACHED: the race was not driven (need >=100 of each). "
                     "This is NOT a clean run -- refusing to report one.\n";
        return 3;
    }

    std::cout << "headerssync_disconnect_race_tsan: edges driven; "
                 "TSan verdict is in the report above (empty == no race found)"
              << std::endl;
    return 0;
}
