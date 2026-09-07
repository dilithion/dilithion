// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Concurrent CRPCServer::Stop() — the exactly-once teardown property.
//
// WHY THIS FILE EXISTS, and what it discriminates
// ------------------------------------------------
// PR #178's first commit made m_serverSocket std::atomic<int>. That removed
// the DATA RACE that ThreadSanitizer reported (7 of 12 reports on main were
// CRPCServer::Stop) and left the RACE CONDITION underneath completely intact.
// A fresh red-team pass caught it. The distinction is the whole point of this
// suite:
//
//   * TSan detects unsynchronised MEMORY access. It does not model file
//     descriptors, so it cannot see a double-close at all -- and Makefile:200
//     records TSan as Linux-only here, while the worst path is Windows.
//     No sanitizer run, at any count, can establish the property below.
//   * So the ONLY thing that can hold the line on this defect is a test that
//     drives Stop() concurrently and asserts the teardown happened once.
//
// THE DEFECT THIS PINS
// --------------------
// Stop() used to open with a check-then-act on an atomic:
//
//     if (!m_running) { return; }     // two threads BOTH observe true
//     m_running = false;              // ...and BOTH proceed
//
// so N callers ran the ENTIRE teardown: N closes of one listening fd
// (a double-close, with an fd-reuse window between them, while P2P is still
// live), N joins of the same std::thread (undefined behaviour), and a
// range-for over m_workerThreads racing another caller's clear() of it.
// It is now `if (!m_running.exchange(false)) return;` -- one winner owns the
// teardown, everyone else returns immediately.
//
// REACHABILITY -- this is the ordinary Ctrl+C path, not a contrived race:
//     node/dilithion-node.cpp:529    g_node_state.rpc_server->Stop()
//     node/dilithion-node.cpp:8862   rpc_server.Stop()
//     node/dilithion-node.cpp:2386   SetConsoleCtrlHandler(...)
// The Windows console handler runs on an OS-INJECTED thread, so a Ctrl+C puts
// two threads inside Stop() by construction, every time.
//
// WHAT THIS SUITE DOES AND DOES NOT COVER -- READ BEFORE TRUSTING A GREEN
// -----------------------------------------------------------------------
// It covers the Stop() RETURN CONTRACT: the first caller reports performing
// the teardown, later callers report that they did not.
//
// It does NOT cover the concurrent exactly-once guarantee. The case that
// claimed to was removed after surviving TWO mutations of the very guard it
// existed to protect -- the full post-mortem is at the removal note further
// down, and the short version is that the check-then-act window is nanoseconds
// wide and a thread barrier cannot reliably land in it.
//
// So: this suite going green says NOTHING about the race. The race is closed
// by construction (a single atomic exchange cannot be won twice), not by any
// test here. Do not cite a green run from this file as evidence about
// concurrency, and do not add a case to this file that has not itself been
// shown to redden against a mutation.

#include <boost/test/unit_test.hpp>

#include <node/mempool.h>
#include <node/blockchain_storage.h>
#include <consensus/chain.h>
#include <rpc/server.h>
#include <rpc/auth.h>  // CVE-2026-RPC-AUTH: tests must init auth before Start()

#include <atomic>
#include <chrono>
#include <exception>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace {

// Ports start well clear of the other suites' allocators so a parallel run
// cannot collide.
std::atomic<uint16_t> g_stop_port_counter{18900};
uint16_t NextStopPort() { return g_stop_port_counter.fetch_add(1); }

struct TempDir {
    std::filesystem::path dir;
    TempDir() {
        dir = std::filesystem::temp_directory_path() /
              ("dil_rpcstop_" + std::to_string(
                  std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);  // best effort
    }
    std::string path() const { return dir.string(); }
};

// A started CRPCServer.
//
// Start() genuinely has to succeed for this suite to mean anything: if it
// returns false there is no listening socket and no server thread, Stop()
// early-returns at its first line, and a concurrent-Stop test would pass
// while exercising nothing. That is not hypothetical -- integration_tests.cpp
// omits InitializePermissions(), so its Start() returns false every run and
// its RPC assertions have never executed the code they name. Both inits below
// are therefore BOOST_REQUIRE, not BOOST_CHECK.
struct StartedServer {
    TempDir scope;
    CTxMemPool mempool;
    CBlockchainDB chain_db;
    std::unique_ptr<CRPCServer> server;
    uint16_t port;

    StartedServer() : port(NextStopPort()) {
        BOOST_REQUIRE(chain_db.Open(scope.path(), true));
        server = std::make_unique<CRPCServer>(port);
        server->RegisterMempool(&mempool);
        server->RegisterBlockchain(&chain_db);

        const std::string perms = scope.path() + "/rpc_permissions.json";
        BOOST_REQUIRE(server->InitializePermissions(perms, "testuser", "testpass"));
        BOOST_REQUIRE(RPCAuth::InitializeAuth("testuser", "testpass"));
        BOOST_REQUIRE(server->Start());
        BOOST_REQUIRE(server->IsRunning());

        // Let the listener reach accept() before anyone tears it down.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(rpc_concurrent_stop_tests)

// ============================================================================
// REMOVED: concurrent_stop_is_exactly_once -- it was THEATRE, and twice over.
//
// It asserted that exactly one of 8 concurrent Stop() callers performs the
// teardown. It PASSED against two separate mutants that restored the broken
// check-then-act guard (CI runs 34013059180 and 34066230515). In BOTH the
// suite provably EXECUTED -- the job logs show every case entering and
// leaving green -- so this is not "the test did not run". A test that passes
// against the exact bug it was written for is worse than no test: it turns an
// unverified property into a green badge.
//
// WHY IT CANNOT DISCRIMINATE, recorded so nobody rebuilds it the same way:
// the check-then-act window is the ~2 instructions between
//     if (!m_running) { return false; }      and      m_running = false;
// A spin gate releases 8 threads within MICROseconds of one another. That
// window is NANOseconds wide. One thread wins it and the rest arrive long
// after the store, take the early return, and the mutant looks correct.
// Widening the gate, adding threads, or repeating the burst do not change the
// ratio, and the fixture starts a real RPC server per iteration, so a run long
// enough to land in the window is far too slow for CI.
//
// WHAT WOULD ACTUALLY PIN IT -- none of it done, none of it claimed:
//   * a mutant carrying a deliberate yield()/sleep INSIDE the window, which
//     proves the test detects the CLASS while conceding the real window is
//     tiny; or
//   * a single-threaded unit test over the guard extracted out of Stop(); or
//   * TSan on the mutant -- it flags an unsynchronised read-modify-write
//     without having to lose the race. That is the most promising route and
//     is blocked only by the sanitizer legs being unable to fail (PR #165).
//
// STATUS OF THE PROPERTY: exactly-once rests on m_running.exchange(false)
// being correct BY CONSTRUCTION -- a single atomic read-modify-write cannot
// be won twice -- and NOT on any test in this repository. That is a weaker
// assurance than a passing test would have implied, which is precisely why
// the misleading test is deleted rather than kept.
// ============================================================================

// Sequential Stop() must be exactly-once. This is the CHEAP HALF of the
// property and it is all this suite still verifies: it pins the bool contract
// (first caller true, later callers false) but NOT the concurrent guarantee,
// because it holds under the broken check-then-act guard too. See the removal
// note above -- do not read a green here as covering the race.
BOOST_AUTO_TEST_CASE(repeated_sequential_stop_is_safe)
{
    StartedServer s;

    BOOST_CHECK_MESSAGE(s.server->Stop(),
        "the first Stop() on a started server must perform the teardown");
    BOOST_CHECK(!s.server->IsRunning());

    // Second and third calls hit the guard's early return and must report
    // that they did NOT perform a teardown.
    BOOST_CHECK_MESSAGE(!s.server->Stop(),
        "a second Stop() reported performing the teardown again");
    BOOST_CHECK_MESSAGE(!s.server->Stop(),
        "a third Stop() reported performing the teardown again");
    BOOST_CHECK(!s.server->IsRunning());
}

// Guards the premise of the suite. If Start() ever silently stops working --
// the integration_tests.cpp failure mode, where a missing InitializePermissions
// makes Start() return false and every downstream RPC assertion vacuous --
// this case fails loudly instead of the suite quietly testing nothing.
BOOST_AUTO_TEST_CASE(fixture_actually_starts_the_server)
{
    StartedServer s;
    BOOST_CHECK_MESSAGE(s.server->IsRunning(),
        "fixture did not actually start a server; every other case in this "
        "suite would pass vacuously");
    s.server->Stop();
}

BOOST_AUTO_TEST_SUITE_END()
