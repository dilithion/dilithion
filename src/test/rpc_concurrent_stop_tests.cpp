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
// HOW TO CONFIRM THIS SUITE IS NOT DECORATIVE
// -------------------------------------------
// Revert server.cpp's guard to the check-then-act form above and rebuild.
// concurrent_stop_is_exactly_once must go RED -- by a std::system_error
// escaping the double join(), or by the process aborting. If it still passes,
// this suite is theatre and should be deleted rather than trusted. A green
// run here is only meaningful against a mutation that has been shown to
// redden it.

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

// The load-bearing case. N threads enter Stop() as close to simultaneously as
// the platform allows; exactly one may perform the teardown.
//
// Under the old check-then-act guard every thread proceeds, so this reaches
// join() on an already-joined std::thread -- undefined behaviour, in practice
// a std::system_error or an abort -- and iterates m_workerThreads while
// another thread clears it.
BOOST_AUTO_TEST_CASE(concurrent_stop_is_exactly_once)
{
    StartedServer s;

    constexpr int kThreads = 8;

    // Spin gate: every thread parks until the flag flips, so they enter Stop()
    // together rather than in a staggered line. Without this the calls
    // serialise and the defect never presents.
    std::atomic<bool> go{false};
    std::atomic<int> ready{0};
    std::atomic<int> threw{0};
    std::atomic<int> returned{0};

    std::vector<std::thread> callers;
    callers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        callers.emplace_back([&]() {
            ready.fetch_add(1, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            try {
                s.server->Stop();
                returned.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception&) {
                // A double join() surfaces here as std::system_error. Counted
                // rather than rethrown so the failure is reported as a failed
                // assertion with a count, not as an opaque terminate().
                threw.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    while (ready.load(std::memory_order_acquire) < kThreads) {
        std::this_thread::yield();
    }
    go.store(true, std::memory_order_release);

    for (auto& t : callers) t.join();

    BOOST_CHECK_MESSAGE(threw.load() == 0,
        "Stop() threw from " << threw.load() << " of " << kThreads
        << " concurrent callers. With an exactly-once guard only one caller "
           "performs the teardown and the rest return immediately; every "
           "caller running it means a double join() on m_serverThread and a "
           "double close() of the listening fd.");

    BOOST_CHECK_MESSAGE(returned.load() == kThreads,
        "only " << returned.load() << " of " << kThreads
        << " Stop() calls returned normally");

    BOOST_CHECK_MESSAGE(!s.server->IsRunning(),
        "server still reports running after " << kThreads << " Stop() calls");
}

// Sequential Stop() must also be exactly-once. This is the cheap half of the
// property and it holds under BOTH the old and new guards -- included so that
// a mutation which reddens the concurrent case but not this one is visibly a
// CONCURRENCY defect rather than a general Stop() breakage. It is a control,
// not extra coverage, and it is expected to stay green across the mutation.
BOOST_AUTO_TEST_CASE(repeated_sequential_stop_is_safe)
{
    StartedServer s;

    BOOST_REQUIRE_NO_THROW(s.server->Stop());
    BOOST_CHECK(!s.server->IsRunning());

    // Second and third calls hit the guard's early return.
    BOOST_REQUIRE_NO_THROW(s.server->Stop());
    BOOST_REQUIRE_NO_THROW(s.server->Stop());
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
