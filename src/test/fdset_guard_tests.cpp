// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// BKL-30 / A-08 — behavioural tests for the FD_SET guard and the bounded RPC
// accept queue.
//
// Invariants under test:
//   I1. FD_SET / FD_ISSET are only ever reached with sock < FD_SETSIZE (POSIX).
//       A descriptor at/above it is refused by every select() wrapper and
//       reported as an error on that socket — never indexed.
//   I2. CRPCServer::m_clientQueue.size() <= MAX_PENDING_RPC_CLIENTS at all
//       times; accepts beyond it are closed immediately and counted
//       (getrpcinfo.dropped_accepts); Stop() closes what is still queued.
//
// The POSIX cases reproduce the M-30 abort: with -D_FORTIFY_SOURCE=2 (the
// default CXXFLAGS) glibc's FD_SET expands to __fdelt_chk, which calls
// __chk_fail -> SIGABRT for fd >= FD_SETSIZE. Removing the guard makes these
// cases abort the whole test binary (verify-the-verifier: fix_a08_report.md).

#include <boost/test/unit_test.hpp>

#include <util/fdset_guard.h>
#include <net/sock.h>
#include <net/socket.h>
#include <net/connman.h>
#include <rpc/auth.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

namespace {

#ifdef _WIN32
using test_sock_t = SOCKET;
const test_sock_t kBadSock = INVALID_SOCKET;
void CloseSock(test_sock_t s) { if (s != INVALID_SOCKET) closesocket(s); }
bool SetNonBlock(test_sock_t s) { u_long m = 1; return ioctlsocket(s, FIONBIO, &m) == 0; }
struct WinsockScope {
    WinsockScope() { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); }
    ~WinsockScope() { WSACleanup(); }
};
#else
using test_sock_t = int;
const test_sock_t kBadSock = -1;
void CloseSock(test_sock_t s) { if (s >= 0) close(s); }
bool SetNonBlock(test_sock_t s) {
    int f = fcntl(s, F_GETFL, 0);
    return f >= 0 && fcntl(s, F_SETFL, f | O_NONBLOCK) == 0;
}
struct WinsockScope {};
#endif

// Loopback IPv4 listener on an ephemeral port.
struct Listener {
    test_sock_t fd{kBadSock};
    uint16_t port{0};
    Listener() {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == kBadSock) return;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || listen(fd, 16) != 0) {
            CloseSock(fd);
            fd = kBadSock;
            return;
        }
        socklen_t len = sizeof(a);
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
            CloseSock(fd);
            fd = kBadSock;
            return;
        }
        port = ntohs(a.sin_port);
    }
    ~Listener() { CloseSock(fd); }
};

test_sock_t ConnectLoopback(uint16_t port) {
    test_sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == kBadSock) return kBadSock;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        CloseSock(s);
        return kBadSock;
    }
    return s;
}


// Ports: distinct from rpc_tests (18432-18435), tx_index_integration (18500+)
// and the live local test nodes (18981/18982/18991/18992).
std::atomic<uint16_t> g_a08_port{18650};
uint16_t NextA08Port() { return g_a08_port.fetch_add(1); }



} // namespace

// Friend seam declared in connman.h: reaches the private select() wrapper
// without starting threads or a peer manager.
struct CConnmanFdSetTestAccess {
    static bool Select(CConnman& c, std::set<int>& r, std::set<int>& s, std::set<int>& e) {
        return c.SocketEventsSelect(r, s, e);
    }
};

BOOST_AUTO_TEST_SUITE(fdset_guard_tests)

// ---------------------------------------------------------------------------
// I1(a) — the primitive itself
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(fdsetadd_refuses_what_fd_set_cannot_hold)
{
    fd_set set;
    FD_ZERO(&set);
#ifndef _WIN32
    BOOST_CHECK(!IsFdSelectable(-1));
    BOOST_CHECK(IsFdSelectable(0));
    BOOST_CHECK(IsFdSelectable(FD_SETSIZE - 1));
    BOOST_CHECK(!IsFdSelectable(FD_SETSIZE));          // the M-30 abort value
    BOOST_CHECK(!IsFdSelectable(FD_SETSIZE + 100));
    BOOST_CHECK(!FdSetAdd(FD_SETSIZE, &set));
    BOOST_CHECK(!FdSetAdd(FD_SETSIZE + 100, &set));
    BOOST_CHECK(!FdSetAdd(-1, &set));
    BOOST_CHECK(FdSetAdd(FD_SETSIZE - 1, &set));
    BOOST_CHECK(FD_ISSET(FD_SETSIZE - 1, &set));
#else
    // The Makefile defines FD_SETSIZE=1024 for Windows and the header
    // static_asserts it. The count guard refuses the (FD_SETSIZE+1)th socket
    // instead of letting winsock drop it silently.
    BOOST_CHECK(FD_SETSIZE >= 1024);
    BOOST_CHECK(!FdSetAdd(INVALID_SOCKET, &set));
    for (unsigned i = 0; i < static_cast<unsigned>(FD_SETSIZE); ++i) {
        BOOST_REQUIRE(FdSetAdd(static_cast<SOCKET>(i + 1), &set));
    }
    BOOST_CHECK_EQUAL(set.fd_count, static_cast<unsigned>(FD_SETSIZE));
    BOOST_CHECK(!FdSetAdd(static_cast<SOCKET>(FD_SETSIZE + 1), &set));
    BOOST_CHECK_EQUAL(set.fd_count, static_cast<unsigned>(FD_SETSIZE));
#endif
    BOOST_CHECK(!ShouldLogRefusal(0));
    BOOST_CHECK(ShouldLogRefusal(1));
    BOOST_CHECK(ShouldLogRefusal(2));
    BOOST_CHECK(!ShouldLogRefusal(3));
    BOOST_CHECK(ShouldLogRefusal(1024));
    BOOST_CHECK(!ShouldLogRefusal(1025));
}

#ifndef _WIN32
// ---------------------------------------------------------------------------
// I1(b) — real descriptors at/above FD_SETSIZE. The brief's scenario: raise
// the soft nofile limit to 2048, open 1100 dummy fds, then accept one socket.
// ---------------------------------------------------------------------------
struct HighFdFixture {
    static constexpr int kDummyFds = 1100;
    bool ok{false};
    std::string skip_reason;
    int low_pair[2]{-1, -1};      // created BEFORE the dummies: a low, readable fd
    Listener listener;             // BEFORE the dummies too (its fd stays low)
    std::vector<int> dummies;
    int client{-1};
    int accepted{-1};              // the descriptor the old code would FD_SET

    HighFdFixture() {
        struct rlimit rl{};
        BOOST_REQUIRE_EQUAL(getrlimit(RLIMIT_NOFILE, &rl), 0);
        const rlim_t want = 2048;
        if (rl.rlim_cur < want) {
            rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY || rl.rlim_max >= want) ? want : rl.rlim_max;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
            BOOST_REQUIRE_EQUAL(getrlimit(RLIMIT_NOFILE, &rl), 0);
        }
        if (rl.rlim_cur < static_cast<rlim_t>(kDummyFds + 64)) {
            skip_reason = "RLIMIT_NOFILE soft limit " + std::to_string(rl.rlim_cur) +
                          " cannot be raised to hold 1100 dummy descriptors";
            return;
        }
        BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, low_pair), 0);
        BOOST_REQUIRE(listener.fd >= 0);
        BOOST_REQUIRE(low_pair[0] < FD_SETSIZE && low_pair[1] < FD_SETSIZE && listener.fd < FD_SETSIZE);
        dummies.reserve(kDummyFds);
        for (int i = 0; i < kDummyFds; ++i) {
            int fd = open("/dev/null", O_RDONLY);
            BOOST_REQUIRE_MESSAGE(fd >= 0, "open(/dev/null) #" << i << " failed: " << strerror(errno));
            dummies.push_back(fd);
        }
        BOOST_REQUIRE(dummies.back() >= FD_SETSIZE);
        client = ConnectLoopback(listener.port);
        BOOST_REQUIRE(client >= 0);
        sockaddr_storage ss{};
        socklen_t sl = sizeof(ss);
        accepted = accept(listener.fd, reinterpret_cast<sockaddr*>(&ss), &sl);
        BOOST_REQUIRE(accepted >= 0);
        BOOST_REQUIRE_MESSAGE(accepted >= FD_SETSIZE, "accepted fd " << accepted << " is below FD_SETSIZE "
                              << FD_SETSIZE << " - fixture cannot exercise the guard");
        // make the low fd readable
        BOOST_REQUIRE_EQUAL(write(low_pair[1], "r", 1), 1);
        ok = true;
    }
    ~HighFdFixture() {
        CloseSock(accepted);
        CloseSock(client);
        for (int fd : dummies) close(fd);
        CloseSock(low_pair[0]);
        CloseSock(low_pair[1]);
    }
};

BOOST_AUTO_TEST_CASE(wait_refuses_high_fd_without_abort)
{
    HighFdFixture f;
    if (!f.ok) { BOOST_TEST_MESSAGE("SKIP: " << f.skip_reason); return; }
    // Pre-fix: FD_SET(accepted, ...) -> __fdelt_chk -> SIGABRT right here.
    const int events = static_cast<int>(SocketEvent::RECV) |
                       static_cast<int>(SocketEvent::SEND) |
                       static_cast<int>(SocketEvent::ERR);
    BOOST_CHECK_EQUAL(CSock::Wait(f.accepted, events, std::chrono::milliseconds(10)), -1);
    // Wait() does not own the descriptor: it must still be open and usable by
    // the caller (no close-by-callee, hence no double close on the caller's path).
    BOOST_CHECK_EQUAL(send(f.accepted, "x", 1, MSG_NOSIGNAL), 1);
    // A low fd on the same code path is unaffected.
    BOOST_CHECK_EQUAL(CSock::Wait(f.low_pair[0], static_cast<int>(SocketEvent::RECV), std::chrono::milliseconds(10)),
                      static_cast<int>(SocketEvent::RECV));
}

BOOST_AUTO_TEST_CASE(waitmany_reports_high_fd_as_error_and_still_serves_low_fds)
{
    HighFdFixture f;
    if (!f.ok) { BOOST_TEST_MESSAGE("SKIP: " << f.skip_reason); return; }
    std::set<socket_t> recv_set{f.low_pair[0], f.accepted};
    std::set<socket_t> send_set;
    std::set<socket_t> error_set{f.low_pair[0], f.accepted};
    const int r = CSock::WaitMany(recv_set, send_set, error_set, std::chrono::milliseconds(200));
    BOOST_CHECK_GE(r, 2);                               // low readable + high unselectable
    BOOST_CHECK_EQUAL(recv_set.count(f.low_pair[0]), 1u);
    BOOST_CHECK_EQUAL(recv_set.count(f.accepted), 0u);
    BOOST_CHECK_EQUAL(error_set.count(f.accepted), 1u);  // "you can never wait on this one"
    BOOST_CHECK_EQUAL(error_set.count(f.low_pair[0]), 0u);
    BOOST_CHECK(send_set.empty());
}

BOOST_AUTO_TEST_CASE(waitmany_with_only_high_fds_returns_them_as_errors_without_select)
{
    HighFdFixture f;
    if (!f.ok) { BOOST_TEST_MESSAGE("SKIP: " << f.skip_reason); return; }
    std::set<socket_t> recv_set{f.accepted};
    std::set<socket_t> send_set{f.accepted};
    std::set<socket_t> error_set;
    const auto t0 = std::chrono::steady_clock::now();
    const int r = CSock::WaitMany(recv_set, send_set, error_set, std::chrono::milliseconds(2000));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    BOOST_CHECK_EQUAL(r, 1);
    BOOST_CHECK(recv_set.empty());
    BOOST_CHECK(send_set.empty());
    BOOST_CHECK_EQUAL(error_set.count(f.accepted), 1u);
    // nothing selectable => no select() sleep for the full timeout
    BOOST_CHECK(elapsed < std::chrono::milliseconds(1000));
}

BOOST_AUTO_TEST_CASE(connman_select_marks_high_fd_error_ready)
{
    HighFdFixture f;
    if (!f.ok) { BOOST_TEST_MESSAGE("SKIP: " << f.skip_reason); return; }
    CConnman connman;   // never Start()ed; SocketEventsSelect touches only its arguments
    std::set<int> recv_set{f.low_pair[0], f.accepted};
    std::set<int> send_set;
    std::set<int> error_set{f.low_pair[0], f.accepted};
    BOOST_CHECK(CConnmanFdSetTestAccess::Select(connman, recv_set, send_set, error_set));
    BOOST_CHECK_EQUAL(recv_set.count(f.low_pair[0]), 1u);
    BOOST_CHECK_EQUAL(recv_set.count(f.accepted), 0u);
    BOOST_CHECK_EQUAL(error_set.count(f.accepted), 1u);  // SocketHandler will MarkDisconnect() it
    BOOST_CHECK_EQUAL(error_set.count(f.low_pair[0]), 0u);

    // Only a high fd and nothing readable: still "an event" (the error), not a timeout.
    std::set<int> r2{f.accepted}, s2, e2{f.accepted};
    BOOST_CHECK(CConnmanFdSetTestAccess::Select(connman, r2, s2, e2));
    BOOST_CHECK(r2.empty());
    BOOST_CHECK_EQUAL(e2.count(f.accepted), 1u);
}

BOOST_AUTO_TEST_CASE(csocket_recvall_and_connect_refuse_high_fd)
{
    // CSocket owns its descriptor, so here the guard refuses/closes in place.
    const uint16_t port = NextA08Port();
    CSocket srv;
    BOOST_REQUIRE(srv.Bind(port));       // allocated BEFORE the dummies: low fd
    BOOST_REQUIRE(srv.Listen(4));
    HighFdFixture f;                     // 1100 dummies from here on
    if (!f.ok) { BOOST_TEST_MESSAGE("SKIP: " << f.skip_reason); return; }

    int c = ConnectLoopback(port);
    BOOST_REQUIRE(c >= FD_SETSIZE);
    auto acc = srv.Accept();
    BOOST_REQUIRE(acc);
    BOOST_REQUIRE(acc->GetFD() >= FD_SETSIZE);
    char buf[4];
    // Pre-fix: FD_SET(sock_fd) inside RecvAll -> abort.
    BOOST_CHECK_EQUAL(acc->RecvAll(buf, 1), -1);
    CloseSock(c);

    // Connect(): the non-blocking connect wait FD_SETs the fresh (high) socket.
    // On loopback the connect may complete synchronously (no wait, no FD_SET);
    // either way the call returns without UB, and a high-fd socket that did
    // connect still refuses RecvAll.
    CSocket cli;
    const bool connected = cli.Connect("127.0.0.1", port, 1000);
    if (connected) {
        BOOST_CHECK(cli.GetFD() >= FD_SETSIZE);
        BOOST_CHECK_EQUAL(cli.RecvAll(buf, 1), -1);
    } else {
        BOOST_CHECK(!cli.IsValid());     // the guard closed it in place
    }
}
#endif // !_WIN32

// ---------------------------------------------------------------------------
// I2 — the RPC accept queue is bounded
// ---------------------------------------------------------------------------
// ⛔ TWO CASES ARE DEFERRED WITH THE FIX THEY COVER, NOT DELETED:
//   rpc_accept_queue_caps_at_max_pending_and_counts_drops
//   getrpcinfo_exposes_queue_bound_and_drop_counter
// They exercise the RPC accept-queue bound (BKL-30 / P-04), which is NOT in
// this PR -- its half of 12006c7a edits CRPCServer::Stop(), and main has since
// REORDERED that teardown, so the original review does not transfer. They also
// cannot compile here: they call MAX_PENDING_RPC_CLIENTS, GetDroppedAccepts,
// GetPendingClientCount, SetThreadPoolSize and GetMaxPendingClients, none of
// which exist on main. They land with the accept-queue PR (row FDSET-B).

BOOST_AUTO_TEST_SUITE_END()
