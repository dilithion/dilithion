// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// http_socket_timeout_tests — the bound on an HTTP worker's ONLINE window.
//
// ⚠️ WHY THIS EXISTS, AND IT IS A CORRECTION OF MY OWN CLAIM TWICE OVER.
// CHttpServer's worker thread is an epoch participant, and the eighteen unfunnelled
// `send()` calls in HandleRequest run with it ONLINE — deliberately, because a send
// cannot publish "I hold nothing" without auditing every handler that already ran its
// resolve, and publishing that promise falsely would UNPIN A HOLDER, which is the
// use-after-free direction.
//
// That trade is only acceptable if the ONLINE window is BOUNDED. Round 4 caught a
// comment claiming it was "bounded by the socket timeouts" when this file set no
// socket options at all. Round 8 caught the exemption markers still saying "bounded"
// with nothing bounding them — the same wrong-bound-in-a-comment failure this PR has
// now committed four times (connman's leak, MyEpochSlot's, "Pin bound: one VDF round",
// and this).
//
// So the bound is a VALUE IN CODE (CHttpServer::CLIENT_SOCKET_TIMEOUT_MS) applied by a
// NAMED FUNCTION (ApplyClientSocketTimeouts), and this arm asserts the function does
// what the markers say it does.
//
// ⚠️ WHAT THIS ARM PROVES, AND WHAT IT DOES NOT — stated because the review asked for
// a stronger arm than this one is:
//   PROVES: the production path sets BOTH SO_RCVTIMEO and SO_SNDTIMEO on an accepted
//           socket, at the documented value, and a getsockopt round-trip reads them
//           back. Remove either setsockopt and this goes RED.
//   DOES NOT PROVE: that the OS then honours the timeout and disconnects a
//           non-reading client within it. That is kernel behaviour, not our code, and
//           the arm that would test it needs a live server, a stalled peer and a
//           wall-clock deadline — a timing-dependent integration fixture whose flake
//           rate would exceed its value. Recorded rather than glossed: this is a
//           WIRING arm, not a BEHAVIOUR arm.

#include <api/http_server.h>

#include <cstring>
#include <iostream>
#include <string>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef int socklen_t;
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <unistd.h>
  typedef int SOCKET;
  #define INVALID_SOCKET -1
  #define closesocket close
#endif

namespace {

int g_failed = 0;

void chk(const std::string& what, bool ok)
{
    std::cout << (ok ? "   PASS  " : "   FAIL  ") << what << std::endl;
    if (!ok) ++g_failed;
}

// Read a socket timeout back in milliseconds; -1 if the option cannot be read.
long GetTimeoutMs(SOCKET s, int optname)
{
#ifdef _WIN32
    DWORD tv = 0;
    socklen_t len = sizeof(tv);
    if (getsockopt(s, SOL_SOCKET, optname, (char*)&tv, &len) != 0) return -1;
    return static_cast<long>(tv);
#else
    struct timeval tv;
    std::memset(&tv, 0, sizeof(tv));
    socklen_t len = sizeof(tv);
    if (getsockopt(s, SOL_SOCKET, optname, (char*)&tv, &len) != 0) return -1;
    return static_cast<long>(tv.tv_sec) * 1000 + static_cast<long>(tv.tv_usec) / 1000;
#endif
}

}  // namespace

int main()
{
    std::cout << "\n=== http socket timeouts: the bound on a worker's online window ==="
              << std::endl;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 2;
    }
#endif

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        std::cerr << "could not create a socket -- the arm cannot measure" << std::endl;
        return 2;
    }

    // ⚠️ THE BASELINE IS ASSERTED FIRST. Without it, a platform whose DEFAULT is
    // already 10 s would make this arm pass while the production call did nothing --
    // the arm would be measuring the OS, not the fix.
    const long rcv_before = GetTimeoutMs(s, SO_RCVTIMEO);
    const long snd_before = GetTimeoutMs(s, SO_SNDTIMEO);
    chk("baseline: a fresh socket does NOT already carry the timeout "
        "(else this arm would measure the OS, not the fix)",
        rcv_before != CHttpServer::CLIENT_SOCKET_TIMEOUT_MS &&
        snd_before != CHttpServer::CLIENT_SOCKET_TIMEOUT_MS);

    // THE PRODUCTION PATH. Not a copy of it -- a test that re-implements the thing it
    // checks proves only that the author can write it twice.
    const bool applied = CHttpServer::ApplyClientSocketTimeouts(s);
    chk("the production path reports BOTH options were accepted", applied);

    const long rcv_after = GetTimeoutMs(s, SO_RCVTIMEO);
    const long snd_after = GetTimeoutMs(s, SO_SNDTIMEO);

    chk("SO_RCVTIMEO is set, so a client that connects and says nothing cannot pin "
        "a checkpointing worker indefinitely",
        rcv_after == CHttpServer::CLIENT_SOCKET_TIMEOUT_MS);
    chk("SO_SNDTIMEO is set, so a client that STOPS READING cannot pin one either "
        "-- this is the bound the send-site exemption markers quote",
        snd_after == CHttpServer::CLIENT_SOCKET_TIMEOUT_MS);

    // The markers say "10 s". If the constant moves and the markers do not, the
    // markers are wrong again -- which is the failure this whole arm exists for.
    chk("the documented bound is still 10 s (the exemption markers quote this "
        "value; change one and you must change the other)",
        CHttpServer::CLIENT_SOCKET_TIMEOUT_MS == 10000);

    closesocket(s);
#ifdef _WIN32
    WSACleanup();
#endif

    std::cout << "\n  ===== http socket timeouts: "
              << (g_failed == 0 ? "PASS" : "FAIL") << " (" << g_failed
              << " failed) =====\n" << std::endl;
    return g_failed == 0 ? 0 : 1;
}
