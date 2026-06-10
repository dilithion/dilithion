// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-12 unit tests — the standalone CHttpServer (dashboard / light-wallet HTTP
// server on the api_port, NOT the RPC port) wallet-HTML serving gate.
//
// Background: the C-01b/F-003 hardening disabled the token-minting wallet UI on
// a --public-api node and otherwise gated it on the REAL kernel socket peer
// (IsLoopbackIP), but that protection was applied ONLY to the RPC server
// (server.cpp). The parallel CHttpServer served the same wallet HTML
// UNCONDITIONALLY. LP-12 mirrors the RPC gate onto CHttpServer:
//   1. m_public_api  => 403, no page (regardless of peer);
//   2. else          => serve ONLY if the real socket peer is a loopback IP
//                       literal (IsLoopbackIP), Host header NEVER trusted.
//
// This test models that exact dispatch ordering (the same modelling approach as
// rpc_host_header_tests.cpp), so it links ONLY against rpc/host_validator.{h,cpp}
// and the C++ stdlib — no node depends/ required. It is the SSoT predicate
// (IsLoopbackIP) plus the public-api branch that the test pins; the live code in
// http_server.cpp calls the same predicate in the same order.

#include <rpc/host_validator.h>

#include <iostream>
#include <string>

using rpc::HostValidator;

static int g_checks = 0;
#define CHECK(cond) do { \
    g_checks++; \
    if (!(cond)) { \
        std::cerr << "  FAIL: " #cond " (line " << __LINE__ << ")" << std::endl; \
        std::exit(1); \
    } \
} while (0)

// What the CHttpServer wallet-HTML branch did with a given request.
enum class WalletGate {
    Disabled,   // 403: --public-api node, UI disabled entirely
    Rejected,   // 403: non-loopback socket peer
    Served,     // 200: wallet HTML served
};

// Faithful model of the CHttpServer::HandleRequest wallet-HTML branch
// (http_server.cpp). `peerIP` is the kernel-reported getpeername() result
// (GetPeerIP); `publicApi` is the constructor's --public-api flag. The ordering
// mirrors the live code exactly: public-api check FIRST, then the loopback
// socket-peer gate. NOTE: there is intentionally NO Host-header dimension here —
// the CHttpServer decision rests solely on the real socket peer, never on a
// client-supplied header.
static WalletGate SimulateWalletGate(bool publicApi, const std::string& peerIP) {
    if (publicApi) {
        return WalletGate::Disabled;
    }
    if (!HostValidator::IsLoopbackIP(peerIP)) {
        return WalletGate::Rejected;
    }
    return WalletGate::Served;
}

// --------------------------------------------------------------------------
// 1. --public-api disables the wallet UI for ANY peer, loopback or not.
// --------------------------------------------------------------------------
static void TestPublicApiDisablesWalletEntirely() {
    std::cout << "LP-12: --public-api disables wallet UI for every peer..." << std::endl;
    // Even a loopback peer is refused on a public-API node (belt-and-suspenders:
    // the operator SSH-tunnels to a loopback RPC instead).
    CHECK(SimulateWalletGate(/*publicApi=*/true, "127.0.0.1") == WalletGate::Disabled);
    CHECK(SimulateWalletGate(true, "::1") == WalletGate::Disabled);
    // Remote peers are likewise refused — this is the core LP-12 fix: a remote
    // attacker hitting :9334/wallet on a --public-api seed gets a 403, not the
    // token-minting page.
    CHECK(SimulateWalletGate(true, "203.0.113.7") == WalletGate::Disabled);
    CHECK(SimulateWalletGate(true, "8.8.8.8") == WalletGate::Disabled);
    CHECK(SimulateWalletGate(true, "unknown") == WalletGate::Disabled);
}

// --------------------------------------------------------------------------
// 2. Localhost-default: loopback peer served, non-loopback peer rejected.
//    (This is the pre-LP-12 default behavior, now made explicit/enforced.)
// --------------------------------------------------------------------------
static void TestLocalhostDefaultGate() {
    std::cout << "LP-12: localhost-default serves loopback, rejects remote..." << std::endl;
    // Loopback peers (the desktop wallet case) ARE served — default behavior
    // is unchanged for the legitimate localhost user.
    CHECK(SimulateWalletGate(/*publicApi=*/false, "127.0.0.1") == WalletGate::Served);
    CHECK(SimulateWalletGate(false, "127.1.2.3") == WalletGate::Served);
    CHECK(SimulateWalletGate(false, "::1") == WalletGate::Served);
    CHECK(SimulateWalletGate(false, "::ffff:127.0.0.1") == WalletGate::Served);

    // A non-loopback peer on the default (localhost-bound) server should never
    // reach this branch in practice, but if it does (e.g. misconfigured proxy /
    // future bind change), the socket-peer gate refuses it — defense in depth.
    CHECK(SimulateWalletGate(false, "10.0.0.5") == WalletGate::Rejected);
    CHECK(SimulateWalletGate(false, "203.0.113.7") == WalletGate::Rejected);
    // getpeername failure ("unknown") is treated as non-loopback (default-deny).
    CHECK(SimulateWalletGate(false, "unknown") == WalletGate::Rejected);
    CHECK(SimulateWalletGate(false, "") == WalletGate::Rejected);
}

// --------------------------------------------------------------------------
// 3. The decision rests on the SOCKET PEER, not a Host header. There is no
//    Host dimension in the model precisely because the live code does not read
//    one for this decision — a non-loopback peer cannot smuggle a loopback Host
//    to be served the page.
// --------------------------------------------------------------------------
static void TestNoHostHeaderTrust() {
    std::cout << "LP-12: a remote peer cannot be served via any header trick..." << std::endl;
    // The only inputs are publicApi + peerIP; no request string is consulted.
    // A remote peer is Rejected on a localhost-default node and Disabled on a
    // public-API node — there is no input by which it is ever Served.
    CHECK(SimulateWalletGate(false, "198.51.100.23") == WalletGate::Rejected);
    CHECK(SimulateWalletGate(true, "198.51.100.23") == WalletGate::Disabled);
}

int main() {
    std::cout << "=== LP-12 CHttpServer wallet-HTML gate tests ===" << std::endl;
    TestPublicApiDisablesWalletEntirely();
    TestLocalhostDefaultGate();
    TestNoHostHeaderTrust();
    std::cout << "All " << g_checks << " checks passed." << std::endl;
    return 0;
}
