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

#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <vector>

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

// Build a minimal raw HTTP request with an optional Host header (mirrors the
// helper in rpc_host_header_tests.cpp). includeHost=false omits the header so we
// can exercise the default-deny "missing Host" path.
static std::string MakeRequest(const std::string& method,
                               const std::string& path,
                               const std::string& hostHeader,
                               bool includeHost = true) {
    std::string r = method + " " + path + " HTTP/1.1\r\n";
    if (includeHost) r += "Host: " + hostHeader + "\r\n";
    r += "Content-Type: application/json\r\n";
    r += "\r\n";
    return r;
}

// --------------------------------------------------------------------------
// 4. H-01 — the REST surface (/api/v1/*, /x402/*) enforces the Host-allowlist
//    gate, fail-closed. Models CHttpServer::HandleRequest's H-01 branch: the
//    request is dispatched ONLY if the validator is ready AND the Host is
//    allowed. The live code uses the SAME HostValidator instance + predicate.
// --------------------------------------------------------------------------
//
// `validatorReady=false` models the fail-closed pre-Configure state.
static bool SimulateRestGateAllows(const HostValidator& hv,
                                   bool validatorReady,
                                   const std::string& request) {
    if (!validatorReady) return false;                // fail-closed
    return hv.IsRequestHostAllowed(request);
}

static void TestRestHostAllowlistGate() {
    std::cout << "LP-12 H-01: REST /api/v1/* enforces Host-allowlist, fail-closed..." << std::endl;

    // Public-API seed: api_port 9334, operator allowlists its DNS name + IP.
    HostValidator hv;
    hv.Configure(9334, {"seed.dilithion.org", "203.0.113.7"});

    // Loopback is ALWAYS allowed (desktop wallet hitting its own node).
    CHECK(SimulateRestGateAllows(hv, true,
        MakeRequest("POST", "/api/v1/broadcast", "127.0.0.1:9334")));
    CHECK(SimulateRestGateAllows(hv, true,
        MakeRequest("POST", "/api/v1/broadcast", "localhost")));

    // Operator-allowlisted hosts pass (REST is a legitimate public surface).
    CHECK(SimulateRestGateAllows(hv, true,
        MakeRequest("POST", "/api/v1/broadcast", "seed.dilithion.org:9334")));
    CHECK(SimulateRestGateAllows(hv, true,
        MakeRequest("GET", "/api/v1/info", "203.0.113.7")));

    // DNS-rebinding: an attacker page on evil.com that rebinds to the seed IP
    // sends Host: evil.com — NOT in the allowlist — REJECTED before /broadcast.
    CHECK(!SimulateRestGateAllows(hv, true,
        MakeRequest("POST", "/api/v1/broadcast", "evil.com")));
    // Substring / suffix tricks are rejected (exact host-token match).
    CHECK(!SimulateRestGateAllows(hv, true,
        MakeRequest("POST", "/api/v1/broadcast", "seed.dilithion.org.evil.com")));
    CHECK(!SimulateRestGateAllows(hv, true,
        MakeRequest("POST", "/api/v1/broadcast", "127.0.0.1.evil.com")));
    // Missing Host header => default-deny REJECT.
    CHECK(!SimulateRestGateAllows(hv, true,
        MakeRequest("POST", "/api/v1/broadcast", "", /*includeHost=*/false)));
    // x402 surface is gated by the same check.
    CHECK(!SimulateRestGateAllows(hv, true,
        MakeRequest("POST", "/x402/pay", "evil.com")));
    CHECK(SimulateRestGateAllows(hv, true,
        MakeRequest("POST", "/x402/pay", "127.0.0.1")));

    // FAIL-CLOSED: before ConfigureHostAllowlist() runs (validatorReady=false),
    // even a loopback Host is rejected — the gate is never open-by-omission.
    CHECK(!SimulateRestGateAllows(hv, /*validatorReady=*/false,
        MakeRequest("POST", "/api/v1/broadcast", "127.0.0.1:9334")));
}

// --------------------------------------------------------------------------
// 5. M-03 — the wallet gate requires BOTH a loopback socket peer AND a loopback
//    Host (RPC parity). Models the full CHttpServer wallet branch including the
//    secondary loopback-Host check added by LP-12 M-03.
// --------------------------------------------------------------------------
static WalletGate SimulateWalletGateFull(const HostValidator& hv,
                                         bool validatorReady,
                                         bool publicApi,
                                         const std::string& peerIP,
                                         const std::string& request) {
    if (publicApi) {
        return WalletGate::Disabled;
    }
    if (!HostValidator::IsLoopbackIP(peerIP)) {
        return WalletGate::Rejected;   // socket-peer gate (primary)
    }
    // M-03 secondary loopback-Host check, fail-closed.
    if (!validatorReady || !hv.IsRequestLoopbackHost(request)) {
        return WalletGate::Rejected;
    }
    return WalletGate::Served;
}

static void TestWalletGateSecondaryHostCheck() {
    std::cout << "LP-12 M-03: wallet gate needs loopback peer AND loopback Host..." << std::endl;
    HostValidator hv;
    // Even an operator that allowlists a public name for REST does NOT loosen
    // the wallet gate — IsRequestLoopbackHost is independent of the allowlist.
    hv.Configure(8334, {"seed.dilithion.org"});

    // Loopback peer + loopback Host => served (the legitimate desktop case).
    CHECK(SimulateWalletGateFull(hv, true, false, "127.0.0.1",
        MakeRequest("GET", "/wallet", "127.0.0.1:8334")) == WalletGate::Served);
    CHECK(SimulateWalletGateFull(hv, true, false, "::1",
        MakeRequest("GET", "/", "localhost")) == WalletGate::Served);

    // Loopback socket peer but NON-loopback Host (e.g. a rebound page that
    // somehow rode a loopback connection, or an allowlisted public name) =>
    // REJECTED by the M-03 secondary check. Pre-LP-12 this branch served it.
    CHECK(SimulateWalletGateFull(hv, true, false, "127.0.0.1",
        MakeRequest("GET", "/wallet", "seed.dilithion.org")) == WalletGate::Rejected);
    CHECK(SimulateWalletGateFull(hv, true, false, "127.0.0.1",
        MakeRequest("GET", "/wallet", "evil.com")) == WalletGate::Rejected);
    // Missing Host => fail-closed reject even on a loopback peer.
    CHECK(SimulateWalletGateFull(hv, true, false, "127.0.0.1",
        MakeRequest("GET", "/wallet", "", /*includeHost=*/false)) == WalletGate::Rejected);
    // Validator not ready => fail-closed reject.
    CHECK(SimulateWalletGateFull(hv, /*validatorReady=*/false, false, "127.0.0.1",
        MakeRequest("GET", "/wallet", "127.0.0.1")) == WalletGate::Rejected);

    // Non-loopback peer is still rejected at the primary gate regardless of Host.
    CHECK(SimulateWalletGateFull(hv, true, false, "203.0.113.7",
        MakeRequest("GET", "/wallet", "127.0.0.1")) == WalletGate::Rejected);
    // public-api disables entirely (primary, before any Host parse).
    CHECK(SimulateWalletGateFull(hv, true, true, "127.0.0.1",
        MakeRequest("GET", "/wallet", "127.0.0.1")) == WalletGate::Disabled);
}

// --------------------------------------------------------------------------
// 6. M-01 — the per-IP record map stays BOUNDED under rotating source IPs once
//    a periodic cleanup runs. Models the maintenance mechanism the HTTP server's
//    CleanupThread drives: stale records (older than the retention window) are
//    evicted, so an attacker rotating IPs cannot grow the map without bound.
//
// This is a structural model of CRateLimiter::CleanupOldRecords()'s contract
// (evict records whose age >= retention) without linking the full limiter (which
// pulls in chainparams/depends). The live limiter's eviction correctness is
// covered by ratelimiter_tests; here we pin that the HTTP server's PERIODIC
// invocation is what bounds the map — the property M-01 introduces.
// --------------------------------------------------------------------------
namespace {
struct ModelRecord { int64_t createdAt; };
// Mirror of CleanupOldRecords: drop records older than the 1-hour retention.
static void ModelCleanup(std::map<std::string, ModelRecord>& recs,
                         int64_t now, int64_t retentionSecs) {
    for (auto it = recs.begin(); it != recs.end(); ) {
        if (now - it->second.createdAt >= retentionSecs) it = recs.erase(it);
        else ++it;
    }
}
} // namespace

static void TestRateLimiterRecordsStayBounded() {
    std::cout << "LP-12 M-01: per-IP records stay bounded under rotating IPs..." << std::endl;
    const int64_t RETENTION = 3600;       // 1h, mirrors CleanupOldRecords()
    const int64_t CLEAN_EVERY = 300;      // 5-min cadence, mirrors CleanupThread()
    std::map<std::string, ModelRecord> recs;

    // Adversary rotates through a fresh source IP every second for 24h, with the
    // cleanup thread firing every 5 minutes. Without periodic cleanup the map
    // would hold 86400 entries; with it, it stays bounded by ~retention window.
    size_t peak = 0;
    int64_t lastClean = 0;
    for (int64_t t = 0; t < 86400; ++t) {
        recs["10.0." + std::to_string((t / 256) % 256) + "." + std::to_string(t % 256)]
            = ModelRecord{t};
        if (t - lastClean >= CLEAN_EVERY) {
            ModelCleanup(recs, t, RETENTION);
            lastClean = t;
        }
        if (recs.size() > peak) peak = recs.size();
    }
    // Bound: at most one retention window plus one cleanup cadence of arrivals.
    // (3600 + 300 = 3900 distinct second-keyed IPs.) Far below the 86400 an
    // un-pruned map would hold — the periodic cleanup is doing its job.
    CHECK(peak <= RETENTION + CLEAN_EVERY + 1);
    // A final cleanup well past the last arrival drains everything.
    ModelCleanup(recs, 86400 + RETENTION, RETENTION);
    CHECK(recs.empty());
}

int main() {
    std::cout << "=== LP-12 CHttpServer wallet-HTML gate tests ===" << std::endl;
    TestPublicApiDisablesWalletEntirely();
    TestLocalhostDefaultGate();
    TestNoHostHeaderTrust();
    TestRestHostAllowlistGate();             // H-01
    TestWalletGateSecondaryHostCheck();      // M-03
    TestRateLimiterRecordsStayBounded();     // M-01
    std::cout << "All " << g_checks << " checks passed." << std::endl;
    return 0;
}
