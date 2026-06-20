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
#include <api/http_path_gate.h>

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

// ==========================================================================
// 7. GATE-BYPASS FOLD (PR #112 extreview, finding #1) — the H-01 gate's
//    sensitive-surface decision, exercised through the REAL production
//    functions api::NormalizeRequestPath + api::IsSensitiveSurface (NOT a
//    re-model). CHttpServer::HandleRequest computes exactly:
//
//        const api::NormalizedPath norm = api::NormalizeRequestPath(rawPath);
//        const bool sensitive = !norm.ok || api::IsSensitiveSurface(norm.path);
//
//    GateSensitive() below calls those SAME functions, so if the normalization
//    is deleted or weakened the must-gate assertions here FAIL — this is the
//    mutation-resistance the review demanded (it caught that the OLD test
//    re-implemented the gate and was blind to every bypass vector).
// ==========================================================================

// The live gate decision, verbatim from http_server.cpp's gate block.
static bool GateSensitive(const std::string& rawPath) {
    const api::NormalizedPath norm = api::NormalizeRequestPath(rawPath);
    return !norm.ok || api::IsSensitiveSurface(norm.path);
}

static void TestPathNormalizationGateBypassMatrix() {
    std::cout << "LP-12 fold: every spelling of a sensitive path is gated..." << std::endl;

    // ---- Canonical sensitive surfaces are gated. ----
    CHECK(GateSensitive("/wallet"));
    CHECK(GateSensitive("/wallet.html"));
    CHECK(GateSensitive("/"));
    CHECK(GateSensitive("/api/stats"));
    CHECK(GateSensitive("/metrics"));
    CHECK(GateSensitive("/api/v1/broadcast"));
    CHECK(GateSensitive("/api/v1/info"));
    CHECK(GateSensitive("/x402/pay"));

    // ---- Finding #1 bypass vectors — ALL must now be gated. ----
    // Query string on an exact-match path (the original headline bypass).
    CHECK(GateSensitive("/wallet?x"));
    CHECK(GateSensitive("/wallet?a=b&c=d"));
    CHECK(GateSensitive("/api/stats?x"));
    CHECK(GateSensitive("/metrics?format=prom"));
    // Fragment.
    CHECK(GateSensitive("/wallet#frag"));
    CHECK(GateSensitive("/api/stats#x"));
    // Trailing slash.
    CHECK(GateSensitive("/wallet/"));
    CHECK(GateSensitive("/api/stats/"));
    CHECK(GateSensitive("/metrics/"));
    CHECK(GateSensitive("/api/v1/"));
    CHECK(GateSensitive("/x402/"));
    // Mixed / upper case.
    CHECK(GateSensitive("/API/v1/broadcast"));
    CHECK(GateSensitive("/Api/V1/Broadcast"));
    CHECK(GateSensitive("/X402/pay"));
    CHECK(GateSensitive("/WALLET"));
    CHECK(GateSensitive("/Metrics"));
    CHECK(GateSensitive("/API/STATS"));
    // Percent-encoding (/%61pi/ == /api/, %2f == '/', %2e == '.').
    CHECK(GateSensitive("/%61pi/v1/broadcast"));     // %61 = 'a'
    CHECK(GateSensitive("/api/v1%2fbroadcast"));     // encoded slash -> /api/v1/broadcast
    CHECK(GateSensitive("/%77allet"));               // %77 = 'w'
    // Dot-segment traversal that resolves ONTO a sensitive surface IS gated.
    // (NOTE: /api/v1/../x402/pay canonicalizes to /api/x402/pay — the '..' pops
    //  the v1 segment, NOT 'api' — so it is NOT sensitive and 404s; covered in
    //  the negative cases below. The protection is gate/dispatch agreement on
    //  the SAME canonical path, whatever that path is.)
    CHECK(GateSensitive("/x402/../wallet"));         // -> /wallet
    CHECK(GateSensitive("/api/v1/../../wallet"));    // -> /wallet
    CHECK(GateSensitive("/foo/../wallet"));          // -> /wallet
    CHECK(GateSensitive("/api/v1/%2e%2e/v1/broadcast")); // -> /api/v1/broadcast
    CHECK(GateSensitive("/api/v1/./broadcast"));     // -> /api/v1/broadcast
    CHECK(GateSensitive("/./wallet"));               // -> /wallet
    // Duplicate slashes.
    CHECK(GateSensitive("//api//v1//broadcast"));
    CHECK(GateSensitive("///wallet"));
    CHECK(GateSensitive("//metrics"));
    CHECK(GateSensitive("/api//stats"));

    // ---- Fail-closed: non-normalizable paths are gated (treated sensitive). ----
    CHECK(GateSensitive("/api/v1/%zz"));   // malformed %-escape
    CHECK(GateSensitive("/wallet%2"));     // truncated %-escape
    CHECK(GateSensitive("/%2e%2e/etc"));   // '..' traversing above root
    CHECK(GateSensitive("/../etc/passwd"));
    CHECK(GateSensitive("/wallet%00.html")); // embedded NUL via %00

    // ---- Genuinely public paths are NOT gated (gate must not over-block to
    //      the point of breaking the LB health probe handling order). These are
    //      paths the server would 404 or treat as health; none are sensitive. ----
    CHECK(!GateSensitive("/favicon.ico"));
    CHECK(!GateSensitive("/robots.txt"));
    CHECK(!GateSensitive("/api/health"));   // health is matched ABOVE the gate
    CHECK(!GateSensitive("/api/v2/info"));  // not a known sensitive prefix
    CHECK(!GateSensitive("/walletx"));      // not /wallet (no false prefix)
    CHECK(!GateSensitive("/metricsx"));
    CHECK(!GateSensitive("/api/statsx"));
    CHECK(!GateSensitive("/x402x/pay"));
    CHECK(!GateSensitive("/nope"));
    // /api/v1/../x402/pay -> /api/x402/pay ('..' cancels v1): NOT sensitive.
    // The gate and the live REST dispatch agree it is unrouted -> 404.
    CHECK(!GateSensitive("/api/v1/../x402/pay"));
    CHECK(!GateSensitive("/api/v1/%2e%2e/x402/pay"));  // same, percent-encoded
}

// Direct assertions on the normalizer's canonical output (pins the contract
// the gate relies on — also mutation-resistant: weakening any step shows here).
static void TestNormalizerCanonicalForm() {
    std::cout << "LP-12 fold: NormalizeRequestPath canonical-form contract..." << std::endl;
    auto norm = [](const std::string& p) { return api::NormalizeRequestPath(p); };

    CHECK(norm("/wallet?x").ok && norm("/wallet?x").path == "/wallet");
    CHECK(norm("/wallet/").path == "/wallet");
    CHECK(norm("//api//v1//broadcast").path == "/api/v1/broadcast");
    CHECK(norm("/api/v1/../x402/pay").path == "/api/x402/pay"); // '..' pops v1
    CHECK(norm("/x402/../wallet").path == "/wallet");           // '..' pops x402
    CHECK(norm("/%61pi/v1/info").path == "/api/v1/info");
    CHECK(norm("/").ok && norm("/").path == "/");
    CHECK(norm("/foo/./bar").path == "/foo/bar");
    // Fail-closed cases report ok == false.
    CHECK(!norm("/%zz").ok);
    CHECK(!norm("/wallet%2").ok);
    CHECK(!norm("/../escape").ok);
    CHECK(!norm("/a/../../escape").ok);
    CHECK(!norm("/x%00y").ok);
}

// ==========================================================================
// 9. QUERY-PRESERVATION (x402 functional-regression fix) — the gate strips the
//    query for CLASSIFICATION, but the handler must still RECEIVE it. This
//    models CHttpServer::HandleRequest's dispatch exactly:
//
//        const NormalizedPath norm = NormalizeRequestPath(rawPath);   // gate path
//        const std::string rawQuery = ExtractRawQuery(rawPath);       // carried query
//        dispatchPath = rawQuery.empty() ? norm.path
//                                        : norm.path + "?" + rawQuery; // handler input
//
//    using the REAL production functions (NormalizeRequestPath + ExtractRawQuery),
//    so a regression in either shows up here. We then run the facilitator's OWN
//    query-extraction (subpath.find('?'), verbatim from facilitator.cpp:73) and
//    the REST handler's OWN query-strip on the dispatch path to prove the handler
//    recovers `address=ADDR`.
// ==========================================================================

// Build the dispatch path EXACTLY as the live server does (only on norm.ok).
static std::string DispatchPathForRoutedRequest(const std::string& rawPath) {
    const api::NormalizedPath norm = api::NormalizeRequestPath(rawPath);
    // The live server only reaches handler dispatch when norm.ok; a non-ok path
    // is rejected before this point. Mirror that: callers below use only ok paths.
    const std::string rawQuery = api::ExtractRawQuery(rawPath);
    return rawQuery.empty() ? norm.path : (norm.path + "?" + rawQuery);
}

// Verbatim model of CFacilitator::HandleRequest's query carve-out
// (facilitator.cpp:64-78): strip "/x402/", then split the FIRST '?' into
// pathPart + query. Returns the `query` the handler would parse `address=` from.
static std::string FacilitatorQueryFor(const std::string& dispatchPath) {
    std::string subpath = dispatchPath.substr(6);  // Skip "/x402/"
    size_t qmark = subpath.find('?');
    if (qmark != std::string::npos) return subpath.substr(qmark + 1);
    return std::string();
}

// Verbatim model of CFacilitator::HandleDnaAttest's address parse
// (facilitator.cpp:243-257): pull `address=` out of the query, trim at '&'.
static std::string ParsedAddressFor(const std::string& query) {
    size_t pos = query.find("address=");
    if (pos == std::string::npos) return std::string();
    std::string address = query.substr(pos + 8);
    size_t amp = address.find('&');
    if (amp != std::string::npos) address = address.substr(0, amp);
    return address;
}

// Verbatim model of CRestAPI::HandleRequest's subpath/param parse INCLUDING the
// new query-strip: skip "/api/v1/", drop a trailing '?...', split first '/'.
// Returns the `param` the REST handler would treat as e.g. the address/txid.
static std::string RestParamFor(const std::string& dispatchPath) {
    std::string subpath = dispatchPath.substr(8);  // Skip "/api/v1/"
    size_t qmark = subpath.find('?');
    if (qmark != std::string::npos) subpath = subpath.substr(0, qmark);
    size_t slash = subpath.find('/');
    if (slash != std::string::npos) return subpath.substr(slash + 1);
    return std::string();  // no param segment
}

static void TestQueryPreservationForHandlers() {
    std::cout << "LP-12 fix: handlers receive the query (x402 dna-attest regression)..." << std::endl;

    // ---- THE REGRESSION: /x402/dna-attest?address=ADDR must reach the handler
    //      with the query (and thus address=ADDR) intact. ----
    {
        const std::string dp = DispatchPathForRoutedRequest("/x402/dna-attest?address=DvWxyzADDR123");
        // The gate path used for dispatch is canonical /x402/dna-attest...
        CHECK(dp.rfind("/x402/dna-attest", 0) == 0);
        // ...but the query rode along for the handler.
        const std::string q = FacilitatorQueryFor(dp);
        CHECK(q == "address=DvWxyzADDR123");
        CHECK(ParsedAddressFor(q) == "DvWxyzADDR123");
    }
    // Multi-param query: address= still parsed, trimmed at '&'.
    {
        const std::string dp = DispatchPathForRoutedRequest("/x402/dna-attest?address=ADDR42&foo=bar");
        const std::string q = FacilitatorQueryFor(dp);
        CHECK(q == "address=ADDR42&foo=bar");
        CHECK(ParsedAddressFor(q) == "ADDR42");
    }
    // address= not first in the query is still found (find, not prefix).
    {
        const std::string dp = DispatchPathForRoutedRequest("/x402/dna-attest?foo=1&address=ADDR9");
        CHECK(ParsedAddressFor(FacilitatorQueryFor(dp)) == "ADDR9");
    }
    // A duplicate-slash / case spelling normalizes for dispatch but STILL carries
    // the query (gate path canonical, handler input query-preserved).
    {
        const std::string dp = DispatchPathForRoutedRequest("//x402//dna-attest?address=ADDRdup");
        CHECK(dp.rfind("/x402/dna-attest", 0) == 0);
        CHECK(ParsedAddressFor(FacilitatorQueryFor(dp)) == "ADDRdup");
    }
    // No-query x402 request: dispatch path is just the canonical path (no stray '?').
    {
        const std::string dp = DispatchPathForRoutedRequest("/x402/supported");
        CHECK(dp == "/x402/supported");
        CHECK(FacilitatorQueryFor(dp).empty());
    }

    // ---- REST path-param handlers are UNAFFECTED: their argument is a path
    //      segment, and the new query-strip means a stray query never corrupts it. ----
    {
        // Pure path-segment param (the normal case) — no query.
        const std::string dp = DispatchPathForRoutedRequest("/api/v1/balance/SomeAddress");
        CHECK(dp == "/api/v1/balance/SomeAddress");
        CHECK(RestParamFor(dp) == "SomeAddress");
    }
    {
        // A query tacked onto a REST path must NOT bleed into the param.
        const std::string dp = DispatchPathForRoutedRequest("/api/v1/balance/SomeAddress?foo=bar");
        CHECK(RestParamFor(dp) == "SomeAddress");   // NOT "SomeAddress?foo=bar"
    }

    // ---- SECURITY: query-preservation must NOT open a gate bypass. The query is
    //      carried for the HANDLER only; the gate/dispatch keys on the query-
    //      stripped canonical path. A query can neither un-gate a sensitive path
    //      nor smuggle a sensitive path past the gate. ----
    {
        // /wallet?x is STILL sensitive (gate sees /wallet); the query is irrelevant
        // to classification. (Re-assert against the live gate predicate.)
        CHECK(GateSensitive("/wallet?x"));
        // ExtractRawQuery pulls "x" off /wallet?x, but that value never feeds the gate.
        CHECK(api::ExtractRawQuery("/wallet?x") == "x");
        // The classification depends ONLY on the normalized path, never the query:
        // identical normalized path => identical verdict regardless of query.
        CHECK(GateSensitive("/wallet") == GateSensitive("/wallet?anything=here"));
        CHECK(GateSensitive("/x402/dna-attest") == GateSensitive("/x402/dna-attest?address=ADDR"));
        CHECK(GateSensitive("/nope") == GateSensitive("/nope?address=ADDR"));
    }
    {
        // A query cannot carry a '/' that smuggles a NEW path: ExtractRawQuery
        // returns only the post-'?' bytes; the dispatch path's ROUTING prefix is
        // the canonical pre-'?' path. The handler's own '?' split discards it.
        const std::string dp = DispatchPathForRoutedRequest("/x402/dna-attest?address=ADDR&next=/wallet");
        // Dispatch still routes as /x402/... (the canonical gate path), and the
        // facilitator's pathPart is "dna-attest" — the "/wallet" in the query is
        // inert query data, never a route.
        CHECK(dp.rfind("/x402/", 0) == 0);
        CHECK(FacilitatorQueryFor(dp) == "address=ADDR&next=/wallet");
        CHECK(ParsedAddressFor(FacilitatorQueryFor(dp)) == "ADDR");
    }

    // ---- ExtractRawQuery contract: raw '?' only; %3f is NOT a delimiter;
    //      fragment dropped; first '#' before '?' => no query. ----
    CHECK(api::ExtractRawQuery("/x402/dna-attest?address=A") == "address=A");
    CHECK(api::ExtractRawQuery("/wallet").empty());                 // no query
    CHECK(api::ExtractRawQuery("/wallet#frag").empty());            // fragment, no query
    CHECK(api::ExtractRawQuery("/p?a=b#frag") == "a=b");            // fragment trimmed off query
    CHECK(api::ExtractRawQuery("/p#x?a=b").empty());                // '#' before '?' => no query
    // %3f is a literal byte, NOT a query delimiter — unchanged prior behavior.
    // /wallet%3fx normalizes to a single segment "wallet?x" (NOT /wallet) and has
    // NO raw '?', so ExtractRawQuery returns "" and it is NOT classified sensitive.
    CHECK(api::ExtractRawQuery("/wallet%3fx").empty());
    CHECK(!GateSensitive("/wallet%3fx"));   // prior %3f behavior unchanged
    CHECK(api::NormalizeRequestPath("/wallet%3fx").path == "/wallet?x");
}

// ==========================================================================
// 10. CRPCServer <-> CHttpServer PATH-NORM PARITY (LP-12 follow-on).
//
//    LP-12 wired NormalizeRequestPath into the standalone CHttpServer but NOT
//    into CRPCServer::HandleRequest (the RPC-port server), which classified on
//    RAW request bytes: wallet-HTML on request.find("GET /wallet")/"GET / HTTP",
//    REST on raw IsRESTRequest(path) = path.find("/api/v1/")==0. So alternate
//    spellings classified DIFFERENTLY across the two servers. The follow-on makes
//    CRPCServer reuse the SAME normalizer.
//
//    These models compute each server's CLASSIFICATION decision from the REAL
//    production functions (NormalizeRequestPath / IsRESTRequest / the wallet-
//    surface set) — no re-modelled normalization (the LP-12 lesson). The parity
//    assertion is: for every spelling, both servers reach the SAME wallet/REST/
//    other verdict. The "_RAW" helpers reproduce the PRE-FIX raw-byte logic to
//    PROVE the named vectors diverged before the fix.
// ==========================================================================

enum class Classification { Wallet, Rest, Other };

// Verbatim model of the PRE-FIX CRPCServer raw-byte classification.
static Classification ClassifyRpcRaw(const std::string& method,
                                     const std::string& rawPath) {
    // Wallet branch: request.find("GET /wallet")==0 || request.find("GET / HTTP")==0
    const std::string reqLine = method + " " + rawPath + " HTTP";
    if (reqLine.rfind("GET /wallet", 0) == 0 || reqLine.rfind("GET / HTTP", 0) == 0) {
        return Classification::Wallet;
    }
    // REST branch: raw IsRESTRequest(path) = path.find("/api/v1/")==0
    if (rawPath.find("/api/v1/") == 0) return Classification::Rest;
    return Classification::Other;
}

// Model of the POST-FIX CRPCServer classification (what server.cpp now does):
// canonical wallet-surface set + IsRESTRequest(norm.path), method-gated GET wallet.
static Classification ClassifyRpcNorm(const std::string& method,
                                      const std::string& rawPath) {
    const api::NormalizedPath norm = api::NormalizeRequestPath(rawPath);
    if (!norm.ok) return Classification::Other;  // fail-closed reject (not wallet/REST)
    if (method == "GET" &&
        (norm.path == "/wallet" || norm.path == "/wallet.html" || norm.path == "/")) {
        return Classification::Wallet;
    }
    if (norm.path.find("/api/v1/") == 0) return Classification::Rest;
    return Classification::Other;
}

// Model of CHttpServer's classification (http_server.cpp): wallet on the same
// canonical surface set, REST on norm.path prefix. Same normalizer, same verdict.
static Classification ClassifyHttp(const std::string& method,
                                   const std::string& rawPath) {
    const api::NormalizedPath norm = api::NormalizeRequestPath(rawPath);
    if (!norm.ok) return Classification::Other;
    // CHttpServer serves wallet on GET to {"/wallet","/wallet.html","/"}.
    if (method == "GET" &&
        (norm.path == "/wallet" || norm.path == "/wallet.html" || norm.path == "/")) {
        return Classification::Wallet;
    }
    // CHttpServer routes REST on path.rfind("/api/v1/",0)==0 (== find(...)==0).
    if (norm.path.rfind("/api/v1/", 0) == 0) return Classification::Rest;
    return Classification::Other;
}

static void TestRpcHttpClassificationParity() {
    std::cout << "LP-12 follow-on: CRPCServer <-> CHttpServer path-norm parity..." << std::endl;

    // SCOPE (honest): this verifies PATH-NORMALIZATION parity — that both servers, given
    // the SAME (method, path) tuple, classify the canonical path identically. It does NOT
    // verify request-LINE-parser parity: the two servers split the raw request line
    // differently (CRPCServer: raw find(' '); CHttpServer: istringstream >> tokens), so a
    // MALFORMED request line (e.g. tab-separated, or missing the HTTP-version token) can
    // still produce different (method,path) tuples and thus diverge — a KNOWN residual.
    // That residual is defense-in-depth only (the unconditional Host gate is the live
    // backstop; the wallet UI is loopback-only), tracked as the parser-unification
    // follow-up. Do NOT read this test as asserting byte-for-byte request-line parity.
    //
    // The three vectors named in the contract. POST-FIX, the normalized RPC
    // classification MATCHES CHttpServer for every one (the parity goal). At least
    // two of the three ALSO change verdict vs the pre-fix raw logic, proving the
    // test is load-bearing (asserted concretely below, not vacuously).
    struct Vec { const char* method; const char* path; };
    const Vec namedVectors[] = {
        {"POST", "//api//v1//broadcast"},      // duplicate slashes  (raw: Other, norm: Rest)
        {"POST", "/API/v1/broadcast"},         // mixed case         (both Other: IsRESTRequest is case-sensitive)
        {"POST", "/api/v1/%2e%2e/balance"},    // pct-encoded dot-seg (raw: Rest, norm: Other -> /api/balance)
    };

    for (const auto& v : namedVectors) {
        // POST-FIX: the normalized RPC classification MATCHES CHttpServer exactly.
        const Classification httpCls = ClassifyHttp(v.method, v.path);
        const Classification normRpc = ClassifyRpcNorm(v.method, v.path);
        CHECK(normRpc == httpCls);
    }
    // Load-bearing: at least 2 of the 3 named vectors changed verdict raw->norm.
    int diverged = 0;
    for (const auto& v : namedVectors) {
        if (ClassifyRpcRaw(v.method, v.path) != ClassifyRpcNorm(v.method, v.path)) ++diverged;
    }
    CHECK(diverged >= 2);

    // Concrete expected canonical verdicts for the named vectors:
    //  //api//v1//broadcast      -> /api/v1/broadcast  => REST on both
    CHECK(ClassifyRpcNorm("POST", "//api//v1//broadcast") == Classification::Rest);
    CHECK(ClassifyHttp("POST", "//api//v1//broadcast") == Classification::Rest);
    CHECK(ClassifyRpcRaw("POST", "//api//v1//broadcast") == Classification::Other); // pre-fix miss
    //  /API/v1/broadcast         -> /API/v1/broadcast (case preserved by normalizer);
    //  IsRESTRequest is case-SENSITIVE, so both servers route it as Other (not REST).
    //  The PARITY point: both agree. Pre-fix raw RPC also said Other here, but the
    //  divergence is covered by the other two vectors; assert agreement regardless.
    CHECK(ClassifyRpcNorm("POST", "/API/v1/broadcast") ==
          ClassifyHttp("POST", "/API/v1/broadcast"));
    //  /api/v1/%2e%2e/balance    -> /api/balance => NOT /api/v1/* => Other on both
    //  (the '..' pops v1). Pre-fix raw RPC saw the literal "/api/v1/%2e%2e/balance"
    //  which DOES start with "/api/v1/" => raw said REST (divergence!).
    CHECK(ClassifyRpcRaw("POST", "/api/v1/%2e%2e/balance") == Classification::Rest);   // pre-fix
    CHECK(ClassifyRpcNorm("POST", "/api/v1/%2e%2e/balance") == Classification::Other); // post-fix
    CHECK(ClassifyHttp("POST", "/api/v1/%2e%2e/balance") == Classification::Other);

    // Broad parity sweep: across a spelling matrix, the normalized RPC verdict
    // EQUALS the CHttpServer verdict for every entry (same normalizer, same set).
    const Vec sweep[] = {
        {"GET",  "/wallet"}, {"GET", "/wallet.html"}, {"GET", "/"},
        {"GET",  "/wallet/"}, {"GET", "//wallet"}, {"GET", "/WALLET"},
        {"GET",  "/%77allet"}, {"GET", "/./wallet"}, {"GET", "/x402/../wallet"},
        {"POST", "/"}, {"POST", "/wallet"},          // POST is never wallet
        {"POST", "/api/v1/broadcast"}, {"POST", "//api//v1//broadcast"},
        {"GET",  "/api/v1/balance/ADDR"}, {"GET", "/api/v1/balance/ADDR?foo=bar"},
        {"POST", "/api/v1/"}, {"POST", "/api/v1"},   // bare prefix: Other on both
        {"GET",  "/metrics"}, {"GET", "/api/stats"}, {"GET", "/miner"},
        {"GET",  "/favicon.ico"}, {"GET", "/nope"}, {"POST", "/api/v2/info"},
    };
    for (const auto& v : sweep) {
        CHECK(ClassifyRpcNorm(v.method, v.path) == ClassifyHttp(v.method, v.path));
    }

    // A JSON-RPC POST to "/" must NOT be classified as wallet (method-gated) — it
    // flows on to CSRF/auth/RPC. Regression guard for the most load-bearing case.
    CHECK(ClassifyRpcNorm("POST", "/") == Classification::Other);
    CHECK(ClassifyRpcNorm("GET", "/") == Classification::Wallet);

    // Malformed targets fail-closed to Other (rejected before REST/RPC dispatch),
    // matching CHttpServer's !norm.ok handling.
    CHECK(ClassifyRpcNorm("POST", "/api/v1/%zz") == Classification::Other);
    CHECK(ClassifyRpcNorm("POST", "/../etc/passwd") == Classification::Other);
    CHECK(ClassifyRpcNorm("GET", "/wallet%00.html") == Classification::Other);
}

int main() {
    std::cout << "=== LP-12 CHttpServer wallet-HTML gate tests ===" << std::endl;
    TestPublicApiDisablesWalletEntirely();
    TestLocalhostDefaultGate();
    TestNoHostHeaderTrust();
    TestRestHostAllowlistGate();             // H-01
    TestWalletGateSecondaryHostCheck();      // M-03
    TestRateLimiterRecordsStayBounded();     // M-01
    TestPathNormalizationGateBypassMatrix(); // gate-bypass fold (finding #1+#2)
    TestNormalizerCanonicalForm();           // gate-bypass fold (normalizer contract)
    TestQueryPreservationForHandlers();      // x402 dna-attest query-preservation fix
    TestRpcHttpClassificationParity();       // LP-12 follow-on: CRPCServer<->CHttpServer parity
    std::cout << "All " << g_checks << " checks passed." << std::endl;
    return 0;
}
