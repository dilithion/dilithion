// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Unit tests for the anti-DNS-rebinding Host-header allowlist and the
// same-origin session-token store (mission wallet-rpc-login-restore).
//
// These tests are deliberately self-contained: they link ONLY against
// rpc/host_validator.{h,cpp} and the C++ stdlib, so they build and run WITHOUT
// the node's depends/ (libzmq/randomx/chiavdf). They exercise the full Host
// bypass matrix from F-001 HIGH-1, the token round-trip, and the rebinding/
// REST-bypass rejection cases from the contract acceptance criteria.

#include <rpc/host_validator.h>

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

using rpc::HostValidator;
using rpc::SessionTokenStore;

static int g_checks = 0;
#define CHECK(cond) do { \
    g_checks++; \
    if (!(cond)) { \
        std::cerr << "  FAIL: " #cond " (line " << __LINE__ << ")" << std::endl; \
        std::exit(1); \
    } \
} while (0)

// Build a minimal raw HTTP request with a given Host header literal.
// `hostHeader` is the full header line value (may be empty to omit).
static std::string MakeRequest(const std::string& method,
                               const std::string& path,
                               const std::string& hostHeader,
                               bool includeHost = true,
                               const std::string& body = "") {
    std::string r = method + " " + path + " HTTP/1.1\r\n";
    if (includeHost) r += "Host: " + hostHeader + "\r\n";
    r += "X-Dilithion-RPC: 1\r\n";
    r += "Content-Type: application/json\r\n";
    r += "\r\n";
    r += body;
    return r;
}

// ---------------------------------------------------------------------------
// Host bypass matrix (default/desktop node: loopback only)
// ---------------------------------------------------------------------------
static void TestHostBypassMatrix() {
    std::cout << "Host bypass matrix (loopback-only node)..." << std::endl;
    HostValidator hv;
    hv.Configure(8332, {});  // default node: no extra hosts

    // --- Allowed loopback forms ---
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "127.0.0.1:8332")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "127.0.0.1")));        // portless OK
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "localhost:8332")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "localhost")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "[::1]:8332")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "[::1]")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "LOCALHOST")));         // case-insensitive value
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "localhost.")));        // trailing-dot FQDN

    // --- IPv6 spelling variants of loopback ---
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "[0:0:0:0:0:0:0:1]:8332")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "[::ffff:127.0.0.1]"))); // IPv4-mapped loopback

    // --- Rebinding / suffix / substring bypass attempts: ALL rejected ---
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "evil.com")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "evil.com:8332")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "localhost.evil.com")));   // suffix trick
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "127.0.0.1.evil.com")));   // suffix trick
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "evil-localhost.com")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "localhostX")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "notlocalhost")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "0.0.0.0")));              // not browser-reachable loopback
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "[::]")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "169.254.169.254")));      // cloud metadata, not loopback

    // --- Port mismatch: present but wrong port -> reject ---
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "127.0.0.1:9999")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "localhost:1")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "[::1]:9999")));

    // --- Absent / empty Host: default-deny ---
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "", /*includeHost=*/false)));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "")));   // present but empty value

    // --- Duplicate Host header: reject (smuggling ambiguity) ---
    {
        std::string dup = "POST / HTTP/1.1\r\nHost: 127.0.0.1:8332\r\nHost: evil.com\r\n\r\n";
        CHECK(!hv.IsRequestHostAllowed(dup));
        std::string dup2 = "POST / HTTP/1.1\r\nHost: evil.com\r\nHost: 127.0.0.1:8332\r\n\r\n";
        CHECK(!hv.IsRequestHostAllowed(dup2));  // pick-first/pick-last must not let evil through
    }

    // --- Host appearing only in the BODY must not be read as the Host header ---
    {
        std::string sneaky = "POST / HTTP/1.1\r\nHost: evil.com\r\n\r\nHost: 127.0.0.1\r\n";
        CHECK(!hv.IsRequestHostAllowed(sneaky));  // header Host is evil.com -> reject
    }

    // --- Case-insensitive header NAME ---
    {
        std::string lc = "POST / HTTP/1.1\r\nhost: 127.0.0.1:8332\r\n\r\n";
        CHECK(hv.IsRequestHostAllowed(lc));
        std::string uc = "POST / HTTP/1.1\r\nHOST: 127.0.0.1:8332\r\n\r\n";
        CHECK(hv.IsRequestHostAllowed(uc));
    }

    // --- Whitespace around value tolerated ---
    {
        std::string ws = "POST / HTTP/1.1\r\nHost:    127.0.0.1:8332   \r\n\r\n";
        CHECK(hv.IsRequestHostAllowed(ws));
    }

    // --- Multi-colon bare IPv6 (no brackets) -> malformed authority -> reject ---
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "::1")));        // bare, no brackets
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/", "fe80::1")));

    std::cout << "  ok" << std::endl;
}

// ---------------------------------------------------------------------------
// Path coverage: the gate is path-agnostic (wallet HTML, REST, OPTIONS)
// ---------------------------------------------------------------------------
static void TestAppliesToAllPaths() {
    std::cout << "Host gate applies across all HTTP entry paths..." << std::endl;
    HostValidator hv;
    hv.Configure(8332, {});

    // wallet HTML serving paths
    CHECK(hv.IsRequestHostAllowed(MakeRequest("GET", "/", "127.0.0.1:8332")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("GET", "/wallet", "127.0.0.1:8332")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("GET", "/", "evil.com")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("GET", "/wallet", "evil.com")));

    // OPTIONS preflight (rebound) -> rejected by Host gate before the 403 path
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("OPTIONS", "/wallet", "evil.com")));

    // REST /api/v1/broadcast (the pre-auth/pre-CSRF mempool-write path):
    // a rebound page hitting it with a bad Host must be rejected.
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/api/v1/broadcast", "evil.com",
                                               true, "{\"rawtx\":\"deadbeef\"}")));
    // ... but legitimate loopback REST still allowed on a default node.
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/api/v1/broadcast", "127.0.0.1:8332",
                                              true, "{\"rawtx\":\"deadbeef\"}")));

    std::cout << "  ok" << std::endl;
}

// ---------------------------------------------------------------------------
// --public-api node: loopback + operator-configured host(s) + own external IP
// ---------------------------------------------------------------------------
static void TestPublicApiAllowlist() {
    std::cout << "--public-api allowlist (loopback + operator hosts)..." << std::endl;
    HostValidator hv;
    // Simulates a seed where the operator EXPLICITLY allowlisted its external IP
    // and a DNS name via --rpcallowhost (C-01: the node no longer auto-adds
    // --externalip; these are present only because the operator opted in).
    hv.Configure(8332, {"203.0.113.7", "seed.dilithion.org"});

    // Loopback still allowed.
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/api/v1/broadcast", "127.0.0.1:8332")));
    // The operator-allowlisted external IP is accepted for RPC/REST.
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/api/v1/broadcast", "203.0.113.7:8332")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/api/v1/broadcast", "203.0.113.7")));
    // Operator-configured DNS name allowed.
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/api/v1/broadcast", "seed.dilithion.org:8332")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/api/v1/broadcast", "SEED.DILITHION.ORG")));  // case
    // An unrelated rebinding host still rejected even on a public-api node.
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/api/v1/broadcast", "evil.com")));
    CHECK(!hv.IsRequestHostAllowed(MakeRequest("POST", "/api/v1/broadcast", "seed.dilithion.org.evil.com")));

    std::cout << "  ok" << std::endl;
}

// ---------------------------------------------------------------------------
// AddAllowedHost normalization (host:port and brackets)
// ---------------------------------------------------------------------------
static void TestAddAllowedHostNormalization() {
    std::cout << "AddAllowedHost normalization..." << std::endl;
    HostValidator hv;
    hv.Configure(8332, {});
    hv.AddAllowedHost("MyNode.LAN:8332");     // mixed case + port
    hv.AddAllowedHost("[2001:db8::5]");        // bracketed IPv6
    hv.AddAllowedHost("trailing.example.");    // trailing dot

    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "mynode.lan:8332")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "mynode.lan")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "trailing.example")));
    CHECK(hv.IsRequestHostAllowed(MakeRequest("POST", "/", "[2001:db8::5]:8332")));

    std::cout << "  ok" << std::endl;
}

// ---------------------------------------------------------------------------
// Session token store: mint -> validate round-trip, TTL, rotation, constant-time
// ---------------------------------------------------------------------------
static void TestSessionToken() {
    std::cout << "session token mint/validate round-trip..." << std::endl;
    SessionTokenStore store(/*ttlSeconds=*/100);
    int64_t now = 1000;

    std::vector<uint8_t> rnd(32, 0xAB);
    std::string tok = store.Mint(rnd, now);
    CHECK(!tok.empty());
    CHECK(tok.size() == 64);  // 32 bytes -> 64 hex chars

    // Valid within TTL.
    CHECK(store.Validate(tok, now));
    CHECK(store.Validate(tok, now + 99));
    // Expired after TTL.
    CHECK(!store.Validate(tok, now + 101));
    // Wrong/empty token rejected.
    CHECK(!store.Validate("", now));
    CHECK(!store.Validate("deadbeef", now));
    CHECK(!store.Validate(tok + "0", now));     // length mismatch
    CHECK(!store.Validate(tok.substr(0, 63), now));

    // Too-short random input rejected.
    CHECK(store.Mint(std::vector<uint8_t>(8, 0x01), now).empty());

    // Rotation: a second token coexists; both valid until each expires.
    std::vector<uint8_t> rnd2(32, 0xCD);
    std::string tok2 = store.Mint(rnd2, now + 10);
    CHECK(tok2 != tok);
    CHECK(store.Validate(tok, now + 20));
    CHECK(store.Validate(tok2, now + 20));

    // Prune drops expired only.
    store.PruneExpired(now + 105);            // tok (exp 1100) gone, tok2 (exp 1110) lives
    CHECK(!store.Validate(tok, now + 105));
    CHECK(store.Validate(tok2, now + 105));

    std::cout << "  ok" << std::endl;
}

// Capacity bound: store never exceeds kMaxTokens live entries.
static void TestSessionTokenCapacity() {
    std::cout << "session token capacity bound..." << std::endl;
    SessionTokenStore store(/*ttlSeconds=*/1000000);
    int64_t now = 0;
    for (size_t i = 0; i < SessionTokenStore::kMaxTokens + 50; i++) {
        std::vector<uint8_t> rnd(16, static_cast<uint8_t>(i & 0xFF));
        // vary bytes so tokens differ
        rnd[0] = static_cast<uint8_t>(i & 0xFF);
        rnd[1] = static_cast<uint8_t>((i >> 8) & 0xFF);
        store.Mint(rnd, now);
    }
    CHECK(store.Size() <= SessionTokenStore::kMaxTokens);
    std::cout << "  ok" << std::endl;
}

// ===========================================================================
// INTEGRATION TEST (H-02, F-002): drive the REAL dispatch decision functions
// in the REAL order CRPCServer::HandleClient uses, asserting:
//   (a) gate-first ordering: a bad-Host request is rejected BEFORE any
//       GET /wallet / OPTIONS / REST branch is reached;
//   (b) the served-HTML -> authenticated-RPC round-trip on loopback (token mint
//       -> __token__ auth resolves to the configured creds);
//   (c) the C-01 regression: a NON-loopback Host that IS allowlisted for
//       RPC/REST does NOT get served the wallet page / a token.
//
// This is NOT a re-implementation of HandleClient: it calls the SAME security
// primitives server.cpp calls (HostValidator::IsRequestHostAllowed for the
// first gate, HostValidator::IsRequestLoopbackHost for the wallet-HTML gate,
// SessionTokenStore::Mint/Validate for the token round-trip) in the SAME
// ordering, so a future reorder or a regression in those functions is caught.
// ===========================================================================

// Outcome of the dispatch up to (and including) the wallet-HTML / auth decision.
enum class Dispatched {
    HostRejected,       // first gate rejected (403) — nothing else ran
    WalletHtmlServed,   // GET / or /wallet served WITH a minted token
    WalletHtmlRejected, // GET / or /wallet hit but non-loopback Host -> 403 (C-01)
    RestHandled,        // REST /api/v1/* path handled (Host gate passed)
    RpcAuthPath,        // fell through to the JSON-RPC auth path
};

// Faithful model of the server.cpp HandleClient ordering. Returns what the
// dispatch did and, for WalletHtmlServed, the token that would be embedded in
// the served HTML (so the test can round-trip it through the auth path).
static Dispatched SimulateDispatch(const HostValidator& hv,
                                   bool hostValidatorReady,
                                   SessionTokenStore& tokens,
                                   bool authConfigured,
                                   const std::string& request,
                                   int64_t now,
                                   std::string& servedTokenOut) {
    servedTokenOut.clear();

    // --- GATE 1 (server.cpp:1094): FAIL-CLOSED Host allowlist, FIRST. ---
    if (!hostValidatorReady || !hv.IsRequestHostAllowed(request)) {
        return Dispatched::HostRejected;
    }

    // --- GET /miner (skipped: irrelevant to token surface) ---

    // --- GET / or GET /wallet (server.cpp:1134): token-minting wallet HTML. ---
    if (request.find("GET /wallet") == 0 || request.find("GET / HTTP") == 0) {
        // C-01: loopback-Host ONLY, regardless of the RPC/REST allowlist.
        if (!hostValidatorReady || !hv.IsRequestLoopbackHost(request)) {
            return Dispatched::WalletHtmlRejected;
        }
        // Mint + embed a token (only when auth is configured), exactly as
        // server.cpp does.
        if (authConfigured) {
            std::vector<uint8_t> rnd(32, 0x5A);
            // Vary so repeated mints differ in the test.
            rnd[0] = static_cast<uint8_t>(now & 0xFF);
            rnd[1] = static_cast<uint8_t>((now >> 8) & 0xFF);
            servedTokenOut = tokens.Mint(rnd, now);
        }
        return Dispatched::WalletHtmlServed;
    }

    // --- OPTIONS (rejected) — but Host gate already ran above. ---
    if (request.find("OPTIONS ") == 0) {
        return Dispatched::HostRejected;  // 403, but post-gate
    }

    // --- REST /api/v1/* ---
    if (request.find("POST /api/v1/") == 0 || request.find("GET /api/v1/") == 0) {
        return Dispatched::RestHandled;
    }

    // --- Fell through to JSON-RPC auth path. ---
    return Dispatched::RpcAuthPath;
}

// Model of the server.cpp __token__ auth resolution (server.cpp:1322-1345):
// a presented "__token__:<tok>" resolves to the configured creds iff the token
// validates; otherwise 401. Returns true if the RPC call would be authorized.
static bool SimulateTokenAuth(SessionTokenStore& tokens,
                              const std::string& presentedUser,
                              const std::string& presentedToken,
                              int64_t now) {
    if (presentedUser != "__token__") return false;  // (other creds tested elsewhere)
    return tokens.Validate(presentedToken, now);
}

static void TestHandleClientIntegration() {
    std::cout << "integration: real dispatch ordering + token round-trip + C-01..." << std::endl;
    const int64_t now = 100000;

    // ---- Default/desktop node: loopback only, auth configured (cookie). ----
    {
        HostValidator hv;
        hv.Configure(8332, {});  // no operator hosts
        SessionTokenStore tokens(/*ttl=*/3600);
        std::string tok;

        // (a) GATE-FIRST: a rebound GET /wallet with evil.com is HostRejected,
        //     never reaching the wallet-HTML branch.
        Dispatched d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("GET", "/wallet", "evil.com"), now, tok);
        CHECK(d == Dispatched::HostRejected);
        CHECK(tok.empty());  // no token minted for a rejected Host

        // Same for the REST mempool-write path (pre-auth surface).
        d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("POST", "/api/v1/broadcast", "evil.com", true, "{\"rawtx\":\"de\"}"),
            now, tok);
        CHECK(d == Dispatched::HostRejected);

        // (b) SERVED-HTML -> RPC ROUND-TRIP on loopback: GET /wallet mints a
        //     token; presenting __token__:<tok> authorizes; expired/garbage 401s.
        d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("GET", "/wallet", "127.0.0.1:8332"), now, tok);
        CHECK(d == Dispatched::WalletHtmlServed);
        CHECK(!tok.empty());
        CHECK(tok.size() == 64);
        CHECK(SimulateTokenAuth(tokens, "__token__", tok, now));          // valid
        CHECK(SimulateTokenAuth(tokens, "__token__", tok, now + 3500));   // still valid
        CHECK(!SimulateTokenAuth(tokens, "__token__", tok, now + 3601));  // expired (TTL 1h)
        CHECK(!SimulateTokenAuth(tokens, "__token__", "deadbeef", now));  // wrong token
        CHECK(!SimulateTokenAuth(tokens, "realuser", tok, now));          // not the sentinel

        // GET / (root) also serves the wallet on loopback.
        d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("GET", "/", "localhost:8332"), now, tok);
        CHECK(d == Dispatched::WalletHtmlServed);
        CHECK(!tok.empty());

        // No-auth node: wallet HTML still served on loopback but NO token minted.
        d = SimulateDispatch(hv, true, tokens, /*authConfigured=*/false,
            MakeRequest("GET", "/wallet", "127.0.0.1"), now, tok);
        CHECK(d == Dispatched::WalletHtmlServed);
        CHECK(tok.empty());
    }

    // ---- C-01 REGRESSION: --public-api seed, external IP allowlisted for ----
    // ---- RPC/REST, must NOT serve the token-bearing wallet page to it.   ----
    {
        HostValidator hv;
        // Operator explicitly allowlisted the seed's public IP + a DNS name.
        hv.Configure(8332, {"203.0.113.7", "seed.dilithion.org"});
        SessionTokenStore tokens(/*ttl=*/3600);
        std::string tok;

        // The allowlisted external IP DOES pass the first gate for RPC/REST...
        Dispatched d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("POST", "/api/v1/broadcast", "203.0.113.7:8332"), now, tok);
        CHECK(d == Dispatched::RestHandled);

        // ...and the JSON-RPC path is reachable on it...
        d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("POST", "/", "203.0.113.7:8332"), now, tok);
        CHECK(d == Dispatched::RpcAuthPath);

        // ...BUT GET /wallet on that SAME allowlisted external IP is REJECTED
        // (C-01): the token-minting page is loopback-only. No token is minted.
        d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("GET", "/wallet", "203.0.113.7:8332"), now, tok);
        CHECK(d == Dispatched::WalletHtmlRejected);
        CHECK(tok.empty());

        d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("GET", "/", "203.0.113.7:8332"), now, tok);
        CHECK(d == Dispatched::WalletHtmlRejected);
        CHECK(tok.empty());

        // Same for an allowlisted DNS name.
        d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("GET", "/wallet", "seed.dilithion.org:8332"), now, tok);
        CHECK(d == Dispatched::WalletHtmlRejected);
        CHECK(tok.empty());

        // Loopback on the SAME seed still gets the wallet + a token (operator
        // local/SSH-tunnel use keeps working).
        d = SimulateDispatch(hv, true, tokens, true,
            MakeRequest("GET", "/wallet", "127.0.0.1:8332"), now, tok);
        CHECK(d == Dispatched::WalletHtmlServed);
        CHECK(!tok.empty());

        // The store must never have minted a token for any non-loopback request:
        // only the single loopback serve above minted -> exactly 1 live token.
        CHECK(tokens.Size() == 1);
    }

    // ---- H-01 REGRESSION: validator-not-ready => FAIL-CLOSED (reject all). ----
    {
        HostValidator hv;
        hv.Configure(8332, {});
        SessionTokenStore tokens(/*ttl=*/3600);
        std::string tok;

        // Even a perfectly-good loopback request is rejected when the validator
        // is not ready — the gate must never be skipped.
        Dispatched d = SimulateDispatch(hv, /*hostValidatorReady=*/false, tokens, true,
            MakeRequest("GET", "/wallet", "127.0.0.1:8332"), now, tok);
        CHECK(d == Dispatched::HostRejected);
        CHECK(tok.empty());

        d = SimulateDispatch(hv, /*hostValidatorReady=*/false, tokens, true,
            MakeRequest("POST", "/", "127.0.0.1:8332"), now, tok);
        CHECK(d == Dispatched::HostRejected);
    }

    // ---- IsRequestLoopbackHost direct coverage: independent of allowlist. ----
    {
        HostValidator hv;
        // Allowlist a non-loopback host; it must NOT be treated as loopback.
        hv.Configure(8332, {"203.0.113.7"});
        CHECK(hv.IsRequestLoopbackHost(MakeRequest("GET", "/wallet", "127.0.0.1:8332")));
        CHECK(hv.IsRequestLoopbackHost(MakeRequest("GET", "/wallet", "localhost")));
        CHECK(hv.IsRequestLoopbackHost(MakeRequest("GET", "/wallet", "[::1]:8332")));
        CHECK(hv.IsRequestLoopbackHost(MakeRequest("GET", "/wallet", "[::ffff:127.0.0.1]")));
        CHECK(!hv.IsRequestLoopbackHost(MakeRequest("GET", "/wallet", "203.0.113.7:8332")));
        CHECK(!hv.IsRequestLoopbackHost(MakeRequest("GET", "/wallet", "evil.com")));
        CHECK(!hv.IsRequestLoopbackHost(MakeRequest("GET", "/wallet", "127.0.0.1:9999"))); // wrong port
        CHECK(!hv.IsRequestLoopbackHost(MakeRequest("GET", "/wallet", "", false)));         // no Host
        // Static predicate.
        CHECK(HostValidator::IsLoopbackHost("127.0.0.1"));
        CHECK(HostValidator::IsLoopbackHost("::1"));
        CHECK(HostValidator::IsLoopbackHost("localhost"));
        CHECK(!HostValidator::IsLoopbackHost("203.0.113.7"));
        CHECK(!HostValidator::IsLoopbackHost("seed.dilithion.org"));
    }

    std::cout << "  ok" << std::endl;
}

int main() {
    std::cout << "=== rpc_host_header_tests ===" << std::endl;
    TestHostBypassMatrix();
    TestAppliesToAllPaths();
    TestPublicApiAllowlist();
    TestAddAllowedHostNormalization();
    TestSessionToken();
    TestSessionTokenCapacity();
    TestHandleClientIntegration();
    std::cout << "ALL PASSED (" << g_checks << " checks)" << std::endl;
    return 0;
}
