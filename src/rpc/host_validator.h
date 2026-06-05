// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_HOST_VALIDATOR_H
#define DILITHION_RPC_HOST_VALIDATOR_H

#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <vector>

// ----------------------------------------------------------------------------
// Anti-DNS-rebinding Host-header allowlist + same-origin session token.
//
// Both classes are intentionally dependency-free (only <string>/<set>/<mutex>/
// <vector>) so they can be unit-tested WITHOUT linking the full node (which
// needs depends/{libzmq,randomx,chiavdf}). server.cpp wires these into the
// HTTP request path; the security logic lives here as a single source of truth.
//
// SECURITY MODEL (mirrors geth --http.vhosts; see contract
// wallet-rpc-login-restore):
//   - The Host-header check is the FIRST gate in HandleRequest, strictly above
//     the wallet-HTML / OPTIONS / REST /api/v1/* branches. It blocks DNS
//     rebinding (Geth-2018 / Sia-2019 class fund-drain) before any other
//     processing.
//   - Default-deny: an absent/empty/duplicate/unknown Host is REJECTED.
//   - Exact host-token match after stripping the port — NOT substring search,
//     so localhost.evil.com / 127.0.0.1.evil.com / localhostX are all rejected.
// ----------------------------------------------------------------------------

namespace rpc {

/**
 * Host-header allowlist validator (anti-DNS-rebinding).
 *
 * Construct with the RPC port and the set of operator-configured extra hosts
 * (empty on a default/desktop node). Loopback names (127.0.0.1, ::1, localhost)
 * are ALWAYS allowed. Call ParseHostHeader() to extract+normalize the Host
 * from a raw HTTP request, then IsHostAllowed() / IsRequestHostAllowed().
 */
class HostValidator {
public:
    enum class ParseResult {
        Ok,            ///< exactly one well-formed Host header found
        Missing,       ///< no Host header present  -> default-deny REJECT
        Empty,         ///< Host header present but empty -> REJECT
        Duplicate,     ///< more than one Host header -> REJECT (smuggling)
        Malformed      ///< unparseable (e.g. unterminated IPv6 literal) -> REJECT
    };

    HostValidator() : m_port(0) {}

    /**
     * @param port              RPC port (used to accept "<host>:<port>" forms).
     * @param extraAllowedHosts Operator-configured extra hostnames/IPs
     *                          (lowercased, port-stripped). Loopback names are
     *                          added implicitly and need not be listed.
     */
    void Configure(uint16_t port, const std::vector<std::string>& extraAllowedHosts);

    /** Add a single allowed host at runtime (lowercased internally). */
    void AddAllowedHost(const std::string& host);

    /**
     * Extract the canonical host token (lowercased, port-stripped, IPv6
     * brackets removed) from a raw HTTP request string.
     *
     * Enforces: exactly one Host header (duplicate -> Duplicate), reads only
     * from the header section (stops at the blank line), case-insensitive
     * header-name match, trims surrounding whitespace, validates the port
     * matches the configured RPC port when a port is present.
     *
     * @param rawRequest Full raw HTTP request (request line + headers [+ body]).
     * @param hostOut    Output: canonical host token (only valid on Ok).
     * @param portMatched Output: true if a port was present AND matched m_port,
     *                    or no port was present (portless is acceptable).
     *                    false if a port was present but mismatched.
     * @return ParseResult
     */
    ParseResult ParseHostHeader(const std::string& rawRequest,
                                std::string& hostOut,
                                bool& portMatched) const;

    /**
     * True iff @p canonicalHost (already lowercased + port-stripped + IPv6
     * de-bracketed) is in the allowlist. Exact match only.
     */
    bool IsHostAllowed(const std::string& canonicalHost) const;

    /**
     * End-to-end check on a raw HTTP request: parse the Host header and confirm
     * it is allowed AND (if a port was present) the port matched. Any parse
     * failure (missing/empty/duplicate/malformed) returns false (default-deny).
     */
    bool IsRequestHostAllowed(const std::string& rawRequest) const;

    /**
     * True iff @p canonicalHost (already lowercased + port-stripped + IPv6
     * de-bracketed) is a LOOPBACK host — i.e. 127.0.0.1, ::1, or localhost.
     *
     * This is INDEPENDENT of the operator allowlist: even on a --public-api
     * seed that allowlists its own external IP / a DNS name for RPC+REST, those
     * non-loopback hosts are NOT loopback. Used to gate the token-minting
     * wallet-HTML serving so an admin-bearing page is never served to a remote
     * (but RPC-allowlisted) origin. (wallet-rpc-login-restore C-01.)
     */
    static bool IsLoopbackHost(const std::string& canonicalHost);

    /**
     * True iff @p ip is a LOOPBACK IP **literal** — i.e. an address in
     * 127.0.0.0/8, ::1, or an IPv4-mapped loopback (::ffff:127.x.x.x).
     *
     * CRITICAL — this is an IP-LITERAL classifier, NOT a Host-header parser. It
     * is meant to be fed the KERNEL-reported socket peer (getpeername /
     * GetClientIP), never a client-supplied Host header. The Host header is
     * attacker-controlled on a --public-api (all-interfaces) bind; the socket
     * peer is not. The token-minting wallet-HTML origin decision MUST rest on
     * this predicate applied to the real peer, never on IsLoopbackHost (which
     * trusts the header). The literal name "localhost" is deliberately NOT
     * accepted here — a peer address is always a numeric IP, never a name.
     * (wallet-rpc-login-restore C-01b.)
     */
    static bool IsLoopbackIP(const std::string& ip);

    /**
     * End-to-end LOOPBACK check on a raw HTTP request: parse the Host header and
     * confirm it is a loopback host (127.0.0.1 / ::1 / localhost) AND (if a port
     * was present) the port matched. Any parse failure returns false
     * (default-deny). This is the SSoT gate for serving the token-bearing wallet
     * HTML — it must pass REGARDLESS of --public-api / --rpcallowhost / the
     * general allowlist. (wallet-rpc-login-restore C-01.)
     */
    bool IsRequestLoopbackHost(const std::string& rawRequest) const;

    /** For diagnostics/tests: the current allowlist (lowercased). */
    std::set<std::string> AllowedHosts() const;

private:
    uint16_t m_port;
    std::set<std::string> m_allowed;  // lowercased canonical hosts
};

/**
 * Same-origin session token store.
 *
 * The node mints a token, embeds it in the served wallet HTML, and the wallet
 * uses it as its RPC credential. The token is a REAL credential: validated
 * server-side (constant-time) on every request. It is NOT the CSRF header
 * (which accepts any value) and does NOT bypass the auth gate — server.cpp maps
 * a valid token to the configured cookie credentials and runs them through the
 * existing RPCAuth + permissions path.
 *
 * Lifetime: tokens are bound to this process (the store is created per
 * CRPCServer instance) and expire after a TTL. A fresh token is minted on each
 * served wallet-HTML page load (rotation), and stale tokens are pruned. The
 * authoritative value lives ONLY here (SSoT) — the HTML carries a copy that is
 * validated back against this store.
 */
class SessionTokenStore {
public:
    // Default TTL: 1h (M-02, F-002). The token is a pure bearer credential not
    // bound to client IP/UA, so a shorter window bounds the blast radius of a
    // leaked token. Each wallet page load mints a fresh token (rotation), so an
    // active desktop session self-heals well within an hour; a reload re-mints.
    // (Previously 12h — shortened to reduce the leaked-token exposure window.)
    static constexpr int64_t kDefaultTtlSeconds = 60 * 60;
    // Bound the store so an attacker who can trigger page loads cannot grow it
    // without limit. Oldest entries are pruned first.
    static constexpr size_t kMaxTokens = 512;

    explicit SessionTokenStore(int64_t ttlSeconds = kDefaultTtlSeconds)
        : m_ttl(ttlSeconds) {}

    /**
     * Mint a fresh token from caller-supplied cryptographically-strong random
     * bytes (server.cpp passes GetStrongRandBytes output). The token is the
     * lowercase hex of @p randomBytes. Returns the hex token and records it.
     *
     * @param randomBytes >=16 bytes of CSPRNG output (32 recommended).
     * @param nowUnix      Current unix time (injected for testability).
     * @return hex token string, or "" if randomBytes too short.
     */
    std::string Mint(const std::vector<uint8_t>& randomBytes, int64_t nowUnix);

    /**
     * Validate a presented token in constant time against the live store and
     * confirm it has not expired. Expired/pruned tokens return false.
     */
    bool Validate(const std::string& token, int64_t nowUnix) const;

    /** Remove expired entries (called opportunistically). */
    void PruneExpired(int64_t nowUnix);

    /** Number of live (un-pruned) tokens — for tests. */
    size_t Size() const;

private:
    // Constant-time string compare (length-independent leak avoided by comparing
    // a fixed accumulator; mismatched lengths fail without early-return on content).
    static bool ConstantTimeEquals(const std::string& a, const std::string& b);

    mutable std::mutex m_mutex;
    int64_t m_ttl;
    struct Entry { std::string token; int64_t expiresAt; };
    std::vector<Entry> m_tokens;  // insertion-ordered; prune from front
};

} // namespace rpc

#endif // DILITHION_RPC_HOST_VALIDATOR_H
