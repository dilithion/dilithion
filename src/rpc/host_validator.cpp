// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/host_validator.h>

#include <algorithm>
#include <cctype>

namespace rpc {

// ---------------------------------------------------------------------------
// small helpers (file-local)
// ---------------------------------------------------------------------------

static std::string ToLower(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

static std::string Trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) b++;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) e--;
    return s.substr(b, e - b);
}

static bool IsAllDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) if (c < '0' || c > '9') return false;
    return true;
}

// Canonicalize an IPv6 numeric address (already de-bracketed, lowercased) so
// COMMON spellings of loopback collapse to "::1". Only the loopback forms listed
// below are canonicalized; any other IPv6 is returned lowercased unchanged (and
// will only match if explicitly allowlisted).
//
// L-01 (F-002): this is NOT an exhaustive IPv6 canonicalizer. Spellings NOT
// listed here (e.g. the hex IPv4-mapped form ::ffff:7f00:1, or other zero-run
// compressions) are returned unchanged and therefore REJECTED (fail-closed —
// over-restrictive, never over-permissive). That is safe: an un-canonicalized
// loopback spelling is denied, not allowed. We canonicalize the forms a browser
// actually emits as a same-origin Host (decimal ::1 / dotted IPv4-mapped).
static std::string CanonicalizeIPv6(const std::string& v6) {
    std::string s = v6;
    // Strip a zone id (%eth0) if present.
    size_t pct = s.find('%');
    if (pct != std::string::npos) s = s.substr(0, pct);

    // Fully-expanded loopback.
    if (s == "0:0:0:0:0:0:0:1") return "::1";
    // IPv4-mapped loopback (dotted form): ::ffff:127.0.0.1 and equivalents,
    // plus the hex-encoded IPv4-mapped loopback ::ffff:7f00:1 / 7f00:0001.
    if (s == "::ffff:127.0.0.1" || s == "0:0:0:0:0:ffff:127.0.0.1" ||
        s == "::ffff:7f00:1" || s == "::ffff:7f00:0001" ||
        s == "0:0:0:0:0:ffff:7f00:1" || s == "0:0:0:0:0:ffff:7f00:0001") {
        return "::1";
    }
    return s;
}

// ---------------------------------------------------------------------------
// HostValidator
// ---------------------------------------------------------------------------

void HostValidator::Configure(uint16_t port, const std::vector<std::string>& extraAllowedHosts) {
    m_port = port;
    m_allowed.clear();
    // Loopback names are ALWAYS allowed (default/desktop posture).
    m_allowed.insert("127.0.0.1");
    m_allowed.insert("::1");
    m_allowed.insert("localhost");
    for (const auto& h : extraAllowedHosts) {
        AddAllowedHost(h);
    }
}

void HostValidator::AddAllowedHost(const std::string& host) {
    std::string h = Trim(host);
    if (h.empty()) return;
    // Strip surrounding IPv6 brackets if present.
    if (h.size() >= 2 && h.front() == '[' && h.back() == ']') {
        h = h.substr(1, h.size() - 2);
    }
    h = ToLower(h);
    // If an operator passed host:port, strip the port for IPv4/hostnames.
    // (We do NOT strip ':' inside an IPv6 literal — but operator IPv6 entries
    //  should be passed bracketless and portless; document this.)
    if (h.find(':') != std::string::npos && h.find("::") == std::string::npos) {
        // Looks like host:port (single colon, not IPv6) -> drop the port part.
        size_t c = h.rfind(':');
        std::string maybePort = h.substr(c + 1);
        if (IsAllDigits(maybePort)) h = h.substr(0, c);
    }
    if (h.find(':') != std::string::npos) {
        h = CanonicalizeIPv6(h);
    }
    // Reject trailing-dot FQDN ambiguity by normalizing "localhost." -> "localhost".
    if (!h.empty() && h.back() == '.') h.pop_back();
    if (!h.empty()) m_allowed.insert(h);
}

std::set<std::string> HostValidator::AllowedHosts() const {
    return m_allowed;
}

bool HostValidator::IsHostAllowed(const std::string& canonicalHost) const {
    return m_allowed.find(canonicalHost) != m_allowed.end();
}

HostValidator::ParseResult HostValidator::ParseHostHeader(const std::string& rawRequest,
                                                          std::string& hostOut,
                                                          bool& portMatched) const {
    hostOut.clear();
    portMatched = true;  // portless is acceptable; only a present-but-wrong port flips this

    // Locate the end of the request line and the end of the header block.
    size_t lineEnd = rawRequest.find("\r\n");
    if (lineEnd == std::string::npos) {
        // No CRLF at all — also accept a bare-LF terminated request line for
        // robustness, but if there's no line terminator there are no headers.
        lineEnd = rawRequest.find('\n');
        if (lineEnd == std::string::npos) return ParseResult::Missing;
    }

    // Header section ends at the first blank line (CRLFCRLF or LFLF).
    size_t headerEnd = rawRequest.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        headerEnd = rawRequest.find("\n\n");
    }
    if (headerEnd == std::string::npos) headerEnd = rawRequest.size();

    // Walk header lines (only within [afterRequestLine, headerEnd)).
    size_t pos = lineEnd;
    // advance past the line terminator
    if (pos + 1 < rawRequest.size() && rawRequest[pos] == '\r' && rawRequest[pos + 1] == '\n') pos += 2;
    else if (pos < rawRequest.size() && rawRequest[pos] == '\n') pos += 1;

    int hostCount = 0;
    std::string rawValue;

    while (pos < headerEnd) {
        size_t eol = rawRequest.find('\n', pos);
        if (eol == std::string::npos || eol > headerEnd) eol = headerEnd;
        size_t lineLen = eol - pos;
        // strip a trailing '\r'
        if (lineLen > 0 && rawRequest[pos + lineLen - 1] == '\r') lineLen--;
        std::string line = rawRequest.substr(pos, lineLen);
        pos = eol + 1;

        if (line.empty()) break;  // end of headers (defensive)

        // Case-insensitive "host:" prefix match on the header NAME.
        // Header name is everything before the first ':'.
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = Trim(line.substr(0, colon));
        if (ToLower(name) != "host") continue;

        hostCount++;
        if (hostCount > 1) return ParseResult::Duplicate;  // smuggling defense
        rawValue = Trim(line.substr(colon + 1));
    }

    if (hostCount == 0) return ParseResult::Missing;   // default-deny
    if (rawValue.empty()) return ParseResult::Empty;   // default-deny

    // ---- Split host token from optional port. ----
    std::string host = rawValue;
    std::string portStr;

    if (!host.empty() && host.front() == '[') {
        // IPv6 literal: "[....]" optionally followed by ":port".
        size_t rb = host.find(']');
        if (rb == std::string::npos) return ParseResult::Malformed;  // unterminated
        std::string inner = host.substr(1, rb - 1);
        std::string rest = host.substr(rb + 1);
        if (!rest.empty()) {
            if (rest[0] != ':') return ParseResult::Malformed;
            portStr = rest.substr(1);
        }
        host = inner;
        host = ToLower(host);
        host = CanonicalizeIPv6(host);
    } else {
        // IPv4 or hostname. A single ':' separates host:port. Bare IPv6 without
        // brackets (multiple colons) is not a valid HTTP Host authority -> reject.
        size_t firstColon = host.find(':');
        size_t lastColon = host.rfind(':');
        if (firstColon != std::string::npos && firstColon != lastColon) {
            // multiple colons, no brackets -> malformed authority
            return ParseResult::Malformed;
        }
        if (firstColon != std::string::npos) {
            portStr = host.substr(firstColon + 1);
            host = host.substr(0, firstColon);
        }
        host = ToLower(host);
        // Normalize trailing-dot FQDN ("localhost." -> "localhost").
        if (!host.empty() && host.back() == '.') host.pop_back();
    }

    if (host.empty()) return ParseResult::Empty;

    // ---- Port validation. ----
    if (!portStr.empty()) {
        if (!IsAllDigits(portStr)) return ParseResult::Malformed;
        // Compare numerically against the configured RPC port.
        long p = 0;
        for (char c : portStr) {
            p = p * 10 + (c - '0');
            if (p > 65535) { p = -1; break; }
        }
        portMatched = (p == static_cast<long>(m_port));
    }

    hostOut = host;
    return ParseResult::Ok;
}

bool HostValidator::IsRequestHostAllowed(const std::string& rawRequest) const {
    std::string host;
    bool portMatched = false;
    ParseResult r = ParseHostHeader(rawRequest, host, portMatched);
    if (r != ParseResult::Ok) return false;     // default-deny on any parse failure
    if (!portMatched) return false;              // present-but-wrong port -> reject
    return IsHostAllowed(host);
}

// wallet-rpc-login-restore C-01: loopback predicate, independent of the operator
// allowlist. ParseHostHeader already canonicalizes the various loopback
// spellings ([::1], [0:0:0:0:0:0:0:1], ::ffff:127.0.0.1, localhost.) to one of
// these three tokens, so an exact compare here covers the bypass matrix.
bool HostValidator::IsLoopbackHost(const std::string& canonicalHost) {
    return canonicalHost == "127.0.0.1" ||
           canonicalHost == "::1" ||
           canonicalHost == "localhost";
}

bool HostValidator::IsRequestLoopbackHost(const std::string& rawRequest) const {
    std::string host;
    bool portMatched = false;
    ParseResult r = ParseHostHeader(rawRequest, host, portMatched);
    if (r != ParseResult::Ok) return false;     // default-deny on any parse failure
    if (!portMatched) return false;              // present-but-wrong port -> reject
    return IsLoopbackHost(host);
}

// wallet-rpc-login-restore C-01b: classify a SOCKET-PEER IP literal (from
// getpeername / GetClientIP) as loopback. Unlike IsLoopbackHost, this takes NO
// Host header and accepts NO names — only numeric IP literals. The peer address
// is kernel-reported and cannot be spoofed by a remote client, so it is the
// correct basis for the "is this request loopback-origin" decision on the
// token-minting wallet path. Default-deny: anything not recognised as loopback
// returns false (including "unknown" from a failed getpeername).
//
// Accepted forms:
//   - 127.0.0.0/8        : any 127.x.x.x (the whole loopback /8, not just .1)
//   - ::1                : IPv6 loopback (canonical and fully-expanded spellings)
//   - ::ffff:127.x.x.x   : IPv4-mapped loopback in textual form (defense in depth;
//                          GetClientIP already unwraps these to dotted 127.x, but
//                          accept the literal form too so the classifier is correct
//                          regardless of the caller's unwrapping behaviour)
bool HostValidator::IsLoopbackIP(const std::string& ip) {
    if (ip.empty()) return false;
    std::string s = ToLower(Trim(ip));
    // Strip surrounding IPv6 brackets if a caller passed them.
    if (s.size() >= 2 && s.front() == '[' && s.back() == ']') {
        s = s.substr(1, s.size() - 2);
    }
    // Strip an IPv6 zone id (%eth0) if present.
    size_t pct = s.find('%');
    if (pct != std::string::npos) s = s.substr(0, pct);
    if (s.empty()) return false;

    // IPv6 loopback (canonical + fully-expanded). CanonicalizeIPv6 also collapses
    // the IPv4-mapped-loopback spellings (::ffff:127.0.0.1, ::ffff:7f00:1, ...) to
    // "::1", so this single compare covers those literal forms too.
    if (s.find(':') != std::string::npos) {
        std::string canon = CanonicalizeIPv6(s);
        if (canon == "::1") return true;
        // IPv4-mapped loopback for the general 127.x range (e.g. ::ffff:127.1.2.3)
        // that CanonicalizeIPv6 does not enumerate: peel the mapped IPv4 tail.
        const std::string mapped = "::ffff:";
        if (s.compare(0, mapped.size(), mapped) == 0) {
            std::string tail = s.substr(mapped.size());
            // Only treat as loopback if the tail is a dotted-quad in 127.0.0.0/8.
            if (tail.find('.') != std::string::npos) return IsLoopbackIP(tail);
        }
        return false;
    }

    // IPv4 dotted-quad: loopback is the entire 127.0.0.0/8 block.
    // Parse the first octet and require it to be exactly 127, with a well-formed
    // 4-octet a.b.c.d shape (each octet 0..255). Default-deny on any malformation.
    int octets[4] = {0, 0, 0, 0};
    int idx = 0;
    size_t i = 0;
    while (i < s.size()) {
        if (idx >= 4) return false;            // too many octets
        size_t start = i;
        int val = 0;
        size_t digits = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            val = val * 10 + (s[i] - '0');
            if (val > 255) return false;        // octet out of range
            ++i; ++digits;
        }
        if (digits == 0 || digits > 3) return false;  // empty/oversized octet
        (void)start;
        octets[idx++] = val;
        if (i < s.size()) {
            if (s[i] != '.') return false;      // unexpected char
            ++i;                                 // consume '.'
            if (i == s.size()) return false;     // trailing dot
        }
    }
    if (idx != 4) return false;                 // not exactly 4 octets
    return octets[0] == 127;                    // 127.0.0.0/8
}

// ---------------------------------------------------------------------------
// SessionTokenStore
// ---------------------------------------------------------------------------

std::string SessionTokenStore::Mint(const std::vector<uint8_t>& randomBytes, int64_t nowUnix) {
    if (randomBytes.size() < 16) return std::string();
    static const char* hexd = "0123456789abcdef";
    std::string token;
    token.reserve(randomBytes.size() * 2);
    for (uint8_t b : randomBytes) {
        token.push_back(hexd[(b >> 4) & 0xF]);
        token.push_back(hexd[b & 0xF]);
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    // Opportunistic prune of expired entries.
    {
        std::vector<Entry> live;
        live.reserve(m_tokens.size());
        for (auto& e : m_tokens) if (e.expiresAt > nowUnix) live.push_back(e);
        m_tokens.swap(live);
    }
    // Bound the store: drop oldest if at capacity.
    if (m_tokens.size() >= kMaxTokens) {
        m_tokens.erase(m_tokens.begin(),
                       m_tokens.begin() + (m_tokens.size() - kMaxTokens + 1));
    }
    m_tokens.push_back(Entry{token, nowUnix + m_ttl});
    return token;
}

bool SessionTokenStore::Validate(const std::string& token, int64_t nowUnix) const {
    if (token.empty()) return false;
    std::lock_guard<std::mutex> lock(m_mutex);
    bool ok = false;
    // Walk ALL entries (no early return) so timing does not leak which token,
    // if any, matched. ConstantTimeEquals handles per-token constant time.
    for (const auto& e : m_tokens) {
        if (e.expiresAt > nowUnix && ConstantTimeEquals(e.token, token)) {
            ok = true;
        }
    }
    return ok;
}

void SessionTokenStore::PruneExpired(int64_t nowUnix) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<Entry> live;
    live.reserve(m_tokens.size());
    for (auto& e : m_tokens) if (e.expiresAt > nowUnix) live.push_back(e);
    m_tokens.swap(live);
}

size_t SessionTokenStore::Size() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tokens.size();
}

bool SessionTokenStore::ConstantTimeEquals(const std::string& a, const std::string& b) {
    // Length mismatch is itself a non-match. Compare against the longer length
    // so the loop count does not depend on where the first differing byte is.
    size_t n = std::max(a.size(), b.size());
    unsigned char diff = static_cast<unsigned char>(a.size() ^ b.size());
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
        unsigned char cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
        diff |= static_cast<unsigned char>(ca ^ cb);
    }
    return diff == 0;
}

} // namespace rpc
