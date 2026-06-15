// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <api/http_path_gate.h>

#include <cctype>
#include <vector>

namespace api {

namespace {

// Lowercase ASCII only (paths are ASCII; we never case-fold above 0x7f).
char LowerAscii(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

// Decode a single hex nibble; -1 on non-hex.
int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Percent-decode `in` into `out`. Returns false on a malformed escape (a '%'
// not followed by two hex digits) — fail-closed: the caller treats this as a
// non-normalizable (therefore sensitive) path.
//
// We decode %XX into its raw byte UNCONDITIONALLY (including an encoded '/',
// %2f, and an encoded '.', %2e). That is the whole point: an attacker who hides
// a slash or a dot-segment behind percent-encoding (e.g. /api/v1/%2e%2e/x402/)
// must be normalized into the same canonical form as the literal spelling so
// the gate sees through the disguise. Re-encoding ambiguity does not apply here
// because the normalized path is used only for the gate decision and for the
// server's own case-sensitive routing, never re-emitted to another parser.
bool PercentDecode(const std::string& in, std::string& out) {
    out.clear();
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '%') {
            if (i + 2 >= in.size()) return false;       // truncated escape
            int hi = HexVal(in[i + 1]);
            int lo = HexVal(in[i + 2]);
            if (hi < 0 || lo < 0) return false;          // non-hex escape
            out.push_back(static_cast<char>((hi << 4) | lo));
            i += 2;
        } else {
            out.push_back(c);
        }
    }
    return true;
}

} // namespace

NormalizedPath NormalizeRequestPath(const std::string& rawPath) {
    NormalizedPath result;

    // 1. Strip query string and fragment. The gate is about the path only; a
    //    `?`/`#` must never let a sensitive path slip through (the original bug:
    //    `/wallet?x` != `/wallet`).
    std::string p = rawPath;
    size_t cut = p.find_first_of("?#");
    if (cut != std::string::npos) p = p.substr(0, cut);

    // 2. Percent-decode (fail-closed on a malformed escape).
    std::string decoded;
    if (!PercentDecode(p, decoded)) {
        result.ok = false;
        return result;
    }
    p = decoded;

    // 3. A reject for a NUL byte injected via %00 — a normalized path must not
    //    contain one (truncation / smuggling defense). Fail-closed.
    if (p.find('\0') != std::string::npos) {
        result.ok = false;
        return result;
    }

    // 4. Treat an empty or non-absolute target conservatively. A request target
    //    that does not begin with '/' (e.g. "*", or an absolute-form URI) is not
    //    a path we route; normalize to "/" is wrong (would look like root, a
    //    sensitive surface) — but returning ok with a leading '/' added keeps it
    //    classifiable. Prepend '/' so segment logic below is uniform; the gate
    //    will then evaluate it like any other path.
    if (p.empty() || p.front() != '/') {
        p.insert(p.begin(), '/');
    }

    // 5. Split on '/', collapsing duplicate slashes, and resolve '.'/'..'.
    //    A '..' that would pop above root is a traversal attempt -> fail-closed.
    std::vector<std::string> segs;
    size_t i = 0;
    const size_t n = p.size();
    while (i < n) {
        // p[i] is '/' at the start of each iteration boundary; skip run of '/'.
        while (i < n && p[i] == '/') ++i;
        if (i >= n) break;
        size_t start = i;
        while (i < n && p[i] != '/') ++i;
        std::string seg = p.substr(start, i - start);
        if (seg == ".") {
            // current-dir: drop.
        } else if (seg == "..") {
            if (segs.empty()) {
                // Traversal above root — reject (fail-closed).
                result.ok = false;
                return result;
            }
            segs.pop_back();
        } else {
            segs.push_back(seg);
        }
    }

    // 6. Rebuild canonical path. No trailing slash (except bare root). Leading
    //    slash always present.
    std::string canon = "/";
    for (size_t s = 0; s < segs.size(); ++s) {
        canon += segs[s];
        if (s + 1 < segs.size()) canon += "/";
    }

    result.path = canon;
    result.ok = true;
    return result;
}

bool IsSensitiveSurface(const std::string& normalizedPath) {
    // Case-fold for the comparison. Gating a superset of what the live handler
    // routes (which is case-sensitive) is safe: a gated-but-unrouted path 404s
    // AFTER passing the Host check, leaking nothing. Never the inverse.
    std::string lp;
    lp.reserve(normalizedPath.size());
    for (char c : normalizedPath) lp.push_back(LowerAscii(c));

    // Prefix surfaces (REST + x402 facilitator). Normalized => no duplicate
    // slashes, no dot-segments, no query; a literal "/api/v1/" prefix (or the
    // exact bare "/api/v1") now matches every disguised spelling.
    if (lp == "/api/v1" || lp.rfind("/api/v1/", 0) == 0) return true;
    if (lp == "/x402" || lp.rfind("/x402/", 0) == 0) return true;

    // Exact node-touching surfaces.
    if (lp == "/wallet" || lp == "/wallet.html" || lp == "/") return true;
    if (lp == "/api/stats") return true;
    if (lp == "/metrics") return true;

    return false;
}

} // namespace api
