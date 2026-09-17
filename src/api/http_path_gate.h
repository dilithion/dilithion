// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-12 (gate-bypass fold) — request-path normalization + sensitive-surface
// classification for the standalone CHttpServer's anti-DNS-rebinding Host gate.
//
// Why this is its own dependency-free translation unit:
//   The external-consensus review (PR #112) found that the gate decided
//   `sensitive_surface` on the RAW, un-normalized request path using exact `==`
//   and raw `rfind(...,0)==0`. That let every alternate spelling of a sensitive
//   path — query string (`/wallet?x`), trailing slash (`/wallet/`), case
//   (`/API/v1/`), percent-encoding (`/%61pi/v1/`), dot-segment traversal
//   (`/api/v1/../x402/`), duplicate slashes (`//api//v1//`) — evade the gate.
//   It ALSO found the gate test re-modelled the logic instead of exercising the
//   real code. Extracting the decision into pure functions kills both findings
//   at once: CHttpServer::HandleRequest calls them (real path), and the unit
//   test calls the SAME functions (no re-model), with no node depends/ needed.
//
// Fail-closed contract: NormalizeRequestPath reports `ok=false` for any path it
// cannot safely canonicalize (bad percent-encoding, a `..` that would escape
// above root). Callers MUST treat a non-ok result as SENSITIVE (gate it), never
// as public.

#ifndef DILITHION_API_HTTP_PATH_GATE_H
#define DILITHION_API_HTTP_PATH_GATE_H

#include <string>

namespace api {

struct NormalizedPath {
    // The canonical path used for BOTH the gate decision and (in the live
    // server) handler dispatch. Always begins with '/'. Query string and
    // fragment are stripped. Percent-escapes are decoded. Duplicate slashes are
    // collapsed. '.' and '..' segments are resolved. A trailing slash is removed
    // (except for the bare root "/").
    std::string path;

    // false => the raw path could not be safely normalized (malformed percent
    // escape, or a '..' that traverses above root). The gate MUST treat this as
    // sensitive / reject — fail-closed.
    bool ok = false;
};

// Normalize a raw HTTP request-target path (the second token of the request
// line, e.g. "/api/v1/../x402/foo?bar"). See NormalizedPath for the contract.
// Pure; no I/O; depends only on <string>.
NormalizedPath NormalizeRequestPath(const std::string& rawPath);

// Decide whether a NORMALIZED path is a node-touching "sensitive surface" that
// the anti-DNS-rebinding Host gate must protect. Case-folded so that, e.g.,
// "/API/V1/x" is gated even though the live handler routes case-sensitively —
// gating a superset of routed paths is safe (fail-closed); never the reverse.
//
// Pass the .path from a NormalizeRequestPath result. If that result had
// ok==false, callers must gate regardless (do not even call this) — a path that
// would not normalize is sensitive by definition.
bool IsSensitiveSurface(const std::string& normalizedPath);

// Extract the RAW query string from a raw request-target path: the bytes after
// the FIRST raw '?' and before any '#' fragment. Returns "" if there is no raw
// '?'. This is the EXACT delimiter NormalizeRequestPath strips in its step 1, so
// the query carved out here is precisely the part the gate path dropped — no
// more, no less.
//
// Why raw, not decoded: a percent-encoded '?' (%3f) is a LITERAL path byte, not
// a query delimiter (e.g. "/wallet%3fx" is the single path segment "wallet?x",
// never the path "/wallet" with query "x"). Keying on the raw '?' keeps this
// query-extraction in lockstep with the gate's query-strip, so the same byte
// the gate treats as a query delimiter is the byte that begins the query here —
// a percent-encoded '?' is never mistaken for a delimiter on either side.
//
// SECURITY: this value is used ONLY to reconstruct a handler's input AFTER the
// gate and dispatch decision have already been made on the normalized, query-
// stripped path. It can never influence the sensitivity classification.
std::string ExtractRawQuery(const std::string& rawPath);

/**
 * The REST prefix rule, defined ONCE.
 *
 * CRestAPI::IsRESTRequest delegates here. Before this it carried its own copy
 * of `path.find("/api/v1/") == 0`, and the wallet-gate test carried a THIRD
 * copy in a hand-written model -- three definitions of one rule, which is how a
 * "parity sweep" ended up comparing two identical models to each other instead
 * of to the product (fresh pass 2026-09-07, HIGH-1).
 */
bool IsRestPath(const std::string& normalizedPath);

/// How CRPCServer::HandleClient routes a request line.
enum class RequestKind {
    Malformed,  // target did not normalise -> 400, fail-closed
    Wallet,     // GET of a canonical wallet path -> token-minting page (gated)
    Rest,       // /api/v1/* -> CRestAPI
    Other,      // everything else -> CSRF/auth/JSON-RPC
};

/**
 * Classify a request line the way HandleClient does.
 *
 * THIS IS THE PRODUCTION DECISION, not a model of it. It lives here rather than
 * inside HandleClient so a test can link it: the wallet-gate test links three
 * objects, and rpc/server.o would drag the entire node in. The previous test
 * therefore re-implemented the classification twice and asserted the two copies
 * agreed -- f(x) == f(x), which no production change can break.
 *
 * @param method   HTTP method token, verbatim
 * @param rawPath  request target, verbatim (may be empty on a malformed line)
 */
RequestKind ClassifyRequest(const std::string& method, const std::string& rawPath);

} // namespace api

#endif // DILITHION_API_HTTP_PATH_GATE_H
