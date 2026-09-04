#!/usr/bin/env bash
# Regenerate src/api/wallet_assets.h from the website/ asset tree.
#
# node-wallet-selfcontained: the node-served wallet page (GET / and GET /wallet)
# is subject to the node's own CSP — `default-src 'self'; script-src 'self'
# 'unsafe-inline'` — so EVERY subresource it needs must come from the node
# itself. Before this file existed the node served only the HTML, and the page's
# scripts (light-wallet modules, the Dilithium WASM, and the two libraries it
# used to pull from cdn.jsdelivr.net) were all blocked or 403'd, so the wallet
# could not do address/crypto work at all.
#
# Rather than weaken the CSP to allow a third-party CDN — precisely the
# supply-chain exposure the CSP exists to prevent on a page that signs
# transactions — the assets are compiled into the binary and served from the
# node's own origin.
#
# Run this whenever you add/change a file under website/js (or the favicon),
# then rebuild. Keep the asset list in sync with the <script src> tags in
# website/wallet.html.

set -euo pipefail

cd "$(dirname "$0")/.."

OUT=src/api/wallet_assets.h
DELIM=DILASSET

# path-served-at | source file | mime | kind(text|binary)
ASSETS=(
    "/js/vendor/sha3.min.js|website/js/vendor/sha3.min.js|application/javascript; charset=utf-8|text"
    "/js/vendor/ethers.umd.min.js|website/js/vendor/ethers.umd.min.js|application/javascript; charset=utf-8|text"
    "/js/dilithium.js|website/js/dilithium.js|application/javascript; charset=utf-8|text"
    "/js/dilithium-crypto.js|website/js/dilithium-crypto.js|application/javascript; charset=utf-8|text"
    "/js/connection-manager.js|website/js/connection-manager.js|application/javascript; charset=utf-8|text"
    "/js/local-wallet.js|website/js/local-wallet.js|application/javascript; charset=utf-8|text"
    "/js/transaction-builder.js|website/js/transaction-builder.js|application/javascript; charset=utf-8|text"
    "/js/dilithium.wasm|website/js/dilithium.wasm|application/wasm|binary"
    "/favicon.ico|website/favicon.ico|image/x-icon|binary"
)

# C++ identifier for an asset index.
sym() { printf 'kAsset%02d' "$1"; }

emit_text() {
    local idx="$1" src="$2"
    # HARD FAIL if the payload could terminate the raw string literal. Silently
    # emitting a file that closes the literal early would produce either a
    # compile error or (worse) a truncated asset.
    if grep -qF ")${DELIM}\"" "$src"; then
        echo "error: $src contains the raw-string terminator )${DELIM}\" — pick a new DELIM" >&2
        exit 1
    fi
    printf 'static const std::string& %s_Data() {\n' "$(sym "$idx")"
    printf '    static const std::string d = R"%s(' "$DELIM"
    cat "$src"
    printf ')%s";\n' "$DELIM"
    printf '    return d;\n}\n\n'
}

emit_binary() {
    local idx="$1" src="$2"
    local n
    n=$(wc -c < "$src")
    printf 'static const unsigned char %s_Bytes[] = {\n' "$(sym "$idx")"
    # od -> "0xNN," stream, 12 per line. Portable (no xxd in MSYS2).
    od -An -v -tx1 "$src" | awk '{ for (i = 1; i <= NF; i++) { printf "0x%s,", $i; if (++c % 12 == 0) printf "\n" } } END { printf "\n" }'
    printf '};\n'
    printf 'static const std::string& %s_Data() {\n' "$(sym "$idx")"
    printf '    static const std::string d(reinterpret_cast<const char*>(%s_Bytes), %s);\n' "$(sym "$idx")" "$n"
    printf '    return d;\n}\n\n'
}

{
    cat <<'HEADER'
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
// AUTO-GENERATED FILE - DO NOT EDIT DIRECTLY
// Generated from website/ by scripts/gen-embedded-assets.sh
//
// Static subresources for the node-served wallet page, compiled into the
// binary and served from the node's own origin so the page satisfies its own
// `default-src 'self'` CSP without reaching any third party.

#ifndef DILITHION_API_WALLET_ASSETS_H
#define DILITHION_API_WALLET_ASSETS_H

#include <cstddef>
#include <string>

namespace dilithion {
namespace walletassets {

HEADER

    i=0
    for entry in "${ASSETS[@]}"; do
        IFS='|' read -r path src mime kind <<< "$entry"
        [[ -f "$src" ]] || { echo "error: $src missing" >&2; exit 1; }
        printf '// %s  (from %s, %s bytes)\n' "$path" "$src" "$(wc -c < "$src")"
        if [[ "$kind" == "text" ]]; then
            emit_text "$i" "$src"
        else
            emit_binary "$i" "$src"
        fi
        i=$((i + 1))
    done

    cat <<'MIDDLE'
// Exact-match lookup. `path` is the request path with any query string already
// stripped by the caller. Returns false for anything not in this table — there
// is no directory walk and no path joining anywhere in this file, so no
// traversal is reachable.
inline bool Lookup(const std::string& path, const std::string** out_data,
                   const char** out_mime) {
MIDDLE

    i=0
    for entry in "${ASSETS[@]}"; do
        IFS='|' read -r path src mime kind <<< "$entry"
        printf '    if (path == "%s") { *out_data = &%s_Data(); *out_mime = "%s"; return true; }\n' \
            "$path" "$(sym "$i")" "$mime"
        i=$((i + 1))
    done

    cat <<'FOOTER'
    return false;
}

}  // namespace walletassets
}  // namespace dilithion

#endif // DILITHION_API_WALLET_ASSETS_H
FOOTER
} > "$OUT"

echo "wrote $OUT ($(wc -c < "$OUT") bytes)"
