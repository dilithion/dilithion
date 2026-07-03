// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// bech32m (BIP350) codec — ported/adapted from Bitcoin Core's bech32.cpp
// (MIT license). Bitcoin Core supports both bech32 (checksum constant 1) and
// bech32m (checksum constant 0x2bc830a3); Dilithion's ION address format uses
// bech32m ONLY, so this file hard-codes the bech32m checksum constant.
//
// NOTE: this is a pure human-readable-encoding utility for the wallet/UX layer.
// It is NOT witness-coupled — ION re-encodes its EXISTING pubkey-hash address
// payload ([version byte, 20-byte hash]) in bech32m; the on-chain locking
// script is untouched. It has NOTHING to do with consensus/scriptPubKey.

#ifndef DILITHION_UTIL_BECH32M_H
#define DILITHION_UTIL_BECH32M_H

#include <cstdint>
#include <string>
#include <vector>

namespace bech32m {

// bech32m checksum constant (BIP350). bech32 uses 1; bech32m uses this.
static const uint32_t BECH32M_CONST = 0x2bc830a3;

/**
 * Encode a bech32m string from a human-readable part and 5-bit data groups.
 * @param hrp    lowercase human-readable part (e.g. "ion")
 * @param values 5-bit groups (each value MUST be < 32)
 * @return the bech32m string, or "" on error (bad hrp / non-5-bit value).
 */
std::string Encode(const std::string& hrp, const std::vector<uint8_t>& values);

/** Result of a bech32m decode. `ok` is false on any failure. */
struct DecodeResult {
    std::string hrp;              // lowercase human-readable part
    std::vector<uint8_t> data;    // 5-bit groups, checksum already stripped
    bool ok{false};
};

/**
 * Decode a bech32m string. Rejects mixed case, bad characters, bad checksum,
 * a missing/misplaced separator, and over-length input.
 * @param str the candidate bech32m string
 * @return DecodeResult with ok=true and hrp/data filled on success.
 */
DecodeResult Decode(const std::string& str);

/**
 * General power-of-2 base conversion (e.g. 8-bit bytes <-> 5-bit groups).
 * Appends converted groups to `out`.
 * @param out      output groups (appended to)
 * @param in       input groups
 * @param frombits source group bit-width
 * @param tobits   destination group bit-width
 * @param pad      when true (encoding), pad the final partial group with zero
 *                 bits; when false (decoding), require zero padding and no
 *                 leftover — return false otherwise.
 * @return false if an input value overflows `frombits`, or (pad=false) if the
 *         input does not convert cleanly (non-zero pad bits / leftover bits).
 */
bool ConvertBits(std::vector<uint8_t>& out, const std::vector<uint8_t>& in,
                 int frombits, int tobits, bool pad);

} // namespace bech32m

#endif // DILITHION_UTIL_BECH32M_H
