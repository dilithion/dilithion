// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/sighash_preimage.h>

#include <crypto/sha3.h>
// Pulls in the single canonical SerializeCompactSize encoder (FIX-1 HIGH-1).
// The v0 44-byte layout below uses only fixed-width LE fields and therefore
// does not invoke it, but the 86-byte Q5 form (spent_outputs_hash) will — and
// this include guarantees there is no second encoder to drift against.
#include <primitives/transaction.h>

namespace Consensus {

namespace {
// Append a uint32 in little-endian, matching every open-coded sighash site
// byte-for-byte (the historical form pushed the four bytes low-to-high).
inline void AppendUint32LE(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}
} // namespace

std::vector<uint8_t> BuildSighashPreimage(const uint256& tx_signing_hash,
                                          uint32_t input_idx,
                                          uint32_t tx_version,
                                          uint32_t chain_id,
                                          uint8_t /*suite_id*/) {
    // v0 layout — 44 bytes. Field order and endianness are frozen to match the
    // prior open-coded copies EXACTLY. suite_id is intentionally not emitted in
    // v0 (see header); the 86-byte flip is a separate genesis-gated change.
    std::vector<uint8_t> preimage;
    preimage.reserve(44);

    // tx_signing_hash (32 bytes)
    preimage.insert(preimage.end(), tx_signing_hash.begin(), tx_signing_hash.end());

    // input_idx (4 bytes LE)
    AppendUint32LE(preimage, input_idx);

    // tx_version (4 bytes LE)
    AppendUint32LE(preimage, tx_version);

    // chain_id (4 bytes LE)
    AppendUint32LE(preimage, chain_id);

    return preimage;
}

void ComputeSighash(const uint256& tx_signing_hash,
                    uint32_t input_idx,
                    uint32_t tx_version,
                    uint32_t chain_id,
                    uint8_t out_hash[32],
                    uint8_t suite_id) {
    std::vector<uint8_t> preimage =
        BuildSighashPreimage(tx_signing_hash, input_idx, tx_version, chain_id, suite_id);
    SHA3_256(preimage.data(), preimage.size(), out_hash);
}

} // namespace Consensus
