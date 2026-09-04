// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_SIGHASH_PREIMAGE_H
#define DILITHION_CONSENSUS_SIGHASH_PREIMAGE_H

#include <cstdint>
#include <vector>

#include <uint256.h>

namespace Consensus {

/**
 * Single-source builder for the ML-DSA (Dilithium3) sighash preimage.
 *
 * This is the ONE canonical assembler of the message that is SHA3-256'd and
 * then signed/verified for each transaction input. Historically FIVE
 * independent hand-built copies of this preimage existed (2 VERIFY + 3 SIGN
 * sites); if any single byte diverges between a SIGN site and a VERIFY site,
 * EVERY spend fails to verify — a total, unrecoverable spend freeze. This
 * helper collapses those copies into one so all sites are byte-identical by
 * construction.
 *
 * CURRENT (v0) LAYOUT — 44 bytes, byte-for-byte identical to the prior
 * open-coded form:
 *
 *   offset  size  field
 *   ------  ----  ------------------------------------------------
 *   0       32    tx_signing_hash   (CTransaction::GetSigningHash())
 *   32      4     input_idx         (uint32 little-endian)
 *   36      4     tx_version        (uint32 little-endian)
 *   40      4     chain_id          (uint32 little-endian)
 *
 * chainId and suiteId are passed EXPLICITLY (no global read inside the builder)
 * so callers cannot silently disagree via ambient state. suiteId is accepted
 * now for forward-compatibility with the frozen 86-byte Q5 wire form (which
 * appends a suite byte); it is NOT emitted in the v0 44-byte layout, so passing
 * any value leaves today's bytes unchanged. Flipping to the 86-byte layout is a
 * SEPARATE, genesis-irreversible step (held for Will+Zach) and MUST NOT be done
 * here without that gate.
 */
std::vector<uint8_t> BuildSighashPreimage(const uint256& tx_signing_hash,
                                          uint32_t input_idx,
                                          uint32_t tx_version,
                                          uint32_t chain_id,
                                          uint8_t suite_id = 0);

/**
 * Convenience: build the preimage and SHA3-256 it into a 32-byte digest — the
 * exact message bytes handed to Dilithium3 sign/verify. Equivalent to
 * SHA3_256(BuildSighashPreimage(...)).
 */
void ComputeSighash(const uint256& tx_signing_hash,
                    uint32_t input_idx,
                    uint32_t tx_version,
                    uint32_t chain_id,
                    uint8_t out_hash[32],
                    uint8_t suite_id = 0);

} // namespace Consensus

#endif // DILITHION_CONSENSUS_SIGHASH_PREIMAGE_H
