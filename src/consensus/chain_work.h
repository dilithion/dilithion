// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 3 — chain-work helper. Single source of truth for the
// `2^(256-8*size) / mantissa` formula. Lifted from two existing copies:
//   * CBlockIndex::GetBlockProof (block_index.cpp)
//   * HeadersSyncState::GetBlockWork (headerssync.cpp)
//
// Both copies were behaviour-equivalent; consolidating prevents drift.
//
// Q4 verification (2026-04-26): there is NO separate VDF chain-work
// formula in this codebase. VDF blocks set `nBits` for legacy
// compatibility; `IsVDFBlock()` only short-circuits PoW *verification*,
// not chain-work *contribution*. Both chains use this same formula.
// IHeaderProofChecker::ChainWorkContribution wraps this for both
// concrete impls (RandomXHeaderProofChecker, VDFHeaderProofChecker).

#ifndef DILITHION_CONSENSUS_CHAIN_WORK_H
#define DILITHION_CONSENSUS_CHAIN_WORK_H

#include <primitives/block.h>  // uint256
#include <cstdint>
#include <cstring>

namespace dilithion::consensus {

// Is this nBits usable for CHAIN-WORK ACCOUNTING?
//
// ⛔ CALL THIS BEFORE FEEDING PEER-SUPPLIED nBits TO ComputeChainWork.
//
// ComputeChainWork SATURATES to 0xFF..FF when the mantissa is zero (see its
// own edge-case list below). That is deliberate for the arithmetic, and it is a
// LIVE DEFECT MAGNIFIER on any path that accepts nBits from a peer without
// validating it against a target:
//
//   * a zero MANTISSA is NOT a zero WORD. 0x1e000000 has a non-zero nBits and a
//     zero mantissa, so the widespread `nBits == 0` guard does NOT catch it.
//   * a header whose proof is never checked against its claimed target -- any
//     VDF header, which skips CheckProofOfWork entirely -- can therefore claim
//     MAXIMUM chain work for free.
//
// MEASURED (2026-09-10, probe P4 on CHeadersManager::ProcessHeaders): a
// zero-mantissa VDF sibling OVERTOOK an honest sibling as best header with
// newWork = 0xffff..., on the PRODUCTION header path. Block-level consensus
// still refuses to connect it, so the impact is best-header DoS rather than a
// consensus split -- but it was peer-triggerable on a live node.
//
// The predicate lives HERE, beside the saturation it guards, rather than being
// re-implemented at each caller: the previous round of this fix guarded three
// sites in the dormant header-sync path and MISSED BOTH LIVE SITES, because the
// sibling census was scoped to the wrong files. A guard at the producer cannot
// be scoped to the wrong files.
inline bool NBitsUsableForWork(uint32_t nBits)
{
    // The mantissa test subsumes `nBits == 0`; both are stated because every
    // site this replaces tested only the latter.
    return (nBits & 0x00FFFFFFu) != 0;
}

// Compute per-block chain-work contribution from compact-form difficulty
// bits. Returns work value in little-endian (bytes 0..31 = LSB..MSB) so
// arithmetic addition matches existing AddChainWork semantics.
//
// Formula: work = 2^(256-8*size) / mantissa  (Bitcoin Core legacy form)
// Edge cases:
//   * mantissa == 0  -> max work (uint256 saturated to 0xFF)
//   * size > 31      -> work_byte_pos clamped to 31
//   * size < 0       -> work_byte_pos clamped to 0
inline uint256 ComputeChainWork(uint32_t nBits)
{
    uint256 proof;
    std::memset(proof.data, 0, 32);

    int size = nBits >> 24;
    uint64_t mantissa = nBits & 0x00FFFFFF;

    if (mantissa == 0) {
        std::memset(proof.data, 0xFF, 32);
        return proof;
    }

    int work_exponent = 256 - 8 * size;
    int work_byte_pos = work_exponent / 8;
    if (work_byte_pos < 0) work_byte_pos = 0;
    if (work_byte_pos > 31) work_byte_pos = 31;

    uint64_t work_mantissa = 0xFFFFFFFFFFFFFFFFULL / mantissa;
    for (int i = 0; i < 8 && (work_byte_pos + i) < 32; ++i) {
        proof.data[work_byte_pos + i] = (work_mantissa >> (i * 8)) & 0xFF;
    }
    return proof;
}

// Add two chain-work values with byte-by-byte carry. Saturates at
// max-uint256 on overflow. Behaviour-equivalent to existing
// HeadersSyncState::AddChainWork and CBlockIndex::BuildChainWork addition.
inline uint256 AddChainWork(const uint256& a, const uint256& b)
{
    uint256 result;
    uint32_t carry = 0;
    for (int i = 0; i < 32; ++i) {
        uint32_t sum = static_cast<uint32_t>(a.data[i]) +
                       static_cast<uint32_t>(b.data[i]) + carry;
        result.data[i] = sum & 0xFF;
        carry = sum >> 8;
    }
    if (carry != 0) {
        std::memset(result.data, 0xFF, 32);
    }
    return result;
}

// True if `a >= b` interpreted as 256-bit unsigned little-endian.
inline bool ChainWorkGreaterOrEqual(const uint256& a, const uint256& b)
{
    for (int i = 31; i >= 0; --i) {
        if (a.data[i] > b.data[i]) return true;
        if (a.data[i] < b.data[i]) return false;
    }
    return true;  // equal
}

}  // namespace dilithion::consensus

#endif  // DILITHION_CONSENSUS_CHAIN_WORK_H
