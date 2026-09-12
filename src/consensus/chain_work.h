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
// sibling census was scoped to the wrong files.
//
// ⛔ PLACING IT AT THE PRODUCER REMOVES THE RE-IMPLEMENTATION RISK. IT DOES NOT BY
// ITSELF ESTABLISH COVERAGE, and an earlier version of this comment claimed it did
// ("a guard at the producer cannot be scoped to the wrong files"). A predicate
// applies only where a CALLER INVOKES IT, so this file's coverage claim is exactly
// the call sites listed and no wider.
//
// ⚠️ WHEN EXTENDING IT, ENUMERATE THE CONSUMERS OF ComputeChainWork, NOT THE
// VALIDATORS. That is the population, and scoping to the validators instead is the
// same mistake as the sibling census above -- one level up, and it is why the
// coverage read as settled.
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

// ============================================================================
// SingleHeaderWorkIsWithinBound — THE SECOND PREDICATE, AND IT ANSWERS A
// DIFFERENT QUESTION FROM NBitsUsableForWork. Do not merge the two.
// ============================================================================
//
// ⛔ TWO PREDICATES, TWO CONTRACTS. Conflating them is what let an external panel
// AND this change's own author miss a live hole, so they are stated apart:
//
//   NBitsUsableForWork(nBits)
//     CONTRACT: "this nBits does not trip ComputeChainWork's SATURATION branch."
//     Nothing more. It is NOT "usable for work accounting" in a general sense and
//     it is NOT "a valid difficulty target" — it is exactly the negation of the
//     `mantissa == 0` test inside ComputeChainWork, which is why its mask must BE
//     that function's mask (see its own comment).
//
//   SingleHeaderWorkIsWithinBound(nBits, minimum_required_work)
//     CONTRACT: "one header's work contribution does not on its own reach the
//     configured chain-work threshold." It CAPS SINGLE-HEADER MAGNITUDE.
//
//     ⛔ IT DOES NOT CLOSE THE EXPONENT-INFLATION CLASS, and an earlier version of
//     this comment claimed it did. Three reviewers found the overclaim independently:
//       * it rejects only work >= the bound, so an attacker picks an nBits whose work
//         is far above an honest header (~2^76) but STRICTLY BELOW the bound and
//         ACCUMULATES it across many headers to overtake best-header selection;
//       * the bound is static, so it weakens as real tip work grows past it;
//       * on a network with nMinimumChainWork == 0 -- regtest and testnet today -- it
//         is INERT by design, so the class is wholly unguarded there.
//     ⛔ THE CLASS IS CLOSED ONLY BY REAL RETARGET / DIFFICULTY-TRANSITION
//     VALIDATION, which is still simplified at the call sites (see the "simplified"
//     note at CHeadersManager::ValidateHeader step 3). These two predicates raise the
//     cost of the cheapest attacks; they are not a substitute for that validation and
//     must not be described as one.
//
// ⛔ WHY BOTH ARE NEEDED, MEASURED RATHER THAN ARGUED (probe over ComputeChainWork,
// reimplementing its body verbatim so the probe cannot drift from the subject):
//
//   nBits        mantissa   top set byte   NBitsUsableForWork
//   0x1d00ffff   0x00ffff   9              pass   <- honest DIL/DilV
//   0x1e000000   0x000000   31 (saturated) REJECT <- the saturation class
//   0x01000001   0x000001   31             pass   <- ⛔ ~2^248 work, ONE header
//   0x00000001   0x000001   31             pass   <- same class
//   0x03000001   0x000001   31             pass   <- same class
//
// A SMALL `size` byte puts the quotient at the top of the 256-bit word without the
// mantissa ever being zero. **The saturation guard passes every one of those**, and the
// magnitude bound below rejects the ones at or above the threshold. ⚠️ It does NOT
// reject work merely FAR ABOVE HONEST but below the bound -- see the contract note.
//
// ⚠️ AND THE SIGN-BIT CASES ARE RECORDED AS *MEASURED, NOT A VECTOR*, so the next
// reader does not re-raise them: an external panel proposed masking 0x007FFFFF on the
// grounds that bit 23 is the compact sign bit. Measured, 0x1d800000 / 0x1e800000 /
// 0x1d80ffff produce top set byte 7-8 against an honest header's 9 — they claim LESS
// work than a legitimate header, so rejecting them would reject the innocent. And
// ComputeChainWork has no sign handling at all: its mantissa is the full 24 bits.
// The panel was right about the EXAMPLE (0x01000001) and wrong about the MECHANISM.
//
// HOISTED HERE FROM headerssync.cpp's anonymous namespace, where it was reachable
// from the dormant DoS-protected sync path and from NO production caller
// (`grep SingleHeaderWorkIsWithinBound src/net/headers_manager.cpp` = 0). A guard
// that exists, is reviewed, and is called by nothing is the defect this file's other
// predicate was written to fix — the same shape, one class over.
inline bool SingleHeaderWorkIsWithinBound(uint32_t nBits,
                                          const uint256& minimum_required_work)
{
    // A zero bound means no gate is configured (test callers, and any caller before
    // nMinimumChainWork is set). Bounding against zero would reject EVERY header, so
    // the check is inert rather than fail-closed: this guards the gate's arithmetic,
    // and with no gate there is nothing to inflate.
    bool bound_is_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (minimum_required_work.data[i] != 0) { bound_is_zero = false; break; }
    }
    if (bound_is_zero) return true;

    const uint256 single = ComputeChainWork(nBits);
    // ⚠️ READ THE SENSE CAREFULLY — BOTH SENSES ARE SPELLED OUT BECAUSE THIS COMMENT
    // ONCE LED A REVIEWER TO A FALSE HIGH.
    //
    // The function is named for what it RETURNS, not for what it rejects:
    //   returns TRUE  <=> single-header work is BELOW the minimum  (within bound, fine)
    //   returns FALSE <=> single-header work REACHES the minimum   (the hazard)
    // and every caller rejects on the NEGATION:
    //   if (!SingleHeaderWorkIsWithinBound(...)) { reject; }
    //
    // `>=` and not `>` inside the negation, because a header that EXACTLY meets the
    // minimum satisfies the gate on its own — the thing being prevented — so it must
    // land on the FALSE side.
    return !ChainWorkGreaterOrEqual(single, minimum_required_work);
}

}  // namespace dilithion::consensus

#endif  // DILITHION_CONSENSUS_CHAIN_WORK_H
