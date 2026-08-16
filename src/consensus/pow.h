// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_POW_H
#define DILITHION_CONSENSUS_POW_H

#include <primitives/block.h>
#include <cstdint>

// Forward declarations for DFMP
namespace DFMP {
    class CHeatTracker;
    class CIdentityDB;
}

/**
 * Consensus Parameters
 */

/** Target block time in seconds (4 minutes) */
const int64_t BLOCK_TARGET_SPACING = 240;  // 4 minutes = 240 seconds

/** Minimum difficulty target (hardest) */
const uint32_t MIN_DIFFICULTY_BITS = 0x1d00ffff;

/** Maximum difficulty target (easiest - allow testnet 0x1f060000) */
const uint32_t MAX_DIFFICULTY_BITS = 0x1f0fffff;

/**
 * Emergency Difficulty Adjustment (EDA) parameters
 *
 * Prevents death spiral when hashrate drops significantly between
 * 2016-block difficulty adjustments. When a block takes more than
 * EDA_THRESHOLD_BLOCKS * blockTime to arrive, difficulty progressively
 * decreases to allow mining to continue.
 */
/** Threshold: EDA triggers after this many missed block intervals */
const int EDA_THRESHOLD_BLOCKS = 6;
/** Step size: each step beyond threshold reduces difficulty further */
const int EDA_STEP_BLOCKS = 6;
/** Reduction per step: target *= 5/4 (25% easier each step) */
const int EDA_REDUCTION_NUMERATOR = 5;
const int EDA_REDUCTION_DENOMINATOR = 4;
/** Maximum number of reduction steps (cap at ~97% reduction) */
const int EDA_MAX_STEPS = 20;

/**
 * Expand a compact nBits and decide whether it is an ACCEPTABLE PoW target:
 * rejects a zero/overflow expansion and a target EASIER than powLimit
 * (CompactToBig(MAX_DIFFICULTY_BITS)). Shared by CheckProofOfWork and
 * CheckProofOfWorkDFMP so every seam agrees. On success `target` holds the
 * expanded value. Bit-23 ("negative") mantissas are NOT rejected — see the
 * definition for why (canonical DIL history carries them; CompactToBig masks
 * them deterministically).
 */
bool IsValidPoWTarget(uint32_t nBits, uint256& target);

/** Check whether a block hash satisfies the proof-of-work requirement */
bool CheckProofOfWork(uint256 hash, uint32_t nBits);

/**
 * Check proof-of-work with DFMP difficulty adjustment
 *
 * This is the DFMP-aware version of CheckProofOfWork that applies
 * identity-based difficulty multipliers.
 *
 * @param block Full block (needed to extract coinbase identity)
 * @param hash Block hash (RandomX result)
 * @param nBits Compact difficulty target
 * @param height Block height
 * @param activationHeight DFMP activation height (0 = always active)
 * @return true if PoW meets DFMP-adjusted difficulty
 */
bool CheckProofOfWorkDFMP(
    const CBlock& block,
    const uint256& hash,
    uint32_t nBits,
    int height,
    int activationHeight = 0
);

/** Get target from compact difficulty representation */
uint256 CompactToBig(uint32_t nCompact);

/** Get compact difficulty from target */
uint32_t BigToCompact(const uint256& target);

/**
 * Fix compact encoding sign bit collision
 *
 * BigToCompact has a bug where bit 23 of the mantissa collides with the
 * sign bit in Bitcoin's compact target format. CompactToBig masks with
 * 0x007fffff, stripping bit 23 and corrupting the target value (making
 * difficulty up to ~10x harder than intended on round-trip).
 *
 * This function applies Bitcoin Core's GetCompact() fix: if bit 23 is set,
 * shift the mantissa right by 8 bits and increment the exponent.
 *
 * @param nCompact The compact value from BigToCompact
 * @return The corrected compact value with no sign bit collision
 */
uint32_t FixCompactEncoding(uint32_t nCompact);

/**
 * Calculate difficulty adjustment (testing version)
 *
 * This is a simplified version of GetNextWorkRequired for testing purposes.
 * It performs just the core difficulty arithmetic without blockchain context.
 *
 * Used by: difficulty_determinism_test.cpp for cross-platform validation
 *
 * @param nCompactOld The current difficulty in compact format
 * @param nActualTimespan The actual time taken (seconds)
 * @param nTargetTimespan The target time expected (seconds)
 * @param maxChange Maximum change factor (2 = 2x, 4 = 4x)
 * @return The new difficulty in compact format
 */
uint32_t CalculateNextWorkRequired(
    uint32_t nCompactOld,
    int64_t nActualTimespan,
    int64_t nTargetTimespan,
    int maxChange = 4
);

// Forward declaration for ASERT and GetNextWorkRequired
class CBlockIndex;

/**
 * ASERT (Absolutely Scheduled Exponential Rising Targets) difficulty algorithm
 *
 * Computes the next difficulty target using an exponential formula anchored
 * to a fixed reference block. Based on Bitcoin Cash's aserti3-2d (Nov 2020).
 *
 * Formula: next_target = anchor_target * 2^((time_delta - blockTime * height_delta) / halflife)
 *
 * Uses integer-only arithmetic with 16-bit fixed-point exponent and cubic
 * polynomial approximation of 2^x for the fractional part.
 *
 * Timestamp domain: raw nTime (NOT MTP). Consistent with legacy difficulty code.
 *
 * @param pindexPrev  The parent block (tip of the chain being extended)
 * @param nBlockTime  Timestamp of the new block (used for logging only; difficulty
 *                    depends on parent, not the new block's timestamp)
 * @param pindexAnchor The anchor block (at asertActivationHeight - 1)
 * @return The next difficulty target in compact format (nBits)
 */
uint32_t GetNextWorkRequiredASERT(
    const CBlockIndex* pindexPrev,
    int64_t nBlockTime,
    const CBlockIndex* pindexAnchor
);

/** Check if hash is less than target (satisfies PoW) */
bool HashLessThan(const uint256& hash, const uint256& target);

/**
 * Compare chain work (cumulative PoW)
 * Returns true if work1 > work2 (using big-endian comparison)
 */
bool ChainWorkGreaterThan(const uint256& work1, const uint256& work2);

/**
 * Calculate the next required proof-of-work difficulty
 * Implements difficulty adjustment algorithm (every 2016 blocks)
 * with Emergency Difficulty Adjustment (EDA) for stuck chains.
 *
 * @param pindexLast The last block in the chain
 * @param nBlockTime Timestamp of the new block (0 = no EDA check, backward compatible)
 * @return The new difficulty target in compact format (nBits)
 */
uint32_t GetNextWorkRequired(const CBlockIndex* pindexLast, int64_t nBlockTime = 0);

/**
 * Calculate median-time-past for timestamp validation
 * Returns the median timestamp of the last 11 blocks
 * @param pindex The block index to calculate MTP from
 * @return Median timestamp (Unix time)
 */
int64_t GetMedianTimePast(const CBlockIndex* pindex);

/**
 * Validate block timestamp according to consensus rules
 *
 * Rules:
 * 1. Block time must not be more than MAX_FUTURE_BLOCK_TIME in the future
 *    (post-fork at timestampValidationHeight: 600s; pre-fork: 7200s)
 * 2. Block time must be greater than median-time-past
 *
 * @param block The block header to validate
 * @param pindexPrev The previous block index (nullptr for genesis)
 * @param blockHeight Block height for fork-aware limit (-1 = use pre-fork 7200s limit)
 * @return true if timestamp is valid, false otherwise
 */
bool CheckBlockTimestamp(const CBlockHeader& block, const CBlockIndex* pindexPrev, int blockHeight = -1);

#endif // DILITHION_CONSENSUS_POW_H
