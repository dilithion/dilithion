// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DFMP_H
#define DILITHION_DFMP_H

/**
 * Dilithion Fair Mining Protocol (DFMP) v3.0
 *
 * Creates diminishing returns for concentrated mining power through:
 * 1. Identity-based tracking (derived from coinbase scriptPubKey)
 * 2. First-block grace: New identities get ONE block at 1× to establish identity
 * 3. Pending penalty: After first block, 5× → 1× decay over 500 blocks
 * 4. Heat-based penalty for prolific miners (quadratic scaling)
 *
 * See: docs/specs/DILITHION-FAIR-MINING-PROTOCOL-SPEC.md
 */

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <cstdint>
#include <vector>
#include <deque>
#include <map>
#include <mutex>
#include <string>

namespace DFMP {

// ============================================================================
// PROTOCOL CONSTANTS (v3.0)
// ============================================================================
// v2.0 uses Mining Identity Key (MIK) for persistent identity tracking
// and updated penalty parameters. See mik.h for full v2.0 spec.

/** Number of blocks in the observation window for heat calculation (v2.0: 360 blocks = ~24 hours) */
constexpr int OBSERVATION_WINDOW = 360;

/** Number of free blocks before heat penalty applies (v3.0: 12 blocks ~3.3%) */
constexpr int FREE_TIER_THRESHOLD = 12;

/** Number of blocks for maturity penalty to fully decay (v2.0: 400 blocks) */
constexpr int MATURITY_BLOCKS = 800;

/** Starting maturity penalty multiplier for new identities (v2.0: 3.0x, no first-block grace) */
constexpr double PENDING_PENALTY_START = 5.0;

/** Ending maturity penalty multiplier (mature identity) */
constexpr double PENDING_PENALTY_END = 1.0;

/** v3.0: Cliff penalty at FREE_TIER_THRESHOLD + 1 (2.0x immediate jump) */
constexpr double HEAT_CLIFF_PENALTY = 2.0;

/** v3.0: Exponential growth rate per block above free tier (1.58x per block) */
constexpr double HEAT_GROWTH_RATE = 1.58;

// Legacy v1.3 constants (kept for reference, no longer used)
// constexpr double HEAT_COEFFICIENT = 0.046;
// constexpr double HEAT_EXPONENT = 2.0;

// Fixed-point scale for deterministic integer arithmetic
// All multipliers are stored as (value * FP_SCALE)
constexpr int64_t FP_SCALE = 1000000;

// Fixed-point versions of v2.0 constants
constexpr int64_t FP_PENDING_START = 5000000;   // 5.0 × 1,000,000 (v3.0 maturity start)
constexpr int64_t FP_PENDING_END = 1000000;     // 1.0 × 1,000,000
constexpr int64_t FP_HEAT_CLIFF = 2000000;      // 2.0 × 1,000,000 (cliff at free tier + 1)
constexpr int64_t FP_HEAT_GROWTH = 158;          // 1.58x per block (multiply by 158, divide by 100)

// C-3: saturating cap for the heat-penalty exponential. = INT64_MAX / FP_HEAT_GROWTH
// (the largest growth factor, 158) so the next (penalty*FP_HEAT_GROWTH) can never overflow
// int64. Minimal-behavior-change: only inputs that WOULD overflow are flattened — they
// saturate to the HARDEST target instead of wrapping to the easiest 1.0x. Activation-gated.
constexpr int64_t FP_HEAT_MULTIPLIER_MAX = INT64_MAX / FP_HEAT_GROWTH;  // ≈ 5.83e16

// DFMP v3.0: Dormancy decay constants
constexpr int DORMANCY_THRESHOLD = 720;           // Blocks of inactivity before maturity resets
constexpr int DORMANCY_DECAY_BLOCKS = 400;         // Decay duration after dormancy reset
constexpr int64_t FP_DORMANCY_PENALTY = 2500000;   // 2.5 × 1,000,000 (dormancy reset penalty)

// DFMP v3.0: Registration PoW - computational cost per new MIK identity
constexpr int REGISTRATION_POW_BITS = 28;          // Default/fallback — actual value from chainparams.registrationPowBits (DIL=28, DilV=30)

// Phase 3b: Shared heat — cluster heat capped at this multiple of own heat
constexpr int MAX_CLUSTER_HEAT_MULTIPLIER = 5;

// ============================================================================
// DFMP v3.1 CONSTANTS (softened for small networks)
// ============================================================================
// v3.1 reduces penalty aggressiveness to prevent network stall when
// few miners are active. Same structure as v3.0 (payout heat, dormancy,
// registration PoW) but with gentler parameters.

/** v3.1: Free blocks before heat penalty (raised from 12 to 36) */
constexpr int FREE_TIER_THRESHOLD_V31 = 36;

/** v3.1: Maturity decay duration (reduced from 800 to 400 blocks) */
constexpr int MATURITY_BLOCKS_V31 = 400;

/** v3.1: Starting maturity penalty (reduced from 5.0x to 2.0x) */
constexpr int64_t FP_PENDING_START_V31 = 2000000;   // 2.0 × 1,000,000

/** v3.1: Cliff penalty at free tier + 1 (reduced from 2.0x to 1.5x) */
constexpr int64_t FP_HEAT_CLIFF_V31 = 1500000;      // 1.5 × 1,000,000

/** v3.1: Exponential growth rate per block (reduced from 1.58x to 1.08x) */
constexpr int64_t FP_HEAT_GROWTH_V31 = 108;          // 1.08x per block

// ============================================================================
// DFMP v3.2 CONSTANTS (tightened anti-whale, back to v3.0 heat with softer maturity)
// ============================================================================
// v3.2 returns to v3.0 heat aggressiveness (12-block free tier, 2.0x cliff,
// 1.58x growth) but with a more moderate maturity penalty (2.5x over 500 blocks)
// to avoid the network stall that occurred with v3.0's 5.0x over 800 blocks.

/** v3.2: Free blocks before heat penalty (back to v3.0: 12) */
constexpr int FREE_TIER_THRESHOLD_V32 = 12;

/** v3.2: Maturity decay duration (500 blocks, between v3.0's 800 and v3.1's 400) */
constexpr int MATURITY_BLOCKS_V32 = 500;

/** v3.2: Starting maturity penalty (2.5x, between v3.0's 5.0x and v3.1's 2.0x) */
constexpr int64_t FP_PENDING_START_V32 = 2500000;   // 2.5 × 1,000,000

/** v3.2: Cliff penalty at free tier + 1 (back to v3.0: 2.0x) */
constexpr int64_t FP_HEAT_CLIFF_V32 = 2000000;      // 2.0 × 1,000,000

/** v3.2: Exponential growth rate per block (back to v3.0: 1.58x) */
constexpr int64_t FP_HEAT_GROWTH_V32 = 158;          // 1.58x per block

// ============================================================================
// DFMP v3.3 CONSTANTS (remove dynamic scaling, linear+exponential penalty)
// ============================================================================
// v3.3 removes dynamic scaling entirely. Uses a three-zone penalty curve:
//   Zone 1 (Free):        0-12 blocks  → 1.0x (no penalty)
//   Zone 2 (Linear):     13-24 blocks  → ramps from 1.25x to 4.0x
//   Zone 3 (Exponential): 25+ blocks   → 4.0x × 1.58^(heat-24)
// This prevents whale dominance in small networks while keeping the chain moving.

/** v3.3: Free blocks before any penalty (same base as v3.2, but NO dynamic scaling) */
constexpr int FREE_TIER_THRESHOLD_V33 = 12;

/** v3.3: End of linear zone (penalty reaches 4.0x at this point) */
constexpr int LINEAR_ZONE_END_V33 = 24;

/** v3.3: Penalty at end of linear zone / start of exponential (4.0x) */
constexpr int64_t FP_LINEAR_END_PENALTY_V33 = 4000000;   // 4.0 × 1,000,000

/** v3.3: Exponential growth rate per block above linear zone (1.58x) */
constexpr int64_t FP_HEAT_GROWTH_V33 = 158;               // 1.58x per block

/** v3.3: Maturity penalty unchanged from v3.2 */
constexpr int MATURITY_BLOCKS_V33 = 500;
constexpr int64_t FP_PENDING_START_V33 = 2500000;         // 2.5 × 1,000,000

// ============================================================================
// DFMP v3.4 CONSTANTS (verification-aware free tier)
// ============================================================================
// v3.4 introduces a split free tier based on DNA verification status:
//   Verified MIKs:   12 free blocks (same as v3.3)
//   Unverified MIKs:  3 free blocks (reduced)
// Linear and exponential zones use the same endpoint/growth as v3.3.

/** v3.4: Free blocks for DNA-verified MIKs */
constexpr int FREE_TIER_THRESHOLD_V34_VERIFIED = 12;

/** v3.4: Free blocks for unverified MIKs */
constexpr int FREE_TIER_THRESHOLD_V34_UNVERIFIED = 3;

/** v3.4: End of linear zone (same as v3.3) */
constexpr int LINEAR_ZONE_END_V34 = 24;

/** v3.4: Penalty at end of linear zone (4.0x, same as v3.3) */
constexpr int64_t FP_LINEAR_END_PENALTY_V34 = 4000000;

/** v3.4: Exponential growth rate (1.58x, same as v3.3) */
constexpr int64_t FP_HEAT_GROWTH_V34 = 158;

// ============================================================================
// IDENTITY TYPE (20 bytes)
// ============================================================================

/**
 * Miner identity - 20-byte hash derived from coinbase scriptPubKey
 *
 * Identity = SHA256(coinbase.vout[0].scriptPubKey)[:20]
 */
struct Identity {
    uint8_t data[20];

    /** Construct null identity */
    Identity();

    /** Construct from raw bytes */
    explicit Identity(const uint8_t* bytes);

    /** Check if identity is null (all zeros) */
    bool IsNull() const;

    /** Equality comparison */
    bool operator==(const Identity& other) const;

    /** Inequality comparison */
    bool operator!=(const Identity& other) const;

    /** Less-than comparison (for std::map) */
    bool operator<(const Identity& other) const;

    /** Get hexadecimal string representation (40 chars) */
    std::string GetHex() const;

    /** Set from hexadecimal string */
    bool SetHex(const std::string& hex);
};

// ============================================================================
// IDENTITY DERIVATION
// ============================================================================

/**
 * Derive miner identity from coinbase transaction
 *
 * @param coinbaseTx The coinbase transaction (must have at least one output)
 * @return Identity derived from SHA256(vout[0].scriptPubKey)[:20]
 *         Returns null identity if coinbase has no outputs
 */
Identity DeriveIdentity(const CTransaction& coinbaseTx);

/**
 * Derive identity from raw scriptPubKey bytes
 *
 * @param scriptPubKey The locking script bytes
 * @return Identity derived from SHA256(scriptPubKey)[:20]
 *         Returns null identity if scriptPubKey is empty
 */
Identity DeriveIdentityFromScript(const std::vector<uint8_t>& scriptPubKey);

// ============================================================================
// HEAT TRACKER
// ============================================================================

/**
 * Tracks miner heat (blocks mined in observation window)
 *
 * Maintains a sliding window of recent blocks and their miner identities.
 * Heat for an identity = count of blocks by that identity in the window.
 *
 * Thread-safe: Protected by internal mutex.
 * In-memory: Rebuilt from chain on startup.
 */
class CHeatTracker {
private:
    /** Sliding window of (height, identity) pairs */
    std::deque<std::pair<int, Identity>> m_window;

    /** Cache: identity -> block count in window (O(1) lookup) */
    std::map<Identity, int> m_heatCache;

    /** Mutex for thread safety */
    mutable std::mutex m_mutex;

public:
    CHeatTracker() = default;

    /**
     * Called when a new block is connected to the chain
     *
     * @param height Block height
     * @param identity Miner identity from coinbase
     */
    void OnBlockConnected(int height, const Identity& identity);

    /**
     * Called when a block is disconnected (reorg)
     *
     * @param height Height of disconnected block
     */
    void OnBlockDisconnected(int height);

    /**
     * Get current heat for an identity
     *
     * @param identity Miner identity to query
     * @return Number of blocks by this identity in the observation window
     */
    int GetHeat(const Identity& identity) const;

    /**
     * Get effective heat (heat minus free tier threshold)
     *
     * @param identity Miner identity to query
     * @return max(0, heat - FREE_TIER_THRESHOLD)
     */
    int GetEffectiveHeat(const Identity& identity) const;

    /**
     * Clear all tracking data
     */
    void Clear();

    /**
     * Get current window size (for debugging)
     */
    size_t GetWindowSize() const;

    /**
     * Get number of unique miners in the current observation window
     * Used for dynamic DFMP scaling
     */
    int GetUniqueMinerCount() const;

    /**
     * Get all identities and their block counts in the current window
     * (for distribution analysis)
     */
    std::map<Identity, int> GetAllHeat() const;

    /**
     * Persist heat tracker state to a binary file.
     * Called during shutdown to avoid chain rebuild on next startup.
     *
     * @param path File path to write to
     * @param tipHeight Current chain tip height (for staleness detection)
     * @return true if written successfully
     */
    bool SaveToFile(const std::string& path, int tipHeight) const;

    /**
     * Load heat tracker state from a binary file.
     * Called during startup as fast alternative to chain rebuild.
     *
     * @param path File path to read from
     * @param expectedTipHeight Current chain tip height (reject stale data)
     * @return true if loaded successfully and tip matches
     */
    bool LoadFromFile(const std::string& path, int expectedTipHeight);
};

// ============================================================================
// MULTIPLIER CALCULATION (Fixed-Point)
// ============================================================================

/**
 * Calculate pending penalty multiplier (fixed-point)
 *
 * New identities (firstSeenHeight = -1) get ONE free block at 1× difficulty
 * to establish their identity. After that first block is mined, subsequent
 * blocks face 5× difficulty that decays linearly to 1× over 500 blocks.
 *
 * @param currentHeight Current block height
 * @param firstSeenHeight Height where identity was first seen (-1 for new identity)
 * @return Pending multiplier × FP_SCALE (1000000 for new, up to 5000000 for just-established)
 */
int64_t CalculatePendingPenaltyFP(int currentHeight, int firstSeenHeight);

// ============================================================================
// C-3 ACTIVATION GATE (SINGLE SOURCE OF TRUTH)
// ============================================================================

/**
 * C-3: is the saturating heat math active at `height`?
 *
 * THE single source of truth for the `saturate` flag threaded through every
 * CalculateHeatMultiplierFP* / CalculateTotalMultiplierFP* / CombineMaturityHeatFP
 * call. The consensus validator (consensus/pow.cpp), the miner
 * (miner/controller.cpp) and both node mining-state mirrors
 * (node/dilithion-node.cpp, node/dilv-node.cpp) MUST route through this function
 * and MUST NOT re-derive the comparison locally: a single `>` vs `>=` divergence
 * between miner and validator is a chain split at exactly the activation boundary.
 * `dfmp_heat_overflow_tests` enforces that by scanning the sources.
 *
 * Semantics (frozen — byte-identical to the four hand-written sites it replaces):
 *   - null g_chainParams            -> false (legacy math)
 *   - height <  activation height   -> false (legacy math)
 *   - height >= activation height   -> true  (saturating math)
 *
 * @param height Block height being validated/mined (validator passes `height`;
 *               callers holding an unsigned nHeight pass static_cast<int>(nHeight),
 *               exactly as the replaced inline expressions did).
 */
bool DfmpSaturatingMathActive(int height);

/**
 * Calculate heat multiplier (fixed-point) with dynamic scaling
 *
 * Free tier scales by active miner count:
 *   effectiveFreeThreshold = max(FREE_TIER_THRESHOLD, OBSERVATION_WINDOW / uniqueMiners)
 *
 * @param heat Block count in observation window
 * @param uniqueMiners Number of unique miners in window (0 = use static threshold)
 * @return Heat multiplier × FP_SCALE (e.g., 1000000 for 1.0×)
 */
int64_t CalculateHeatMultiplierFP(int heat, int uniqueMiners = 0, bool saturate = false);

/**
 * Calculate total DFMP multiplier (fixed-point)
 *
 * Total = pending_multiplier × heat_multiplier
 *
 * @param currentHeight Current block height
 * @param firstSeenHeight Height where identity was first seen (-1 for new)
 * @param heat Block count in observation window
 * @param uniqueMiners Number of unique miners in window (0 = use static threshold)
 * @return Total multiplier × FP_SCALE
 */
int64_t CalculateTotalMultiplierFP(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners = 0, bool saturate = false);

/**
 * Calculate effective target (256-bit integer division)
 *
 * effective_target = base_target / multiplier
 *
 * @param baseTarget The unadjusted difficulty target
 * @param multiplierFP Total multiplier × FP_SCALE
 * @return Effective target (never less than 1)
 */
uint256 CalculateEffectiveTarget(const uint256& baseTarget, int64_t multiplierFP);

/**
 * C-3: combine maturity × heat into a total multiplier (fixed-point), overflow-safe.
 *
 * Computes (maturityFP × heatFP) / FP_SCALE. When `saturate` is true (at/above the
 * overflow-fix activation height), the product is evaluated in 128-bit and clamped to
 * FP_HEAT_MULTIPLIER_MAX so a capped heat penalty (≤ ~5.83e16) times maturity (≤ 5e6)
 * cannot overflow int64. When `saturate` is false the result is byte-identical to the
 * legacy inline `(maturityFP * heatFP) / FP_SCALE` int64 expression (consensus-frozen).
 *
 * Used by the consensus validator (pow.cpp) and the mining-state mirror (dilithion-node.cpp),
 * which combine the maturity and effective-heat penalties inline rather than via the
 * CalculateTotalMultiplierFP* combinators.
 */
int64_t CombineMaturityHeatFP(int64_t maturityFP, int64_t heatFP, bool saturate = false);

// ============================================================================
// DFMP v3.1 MULTIPLIER CALCULATION (Fixed-Point)
// ============================================================================

/** v3.1 pending penalty: 2.0x → 1.5x → 1.0x over 400 blocks */
int64_t CalculatePendingPenaltyFP_V31(int currentHeight, int firstSeenHeight);

/** v3.1 heat multiplier: 36-block free tier, 1.5x cliff, 1.08x growth */
int64_t CalculateHeatMultiplierFP_V31(int heat, int uniqueMiners = 0, bool saturate = false);

/** v3.1 total multiplier: maturity × heat */
int64_t CalculateTotalMultiplierFP_V31(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners = 0, bool saturate = false);

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * Get pending penalty as double (for display/logging)
 */
double GetPendingPenalty(int currentHeight, int firstSeenHeight);

/**
 * Get heat multiplier as double (for display/logging)
 */
double GetHeatMultiplier(int heat, int uniqueMiners = 0);

/**
 * Get total multiplier as double (for display/logging)
 */
double GetTotalMultiplier(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners = 0);

/** v3.1 convenience functions for logging */
double GetPendingPenalty_V31(int currentHeight, int firstSeenHeight);
double GetHeatMultiplier_V31(int heat, int uniqueMiners = 0);

// ============================================================================
// DFMP v3.2 MULTIPLIER CALCULATION (Fixed-Point)
// ============================================================================

/** v3.2 pending penalty: 2.5x → 2.0x → 1.5x → 1.25x → 1.0x over 500 blocks */
int64_t CalculatePendingPenaltyFP_V32(int currentHeight, int firstSeenHeight);

/** v3.2 heat multiplier: 12-block free tier, 2.0x cliff, 1.58x growth */
int64_t CalculateHeatMultiplierFP_V32(int heat, int uniqueMiners = 0, bool saturate = false);

/** v3.2 total multiplier: maturity × heat */
int64_t CalculateTotalMultiplierFP_V32(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners = 0, bool saturate = false);

/** v3.2 convenience functions for logging */
double GetPendingPenalty_V32(int currentHeight, int firstSeenHeight);
double GetHeatMultiplier_V32(int heat, int uniqueMiners = 0);

// ============================================================================
// DFMP v3.3 MULTIPLIER CALCULATION (Fixed-Point)
// ============================================================================

/** v3.3 pending penalty: same as v3.2 (2.5x → 1.0x over 500 blocks) */
int64_t CalculatePendingPenaltyFP_V33(int currentHeight, int firstSeenHeight);

/** v3.3 heat multiplier: 12-block free, linear to 4.0x at 24, then exponential (NO dynamic scaling) */
int64_t CalculateHeatMultiplierFP_V33(int heat, bool saturate = false);

/** v3.3 total multiplier: maturity × heat */
int64_t CalculateTotalMultiplierFP_V33(int currentHeight, int firstSeenHeight, int heat, bool saturate = false);

/** v3.3 convenience functions for logging */
double GetPendingPenalty_V33(int currentHeight, int firstSeenHeight);
double GetHeatMultiplier_V33(int heat);

// ============================================================================
// DFMP v3.4 MULTIPLIER CALCULATION (Verification-Aware Free Tier)
// ============================================================================

/** v3.4 pending penalty: same as v3.3/v3.2 */
int64_t CalculatePendingPenaltyFP_V34(int currentHeight, int firstSeenHeight);

/** v3.4 heat multiplier: free tier depends on verification status */
int64_t CalculateHeatMultiplierFP_V34(int heat, bool isVerified, bool saturate = false);

/** v3.4 total multiplier: maturity × heat */
int64_t CalculateTotalMultiplierFP_V34(int currentHeight, int firstSeenHeight, int heat, bool isVerified, bool saturate = false);

/** v3.4 convenience functions for logging */
double GetPendingPenalty_V34(int currentHeight, int firstSeenHeight);
double GetHeatMultiplier_V34(int heat, bool isVerified);

// ============================================================================
// GLOBAL STATE
// ============================================================================

// Forward declaration
class CIdentityDB;

/** Global heat tracker instance */
extern CHeatTracker* g_heatTracker;

/** Global payout address heat tracker (v3.0) */
extern CHeatTracker* g_payoutHeatTracker;

/** Global identity database instance */
extern CIdentityDB* g_identityDb;

/**
 * Initialize DFMP subsystem
 *
 * @param dataDir Data directory for identity database
 * @return true if initialization successful
 */
bool InitializeDFMP(const std::string& dataDir);

/**
 * Shutdown DFMP subsystem
 *
 * @param dataDir Data directory (for persisting heat tracker). Empty = don't persist.
 * @param tipHeight Current chain tip height (for staleness detection on next load)
 */
void ShutdownDFMP(const std::string& dataDir = "", int tipHeight = 0);

/**
 * Check if DFMP is initialized and ready
 */
bool IsDFMPReady();

} // namespace DFMP

#endif // DILITHION_DFMP_H
