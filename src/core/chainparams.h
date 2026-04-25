#ifndef DILITHION_CHAINPARAMS_H
#define DILITHION_CHAINPARAMS_H

#include <cstdint>
#include <string>
#include <vector>
#include <uint256.h>

namespace Dilithion {

enum Network {
    MAINNET,
    TESTNET,
    DILV        // DilV: VDF distribution payment chain
};

/**
 * MAINNET SECURITY: Blockchain Checkpoint
 *
 * Checkpoints are hardcoded trusted block hashes that:
 * 1. Prevent deep chain reorganizations (51% attack protection)
 * 2. Speed up initial block download (skip signature verification before checkpoint)
 * 3. Protect users - coins received in old blocks are safe from reorgs
 *
 * Testnet: No checkpoints (allows testing reorgs)
 * Mainnet: Populated after launch, updated with each release
 */
struct CCheckpoint {
    int nHeight;
    uint256 hashBlock;

    CCheckpoint(int height, const uint256& hash)
        : nHeight(height), hashBlock(hash) {}
};

class ChainParams {
public:
    Network network;

    // Network identification
    uint32_t networkMagic;          // Message start bytes for P2P protocol
    uint32_t chainID;               // Chain ID for replay protection (included in tx signatures)

    // Genesis block parameters
    uint32_t genesisTime;           // Genesis block timestamp
    uint32_t genesisNonce;          // Genesis block nonce (0 = not mined yet)
    uint32_t genesisNBits;          // Genesis block difficulty target
    std::string genesisHash;        // Genesis block hash (empty = not mined yet)
    std::string genesisCoinbaseMsg; // Genesis coinbase message

    // Network ports
    uint16_t p2pPort;               // Peer-to-peer network port
    uint16_t rpcPort;               // RPC server port

    // Data directory
    std::string dataDir;            // Default data directory name

    // Consensus parameters
    uint32_t blockTime;             // Target seconds per block
    uint64_t halvingInterval;       // Blocks between reward halvings
    uint64_t difficultyAdjustment;  // Blocks between difficulty adjustments (pre-fork)
    uint64_t difficultyAdjustmentV2; // Blocks between difficulty adjustments (post-fork)
    int difficultyForkHeight;       // Height at which v2 difficulty rules activate
    int difficultyMaxChange;        // Max difficulty change factor per retarget (2 = 2x, 4 = 4x)
    int difficultyV3ForkHeight;     // Height where v3 rules activate (4x clamp, 15-block EDA threshold)
    uint32_t maxBlockSize;          // Maximum block size in bytes

    // Mining parameters
    uint64_t initialReward;         // Initial block reward in ions (1 DIL = 100,000,000 ions)

    // Testnet-only: Allow minimum difficulty blocks if no block for 2x target time
    // SECURITY: Must be FALSE for mainnet (prevents difficulty gaming attacks)
    // When enabled, if a block takes > 2x target time (e.g., 120s for 60s testnet),
    // miners can submit blocks at minimum difficulty. This prevents testnet from
    // getting stuck when miners leave, but would be exploitable on mainnet.
    // NOTE: Superseded by EDA (Emergency Difficulty Adjustment) which is consensus-safe.
    bool fPowAllowMinDifficultyBlocks;

    // Emergency Difficulty Adjustment (EDA) activation height
    // Prevents death spiral when hashrate drops between 2016-block adjustments.
    // When a block takes more than 6x target time, difficulty progressively decreases.
    // -1 = EDA disabled
    int edaActivationHeight;

    // DFMP (Fair Mining Protocol) activation height
    // Before this height: Standard PoW (no identity penalties)
    // After this height: DFMP active (pending + heat penalties apply)
    // Mainnet: Activate from genesis (0) or early block to establish fair mining
    // Testnet: Activate from genesis (0) for testing
    int dfmpActivationHeight;

    // DFMP Assume-Valid Height (IBD optimization)
    // Blocks at or below this height skip DFMP penalty multiplier verification.
    // PoW and MIK signature are STILL verified - only penalty calculation is skipped.
    // This fixes IBD where in-memory state (identity DB, heat tracker) differs from
    // when blocks were originally mined.
    // Updated with each release as chain grows.
    // 0 = validate everything (no optimization)
    int dfmpAssumeValidHeight;

    // DFMP v3.0 Activation Height
    // Before this height: DFMP v2.0 rules (20-block free tier, 3.0x maturity, no payout heat)
    // After this height: DFMP v3.0 rules (5-block free tier, 5.0x maturity, payout heat, dormancy, registration PoW)
    // This is a consensus-critical change - all nodes must upgrade before this height
    int dfmpV3ActivationHeight;

    // Registration PoW difficulty (leading zero bits required)
    // DIL mainnet: 24 bits (~1-2 min) — existing chain, cannot change without hard fork
    // DilV mainnet: 30 bits (~40-60 min) — production strength from genesis
    int registrationPowBits;

    // DFMP Dynamic Scaling Activation Height
    // Before this height: Static free tier thresholds (12 for v3.0, 20 for v2.0)
    // After this height: Free tier scales by active miner count:
    //   effectiveFreeThreshold = max(staticThreshold, observationWindow / uniqueMiners)
    // This prevents DFMP from punishing normal mining when few miners are active
    int dfmpDynamicScalingHeight;

    // DFMP v3.1 Activation Height (emergency parameter softening)
    // Before this height: DFMP v3.0 rules (12-block free tier, 1.58x growth, 5.0x maturity)
    // After this height: DFMP v3.1 rules (36-block free tier, 1.08x growth, 2.0x maturity)
    // Same structure as v3.0 (payout heat, dormancy, registration PoW) but gentler parameters
    int dfmpV31ActivationHeight;

    // DFMP v3.2 Activation Height (tightened anti-whale)
    // Before this height: DFMP v3.1 rules (36-block free tier, 1.08x growth, 2.0x maturity)
    // After this height: DFMP v3.2 rules (12-block free tier, 1.58x growth, 2.5x maturity)
    // Returns to v3.0 heat aggressiveness with moderate maturity penalty
    int dfmpV32ActivationHeight;

    // DFMP v3.3 Activation Height (remove dynamic scaling, linear+exponential penalty)
    // Before this height: DFMP v3.2 rules (dynamic scaling inflates free tier in small networks)
    // After this height: DFMP v3.3 rules (fixed 12-block free tier, linear to 4x at 24, exponential)
    int dfmpV33ActivationHeight;

    // DFMP v3.4 Activation Height (verification-aware free tier)
    // Before this height: all MIKs get 12 free blocks (v3.3 rules)
    // After this height: verified MIKs get 12, unverified get 3 free blocks
    int dfmpV34ActivationHeight;

    // VDF Fair Mining parameters
    // vdfActivationHeight: Hybrid period starts (accept both RandomX and VDF blocks)
    // vdfExclusiveHeight:  VDF-only period (reject RandomX blocks after this)
    // vdfIterations:       Target squarings per VDF round
    // 0 = VDF not active (default for both networks until fork is scheduled)
    int vdfActivationHeight;
    int vdfExclusiveHeight;
    uint64_t vdfIterations;

    // VDF Distribution parameters
    // vdfLotteryActivationHeight: Height at which "lowest output wins" activates
    // vdfLotteryGracePeriod: Seconds after first block at a height during which
    //                        a lower-output VDF block can replace the tip
    int vdfLotteryActivationHeight;
    int vdfLotteryGracePeriod;   // seconds

    // VDF Minimum Block Time (seconds)
    // After the chain advances to a new height, miners wait this long before
    // starting the next VDF computation. Ensures all miners finish current-height
    // VDF and participate in the distribution before the chain moves on.
    // 0 = no minimum (legacy behavior)
    int vdfMinBlockTime;

    // VDF cooldown active window (blocks)
    // How many recent blocks to scan when counting "active miners" for the
    // cooldown formula.  Should approximate 24 hours of blocks.
    // DIL mainnet/testnet: 360  (360 × 240s ≈ 24h)
    // DilV:               1920  (1920 × 45s  ≈ 24h)
    int vdfCooldownActiveWindow;

    // Consensus-enforced cooldown activation height (HARD FORK)
    // Before this height: Cooldown is miner-side policy only (voluntary)
    // After this height: Blocks violating cooldown are REJECTED at consensus
    // All nodes must upgrade before this height or they will fork off.
    // 999999999 = disabled
    int dfmpCooldownConsensusHeight;

    // Tightened stall exemption activation height (HARD FORK)
    // After this height: stall threshold raised from 300s to 600s AND
    // stall bypass requires a different miner from the previous block
    // (unless only 1 active miner exists — solo mining scenario).
    // Prevents private fork mining via stall exemption abuse.
    // 999999999 = disabled
    int stallExemptionV2Height;

    // Consecutive miner check activation height (HARD FORK)
    // After this height: reject VDF blocks where the same MIK identity
    // has mined more than 3 consecutive blocks (unless solo mining).
    // Prevents private fork chain construction by a single miner.
    // 999999999 = disabled
    int consecutiveMinerCheckHeight;

    // v4.0.21 — Patch A: After this height, the 1-hour stall exemption in
    // CheckConsecutiveMiner and CheckVDFReplacementPreflight is RETIRED.
    // The exemption was an attack surface during the 2026-04-25 incident:
    // chain stalls during fork churn allowed consecutive-miner bypass which
    // compounded with cooldown self-reinforcement. With 50+ active miners
    // on mainnet, a 1-hour gap is not a real failure mode; if it does happen,
    // operator action (forcerebuild RPC) is the right response, not a quiet
    // rule bypass. Set to a future height (DilV mainnet = 44600) so v4.0.21
    // is forward-only and existing chain history retains the prior rule.
    // 999999999 = disabled
    int consecutiveMinerStallExemptionRetiredHeight;

    // v4.0.21 — Patch C: After this height, the solo-miner exemption in
    // CheckConsecutiveMiner only applies if BOTH activeMiners <= 1 AND the
    // chain has had <= kBootstrapMinerThreshold (5) distinct MIKs in its
    // entire history. Prevents the "active window dominated → activeMiners
    // reports 1 → solo exemption fires" self-reinforcing exploit.
    // 999999999 = disabled
    int soloExemptionLifetimeGateHeight;

    // VDF cooldown short window (blocks) for dual-window cooldown.
    // After stabilizationForkHeight, effective cooldown = min(longCooldown, shortCooldown).
    // Short window tracks recent participation; long window prevents gaming.
    // 0 = disabled (single-window only)
    int vdfCooldownShortWindow;

    // Stabilization fork activation height (HARD FORK)
    // Activates: dual-window cooldown, time-based cooldown expiry,
    // stall exemption removal.  Single height for all stabilization changes.
    // 999999999 = disabled
    int stabilizationForkHeight;

    // Per-MIK window cap: max blocks a single MIK can mine in a rolling window.
    // Prevents one miner (or Sybil identity) from taking >5% of blocks.
    // 0 = disabled
    int mikWindowCapWindow;           // Rolling window size in blocks (480 = ~6h at 45s)
    int mikWindowCapFloor;            // Max blocks per MIK per window (24 = 5% of 480)

    // Liveness escape: if no block for this many seconds, cap is suspended.
    // Prevents deadlock when all eligible miners are capped.
    // 0 = disabled
    int livenessTimeoutSec;           // seconds (300 = ~6.7× target block time)

    // Minimum block timestamp gap (seconds).
    // Consensus rule: block.nTime >= prevBlock.nTime + minBlockTimestampGap.
    // Enforces minimum block spacing at the consensus level regardless of
    // miner behavior.  Interacts with MTP and future-time checks.
    // 0 = disabled (legacy behavior)
    int minBlockTimestampGap;
    int minBlockTimestampGapHeight;    // Activation height for the gap rule (0 = from genesis)

    // Coinbase maturity (blocks before mining rewards are spendable)
    // DIL mainnet/testnet: 100 (PoW reorg safety)
    // DilV: 6 (VDF is deterministic/sequential — reorgs are virtually impossible)
    int coinbaseMaturity{100};

    // Script V2 activation height
    // Before this height: Only standard P2PKH scripts are accepted
    // After this height: All script types (HTLC, multisig, etc.) are valid
    // This gates new script types while the interpreter handles all scripts
    // DIL mainnet: 999999999 (disabled until fork is scheduled)
    // DIL testnet: 0 (immediate)
    // DilV: 0 (from genesis)
    int scriptV2ActivationHeight;

    // Digital DNA activation height
    // Before this height: DNA collection and registration disabled
    // After this height: DNA auto-collection starts for miners, registration active
    // Mainnet: 999999999 (disabled until fork is scheduled)
    // Testnet: 1 (active from near-genesis)
    int digitalDnaActivationHeight;

    // DNA commitment activation height (VDF blocks only)
    // After this height: VDF coinbase must include 0xDD + 32-byte DNA hash
    // Miners commit SHA3-256(serialized_DNA) to prove identity continuity
    // Mainnet/Testnet: 999999999 (disabled until fork is scheduled)
    // DilV: 999999999 (disabled until fork is scheduled)
    int dnaCommitmentActivationHeight;

    // DNA hash-equality enforcement height (VDF blocks only)
    // After this height: committed DNA hash must match the DNA hash in
    // the local registry for that MIK identity.  Blocks with mismatching
    // hashes are rejected at consensus.  If the MIK has no DNA on file,
    // the check passes (cannot verify without data).
    // Mainnet/Testnet/DilV: 999999999 (disabled until calibration complete)
    int dnaHashEnforcementHeight;

    // Trust-weighted network activation height (Phase 4 Sybil Defense)
    // After this height: peer eviction, relay priority, and outbound selection
    // are influenced by DNA trust scores. Purely P2P policy — no consensus impact.
    int trustWeightedNetworkHeight;

    // Phase 5: DNA rotation detection activation height
    // After this height: DNA changes trigger trust penalties and stabilization
    int dnaRotationActivationHeight;

    // MIK Expiration (Layer 2 Sybil Defense, hard fork)
    // After this height: reference blocks (type 0x02) from MIKs idle for
    // mikExpirationThreshold blocks are rejected. Must re-register (type 0x01).
    int mikExpirationActivationHeight;
    int mikExpirationThreshold;          // Blocks of inactivity before expiry

    // Registration Rate Limit (Layer 3 Sybil Defense, hard fork)
    // After this height: no more than mikRegistrationMaxPerWindow new MIK
    // registrations in a rolling window of mikRegistrationRateWindow blocks.
    int mikRegistrationRateLimitHeight;
    int mikRegistrationRateWindow;       // Rolling window in blocks
    int mikRegistrationMaxPerWindow;     // Max new registrations per window

    // Seed-attested MIK registration activation height (Phase 2+3)
    // After this height: MIK registration blocks must include 3+ valid
    // attestations signed by known seed node keys (hardcoded below).
    // 999999999 = disabled
    int seedAttestationActivationHeight;

    // Whether seeds should reject attestation requests from datacenter IPs.
    // true on DilV (VDF Sybil defense — VM farms are the primary threat).
    // false on DIL (PoW — hashrate is the limiting factor, not MIK count;
    // banning datacenter IPs would shrink the miner pool without meaningful
    // security gain since DFMP heat penalties + registration PoW already
    // limit MIK rotation attacks).
    bool attestationDatacenterBan;

    // Seed node public keys for attestation verification (Dilithium3, 1952 bytes each)
    // Ordered by seed index (0-3): NYC, London, Singapore, Sydney
    // Populated for both DIL mainnet and DilV mainnet. Empty for testnet.
    std::vector<std::vector<uint8_t>> seedAttestationPubkeys;

    // Seed node IPs and RPC port (used by miners to request attestations)
    std::vector<std::string> seedAttestationIPs;
    uint16_t seedAttestationRPCPort;

    // Pre-funded addresses for chain reset (balance restoration)
    // Each entry: {base58_address, amount_in_smallest_units}
    std::vector<std::pair<std::string, uint64_t>> preFundAddresses;

    // Compact encoding fix activation height
    // Before this height: BigToCompact has a sign bit bug where bit 23 of the
    // mantissa collides with the sign bit, causing ~2x difficulty corruption on
    // round-trip through BigToCompact/CompactToBig. Discovered when the retarget
    // at block 18144 produced nBits with bit 23 set, making the chain 18x harder
    // than intended after cascading through EDA steps.
    // After this height: GetNextWorkRequired applies the sign bit fix to all
    // compact encoding outputs, matching Bitcoin Core's GetCompact() behavior.
    // -1 = fix disabled
    int compactEncodingFixHeight;

    // ASERT (Absolutely Scheduled Exponential Rising Targets) activation height
    //
    // Replaces periodic retarget + EDA with a per-block exponential formula.
    // Based on Bitcoin Cash's aserti3-2d algorithm (active since Nov 2020).
    //
    // Every block's target is computed from a fixed anchor block:
    //   exponent = (time_delta - blockTime * height_delta) / halflife
    //   next_target = anchor_target * 2^exponent
    //
    // Key properties:
    //   - Path-independent: depends only on anchor + current height/time
    //   - No oscillation: smooth exponential response to hashrate changes
    //   - No separate EDA needed: handles hashrate drops natively
    //   - Symmetric response to increases and decreases
    //
    // Anchor block: The block at (asertActivationHeight - 1).
    //   Its nBits, nTime, and nHeight define the reference point.
    //   Deterministic: all nodes derive the same anchor from the active chain.
    //
    // Timestamp domain: Uses raw nTime (same as legacy GetNextWorkRequired).
    //   MTP validation remains separate in CheckBlockTimestamp().
    //
    // Pre-activation: Legacy periodic retarget + EDA rules apply unchanged.
    // Post-activation: Only ASERT executes; EDA and periodic retarget are dead code.
    //
    // 999999999 = ASERT disabled
    int asertActivationHeight;

    // ASERT halflife in seconds
    // Controls responsiveness: time for difficulty to halve/double when blocks
    // are consistently 2x too slow/fast. Scaled from BCH's 2-day halflife
    // proportionally to block time.
    // Mainnet (240s blocks): 34560s = 144 blocks * 240s = 9.6 hours
    // Testnet (60s blocks):  8640s  = 144 blocks * 60s  = 2.4 hours
    int64_t asertHalflife;

    // Timestamp validation hard fork
    // Activates CheckBlockTimestamp() in ProcessNewBlock and reduces
    // MAX_FUTURE_BLOCK_TIME from 7200s to 600s. Also re-anchors ASERT
    // at (timestampValidationHeight - 1) to eliminate accumulated drift.
    int timestampValidationHeight;

    // MAINNET SECURITY: Checkpoints to prevent deep reorganizations
    // Testnet: empty (no checkpoint protection, allows testing reorgs)
    // Mainnet: populated after launch, updated with each software release
    std::vector<CCheckpoint> checkpoints;

    // ASSUME-VALID: Skip DFMP penalty validation below this block (Bitcoin Core pattern)
    // This is a performance optimization for IBD - blocks still have PoW verified.
    // Set via --assumevalid CLI parameter or use this default.
    // Empty string = validate everything (no assumevalid optimization)
    // Updated with each software release after mainnet has established blocks.
    std::string defaultAssumeValid;

    // Factory methods
    static ChainParams Mainnet();
    static ChainParams Testnet();
    static ChainParams DilV();

    // Helper methods
    const char* GetNetworkName() const {
        switch (network) {
            case MAINNET: return "mainnet";
            case TESTNET: return "testnet";
            case DILV:    return "dilv";
            default:      return "unknown";
        }
    }

    bool IsMainnet() const { return network == MAINNET; }
    bool IsTestnet() const { return network == TESTNET; }
    bool IsDilV() const { return network == DILV; }

    /**
     * MAINNET SECURITY: Get the last checkpoint at or before given height
     *
     * Used during chain reorganization to reject reorgs that would
     * disconnect blocks before the last checkpoint.
     *
     * @param height Current chain height
     * @return Pointer to last checkpoint before height, or nullptr if none
     */
    const CCheckpoint* GetLastCheckpoint(int height) const {
        // Find highest checkpoint at or below given height
        const CCheckpoint* result = nullptr;
        for (const auto& cp : checkpoints) {
            if (cp.nHeight <= height) {
                if (!result || cp.nHeight > result->nHeight) {
                    result = &cp;
                }
            }
        }
        return result;
    }

    /**
     * Check if a block hash matches a checkpoint at the given height
     *
     * @param height Block height
     * @param hash Block hash
     * @return true if no checkpoint at height, or if hash matches checkpoint
     */
    bool CheckpointCheck(int height, const uint256& hash) const {
        for (const auto& cp : checkpoints) {
            if (cp.nHeight == height) {
                return cp.hashBlock == hash;
            }
        }
        return true;  // No checkpoint at this height
    }

    /**
     * Get the height of the highest checkpoint
     *
     * Used by HeadersManager to skip PoW validation for headers at/before this height.
     * This dramatically speeds up IBD by skipping expensive RandomX validation for
     * headers that are protected by checkpoints.
     *
     * @return Highest checkpoint height, or -1 if no checkpoints
     */
    int GetHighestCheckpointHeight() const {
        int highest = -1;
        for (const auto& cp : checkpoints) {
            if (cp.nHeight > highest) {
                highest = cp.nHeight;
            }
        }
        return highest;
    }
};

// Global chain parameters (initialized at startup)
extern ChainParams* g_chainParams;

} // namespace Dilithion

#endif // DILITHION_CHAINPARAMS_H
