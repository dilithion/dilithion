#include "chainparams.h"
#include "../attestation/seed_pubkeys_testnet.h"
#include "../attestation/seed_pubkeys_mainnet.h"
#include <util/system.h>

namespace Dilithion {

// Global chain parameters pointer
ChainParams* g_chainParams = nullptr;

ChainParams ChainParams::Mainnet() {
    ChainParams params;
    params.network = MAINNET;

    // Network identification
    // Magic bytes: 0xD1714102 (DIL in hex-ish, plus version)
    // BUGFIX: Was 0xD1711710, but protocol.h had 0xD1714102. Unified to protocol.h value.
    params.networkMagic = 0xD1714102;

    // Chain ID for replay protection (EIP-155 style)
    // Included in transaction signatures to prevent cross-chain replay attacks
    params.chainID = 1;  // Mainnet Chain ID

    // Genesis block parameters
    // v2.0.0 genesis - complete mainnet reset (January 18, 2026)
    params.genesisTime = 1737158400;   // January 18, 2026 00:00:00 UTC (v2.0.0 genesis)
    params.genesisNonce = 429612875;   // MINED
    params.genesisNBits = 0x1e01fffe;  // 128x harder than original (50% reduction from 0x1e00ffff)
    params.genesisHash = "0000009eaa5e7781ba6d14525c3f75c35444045b21ddafbbea61090db99b0bc3";  // MINED
    params.genesisCoinbaseMsg = "Dilithion Mainnet v2.0.0 - Fair Launch Reset - Quantum-Resistant Digital Gold";

    // Network ports
    params.p2pPort = 8444;             // P2P network port
    params.rpcPort = 8332;             // RPC server port

    // Data directory (use absolute path from utility function)
    params.dataDir = GetDataDir(false);

    // Consensus parameters
    params.blockTime = 240;                // 4 minutes (240 seconds)
    params.halvingInterval = 210000;       // ~1.6 years at 4-minute blocks
    params.difficultyAdjustment = 2016;    // ~5.6 days at 4-minute blocks (pre-fork)
    params.difficultyAdjustmentV2 = 360;   // ~1 day at 4-minute blocks (post-fork)
    params.difficultyForkHeight = 18500;   // Activate v2 difficulty at this height (moved from 20160 to fix sign bit + EDA interaction)
    params.difficultyMaxChange = 2;        // 2x max change per retarget (post-fork, pre-v3)
    params.difficultyV3ForkHeight = 20520; // v3: 4x clamp + 1-hour EDA threshold (15 blocks)
    params.maxBlockSize = 4 * 1024 * 1024; // 4 MB (for post-quantum signatures)

    // Mining parameters
    params.initialReward = 50ULL * 100000000ULL; // 50 DIL (in ions: 1 DIL = 100,000,000 ions)

    // MAINNET SECURITY: Never allow minimum difficulty blocks
    // This prevents attackers from gaming timestamps to get easy blocks
    params.fPowAllowMinDifficultyBlocks = false;

    // Emergency Difficulty Adjustment: activate at block 7034
    // Mainnet stuck at 7033 due to hashrate drop - EDA prevents death spiral
    params.edaActivationHeight = 7034;

    // DFMP (Fair Mining Protocol) activation
    // Active from genesis to establish fair mining from the start
    // This prevents early mining dominance before DFMP can take effect
    params.dfmpActivationHeight = 0;

    // DFMP Assume-Valid Height (IBD fix)
    // Skip DFMP penalty validation for blocks at or below this height.
    // PoW and MIK signature verification skipped for historical blocks during IBD.
    // This fixes IBD where identity database is empty/incomplete.
    // NOTE: Chain built with MIK bypassed - cannot be removed, only raised
    params.dfmpAssumeValidHeight = 44000;  // v4.0.17: match new checkpoint at 44000 — skip cooldown/ban validation for checkpointed blocks during IBD

    // DFMP v3.0 activation - payout heat tracking, reduced free tier, dormancy decay
    params.dfmpV3ActivationHeight = 7000;
    params.registrationPowBits = 28;  // DIL mainnet: original production value (unchanged)

    // DFMP Dynamic Scaling - free tier scales by active miner count
    // Prevents penalty spiral with few miners (e.g., 3 miners sharing 360-block window)
    params.dfmpDynamicScalingHeight = 7100;

    // DFMP v3.1 - emergency parameter softening (network stalling at v3.0 parameters)
    // Reduces: free tier 12→36, growth 1.58x→1.08x, maturity 5.0x→2.0x
    params.dfmpV31ActivationHeight = 7168;

    // DFMP v3.2 - tightened anti-whale (community feedback: whales accumulating 50-60k coins)
    // Returns to v3.0 heat: free tier 36→12, growth 1.08x→1.58x, cliff 1.5x→2.0x
    // Moderate maturity: 2.5x over 500 blocks (softer than v3.0's 5.0x/800)
    params.dfmpV32ActivationHeight = 13250;

    // DFMP v3.3 - remove dynamic scaling, linear+exponential penalty
    // Dynamic scaling was inflating free tier to 72+ blocks with few miners, negating v3.2
    // v3.3: fixed 12-block free tier, linear ramp to 4.0x at 24, then exponential wall
    params.dfmpV33ActivationHeight = 13500;

    // DFMP v3.4: verification-aware free tier (verified=12, unverified=3)
    params.dfmpV34ActivationHeight = 999999999;  // Disabled until DNA verification matures

    // Compact encoding fix: fixes BigToCompact sign bit bug that caused
    // difficulty to be ~5x harder than intended due to EDA + sign bit compounding.
    // Moved from 20160 to 18500 to stop ongoing chain degradation.
    params.compactEncodingFixHeight = 18500;

    // Phase 3 port: HeadersSync PRESYNC chain-work gate. Zero for now
    // (preserves pre-port behaviour where this gate was hardcoded zero in
    // CHeadersManager). A non-zero value can be set in a follow-up after
    // smoke-testing that a fresh node successfully clears the threshold
    // against a live seed. Q7 plan recommendation deferred to Phase 4.
    params.nMinimumChainWork = uint256();

    // Phase 4 port: outbound connection class targets. DIL has 240s blocks
    // where propagation latency is well-absorbed; Bitcoin defaults are fine.
    params.nOutboundFullRelayTarget = 8;
    params.nOutboundBlockRelayTarget = 2;

    // Phase 6 PR6.1 (v1.5 §3.2 + Cursor CONCERN 1): mapBlockIndex cap.
    // 500K covers ~14 weeks at one attacker-header-per-second sustained
    // rate — well past the IBD horizon for 240s-block DIL.
    params.nMapBlockIndexCap = 500000;

    // ASERT difficulty algorithm activation
    // Replaces periodic retarget + EDA with per-block exponential adjustment.
    // Anchor block: height 23039 (the block at activationHeight - 1).
    params.asertActivationHeight = 23040;
    params.asertHalflife = 34560;  // 144 blocks * 240s = 9.6 hours

    // Timestamp validation hard fork: enforce CheckBlockTimestamp in block processing,
    // reduce future time limit from 2h to 10min, re-anchor ASERT at this height.
    params.timestampValidationHeight = 24500;

    // VDF Fair Mining (not yet scheduled for mainnet)
    params.vdfActivationHeight = 999999999;   // Disabled until fork is scheduled
    params.vdfExclusiveHeight  = 999999999;
    params.vdfIterations       = 5'000'000;   // ~44s fast, ~110s slow (fairness via minBlockTime)

    // VDF Distribution: "lowest output wins" (disabled until fork is scheduled)
    params.vdfLotteryActivationHeight = 999999999;
    params.vdfLotteryGracePeriod = 60;  // 60 seconds
    params.vdfMinBlockTime = 180;       // 3 minutes: ensures all miners finish VDF
    params.vdfCooldownActiveWindow = 360; // 360 × 240s ≈ 24 hours
    params.dfmpCooldownConsensusHeight = 999999999; // Disabled (VDF not active on mainnet)
    params.stallExemptionV2Height = 999999999;     // Disabled (VDF not active on mainnet)
    params.consecutiveMinerCheckHeight = 999999999; // Disabled (VDF not active on mainnet)
    params.consecutiveMinerStallExemptionRetiredHeight = 999999999;  // v4.0.21 Patch A: disabled on DIL (no VDF)
    params.soloExemptionLifetimeGateHeight = 999999999;              // v4.0.21 Patch C: disabled on DIL (no VDF)
    params.timeBasedCooldownExpiryRetiredHeight = 999999999;         // v4.0.22 Patch E: disabled on DIL (no VDF)
    params.timeDecayCooldownActivationHeight = 999999999;            // v4.2.0: disabled on DIL (no VDF / no per-MIK cooldown)
    params.cooldownTimeDecaySeconds = 60;                            // v4.2.0: ignored on DIL but kept for type-safety
    params.vdfCooldownShortWindow = 0;               // Disabled (VDF not active on mainnet)
    params.stabilizationForkHeight = 999999999;      // Disabled (VDF not active on mainnet)
    params.mikWindowCapWindow = 0;                   // Disabled (VDF not active on mainnet)
    params.mikWindowCapFloor = 0;
    params.livenessTimeoutSec = 0;
    params.minBlockTimestampGap = 0;                 // Disabled (DIL uses RandomX, not VDF pacing)
    params.minBlockTimestampGapHeight = 0;
    params.coinbaseMaturity = 100;        // Standard PoW safety margin

    // Script V2 (HTLC, multisig, etc.): disabled until fork is scheduled
    params.scriptV2ActivationHeight = 999999999;

    params.digitalDnaActivationHeight = 30000;  // DNA collection + P2P exchange (advisory only, no consensus impact)
    params.dnaCommitmentActivationHeight = 40000;  // DNA mandatory in MIK registration from height 40,000
    params.dnaHashEnforcementHeight = 999999999;       // Disabled until calibration complete
    params.trustWeightedNetworkHeight = 999999999;     // Phase 4: trust-weighted P2P (disabled)
    params.dnaRotationActivationHeight = 999999999;   // Phase 5: DNA rotation penalties (disabled)

    // Layer 2: MIK Expiration — disabled on DIL for now
    params.mikExpirationActivationHeight = 999999999;
    params.mikExpirationThreshold = 1080;              // ~3 days at 240s blocks

    // Layer 3: Registration Rate Limit — disabled on DIL for now
    params.mikRegistrationRateLimitHeight = 999999999;
    params.mikRegistrationRateWindow = 37;             // ~2.5 hours at 240s blocks
    params.mikRegistrationMaxPerWindow = 10;

    // Seed attestation: MIK registration requires 3-of-4 seed attestations
    // Activates at height 40,000 (~11 days from v4.0.0 release)
    // Datacenter ban DISABLED on DIL: PoW economics + DFMP heat penalties
    // already limit MIK rotation. Banning datacenter IPs would shrink the
    // miner pool without meaningful security gain. See DilV for contrast.
    params.seedAttestationActivationHeight = 40000;
    params.attestationDatacenterBan = false;  // DIL: allow datacenter miners
    // Same seed servers as DilV — same attestation keys
    params.seedAttestationPubkeys = Attestation::GetMainnetSeedPubkeys();
    params.seedAttestationIPs = {
        "138.197.68.128",   // NYC
        "167.172.56.119",   // London
        "165.22.103.114",   // Singapore
        "134.199.159.83"    // Sydney
    };
    params.seedAttestationRPCPort = 8332;  // DIL mainnet RPC port

    // MAINNET SECURITY: Checkpoints (hardcoded trusted block hashes)
    // These prevent deep chain reorganizations and protect user funds
    //
    // IMPORTANT: After mainnet launch, add checkpoints every ~10,000 blocks:
    //   params.checkpoints.emplace_back(10000, uint256S("0000..."));
    //   params.checkpoints.emplace_back(20000, uint256S("0000..."));
    //
    // Checkpoint at height 1000 - locks in chain before DFMP enforcement
    params.checkpoints.emplace_back(1000, uint256S("000000006c282edbcc0f2eee5b0f8c8feb62c73d3787137037e589db99cab59f"));
    // Checkpoint at height 2000 - locks in chain through difficulty adjustment period
    params.checkpoints.emplace_back(2000, uint256S("0000002c86158454f79a22a31dcabcaca7861f7e95e98275439dd66f4f9e8b4d"));
    // Checkpoint at height 5000 - locks in chain past fork recovery fixes
    params.checkpoints.emplace_back(5000, uint256S("00000152698282228ce368858d4070bc9da937ff2ed5c6276adf45dd9d299ee9"));
    // Checkpoint at height 10000
    params.checkpoints.emplace_back(10000, uint256S("000032dc7d684254b446b7568ec895b3279e1230d5a6b6a42e5552e1d45f8402"));
    // Checkpoint at height 11000
    params.checkpoints.emplace_back(11000, uint256S("000009628d3af9adef443ee681d19e4ff7c9d8f56a0b05acce8f55e43f88a6cf"));
    // Checkpoint at height 13000
    params.checkpoints.emplace_back(13000, uint256S("000001fe5b08776d2f96e3fca8a30ad4113e8e2d998f800e70b06e73454380c7"));
    // Checkpoint at height 16500 - locks in chain through DFMP v3.3 stabilization
    params.checkpoints.emplace_back(16500, uint256S("000000b37d07c641b2b0e18ff7931300ac76ee083eae2522632b343ee221475f"));
    // Checkpoint at height 18500 - post difficulty fork stabilization
    params.checkpoints.emplace_back(18500, uint256S("0000000c9cbfc8c909156c22b37437183ece80257851d5dc324312497d3f2a37"));
    // Checkpoint at height 23000 - pre-ASERT activation (protects all pre-ASERT history)
    params.checkpoints.emplace_back(23000, uint256S("00000a5bbef0e203c6b013976bbe4a3afc401975d5d4405298691d6620f47fa6"));
    // Checkpoint at height 24476 - covers blocks with stale nBits accepted via fork switch path
    params.checkpoints.emplace_back(24476, uint256S("000007289cc3fdbe88a572d84f974a49fb962eda7412312c28930153ae52d611"));
    // Checkpoint at height 30000 - locks in chain through Digital DNA activation
    params.checkpoints.emplace_back(30000, uint256S("0000000f1cadcbc897976ebe04f1171a5d591ebdb580bdd229d2e310f1a09f05"));
    // Checkpoint at height 34000 - post v3.9.0 stabilization
    params.checkpoints.emplace_back(34000, uint256S("00000009b2312644f10b286934ed982520e92aaa54b2736e46f365a77bd92d98"));
    params.checkpoints.emplace_back(40000, uint256S("000000271909e84a5a31fe60c27a9e40a2a51828efc89c6af059a2db2f6e2576"));
    params.checkpoints.emplace_back(44000, uint256S("0000002751fc99551f4fce1f2e92053b2432788f1dc12412fd81223204d11377"));

    // ASSUME-VALID: Skip DFMP penalty validation below this block
    // Empty = validate everything (populate after mainnet has established blocks)
    params.defaultAssumeValid = "";

    return params;
}

ChainParams ChainParams::Testnet() {
    ChainParams params;
    params.network = TESTNET;

    // Network identification
    // Different magic bytes to prevent testnet/mainnet cross-contamination
    params.networkMagic = 0xDAB5BFFA;

    // Chain ID for replay protection (EIP-155 style)
    // Different from mainnet to prevent transaction replay between networks
    params.chainID = 1001;  // Testnet Chain ID

    // Genesis block parameters — VDF genesis for MVP testing
    params.genesisTime = 1774656000;   // March 25, 2026 12:00:00 UTC (MVP testnet reset)
    params.genesisNonce = 0;           // VDF blocks don't use nonce
    params.genesisNBits = 0x1d00ffff;  // Fixed — VDF uses lowest-output-wins
    params.genesisHash = "";           // COMPUTED AT STARTUP — will be printed on first run
    params.genesisCoinbaseMsg = "Dilithion Testnet MVP - Fair Mining Reset";

    // Network ports (different from mainnet to allow running both simultaneously)
    params.p2pPort = 18444;            // Testnet P2P port
    params.rpcPort = 18332;            // Testnet RPC port

    // Data directory (use absolute path from utility function - separate from mainnet)
    params.dataDir = GetDataDir(true);

    // Consensus parameters (faster blocks for testnet)
    params.blockTime = 60;                 // 1 minute (4x faster than mainnet for quicker testing)
    params.halvingInterval = 210000;       // Same as mainnet
    params.difficultyAdjustment = 2016;    // Pre-fork (same as mainnet)
    params.difficultyAdjustmentV2 = 360;   // Post-fork: ~6 hours at 1-minute blocks
    params.difficultyForkHeight = 0;       // Active from genesis on testnet
    params.difficultyMaxChange = 2;        // 2x max change per retarget (pre-v3)
    params.difficultyV3ForkHeight = 0;     // v3 active from genesis on testnet
    params.maxBlockSize = 4 * 1024 * 1024; // 4 MB (same as mainnet)

    // Mining parameters (same as mainnet)
    params.initialReward = 50ULL * 100000000ULL; // 50 DIL (same as mainnet)

    // TESTNET: Allow minimum difficulty blocks for network resilience
    // If no block is found for 2x target time (120s), allow easy difficulty
    // This prevents testnet from getting stuck when miners leave
    // Safe for testnet since coins have no value (would be exploitable on mainnet)
    // NOTE: Superseded by EDA which handles this at the consensus level
    params.fPowAllowMinDifficultyBlocks = true;

    // Emergency Difficulty Adjustment: always active on testnet
    params.edaActivationHeight = 0;

    // DFMP (Fair Mining Protocol) activation
    // Active from genesis for testing fair mining protocol
    params.dfmpActivationHeight = 0;

    // DFMP Assume-Valid Height (IBD optimization)
    // Skip MIK and penalty validation for historical blocks during IBD.
    // Early testnet blocks were mined before MIK was added to coinbase.
    // Must cover all pre-MIK blocks to allow fresh nodes to sync.
    params.dfmpAssumeValidHeight = 86850;

    // DFMP v3.0 activation - set above existing testnet chain height
    // Testnet tip was ~86,829 when v3.0 was implemented
    // Activation at 87,000 gives ~170 blocks buffer for upgrade
    params.dfmpV3ActivationHeight = 87000;
    params.registrationPowBits = 24;  // DIL testnet

    // DFMP Dynamic Scaling - always active on testnet
    params.dfmpDynamicScalingHeight = 0;

    // DFMP v3.1 - always active on testnet (softened parameters)
    params.dfmpV31ActivationHeight = 0;

    // DFMP v3.2 - always active on testnet (tightened anti-whale)
    params.dfmpV32ActivationHeight = 0;

    // DFMP v3.3 - always active on testnet (no dynamic scaling)
    params.dfmpV33ActivationHeight = 0;

    // DFMP v3.4 - disabled on testnet until DNA verification matures
    params.dfmpV34ActivationHeight = 999999999;

    // Compact encoding fix: always active on testnet (no legacy blocks to worry about)
    params.compactEncodingFixHeight = 0;

    // ASERT difficulty algorithm (disabled on testnet for now)
    params.asertActivationHeight = 999999999;
    params.asertHalflife = 8640;  // 144 blocks * 60s = 2.4 hours

    // Timestamp validation: active from genesis on testnet
    params.timestampValidationHeight = 0;

    // Phase 3 port: testnet has no PRESYNC chain-work gate.
    params.nMinimumChainWork = uint256();

    // Phase 4 port: outbound class targets — testnet uses DIL defaults.
    params.nOutboundFullRelayTarget = 8;
    params.nOutboundBlockRelayTarget = 2;

    // Phase 6 PR6.1: mapBlockIndex cap — testnet matches mainnet semantics.
    params.nMapBlockIndexCap = 500000;

    // VDF Fair Mining — VDF-only from genesis for MVP testing
    params.vdfActivationHeight = 0;
    params.vdfExclusiveHeight  = 0;            // VDF-only from genesis (like DilV)
    params.vdfIterations       = 500000;       // 500K iterations (~4-8s, matches DilV)

    // VDF Distribution: "lowest output wins" — reset MVP testing
    params.vdfLotteryActivationHeight = 0;     // Active from genesis for MVP testing
    params.vdfLotteryGracePeriod = 45;         // 45s grace period (MVP)
    params.vdfMinBlockTime = 0;                // Disabled — grace period controls pacing
    params.vdfCooldownActiveWindow = 200;      // 200 × 45s ≈ 2.5h (reduced from 1920 — count actual producers, not all historical MIKs)
    params.dfmpCooldownConsensusHeight = 0;    // Consensus-enforced cooldown from genesis
    params.stallExemptionV2Height = 0;         // Tightened stall exemption from genesis
    params.consecutiveMinerCheckHeight = 0;    // Reject >3 consecutive from genesis
    params.consecutiveMinerStallExemptionRetiredHeight = 0;  // v4.0.21 Patch A: testnet retires stall exemption from genesis
    params.soloExemptionLifetimeGateHeight = 0;              // v4.0.21 Patch C: testnet activates lifetime gate from genesis
    params.timeBasedCooldownExpiryRetiredHeight = 0;         // v4.0.22 Patch E: testnet retires time-based expiry from genesis
    params.timeDecayCooldownActivationHeight = 0;            // v4.2.0: testnet activates time-decay cooldown from genesis
    params.cooldownTimeDecaySeconds = 60;                    // v4.2.0: 60s decay rate (1 cooldown-block per minute)
    params.vdfCooldownShortWindow = 0;         // Disabled — avoids MIN_COOLDOWN bypass
    params.stabilizationForkHeight = 0;        // Dual-window + time expiry from genesis
    params.mikWindowCapWindow = 480;           // 480 blocks = ~6h at 45s/block (MVP)
    params.mikWindowCapFloor = 24;             // Max 24 blocks per MIK per window (5%)
    params.livenessTimeoutSec = 300;           // 300s liveness escape (MVP)
    params.minBlockTimestampGap = 45;          // Consensus-enforced 45s min gap (MVP)
    params.minBlockTimestampGapHeight = 0;     // Active from genesis on testnet
    params.coinbaseMaturity = 100;        // Standard PoW safety margin

    // Script V2 (HTLC, multisig, etc.): active from genesis on testnet
    params.scriptV2ActivationHeight = 0;

    params.digitalDnaActivationHeight = 1;    // Active from near-genesis for testing
    params.dnaCommitmentActivationHeight = 999999999;  // Disabled until fork is scheduled
    params.dnaHashEnforcementHeight = 999999999;       // Disabled until calibration complete
    params.trustWeightedNetworkHeight = 999999999;     // Phase 4: trust-weighted P2P (disabled)
    params.dnaRotationActivationHeight = 999999999;   // Phase 5: DNA rotation penalties (disabled)

    // Layer 2+3: Sybil defense — disabled on DIL testnet
    params.mikExpirationActivationHeight = 999999999;
    params.mikExpirationThreshold = 200;
    params.mikRegistrationRateLimitHeight = 999999999;
    params.mikRegistrationRateWindow = 50;
    params.mikRegistrationMaxPerWindow = 5;

    // Seed attestation: disabled on DIL testnet
    params.seedAttestationActivationHeight = 999999999;
    params.attestationDatacenterBan = false;
    params.seedAttestationPubkeys = {};
    params.seedAttestationIPs = {};
    params.seedAttestationRPCPort = 0;

    // TESTNET: Checkpoints for IBD optimization
    // PoW validation is skipped for headers at/before the highest checkpoint
    // This dramatically speeds up Initial Block Download (~100ms -> ~1ms per header)
    // Reorgs can still be tested on blocks AFTER the highest checkpoint
    params.checkpoints.emplace_back(1000, uint256S("0000cb60f4051a278b03a4133a6cefda689a5788a215c6209b160a9be632b5ca"));
    params.checkpoints.emplace_back(2000, uint256S("000099b421f37840b53ec623a201c817a7ea9fcfa48e69e5c3461727fd92282f"));
    params.checkpoints.emplace_back(3000, uint256S("00002c1ca3bbbd9c7dd7b0903873b36724e1ee31c53f70ab7c81123228d9edb4"));
    params.checkpoints.emplace_back(5000, uint256S("00000e8e96d5571c22a6dbf934cb50b9c27c513d0bdf86d3539a014b59751643"));
    params.checkpoints.emplace_back(10000, uint256S("0001cb679cfe170ba4893cac1b6a3cb22c69dabe4913927a513761a0ad788e9a"));
    params.checkpoints.emplace_back(20000, uint256S("000adc0c364bed2b4f2247961d852d19d5432b8363e801df24045258a6730b3c"));
    params.checkpoints.emplace_back(40000, uint256S("0007eb5ab7d4a2086d5cc554ce7bbd7866c8ca5791e4ab1cedf631d04803f015"));
    params.checkpoints.emplace_back(60000, uint256S("0003d271d83c1fc66bb2af7cf8f16207034c8f80ec918f119a51ccb4203aadc7"));
    params.checkpoints.emplace_back(80000, uint256S("000a18c94a5bd98403807aff7260c5671079be0d822bdc0815916d8b6fed718e"));
    params.checkpoints.emplace_back(86000, uint256S("00001432d1653a47059b1aa78e71b9cbe69720555cdea55473412d97f74cb3dd"));

    // ASSUME-VALID: Skip DFMP penalty validation below this block
    // Empty = validate everything (populate after testnet has established blocks)
    params.defaultAssumeValid = "";

    return params;
}

ChainParams ChainParams::DilV() {
    ChainParams params;
    params.network = DILV;

    // Network identification
    // Unique magic for DilV chain — prevents cross-chain message contamination
    params.networkMagic = 0xD17FD100;

    // Chain ID for replay protection
    // Different from mainnet (1) and testnet (1001) to prevent cross-chain tx replay
    params.chainID = 2;

    // Genesis block parameters (VDF genesis — pre-computed)
    // Genesis VDF proof computed by dilv-genesis-vdf tool
    params.genesisTime = 1774656000;  // March 28, 2026 00:00:00 UTC (chain reset)
    params.genesisNonce = 0;          // Not used for VDF blocks (nonce is vestigial)
    params.genesisNBits = 0x1d00ffff; // Fixed — VDF uses lowest-output-wins, not hash-under-target
    params.genesisHash = "ed06d89a233d9cfa4518f9a6012d8bccb2264afed098c6035b9949710d31c48e";
    params.genesisCoinbaseMsg = "DilV Reset - Fair Distribution Recovery - March 2026";

    // Network ports (unique to DilV)
    params.p2pPort = 9444;
    params.rpcPort = 9332;

    // Data directory — separate from DIL and testnet
    params.dataDir = GetDataDir(DILV);

    // Consensus parameters
    params.blockTime = 45;                     // ~45-second target block time
    params.halvingInterval = 1050000;          // ~1.5 years at 45s blocks, yields ~210M total supply
    params.difficultyAdjustment = 0;           // Unused — VDF doesn't use difficulty retargeting
    params.difficultyAdjustmentV2 = 0;         // Unused
    params.difficultyForkHeight = 999999999;   // Disabled
    params.difficultyMaxChange = 0;            // Unused
    params.difficultyV3ForkHeight = 999999999; // Disabled
    params.maxBlockSize = 4 * 1024 * 1024;     // 4 MB (same as DIL — room for Dilithium signatures)

    // Mining parameters
    params.initialReward = 100ULL * 100000000ULL; // 100 DilV per block (in volts: 1 DilV = 100,000,000 volts)

    // VDF chain: no RandomX minimum difficulty blocks
    params.fPowAllowMinDifficultyBlocks = false;

    // EDA disabled — not applicable to VDF consensus
    params.edaActivationHeight = -1;

    // DFMP (Fair Mining Protocol) — active from genesis
    // Genesis block itself is exempt (code at chain.cpp:889-890 skips height 0)
    // MIK required from block 1 onward
    params.dfmpActivationHeight = 0;
    params.dfmpAssumeValidHeight = 44233;  // v4.1 (was 44469): aligned with the new mandatory rollback checkpoint at 44233. Skips strict consensus checks (cooldown, MIK, DNA, attestation) only for blocks AT OR BELOW the canonical 44233 anchor. Above 44233, Patches A/C/E activate AND consensus checks are enforced — no bypass window. (v4.0.22 had this at 44469 with Patches at 44470, leaving 44234-44469 unprotected; that re-creates the v4.0.22 stop-gap failure mode. See cross-component audit finding HIGH-1.)

    // All DFMP versions active from genesis — use modern rules from day one
    params.dfmpV3ActivationHeight = 0;
    params.registrationPowBits = 28;  // DilV mainnet: ~27 min on consumer hardware (DNA+attestation are primary Sybil defense)
    params.dfmpDynamicScalingHeight = 0;
    params.dfmpV31ActivationHeight = 0;
    params.dfmpV32ActivationHeight = 0;
    params.dfmpV33ActivationHeight = 0;
    params.dfmpV34ActivationHeight = 999999999;  // Disabled until DNA verification matures

    // Compact encoding fix: active from genesis
    params.compactEncodingFixHeight = 0;

    // ASERT: disabled — VDF uses distribution (lowest output wins), not difficulty retargeting
    params.asertActivationHeight = 999999999;
    params.asertHalflife = 0;  // Unused

    // Timestamp validation: active from genesis
    params.timestampValidationHeight = 0;

    // Phase 3 port: DilV starts with no PRESYNC chain-work gate; the
    // gate value can be tightened in Phase 4 after telemetry confirms
    // typical fresh-node IBD work accumulation against live seeds.
    params.nMinimumChainWork = uint256();

    // Phase 4 port: outbound class targets — DilV's 45s blocks benefit
    // from faster propagation, so bump BlockRelay to 4 (Q4 recommendation).
    params.nOutboundFullRelayTarget = 8;
    params.nOutboundBlockRelayTarget = 4;

    // Phase 6 PR6.1: mapBlockIndex cap — DilV is 5M (10× DIL) because
    // its 60s blocks produce headers ~4× faster than DIL's 240s.
    params.nMapBlockIndexCap = 5000000;

    // VDF: active from genesis — DilV is a VDF-only chain
    params.vdfActivationHeight = 0;
    params.vdfExclusiveHeight  = 0;            // No RandomX blocks ever accepted
    params.vdfIterations       = 500000;       // 500K iterations (~4-8s compute time)

    // VDF Distribution: active from genesis
    params.vdfLotteryActivationHeight = 0;
    params.vdfLotteryGracePeriod = 45;         // 45 seconds — collection window for all miners' VDF outputs
    params.vdfMinBlockTime = 0;                // Disabled — grace period controls pacing now
    params.vdfCooldownActiveWindow = 200;      // 200 × 45s ≈ 2.5h (reduced from 1920 — count actual producers, not all historical MIKs)
    params.dfmpCooldownConsensusHeight = 0;    // Consensus-enforced cooldown from genesis
    params.stallExemptionV2Height = 0;         // Tightened stall exemption from genesis
    params.consecutiveMinerCheckHeight = 0;    // Reject >3 consecutive blocks from same miner from genesis
    // v4.1 (2026-05-02) — Mandatory upgrade. Chain rollback to height 44233
    // (last common ancestor across NYC/LDN/SGP/SYD per 2026-05-02 multi-seed
    // hash agreement). Replaces the v4.0.22 50000 stop-gap that never resolved
    // because the chain split made coordinated miner upgrade impossible.
    //
    // Activation height = checkpoint height = rollback target = 44233.
    // Strict activation: miner pre-upgrade is REQUIRED before seed cutover
    // (operator coordinates via Telegram quorum gate per v4_1 spec §5.3).
    //
    // CRITICAL: this is paired with the checkpoint at 44233 below — without
    // the checkpoint, v4.1 nodes could silently extend any of the four
    // incident-era forks. With both, v4.1 nodes only follow the chain whose
    // block-44233 hash matches the canonical anchor.
    params.consecutiveMinerStallExemptionRetiredHeight = 44233;
    params.soloExemptionLifetimeGateHeight = 44233;
    params.timeBasedCooldownExpiryRetiredHeight = 44233;
    // v4.2.0 — Time-decay cooldown activation, height 44255 on DilV mainnet.
    // The brittle stall-exemption-tier system in chain.cpp is REPLACED by the
    // self-correcting time-decay rule at and above this height. See spec
    // .claude/contracts/v4_2_time_decay_cooldown_spec.md.
    //
    // Chosen as tip+6 from the 2026-05-03 stall-recovery cutover (London tip
    // was 44249 at decision time; NYC/SYD/SGP recovering). Forward-activation
    // (no in-flight blocks need re-validation) → zero consensus-fork risk.
    // The +6 buffer accommodates any block produced during seed restoration
    // before all v4.2 binaries are deployed.
    params.timeDecayCooldownActivationHeight = 44250;  // v4.3 KEEPS this active 2026-05-04. Earlier draft of v4.3 set 999999999 to disable; reconsidered after operator review noted: time-decay is currently the chain's only unstick mechanism (livenessTimeout via legacy path was demonstrated to deadlock on 2026-05-03 — chain stalled 5h at h=44249 before v4.2.0 activated time-decay at 44250). Returning to legacy path = stall risk, NOT return to pre-Apr-25 clean state (those rules have been retired/replaced since then). v4.3's actual fix is the port path correctness (A1 + ABI + connman) — once stuck v4.1 peers sync past 44249 via ABI flag-merge fix, active-miner cache refreshes higher, time-decay self-corrects to lower cooldown values. Cooldown layer retirement deferred to chain reset OR v4.4 properly-engineered transition.
    params.cooldownTimeDecaySeconds = 60;      // 1 cooldown-block drains per 60s wall-clock
    params.vdfCooldownShortWindow = 0;         // Disabled at genesis — avoids short-window MIN_COOLDOWN bypass
    params.stabilizationForkHeight = 0;        // Dual-window cooldown + time-based expiry from genesis

    // Per-MIK window cap + liveness escape
    params.mikWindowCapWindow = 480;           // 480 blocks = ~6 hours at 45s/block
    params.mikWindowCapFloor = 24;             // Max 24 blocks per MIK per 480-block window (5%)
    params.livenessTimeoutSec = 300;           // 300s = ~6.7× target; suspends cap during stalls

    // Minimum block timestamp gap (consensus-enforced block pacing)
    params.minBlockTimestampGap = 45;          // block.nTime >= prevBlock.nTime + 45
    params.minBlockTimestampGapHeight = 37000; // Activate after existing chain (pre-deploy blocks had <45s gaps)

    params.coinbaseMaturity = 6;               // VDF is sequential/deterministic — reorgs near-impossible

    // Script V2 (HTLC, multisig, etc.): active from genesis on DilV
    params.scriptV2ActivationHeight = 0;

    // Digital DNA: active from genesis
    params.digitalDnaActivationHeight = 0;
    params.dnaCommitmentActivationHeight = 0;           // Active from genesis
    params.dnaHashEnforcementHeight = 999999999;       // Disabled until calibration complete
    params.trustWeightedNetworkHeight = 999999999;     // Phase 4: trust-weighted P2P (disabled)
    params.dnaRotationActivationHeight = 999999999;   // Phase 5: DNA rotation penalties (disabled)

    // Layer 2: MIK Expiration — dormant MIKs must re-register
    // Activation TBD (~2 days after deploy). Threshold: 5760 blocks (~3 days at 45s).
    params.mikExpirationActivationHeight = 999999999;  // Set after deploy + announce
    params.mikExpirationThreshold = 5760;

    // Layer 3: Registration Rate Limit — cap new MIK registrations per window
    // Activation TBD (same height as Layer 2).
    params.mikRegistrationRateLimitHeight = 999999999;  // Set after deploy + announce
    params.mikRegistrationRateWindow = 200;             // ~2.5 hours at 45s blocks
    params.mikRegistrationMaxPerWindow = 10;

    // Seed-attested MIK registration (Phase 2+3)
    // Datacenter ban ENABLED on DilV: VDF = one miner per machine, so VM farms
    // are the primary Sybil vector. Proven by the March 31 attack (97-MIK round-robin).
    params.seedAttestationActivationHeight = 2000;  // BUG #281: pre-2000 blocks mined before attestation deployed, lack seed signatures
    params.attestationDatacenterBan = true;   // DilV: block datacenter miners

    // Seed attestation public keys (mainnet — extracted from seed nodes)
    params.seedAttestationPubkeys = Attestation::GetMainnetSeedPubkeys();

    // Seed node IPs for attestation requests (DilV mainnet seeds)
    params.seedAttestationIPs = {
        "138.197.68.128",   // NYC
        "167.172.56.119",   // London
        "165.22.103.114",   // Singapore
        "134.199.159.83"    // Sydney
    };
    params.seedAttestationRPCPort = 9332;  // DilV mainnet RPC port

    // DilV Checkpoints — enforce legitimate chain, reject Sybil fork at height 2631
    params.checkpoints.emplace_back(500,  uint256S("88c3760b617f4295176a76871acc60904e8dfc9ccd62d6d460475c520a039f1e"));
    params.checkpoints.emplace_back(1000, uint256S("9884fa2d1fcd8b2c7b5c3b49a6aa6c11c60a467ad93048cd871d0ebba42cc81e"));
    params.checkpoints.emplace_back(1500, uint256S("3fd46e642ef3b8a4a0ba29c80293dff82956bb10dedc26f6679045994d2b97de"));
    params.checkpoints.emplace_back(2000, uint256S("6b7f65e2e1c9171ec26dd68bf49b44c72eb1b6ad819b08864f79d9e48136d1a6"));
    params.checkpoints.emplace_back(2500, uint256S("05dff2b9b58ab6145e8345f103a12fd605a71092c7113527acc743d58d34f233"));
    params.checkpoints.emplace_back(2632, uint256S("7e250f5f24081906aeea465c546a371937812939dc00ead70a9621f897619caf"));
    params.checkpoints.emplace_back(2700, uint256S("475d9fcb367c512c65eb24d6feb962c3eaafb847a3c45265d108863cadbf4a0f"));
    params.checkpoints.emplace_back(2800, uint256S("dda53ab45040a889457f21bd828fc82b3c81dfc797be671e157d9e4d8c6438fa"));
    params.checkpoints.emplace_back(2900, uint256S("a0ce1e87001b1440837bfc3c2d2be8f481f68bf85cb9038b4a89360d9497be3e"));
    params.checkpoints.emplace_back(2935, uint256S("64abd9e3f640b683145e2a8fe10339573c658da53457611817c4b10a642698ee"));
    params.checkpoints.emplace_back(2949, uint256S("d8d2c97abb1d6e5aa15285ece31b44d6e9b779fcf97abfff65dfee62542938a0"));
    params.checkpoints.emplace_back(2951, uint256S("31cfe3012d8fe67482ed99474433c4f365d89c76003c90adf11e5fcd49438077"));
    params.checkpoints.emplace_back(2961, uint256S("0727d34f6604ec5f4c1efe92825f8b5c7f325f65d4a220005cd6f2ee1ee122b2"));
    // Checkpoint at height 8000
    params.checkpoints.emplace_back(8000, uint256S("9453c0150d81df7785c4b95c4ca50df75a1a561f092192a8ca55c15507397876"));
    // Checkpoint at height 8370 — covers all pre-ban-deployment blocks (ban deployed to all seeds Apr 4)
    params.checkpoints.emplace_back(8370, uint256S("ef1e3a7de515523cde0b224865b26dc049c92033bc5a86b31e0e32cd1ca852be"));
    params.checkpoints.emplace_back(15000, uint256S("45f5877adcc1ec2dab453412d6a5cb3fd9383fc97a184aa4ec855db55212f5d6"));
    params.checkpoints.emplace_back(18700, uint256S("1fbcf55c40c735596b68772af0072b98342a098bd5c1ff0b3bb26423720e9295"));
    params.checkpoints.emplace_back(36500, uint256S("3a6c72ee0ac27508fe82b76ed561dc93bc52ee5a26825cbf3f693bbc7070fd63"));
    // v4.1 (2026-05-02): MANDATORY ROLLBACK ANCHOR.
    //
    // Verified hash: 927a1e79a410e73c1778dd3eaebae1c07ce5271431abffa9b62a6f6b3177e373
    //
    // Confirmed independently 2026-05-02 from all four DilV mainnet seeds
    // (NYC tip 44740, LDN tip 44491, SGP tip 44542, SYD tip 44700) — each
    // currently on a DIFFERENT post-incident chain. The agreement at 44233
    // across four nodes that disagree at every height above 44233 is the
    // canonical pre-fork ancestor.
    //
    // History: the v4.0.22 50000-stop-gap (Patches A/C/E pushed to height
    // 50000) failed to resolve because the chain was already split four
    // ways and no rule-based mechanism could converge them. v4.1 reverts
    // to the original v4.0.21 plan: hard rollback at the last common
    // ancestor with three-tier ABC enforcement (chain.cpp), header-time
    // enforcement (headers_manager.cpp), and a startup validator
    // (startup_checkpoint_validator.cpp) ensuring every v4.1 node refuses
    // any chain whose block-44233 hash differs from the embedded value.
    //
    // The Patches A/C/E activation heights (above) are now also 44233,
    // matching this checkpoint. Together they constitute the v4.1
    // mandatory upgrade.
    params.checkpoints.emplace_back(44233, uint256S("927a1e79a410e73c1778dd3eaebae1c07ce5271431abffa9b62a6f6b3177e373"));

    // v4.4 chainstate-integrity anchor: lower bound of the rolling integrity-check
    // window (highest_checkpoint+1 .. tip). Verified unanimous across all 4 DilV
    // mainnet seeds 2026-05-06. See v4_4_chainstate_integrity_contract.md decision (a).
    params.checkpoints.emplace_back(47500, uint256S("1094f7ca0197845a120a5440ce01c88e65b72f84f42a456f29e43c81b0cddbce"));

    // v4.1 lifetime-miner deterministic snapshot (closes CRIT-1 from
    // v0.1 spec review — non-deterministic Patch C lifetime gate at
    // activation height if pre-44233 history is ingested differently
    // across nodes). Placeholder = 0 disables the assertion (gated on
    // > 0 in startup_checkpoint_validator.cpp::ValidateLifetimeMinerSnapshot).
    // Pass-1 build runs on a clean datadir, IBDs to >= 44232, queries
    // getfullmikdistribution {"maxHeight": 44232}, and the unique_miners
    // count is embedded here for the pass-2 release build.
    //
    // PRE-RELEASE GATE: grep this file for lifetimeMinerCountAt44232; the
    // value MUST be > 0 before tagging v4.1 (the release SOP includes
    // this check).
    params.lifetimeMinerCountAt44232 = 255;  // v4.1.2 re-capture 2026-05-03: original 65 was from the BUGGY sliding-window query (window=200, captured at tip=44233) and never matched the fixed lifetime-store semantic. Re-captured 2026-05-03 against the canonical chain (Phase 1 checkpoint at 44233 = 927a1e79... passed). Three independent computations on chains whose Phase 1 passed (SYD live, user's local Windows, LDN-source snapshot) converged on 255.

    // No assume-valid yet
    params.defaultAssumeValid = "";

    // =========================================================================
    // Pre-funded addresses: balance restoration from chain reset
    // Generated by chain_forensics.py at height 36202 (2026-03-27)
    // 146 legitimate addresses + bridge backing for 297,987 wDILV
    // Exploiter addresses (9,389) excluded via transaction graph analysis
    // =========================================================================
    #include "dilv_prefund.inc"

    return params;
}

// ===========================================================================
// Phase 5 (2026-04-26): Regression-test mode.
// ===========================================================================
//
// Regtest is a deterministic, isolated network for byte-equivalence
// integration tests. Built on the testnet baseline with these overrides:
//   * Distinct network magic + ports (no cross-contamination)
//   * No checkpoints (reorgs can be tested freely)
//   * Reduced VDF iterations for fast block generation
//   * Short grace period + faster block time for tests
//   * No pre-funded addresses
//
// Used by: tools/run_phase5_v2_byte_equivalence.sh and similar test
// scripts that spin up two binaries with different env-var settings,
// mine N blocks, and compare LevelDB hashes.
ChainParams ChainParams::Regtest() {
    // Start from testnet (most permissive baseline) and override.
    ChainParams params = Testnet();
    params.network = REGTEST;

    // Network identification — distinct from mainnet/testnet/dilv.
    params.networkMagic = 0xDA8FB5BB;  // Regtest magic
    params.chainID = 9999;             // Regtest chain ID

    // Distinct ports for regtest (allow running alongside any other network).
    params.p2pPort = 19444;
    params.rpcPort = 19332;

    // Regtest datadir.
    params.dataDir = GetDataDir(false) + "-regtest";

    // No checkpoints — regtest exists to test reorgs, including deep ones.
    params.checkpoints.clear();
    params.defaultAssumeValid = "";

    // Identifying coinbase message for regtest blocks.
    params.genesisCoinbaseMsg = "Dilithion Regtest";
    params.genesisHash = "";  // computed at startup

    // Phase 5 (2026-04-26): regtest IS a VDF chain, run via dilv-node binary.
    //
    // Why dilv-node: dilithion-node calls Genesis::CreateGenesisBlock() at
    // boot (non-VDF path), which fails IsGenesisBlock's nVersion check
    // when genesis params indicate VDF-from-genesis. dilv-node correctly
    // calls CreateDilVGenesisBlock(), so a fresh regtest datadir loads
    // cleanly there.
    //
    // The chain-selection algorithm is chain-agnostic (same CChainState,
    // same m_setBlockIndexCandidates, same ActivateBestChainStep
    // regardless of IHeaderProofChecker). V2 byte-equivalence on the
    // DilV-style regtest chain proves the algorithm equally for DIL.
    //
    // Reduced VDF iterations for fast block production in tests
    // (~0.4-0.8s per block at 50K iterations vs production's 500K).
    params.vdfIterations = 50000;
    params.vdfLotteryGracePeriod = 3;  // 3s grace
    params.blockTime = 3;              // 3s target

    // Phase 6 PR6.1: mapBlockIndex cap — regtest uses a SMALL cap (1000)
    // so cap-saturation tests can exercise eviction without flooding 500K+
    // headers. Override of inherited Testnet value.
    params.nMapBlockIndexCap = 1000;

    // Phase 8 PR8.0 (2026-05-01): disable the 45s minBlockTimestampGap
    // inherited from Testnet. Regtest inherits Testnet's gap = 45 + height = 0
    // ("active from genesis"), which throttles single-miner regtest setups
    // to ~45s/block — too slow to hit Phase 8 acceptance bars (≥20 blocks
    // within 60s for the 4-node harness). The gap is a Sybil/pacing rule
    // for production VDF chains; regtest is a deterministic single-process
    // (or few-process) lab environment with no Sybil surface to defend.
    // Disabling it lets blocks publish immediately after VDF + DFMP
    // validation succeed. Consensus-side check at pow.cpp:1422 is gated
    // on `minGap > 0`, so setting to 0 disables both the miner-side wait
    // (vdf_miner.cpp:396-407) AND the consensus-side enforcement.
    params.minBlockTimestampGap = 0;
    params.minBlockTimestampGapHeight = 0;

    // Phase 10 PR10.6-followup-2 (2026-05-02): disable Patch E (time-based
    // cooldown expiry retirement) on regtest. Patch E is a DilV-mainnet
    // incident-recovery rule that retires the "MIN_COOLDOWN=2 solo miner
    // waits ~95s via time-based expiry" path. Regtest inherits Testnet's
    // value of 0 (active from genesis), which deadlocks the single-miner
    // smoke harness at height 1: with cooldown=2 and time-based expiry
    // retired, the only escape is block-gap >= 2, but block 2 can never
    // be produced because block 2 IS what's blocked. Set to 999999999
    // (DIL-style sentinel) to keep the legacy time-based expiry path
    // active on regtest, matching the cooldown_tracker.h design comment.
    params.timeBasedCooldownExpiryRetiredHeight = 999999999;

    // v4.2.0 PR follow-up: disable time-decay cooldown on regtest as well, for
    // the same reason as Patch E — single-miner regtest harnesses need the
    // legacy time-based expiry to escape MIN_COOLDOWN=2. Above-activation
    // tests construct their own CCooldownTracker with explicit params and do
    // NOT rely on chainparams; so disabling the chainparams field here only
    // affects the regtest-via-chainparams path.
    params.timeDecayCooldownActivationHeight = 999999999;
    // ISSUE-2 (close-readiness): set every chain's cooldownTimeDecaySeconds
    // explicitly. Regtest copies from testnet which sets 60; if testnet were
    // to change to a different rate (e.g. 30 for fast cycles), regtest would
    // silently inherit it while having activation disabled — confusing.
    // Make the asymmetry explicit instead.
    params.cooldownTimeDecaySeconds = 60;

    return params;
}

} // namespace Dilithion
