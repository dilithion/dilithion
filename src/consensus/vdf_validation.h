#ifndef DILITHION_CONSENSUS_VDF_VALIDATION_H
#define DILITHION_CONSENSUS_VDF_VALIDATION_H

#include <primitives/block.h>
#include <array>
#include <string>
#include <vector>

/**
 * VDF consensus validation.
 *
 * Called by the PoW dispatcher when a block has version >= 4 (VDF block).
 * Validates:
 *   1. VDF proof is present in coinbase and matches header's vdfProofHash
 *   2. VDF proof verifies against the expected challenge
 *   3. VDF output in header matches the proof's output
 *
 * Note: Cooldown was miner-side policy until dfmpCooldownConsensusHeight.
 * After that height, CheckVDFCooldown() enforces cooldown at consensus.
 */

/**
 * Full VDF block validation.
 *
 * @param block         The candidate block (must be IsVDFBlock())
 * @param height        Block height
 * @param prevHash      Hash of the previous block (for challenge derivation)
 * @param vdfIterations Expected iteration count (from chainparams)
 * @param error         Human-readable error string on failure
 * @return true if VDF proof is valid and all consensus checks pass
 */
bool CheckVDFProof(
    const CBlock& block,
    int height,
    const uint256& prevHash,
    uint64_t vdfIterations,
    std::string& error
);

/**
 * Connect-path VDF enforcement seam (ECOSYSTEM_HUNT_FINDINGS #3 remediation).
 *
 * The SINGLE decision the connect path (CChainState::ConnectTip) makes about a
 * block's VDF proof, composed in one testable place:
 *   - Non-VDF (pre-v4) blocks and genesis (height 0) are exempt (return true).
 *   - The ~44 ms Wesolowski verify is skipped only when the assume-valid gate
 *     (ConnectPathVerifyVDF, reading vdfAssumeValidHeight) says so — i.e. a
 *     historical at/below-boundary block during IBD. Default vdfAssumeValidHeight
 *     == 0 => verify EVERY block from height 1; a tip/reorg block is never skipped.
 *   - Otherwise CheckVDFProof runs, covering BOTH the coinbase commitment
 *     (vdfProofHash == SHA3(proof)) and the class-group Wesolowski proof.
 *
 * Iteration count and the assume-valid height are read from Dilithion::g_chainParams
 * (fail-safe: null params => iterations 0 and vdfAssumeValidHeight 0 => verify).
 * Called from the reorg-safe section of ConnectTip so it runs for normal AND
 * reorg/fork-activation connects — a forged VDF block arriving as a reorg
 * candidate is the attack this closes.
 *
 * @param block                  The candidate block (block.vtx carries the coinbase).
 * @param nHeight                Height at which the block is being connected.
 * @param prevHash               Hash of the previous block (for challenge derivation).
 * @param fInitialBlockDownload  True iff the node is in initial block download.
 * @param error                  Human-readable rejection reason on failure.
 * @return true if the block's VDF proof is valid (or verification is exempt/skipped);
 *         false (with error set) if the VDF proof is invalid — abort the connect.
 */
bool ConnectPathCheckVDF(
    const CBlock& block,
    int nHeight,
    const uint256& prevHash,
    bool fInitialBlockDownload,
    std::string& error
);

/**
 * Compute the per-miner VDF challenge.
 *
 * challenge = SHA3-256( prevHash || height_le32 || minerAddress )
 *
 * Each miner gets a unique challenge derived from the previous block
 * and their payout address, ensuring independent VDF computations.
 */
std::array<uint8_t, 32> ComputeVDFChallenge(
    const uint256& prevHash,
    int height,
    const std::array<uint8_t, 20>& minerAddress
);

/**
 * Extract the miner's payout address (first 20 bytes of first output's
 * scriptPubKey) from the coinbase transaction.
 *
 * @param block  The block containing the coinbase
 * @param addr   Output: 20-byte address
 * @return true if extraction succeeded
 */
bool ExtractCoinbaseAddress(
    const CBlock& block,
    std::array<uint8_t, 20>& addr
);

/**
 * Extract the miner's MIK identity (20 bytes) from the coinbase scriptSig.
 *
 * Parses the MIK_MARKER (0xDF) section of the coinbase and returns the
 * 20-byte MIK identity.  Falls back to payout address if MIK is not present
 * (pre-MIK blocks or blocks without MIK data).
 *
 * @param block  The block containing the coinbase
 * @param mikId  Output: 20-byte MIK identity
 * @return true if extraction succeeded
 */
bool ExtractCoinbaseMIKIdentity(
    const CBlock& block,
    std::array<uint8_t, 20>& mikId
);

// Forward declarations
class CCooldownTracker;
namespace digital_dna { class IDNARegistry; }

/**
 * Check VDF cooldown consensus rule (hard fork).
 *
 * After dfmpCooldownConsensusHeight, rejects blocks where the miner's MIK
 * identity has mined within the cooldown period.
 *
 * @param block          The candidate block
 * @param height         Block height
 * @param tracker        Cooldown tracker with current chain state
 * @param error          Human-readable error string on failure
 * @param blockTimestamp Block's nTime for time-based cooldown expiry (0 = disabled)
 * @return true if block passes cooldown check (or not yet enforced)
 */
bool CheckVDFCooldown(
    const CBlock& block,
    int height,
    CCooldownTracker& tracker,
    std::string& error,
    int64_t blockTimestamp = 0
);

/**
 * Check DNA commitment in VDF block coinbase (Phase 3).
 *
 * After dnaCommitmentActivationHeight, VDF blocks must include a 0xDD + 32-byte
 * DNA hash in their coinbase scriptSig (after MIK data).
 *
 * @param block         The candidate VDF block
 * @param height        Block height
 * @param error         Human-readable error string on failure
 * @return true if block passes DNA commitment check (or pre-activation)
 */
bool CheckDNACommitment(
    const CBlock& block,
    int height,
    std::string& error
);

/**
 * Check DNA hash equality at consensus (Phase 5A).
 *
 * After dnaHashEnforcementHeight, the DNA hash committed in the coinbase
 * must match the hash of the DNA stored in the local registry for that MIK.
 * If the MIK has no DNA on file, the check passes (can't verify).
 *
 * @param block         The candidate VDF block
 * @param height        Block height
 * @param registry      DNA registry with stored identities
 * @param error         Human-readable error string on failure
 * @return true if hash matches or cannot be verified (no local DNA)
 */
bool CheckDNAHashEquality(
    const CBlock& block,
    int height,
    const digital_dna::IDNARegistry& registry,
    std::string& error
);

// Forward declaration
class CBlockchainDB;
class CBlockIndex;

/**
 * Check for consecutive same-miner blocks (hard fork).
 *
 * After consecutiveMinerCheckHeight, rejects VDF blocks where the same
 * MIK identity has mined more than MAX_CONSECUTIVE_SAME_MINER consecutive
 * blocks. Exception: solo miner (1 active miner in cooldown window).
 *
 * @param block         The candidate VDF block
 * @param pindex        Block index with parent chain linkage
 * @param db            Blockchain database (to load previous blocks)
 * @param tracker       Cooldown tracker (for active miner count)
 * @param error         Human-readable error string on failure
 * @return true if block passes consecutive miner check
 */
bool CheckConsecutiveMiner(
    const CBlock& block,
    const CBlockIndex* pindex,
    CBlockchainDB* db,
    CCooldownTracker& tracker,
    std::string& error
);

/**
 * Check per-MIK window cap (hard fork).
 *
 * Rejects blocks where the miner's MIK identity has already mined
 * mikWindowCapFloor blocks in the trailing mikWindowCapWindow blocks.
 *
 * Exemptions:
 *   - Solo miner (activeMiners <= 1): cap disabled to prevent chain stall
 *   - Liveness timeout: if no block for livenessTimeoutSec seconds, cap
 *     suspended until chain advances (prevents deadlock when all miners capped)
 *
 * @param block          The candidate VDF block
 * @param height         Block height
 * @param tracker        Cooldown tracker with current chain state
 * @param prevBlockTime  Timestamp of the previous block (for liveness check)
 * @param blockTime      Timestamp of the candidate block
 * @param error          Human-readable error string on failure
 * @return true if block passes window cap check
 */
bool CheckMIKWindowCap(
    const CBlock& block,
    int height,
    CCooldownTracker& tracker,
    int64_t prevBlockTime,
    int64_t blockTime,
    std::string& error
);

/**
 * Check seed attestations in MIK registration block (Phase 2+3).
 *
 * After seedAttestationActivationHeight, MIK registration blocks must include
 * 3+ valid attestations signed by known seed node public keys. Attestations
 * prove the miner's IP was verified as non-datacenter at registration time.
 *
 * Only applies to MIK registration blocks (type 0x01). Reference blocks
 * (type 0x02) do not need attestations — the MIK was already attested.
 *
 * @param block         The candidate VDF block
 * @param height        Block height
 * @param error         Human-readable error string on failure
 * @return true if block passes attestation check (or pre-activation, or not registration)
 */
bool CheckMIKAttestations(
    const CBlock& block,
    int height,
    std::string& error
);

/**
 * Check MIK expiration (Layer 2 Sybil Defense, hard fork).
 *
 * After mikExpirationActivationHeight, reference blocks (type 0x02) from
 * MIK identities that haven't mined in mikExpirationThreshold blocks are
 * rejected. The MIK must re-register with a full registration block (0x01).
 *
 * Registration blocks always pass. Depends on identity DB (GetLastMined).
 *
 * FAILS CLOSED post-activation: an empty vtx, unparseable tx-count/coinbase,
 * non-coinbase-form first tx, missing MIK data, or unavailable identity DB
 * returns false (with error set) — the block has not proven its identity is
 * unexpired. Pre-activation always returns true. NOT reorg-safe (identity-DB
 * dependent) — callers keep it inside the !skipValidation gate.
 */
bool CheckMIKExpiration(
    const CBlock& block,
    int height,
    std::string& error
);

class CCooldownTracker;  // forward declaration

/**
 * Check MIK registration rate limit (Layer 3 Sybil Defense, hard fork).
 *
 * After mikRegistrationRateLimitHeight, reject registration blocks if more
 * than mikRegistrationMaxPerWindow new registrations have occurred in the
 * trailing mikRegistrationRateWindow blocks.
 *
 * Reference blocks always pass. Uses cooldown tracker (reorg-safe).
 */
bool CheckRegistrationRateLimit(
    const CBlock& block,
    int height,
    CCooldownTracker& tracker,
    std::string& error
);

/**
 * Option C preflight for VDF same-height replacement/tiebreak:
 * checks replacement block against DFMP rules using simulated tracker state
 * with the current tip height excluded.
 */
bool CheckVDFReplacementPreflight(
    const CBlock& block,
    const CBlockIndex* pindexNew,
    const CBlockIndex* pindexTip,
    CBlockchainDB* db,
    int height,
    CCooldownTracker& tracker,
    std::string& error
);

#endif // DILITHION_CONSENSUS_VDF_VALIDATION_H
