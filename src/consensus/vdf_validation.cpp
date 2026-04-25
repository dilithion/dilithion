// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/vdf_validation.h>
#include <consensus/validation.h>
#include <vdf/vdf.h>
#include <vdf/coinbase_vdf.h>
#include <vdf/cooldown_tracker.h>
#include <dfmp/mik.h>
#include <dfmp/dfmp.h>
#include <dfmp/identity_db.h>
#include <core/chainparams.h>
#include <digital_dna/digital_dna.h>
#include <node/blockchain_storage.h>
#include <node/block_index.h>
#include <attestation/seed_attestation.h>
#include <crypto/sha3.h>
#include <cstring>
#include <iostream>
#include <sstream>

// ---------------------------------------------------------------------------
// ComputeVDFChallenge
// ---------------------------------------------------------------------------

std::array<uint8_t, 32> ComputeVDFChallenge(
    const uint256& prevHash,
    int height,
    const std::array<uint8_t, 20>& minerAddress)
{
    // Preimage: prevHash(32) || height_le32(4) || minerAddress(20) = 56 bytes
    uint8_t preimage[56];
    std::memcpy(preimage,      prevHash.data, 32);
    uint32_t hLE = static_cast<uint32_t>(height);
    std::memcpy(preimage + 32, &hLE, 4);
    std::memcpy(preimage + 36, minerAddress.data(), 20);

    std::array<uint8_t, 32> challenge{};
    SHA3_256(preimage, sizeof(preimage), challenge.data());
    return challenge;
}

// ---------------------------------------------------------------------------
// ExtractCoinbaseAddress
// ---------------------------------------------------------------------------

bool ExtractCoinbaseAddress(
    const CBlock& block,
    std::array<uint8_t, 20>& addr)
{
    if (block.vtx.empty())
        return false;

    // Deserialize just the coinbase transaction.
    CBlockValidator validator;
    std::vector<CTransactionRef> txs;
    std::string err;
    if (!validator.DeserializeBlockTransactions(block, txs, err) || txs.empty())
        return false;

    const CTransaction& coinbase = *txs[0];
    if (!coinbase.IsCoinBase())
        return false;

    // The miner's payout address is the first 20 bytes of the first
    // output's scriptPubKey (P2PKH format: OP_DUP OP_HASH160 <20 bytes> ...).
    // In Dilithion P2PKH the address bytes start at scriptPubKey[3].
    if (coinbase.vout.empty())
        return false;

    const auto& spk = coinbase.vout[0].scriptPubKey;
    // Minimum P2PKH: OP_DUP(1) OP_HASH160(1) OP_PUSH20(1) <20> OP_EQUALVERIFY(1) OP_CHECKSIG(1) = 25
    if (spk.size() < 25)
        return false;

    std::memcpy(addr.data(), spk.data() + 3, 20);
    return true;
}

// ---------------------------------------------------------------------------
// ExtractCoinbaseMIKIdentity
// ---------------------------------------------------------------------------

bool ExtractCoinbaseMIKIdentity(
    const CBlock& block,
    std::array<uint8_t, 20>& mikId)
{
    if (block.vtx.empty())
        return false;

    CBlockValidator validator;
    std::vector<CTransactionRef> txs;
    std::string err;
    if (!validator.DeserializeBlockTransactions(block, txs, err) || txs.empty())
        return false;

    const CTransaction& coinbase = *txs[0];
    if (!coinbase.IsCoinBase() || coinbase.vin.empty())
        return false;

    // Try to parse MIK from coinbase scriptSig
    DFMP::CMIKScriptData mikData;
    if (DFMP::ParseMIKFromScriptSig(coinbase.vin[0].scriptSig, mikData) &&
        !mikData.identity.IsNull()) {
        std::memcpy(mikId.data(), mikData.identity.data, 20);
        return true;
    }

    // Fallback: use payout address for pre-MIK blocks
    return ExtractCoinbaseAddress(block, mikId);
}

// ---------------------------------------------------------------------------
// CheckVDFProof
// ---------------------------------------------------------------------------

bool CheckVDFProof(
    const CBlock& block,
    int height,
    const uint256& prevHash,
    uint64_t vdfIterations,
    std::string& error)
{
    // 1. Block must be a VDF block.
    if (!block.IsVDFBlock()) {
        error = "CheckVDFProof: block is not version >= 4";
        return false;
    }

    // 2. vdfOutput must not be null.
    if (block.vdfOutput.IsNull()) {
        error = "CheckVDFProof: vdfOutput is null";
        return false;
    }

    // 3. vdfProofHash must not be null.
    if (block.vdfProofHash.IsNull()) {
        error = "CheckVDFProof: vdfProofHash is null";
        return false;
    }

    // 4. Extract VDF proof from coinbase scriptSig.
    CBlockValidator validator;
    std::vector<CTransactionRef> txs;
    std::string deserErr;
    if (!validator.DeserializeBlockTransactions(block, txs, deserErr) || txs.empty()) {
        error = "CheckVDFProof: failed to deserialize coinbase: " + deserErr;
        return false;
    }

    const CTransaction& coinbase = *txs[0];
    if (!coinbase.IsCoinBase()) {
        error = "CheckVDFProof: first transaction is not coinbase";
        return false;
    }

    std::vector<uint8_t> proof = CoinbaseVDF::ExtractProof(coinbase.vin[0].scriptSig);
    if (proof.empty()) {
        error = "CheckVDFProof: no VDF proof found in coinbase scriptSig";
        return false;
    }

    // 5. Verify proof hash commitment: SHA3-256(proof) == header.vdfProofHash.
    uint256 computedHash = CoinbaseVDF::ComputeProofHash(proof);
    if (computedHash != block.vdfProofHash) {
        error = "CheckVDFProof: proof hash mismatch (commitment failed)";
        return false;
    }

    // 6. Extract miner address from coinbase.
    std::array<uint8_t, 20> minerAddr{};
    if (!ExtractCoinbaseAddress(block, minerAddr)) {
        error = "CheckVDFProof: cannot extract miner address from coinbase";
        return false;
    }

    // 7. Compute expected challenge.
    std::array<uint8_t, 32> challenge = ComputeVDFChallenge(prevHash, height, minerAddr);

    // 8. Reconstruct VDFResult and verify the Wesolowski proof via chiavdf.
    vdf::VDFResult result;
    std::memcpy(result.output.data(), block.vdfOutput.data, 32);
    result.proof = proof;
    result.iterations = vdfIterations;
    result.duration_us = 0; // not needed for verification

    vdf::VDFConfig cfg;
    cfg.target_iterations = vdfIterations;

    if (!vdf::verify(challenge, result, cfg)) {
        error = "CheckVDFProof: Wesolowski proof verification failed";
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// CheckVDFCooldown  (consensus-enforced cooldown — hard fork)
// ---------------------------------------------------------------------------

bool CheckVDFCooldown(
    const CBlock& block,
    int height,
    CCooldownTracker& tracker,
    std::string& error,
    int64_t blockTimestamp)
{
    // Gate: only enforce after activation height
    int activationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpCooldownConsensusHeight : 999999999;
    if (height < activationHeight)
        return true;

    // Only applies to VDF blocks
    if (!block.IsVDFBlock())
        return true;

    // Genesis is always exempt
    if (height == 0)
        return true;

    // Extract MIK identity from coinbase
    std::array<uint8_t, 20> mikId{};
    if (!ExtractCoinbaseMIKIdentity(block, mikId)) {
        error = "CheckVDFCooldown: cannot extract MIK identity from coinbase";
        return false;
    }

    // Check if this MIK is in cooldown (pass timestamp for time-based expiry)
    // DEBUG: log cooldown state for diagnosis
    {
        int dbgLastWin = tracker.GetLastWinHeight(mikId);
        int dbgCooldown = tracker.GetEffectiveCooldown(height);
        int dbgActive = tracker.GetActiveMiners();
        int dbgGap = (dbgLastWin >= 0) ? (height - dbgLastWin) : -1;
        if (dbgLastWin >= 0 && dbgGap < dbgCooldown) {
            std::cerr << "[CooldownDBG] h=" << height << " mik=" << std::hex;
            for (int i = 0; i < 4; i++) { char h2[3]; snprintf(h2,3,"%02x",mikId[i]); std::cerr << h2; }
            std::cerr << std::dec << " lastWin=" << dbgLastWin << " gap=" << dbgGap
                      << " cooldown=" << dbgCooldown << " active=" << dbgActive
                      << " blockTs=" << blockTimestamp << std::endl;
        }
    }
    if (tracker.IsInCooldown(mikId, height, blockTimestamp)) {
        int lastWin = tracker.GetLastWinHeight(mikId);
        int cooldown = tracker.GetCooldownBlocks();
        int activeMiners = tracker.GetActiveMiners();

        std::ostringstream oss;
        oss << "CheckVDFCooldown: MIK ";
        for (int i = 0; i < 4; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", mikId[i]);
            oss << hex;
        }
        oss << "... violated cooldown (last win: " << lastWin
            << ", cooldown: " << cooldown
            << ", active miners: " << activeMiners
            << ", height: " << height
            << ", gap: " << (height - lastWin) << ")";
        error = oss.str();
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// CheckConsecutiveMiner  (consensus-enforced — hard fork)
// ---------------------------------------------------------------------------

bool CheckConsecutiveMiner(
    const CBlock& block,
    const CBlockIndex* pindex,
    CBlockchainDB* db,
    CCooldownTracker& tracker,
    std::string& error)
{
    static constexpr int MAX_CONSECUTIVE_SAME_MINER = 3;

    // Gate: only enforce after activation height
    int activationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->consecutiveMinerCheckHeight : 999999999;
    if (pindex->nHeight < activationHeight)
        return true;

    // Only applies to VDF blocks
    if (!block.IsVDFBlock())
        return true;

    // Extract this block's miner identity first (needed for solo check below)
    std::array<uint8_t, 20> currentMik{};
    if (!ExtractCoinbaseMIKIdentity(block, currentMik)) {
        error = "CheckConsecutiveMiner: cannot extract MIK identity";
        return false;
    }

    // Solo miner exemption — a lone miner must be able to keep the chain alive.
    // Force recalc at this height to avoid stale cache (Cursor review finding #2).
    tracker.IsInCooldown(currentMik, pindex->nHeight);
    int activeMiners = tracker.GetActiveMiners();

    // v4.0.21 — Patch C: tighten solo-miner exemption with deterministic
    // lifetime gate. Pre-fix bug (incident 2026-04-25): if the active sliding
    // window happened to contain mostly one MIK's blocks (Vector 3
    // self-reinforcing dominance), activeMiners reports 1, solo exemption
    // fires, that MIK keeps mining freely. New rule: solo exemption only
    // applies if BOTH activeMiners <= 1 AND the chain has had <= bootstrap
    // threshold (5) distinct MIKs in its entire history. Once the chain has
    // seen more miners, "solo" is no longer a legitimate state — it's a
    // concentration symptom and the consecutive-miner cap applies.
    int soloLifetimeGateHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->soloExemptionLifetimeGateHeight : 999999999;
    constexpr int kBootstrapMinerThreshold = 5;
    if (activeMiners <= 1) {
        if (pindex->nHeight < soloLifetimeGateHeight) {
            // Pre-activation: original solo exemption applies (no lifetime gate).
            return true;
        }
        // Post-activation: solo exemption gated on lifetime miner count.
        int lifetimeMiners = tracker.GetLifetimeMinerCount();
        if (lifetimeMiners <= kBootstrapMinerThreshold) {
            return true;  // genuine bootstrap network, allow solo
        }
        // Otherwise: even though activeMiners is 1 right now, the chain has
        // seen many distinct MIKs over its history — fall through to consecutive
        // check. The rule will reject 4+ same-MIK in a row even with reported
        // activeMiners=1. Network self-heals as other miners come back online.
    }

    // Walk back through parent chain, counting consecutive same-miner blocks
    int consecutiveCount = 0;
    const CBlockIndex* pWalk = pindex->pprev;

    while (pWalk && consecutiveCount < MAX_CONSECUTIVE_SAME_MINER && db) {
        CBlock prevBlock;
        if (!db->ReadBlock(pWalk->GetBlockHash(), prevBlock))
            break;

        std::array<uint8_t, 20> prevMik{};
        if (!ExtractCoinbaseMIKIdentity(prevBlock, prevMik))
            break;

        if (prevMik != currentMik)
            break;

        consecutiveCount++;
        pWalk = pWalk->pprev;
    }

    if (consecutiveCount >= MAX_CONSECUTIVE_SAME_MINER) {
        // v4.0.21 — Patch A: retire stall exemption above activation height.
        // The 1-hour stall exemption was an attack surface during the 2026-04-25
        // incident. With 50+ active miners, a 1-hour stall is not a real failure
        // mode; if it does happen, operator action (forcerebuild RPC, manual
        // intervention) is the right response, not a quiet rule bypass.
        // For activation see consecutiveMinerStallExemptionRetiredHeight (DilV: 44600).
        // For pre-activation history we keep the original behaviour so this
        // change is forward-only and does not invalidate existing chain history.
        int stallRetiredHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->consecutiveMinerStallExemptionRetiredHeight : 999999999;

        if (pindex->nHeight < stallRetiredHeight) {
            // Pre-activation: original stall exemption applies.
            // Stall exemption: if no block has been produced for a long time,
            // allow the same miner past the consecutive limit to keep the chain
            // alive. 3600s threshold = ~3 blocks/hour for a solo miner.
            static constexpr int64_t CONSECUTIVE_STALL_THRESHOLD_SECS = 3600;

            if (pindex->pprev) {
                int64_t gap = static_cast<int64_t>(block.nTime) -
                              static_cast<int64_t>(pindex->pprev->nTime);
                if (gap >= CONSECUTIVE_STALL_THRESHOLD_SECS) {
                    std::cout << "[Chain] CheckConsecutiveMiner: stall exemption at height "
                              << pindex->nHeight << " (gap=" << gap
                              << "s >= " << CONSECUTIVE_STALL_THRESHOLD_SECS << "s, "
                              << (consecutiveCount + 1) << " consecutive)" << std::endl;
                    return true;
                }
            }
        }
        // Post-activation OR no stall exemption matched: fall through to error below.

        std::ostringstream oss;
        oss << "CheckConsecutiveMiner: MIK ";
        for (int i = 0; i < 4; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", currentMik[i]);
            oss << hex;
        }
        oss << "... has mined " << (consecutiveCount + 1)
            << " consecutive blocks (max " << MAX_CONSECUTIVE_SAME_MINER
            << ", active miners: " << activeMiners << ")";
        error = oss.str();
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// CheckDNACommitment
// ---------------------------------------------------------------------------

bool CheckDNACommitment(
    const CBlock& block,
    int height,
    std::string& error)
{
    // Pre-activation: always pass
    int activationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dnaCommitmentActivationHeight : 999999999;
    if (height < activationHeight) {
        return true;
    }

    // Only applies to VDF blocks
    if (!block.IsVDFBlock()) {
        return true;
    }

    // Deserialize coinbase to get scriptSig
    if (block.vtx.empty()) {
        error = "CheckDNACommitment: empty vtx";
        return false;
    }

    const uint8_t* data = block.vtx.data();
    size_t dataSize = block.vtx.size();

    // Parse tx count varint
    size_t txCountSize = 0;
    if (data[0] < 253) {
        txCountSize = 1;
    } else if (data[0] == 253 && dataSize >= 3) {
        txCountSize = 3;
    } else {
        error = "CheckDNACommitment: unsupported tx count encoding";
        return false;
    }

    // Deserialize coinbase
    CTransaction coinbase;
    size_t consumed = 0;
    if (!coinbase.Deserialize(data + txCountSize, dataSize - txCountSize, nullptr, &consumed)) {
        error = "CheckDNACommitment: failed to deserialize coinbase";
        return false;
    }

    if (coinbase.vin.empty()) {
        error = "CheckDNACommitment: coinbase has no inputs";
        return false;
    }

    // Parse MIK data from scriptSig — DNA commitment is parsed automatically
    DFMP::CMIKScriptData mikData;
    if (!DFMP::ParseMIKFromScriptSig(coinbase.vin[0].scriptSig, mikData)) {
        error = "CheckDNACommitment: failed to parse MIK from coinbase";
        return false;
    }

    // Post-activation: DNA commitment must be present
    if (!mikData.has_dna_hash) {
        error = "CheckDNACommitment: missing DNA commitment (0xDD marker) in VDF block at height " + std::to_string(height);
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// CheckDNAHashEquality  (Phase 5A — hash-equality consensus enforcement)
// ---------------------------------------------------------------------------

bool CheckDNAHashEquality(
    const CBlock& block,
    int height,
    const digital_dna::IDNARegistry& registry,
    std::string& error)
{
    // Pre-activation: always pass
    int enforcementHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dnaHashEnforcementHeight : 999999999;
    if (height < enforcementHeight) {
        return true;
    }

    // Only applies to VDF blocks
    if (!block.IsVDFBlock()) {
        return true;
    }

    // Deserialize coinbase
    if (block.vtx.empty()) {
        error = "CheckDNAHashEquality: empty vtx";
        return false;
    }

    const uint8_t* data = block.vtx.data();
    size_t dataSize = block.vtx.size();

    size_t txCountSize = 0;
    if (data[0] < 253) {
        txCountSize = 1;
    } else if (data[0] == 253 && dataSize >= 3) {
        txCountSize = 3;
    } else {
        error = "CheckDNAHashEquality: unsupported tx count encoding";
        return false;
    }

    CTransaction coinbase;
    size_t consumed = 0;
    if (!coinbase.Deserialize(data + txCountSize, dataSize - txCountSize, nullptr, &consumed)) {
        error = "CheckDNAHashEquality: failed to deserialize coinbase";
        return false;
    }

    if (coinbase.vin.empty()) {
        error = "CheckDNAHashEquality: coinbase has no inputs";
        return false;
    }

    // Parse MIK + DNA commitment from scriptSig
    DFMP::CMIKScriptData mikData;
    if (!DFMP::ParseMIKFromScriptSig(coinbase.vin[0].scriptSig, mikData)) {
        error = "CheckDNAHashEquality: failed to parse MIK from coinbase";
        return false;
    }

    // No DNA commitment → can't check equality (CheckDNACommitment handles presence)
    if (!mikData.has_dna_hash) {
        return true;
    }

    // Look up the MIK identity in the local registry
    std::array<uint8_t, 20> mikArr{};
    std::copy(mikData.identity.data, mikData.identity.data + 20, mikArr.begin());

    auto existing = registry.get_identity_by_mik(mikArr);
    if (!existing) {
        // No DNA on file for this MIK — can't verify, pass
        return true;
    }

    // Compare committed hash against local hash
    auto localHash = existing->hash();
    if (localHash != mikData.dna_hash) {
        std::ostringstream oss;
        oss << "CheckDNAHashEquality: DNA hash mismatch at height " << height
            << " for MIK ";
        for (int i = 0; i < 4; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", mikArr[i]);
            oss << hex;
        }
        oss << "... (committed ";
        for (int i = 0; i < 4; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", mikData.dna_hash[i]);
            oss << hex;
        }
        oss << "... != local ";
        for (int i = 0; i < 4; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", localHash[i]);
            oss << hex;
        }
        oss << "...)";
        error = oss.str();
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// CheckMIKWindowCap — per-MIK block cap in a rolling window
// ---------------------------------------------------------------------------

bool CheckMIKWindowCap(
    const CBlock& block,
    int height,
    CCooldownTracker& tracker,
    int64_t prevBlockTime,
    int64_t blockTime,
    std::string& error)
{
    // Gate: only enforce when window cap is configured
    if (!Dilithion::g_chainParams)
        return true;

    int window = Dilithion::g_chainParams->mikWindowCapWindow;
    int cap = Dilithion::g_chainParams->mikWindowCapFloor;
    if (window <= 0 || cap <= 0)
        return true;

    // Only applies to VDF blocks
    if (!block.IsVDFBlock())
        return true;

    // Genesis is always exempt
    if (height == 0)
        return true;

    // Solo miner exemption: if only 1 active miner, cap disabled
    int activeMiners = tracker.GetActiveMiners();
    if (activeMiners <= 1)
        return true;

    // Liveness escape: if no block for livenessTimeoutSec, cap suspended
    int livenessTimeout = Dilithion::g_chainParams->livenessTimeoutSec;
    if (livenessTimeout > 0 && prevBlockTime > 0 && blockTime > 0) {
        int64_t gap = blockTime - prevBlockTime;
        if (gap >= livenessTimeout)
            return true;  // chain stall — let any miner produce a block
    }

    // Extract MIK identity
    std::array<uint8_t, 20> mikId{};
    if (!ExtractCoinbaseMIKIdentity(block, mikId)) {
        error = "CheckMIKWindowCap: cannot extract MIK identity from coinbase";
        return false;
    }

    // Count blocks by this MIK in the trailing window (exclude current height)
    int count = tracker.GetBlockCountInWindow(mikId, height - 1, window);
    if (count >= cap) {
        std::ostringstream oss;
        oss << "CheckMIKWindowCap: MIK ";
        for (int i = 0; i < 4; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", mikId[i]);
            oss << hex;
        }
        oss << "... exceeded window cap (" << count << " blocks in "
            << window << "-block window, cap=" << cap
            << ", active miners=" << activeMiners << ")";
        error = oss.str();
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// CheckMIKAttestations (Phase 2+3 — seed-attested MIK registration)
// ---------------------------------------------------------------------------

bool CheckMIKAttestations(
    const CBlock& block,
    int height,
    std::string& error)
{
    // Pre-activation: always pass
    // DIL activates at height 40,000; DilV at height 2,000
    int activationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->seedAttestationActivationHeight : 999999999;
    if (height < activationHeight) {
        return true;
    }

    // Deserialize coinbase
    if (block.vtx.empty()) {
        error = "CheckMIKAttestations: empty vtx";
        return false;
    }

    const uint8_t* data = block.vtx.data();
    size_t dataSize = block.vtx.size();

    // Parse tx count varint
    size_t txCountSize = 0;
    if (data[0] < 253) {
        txCountSize = 1;
    } else if (data[0] == 253 && dataSize >= 3) {
        txCountSize = 3;
    } else {
        error = "CheckMIKAttestations: unsupported tx count encoding";
        return false;
    }

    CTransaction coinbase;
    size_t consumed = 0;
    if (!coinbase.Deserialize(data + txCountSize, dataSize - txCountSize, nullptr, &consumed)) {
        error = "CheckMIKAttestations: failed to deserialize coinbase";
        return false;
    }

    if (coinbase.vin.empty()) {
        error = "CheckMIKAttestations: coinbase has no inputs";
        return false;
    }

    // Parse MIK data from scriptSig
    DFMP::CMIKScriptData mikData;
    if (!DFMP::ParseMIKFromScriptSig(coinbase.vin[0].scriptSig, mikData)) {
        error = "CheckMIKAttestations: failed to parse MIK from coinbase";
        return false;
    }

    // Only registration blocks need attestations
    if (!mikData.isRegistration) {
        return true;  // Reference block — MIK was already attested at registration
    }

    // Registration block: must have attestation data
    if (!mikData.has_attestations) {
        error = "CheckMIKAttestations: MIK registration at height " +
                std::to_string(height) + " missing required seed attestations";
        return false;
    }

    if (mikData.attestation_count < Attestation::MIN_ATTESTATIONS) {
        error = "CheckMIKAttestations: insufficient attestations: " +
                std::to_string(mikData.attestation_count) + " < " +
                std::to_string(Attestation::MIN_ATTESTATIONS);
        return false;
    }

    // Get seed public keys from chainparams
    const auto& seedPubkeys = Dilithion::g_chainParams->seedAttestationPubkeys;
    if (seedPubkeys.size() != Attestation::NUM_SEEDS) {
        error = "CheckMIKAttestations: chainparams has " +
                std::to_string(seedPubkeys.size()) + " seed pubkeys, expected " +
                std::to_string(Attestation::NUM_SEEDS);
        return false;
    }

    // Get DNA hash from parsed MIK data
    std::array<uint8_t, 32> dnaHash{};
    if (mikData.has_dna_hash) {
        dnaHash = mikData.dna_hash;
    }

    // Build attestation set for verification
    Attestation::CAttestationSet attestSet;
    for (const auto& entry : mikData.attestations) {
        Attestation::CAttestation att;
        att.seedId = entry.seedId;
        att.timestamp = entry.timestamp;
        att.signature = entry.signature;
        attestSet.attestations.push_back(std::move(att));
    }

    // Verify attestations
    int64_t blockTimestamp = block.nTime;
    std::string verifyError;
    if (!Attestation::VerifyAttestationSet(
            attestSet, mikData.pubkey, dnaHash,
            seedPubkeys, blockTimestamp, verifyError)) {
        error = "CheckMIKAttestations: " + verifyError + " at height " + std::to_string(height);
        return false;
    }

    return true;
}

// ============================================================================
// Layer 2 Sybil Defense: MIK Expiration After Dormancy
// ============================================================================

bool CheckMIKExpiration(
    const CBlock& block,
    int height,
    std::string& error)
{
    // Pre-activation: always pass
    int activationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->mikExpirationActivationHeight : 999999999;
    if (height < activationHeight) {
        return true;
    }

    int threshold = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->mikExpirationThreshold : 5760;

    // Deserialize coinbase
    if (block.vtx.empty()) {
        return true;  // No coinbase to check
    }

    const uint8_t* data = block.vtx.data();
    size_t dataSize = block.vtx.size();

    // Parse tx count varint
    size_t txCountSize = 0;
    if (data[0] < 253) {
        txCountSize = 1;
    } else if (data[0] == 253 && dataSize >= 3) {
        txCountSize = 3;
    } else {
        return true;  // Can't parse — let other checks handle
    }

    CTransaction coinbase;
    size_t consumed = 0;
    if (!coinbase.Deserialize(data + txCountSize, dataSize - txCountSize, nullptr, &consumed)) {
        return true;  // Can't parse — let other checks handle
    }

    if (coinbase.vin.empty()) {
        return true;
    }

    // Parse MIK data
    DFMP::CMIKScriptData mikData;
    if (!DFMP::ParseMIKFromScriptSig(coinbase.vin[0].scriptSig, mikData)) {
        return true;  // No MIK data — let other checks handle
    }

    // Registration blocks always pass (re-registering is the cure for expiration)
    if (mikData.isRegistration) {
        return true;
    }

    // Reference block: check if MIK is expired
    if (!DFMP::g_identityDb) {
        return true;  // No identity DB — can't check
    }

    int lastMined = DFMP::g_identityDb->GetLastMined(mikData.identity);
    if (lastMined < 0) {
        // Never mined before — check first-seen as fallback
        int firstSeen = DFMP::g_identityDb->GetFirstSeen(mikData.identity);
        if (firstSeen >= 0) {
            lastMined = firstSeen;  // Use registration height as anchor
        } else {
            // Unknown identity using a reference block — reject
            error = "CheckMIKExpiration: unknown identity using reference block at height " +
                    std::to_string(height);
            return false;
        }
    }

    if (height - lastMined > threshold) {
        error = "CheckMIKExpiration: MIK expired at height " + std::to_string(height) +
                " (last mined at " + std::to_string(lastMined) +
                ", dormant " + std::to_string(height - lastMined) +
                " blocks, threshold " + std::to_string(threshold) +
                "). Must re-register with type 0x01 and fresh attestations.";
        return false;
    }

    return true;
}

// ============================================================================
// Layer 3 Sybil Defense: Registration Rate Limit
// ============================================================================

bool CheckRegistrationRateLimit(
    const CBlock& block,
    int height,
    CCooldownTracker& tracker,
    std::string& error)
{
    // Pre-activation: always pass
    int activationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->mikRegistrationRateLimitHeight : 999999999;
    if (height < activationHeight) {
        return true;
    }

    int window = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->mikRegistrationRateWindow : 200;
    int maxPerWindow = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->mikRegistrationMaxPerWindow : 10;

    // Deserialize coinbase
    if (block.vtx.empty()) {
        return true;
    }

    const uint8_t* data = block.vtx.data();
    size_t dataSize = block.vtx.size();

    size_t txCountSize = 0;
    if (data[0] < 253) {
        txCountSize = 1;
    } else if (data[0] == 253 && dataSize >= 3) {
        txCountSize = 3;
    } else {
        return true;
    }

    CTransaction coinbase;
    size_t consumed = 0;
    if (!coinbase.Deserialize(data + txCountSize, dataSize - txCountSize, nullptr, &consumed)) {
        return true;
    }

    if (coinbase.vin.empty()) {
        return true;
    }

    DFMP::CMIKScriptData mikData;
    if (!DFMP::ParseMIKFromScriptSig(coinbase.vin[0].scriptSig, mikData)) {
        return true;
    }

    // Only registration blocks are rate-limited
    if (!mikData.isRegistration) {
        return true;
    }

    // Check registration count in trailing window (height-1 because current block not yet counted)
    int count = tracker.GetRegistrationCount(height - 1, window);
    if (count >= maxPerWindow) {
        error = "CheckRegistrationRateLimit: registration rate limit exceeded at height " +
                std::to_string(height) + " (" + std::to_string(count) +
                " registrations in last " + std::to_string(window) +
                " blocks, max " + std::to_string(maxPerWindow) + ")";
        return false;
    }

    return true;
}

bool CheckVDFReplacementPreflight(
    const CBlock& block,
    const CBlockIndex* pindexNew,
    const CBlockIndex* pindexTip,
    CBlockchainDB* db,
    int height,
    CCooldownTracker& tracker,
    std::string& error)
{
    if (!block.IsVDFBlock()) return true;
    if (!Dilithion::g_chainParams) return true;

    const int excludeHeight = pindexTip ? pindexTip->nHeight : -1;

    std::array<uint8_t, 20> mikId{};
    if (!ExtractCoinbaseMIKIdentity(block, mikId)) {
        error = "CheckVDFReplacementPreflight: cannot extract MIK identity";
        return false;
    }

    if (height >= Dilithion::g_chainParams->dfmpCooldownConsensusHeight) {
        int64_t ts = static_cast<int64_t>(block.nTime);
        if (tracker.IsInCooldownExcludingHeight(mikId, height, ts, excludeHeight)) {
            error = "CheckVDFReplacementPreflight: cooldown preflight failed";
            return false;
        }
    }

    if (height >= Dilithion::g_chainParams->consecutiveMinerCheckHeight) {
        static constexpr int MAX_CONSECUTIVE_SAME_MINER = 3;
        int activeMiners = tracker.GetActiveMinersExcludingHeight(height, excludeHeight);
        if (activeMiners > 1) {
            int consecutiveCount = 0;
            const CBlockIndex* pWalk = pindexNew ? pindexNew->pprev : nullptr;
            while (pWalk && consecutiveCount < MAX_CONSECUTIVE_SAME_MINER && db) {
                CBlock prevBlock;
                if (!db->ReadBlock(pWalk->GetBlockHash(), prevBlock)) break;
                std::array<uint8_t, 20> prevMik{};
                if (!ExtractCoinbaseMIKIdentity(prevBlock, prevMik)) break;
                if (prevMik != mikId) break;
                consecutiveCount++;
                pWalk = pWalk->pprev;
            }

            if (consecutiveCount >= MAX_CONSECUTIVE_SAME_MINER) {
                // v4.0.21 — Patch A: retire stall exemption above activation height.
                // Mirror of the change in CheckConsecutiveMiner (line ~326).
                // Both call sites updated in lockstep so a block rejected by the
                // authoritative connect path is also rejected by preflight.
                int stallRetiredHeight = Dilithion::g_chainParams ?
                    Dilithion::g_chainParams->consecutiveMinerStallExemptionRetiredHeight : 999999999;
                bool stallExempt = false;
                if (height < stallRetiredHeight) {
                    static constexpr int64_t CONSECUTIVE_STALL_THRESHOLD_SECS = 3600;
                    if (pindexNew && pindexNew->pprev) {
                        int64_t gap = static_cast<int64_t>(block.nTime) -
                                      static_cast<int64_t>(pindexNew->pprev->nTime);
                        if (gap >= CONSECUTIVE_STALL_THRESHOLD_SECS) stallExempt = true;
                    }
                }
                if (!stallExempt) {
                    error = "CheckVDFReplacementPreflight: consecutive-miner preflight failed";
                    return false;
                }
            }
        }
    }

    int window = Dilithion::g_chainParams->mikWindowCapWindow;
    int cap = Dilithion::g_chainParams->mikWindowCapFloor;
    if (window > 0 && cap > 0 && height > 0) {
        int activeMiners = tracker.GetActiveMinersExcludingHeight(height, excludeHeight);
        if (activeMiners > 1) {
            int livenessTimeout = Dilithion::g_chainParams->livenessTimeoutSec;
            int64_t prevBlockTime = (pindexNew && pindexNew->pprev)
                ? static_cast<int64_t>(pindexNew->pprev->nTime) : 0;
            int64_t blockTime = static_cast<int64_t>(block.nTime);
            if (!(livenessTimeout > 0 && prevBlockTime > 0 && (blockTime - prevBlockTime) >= livenessTimeout)) {
                int count = tracker.GetBlockCountInWindow(mikId, height - 1, window);
                if (count >= cap) {
                    error = "CheckVDFReplacementPreflight: window-cap preflight failed";
                    return false;
                }
            }
        }
    }

    return true;
}
