// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <dfmp/mik.h>
#include <crypto/sha3.h>
#include <wallet/crypter.h>  // For memory_cleanse()

#include <atomic>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>

// Dilithium3 reference implementation
extern "C" {
    int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
    int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *sk);
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

namespace DFMP {

// ============================================================================
// CMiningIdentityKey IMPLEMENTATION
// ============================================================================

CMiningIdentityKey::CMiningIdentityKey() {
    // Default constructor - creates empty/invalid MIK
}

CMiningIdentityKey::~CMiningIdentityKey() {
    Clear();
}

CMiningIdentityKey::CMiningIdentityKey(CMiningIdentityKey&& other) noexcept
    : pubkey(std::move(other.pubkey)),
      privkey(std::move(other.privkey)),
      identity(other.identity) {
    // Clear the moved-from identity
    std::memset(other.identity.data, 0, sizeof(other.identity.data));
}

CMiningIdentityKey& CMiningIdentityKey::operator=(CMiningIdentityKey&& other) noexcept {
    if (this != &other) {
        // Clear current data
        Clear();

        // Move data from other
        pubkey = std::move(other.pubkey);
        privkey = std::move(other.privkey);
        identity = other.identity;

        // Clear the moved-from identity
        std::memset(other.identity.data, 0, sizeof(other.identity.data));
    }
    return *this;
}

bool CMiningIdentityKey::IsValid() const {
    return pubkey.size() == MIK_PUBKEY_SIZE && !identity.IsNull();
}

bool CMiningIdentityKey::HasPrivateKey() const {
    return privkey.size() == MIK_PRIVKEY_SIZE;
}

bool CMiningIdentityKey::Generate() {
    // Allocate space for keys
    pubkey.resize(MIK_PUBKEY_SIZE);
    privkey.resize(MIK_PRIVKEY_SIZE);

    // Generate Dilithium3 keypair
    int result = pqcrystals_dilithium3_ref_keypair(pubkey.data(), privkey.data());
    if (result != 0) {
        Clear();
        return false;
    }

    // Derive identity from public key
    identity = DeriveIdentityFromMIK(pubkey);
    if (identity.IsNull()) {
        Clear();
        return false;
    }

    return true;
}

bool CMiningIdentityKey::Sign(const uint256& prevHash, int height, uint32_t timestamp,
                               std::vector<uint8_t>& signature) const {
    if (!HasPrivateKey()) {
        return false;
    }

    // Build the message to sign
    std::vector<uint8_t> message = BuildMIKSignatureMessage(prevHash, height, timestamp, identity);

    // Allocate signature buffer
    signature.resize(MIK_SIGNATURE_SIZE);
    size_t siglen = 0;

    // Sign with Dilithium3
    // Context is empty for MIK signatures
    int result = pqcrystals_dilithium3_ref_signature(
        signature.data(), &siglen,
        message.data(), message.size(),
        nullptr, 0,  // No context
        privkey.data()
    );

    if (result != 0 || siglen != MIK_SIGNATURE_SIZE) {
        signature.clear();
        return false;
    }

    return true;
}

bool CMiningIdentityKey::SignArbitrary(const std::vector<uint8_t>& message,
                                       std::vector<uint8_t>& signature) const {
    if (!HasPrivateKey()) {
        return false;
    }

    signature.resize(MIK_SIGNATURE_SIZE);
    size_t siglen = 0;

    int result = pqcrystals_dilithium3_ref_signature(
        signature.data(), &siglen,
        message.data(), message.size(),
        nullptr, 0,  // No context
        privkey.data()
    );

    if (result != 0 || siglen != MIK_SIGNATURE_SIZE) {
        signature.clear();
        return false;
    }

    return true;
}

void CMiningIdentityKey::Clear() {
    // Securely wipe private key
    if (!privkey.empty()) {
        memory_cleanse(privkey.data(), privkey.size());
    }
    privkey.clear();

    // Clear public key (not sensitive, but for completeness)
    pubkey.clear();

    // Clear identity
    std::memset(identity.data, 0, sizeof(identity.data));
}

std::string CMiningIdentityKey::GetIdentityHex() const {
    return identity.GetHex();
}

void CMiningIdentityKey::SerializePublic(std::vector<uint8_t>& data) const {
    // Format: [pubkey: 1952 bytes]
    data = pubkey;
}

bool CMiningIdentityKey::DeserializePublic(const std::vector<uint8_t>& data) {
    if (data.size() != MIK_PUBKEY_SIZE) {
        return false;
    }

    pubkey = data;
    identity = DeriveIdentityFromMIK(pubkey);
    privkey.clear();  // Public-only deserialization

    return !identity.IsNull();
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

std::vector<uint8_t> BuildMIKSignatureMessage(
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity) {
    // Message format: SHA3-256(prevBlockHash || height || timestamp || identity)
    // This commits to the chain position without requiring the block hash
    // (which would create a circular dependency)

    // Build the preimage
    // prevHash: 32 bytes
    // height: 4 bytes (little-endian)
    // timestamp: 4 bytes (little-endian)
    // identity: 20 bytes
    // Total: 60 bytes

    std::vector<uint8_t> preimage;
    preimage.reserve(60);

    // Previous block hash (32 bytes)
    preimage.insert(preimage.end(), prevHash.data, prevHash.data + 32);

    // Height (4 bytes, little-endian)
    uint32_t h = static_cast<uint32_t>(height);
    preimage.push_back(static_cast<uint8_t>(h & 0xFF));
    preimage.push_back(static_cast<uint8_t>((h >> 8) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((h >> 16) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((h >> 24) & 0xFF));

    // Timestamp (4 bytes, little-endian)
    preimage.push_back(static_cast<uint8_t>(timestamp & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 8) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 16) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 24) & 0xFF));

    // Identity (20 bytes)
    preimage.insert(preimage.end(), identity.data, identity.data + 20);

    // Hash the preimage
    std::vector<uint8_t> message(32);
    SHA3_256(preimage.data(), preimage.size(), message.data());

    return message;
}

bool VerifyMIKSignatureExact(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity) {
    // Validate input sizes
    if (pubkey.size() != MIK_PUBKEY_SIZE) {
        return false;
    }
    if (signature.size() != MIK_SIGNATURE_SIZE) {
        return false;
    }

    // Verify identity matches pubkey
    Identity derivedIdentity = DeriveIdentityFromMIK(pubkey);
    if (derivedIdentity != identity) {
        return false;
    }

    // Build the message
    std::vector<uint8_t> message = BuildMIKSignatureMessage(prevHash, height, timestamp, identity);

    // Verify signature
    int result = pqcrystals_dilithium3_ref_verify(
        signature.data(), signature.size(),
        message.data(), message.size(),
        nullptr, 0,  // No context
        pubkey.data()
    );

    return result == 0;
}

bool VerifyMIKSignature(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity) {
    // First try the supplied timestamp directly. In the common case (signature
    // was created over block.nTime exactly, e.g. for blocks produced by miners
    // running the post-v4.1.0 fixed signing path), this single check passes
    // and we return immediately — no perceptible cost added vs. v4.0.19.
    if (VerifyMIKSignatureExact(pubkey, signature, prevHash, height, timestamp, identity)) {
        return true;
    }

    // Fast-path validation: skip brute-force if obviously malformed.
    // (These all fail quickly inside Exact too, but checking here avoids the
    // 180-iteration loop on garbage input.)
    if (pubkey.size() != MIK_PUBKEY_SIZE || signature.size() != MIK_SIGNATURE_SIZE) {
        return false;
    }
    Identity derivedIdentity = DeriveIdentityFromMIK(pubkey);
    if (derivedIdentity != identity) {
        return false;
    }

    // v4.0.20 backward-window brute force.
    // The signing happens at wall-clock T1 (in RPC), the block's final nTime
    // is set at T3 (after VDF + grace period in vdf_miner.cpp). For DilV
    // mainnet, T3 - T1 can be up to ~90s. We scan back kMIKVerifyBackwardWindowSeconds
    // (180s) for safety margin. Stop at first match.
    //
    // Underflow guard: don't wrap below the genesis timestamp on chains
    // with very early blocks.
    constexpr uint32_t kFloor = 1;
    for (uint32_t k = 1; k <= kMIKVerifyBackwardWindowSeconds; ++k) {
        if (timestamp <= k) break;            // Don't subtract past 0
        const uint32_t earlier = timestamp - k;
        if (earlier < kFloor) break;
        if (VerifyMIKSignatureExact(pubkey, signature, prevHash, height, earlier, identity)) {
            return true;
        }
    }
    return false;
}

Identity DeriveIdentityFromMIK(const std::vector<uint8_t>& pubkey) {
    if (pubkey.size() != MIK_PUBKEY_SIZE) {
        return Identity();  // Null identity
    }

    // Hash the public key with SHA3-256
    uint8_t hash[32];
    SHA3_256(pubkey.data(), pubkey.size(), hash);

    // Take first 20 bytes as identity
    return Identity(hash);
}

bool VerifyArbitrarySignature(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& message) {
    if (pubkey.size() != MIK_PUBKEY_SIZE || signature.size() != MIK_SIGNATURE_SIZE) {
        return false;
    }

    int result = pqcrystals_dilithium3_ref_verify(
        signature.data(), signature.size(),
        message.data(), message.size(),
        nullptr, 0,  // No context
        pubkey.data()
    );

    return result == 0;
}

// ============================================================================
// SCRIPTSIG PARSING
// ============================================================================

bool ParseMIKFromScriptSig(
    const std::vector<uint8_t>& scriptSig,
    CMIKScriptData& mikData) {
    // Look for MIK_MARKER (0xDF) in the scriptSig
    // Typically after the height encoding and any extra nonce

    // Minimum size check: marker(1) + type(1) + identity(20) + sig(3309) = 3331
    if (scriptSig.size() < MIK_REFERENCE_MIN_SIZE) {
        return false;
    }

    // Search for MIK_MARKER
    // It should appear after the height (BIP 34) which is typically 1-4 bytes
    // We'll search from the beginning but skip obvious height encoding
    size_t pos = 0;

    // Skip height encoding (1 byte length + up to 4 bytes data)
    if (scriptSig.size() > 0) {
        uint8_t heightLen = scriptSig[0];
        if (heightLen >= 1 && heightLen <= 4 && scriptSig.size() > heightLen) {
            pos = 1 + heightLen;
        }
    }

    // Search for MIK_MARKER from current position
    while (pos < scriptSig.size()) {
        if (scriptSig[pos] == MIK_MARKER) {
            // Found marker, parse MIK data
            pos++;
            if (pos >= scriptSig.size()) {
                return false;  // No type byte
            }

            uint8_t mikType = scriptSig[pos];
            pos++;

            if (mikType == MIK_TYPE_REGISTRATION) {
                // Registration: pubkey(1952) + signature(3309)
                size_t requiredSize = MIK_PUBKEY_SIZE + MIK_SIGNATURE_SIZE;
                if (pos + requiredSize > scriptSig.size()) {
                    return false;  // Not enough data
                }

                mikData.isRegistration = true;

                // Extract public key
                mikData.pubkey.assign(
                    scriptSig.begin() + pos,
                    scriptSig.begin() + pos + MIK_PUBKEY_SIZE
                );
                pos += MIK_PUBKEY_SIZE;

                // Derive identity from pubkey
                mikData.identity = DeriveIdentityFromMIK(mikData.pubkey);
                if (mikData.identity.IsNull()) {
                    return false;
                }

                // Extract signature
                mikData.signature.assign(
                    scriptSig.begin() + pos,
                    scriptSig.begin() + pos + MIK_SIGNATURE_SIZE
                );
                pos += MIK_SIGNATURE_SIZE;

                // v3.0: Parse registration nonce if present (8 bytes after signature)
                if (pos + 8 <= scriptSig.size()) {
                    mikData.registrationNonce = 0;
                    for (int i = 0; i < 8; i++) {
                        mikData.registrationNonce |= static_cast<uint64_t>(scriptSig[pos + i]) << (i * 8);
                    }
                    pos += 8;
                } else {
                    mikData.registrationNonce = 0;  // Pre-v3.0 registration (no nonce)
                }

                // Parse DNA commitment if present (0xDD + 32 bytes)
                if (pos + DNA_COMMITMENT_SIZE <= scriptSig.size() &&
                    scriptSig[pos] == DNA_COMMITMENT_MARKER) {
                    pos++;  // skip marker
                    std::copy(scriptSig.begin() + pos, scriptSig.begin() + pos + 32,
                              mikData.dna_hash.begin());
                    mikData.has_dna_hash = true;
                    pos += 32;
                }

                // Parse attestation data if present (0xDA + count + entries)
                // Only in registration blocks. Each entry: seed_id(1) + timestamp(4) + sig(3309)
                if (pos + 2 <= scriptSig.size() && scriptSig[pos] == 0xDA) {
                    pos++;  // skip marker
                    uint8_t attCount = scriptSig[pos++];
                    const size_t ATTEST_ENTRY_SIZE = 1 + 4 + MIK_SIGNATURE_SIZE;  // 3314

                    if (pos + (attCount * ATTEST_ENTRY_SIZE) <= scriptSig.size()) {
                        mikData.has_attestations = true;
                        mikData.attestation_count = attCount;
                        for (uint8_t ai = 0; ai < attCount; ai++) {
                            CMIKScriptData::AttestationEntry entry;
                            entry.seedId = scriptSig[pos++];
                            entry.timestamp = static_cast<uint32_t>(scriptSig[pos]) |
                                            (static_cast<uint32_t>(scriptSig[pos + 1]) << 8) |
                                            (static_cast<uint32_t>(scriptSig[pos + 2]) << 16) |
                                            (static_cast<uint32_t>(scriptSig[pos + 3]) << 24);
                            pos += 4;
                            entry.signature.assign(scriptSig.begin() + pos,
                                                   scriptSig.begin() + pos + MIK_SIGNATURE_SIZE);
                            pos += MIK_SIGNATURE_SIZE;
                            mikData.attestations.push_back(std::move(entry));
                        }
                    }
                }

                return true;

            } else if (mikType == MIK_TYPE_REFERENCE) {
                // Reference: identity(20) + signature(3309)
                size_t requiredSize = MIK_IDENTITY_SIZE + MIK_SIGNATURE_SIZE;
                if (pos + requiredSize > scriptSig.size()) {
                    return false;  // Not enough data
                }

                mikData.isRegistration = false;

                // Extract identity
                mikData.identity = Identity(scriptSig.data() + pos);
                pos += MIK_IDENTITY_SIZE;

                // No pubkey for reference (must be looked up)
                mikData.pubkey.clear();

                // Extract signature
                mikData.signature.assign(
                    scriptSig.begin() + pos,
                    scriptSig.begin() + pos + MIK_SIGNATURE_SIZE
                );
                pos += MIK_SIGNATURE_SIZE;

                // Parse DNA commitment if present (0xDD + 32 bytes)
                if (pos + DNA_COMMITMENT_SIZE <= scriptSig.size() &&
                    scriptSig[pos] == DNA_COMMITMENT_MARKER) {
                    pos++;  // skip marker
                    std::copy(scriptSig.begin() + pos, scriptSig.begin() + pos + 32,
                              mikData.dna_hash.begin());
                    mikData.has_dna_hash = true;
                    pos += 32;
                }

                return true;

            } else {
                // Unknown MIK type, continue searching
                continue;
            }
        }
        pos++;
    }

    return false;  // No MIK data found
}

bool BuildMIKScriptSigRegistration(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    std::vector<uint8_t>& data) {
    if (pubkey.size() != MIK_PUBKEY_SIZE) {
        return false;
    }
    if (signature.size() != MIK_SIGNATURE_SIZE) {
        return false;
    }

    // Format: [MIK_MARKER] [MIK_TYPE_REGISTRATION] [pubkey] [signature]
    data.clear();
    data.reserve(1 + 1 + MIK_PUBKEY_SIZE + MIK_SIGNATURE_SIZE);

    data.push_back(MIK_MARKER);
    data.push_back(MIK_TYPE_REGISTRATION);
    data.insert(data.end(), pubkey.begin(), pubkey.end());
    data.insert(data.end(), signature.begin(), signature.end());

    return true;
}

bool BuildMIKScriptSigReference(
    const Identity& identity,
    const std::vector<uint8_t>& signature,
    std::vector<uint8_t>& data) {
    if (identity.IsNull()) {
        return false;
    }
    if (signature.size() != MIK_SIGNATURE_SIZE) {
        return false;
    }

    // Format: [MIK_MARKER] [MIK_TYPE_REFERENCE] [identity] [signature]
    data.clear();
    data.reserve(1 + 1 + MIK_IDENTITY_SIZE + MIK_SIGNATURE_SIZE);

    data.push_back(MIK_MARKER);
    data.push_back(MIK_TYPE_REFERENCE);
    data.insert(data.end(), identity.data, identity.data + MIK_IDENTITY_SIZE);
    data.insert(data.end(), signature.begin(), signature.end());

    return true;
}

bool BuildMIKScriptSigRegistration(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    uint64_t registrationNonce,
    std::vector<uint8_t>& data) {
    if (pubkey.size() != MIK_PUBKEY_SIZE) return false;
    if (signature.size() != MIK_SIGNATURE_SIZE) return false;

    // Format: [MIK_MARKER] [MIK_TYPE_REGISTRATION] [pubkey] [signature] [nonce:8]
    data.clear();
    data.reserve(MIK_REGISTRATION_SIZE);

    data.push_back(MIK_MARKER);
    data.push_back(MIK_TYPE_REGISTRATION);
    data.insert(data.end(), pubkey.begin(), pubkey.end());
    data.insert(data.end(), signature.begin(), signature.end());

    // Append nonce as 8 bytes little-endian
    for (int i = 0; i < 8; i++) {
        data.push_back(static_cast<uint8_t>((registrationNonce >> (i * 8)) & 0xFF));
    }

    return true;
}

// ============================================================================
// DNA COMMITMENT
// ============================================================================

void BuildDNACommitment(const std::array<uint8_t, 32>& dna_hash, std::vector<uint8_t>& data) {
    data.push_back(DNA_COMMITMENT_MARKER);
    data.insert(data.end(), dna_hash.begin(), dna_hash.end());
}

// ============================================================================
// REGISTRATION PROOF-OF-WORK (DFMP v3.0)
// ============================================================================

bool VerifyRegistrationPoW(const std::vector<uint8_t>& pubkey, uint64_t nonce, int requiredBits,
                            const std::array<uint8_t, 32>* dnaHash) {
    if (pubkey.size() != MIK_PUBKEY_SIZE || requiredBits <= 0 || requiredBits > 256) {
        return false;
    }

    // Build preimage: pubkey || [dna_hash] || nonce (little-endian)
    // DNA hash included when provided and non-zero (DilV from genesis, DIL future)
    std::vector<uint8_t> preimage;
    preimage.reserve(MIK_PUBKEY_SIZE + 32 + 8);
    preimage.insert(preimage.end(), pubkey.begin(), pubkey.end());

    // Include DNA hash in preimage if provided and non-zero
    if (dnaHash) {
        bool allZero = true;
        for (auto b : *dnaHash) { if (b != 0) { allZero = false; break; } }
        if (!allZero) {
            preimage.insert(preimage.end(), dnaHash->begin(), dnaHash->end());
        }
    }

    // Append nonce as 8 bytes little-endian
    for (int i = 0; i < 8; i++) {
        preimage.push_back(static_cast<uint8_t>((nonce >> (i * 8)) & 0xFF));
    }

    // Hash with SHA3-256
    uint8_t hash[32];
    SHA3_256(preimage.data(), preimage.size(), hash);

    // Check leading zero bits (hash is big-endian: hash[0] is MSB)
    int zeroBits = 0;
    for (int i = 0; i < 32 && zeroBits < requiredBits; i++) {
        if (hash[i] == 0) {
            zeroBits += 8;
        } else {
            // Count leading zeros in this byte
            uint8_t b = hash[i];
            while ((b & 0x80) == 0 && zeroBits < requiredBits) {
                zeroBits++;
                b <<= 1;
            }
            break;
        }
    }

    return zeroBits >= requiredBits;
}

bool MineRegistrationPoW(const std::vector<uint8_t>& pubkey, int requiredBits, uint64_t& nonce,
                          const std::atomic<bool>* running,
                          const std::array<uint8_t, 32>* dnaHash) {
    if (pubkey.size() != MIK_PUBKEY_SIZE || requiredBits <= 0) {
        return false;
    }

    // Build base preimage: pubkey || [dna_hash] || nonce
    // DNA hash included when provided and non-zero (binds identity to hardware fingerprint)
    std::vector<uint8_t> preimage;
    size_t baseSize = MIK_PUBKEY_SIZE;

    bool includeDna = false;
    if (dnaHash) {
        for (auto b : *dnaHash) { if (b != 0) { includeDna = true; break; } }
    }

    preimage.reserve(baseSize + (includeDna ? 32 : 0) + 8);
    preimage.insert(preimage.end(), pubkey.begin(), pubkey.end());
    if (includeDna) {
        preimage.insert(preimage.end(), dnaHash->begin(), dnaHash->end());
        baseSize += 32;
    }
    preimage.resize(baseSize + 8);  // Reserve space for nonce

    uint8_t hash[32];
    auto start_time = std::chrono::steady_clock::now();
    int64_t expected_total = 1LL << requiredBits;  // 2^28 ≈ 268M for 28 bits

    for (uint64_t n = 0; n < UINT64_MAX; n++) {
        // Check for shutdown every 1M iterations
        if ((n & 0xFFFFF) == 0 && n > 0 && running && !running->load(std::memory_order_relaxed)) {
            std::cout << "  [Mining] Registration PoW interrupted by shutdown" << std::endl;
            return false;
        }

        // Write nonce bytes (little-endian) at offset after pubkey [+ dna_hash]
        for (int i = 0; i < 8; i++) {
            preimage[baseSize + i] = static_cast<uint8_t>((n >> (i * 8)) & 0xFF);
        }

        // Hash
        SHA3_256(preimage.data(), preimage.size(), hash);

        // Check leading zero bits
        int zeroBits = 0;
        bool found = true;
        for (int i = 0; i < 32 && zeroBits < requiredBits; i++) {
            if (hash[i] == 0) {
                zeroBits += 8;
            } else {
                uint8_t b = hash[i];
                while ((b & 0x80) == 0 && zeroBits < requiredBits) {
                    zeroBits++;
                    b <<= 1;
                }
                if (zeroBits < requiredBits) {
                    found = false;
                }
                break;
            }
        }

        if (found && zeroBits >= requiredBits) {
            nonce = n;
            auto total_elapsed = std::chrono::steady_clock::now() - start_time;
            auto total_sec = std::chrono::duration_cast<std::chrono::seconds>(total_elapsed).count();
            std::cout << "  [Mining] Registration PoW complete! (nonce=" << n
                      << ", " << zeroBits << " zero bits, " << total_sec << "s)" << std::endl;
            return true;
        }

        // Log progress every 5M iterations with elapsed time and ETA
        if (n % 5000000 == 0 && n > 0) {
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
            double rate = (elapsed_sec > 0) ? static_cast<double>(n) / elapsed_sec : 0;
            int64_t hashes_done = static_cast<int64_t>(n);

            if (hashes_done < expected_total) {
                // Before expected average: show ETA
                int64_t remaining_sec = (rate > 0) ? static_cast<int64_t>((expected_total - hashes_done) / rate) : 0;
                int eta_min = static_cast<int>(remaining_sec / 60);
                int eta_sec = static_cast<int>(remaining_sec % 60);
                std::cout << "  [Mining] Registration PoW: " << (n / 1000000) << "M hashes"
                          << " (elapsed: " << elapsed_sec << "s"
                          << ", ~" << eta_min << "m " << eta_sec << "s remaining)" << std::endl;
            } else {
                // Past expected average: show multiplier and reassurance
                double multiple = static_cast<double>(hashes_done) / expected_total;
                std::cout << "  [Mining] Registration PoW: " << (n / 1000000) << "M hashes"
                          << " (elapsed: " << elapsed_sec << "s"
                          << ", " << std::fixed << std::setprecision(1) << multiple
                          << "x avg — still searching, this is normal)" << std::endl;
            }
        }
    }

    return false;  // Should never reach here
}

// ============================================================================
// DFMP V2.0 PENALTY CALCULATIONS
// ============================================================================

int64_t CalculateMaturityPenaltyFP_V2(int currentHeight, int firstSeenHeight) {
    // v2.0: NO first-block grace - new MIKs start at 3.0x
    if (firstSeenHeight < 0) {
        return FP_MATURITY_START_V2;  // 3.0x for new MIK
    }

    int age = currentHeight - firstSeenHeight;

    // Step-wise decay over 400 blocks (100 block steps)
    if (age < 100) {
        return FP_MATURITY_START_V2;   // 3.0x (blocks 0-99)
    }
    if (age < 200) {
        return FP_MATURITY_STEP_25;    // 2.5x (blocks 100-199)
    }
    if (age < 300) {
        return FP_MATURITY_STEP_20;    // 2.0x (blocks 200-299)
    }
    if (age < 400) {
        return FP_MATURITY_STEP_15;    // 1.5x (blocks 300-399)
    }

    return FP_SCALE;  // 1.0x (mature, 400+ blocks)
}

int64_t CalculateHeatPenaltyFP_V2(int blocksInWindow, int uniqueMiners) {
    // Dynamic free tier: scale by active miner count
    int effectiveFreeThreshold = FREE_TIER_THRESHOLD_V2;  // Default: 20
    if (uniqueMiners > 0) {
        int dynamicThreshold = OBSERVATION_WINDOW_V2 / std::max(1, uniqueMiners);
        effectiveFreeThreshold = std::max(FREE_TIER_THRESHOLD_V2, dynamicThreshold);
    }
    int linearZoneWidth = LINEAR_ZONE_UPPER_V2 - FREE_TIER_THRESHOLD_V2;  // 5 blocks
    int effectiveLinearUpper = effectiveFreeThreshold + linearZoneWidth;

    // Free tier: 0-N blocks → 1.0x
    if (blocksInWindow <= effectiveFreeThreshold) {
        return FP_SCALE;  // 1.0x
    }

    // Linear zone: N+1 to N+5 blocks → 1.0x to 1.5x
    if (blocksInWindow <= effectiveLinearUpper) {
        int64_t linearPart = FP_LINEAR_INCREMENT_V2 * (blocksInWindow - effectiveFreeThreshold);
        return FP_SCALE + linearPart;
    }

    // Exponential zone: N+6+ blocks → 1.5 × 1.08^(blocks - N - 5)
    int64_t penalty = FP_MATURITY_STEP_15;  // 1.5 × FP_SCALE = 1,500,000
    int exponent = blocksInWindow - effectiveLinearUpper;

    for (int i = 0; i < exponent; i++) {
        penalty = (penalty * 108) / 100;
    }

    return penalty;
}

int64_t CalculateTotalMultiplierFP_V2(int currentHeight, int firstSeenHeight, int blocksInWindow, int uniqueMiners) {
    int64_t maturityFP = CalculateMaturityPenaltyFP_V2(currentHeight, firstSeenHeight);
    int64_t heatFP = CalculateHeatPenaltyFP_V2(blocksInWindow, uniqueMiners);

    // total = maturity × heat
    // In fixed-point: total_fp = (maturity_fp × heat_fp) / FP_SCALE
    return (maturityFP * heatFP) / FP_SCALE;
}

double GetMaturityPenalty_V2(int currentHeight, int firstSeenHeight) {
    return static_cast<double>(CalculateMaturityPenaltyFP_V2(currentHeight, firstSeenHeight)) / FP_SCALE;
}

double GetHeatPenalty_V2(int blocksInWindow) {
    return static_cast<double>(CalculateHeatPenaltyFP_V2(blocksInWindow)) / FP_SCALE;
}

double GetTotalMultiplier_V2(int currentHeight, int firstSeenHeight, int blocksInWindow) {
    return static_cast<double>(CalculateTotalMultiplierFP_V2(currentHeight, firstSeenHeight, blocksInWindow)) / FP_SCALE;
}

} // namespace DFMP
