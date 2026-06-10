// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <attestation/seed_attestation.h>
#include <crypto/sha3.h>
#include <util/strencodings.h>
#include <wallet/crypter.h>  // For memory_cleanse() + CCrypter/DeriveKey (LP-13 encrypt-at-rest)

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/stat.h>   // LP-13: chmod/fchmod for 0600 key file perms
#include <fcntl.h>
#endif

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

namespace Attestation {

// File format magic and version
static constexpr uint32_t KEY_FILE_MAGIC = 0x444C4154;  // "DLAT" (Dilithion Attestation)
// v1: plaintext private key (legacy — still readable for backward-compat migration)
// v2 (LP-13): private key encrypted at rest (AES-256-CBC, PBKDF2-SHA3, encrypt-then-MAC)
static constexpr uint8_t KEY_FILE_VERSION_V1 = 1;
static constexpr uint8_t KEY_FILE_VERSION_V2 = 2;

// LP-13 v2 on-disk sizes (bytes)
static constexpr size_t SEED_KEY_SALT_SIZE = 16;  // PBKDF2 salt (== WALLET_CRYPTO_SALT_SIZE)
static constexpr size_t SEED_KEY_IV_SIZE   = 16;  // AES-CBC IV     (== WALLET_CRYPTO_IV_SIZE)
static constexpr size_t SEED_KEY_MAC_SIZE  = 64;  // HMAC-SHA3-512  (encrypt-then-MAC)

// LP-13: PBKDF2 rounds for the seed-key passphrase. Reuse the wallet constant
// for a single hardened KDF cost across the codebase.
static constexpr unsigned int SEED_KEY_PBKDF2_ROUNDS = WALLET_CRYPTO_PBKDF2_ROUNDS;

// ============================================================================
// LP-13 helpers
// ============================================================================

// Read the operator passphrase from the environment. Empty => not configured
// (Save falls back to legacy v1 plaintext; Load cannot decrypt a v2 file).
static std::string GetSeedKeyPassphrase() {
    const char* env = std::getenv(Attestation::SEED_KEY_PASSPHRASE_ENV);
    if (env == nullptr) return std::string();
    return std::string(env);
}

// Restrict a key file to owner read/write only. POSIX: chmod 0600. Windows:
// best-effort no-op (NTFS confines the per-user profile data dir; documented).
static void RestrictKeyFilePerms(const std::string& path) {
#ifndef _WIN32
    // 0600 = owner rw, no group/other. Failure is logged but non-fatal: the
    // secret is still written; an operator on an exotic FS can harden manually.
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        std::cerr << "[Attestation] WARNING: could not chmod 0600 key file: " << path << std::endl;
    }
#else
    (void)path;  // Windows: relies on NTFS ACL of the user profile data dir.
#endif
}

// ============================================================================
// CSeedAttestationKey
// ============================================================================

CSeedAttestationKey::~CSeedAttestationKey() {
    Clear();
}

void CSeedAttestationKey::Clear() {
    if (!m_privkey.empty()) {
        memory_cleanse(m_privkey.data(), m_privkey.size());
    }
    m_privkey.clear();
    m_pubkey.clear();
}

bool CSeedAttestationKey::Generate() {
    m_pubkey.resize(DFMP::MIK_PUBKEY_SIZE);
    m_privkey.resize(DFMP::MIK_PRIVKEY_SIZE);

    int result = pqcrystals_dilithium3_ref_keypair(m_pubkey.data(), m_privkey.data());
    if (result != 0) {
        Clear();
        return false;
    }
    return true;
}

bool CSeedAttestationKey::Load(const std::string& dataDir) {
    std::string path = dataDir + "/" + SEED_KEY_FILENAME;
    // Read the whole file up front so v2 length/format checks are robust against
    // truncation, and so we never leave a half-read secret in memory on error.
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
    file.close();

    // magic(4) + version(1) header
    if (buf.size() < 5) {
        std::cerr << "[Attestation] Key file too short" << std::endl;
        return false;
    }

    uint32_t magic = 0;
    std::memcpy(&magic, buf.data(), 4);
    if (magic != KEY_FILE_MAGIC) {
        std::cerr << "[Attestation] Invalid key file magic" << std::endl;
        return false;
    }

    uint8_t version = buf[4];
    size_t off = 5;

    if (version == KEY_FILE_VERSION_V1) {
        // Legacy plaintext format (backward compat for un-migrated seeds):
        //   magic(4) version(1) pubkey(1952) privkey(4032)
        if (buf.size() < off + DFMP::MIK_PUBKEY_SIZE + DFMP::MIK_PRIVKEY_SIZE) {
            std::cerr << "[Attestation] v1 key file truncated" << std::endl;
            return false;
        }
        m_pubkey.assign(buf.begin() + off, buf.begin() + off + DFMP::MIK_PUBKEY_SIZE);
        off += DFMP::MIK_PUBKEY_SIZE;
        m_privkey.assign(buf.begin() + off, buf.begin() + off + DFMP::MIK_PRIVKEY_SIZE);
        // Wipe the plaintext private key out of the read buffer.
        memory_cleanse(buf.data() + off, DFMP::MIK_PRIVKEY_SIZE);
        std::cout << "[Attestation] Loaded seed attestation key (v1 plaintext): "
                  << GetPubKeyHex().substr(0, 16) << "..." << std::endl;
        std::cerr << "[Attestation] NOTE: key file is unencrypted (v1). Set "
                  << SEED_KEY_PASSPHRASE_ENV << " to re-save it encrypted (v2)." << std::endl;
        return true;
    }

    if (version == KEY_FILE_VERSION_V2) {
        // LP-13 encrypted format:
        //   magic(4) version(1) pubkey(1952) salt(16) iv(16) mac(64)
        //   ctlen(4 LE) ciphertext(ctlen)
        size_t headerEnd = off + DFMP::MIK_PUBKEY_SIZE + SEED_KEY_SALT_SIZE +
                           SEED_KEY_IV_SIZE + SEED_KEY_MAC_SIZE + 4;
        if (buf.size() < headerEnd) {
            std::cerr << "[Attestation] v2 key file truncated (header)" << std::endl;
            return false;
        }

        m_pubkey.assign(buf.begin() + off, buf.begin() + off + DFMP::MIK_PUBKEY_SIZE);
        off += DFMP::MIK_PUBKEY_SIZE;

        std::vector<uint8_t> salt(buf.begin() + off, buf.begin() + off + SEED_KEY_SALT_SIZE);
        off += SEED_KEY_SALT_SIZE;
        std::vector<uint8_t> iv(buf.begin() + off, buf.begin() + off + SEED_KEY_IV_SIZE);
        off += SEED_KEY_IV_SIZE;
        std::vector<uint8_t> mac(buf.begin() + off, buf.begin() + off + SEED_KEY_MAC_SIZE);
        off += SEED_KEY_MAC_SIZE;

        uint32_t ctlen = static_cast<uint32_t>(buf[off]) |
                         (static_cast<uint32_t>(buf[off + 1]) << 8) |
                         (static_cast<uint32_t>(buf[off + 2]) << 16) |
                         (static_cast<uint32_t>(buf[off + 3]) << 24);
        off += 4;

        if (buf.size() != off + ctlen || ctlen == 0 || (ctlen % 16) != 0) {
            std::cerr << "[Attestation] v2 key file truncated or malformed ciphertext" << std::endl;
            return false;
        }
        std::vector<uint8_t> ciphertext(buf.begin() + off, buf.begin() + off + ctlen);

        std::string passphrase = GetSeedKeyPassphrase();
        if (passphrase.empty()) {
            std::cerr << "[Attestation] ERROR: key file is encrypted (v2) but "
                      << SEED_KEY_PASSPHRASE_ENV << " is not set. Cannot decrypt." << std::endl;
            Clear();
            return false;
        }

        // Derive AES key from passphrase + salt, then encrypt-then-MAC verify.
        std::vector<uint8_t> aesKey;
        if (!DeriveKey(passphrase, salt, SEED_KEY_PBKDF2_ROUNDS, aesKey)) {
            std::cerr << "[Attestation] ERROR: key derivation failed" << std::endl;
            memory_cleanse(&passphrase[0], passphrase.size());
            Clear();
            return false;
        }
        memory_cleanse(&passphrase[0], passphrase.size());

        CCrypter crypter;
        if (!crypter.SetKey(aesKey, iv)) {
            std::cerr << "[Attestation] ERROR: failed to set decryption key" << std::endl;
            memory_cleanse(aesKey.data(), aesKey.size());
            Clear();
            return false;
        }
        memory_cleanse(aesKey.data(), aesKey.size());

        // Verify MAC BEFORE decrypt (prevents padding-oracle / tamper). A wrong
        // passphrase yields a different derived key => MAC mismatch => reject.
        if (!crypter.VerifyMAC(ciphertext, mac)) {
            std::cerr << "[Attestation] ERROR: key file MAC verification failed "
                      << "(wrong passphrase or tampered/corrupt file)." << std::endl;
            Clear();
            return false;
        }

        std::vector<uint8_t> plain;
        if (!crypter.Decrypt(ciphertext, plain) || plain.size() != DFMP::MIK_PRIVKEY_SIZE) {
            std::cerr << "[Attestation] ERROR: key file decryption failed" << std::endl;
            if (!plain.empty()) memory_cleanse(plain.data(), plain.size());
            Clear();
            return false;
        }
        m_privkey.assign(plain.begin(), plain.end());
        memory_cleanse(plain.data(), plain.size());

        std::cout << "[Attestation] Loaded seed attestation key (v2 encrypted): "
                  << GetPubKeyHex().substr(0, 16) << "..." << std::endl;
        return true;
    }

    std::cerr << "[Attestation] Unsupported key file version: " << (int)version << std::endl;
    return false;
}

// LP-13 MEDIUM-1: zero a transient buffer that may hold the plaintext private
// key on the v1 Save path. Exposed (declared in the header) so the test suite
// can assert the wipe actually happens — deleting the memory_cleanse below is
// the mutation the cleanse test is designed to catch.
void CleanseSeedKeyBuffer(std::vector<uint8_t>& buf) {
    if (!buf.empty()) memory_cleanse(buf.data(), buf.size());
}

bool CSeedAttestationKey::Save(const std::string& dataDir) const {
    if (!IsValid()) return false;

    std::string path = dataDir + "/" + SEED_KEY_FILENAME;

    // LP-13: assemble the full serialized blob in memory first, then write it
    // in one shot. This lets us harden file permissions BEFORE any secret bytes
    // hit the disk (POSIX: create with 0600), avoiding a world-readable window.
    std::vector<uint8_t> out;
    auto putU32 = [&out](uint32_t v) {
        out.push_back(static_cast<uint8_t>(v & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    };

    // magic(4, native order to match Load's memcpy) + version(1)
    uint32_t magic = KEY_FILE_MAGIC;
    const uint8_t* magicBytes = reinterpret_cast<const uint8_t*>(&magic);
    out.insert(out.end(), magicBytes, magicBytes + 4);

    std::string passphrase = GetSeedKeyPassphrase();
    bool encrypt = !passphrase.empty();

    // LP-13 MEDIUM-1: on the v1 (default, un-passphrased) path `out` holds the
    // plaintext Dilithium3 private key; on the v2 path it holds only ciphertext.
    // Cleanse `out` UNCONDITIONALLY before every return so the plaintext key is
    // never left in freed heap (cleansing the non-secret v2 buffer is harmless).
    // The actual wipe lives in CleanseSeedKeyBuffer (a test seam — see
    // seed_attestation_key_tests.cpp); this lambda is the single exit gate for
    // all returns past this point.
    auto finish = [&out](bool ok) -> bool {
        CleanseSeedKeyBuffer(out);
        return ok;
    };

    if (!encrypt) {
        // ---- Legacy v1 plaintext (no passphrase configured) ----
        out.push_back(KEY_FILE_VERSION_V1);
        out.insert(out.end(), m_pubkey.begin(), m_pubkey.end());
        out.insert(out.end(), m_privkey.begin(), m_privkey.end());
        std::cerr << "[Attestation] WARNING: " << SEED_KEY_PASSPHRASE_ENV
                  << " not set — writing UNENCRYPTED (v1) key file. Set it to "
                     "encrypt the consensus signing key at rest." << std::endl;
    } else {
        // ---- LP-13 v2 encrypted: AES-256-CBC, PBKDF2-SHA3, encrypt-then-MAC ----
        std::vector<uint8_t> salt, iv;
        if (!GenerateSalt(salt) || !GenerateIV(iv)) {
            std::cerr << "[Attestation] ERROR: failed to generate salt/IV" << std::endl;
            memory_cleanse(&passphrase[0], passphrase.size());
            return finish(false);
        }

        std::vector<uint8_t> aesKey;
        if (!DeriveKey(passphrase, salt, SEED_KEY_PBKDF2_ROUNDS, aesKey)) {
            std::cerr << "[Attestation] ERROR: key derivation failed" << std::endl;
            memory_cleanse(&passphrase[0], passphrase.size());
            return finish(false);
        }
        memory_cleanse(&passphrase[0], passphrase.size());

        CCrypter crypter;
        if (!crypter.SetKey(aesKey, iv)) {
            std::cerr << "[Attestation] ERROR: failed to set encryption key" << std::endl;
            memory_cleanse(aesKey.data(), aesKey.size());
            return finish(false);
        }
        memory_cleanse(aesKey.data(), aesKey.size());

        // LP-13 LOW-1: ComputeMAC keys the HMAC with the SAME 32-byte AES key
        // (no separate k_mac). This is a DELIBERATE reuse of the audited wallet
        // CCrypter construction (encrypt-then-MAC, MAC verified BEFORE decrypt at
        // Load → no padding-oracle surface), not an oversight. AES-256-CBC and
        // HMAC-SHA3-512 are independent constructions with no known cross-protocol
        // interaction under shared keying, so this is no weaker than the wallet's
        // at-rest format. Documented here so it is not re-litigated in review.
        std::vector<uint8_t> ciphertext, mac;
        if (!crypter.Encrypt(m_privkey, ciphertext) ||
            !crypter.ComputeMAC(ciphertext, mac)) {
            std::cerr << "[Attestation] ERROR: encryption/MAC failed" << std::endl;
            return finish(false);
        }

        // magic(4) version(1) pubkey(1952) salt(16) iv(16) mac(64) ctlen(4) ct
        out.push_back(KEY_FILE_VERSION_V2);
        out.insert(out.end(), m_pubkey.begin(), m_pubkey.end());
        out.insert(out.end(), salt.begin(), salt.end());
        out.insert(out.end(), iv.begin(), iv.end());
        out.insert(out.end(), mac.begin(), mac.end());
        putU32(static_cast<uint32_t>(ciphertext.size()));
        out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    }

#ifndef _WIN32
    // POSIX: create the file with 0600 from the outset (no world-readable
    // window between create and chmod). open() honors the mode on creation.
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        std::cerr << "[Attestation] Failed to open key file for writing: " << path << std::endl;
        return finish(false);
    }
    // LP-13 LOW-2: O_TRUNC does NOT reset the mode of a PRE-EXISTING file, so a
    // stale 0644 file would hold fresh secret bytes between ::write and the
    // post-write chmod. fchmod the open fd to 0600 BEFORE writing any secret,
    // closing that microsecond window (the open-with-mode above only covers the
    // freshly-created case). Non-fatal on failure — the post-write re-assert below
    // and the warning in RestrictKeyFilePerms still apply.
    if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        std::cerr << "[Attestation] WARNING: fchmod 0600 on key file failed (errno "
                  << errno << "); proceeding, will re-assert perms after write." << std::endl;
    }
    size_t written = 0;
    bool writeOk = true;
    while (written < out.size()) {
        ssize_t n = ::write(fd, out.data() + written, out.size() - written);
        if (n <= 0) { writeOk = false; break; }
        written += static_cast<size_t>(n);
    }
    ::close(fd);
    // Belt-and-braces: re-assert 0600 in case a pre-existing file kept old perms.
    RestrictKeyFilePerms(path);
    if (!writeOk) {
        std::cerr << "[Attestation] Key file write error" << std::endl;
        return finish(false);
    }
#else
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "[Attestation] Failed to open key file for writing: " << path << std::endl;
        return finish(false);
    }
    file.write(reinterpret_cast<const char*>(out.data()), out.size());
    bool writeOk = file.good();
    file.close();
    RestrictKeyFilePerms(path);  // best-effort no-op on Windows (NTFS ACL governs)
    if (!writeOk) {
        std::cerr << "[Attestation] Key file write error" << std::endl;
        return finish(false);
    }
#endif

    std::cout << "[Attestation] Saved seed attestation key to: " << path
              << (encrypt ? " (v2 encrypted)" : " (v1 plaintext)") << std::endl;
    return finish(true);
}

bool CSeedAttestationKey::LoadOrGenerate(const std::string& dataDir, bool allowGenerate) {
    if (Load(dataDir)) {
        return true;
    }

    // LP-13: a missing/unreadable key file must NOT silently mint a fresh
    // consensus signing key on a production seed. Auto-mint is gated behind the
    // explicit --generate-seed-key operator flag (allowGenerate).
    if (!allowGenerate) {
        std::cerr << "[Attestation] FATAL: no usable seed attestation key at "
                  << dataDir << "/" << SEED_KEY_FILENAME
                  << " and --generate-seed-key was NOT given. Refusing to mint a"
                     " new consensus signing key. If this is a first-time"
                     " provision, restart with --generate-seed-key; if the key"
                     " was expected to exist, investigate (wrong data dir,"
                     " missing/encrypted file, or unset "
                  << SEED_KEY_PASSPHRASE_ENV << ")." << std::endl;
        return false;
    }

    std::cout << "[Attestation] No existing attestation key found, generating new keypair (--generate-seed-key)..." << std::endl;
    if (!Generate()) {
        std::cerr << "[Attestation] Failed to generate attestation keypair" << std::endl;
        return false;
    }

    if (!Save(dataDir)) {
        std::cerr << "[Attestation] WARNING: Generated key but failed to save to disk" << std::endl;
        // Key is still valid in memory, so don't fail
    }

    std::cout << "[Attestation] Generated new seed attestation key: " << GetPubKeyHex().substr(0, 16) << "..." << std::endl;
    return true;
}

bool CSeedAttestationKey::Sign(const std::vector<uint8_t>& message,
                                std::vector<uint8_t>& signature) const {
    if (!IsValid() || m_privkey.empty()) return false;

    signature.resize(DFMP::MIK_SIGNATURE_SIZE);
    size_t siglen = 0;

    int result = pqcrystals_dilithium3_ref_signature(
        signature.data(), &siglen,
        message.data(), message.size(),
        nullptr, 0,
        m_privkey.data()
    );

    if (result != 0 || siglen != DFMP::MIK_SIGNATURE_SIZE) {
        signature.clear();
        return false;
    }
    return true;
}

bool CSeedAttestationKey::IsValid() const {
    return m_pubkey.size() == DFMP::MIK_PUBKEY_SIZE;
}

std::string CSeedAttestationKey::GetPubKeyHex() const {
    return HexStr(m_pubkey);
}

// ============================================================================
// MESSAGE BUILDING
// ============================================================================

std::vector<uint8_t> BuildAttestationMessage(
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    uint32_t timestamp,
    uint8_t seedId)
{
    // Build: "DILV_ATTEST" || mikPubkey || dnaHash || timestamp_le32 || seedId
    std::vector<uint8_t> preimage;
    preimage.reserve(ATTESTATION_DOMAIN_LEN + mikPubkey.size() + 32 + 4 + 1);

    // Domain separator
    preimage.insert(preimage.end(),
        reinterpret_cast<const uint8_t*>(ATTESTATION_DOMAIN),
        reinterpret_cast<const uint8_t*>(ATTESTATION_DOMAIN) + ATTESTATION_DOMAIN_LEN);

    // MIK pubkey
    preimage.insert(preimage.end(), mikPubkey.begin(), mikPubkey.end());

    // DNA hash
    preimage.insert(preimage.end(), dnaHash.begin(), dnaHash.end());

    // Timestamp (little-endian)
    preimage.push_back(static_cast<uint8_t>(timestamp & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 8) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 16) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 24) & 0xFF));

    // Seed ID
    preimage.push_back(seedId);

    // Hash to 32 bytes
    std::vector<uint8_t> hash(32);
    SHA3_256(preimage.data(), preimage.size(), hash.data());
    return hash;
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

bool VerifyAttestation(
    const CAttestation& attestation,
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    const std::vector<uint8_t>& seedPubkey)
{
    if (!attestation.IsValid()) return false;
    if (seedPubkey.size() != DFMP::MIK_PUBKEY_SIZE) return false;

    // Reconstruct the signed message
    std::vector<uint8_t> message = BuildAttestationMessage(
        mikPubkey, dnaHash, attestation.timestamp, attestation.seedId);

    // Verify Dilithium3 signature
    int result = pqcrystals_dilithium3_ref_verify(
        attestation.signature.data(), attestation.signature.size(),
        message.data(), message.size(),
        nullptr, 0,
        seedPubkey.data()
    );

    return (result == 0);
}

bool VerifyAttestationSet(
    const CAttestationSet& attestations,
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    const std::vector<std::vector<uint8_t>>& seedPubkeys,
    int64_t blockTimestamp,
    std::string& error)
{
    if (seedPubkeys.size() != NUM_SEEDS) {
        error = "Invalid seed pubkey count";
        return false;
    }

    int validCount = 0;
    bool usedSeed[NUM_SEEDS] = {};  // Track which seeds have been used (no duplicates)

    for (size_t idx = 0; idx < attestations.attestations.size(); idx++) {
        const auto& att = attestations.attestations[idx];
        if (att.seedId >= NUM_SEEDS) {
            std::cerr << "  [Attest] #" << idx << ": seedId=" << (int)att.seedId << " SKIP (invalid id)" << std::endl;
            continue;
        }

        if (usedSeed[att.seedId]) {
            std::cerr << "  [Attest] #" << idx << ": seedId=" << (int)att.seedId << " SKIP (duplicate)" << std::endl;
            continue;
        }

        // Check freshness: attestation timestamp within validity window of block timestamp
        int64_t timeDiff = blockTimestamp - static_cast<int64_t>(att.timestamp);
        if (timeDiff < 0 || timeDiff > ATTESTATION_VALIDITY_WINDOW) {
            std::cerr << "  [Attest] #" << idx << ": seedId=" << (int)att.seedId
                      << " SKIP (stale: diff=" << timeDiff << "s, window=" << ATTESTATION_VALIDITY_WINDOW << ")" << std::endl;
            continue;
        }

        // Verify signature
        bool sigOk = VerifyAttestation(att, mikPubkey, dnaHash, seedPubkeys[att.seedId]);
        if (sigOk) {
            usedSeed[att.seedId] = true;
            validCount++;
        } else {
            std::cerr << "  [Attest] #" << idx << ": seedId=" << (int)att.seedId
                      << " FAILED signature (sigSize=" << att.signature.size()
                      << ", keySize=" << seedPubkeys[att.seedId].size() << ")" << std::endl;
        }
    }

    if (validCount < MIN_ATTESTATIONS) {
        error = "Insufficient valid attestations: " + std::to_string(validCount) +
                " of " + std::to_string(MIN_ATTESTATIONS) + " required"
                + " (checked " + std::to_string(attestations.attestations.size()) + " entries)";
        return false;
    }

    return true;
}

// ============================================================================
// SERIALIZATION
// ============================================================================

bool BuildAttestationScriptData(
    const CAttestationSet& attestations,
    std::vector<uint8_t>& data)
{
    if (attestations.attestations.empty()) return false;
    if (attestations.attestations.size() > 255) return false;  // Count fits in 1 byte

    // Marker
    data.push_back(ATTESTATION_MARKER);

    // Count
    data.push_back(static_cast<uint8_t>(attestations.attestations.size()));

    // Each attestation entry
    for (const auto& att : attestations.attestations) {
        if (!att.IsValid()) return false;

        // Seed ID
        data.push_back(att.seedId);

        // Timestamp (little-endian)
        data.push_back(static_cast<uint8_t>(att.timestamp & 0xFF));
        data.push_back(static_cast<uint8_t>((att.timestamp >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>((att.timestamp >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((att.timestamp >> 24) & 0xFF));

        // Signature
        data.insert(data.end(), att.signature.begin(), att.signature.end());
    }

    return true;
}

bool ParseAttestationScriptData(
    const uint8_t* data,
    size_t dataLen,
    CAttestationSet& attestations,
    size_t& consumed)
{
    consumed = 0;
    attestations.attestations.clear();

    if (dataLen < 2) return false;  // Need at least marker + count

    // Verify marker
    if (data[0] != ATTESTATION_MARKER) return false;

    uint8_t count = data[1];
    size_t expectedSize = 2 + (count * ATTESTATION_ENTRY_SIZE);
    if (dataLen < expectedSize) return false;

    size_t offset = 2;
    for (uint8_t i = 0; i < count; i++) {
        CAttestation att;

        // Seed ID
        att.seedId = data[offset++];

        // Timestamp (little-endian)
        att.timestamp = static_cast<uint32_t>(data[offset]) |
                       (static_cast<uint32_t>(data[offset + 1]) << 8) |
                       (static_cast<uint32_t>(data[offset + 2]) << 16) |
                       (static_cast<uint32_t>(data[offset + 3]) << 24);
        offset += 4;

        // Signature
        att.signature.assign(data + offset, data + offset + DFMP::MIK_SIGNATURE_SIZE);
        offset += DFMP::MIK_SIGNATURE_SIZE;

        attestations.attestations.push_back(std::move(att));
    }

    consumed = offset;
    return true;
}

// ============================================================================
// RPC HELPERS — Request attestation from seed nodes
// ============================================================================

// Simple synchronous HTTP POST for JSON-RPC (no external dependencies)
static bool HttpJsonRpcCall(
    const std::string& host,
    uint16_t port,
    const std::string& jsonBody,
    std::string& response,
    std::string& error,
    int timeoutSec = 10)
{
    // Create socket
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        error = "Failed to create socket";
        return false;
    }
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        error = "Failed to create socket";
        return false;
    }
#endif

    // Set timeout
#ifdef _WIN32
    // Windows SO_RCVTIMEO/SO_SNDTIMEO expects DWORD in milliseconds, not struct timeval
    DWORD timeout_ms = timeoutSec * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = timeoutSec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif

    // Resolve and connect
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        error = "Invalid IP address: " + host;
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        error = "Connection failed to " + host + ":" + std::to_string(port);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    // Build HTTP request with auth header (rpc:rpc)
    std::string httpRequest =
        "POST / HTTP/1.1\r\n"
        "Host: " + host + ":" + std::to_string(port) + "\r\n"
        "Content-Type: application/json\r\n"
        "X-Dilithion-RPC: 1\r\n"
        "Authorization: Basic cnBjOnJwYw==\r\n"  // base64("rpc:rpc")
        "Content-Length: " + std::to_string(jsonBody.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" + jsonBody;

    // Send
    int sent = send(sock, httpRequest.c_str(), static_cast<int>(httpRequest.size()), 0);
    if (sent <= 0) {
        error = "Failed to send request";
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    // Receive response
    response.clear();
    char buf[4096];
    int received;
    while ((received = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[received] = '\0';
        response += buf;
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    if (response.empty()) {
        error = "Empty response from " + host;
        return false;
    }

    // Strip HTTP headers — find the JSON body after \r\n\r\n
    size_t bodyStart = response.find("\r\n\r\n");
    if (bodyStart != std::string::npos) {
        response = response.substr(bodyStart + 4);
    }

    return true;
}

// Simple JSON string value extractor (avoid external JSON library dependency)
static std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    pos += searchKey.size();
    size_t endPos = json.find("\"", pos);
    if (endPos == std::string::npos) return "";
    return json.substr(pos, endPos - pos);
}

static std::string ExtractJsonNumber(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    pos += searchKey.size();
    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    size_t endPos = pos;
    while (endPos < json.size() && (json[endPos] >= '0' && json[endPos] <= '9')) endPos++;
    if (endPos == pos) return "";
    return json.substr(pos, endPos - pos);
}

bool RequestAttestation(
    const std::string& seedIP,
    uint16_t rpcPort,
    const std::string& mikPubkeyHex,
    const std::string& dnaHashHex,
    CAttestation& attestation,
    std::string& error)
{
    // Build JSON-RPC request
    std::string jsonBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getmikattestation\","
                           "\"params\":{\"mik_pubkey\":\"" + mikPubkeyHex + "\","
                           "\"dna_hash\":\"" + dnaHashHex + "\"}}";

    std::string response;
    if (!HttpJsonRpcCall(seedIP, rpcPort, jsonBody, response, error)) {
        return false;
    }

    // Check for error in response
    if (response.find("\"error\"") != std::string::npos &&
        response.find("\"error\":null") == std::string::npos) {
        // Extract error message
        std::string errMsg = ExtractJsonString(response, "message");
        if (!errMsg.empty()) {
            error = "Seed " + seedIP + ": " + errMsg;
        } else {
            error = "Seed " + seedIP + " returned error: " + response.substr(0, 200);
        }
        return false;
    }

    // Extract result fields
    std::string seedIdStr = ExtractJsonNumber(response, "seed_id");
    std::string timestampStr = ExtractJsonNumber(response, "timestamp");
    std::string signatureHex = ExtractJsonString(response, "signature");

    if (seedIdStr.empty() || timestampStr.empty() || signatureHex.empty()) {
        error = "Missing fields in attestation response from " + seedIP;
        return false;
    }

    attestation.seedId = static_cast<uint8_t>(std::stoi(seedIdStr));
    attestation.timestamp = static_cast<uint32_t>(std::stoul(timestampStr));
    attestation.signature = ParseHex(signatureHex);

    if (attestation.signature.size() != DFMP::MIK_SIGNATURE_SIZE) {
        error = "Invalid signature size from " + seedIP + ": " +
                std::to_string(attestation.signature.size());
        attestation.signature.clear();
        return false;
    }

    return true;
}

bool CollectAttestations(
    const std::vector<std::string>& seedIPs,
    uint16_t rpcPort,
    const std::string& mikPubkeyHex,
    const std::string& dnaHashHex,
    CAttestationSet& attestations,
    std::string& error)
{
    attestations.attestations.clear();
    int failures = 0;

    for (size_t i = 0; i < seedIPs.size(); i++) {
        std::cout << "  [Attestation] Requesting from seed " << i << " (" << seedIPs[i] << ")..." << std::flush;

        CAttestation att;
        std::string seedError;
        if (RequestAttestation(seedIPs[i], rpcPort, mikPubkeyHex, dnaHashHex, att, seedError)) {
            std::cout << " OK" << std::endl;
            attestations.attestations.push_back(std::move(att));

            if (attestations.HasMinimum()) {
                std::cout << "  [Attestation] Collected " << attestations.Count()
                          << " attestations (minimum " << MIN_ATTESTATIONS << " met)" << std::endl;
                return true;
            }
        } else {
            std::cout << " FAILED: " << seedError << std::endl;
            failures++;
        }
    }

    if (!attestations.HasMinimum()) {
        error = "Only " + std::to_string(attestations.Count()) + " of " +
                std::to_string(MIN_ATTESTATIONS) + " required attestations collected (" +
                std::to_string(failures) + " seeds failed)";
        return false;
    }

    return true;
}

} // namespace Attestation
