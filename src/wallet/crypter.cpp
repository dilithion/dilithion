// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/crypter.h>
#include <crypto/sha3.h>
#include <crypto/hmac_sha3.h>  // FIX-008 (CRYPT-007): For authenticated encryption
#include <rpc/auth.h>  // FIX-008: For constant-time MAC comparison
#include <cstring>
#include <algorithm>

// FIX-007 (CRYPT-001/006): OpenSSL for secure, hardware-accelerated AES-256
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

// FIX-007 (CRYPT-001/006): Removed 300+ lines of custom AES-256 implementation (replaced with OpenSSL EVP API)
// Deleted code (lines 21-316):
//   - Helper functions: AddPKCS7Padding, RemovePKCS7Padding, XORBytes, GF_Mul
//   - Lookup tables: AES_SBOX[256], AES_INV_SBOX[256], RCON[11]
//   - Core functions: AES256_KeyExpansion, AES256_EncryptBlock, AES256_DecryptBlock
//
// SECURITY BENEFITS OF OPENSSL:
//   ✓ Hardware acceleration via AES-NI instructions (5-10x faster)
//   ✓ Constant-time operations (prevents cache-timing side-channel attacks)
//   ✓ Extensively audited by security researchers worldwide
//   ✓ No risk of implementation bugs in crypto primitives
//
// ============================================================================
// CCrypter Implementation
// ============================================================================

bool CCrypter::SetKey(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    if (key.size() != 32) return false;  // AES-256 requires 32-byte key
    if (iv.size() != 16) return false;   // AES requires 16-byte IV

    memcpy(vchKey.data_ptr(), key.data(), 32);
    memcpy(vchIV.data(), iv.data(), 16);
    fKeySet = true;

    return true;
}

bool CCrypter::EncryptAES256(const std::vector<uint8_t>& plaintext,
                             std::vector<uint8_t>& ciphertext) {
    // FIX-007 (CRYPT-001/006): Replaced custom AES with OpenSSL EVP API
    // Benefits: Hardware acceleration (AES-NI), constant-time operations, audited implementation

    if (!fKeySet) return false;
    if (plaintext.empty()) return false;

    // OpenSSL EVP API for AES-256-CBC encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;  // Memory allocation failed
    }

    // Initialize encryption context
    // EVP_aes_256_cbc(): AES-256 with CBC mode and PKCS#7 padding (automatic)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           vchKey.data_ptr(), vchIV.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Allocate output buffer: plaintext size + block size for padding
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int ciphertext_len = 0;

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    // Finalize encryption (adds PKCS#7 padding automatically)
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    // Resize to actual ciphertext length
    ciphertext.resize(ciphertext_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool CCrypter::DecryptAES256(const std::vector<uint8_t>& ciphertext,
                             std::vector<uint8_t>& plaintext) {
    // FIX-007 (CRYPT-001/006): Replaced custom AES with OpenSSL EVP API
    // Benefits: Hardware acceleration (AES-NI), constant-time operations, audited implementation

    if (!fKeySet) return false;
    if (ciphertext.empty()) return false;
    if (ciphertext.size() % 16 != 0) return false;  // Must be multiple of block size

    // OpenSSL EVP API for AES-256-CBC decryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;  // Memory allocation failed
    }

    // Initialize decryption context
    // EVP_aes_256_cbc(): AES-256 with CBC mode and PKCS#7 padding (automatic removal)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           vchKey.data_ptr(), vchIV.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Allocate output buffer: same size as ciphertext (will be smaller after padding removal)
    plaintext.resize(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    // Finalize decryption (removes PKCS#7 padding automatically)
    // Returns error if padding is invalid (wrong key or corrupted data)
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;  // Invalid padding or decryption failed
    }
    plaintext_len += len;

    // Resize to actual plaintext length (after padding removal)
    plaintext.resize(plaintext_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool CCrypter::Encrypt(const std::vector<uint8_t>& plaintext,
                       std::vector<uint8_t>& ciphertext) {
    return EncryptAES256(plaintext, ciphertext);
}

bool CCrypter::Decrypt(const std::vector<uint8_t>& ciphertext,
                       std::vector<uint8_t>& plaintext) {
    return DecryptAES256(ciphertext, plaintext);
}

// ============================================================================
// FIX-008 (CRYPT-007): Authenticated Encryption (Encrypt-then-MAC)
// ============================================================================

bool CCrypter::ComputeMAC(const std::vector<uint8_t>& ciphertext,
                          std::vector<uint8_t>& mac,
                          bool useLegacyKeying) {
    if (!fKeySet) return false;
    if (ciphertext.empty()) return false;

    // Encrypt-then-MAC: Compute HMAC over (IV || ciphertext)
    // This authenticates both the IV and ciphertext, preventing:
    // - Padding oracle attacks (attacker can't tamper with ciphertext)
    // - IV manipulation attacks
    std::vector<uint8_t> data;
    data.reserve(vchIV.size() + ciphertext.size());
    data.insert(data.end(), vchIV.begin(), vchIV.end());
    data.insert(data.end(), ciphertext.begin(), ciphertext.end());

    mac.resize(64);

    if (useLegacyKeying) {
        // LEGACY (v3-v6 wallets): HMAC was keyed with the AES key itself.
        // This branch exists ONLY to verify MACs on records that were written
        // before the LP-7 key-separation fix, so that pre-fix encrypted wallets
        // still unlock and can be migrated. Never used when WRITING new records.
        HMAC_SHA3_512(vchKey.data_ptr(), vchKey.size(),
                      data.data(), data.size(),
                      mac.data());
        return true;
    }

    // LP-7 (wallet-Inv-2): KEY-SEPARATION FIX (v7+).
    // The same key must not be used for two different primitives (AES-CBC and
    // HMAC). Derive a distinct MAC key from the AES key via HKDF-SHA3-256 with a
    // dedicated context so the HMAC key is independent of the cipher key.
    std::vector<uint8_t> aesKey(vchKey.data_ptr(), vchKey.data_ptr() + vchKey.size());
    std::vector<uint8_t> macKey;
    DeriveEncryptionKey(aesKey, "wallet-record-mac", macKey);
    memory_cleanse(aesKey.data(), aesKey.size());

    // Compute HMAC-SHA3-512 keyed with the SEPARATE MAC key (not the AES key)
    HMAC_SHA3_512(macKey.data(), macKey.size(),
                  data.data(), data.size(),
                  mac.data());

    memory_cleanse(macKey.data(), macKey.size());

    return true;
}

bool CCrypter::VerifyMAC(const std::vector<uint8_t>& ciphertext,
                         const std::vector<uint8_t>& mac,
                         bool useLegacyKeying) {
    if (!fKeySet) return false;
    if (ciphertext.empty()) return false;
    if (mac.size() != 64) return false;  // HMAC-SHA3-512 is 64 bytes

    // Compute expected MAC
    std::vector<uint8_t> expected_mac;
    if (!ComputeMAC(ciphertext, expected_mac, useLegacyKeying)) {
        return false;
    }

    // Constant-time comparison to prevent timing attacks
    // Use RPCAuth::SecureCompare() which is designed for this purpose
    return RPCAuth::SecureCompare(expected_mac.data(), mac.data(), 64);
}

// ============================================================================
// Key Derivation (PBKDF2-SHA3)
// ============================================================================

/**
 * PBKDF2-SHA3 Implementation
 *
 * PBKDF2 (Password-Based Key Derivation Function 2) using SHA-3-256 as PRF.
 * This is quantum-resistant due to use of SHA-3 instead of SHA-2.
 *
 * Algorithm:
 *   DK = PBKDF2(PRF, Password, Salt, c, dkLen)
 *   where PRF = HMAC-SHA3-256
 */

// NOTE: HMAC_SHA3_256 is already implemented in src/crypto/hmac_sha3.cpp
//       (included via #include <crypto/hmac_sha3.h> at line 6)
//       Removed duplicate static implementation to avoid linkage conflicts

// WL-007 FIX: HKDF-SHA3-256 for key derivation with domain separation
// Implements HKDF-Expand from RFC 5869, adapted for SHA3-256
//
// HKDF provides cryptographic domain separation by deriving separate
// sub-keys from a master key using different "info" context strings.
//
// Algorithm: OKM = HMAC(PRK, info | 0x01) for 32-byte output
//
// This prevents key reuse across different encryption contexts:
// - Private keys encrypted with one derived key
// - HD master encrypted with different derived key
// - Mnemonic encrypted with yet another derived key
//
static void HKDF_Expand_SHA3_256(const uint8_t* prk, size_t prkLen,
                                 const char* info, size_t infoLen,
                                 uint8_t* okm, size_t okmLen) {
    // For 32-byte output with SHA3-256, we only need one iteration
    // T(1) = HMAC(PRK, info | 0x01)
    if (okmLen > 32) {
        // Multiple iterations needed (not implemented for simplicity)
        // Current use case only needs 32 bytes
        return;
    }

    // Build: info | 0x01
    std::vector<uint8_t> data;
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(info),
                reinterpret_cast<const uint8_t*>(info) + infoLen);
    data.push_back(0x01);

    // T(1) = HMAC(PRK, info | 0x01)
    HMAC_SHA3_256(prk, prkLen, data.data(), data.size(), okm);
}

// WL-007 FIX: Derive encryption key with domain separation
// Uses HKDF to generate separate keys for different encryption purposes
//
// @param masterKey The wallet master key (32 bytes)
// @param context Domain separation context (e.g., "privkey", "hdmaster", "mnemonic")
// @param derivedKey Output buffer for derived key (32 bytes)
void DeriveEncryptionKey(const std::vector<uint8_t>& masterKey,
                        const char* context,
                        std::vector<uint8_t>& derivedKey) {
    derivedKey.resize(32);

    // Build info string: "dilithion-encryption-" + context
    std::string info = std::string("dilithion-encryption-") + context;

    HKDF_Expand_SHA3_256(masterKey.data(), masterKey.size(),
                        info.c_str(), info.length(),
                        derivedKey.data(), 32);
}

bool DeriveKey(const std::string& passphrase,
               const std::vector<uint8_t>& salt,
               unsigned int rounds,
               std::vector<uint8_t>& keyOut) {
    // WL-014 FIX: Detailed comments explaining PBKDF2 iteration logic

    if (passphrase.empty()) return false;
    if (salt.size() != WALLET_CRYPTO_SALT_SIZE) return false;
    if (rounds == 0) return false;

    keyOut.resize(WALLET_CRYPTO_KEY_SIZE);

    // PBKDF2-SHA3-256 ALGORITHM (RFC 2898):
    // Purpose: Derive cryptographic key from password with computational cost
    //
    // WHY PBKDF2:
    // - Prevents rainbow table attacks (salt adds uniqueness)
    // - Prevents brute force (iterations add computational cost)
    // - Each additional iteration doubles attacker's work
    //
    // ITERATION COUNT (500,000 rounds):
    // - Typical passphrase entropy: ~40-80 bits
    // - GPU can do ~10^9 SHA3-256/sec
    // - 500k iterations = ~0.5ms per attempt on CPU
    // - Brute force 2^40 space: 10^12 / (2 * 10^6) = 500,000 seconds (~6 days on single GPU)
    // - More rounds = better security, but slower wallet unlock
    // - 500k chosen to balance security (strong) with UX (~500ms unlock)
    //
    // PBKDF2 FORMULA:
    //   T_i = F(Password, Salt, c, i) where:
    //   F(Password, Salt, c, i) = U_1 XOR U_2 XOR ... XOR U_c
    //   U_1 = PRF(Password, Salt || INT_32_BE(i))
    //   U_n = PRF(Password, U_{n-1})
    //
    // For AES-256 we only need 32 bytes = 1 block, so i=1

    // Generate first block (only need 32 bytes = 1 block for AES-256)
    std::vector<uint8_t> saltBlock(salt.begin(), salt.end());
    saltBlock.push_back(0);
    saltBlock.push_back(0);
    saltBlock.push_back(0);
    saltBlock.push_back(1);  // Block number = 1 (big-endian)

    // U_1 = PRF(password, salt || 0x00000001)
    // PRF = HMAC-SHA3-256 (more secure than HMAC-SHA256, quantum-resistant)
    uint8_t U[32];
    HMAC_SHA3_256(reinterpret_cast<const uint8_t*>(passphrase.data()),
                  passphrase.length(),
                  saltBlock.data(),
                  saltBlock.size(),
                  U);

    memcpy(keyOut.data(), U, 32);  // T = U_1

    // ITERATION LOOP:
    // Repeatedly apply PRF and XOR results
    // T = U_1 XOR U_2 XOR U_3 XOR ... XOR U_c
    // where U_n = PRF(password, U_{n-1})
    //
    // WHY XOR:
    // - Each iteration mixes in more entropy
    // - Attacker must compute all iterations to get final key
    // - Cannot precompute partial results (each depends on previous)
    for (unsigned int i = 1; i < rounds; i++) {
        uint8_t Unext[32];

        // U_n = HMAC-SHA3-256(password, U_{n-1})
        HMAC_SHA3_256(reinterpret_cast<const uint8_t*>(passphrase.data()),
                      passphrase.length(),
                      U,
                      32,
                      Unext);

        // T = T XOR U_n
        for (int j = 0; j < 32; j++) {
            keyOut[j] ^= Unext[j];
        }

        memcpy(U, Unext, 32);
    }

    // Wipe sensitive data
    memory_cleanse(U, 32);

    return true;
}

// ============================================================================
// Random Number Generation
// ============================================================================

bool GetStrongRandBytes(uint8_t* buf, size_t len) {
    if (buf == nullptr || len == 0) return false;

#ifdef _WIN32
    // Windows: Use CryptGenRandom
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContextW(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return false;
    }

    bool success = CryptGenRandom(hProvider, static_cast<DWORD>(len), buf);
    CryptReleaseContext(hProvider, 0);
    return success;

#else
    // Unix: Use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            close(fd);
            return false;
        }
        total += n;
    }

    close(fd);
    return true;
#endif
}

bool GenerateSalt(std::vector<uint8_t>& salt) {
    salt.resize(WALLET_CRYPTO_SALT_SIZE);
    return GetStrongRandBytes(salt.data(), WALLET_CRYPTO_SALT_SIZE);
}

bool GenerateIV(std::vector<uint8_t>& iv) {
    iv.resize(WALLET_CRYPTO_IV_SIZE);
    return GetStrongRandBytes(iv.data(), WALLET_CRYPTO_IV_SIZE);
}
