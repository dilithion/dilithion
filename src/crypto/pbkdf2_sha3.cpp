// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <crypto/pbkdf2_sha3.h>
#include <crypto/hmac_sha3.h>
#include <cstring>
#include <stdexcept>
#include <vector>

// SHA3-512 output size in bytes
static const size_t SHA3_512_OUTPUT_SIZE = 64;

/**
 * Convert 32-bit integer to big-endian byte array (network byte order)
 */
static void INT_32_BE(uint32_t value, uint8_t output[4]) {
    output[0] = (value >> 24) & 0xFF;
    output[1] = (value >> 16) & 0xFF;
    output[2] = (value >> 8) & 0xFF;
    output[3] = value & 0xFF;
}

/**
 * XOR two byte arrays: dest = dest ^ src
 */
static void xor_bytes(uint8_t* dest, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dest[i] ^= src[i];
    }
}

/**
 * PBKDF2 function F for a single block
 *
 * F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc
 * Where:
 *   U1 = HMAC(Password, Salt || INT_32_BE(i))
 *   U2 = HMAC(Password, U1)
 *   ...
 *   Uc = HMAC(Password, Uc-1)
 *
 * @param password Password bytes
 * @param password_len Password length
 * @param salt Salt bytes
 * @param salt_len Salt length
 * @param iterations Number of iterations (c)
 * @param block_index Block index (i, 1-based)
 * @param output Output buffer for 64-byte block
 */
static void pbkdf2_f(const uint8_t* password, size_t password_len,
                     const uint8_t* salt, size_t salt_len,
                     uint32_t iterations, uint32_t block_index,
                     uint8_t output[SHA3_512_OUTPUT_SIZE]) {
    // U1 = HMAC(Password, Salt || INT_32_BE(i))
    uint8_t u_current[SHA3_512_OUTPUT_SIZE];
    uint8_t u_previous[SHA3_512_OUTPUT_SIZE];

    // First iteration: HMAC(password, salt || block_index)
    {
        // Prepare salt || INT_32_BE(block_index)
        // Use std::vector for automatic memory management (RAII)
        size_t salt_block_len = salt_len + 4;
        std::vector<uint8_t> salt_block(salt_block_len);
        // salt == nullptr is accepted when salt_len == 0 (validated by the
        // caller), and memcpy(dst, nullptr, 0) is UB under memcpy's nonnull
        // attribute. Same guard shape as HMAC_SHA3_*; output is unchanged.
        if (salt_len > 0) {
            std::memcpy(salt_block.data(), salt, salt_len);
        }
        INT_32_BE(block_index, salt_block.data() + salt_len);

        // U1 = HMAC(password, salt || block_index)
        HMAC_SHA3_512(password, password_len, salt_block.data(), salt_block_len, u_current);

        // salt_block automatically freed here - no memory leak on exception
    }

    // Initialize output with U1
    std::memcpy(output, u_current, SHA3_512_OUTPUT_SIZE);

    // Remaining iterations: U2 ... Uc
    for (uint32_t iter = 2; iter <= iterations; iter++) {
        // Store previous U value
        std::memcpy(u_previous, u_current, SHA3_512_OUTPUT_SIZE);

        // Ui = HMAC(password, Ui-1)
        HMAC_SHA3_512(password, password_len, u_previous, SHA3_512_OUTPUT_SIZE, u_current);

        // output ^= Ui
        xor_bytes(output, u_current, SHA3_512_OUTPUT_SIZE);
    }

    // Wipe sensitive data
    std::memset(u_current, 0, SHA3_512_OUTPUT_SIZE);
    std::memset(u_previous, 0, SHA3_512_OUTPUT_SIZE);
}

void PBKDF2_SHA3_512(const uint8_t* password, size_t password_len,
                     const uint8_t* salt, size_t salt_len,
                     uint32_t iterations,
                     uint8_t* output, size_t output_len) {
    // Validate inputs (CRITICAL: Must be runtime checks, not assert())
    // assert() is removed in release builds (-DNDEBUG), creating security vulnerabilities
    if ((password == nullptr && password_len > 0)) {
        throw std::invalid_argument("PBKDF2: password is NULL but password_len > 0");
    }
    if ((salt == nullptr && salt_len > 0)) {
        throw std::invalid_argument("PBKDF2: salt is NULL but salt_len > 0");
    }
    if (iterations == 0) {
        throw std::invalid_argument("PBKDF2: iterations must be > 0");
    }
    if (output == nullptr) {
        throw std::invalid_argument("PBKDF2: output buffer is NULL");
    }
    if (output_len == 0) {
        throw std::invalid_argument("PBKDF2: output_len must be > 0");
    }

    // Calculate number of blocks needed
    // Each block produces SHA3_512_OUTPUT_SIZE (64) bytes
    // Check for integer overflow in addition
    if (output_len > SIZE_MAX - SHA3_512_OUTPUT_SIZE + 1) {
        throw std::overflow_error("PBKDF2: output_len too large (would overflow)");
    }
    size_t num_blocks = (output_len + SHA3_512_OUTPUT_SIZE - 1) / SHA3_512_OUTPUT_SIZE;

    // Check that num_blocks fits in uint32_t (block index is 1-based, max = num_blocks)
    if (num_blocks > UINT32_MAX) {
        throw std::overflow_error("PBKDF2: output_len too large (num_blocks > UINT32_MAX)");
    }

    // Generate each block
    for (size_t i = 0; i < num_blocks; i++) {
        uint8_t block[SHA3_512_OUTPUT_SIZE];

        // F(Password, Salt, c, i+1) - block index is 1-based
        pbkdf2_f(password, password_len, salt, salt_len, iterations,
                 static_cast<uint32_t>(i + 1), block);

        // Copy block to output (handle partial last block)
        size_t offset = i * SHA3_512_OUTPUT_SIZE;
        size_t bytes_to_copy = SHA3_512_OUTPUT_SIZE;
        if (offset + bytes_to_copy > output_len) {
            bytes_to_copy = output_len - offset;
        }

        std::memcpy(output + offset, block, bytes_to_copy);

        // Wipe block
        std::memset(block, 0, SHA3_512_OUTPUT_SIZE);
    }
}

void BIP39_MnemonicToSeed(const char* mnemonic_phrase, size_t mnemonic_len,
                          const char* passphrase, size_t passphrase_len,
                          uint8_t seed_output[64]) {
    // BIP39 standard parameters
    const char* SALT_PREFIX = "dilithion-mnemonic";
    const size_t PREFIX_LEN = std::strlen(SALT_PREFIX);
    const uint32_t BIP39_ITERATIONS = 2048;

    // Prepare salt: "dilithion-mnemonic" + passphrase
    // Use std::vector for automatic memory management (RAII)
    size_t salt_len = PREFIX_LEN + passphrase_len;
    std::vector<uint8_t> salt(salt_len);

    std::memcpy(salt.data(), SALT_PREFIX, PREFIX_LEN);
    if (passphrase_len > 0 && passphrase != nullptr) {
        std::memcpy(salt.data() + PREFIX_LEN, passphrase, passphrase_len);
    }

    // Derive seed using PBKDF2-SHA3-512
    PBKDF2_SHA3_512(reinterpret_cast<const uint8_t*>(mnemonic_phrase), mnemonic_len,
                    salt.data(), salt_len,
                    BIP39_ITERATIONS,
                    seed_output, 64);

    // Wipe sensitive data
    std::memset(salt.data(), 0, salt_len);
    // salt automatically freed here - no memory leak on exception
}
