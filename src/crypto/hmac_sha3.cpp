// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <crypto/hmac_sha3.h>
#include <crypto/sha3.h>
#include <cstring>
#include <stdexcept>
#include <vector>

// SHA3-256 block size (rate in bytes)
// SHA3-256 has capacity = 512 bits, rate = 1600 - 512 = 1088 bits = 136 bytes
static const size_t SHA3_256_BLOCKSIZE = 136;

// SHA3-512 block size (rate in bytes)
// SHA3-512 has capacity = 1024 bits, rate = 1600 - 1024 = 576 bits = 72 bytes
static const size_t SHA3_512_BLOCKSIZE = 72;

void HMAC_SHA3_256(const uint8_t* key, size_t key_len,
                   const uint8_t* data, size_t data_len,
                   uint8_t output[32]) {
    // Validate inputs
    if (key == nullptr && key_len > 0) {
        throw std::invalid_argument("HMAC_SHA3_256: key is NULL but key_len > 0");
    }
    if (data == nullptr && data_len > 0) {
        throw std::invalid_argument("HMAC_SHA3_256: data is NULL but data_len > 0");
    }
    if (output == nullptr) {
        throw std::invalid_argument("HMAC_SHA3_256: output buffer is NULL");
    }

    // Check for integer overflow in inner_len calculation
    if (data_len > SIZE_MAX - SHA3_256_BLOCKSIZE) {
        throw std::overflow_error("HMAC_SHA3_256: data_len too large (would overflow)");
    }

    // Prepare key
    uint8_t key_block[SHA3_256_BLOCKSIZE];
    std::memset(key_block, 0, SHA3_256_BLOCKSIZE);

    if (key_len > SHA3_256_BLOCKSIZE) {
        // If key is longer than block size, hash it first
        uint8_t key_hash[32];
        SHA3_256(key, key_len, key_hash);
        std::memcpy(key_block, key_hash, 32);
    } else if (key_len > 0) {
        // Otherwise use key directly (padded with zeros).
        //
        // The key_len > 0 guard is required, not cosmetic. The validation above
        // deliberately ACCEPTS key == nullptr when key_len == 0, and memcpy
        // declares both pointer arguments __attribute__((nonnull)) even when n
        // is 0 — so memcpy(dst, nullptr, 0) is undefined behaviour by the
        // standard regardless of it copying nothing in practice. key_block is
        // already zeroed by the memset above, so skipping the call is exactly
        // equivalent for every accepted input.
        std::memcpy(key_block, key, key_len);
    }

    // Prepare inner and outer padded keys
    uint8_t ipad_key[SHA3_256_BLOCKSIZE];
    uint8_t opad_key[SHA3_256_BLOCKSIZE];

    for (size_t i = 0; i < SHA3_256_BLOCKSIZE; i++) {
        ipad_key[i] = key_block[i] ^ 0x36;
        opad_key[i] = key_block[i] ^ 0x5c;
    }

    // Inner hash: SHA3-256((K ⊕ ipad) || data)
    uint8_t inner_hash[32];
    {
        // Concatenate ipad_key and data
        size_t inner_len = SHA3_256_BLOCKSIZE + data_len;
        std::vector<uint8_t> inner_data(inner_len);
        std::memcpy(inner_data.data(), ipad_key, SHA3_256_BLOCKSIZE);
        std::memcpy(inner_data.data() + SHA3_256_BLOCKSIZE, data, data_len);

        SHA3_256(inner_data.data(), inner_len, inner_hash);
    }

    // Outer hash: SHA3-256((K ⊕ opad) || inner_hash)
    {
        size_t outer_len = SHA3_256_BLOCKSIZE + 32;
        std::vector<uint8_t> outer_data(outer_len);
        std::memcpy(outer_data.data(), opad_key, SHA3_256_BLOCKSIZE);
        std::memcpy(outer_data.data() + SHA3_256_BLOCKSIZE, inner_hash, 32);

        SHA3_256(outer_data.data(), outer_len, output);
    }

    // Wipe sensitive data
    std::memset(key_block, 0, SHA3_256_BLOCKSIZE);
    std::memset(ipad_key, 0, SHA3_256_BLOCKSIZE);
    std::memset(opad_key, 0, SHA3_256_BLOCKSIZE);
    std::memset(inner_hash, 0, 32);
}

void HMAC_SHA3_512(const uint8_t* key, size_t key_len,
                   const uint8_t* data, size_t data_len,
                   uint8_t output[64]) {
    // Validate inputs
    if (key == nullptr && key_len > 0) {
        throw std::invalid_argument("HMAC_SHA3_512: key is NULL but key_len > 0");
    }
    if (data == nullptr && data_len > 0) {
        throw std::invalid_argument("HMAC_SHA3_512: data is NULL but data_len > 0");
    }
    if (output == nullptr) {
        throw std::invalid_argument("HMAC_SHA3_512: output buffer is NULL");
    }

    // Check for integer overflow in inner_len calculation
    if (data_len > SIZE_MAX - SHA3_512_BLOCKSIZE) {
        throw std::overflow_error("HMAC_SHA3_512: data_len too large (would overflow)");
    }

    // Prepare key
    uint8_t key_block[SHA3_512_BLOCKSIZE];
    std::memset(key_block, 0, SHA3_512_BLOCKSIZE);

    if (key_len > SHA3_512_BLOCKSIZE) {
        // If key is longer than block size, hash it first
        uint8_t key_hash[64];
        SHA3_512(key, key_len, key_hash);
        std::memcpy(key_block, key_hash, 64);
    } else if (key_len > 0) {
        // See the SHA3-256 variant above: the key_len > 0 guard avoids
        // memcpy(dst, nullptr, 0), which is UB even though it copies nothing.
        // This is the site UBSan actually reported (hmac_sha3.cpp:119) once the
        // job was able to fail; the 256-bit variant has the identical bug and is
        // fixed too, since halt_on_error=1 stops at the first finding and would
        // otherwise have hidden it until the next run.
        std::memcpy(key_block, key, key_len);
    }

    // Prepare inner and outer padded keys
    uint8_t ipad_key[SHA3_512_BLOCKSIZE];
    uint8_t opad_key[SHA3_512_BLOCKSIZE];

    for (size_t i = 0; i < SHA3_512_BLOCKSIZE; i++) {
        ipad_key[i] = key_block[i] ^ 0x36;
        opad_key[i] = key_block[i] ^ 0x5c;
    }

    // Inner hash: SHA3-512((K ⊕ ipad) || data)
    uint8_t inner_hash[64];
    {
        // Concatenate ipad_key and data
        // Use std::vector for automatic memory management (RAII)
        size_t inner_len = SHA3_512_BLOCKSIZE + data_len;
        std::vector<uint8_t> inner_data(inner_len);
        std::memcpy(inner_data.data(), ipad_key, SHA3_512_BLOCKSIZE);
        std::memcpy(inner_data.data() + SHA3_512_BLOCKSIZE, data, data_len);

        SHA3_512(inner_data.data(), inner_len, inner_hash);

        // inner_data automatically freed here - no memory leak on exception
    }

    // Outer hash: SHA3-512((K ⊕ opad) || inner_hash)
    {
        // Use std::vector for automatic memory management (RAII)
        size_t outer_len = SHA3_512_BLOCKSIZE + 64;
        std::vector<uint8_t> outer_data(outer_len);
        std::memcpy(outer_data.data(), opad_key, SHA3_512_BLOCKSIZE);
        std::memcpy(outer_data.data() + SHA3_512_BLOCKSIZE, inner_hash, 64);

        SHA3_512(outer_data.data(), outer_len, output);

        // outer_data automatically freed here - no memory leak on exception
    }

    // Wipe sensitive data
    std::memset(key_block, 0, SHA3_512_BLOCKSIZE);
    std::memset(ipad_key, 0, SHA3_512_BLOCKSIZE);
    std::memset(opad_key, 0, SHA3_512_BLOCKSIZE);
    std::memset(inner_hash, 0, 64);
}
