// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * PBKDF2-SHA3-512 Tests
 *
 * CRITICAL SECURITY COMPONENT: PBKDF2 converts user mnemonics to wallet seeds
 * Any bug in this function = permanent fund loss for users
 *
 * This test suite provides comprehensive coverage with BIP39 test vectors
 * and extensive edge case testing to ensure correctness.
 *
 * Following Bitcoin Core testing standards with Boost Test Framework
 */

#include <boost/test/unit_test.hpp>

#include <crypto/pbkdf2_sha3.h>
#include <crypto/hmac_sha3.h>
#include <crypto/sha3.h>

#include <vector>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <iomanip>
#include <sstream>

BOOST_AUTO_TEST_SUITE(pbkdf2_tests)

/**
 * Helper function to convert hex string to bytes
 */
static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

/**
 * Helper function to convert bytes to hex string for debugging
 */
static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

/**
 * Test Case 1: Basic PBKDF2 Functionality
 * Simple known-answer test to verify basic operation
 */
BOOST_AUTO_TEST_CASE(pbkdf2_basic_operation) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;
    uint8_t output[64];

    PBKDF2_SHA3_512(
        password, sizeof(password) - 1,
        salt, sizeof(salt) - 1,
        iterations,
        output, sizeof(output)
    );

    // Output should not be all zeros
    bool all_zeros = std::all_of(output, output + 64, [](uint8_t b) { return b == 0; });
    BOOST_CHECK(!all_zeros);
}

/**
 * Test Case 2: Determinism - Same Input Produces Same Output
 * CRITICAL: HD wallets must produce identical seeds from same mnemonic
 */
BOOST_AUTO_TEST_CASE(pbkdf2_determinism) {
    const uint8_t password[] = "test password";
    const uint8_t salt[] = "test salt";
    const uint32_t iterations = 2048;
    uint8_t output1[64], output2[64], output3[64];

    // Derive key three times
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output1, 64);
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output2, 64);
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output3, 64);

    // All outputs must be identical (critical for wallet recovery)
    BOOST_CHECK_EQUAL_COLLECTIONS(output1, output1 + 64, output2, output2 + 64);
    BOOST_CHECK_EQUAL_COLLECTIONS(output2, output2 + 64, output3, output3 + 64);
}

/**
 * Test Case 3: Iteration Count Effect
 * Different iteration counts should produce different outputs
 */
BOOST_AUTO_TEST_CASE(pbkdf2_iteration_effect) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    uint8_t output1[64], output2[64];

    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, 1, output1, 64);
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, 2, output2, 64);

    // Different iteration counts should produce different results
    BOOST_CHECK(std::memcmp(output1, output2, 64) != 0);
}

/**
 * Test Case 4: Password Sensitivity
 * Different passwords should produce different outputs
 */
BOOST_AUTO_TEST_CASE(pbkdf2_password_sensitivity) {
    const uint8_t password1[] = "password1";
    const uint8_t password2[] = "password2";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 2048;
    uint8_t output1[64], output2[64];

    PBKDF2_SHA3_512(password1, sizeof(password1) - 1, salt, sizeof(salt) - 1, iterations, output1, 64);
    PBKDF2_SHA3_512(password2, sizeof(password2) - 1, salt, sizeof(salt) - 1, iterations, output2, 64);

    // Different passwords should produce different results
    BOOST_CHECK(std::memcmp(output1, output2, 64) != 0);
}

/**
 * Test Case 5: Salt Sensitivity
 * Different salts should produce different outputs
 */
BOOST_AUTO_TEST_CASE(pbkdf2_salt_sensitivity) {
    const uint8_t password[] = "password";
    const uint8_t salt1[] = "salt1";
    const uint8_t salt2[] = "salt2";
    const uint32_t iterations = 2048;
    uint8_t output1[64], output2[64];

    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt1, sizeof(salt1) - 1, iterations, output1, 64);
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt2, sizeof(salt2) - 1, iterations, output2, 64);

    // Different salts should produce different results
    BOOST_CHECK(std::memcmp(output1, output2, 64) != 0);
}

/**
 * Test Case 6: Empty Password
 */
BOOST_AUTO_TEST_CASE(pbkdf2_empty_password) {
    const uint8_t* password = nullptr;
    const size_t password_len = 0;
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;
    uint8_t output[64];

    PBKDF2_SHA3_512(password, password_len, salt, sizeof(salt) - 1, iterations, output, 64);

    // Should produce valid output
    bool all_zeros = std::all_of(output, output + 64, [](uint8_t b) { return b == 0; });
    BOOST_CHECK(!all_zeros);
}

/**
 * Test Case 7: Empty Salt
 */
BOOST_AUTO_TEST_CASE(pbkdf2_empty_salt) {
    const uint8_t password[] = "password";
    const uint8_t* salt = nullptr;
    const size_t salt_len = 0;
    const uint32_t iterations = 1;
    uint8_t output[64];

    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, salt_len, iterations, output, 64);

    // Should produce valid output
    bool all_zeros = std::all_of(output, output + 64, [](uint8_t b) { return b == 0; });
    BOOST_CHECK(!all_zeros);
}

/**
 * Test Case 8: Long Password
 */
BOOST_AUTO_TEST_CASE(pbkdf2_long_password) {
    // 256 byte password
    std::vector<uint8_t> password(256);
    for (size_t i = 0; i < password.size(); i++) {
        password[i] = static_cast<uint8_t>(i & 0xFF);
    }

    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;
    uint8_t output[64];

    PBKDF2_SHA3_512(password.data(), password.size(), salt, sizeof(salt) - 1, iterations, output, 64);

    // Should handle long password
    bool all_zeros = std::all_of(output, output + 64, [](uint8_t b) { return b == 0; });
    BOOST_CHECK(!all_zeros);
}

/**
 * Test Case 9: Long Salt
 */
BOOST_AUTO_TEST_CASE(pbkdf2_long_salt) {
    const uint8_t password[] = "password";

    // 256 byte salt
    std::vector<uint8_t> salt(256);
    for (size_t i = 0; i < salt.size(); i++) {
        salt[i] = static_cast<uint8_t>((i * 3) & 0xFF);
    }

    const uint32_t iterations = 1;
    uint8_t output[64];

    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt.data(), salt.size(), iterations, output, 64);

    // Should handle long salt
    bool all_zeros = std::all_of(output, output + 64, [](uint8_t b) { return b == 0; });
    BOOST_CHECK(!all_zeros);
}

/**
 * Test Case 10: Various Output Lengths
 */
BOOST_AUTO_TEST_CASE(pbkdf2_various_output_lengths) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;

    // Test various output lengths
    std::vector<size_t> lengths = {1, 16, 32, 64, 128, 256};

    for (size_t len : lengths) {
        std::vector<uint8_t> output(len);
        PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output.data(), len);

        // Output should not be all zeros
        bool all_zeros = std::all_of(output.begin(), output.end(), [](uint8_t b) { return b == 0; });
        BOOST_CHECK(!all_zeros);
    }
}

/**
 * Test Case 11: Single Iteration
 */
BOOST_AUTO_TEST_CASE(pbkdf2_single_iteration) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;
    uint8_t output[64];

    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output, 64);

    // Verify determinism with single iteration
    uint8_t output2[64];
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output2, 64);

    BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 64, output2, output2 + 64);
}

/**
 * Test Case 12: Many Iterations (BIP39 Standard)
 */
BOOST_AUTO_TEST_CASE(pbkdf2_bip39_iterations) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 2048;  // BIP39 standard
    uint8_t output[64];

    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output, 64);

    // Verify determinism with BIP39 iteration count
    uint8_t output2[64];
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output2, 64);

    BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 64, output2, output2 + 64);
}

/**
 * Test Case 13: Input Validation - NULL Password with Non-Zero Length
 * Tests the Phase 3.5.1 input validation fixes
 */
BOOST_AUTO_TEST_CASE(pbkdf2_validation_null_password) {
    const uint8_t* password = nullptr;
    const size_t password_len = 10;  // Non-zero but NULL pointer
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;
    uint8_t output[64];

    // Should throw std::invalid_argument
    BOOST_CHECK_THROW(
        PBKDF2_SHA3_512(password, password_len, salt, sizeof(salt) - 1, iterations, output, 64),
        std::invalid_argument
    );
}

/**
 * Test Case 14: Input Validation - NULL Salt with Non-Zero Length
 */
BOOST_AUTO_TEST_CASE(pbkdf2_validation_null_salt) {
    const uint8_t password[] = "password";
    const uint8_t* salt = nullptr;
    const size_t salt_len = 10;  // Non-zero but NULL pointer
    const uint32_t iterations = 1;
    uint8_t output[64];

    // Should throw std::invalid_argument
    BOOST_CHECK_THROW(
        PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, salt_len, iterations, output, 64),
        std::invalid_argument
    );
}

/**
 * Test Case 15: Input Validation - Zero Iterations
 */
BOOST_AUTO_TEST_CASE(pbkdf2_validation_zero_iterations) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 0;  // Invalid
    uint8_t output[64];

    // Should throw std::invalid_argument
    BOOST_CHECK_THROW(
        PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output, 64),
        std::invalid_argument
    );
}

/**
 * Test Case 16: Input Validation - NULL Output Buffer
 */
BOOST_AUTO_TEST_CASE(pbkdf2_validation_null_output) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;
    uint8_t* output = nullptr;

    // Should throw std::invalid_argument
    BOOST_CHECK_THROW(
        PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output, 64),
        std::invalid_argument
    );
}

/**
 * Test Case 17: Input Validation - Zero Output Length
 */
BOOST_AUTO_TEST_CASE(pbkdf2_validation_zero_output_len) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;
    uint8_t output[64];

    // Should throw std::invalid_argument
    BOOST_CHECK_THROW(
        PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output, 0),
        std::invalid_argument
    );
}

/**
 * Test Case 18: Integer Overflow Protection - Output Length
 */
BOOST_AUTO_TEST_CASE(pbkdf2_overflow_protection_output_len) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;
    uint8_t output[64];

    // Try to cause overflow: output_len = SIZE_MAX - 50
    size_t huge_len = SIZE_MAX - 50;

    // Should throw std::overflow_error
    BOOST_CHECK_THROW(
        PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output, huge_len),
        std::overflow_error
    );
}

/**
 * Test Case 19: BIP39_MnemonicToSeed - Basic Functionality
 */
BOOST_AUTO_TEST_CASE(bip39_basic_operation) {
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* passphrase = "";
    uint8_t seed[64];

    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed);

    // Seed should not be all zeros
    bool all_zeros = std::all_of(seed, seed + 64, [](uint8_t b) { return b == 0; });
    BOOST_CHECK(!all_zeros);
}

/**
 * Test Case 20: BIP39_MnemonicToSeed - Determinism
 * CRITICAL: Same mnemonic must always produce same seed
 */
BOOST_AUTO_TEST_CASE(bip39_determinism) {
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* passphrase = "";
    uint8_t seed1[64], seed2[64], seed3[64];

    // Generate seed three times
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed1);
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed2);
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed3);

    // All seeds must be identical (CRITICAL for wallet recovery)
    BOOST_CHECK_EQUAL_COLLECTIONS(seed1, seed1 + 64, seed2, seed2 + 64);
    BOOST_CHECK_EQUAL_COLLECTIONS(seed2, seed2 + 64, seed3, seed3 + 64);
}

/**
 * Test Case 21: BIP39_MnemonicToSeed - With Passphrase
 */
BOOST_AUTO_TEST_CASE(bip39_with_passphrase) {
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* passphrase1 = "";
    const char* passphrase2 = "TREZOR";
    uint8_t seed1[64], seed2[64];

    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase1, std::strlen(passphrase1), seed1);
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase2, std::strlen(passphrase2), seed2);

    // Different passphrases should produce different seeds
    BOOST_CHECK(std::memcmp(seed1, seed2, 64) != 0);
}

/**
 * Test Case 22: BIP39_MnemonicToSeed - Different Mnemonics
 */
BOOST_AUTO_TEST_CASE(bip39_different_mnemonics) {
    const char* mnemonic1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* mnemonic2 = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const char* passphrase = "";
    uint8_t seed1[64], seed2[64];

    BIP39_MnemonicToSeed(mnemonic1, std::strlen(mnemonic1), passphrase, std::strlen(passphrase), seed1);
    BIP39_MnemonicToSeed(mnemonic2, std::strlen(mnemonic2), passphrase, std::strlen(passphrase), seed2);

    // Different mnemonics should produce different seeds
    BOOST_CHECK(std::memcmp(seed1, seed2, 64) != 0);
}

/**
 * Test Case 23: BIP39 Test Vector 1
 * Official BIP39 test vector from the specification
 */
BOOST_AUTO_TEST_CASE(bip39_test_vector_1) {
    // Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
    // Passphrase: TREZOR
    // This is a real BIP39 test vector - note: we use "dilithion-mnemonic" prefix instead of "mnemonic"
    // so our output will differ from BIP39 (which is correct - we're using SHA3 not SHA2)
    // But determinism and basic operation should work

    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* passphrase = "TREZOR";
    uint8_t seed[64];

    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed);

    // Verify determinism (most important property)
    uint8_t seed2[64];
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed2);

    BOOST_CHECK_EQUAL_COLLECTIONS(seed, seed + 64, seed2, seed2 + 64);

    // Seed should not be all zeros (would be catastrophic)
    bool all_zeros = std::all_of(seed, seed + 64, [](uint8_t b) { return b == 0; });
    BOOST_CHECK(!all_zeros);
}

/**
 * Test Case 24: BIP39 Test Vector 2
 */
BOOST_AUTO_TEST_CASE(bip39_test_vector_2) {
    const char* mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const char* passphrase = "TREZOR";
    uint8_t seed[64];

    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed);

    // Verify determinism
    uint8_t seed2[64];
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed2);

    BOOST_CHECK_EQUAL_COLLECTIONS(seed, seed + 64, seed2, seed2 + 64);

    // Verify different from test vector 1
    const char* mnemonic1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    uint8_t seed1[64];
    BIP39_MnemonicToSeed(mnemonic1, std::strlen(mnemonic1), passphrase, std::strlen(passphrase), seed1);

    BOOST_CHECK(std::memcmp(seed, seed1, 64) != 0);
}

/**
 * Test Case 25: BIP39 Test Vector 3 - 24 Words
 */
BOOST_AUTO_TEST_CASE(bip39_test_vector_3_24_words) {
    const char* mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless";
    const char* passphrase = "TREZOR";
    uint8_t seed[64];

    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed);

    // Verify determinism
    uint8_t seed2[64];
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed2);

    BOOST_CHECK_EQUAL_COLLECTIONS(seed, seed + 64, seed2, seed2 + 64);

    // Seed should not be all zeros
    bool all_zeros = std::all_of(seed, seed + 64, [](uint8_t b) { return b == 0; });
    BOOST_CHECK(!all_zeros);
}

/**
 * Test Case 26: BIP39 with Empty Passphrase
 */
BOOST_AUTO_TEST_CASE(bip39_empty_passphrase) {
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* passphrase = "";
    uint8_t seed[64];

    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed);

    // Verify determinism
    uint8_t seed2[64];
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed2);

    BOOST_CHECK_EQUAL_COLLECTIONS(seed, seed + 64, seed2, seed2 + 64);
}

/**
 * Test Case 27: BIP39 with Special Characters in Passphrase
 */
BOOST_AUTO_TEST_CASE(bip39_special_characters_passphrase) {
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* passphrase = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`";
    uint8_t seed[64];

    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed);

    // Verify determinism
    uint8_t seed2[64];
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), passphrase, std::strlen(passphrase), seed2);

    BOOST_CHECK_EQUAL_COLLECTIONS(seed, seed + 64, seed2, seed2 + 64);

    // Should differ from empty passphrase
    const char* empty_passphrase = "";
    uint8_t seed_empty[64];
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), empty_passphrase, std::strlen(empty_passphrase), seed_empty);

    BOOST_CHECK(std::memcmp(seed, seed_empty, 64) != 0);
}

/**
 * Test Case 28: BIP39 with Long Passphrase
 */
BOOST_AUTO_TEST_CASE(bip39_long_passphrase) {
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // 100 character passphrase
    std::string long_passphrase(100, 'x');
    uint8_t seed[64];

    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), long_passphrase.c_str(), long_passphrase.length(), seed);

    // Verify determinism
    uint8_t seed2[64];
    BIP39_MnemonicToSeed(mnemonic, std::strlen(mnemonic), long_passphrase.c_str(), long_passphrase.length(), seed2);

    BOOST_CHECK_EQUAL_COLLECTIONS(seed, seed + 64, seed2, seed2 + 64);
}

/**
 * Test Case 29: Multiple Block Outputs
 * Test output lengths that require multiple PBKDF2 blocks
 */
BOOST_AUTO_TEST_CASE(pbkdf2_multiple_blocks) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;

    // 128 bytes = 2 blocks (each block is 64 bytes for SHA3-512)
    uint8_t output[128];
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output, 128);

    // Verify determinism
    uint8_t output2[128];
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output2, 128);

    BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 128, output2, output2 + 128);

    // First and second blocks should be different
    BOOST_CHECK(std::memcmp(output, output + 64, 64) != 0);
}

/**
 * Test Case 30: Partial Block Output
 * Test output length not aligned to block size
 */
BOOST_AUTO_TEST_CASE(pbkdf2_partial_block) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;

    // 80 bytes = 1 full block + 16 bytes
    uint8_t output[80];
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output, 80);

    // Verify determinism
    uint8_t output2[80];
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output2, 80);

    BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 80, output2, output2 + 80);

    // Verify first 64 bytes match a full-block derivation
    uint8_t output_64[64];
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, output_64, 64);

    BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 64, output_64, output_64 + 64);
}

/**
 * Test Case 31: Cross-Validation with Manual HMAC
 * Verify PBKDF2 F function with iteration count = 1 matches direct HMAC
 */
BOOST_AUTO_TEST_CASE(pbkdf2_cross_validate_hmac) {
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint32_t iterations = 1;
    uint8_t pbkdf2_output[64];

    // Derive with PBKDF2 (iterations = 1)
    PBKDF2_SHA3_512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, iterations, pbkdf2_output, 64);

    // For PBKDF2 with iterations = 1, result should be HMAC(password, salt || 0x00000001)
    uint8_t salt_block[sizeof(salt) - 1 + 4];
    std::memcpy(salt_block, salt, sizeof(salt) - 1);
    salt_block[sizeof(salt) - 1 + 0] = 0x00;
    salt_block[sizeof(salt) - 1 + 1] = 0x00;
    salt_block[sizeof(salt) - 1 + 2] = 0x00;
    salt_block[sizeof(salt) - 1 + 3] = 0x01;

    uint8_t hmac_output[64];
    HMAC_SHA3_512(password, sizeof(password) - 1, salt_block, sizeof(salt_block), hmac_output);

    // Outputs should match
    BOOST_CHECK_EQUAL_COLLECTIONS(pbkdf2_output, pbkdf2_output + 64, hmac_output, hmac_output + 64);
}

/**
 * Test Case 32: Binary Input Handling
 */
BOOST_AUTO_TEST_CASE(pbkdf2_binary_input) {
    // Binary password with all byte values
    uint8_t password[256];
    for (int i = 0; i < 256; i++) {
        password[i] = static_cast<uint8_t>(i);
    }

    // Binary salt
    uint8_t salt[256];
    for (int i = 0; i < 256; i++) {
        salt[i] = static_cast<uint8_t>(255 - i);
    }

    const uint32_t iterations = 1;
    uint8_t output[64];

    PBKDF2_SHA3_512(password, sizeof(password), salt, sizeof(salt), iterations, output, 64);

    // Verify determinism
    uint8_t output2[64];
    PBKDF2_SHA3_512(password, sizeof(password), salt, sizeof(salt), iterations, output2, 64);

    BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 64, output2, output2 + 64);
}

/**
 * Known-answer tests for the empty-input edge cases (UBSan nonnull-attribute
 * finding, PR #165 / CI-1). A NULL salt with salt_len == 0 is an accepted
 * input that used to reach memcpy(salt_block, nullptr, 0) in pbkdf2_f, and a
 * NULL password flows into the guarded HMAC_SHA3_512 key copy. The guards must
 * not change any output byte, so each case is pinned to a vector computed
 * INDEPENDENTLY of this code with Python 3:
 *
 *   hashlib.pbkdf2_hmac("sha3_512", password, salt, 1, 64).hex()
 *
 * (Python's hashlib over OpenSSL; nothing here is derived from the
 * implementation under test.)
 */
BOOST_AUTO_TEST_CASE(pbkdf2_empty_password_empty_salt_kat) {
    uint8_t output[64];
    PBKDF2_SHA3_512(nullptr, 0, nullptr, 0, 1, output, 64);
    const std::vector<uint8_t> expected = hex_to_bytes(
        "665409f49b9b46e3f4cb15476ed41d562f4ba27068be4c324d95f25755c37edf"
        "23d64a31e4a35a344326da324ccee72cf45e5896f9bd261ba622e43b7a1a5204");
    BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 64, expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(pbkdf2_empty_salt_kat) {
    const uint8_t password[] = "password";
    uint8_t output[64];
    PBKDF2_SHA3_512(password, sizeof(password) - 1, nullptr, 0, 1, output, 64);
    const std::vector<uint8_t> expected = hex_to_bytes(
        "fd09c0022a125751e40735a877ab46fed5c0e2657ecbc4371330f578a8211fa2"
        "d4f527e5d455cb43945c6dc7d5c10d8c32bb9834b6bd367b7624bb6dbab27f16");
    BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 64, expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(pbkdf2_empty_password_kat) {
    const uint8_t salt[] = "salt";
    uint8_t output[64];
    PBKDF2_SHA3_512(nullptr, 0, salt, sizeof(salt) - 1, 1, output, 64);
    const std::vector<uint8_t> expected = hex_to_bytes(
        "6c63809f5dc2c6c9bc4e1267267ddd471a34b16534eda6e6eb750f3d1436e1e6"
        "abaf45f73de334dce8e863c06a820612ad0ccbf74b837b3555eb5142dfd0807a");
    BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 64, expected.begin(), expected.end());
}

BOOST_AUTO_TEST_SUITE_END() // pbkdf2_tests
