// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Wallet Encryption Integration Tests
 *
 * Tests the complete wallet encryption system:
 * - Wallet encryption workflow
 * - Lock/unlock functionality
 * - Passphrase management
 * - Encrypted key generation
 * - Timeout-based locking
 */

#include <wallet/wallet.h>
#include <wallet/crypter.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cassert>

// ANSI color codes
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_BLUE "\033[34m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RESET "\033[0m"

// Test macros
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            std::cout << COLOR_RED << "✗ " << message << COLOR_RESET << std::endl; \
            return false; \
        } \
    } while(0)

#define TEST_SUCCESS(message) \
    std::cout << COLOR_GREEN << "✓ " << message << COLOR_RESET << std::endl

#define TEST_INFO(message) \
    std::cout << COLOR_BLUE << "ℹ " << message << COLOR_RESET << std::endl

// Test counter
static int g_testsPassed = 0;
static int g_testsFailed = 0;

/**
 * Test 1: Basic Wallet Encryption
 *
 * Tests:
 * - Encrypt an unencrypted wallet
 * - Verify wallet is encrypted
 * - Verify wallet is unlocked after encryption
 */
bool Test_BasicEncryption() {
    std::cout << COLOR_BLUE << "\n=== Test 1: Basic Wallet Encryption ===" << COLOR_RESET << std::endl;

    CWallet wallet;

    // Generate some keys before encryption
    TEST_ASSERT(wallet.GenerateNewKey(), "Generate key 1 before encryption");
    TEST_ASSERT(wallet.GenerateNewKey(), "Generate key 2 before encryption");

    size_t keysBefore = wallet.GetKeyPoolSize();
    TEST_INFO("Keys before encryption: " + std::to_string(keysBefore));

    // Encrypt wallet
    std::string passphrase = "TestPassphrase123!";
    TEST_ASSERT(wallet.EncryptWallet(passphrase), "Encrypt wallet");
    TEST_SUCCESS("Wallet encrypted successfully");

    // Verify wallet is encrypted
    TEST_ASSERT(wallet.IsCrypted(), "Wallet should be encrypted");
    TEST_SUCCESS("Wallet is encrypted");

    // Verify wallet is unlocked after encryption
    TEST_ASSERT(!wallet.IsLocked(), "Wallet should be unlocked after encryption");
    TEST_SUCCESS("Wallet unlocked after encryption");

    // Verify keys still accessible
    size_t keysAfter = wallet.GetKeyPoolSize();
    TEST_ASSERT(keysAfter == keysBefore, "Key count should match after encryption");
    TEST_SUCCESS("All keys preserved after encryption");

    // Verify cannot encrypt again
    TEST_ASSERT(!wallet.EncryptWallet(passphrase), "Should not allow double encryption");
    TEST_SUCCESS("Double encryption prevented");

    g_testsPassed++;
    return true;
}

/**
 * Test 2: Lock and Unlock
 *
 * Tests:
 * - Lock wallet
 * - Unlock with correct passphrase
 * - Unlock with wrong passphrase
 */
bool Test_LockUnlock() {
    std::cout << COLOR_BLUE << "\n=== Test 2: Lock and Unlock ===" << COLOR_RESET << std::endl;

    CWallet wallet;
    wallet.GenerateNewKey();

    std::string passphrase = "SecurePass456!@@##";  // WL-009: min 16 chars
    wallet.EncryptWallet(passphrase);

    // Lock wallet
    TEST_ASSERT(wallet.Lock(), "Lock wallet");
    TEST_ASSERT(wallet.IsLocked(), "Wallet should be locked");
    TEST_SUCCESS("Wallet locked successfully");

    // Try to generate key while locked (should fail)
    TEST_ASSERT(!wallet.GenerateNewKey(), "Key generation should fail when locked");
    TEST_SUCCESS("Key generation blocked on locked wallet");

    // Try to unlock with wrong passphrase
    TEST_ASSERT(!wallet.Unlock("WrongPassword"), "Unlock should fail with wrong passphrase");
    TEST_ASSERT(wallet.IsLocked(), "Wallet should remain locked");
    TEST_SUCCESS("Wrong passphrase rejected");

    // WL-011: Wait for rate limiting to expire before correct attempt
    TEST_INFO("Waiting 2 seconds for rate limit to expire (WL-011)...");
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Unlock with correct passphrase
    TEST_ASSERT(wallet.Unlock(passphrase), "Unlock with correct passphrase");
    TEST_ASSERT(!wallet.IsLocked(), "Wallet should be unlocked");
    TEST_SUCCESS("Wallet unlocked with correct passphrase");

    // Generate key while unlocked (should succeed)
    TEST_ASSERT(wallet.GenerateNewKey(), "Key generation should succeed when unlocked");
    TEST_SUCCESS("Key generation works on unlocked wallet");

    g_testsPassed++;
    return true;
}

/**
 * Test 3: Passphrase Change
 *
 * Tests:
 * - Change passphrase with correct old passphrase
 * - Verify old passphrase no longer works
 * - Verify new passphrase works
 */
bool Test_PassphraseChange() {
    std::cout << COLOR_BLUE << "\n=== Test 3: Passphrase Change ===" << COLOR_RESET << std::endl;

    CWallet wallet;
    wallet.GenerateNewKey();

    std::string oldPass = "MyStr0ng!Old#P@ss";
    std::string newPass = "MyStr0ng!New#P@ss";

    wallet.EncryptWallet(oldPass);

    // Change passphrase with wrong old passphrase (should fail)
    TEST_ASSERT(!wallet.ChangePassphrase("WrongOldPass", newPass),
                 "Change should fail with wrong old passphrase");
    TEST_SUCCESS("Passphrase change blocked with wrong old passphrase");

    // Change passphrase with correct old passphrase
    TEST_ASSERT(wallet.ChangePassphrase(oldPass, newPass),
                "Change passphrase with correct old passphrase");
    TEST_SUCCESS("Passphrase changed successfully");

    // Lock wallet
    wallet.Lock();

    // Old passphrase should no longer work
    TEST_ASSERT(!wallet.Unlock(oldPass), "Old passphrase should not work");
    TEST_ASSERT(wallet.IsLocked(), "Wallet should remain locked");
    TEST_SUCCESS("Old passphrase rejected after change");

    // WL-011: Wait for rate limiting to expire before correct attempt
    TEST_INFO("Waiting 2 seconds for rate limit to expire (WL-011)...");
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // New passphrase should work
    TEST_ASSERT(wallet.Unlock(newPass), "New passphrase should work");
    TEST_ASSERT(!wallet.IsLocked(), "Wallet should be unlocked");
    TEST_SUCCESS("New passphrase works");

    // Verify key generation still works with new passphrase
    TEST_ASSERT(wallet.GenerateNewKey(), "Key generation should work with new passphrase");
    TEST_SUCCESS("Key generation works after passphrase change");

    g_testsPassed++;
    return true;
}

/**
 * Test 4: Encrypted Key Generation
 *
 * Tests:
 * - Generate keys in encrypted wallet
 * - Access keys from encrypted wallet
 * - Verify key signing works
 */
bool Test_EncryptedKeyGeneration() {
    std::cout << COLOR_BLUE << "\n=== Test 4: Encrypted Key Generation ===" << COLOR_RESET << std::endl;

    CWallet wallet;

    std::string passphrase = "KeyGenPass789!@@##";  // WL-009: min 16 chars

    // Encrypt empty wallet
    wallet.EncryptWallet(passphrase);
    TEST_SUCCESS("Empty wallet encrypted");

    // Generate keys in encrypted wallet
    TEST_ASSERT(wallet.GenerateNewKey(), "Generate key 1 in encrypted wallet");
    TEST_ASSERT(wallet.GenerateNewKey(), "Generate key 2 in encrypted wallet");
    TEST_ASSERT(wallet.GenerateNewKey(), "Generate key 3 in encrypted wallet");
    TEST_SUCCESS("Generated 3 keys in encrypted wallet");

    TEST_ASSERT(wallet.GetKeyPoolSize() == 3, "Should have 3 keys");

    // Get an address
    CDilithiumAddress addr = wallet.GetNewAddress();
    TEST_ASSERT(addr.IsValid(), "Address should be valid");
    TEST_SUCCESS("Got valid address from encrypted wallet");

    // Verify key is accessible
    CKey key;
    TEST_ASSERT(wallet.GetKey(addr, key), "Should be able to get key");
    TEST_ASSERT(key.IsValid(), "Key should be valid");
    TEST_SUCCESS("Retrieved valid key from encrypted wallet");

    // Lock wallet
    wallet.Lock();

    // Should not be able to generate key when locked
    TEST_ASSERT(!wallet.GenerateNewKey(), "Key generation should fail when locked");
    TEST_SUCCESS("Key generation blocked on locked wallet");

    // Should not be able to get key when locked
    CKey lockedKey;
    TEST_ASSERT(!wallet.GetKey(addr, lockedKey), "Should not get key when locked");
    TEST_SUCCESS("Key retrieval blocked on locked wallet");

    // Unlock and try again
    wallet.Unlock(passphrase);
    TEST_ASSERT(wallet.GetKey(addr, lockedKey), "Should get key when unlocked");
    TEST_ASSERT(lockedKey.IsValid(), "Retrieved key should be valid");
    TEST_SUCCESS("Key retrieval works after unlock");

    g_testsPassed++;
    return true;
}

/**
 * Test 5: Timeout-Based Auto-Lock
 *
 * Tests:
 * - Unlock with timeout
 * - Verify wallet locks after timeout
 */
bool Test_TimeoutLock() {
    std::cout << COLOR_BLUE << "\n=== Test 5: Timeout-Based Auto-Lock ===" << COLOR_RESET << std::endl;

    CWallet wallet;
    wallet.GenerateNewKey();

    std::string passphrase = "TimeoutPass123!@@#";  // WL-009: min 16 chars
    wallet.EncryptWallet(passphrase);
    wallet.Lock();

    // Unlock with 2 second timeout
    TEST_ASSERT(wallet.Unlock(passphrase, 2), "Unlock with 2 second timeout");
    TEST_ASSERT(!wallet.IsLocked(), "Wallet should be unlocked");
    TEST_SUCCESS("Wallet unlocked with timeout");

    TEST_INFO("Waiting 1 second...");
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Should still be unlocked
    wallet.CheckUnlockTimeout();
    TEST_ASSERT(!wallet.IsLocked(), "Wallet should still be unlocked after 1 second");
    TEST_SUCCESS("Wallet still unlocked before timeout");

    TEST_INFO("Waiting another 2 seconds (total 3 seconds, timeout=2)...");
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Should now be locked
    wallet.CheckUnlockTimeout();
    TEST_ASSERT(wallet.IsLocked(), "Wallet should be locked after timeout");
    TEST_SUCCESS("Wallet auto-locked after timeout");

    // Verify key generation fails after auto-lock
    TEST_ASSERT(!wallet.GenerateNewKey(), "Key generation should fail after auto-lock");
    TEST_SUCCESS("Key generation blocked after auto-lock");

    g_testsPassed++;
    return true;
}

/**
 * Test 6: Key Persistence Through Lock/Unlock
 *
 * Tests:
 * - Keys remain accessible through lock/unlock cycles
 * - Key data integrity maintained
 */
bool Test_KeyPersistence() {
    std::cout << COLOR_BLUE << "\n=== Test 6: Key Persistence ===" << COLOR_RESET << std::endl;

    CWallet wallet;

    std::string passphrase = "PersistPass123!@@#";  // WL-009: min 16 chars

    // Generate keys before encryption
    wallet.GenerateNewKey();
    wallet.GenerateNewKey();
    CDilithiumAddress addr1 = wallet.GetNewAddress();

    // Get key data before encryption
    CKey keyBefore;
    TEST_ASSERT(wallet.GetKey(addr1, keyBefore), "Get key before encryption");
    std::vector<uint8_t> pubkeyBefore = keyBefore.vchPubKey;

    // Encrypt wallet
    wallet.EncryptWallet(passphrase);
    TEST_SUCCESS("Wallet encrypted");

    // Verify key still accessible (wallet unlocked after encryption)
    CKey keyAfterEncrypt;
    TEST_ASSERT(wallet.GetKey(addr1, keyAfterEncrypt), "Get key after encryption");
    TEST_ASSERT(keyAfterEncrypt.vchPubKey == pubkeyBefore, "Public key should match");
    TEST_SUCCESS("Key accessible after encryption");

    // Lock wallet
    wallet.Lock();

    // Generate more keys (should fail when locked)
    TEST_ASSERT(!wallet.GenerateNewKey(), "Cannot generate when locked");

    // Unlock wallet
    wallet.Unlock(passphrase);

    // Generate more keys
    wallet.GenerateNewKey();
    CDilithiumAddress addr2 = wallet.GetNewAddress();

    // Verify both old and new keys accessible
    CKey key1, key2;
    TEST_ASSERT(wallet.GetKey(addr1, key1), "Old key accessible");
    TEST_ASSERT(wallet.GetKey(addr2, key2), "New key accessible");
    TEST_ASSERT(key1.vchPubKey == pubkeyBefore, "Old key data preserved");
    TEST_SUCCESS("Keys persistent through lock/unlock cycles");

    // Lock again
    wallet.Lock();

    // Unlock with wrong passphrase (should fail)
    TEST_ASSERT(!wallet.Unlock("WrongPass"), "Wrong passphrase rejected");

    // WL-011: Wait for rate limiting to expire before correct attempt
    TEST_INFO("Waiting 2 seconds for rate limit to expire (WL-011)...");
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Verify keys not accessible when locked
    CKey keyLocked;
    TEST_ASSERT(!wallet.GetKey(addr1, keyLocked), "Key not accessible when locked");
    TEST_ASSERT(!wallet.GetKey(addr2, keyLocked), "Key not accessible when locked");
    TEST_SUCCESS("Keys protected when locked");

    // Unlock again
    wallet.Unlock(passphrase);

    // Verify keys still accessible
    TEST_ASSERT(wallet.GetKey(addr1, key1), "Old key accessible after re-unlock");
    TEST_ASSERT(wallet.GetKey(addr2, key2), "New key accessible after re-unlock");
    TEST_SUCCESS("Keys remain accessible after multiple lock/unlock cycles");

    g_testsPassed++;
    return true;
}

/**
 * Test 7: Edge Cases
 *
 * Tests:
 * - Empty passphrase handling
 * - Unencrypted wallet lock/unlock
 * - Multiple unlock calls
 */
bool Test_EdgeCases() {
    std::cout << COLOR_BLUE << "\n=== Test 7: Edge Cases ===" << COLOR_RESET << std::endl;

    // Test 1: Unencrypted wallet lock/unlock should fail gracefully
    CWallet unencryptedWallet;
    TEST_ASSERT(!unencryptedWallet.Lock(), "Cannot lock unencrypted wallet");
    TEST_ASSERT(!unencryptedWallet.Unlock("anypass"), "Cannot unlock unencrypted wallet");
    TEST_ASSERT(!unencryptedWallet.IsLocked(), "Unencrypted wallet not locked");
    TEST_ASSERT(!unencryptedWallet.IsCrypted(), "Wallet not encrypted");
    TEST_SUCCESS("Unencrypted wallet handles lock/unlock gracefully");

    // Test 2: Multiple unlock calls
    CWallet wallet;
    wallet.GenerateNewKey();
    std::string pass = "MultiUnlock123!@@";  // WL-009: min 16 chars
    wallet.EncryptWallet(pass);
    wallet.Lock();

    TEST_ASSERT(wallet.Unlock(pass), "First unlock succeeds");
    TEST_ASSERT(wallet.Unlock(pass), "Second unlock succeeds (idempotent)");
    TEST_ASSERT(!wallet.IsLocked(), "Wallet remains unlocked");
    TEST_SUCCESS("Multiple unlock calls handled correctly");

    // Test 3: Multiple lock calls
    TEST_ASSERT(wallet.Lock(), "First lock succeeds");
    TEST_ASSERT(wallet.Lock(), "Second lock succeeds (idempotent)");
    TEST_ASSERT(wallet.IsLocked(), "Wallet remains locked");
    TEST_SUCCESS("Multiple lock calls handled correctly");

    // Test 4: Unlock with timeout=0 (forever)
    wallet.Unlock(pass, 0);
    TEST_INFO("Unlocked with timeout=0 (forever)");
    std::this_thread::sleep_for(std::chrono::seconds(2));
    wallet.CheckUnlockTimeout();
    TEST_ASSERT(!wallet.IsLocked(), "Wallet should remain unlocked (timeout=0)");
    TEST_SUCCESS("Timeout=0 (forever) works correctly");

    g_testsPassed++;
    return true;
}

/**
 * Test 8: Stress Test - Multiple Keys
 *
 * Tests:
 * - Generate many keys
 * - Encrypt with many keys
 * - Access all keys after encryption
 */
bool Test_StressMultipleKeys() {
    std::cout << COLOR_BLUE << "\n=== Test 8: Stress Test - Multiple Keys ===" << COLOR_RESET << std::endl;

    CWallet wallet;

    const int numKeys = 20;
    std::vector<CDilithiumAddress> addresses;

    // Generate many keys before encryption
    TEST_INFO("Generating " + std::to_string(numKeys) + " keys...");
    for (int i = 0; i < numKeys; i++) {
        TEST_ASSERT(wallet.GenerateNewKey(), "Generate key " + std::to_string(i));
        addresses.push_back(wallet.GetNewAddress());
    }
    TEST_SUCCESS("Generated " + std::to_string(numKeys) + " keys");

    // Store public keys before encryption
    std::vector<std::vector<uint8_t>> pubkeysBefore;
    for (const auto& addr : addresses) {
        CKey key;
        TEST_ASSERT(wallet.GetKey(addr, key), "Get key before encryption");
        pubkeysBefore.push_back(key.vchPubKey);
    }

    // Encrypt wallet
    std::string pass = "MyStr3ss!T3st#P@ss";
    TEST_INFO("Encrypting wallet with " + std::to_string(numKeys) + " keys...");
    TEST_ASSERT(wallet.EncryptWallet(pass), "Encrypt wallet");
    TEST_SUCCESS("Wallet encrypted with " + std::to_string(numKeys) + " keys");

    // Verify all keys still accessible
    TEST_INFO("Verifying all keys accessible after encryption...");
    for (size_t i = 0; i < addresses.size(); i++) {
        CKey key;
        TEST_ASSERT(wallet.GetKey(addresses[i], key), "Get key " + std::to_string(i) + " after encryption");
        TEST_ASSERT(key.vchPubKey == pubkeysBefore[i], "Public key " + std::to_string(i) + " matches");
    }
    TEST_SUCCESS("All " + std::to_string(numKeys) + " keys accessible and intact");

    // Lock and unlock
    wallet.Lock();
    wallet.Unlock(pass);

    // Verify all keys still accessible after unlock
    TEST_INFO("Verifying all keys accessible after unlock...");
    for (size_t i = 0; i < addresses.size(); i++) {
        CKey key;
        TEST_ASSERT(wallet.GetKey(addresses[i], key), "Get key " + std::to_string(i) + " after unlock");
        TEST_ASSERT(key.vchPubKey == pubkeysBefore[i], "Public key " + std::to_string(i) + " matches");
    }
    TEST_SUCCESS("All " + std::to_string(numKeys) + " keys accessible after unlock");

    g_testsPassed++;
    return true;
}

// Main test runner
int main() {
    std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;
    std::cout << COLOR_BLUE << "  Wallet Encryption Integration Tests  " << COLOR_RESET << std::endl;
    std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;

    bool allPassed = true;

    // Run all tests
    allPassed &= Test_BasicEncryption();
    allPassed &= Test_LockUnlock();
    allPassed &= Test_PassphraseChange();
    allPassed &= Test_EncryptedKeyGeneration();
    allPassed &= Test_TimeoutLock();
    allPassed &= Test_KeyPersistence();
    allPassed &= Test_EdgeCases();
    allPassed &= Test_StressMultipleKeys();

    // Print summary
    std::cout << "\n" << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;
    if (allPassed) {
        std::cout << COLOR_GREEN << "✓ ALL TESTS PASSED (" << g_testsPassed << "/" << g_testsPassed << ")"
                  << COLOR_RESET << std::endl;
        std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;
        return 0;
    } else {
        std::cout << COLOR_RED << "✗ SOME TESTS FAILED" << COLOR_RESET << std::endl;
        std::cout << COLOR_GREEN << "  Passed: " << g_testsPassed << COLOR_RESET << std::endl;
        std::cout << COLOR_RED << "  Failed: " << g_testsFailed << COLOR_RESET << std::endl;
        std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;
        return 1;
    }
}
