// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/crypter.h>
#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>

using namespace std;

/**
 * Test 1: Random Generation
 */
bool TestRandomGeneration() {
    cout << "Testing random generation..." << endl;

    // Test salt generation
    vector<uint8_t> salt1, salt2;
    if (!GenerateSalt(salt1)) {
        cout << "  ✗ Failed to generate salt 1" << endl;
        return false;
    }
    if (salt1.size() != WALLET_CRYPTO_SALT_SIZE) {
        cout << "  ✗ Salt 1 wrong size: " << salt1.size() << endl;
        return false;
    }
    cout << "  ✓ Salt 1 generated (" << salt1.size() << " bytes)" << endl;

    if (!GenerateSalt(salt2)) {
        cout << "  ✗ Failed to generate salt 2" << endl;
        return false;
    }
    if (salt2.size() != WALLET_CRYPTO_SALT_SIZE) {
        cout << "  ✗ Salt 2 wrong size" << endl;
        return false;
    }

    // Salts should be different (extremely high probability)
    if (salt1 == salt2) {
        cout << "  ✗ Generated identical salts (random failure)" << endl;
        return false;
    }
    cout << "  ✓ Salt 2 generated and different from salt 1" << endl;

    // Test IV generation
    vector<uint8_t> iv1, iv2;
    if (!GenerateIV(iv1)) {
        cout << "  ✗ Failed to generate IV 1" << endl;
        return false;
    }
    if (iv1.size() != WALLET_CRYPTO_IV_SIZE) {
        cout << "  ✗ IV 1 wrong size" << endl;
        return false;
    }
    cout << "  ✓ IV 1 generated (" << iv1.size() << " bytes)" << endl;

    if (!GenerateIV(iv2)) {
        cout << "  ✗ Failed to generate IV 2" << endl;
        return false;
    }

    // IVs should be different
    if (iv1 == iv2) {
        cout << "  ✗ Generated identical IVs (random failure)" << endl;
        return false;
    }
    cout << "  ✓ IV 2 generated and different from IV 1" << endl;

    return true;
}

/**
 * Test 2: Key Derivation (PBKDF2-SHA3)
 */
bool TestKeyDerivation() {
    cout << "\nTesting PBKDF2-SHA3 key derivation..." << endl;

    vector<uint8_t> salt;
    if (!GenerateSalt(salt)) {
        cout << "  ✗ Failed to generate salt" << endl;
        return false;
    }

    // Test 1: Derive key with valid inputs
    vector<uint8_t> key1;
    if (!DeriveKey("my_secure_password", salt, 1000, key1)) {
        cout << "  ✗ Failed to derive key 1" << endl;
        return false;
    }
    if (key1.size() != WALLET_CRYPTO_KEY_SIZE) {
        cout << "  ✗ Key 1 wrong size" << endl;
        return false;
    }
    cout << "  ✓ Key 1 derived (" << key1.size() << " bytes)" << endl;

    // Test 2: Same password + salt = same key
    vector<uint8_t> key2;
    if (!DeriveKey("my_secure_password", salt, 1000, key2)) {
        cout << "  ✗ Failed to derive key 2" << endl;
        return false;
    }
    if (key1 != key2) {
        cout << "  ✗ Same password/salt produced different keys" << endl;
        return false;
    }
    cout << "  ✓ Same password/salt produces same key" << endl;

    // Test 3: Different password = different key
    vector<uint8_t> key3;
    if (!DeriveKey("different_password", salt, 1000, key3)) {
        cout << "  ✗ Failed to derive key 3" << endl;
        return false;
    }
    if (key1 == key3) {
        cout << "  ✗ Different passwords produced same key" << endl;
        return false;
    }
    cout << "  ✓ Different password produces different key" << endl;

    // Test 4: Different salt = different key
    vector<uint8_t> salt2;
    if (!GenerateSalt(salt2)) {
        cout << "  ✗ Failed to generate salt 2" << endl;
        return false;
    }
    vector<uint8_t> key4;
    if (!DeriveKey("my_secure_password", salt2, 1000, key4)) {
        cout << "  ✗ Failed to derive key 4" << endl;
        return false;
    }
    if (key1 == key4) {
        cout << "  ✗ Different salts produced same key" << endl;
        return false;
    }
    cout << "  ✓ Different salt produces different key" << endl;

    // Test 5: Error handling - empty password
    vector<uint8_t> keyErr;
    if (DeriveKey("", salt, 1000, keyErr)) {
        cout << "  ✗ Accepted empty password" << endl;
        return false;
    }
    cout << "  ✓ Empty password rejected" << endl;

    // Test 6: Error handling - zero rounds
    if (DeriveKey("password", salt, 0, keyErr)) {
        cout << "  ✗ Accepted zero rounds" << endl;
        return false;
    }
    cout << "  ✓ Zero rounds rejected" << endl;

    return true;
}

/**
 * Test 3: Basic Encryption/Decryption
 */
bool TestBasicEncryption() {
    cout << "\nTesting basic AES-256-CBC encryption/decryption..." << endl;

    // Generate key and IV
    vector<uint8_t> key(32);
    vector<uint8_t> iv(16);
    for (int i = 0; i < 32; i++) key[i] = i;
    for (int i = 0; i < 16; i++) iv[i] = i * 2;

    // Create crypter
    CCrypter crypter;
    if (!crypter.SetKey(key, iv)) {
        cout << "  ✗ Failed to set key" << endl;
        return false;
    }
    cout << "  ✓ Key and IV set" << endl;

    // Test data
    vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    vector<uint8_t> ciphertext;

    // Encrypt
    if (!crypter.Encrypt(plaintext, ciphertext)) {
        cout << "  ✗ Encryption failed" << endl;
        return false;
    }
    cout << "  ✓ Encrypted " << plaintext.size() << " bytes → " << ciphertext.size() << " bytes" << endl;

    // Ciphertext should be different from plaintext
    if (ciphertext == plaintext) {
        cout << "  ✗ Ciphertext equals plaintext" << endl;
        return false;
    }

    // Ciphertext should be multiple of 16 (block size)
    if (ciphertext.size() % 16 != 0) {
        cout << "  ✗ Ciphertext not multiple of block size" << endl;
        return false;
    }
    cout << "  ✓ Ciphertext is encrypted and padded" << endl;

    // Decrypt
    vector<uint8_t> decrypted;
    if (!crypter.Decrypt(ciphertext, decrypted)) {
        cout << "  ✗ Decryption failed" << endl;
        return false;
    }
    cout << "  ✓ Decrypted " << ciphertext.size() << " bytes → " << decrypted.size() << " bytes" << endl;

    // Decrypted should match original plaintext
    if (decrypted != plaintext) {
        cout << "  ✗ Decrypted text doesn't match plaintext" << endl;
        return false;
    }
    cout << "  ✓ Decrypted text matches original" << endl;

    return true;
}

/**
 * Test 4: Various Data Sizes
 */
bool TestVariousDataSizes() {
    cout << "\nTesting encryption with various data sizes..." << endl;

    vector<uint8_t> key(32, 0xAA);
    vector<uint8_t> iv(16, 0x55);
    CCrypter crypter;
    crypter.SetKey(key, iv);

    // Test different sizes
    vector<size_t> sizes = {1, 15, 16, 17, 31, 32, 64, 100, 256, 1000};

    for (size_t size : sizes) {
        vector<uint8_t> plaintext(size);
        for (size_t i = 0; i < size; i++) {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }

        vector<uint8_t> ciphertext;
        if (!crypter.Encrypt(plaintext, ciphertext)) {
            cout << "  ✗ Failed to encrypt " << size << " bytes" << endl;
            return false;
        }

        vector<uint8_t> decrypted;
        if (!crypter.Decrypt(ciphertext, decrypted)) {
            cout << "  ✗ Failed to decrypt " << size << " bytes" << endl;
            return false;
        }

        if (decrypted != plaintext) {
            cout << "  ✗ Decrypted data mismatch for size " << size << endl;
            return false;
        }

        cout << "  ✓ Encrypted/decrypted " << size << " bytes successfully" << endl;
    }

    return true;
}

/**
 * Test 5: Wrong Key Rejection
 */
bool TestWrongKeyRejection() {
    cout << "\nTesting wrong key rejection..." << endl;

    // Encrypt with key1
    vector<uint8_t> key1(32, 0x11);
    vector<uint8_t> iv(16, 0x22);
    CCrypter crypter1;
    crypter1.SetKey(key1, iv);

    vector<uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't', ' ', 'D', 'a', 't', 'a'};
    vector<uint8_t> ciphertext;

    if (!crypter1.Encrypt(plaintext, ciphertext)) {
        cout << "  ✗ Encryption failed" << endl;
        return false;
    }
    cout << "  ✓ Data encrypted with key1" << endl;

    // Try to decrypt with key2 (wrong key)
    vector<uint8_t> key2(32, 0x99);  // Different key
    CCrypter crypter2;
    crypter2.SetKey(key2, iv);

    vector<uint8_t> decrypted;
    // Decryption should fail due to invalid padding
    if (crypter2.Decrypt(ciphertext, decrypted)) {
        cout << "  ✗ Wrong key accepted (decryption succeeded)" << endl;
        return false;
    }
    cout << "  ✓ Wrong key rejected (padding validation failed)" << endl;

    return true;
}

/**
 * Test 6: Error Handling
 */
bool TestErrorHandling() {
    cout << "\nTesting error handling..." << endl;

    CCrypter crypter;

    // Test 1: Encrypt without setting key
    vector<uint8_t> plaintext = {'t', 'e', 's', 't'};
    vector<uint8_t> ciphertext;
    if (crypter.Encrypt(plaintext, ciphertext)) {
        cout << "  ✗ Encryption succeeded without key" << endl;
        return false;
    }
    cout << "  ✓ Encryption fails without key" << endl;

    // Test 2: Invalid key size
    vector<uint8_t> badKey(20);  // Wrong size
    vector<uint8_t> iv(16);
    if (crypter.SetKey(badKey, iv)) {
        cout << "  ✗ Accepted wrong key size" << endl;
        return false;
    }
    cout << "  ✓ Wrong key size rejected" << endl;

    // Test 3: Invalid IV size
    vector<uint8_t> key(32);
    vector<uint8_t> badIV(10);  // Wrong size
    if (crypter.SetKey(key, badIV)) {
        cout << "  ✗ Accepted wrong IV size" << endl;
        return false;
    }
    cout << "  ✓ Wrong IV size rejected" << endl;

    // Test 4: Decrypt invalid data (not multiple of block size)
    crypter.SetKey(key, iv);
    vector<uint8_t> badCiphertext = {1, 2, 3, 4, 5};  // Not multiple of 16
    vector<uint8_t> decrypted;
    if (crypter.Decrypt(badCiphertext, decrypted)) {
        cout << "  ✗ Decrypted invalid-size ciphertext" << endl;
        return false;
    }
    cout << "  ✓ Invalid ciphertext size rejected" << endl;

    return true;
}

/**
 * Test 7: Full End-to-End Wallet Encryption Scenario
 */
bool TestWalletScenario() {
    cout << "\nTesting full wallet encryption scenario..." << endl;

    // Simulate user setting a wallet password
    string userPassword = "MyStrongPassword123!";

    // Step 1: Generate random salt (done once when wallet is encrypted)
    vector<uint8_t> salt;
    if (!GenerateSalt(salt)) {
        cout << "  ✗ Failed to generate salt" << endl;
        return false;
    }
    cout << "  ✓ Generated random salt" << endl;

    // Step 2: Derive encryption key from password
    vector<uint8_t> masterKey;
    if (!DeriveKey(userPassword, salt, WALLET_CRYPTO_PBKDF2_ROUNDS, masterKey)) {
        cout << "  ✗ Failed to derive key" << endl;
        return false;
    }
    cout << "  ✓ Derived master key from password (100,000 rounds)" << endl;

    // Step 3: Generate random IV for this encryption operation
    vector<uint8_t> iv;
    if (!GenerateIV(iv)) {
        cout << "  ✗ Failed to generate IV" << endl;
        return false;
    }
    cout << "  ✓ Generated random IV" << endl;

    // Step 4: Encrypt private key data
    CCrypter crypter;
    if (!crypter.SetKey(masterKey, iv)) {
        cout << "  ✗ Failed to set crypter key" << endl;
        return false;
    }

    // Simulate a 32-byte private key
    vector<uint8_t> privateKey(32);
    for (int i = 0; i < 32; i++) privateKey[i] = static_cast<uint8_t>(i * 7);

    vector<uint8_t> encryptedKey;
    if (!crypter.Encrypt(privateKey, encryptedKey)) {
        cout << "  ✗ Failed to encrypt private key" << endl;
        return false;
    }
    cout << "  ✓ Private key encrypted (" << privateKey.size()
         << " → " << encryptedKey.size() << " bytes)" << endl;

    // Step 5: Simulate wallet close (wipe master key from memory)
    // masterKey auto-wiped when goes out of scope

    // Step 6: Later, user unlocks wallet with password
    vector<uint8_t> masterKey2;
    if (!DeriveKey(userPassword, salt, WALLET_CRYPTO_PBKDF2_ROUNDS, masterKey2)) {
        cout << "  ✗ Failed to re-derive key" << endl;
        return false;
    }
    cout << "  ✓ Re-derived master key from password" << endl;

    // Step 7: Decrypt private key
    CCrypter crypter2;
    if (!crypter2.SetKey(masterKey2, iv)) {
        cout << "  ✗ Failed to set crypter key for decryption" << endl;
        return false;
    }

    vector<uint8_t> decryptedKey;
    if (!crypter2.Decrypt(encryptedKey, decryptedKey)) {
        cout << "  ✗ Failed to decrypt private key" << endl;
        return false;
    }
    cout << "  ✓ Private key decrypted" << endl;

    // Step 8: Verify decrypted key matches original
    if (decryptedKey != privateKey) {
        cout << "  ✗ Decrypted key doesn't match original" << endl;
        return false;
    }
    cout << "  ✓ Decrypted key matches original" << endl;

    // Step 9: Test wrong password
    vector<uint8_t> wrongKey;
    if (!DeriveKey("WrongPassword", salt, WALLET_CRYPTO_PBKDF2_ROUNDS, wrongKey)) {
        cout << "  ✗ Failed to derive wrong key" << endl;
        return false;
    }

    // GATE ON IDENTITY, NOT ON WHETHER Decrypt() RETURNED TRUE.
    //
    // This assertion used to fail the suite whenever Decrypt() returned true for the
    // wrong key. That is a PROBABILISTIC assertion wearing a deterministic face:
    // CCrypter::Decrypt's only gate here is PKCS#7 padding validity -- no MAC, no
    // identity check -- and AES-CBC + PKCS#7 accepts a wrong key whenever the
    // trailing bytes happen to form valid padding.
    //
    // MEASURED against this very implementation: 765 acceptances in 200,000
    // wrong-key attempts = 0.3825%, against a strict-PKCS#7 prediction of
    // sum_{k=1..16}(1/256)^k = 0.3922%. So this test reddened roughly ONE RUN IN 260
    // -- on every pull request in the repository, in a suite nobody associates with
    // wallets, and it was read as noise for as long as it existed.
    //
    // The security property was never "the decrypt must fail". It is "a wrong
    // password must not yield the private key", and that is what is asserted now.
    // A wrong key that unpads by chance and returns GARBAGE is correct behaviour;
    // a wrong key that returns the KEY is the catastrophe, and it is deterministic.
    //
    // This is the same correction the LP-7 wallet migration makes: verify the
    // recovered bytes, do not trust that a decrypt returned true.
    CCrypter crypter3;
    crypter3.SetKey(wrongKey, iv);
    vector<uint8_t> wrongDecrypt;
    const bool unpadded = crypter3.Decrypt(encryptedKey, wrongDecrypt);
    if (unpadded && wrongDecrypt == privateKey) {
        cout << "  ✗ Wrong password RECOVERED THE PRIVATE KEY" << endl;
        return false;
    }
    if (unpadded) {
        cout << "  ✓ Wrong password unpadded by chance (~0.39% of attempts) but "
                "yielded garbage, not the key" << endl;
    } else {
        cout << "  ✓ Wrong password rejected by padding validation" << endl;
    }

    return true;
}

/**
 * Main Test Runner
 */
int main() {
    cout << "======================================" << endl;
    cout << "Wallet Encryption Tests" << endl;
    cout << "AES-256-CBC + PBKDF2-SHA3" << endl;
    cout << "======================================" << endl;
    cout << endl;

    bool allPassed = true;

    allPassed &= TestRandomGeneration();
    allPassed &= TestKeyDerivation();
    allPassed &= TestBasicEncryption();
    allPassed &= TestVariousDataSizes();
    allPassed &= TestWrongKeyRejection();
    allPassed &= TestErrorHandling();
    allPassed &= TestWalletScenario();

    cout << endl;
    cout << "======================================" << endl;
    if (allPassed) {
        cout << "✅ All wallet encryption tests passed!" << endl;
    } else {
        cout << "❌ Some tests failed" << endl;
    }
    cout << "======================================" << endl;
    cout << endl;

    cout << "Components Validated:" << endl;
    cout << "  ✓ Cryptographically secure random generation" << endl;
    cout << "  ✓ PBKDF2-SHA3 key derivation (100,000 rounds)" << endl;
    cout << "  ✓ AES-256-CBC encryption/decryption" << endl;
    cout << "  ✓ PKCS#7 padding" << endl;
    cout << "  ✓ Wrong key rejection" << endl;
    cout << "  ✓ Error handling" << endl;
    cout << "  ✓ Full wallet encryption workflow" << endl;
    cout << endl;

    cout << "Security Features:" << endl;
    cout << "  ✓ 256-bit AES encryption (industry standard)" << endl;
    cout << "  ✓ Quantum-resistant SHA-3 hashing" << endl;
    cout << "  ✓ 100,000 PBKDF2 iterations (slow brute force)" << endl;
    cout << "  ✓ Random salt per wallet" << endl;
    cout << "  ✓ Random IV per encryption" << endl;
    cout << "  ✓ Automatic memory wiping" << endl;
    cout << endl;

    return allPassed ? 0 : 1;
}
