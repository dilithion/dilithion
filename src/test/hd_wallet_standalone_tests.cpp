// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// Standalone HD Wallet Tests (no Boost dependency)

#include <wallet/wallet.h>
#include <wallet/mnemonic.h>
#include <wallet/hd_derivation.h>
#include <iostream>
#include <set>
#include <cstring>

// ANSI colors
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_BLUE "\033[34m"
#define COLOR_RESET "\033[0m"

int passed = 0;
int failed = 0;

#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cout << COLOR_RED << "FAIL: " << msg << COLOR_RESET << std::endl; \
        failed++; \
        return false; \
    }

#define TEST_PASS(msg) \
    std::cout << COLOR_GREEN << "PASS: " << msg << COLOR_RESET << std::endl; \
    passed++;

// Test 1: Generate HD wallet with new mnemonic
bool Test_GenerateHDWallet() {
    std::cout << COLOR_BLUE << "\n[TEST 1] Generate HD Wallet" << COLOR_RESET << std::endl;

    CWallet wallet;
    std::string mnemonic;

    // Generate new HD wallet
    TEST_ASSERT(wallet.GenerateHDWallet(mnemonic), "GenerateHDWallet failed");

    // Verify mnemonic is valid
    TEST_ASSERT(CMnemonic::Validate(mnemonic), "Mnemonic is invalid");

    // Verify wallet is marked as HD
    TEST_ASSERT(wallet.IsHDWallet(), "Wallet not marked as HD");

    // Verify HD wallet info
    uint32_t account, external_idx, internal_idx;
    TEST_ASSERT(wallet.GetHDWalletInfo(account, external_idx, internal_idx), "GetHDWalletInfo failed");
    TEST_ASSERT(account == 0, "Account should be 0");
    // STALE EXPECTATION FIXED, and the product is right, not this file.
    //
    // This asserted external_idx == 1 ("first address generated"), which was
    // true until the BUG #115 fix. GenerateHDWallet now PRE-GENERATES
    // HD_GAP_LIMIT addresses at creation (wallet.cpp:5286-5291) so that the
    // initial rescan checks all of them, and sets nHDExternalChainIndex =
    // HD_GAP_LIMIT (wallet.cpp:5316). Measured: expected 1, actual 20 --
    // off by exactly HD_GAP_LIMIT - 1.
    //
    // Expressed as a RELATIONSHIP, not the literal 20. `external_idx == 20`
    // would silently stop testing anything the day HD_GAP_LIMIT changes: it
    // would still pass while the wallet pre-generated a different number of
    // addresses, which is the same class of drift that produced this bug.
    // HD_GAP_LIMIT itself is private, and this is a test-file-only change, so
    // the invariant is stated against what the wallet actually produced --
    // which is the stronger claim anyway: the next index must sit exactly past
    // the addresses that exist.
    //
    // WHY THIS MATTERED: ci.yml excluded this suite six times for
    // "GetNewHDAddress() hangs in CI (BUG-77) ... blocking on /dev/random".
    // There is no /dev/random path anywhere in src/ or depends/dilithium/ --
    // the suite does not hang, it fails in 2 seconds on this line. The
    // misdiagnosis kept anyone from looking for ~1054 commits, per
    // missions/security-audit-2026-09/artifacts/audit_wallet_keys.md F2.
    // RELATIONAL, not a pinned number (a8 review LOW-1, measured): a deliberate
    // HD_GAP_LIMIT change SURVIVES this assertion while breaking the relation
    // KILLS it -- so it tests the invariant that must hold rather than the
    // policy value that is allowed to move. A literal here would redden the
    // suite on a legitimate change, and a suite that reddens on legitimate
    // changes is one that gets excluded from CI, which is exactly the history
    // this file is recovering from.
    const size_t pregenerated = wallet.GetAddresses().size();
    TEST_ASSERT(pregenerated > 1,
                "BUG #115 must pre-generate a gap limit of addresses, not one");
    TEST_ASSERT(external_idx == pregenerated,
                "External index must sit exactly past the pre-generated addresses");
    // Internal is NOT pre-advanced: wallet.cpp:5284 leaves it at 0.
    TEST_ASSERT(internal_idx == 0, "Internal index should be 0");

    std::cout << "  Generated mnemonic: " << mnemonic.substr(0, 30) << "..." << std::endl;

    TEST_PASS("HD wallet generated successfully");
    return true;
}

// Test 2: Initialize HD wallet from known mnemonic
bool Test_InitializeFromMnemonic() {
    std::cout << COLOR_BLUE << "\n[TEST 2] Initialize HD Wallet from Mnemonic" << COLOR_RESET << std::endl;

    // First generate a valid mnemonic to use
    CWallet temp_wallet;
    std::string valid_mnemonic;
    TEST_ASSERT(temp_wallet.GenerateHDWallet(valid_mnemonic), "Failed to generate test mnemonic");

    // Now use that mnemonic to initialize another wallet
    CWallet wallet;
    TEST_ASSERT(wallet.InitializeHDWallet(valid_mnemonic), "InitializeHDWallet failed");

    // Verify wallet is HD
    TEST_ASSERT(wallet.IsHDWallet(), "Wallet not marked as HD");

    // Verify initial state
    uint32_t account, external_idx, internal_idx;
    TEST_ASSERT(wallet.GetHDWalletInfo(account, external_idx, internal_idx), "GetHDWalletInfo failed");
    TEST_ASSERT(account == 0, "Account should be 0");

    std::cout << "  Initialized from generated mnemonic" << std::endl;

    TEST_PASS("HD wallet initialized from mnemonic");
    return true;
}

// Test 3: Reject invalid mnemonic
bool Test_RejectInvalidMnemonic() {
    std::cout << COLOR_BLUE << "\n[TEST 3] Reject Invalid Mnemonic" << COLOR_RESET << std::endl;

    CWallet wallet;

    // Invalid mnemonic (wrong checksum)
    std::string bad_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

    // Should fail
    bool result = wallet.InitializeHDWallet(bad_mnemonic);
    TEST_ASSERT(!result, "Should reject invalid mnemonic");
    TEST_ASSERT(!wallet.IsHDWallet(), "Wallet should not be HD after failed initialization");

    std::cout << "  Invalid mnemonic correctly rejected" << std::endl;

    TEST_PASS("Invalid mnemonic rejected");
    return true;
}

// Test 4: Derive receive addresses
bool Test_DeriveReceiveAddresses() {
    std::cout << COLOR_BLUE << "\n[TEST 4] Derive Receive Addresses" << COLOR_RESET << std::endl;

    CWallet wallet;
    std::string mnemonic;
    TEST_ASSERT(wallet.GenerateHDWallet(mnemonic), "GenerateHDWallet failed");

    // Derive multiple receive addresses
    CDilithiumAddress addr1 = wallet.GetNewHDAddress();
    CDilithiumAddress addr2 = wallet.GetNewHDAddress();
    CDilithiumAddress addr3 = wallet.GetNewHDAddress();

    // All should be valid
    TEST_ASSERT(addr1.IsValid(), "Address 1 should be valid");
    TEST_ASSERT(addr2.IsValid(), "Address 2 should be valid");
    TEST_ASSERT(addr3.IsValid(), "Address 3 should be valid");

    // All should be unique
    TEST_ASSERT(!(addr1 == addr2), "Addresses 1 and 2 should be different");
    TEST_ASSERT(!(addr2 == addr3), "Addresses 2 and 3 should be different");
    TEST_ASSERT(!(addr1 == addr3), "Addresses 1 and 3 should be different");

    std::cout << "  Address 1: " << addr1.ToString() << std::endl;
    std::cout << "  Address 2: " << addr2.ToString() << std::endl;
    std::cout << "  Address 3: " << addr3.ToString() << std::endl;

    TEST_PASS("Receive addresses derived successfully");
    return true;
}

// Test 5: Derive change addresses
bool Test_DeriveChangeAddresses() {
    std::cout << COLOR_BLUE << "\n[TEST 5] Derive Change Addresses" << COLOR_RESET << std::endl;

    CWallet wallet;
    std::string mnemonic;
    TEST_ASSERT(wallet.GenerateHDWallet(mnemonic), "GenerateHDWallet failed");

    // Derive change addresses
    CDilithiumAddress change1 = wallet.GetChangeAddress();
    CDilithiumAddress change2 = wallet.GetChangeAddress();

    // Should be valid
    TEST_ASSERT(change1.IsValid(), "Change address 1 should be valid");
    TEST_ASSERT(change2.IsValid(), "Change address 2 should be valid");

    // Should be unique
    TEST_ASSERT(!(change1 == change2), "Change addresses should be different");

    // Should be different from receive addresses
    CDilithiumAddress receive = wallet.GetNewHDAddress();
    TEST_ASSERT(!(change1 == receive), "Change and receive should be different");

    std::cout << "  Change 1: " << change1.ToString() << std::endl;
    std::cout << "  Change 2: " << change2.ToString() << std::endl;

    TEST_PASS("Change addresses derived successfully");
    return true;
}

// Test 6: Deterministic derivation (same mnemonic = same addresses)
bool Test_DeterministicDerivation() {
    std::cout << COLOR_BLUE << "\n[TEST 6] Deterministic Derivation" << COLOR_RESET << std::endl;

    // Generate a valid mnemonic to use
    CWallet temp_wallet;
    std::string mnemonic;
    TEST_ASSERT(temp_wallet.GenerateHDWallet(mnemonic), "Failed to generate test mnemonic");

    // Create two wallets from same mnemonic
    CWallet wallet1;
    CWallet wallet2;

    TEST_ASSERT(wallet1.InitializeHDWallet(mnemonic), "Wallet 1 init failed");
    TEST_ASSERT(wallet2.InitializeHDWallet(mnemonic), "Wallet 2 init failed");

    // Derive addresses from both
    CDilithiumAddress addr1_w1 = wallet1.GetNewHDAddress();
    CDilithiumAddress addr2_w1 = wallet1.GetNewHDAddress();

    CDilithiumAddress addr1_w2 = wallet2.GetNewHDAddress();
    CDilithiumAddress addr2_w2 = wallet2.GetNewHDAddress();

    // Same mnemonic should produce same addresses
    TEST_ASSERT(addr1_w1 == addr1_w2, "First address should be same");
    TEST_ASSERT(addr2_w1 == addr2_w2, "Second address should be same");

    std::cout << "  Both wallets produce: " << addr1_w1.ToString() << std::endl;

    TEST_PASS("Deterministic derivation verified");
    return true;
}

// Test 7: Mnemonic generation uniqueness
bool Test_MnemonicUniqueness() {
    std::cout << COLOR_BLUE << "\n[TEST 7] Mnemonic Uniqueness" << COLOR_RESET << std::endl;

    std::set<std::string> mnemonics;
    const int count = 10;

    for (int i = 0; i < count; i++) {
        CWallet wallet;
        std::string mnemonic;
        TEST_ASSERT(wallet.GenerateHDWallet(mnemonic), "GenerateHDWallet failed");

        // Check uniqueness
        TEST_ASSERT(mnemonics.find(mnemonic) == mnemonics.end(), "Duplicate mnemonic generated!");
        mnemonics.insert(mnemonic);
    }

    std::cout << "  Generated " << count << " unique mnemonics" << std::endl;

    TEST_PASS("All mnemonics are unique");
    return true;
}

// Test 8: HD wallet with encryption
bool Test_HDWalletEncryption() {
    std::cout << COLOR_BLUE << "\n[TEST 8] HD Wallet with Encryption" << COLOR_RESET << std::endl;

    CWallet wallet;
    std::string mnemonic;
    TEST_ASSERT(wallet.GenerateHDWallet(mnemonic), "GenerateHDWallet failed");

    // Get address before encryption
    CDilithiumAddress addr_before = wallet.GetNewHDAddress();
    TEST_ASSERT(addr_before.IsValid(), "Address before encryption should be valid");

    // Encrypt wallet with a strong, unique passphrase (meets WL-009 requirements)
    TEST_ASSERT(wallet.EncryptWallet("MyV3ry$tr0ngUn1queP@ss!"), "EncryptWallet failed");
    TEST_ASSERT(wallet.IsCrypted(), "Wallet should be encrypted");

    // Generate new address (wallet should be unlocked after encryption)
    CDilithiumAddress addr_after = wallet.GetNewHDAddress();
    TEST_ASSERT(addr_after.IsValid(), "Address after encryption should be valid");

    // Lock and try to generate (should fail)
    wallet.Lock();
    CDilithiumAddress addr_locked = wallet.GetNewHDAddress();
    // GetNewHDAddress may return invalid address when locked

    // Unlock and verify HD functionality
    TEST_ASSERT(wallet.Unlock("MyV3ry$tr0ngUn1queP@ss!"), "Unlock failed");
    CDilithiumAddress addr_unlocked = wallet.GetNewHDAddress();
    TEST_ASSERT(addr_unlocked.IsValid(), "Address after unlock should be valid");

    std::cout << "  Before encryption: " << addr_before.ToString() << std::endl;
    std::cout << "  After encryption: " << addr_after.ToString() << std::endl;
    std::cout << "  After unlock: " << addr_unlocked.ToString() << std::endl;

    TEST_PASS("HD wallet encryption works");
    return true;
}

// Test 9: Mnemonic word list validation
bool Test_MnemonicWordValidation() {
    std::cout << COLOR_BLUE << "\n[TEST 9] Mnemonic Word Validation" << COLOR_RESET << std::endl;

    // Generate a valid 12-word mnemonic for testing
    CWallet temp_wallet;
    std::string valid_mnemonic;
    TEST_ASSERT(temp_wallet.GenerateHDWallet(valid_mnemonic), "Failed to generate test mnemonic");

    // Valid mnemonic should pass validation
    TEST_ASSERT(CMnemonic::Validate(valid_mnemonic), "Generated mnemonic should be valid");

    // Invalid word (first word replaced with nonsense)
    std::string invalid_word_mnemonic = "notawordxyz " + valid_mnemonic.substr(valid_mnemonic.find(' ') + 1);
    TEST_ASSERT(!CMnemonic::Validate(invalid_word_mnemonic), "Invalid word should be rejected");

    // Wrong word count (only 3 words)
    TEST_ASSERT(!CMnemonic::Validate("abandon abandon abandon"), "Wrong word count should be rejected");

    // Empty mnemonic
    TEST_ASSERT(!CMnemonic::Validate(""), "Empty mnemonic should be rejected");

    std::cout << "  Valid mnemonic: accepted" << std::endl;
    std::cout << "  Invalid words: rejected" << std::endl;
    std::cout << "  Wrong word count: rejected" << std::endl;

    TEST_PASS("Mnemonic word validation works");
    return true;
}

// Test 10: Large-scale address derivation
bool Test_LargeScaleDerivation() {
    std::cout << COLOR_BLUE << "\n[TEST 10] Large-Scale Address Derivation (100 addresses)" << COLOR_RESET << std::endl;

    CWallet wallet;
    std::string mnemonic;
    TEST_ASSERT(wallet.GenerateHDWallet(mnemonic), "GenerateHDWallet failed");

    std::set<std::string> addresses;
    const int count = 100;

    for (int i = 0; i < count; i++) {
        CDilithiumAddress addr = wallet.GetNewHDAddress();
        TEST_ASSERT(addr.IsValid(), "Address should be valid");

        std::string addr_str = addr.ToString();
        TEST_ASSERT(addresses.find(addr_str) == addresses.end(), "Duplicate address generated!");
        addresses.insert(addr_str);

        if ((i + 1) % 25 == 0) {
            std::cout << "  Generated " << (i + 1) << " addresses..." << std::endl;
        }
    }

    TEST_PASS("100 unique addresses derived successfully");
    return true;
}

int main() {
    std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;
    std::cout << COLOR_BLUE << "   HD Wallet Standalone Tests          " << COLOR_RESET << std::endl;
    std::cout << COLOR_BLUE << "   BIP39/BIP44 Implementation          " << COLOR_RESET << std::endl;
    std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;

    // Run all tests
    Test_GenerateHDWallet();
    Test_InitializeFromMnemonic();
    Test_RejectInvalidMnemonic();
    Test_DeriveReceiveAddresses();
    Test_DeriveChangeAddresses();
    Test_DeterministicDerivation();
    Test_MnemonicUniqueness();
    Test_HDWalletEncryption();
    Test_MnemonicWordValidation();
    Test_LargeScaleDerivation();

    std::cout << "\n" << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;
    std::cout << "Total Tests: " << (passed + failed) << std::endl;
    std::cout << COLOR_GREEN << "Passed: " << passed << COLOR_RESET << std::endl;
    if (failed > 0) {
        std::cout << COLOR_RED << "Failed: " << failed << COLOR_RESET << std::endl;
    }
    std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;

    if (failed == 0) {
        std::cout << COLOR_GREEN << "\nALL HD WALLET TESTS PASSED" << COLOR_RESET << std::endl;
        std::cout << "\nBIP39/BIP44 Features Verified:" << std::endl;
        std::cout << "  - Mnemonic generation (12/24 words)" << std::endl;
        std::cout << "  - Mnemonic validation" << std::endl;
        std::cout << "  - Deterministic key derivation" << std::endl;
        std::cout << "  - Receive address derivation (external chain)" << std::endl;
        std::cout << "  - Change address derivation (internal chain)" << std::endl;
        std::cout << "  - HD wallet encryption compatibility" << std::endl;
        return 0;
    } else {
        std::cout << COLOR_RED << "\nSOME TESTS FAILED" << COLOR_RESET << std::endl;
        return 1;
    }
}
