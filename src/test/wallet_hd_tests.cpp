// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <boost/test/unit_test.hpp>
#include <wallet/wallet.h>
#include <wallet/mnemonic.h>
#include <wallet/hd_derivation.h>
#include <cstring>
#include <fstream>
#include <thread>
#include <chrono>

// ---------------------------------------------------------------------------
// BUG #115 BASE. GenerateHDWallet pre-generates HD_GAP_LIMIT addresses at
// wallet creation (wallet.cpp:5286-5291) and sets nHDExternalChainIndex past
// them (wallet.cpp:5316). Every EXTERNAL-chain expectation below is written
// relative to this base rather than to a bare literal.
//
// WHY NOT JUST ADD 19 TO EACH LITERAL: that fixes today and rebuilds the trap.
// The next gap-limit change would break the same 18 sites again with nothing
// naming the reason. Centralised, such a change breaks ONE line, loudly --
// which is what a test should do when product policy moves. Loudly is the
// point: these expectations DID fail when BUG #115 landed, and the suites were
// excluded from CI rather than updated (ci.yml: "GetNewHDAddress() hangs in CI
// (BUG-77) ... blocking on /dev/random" -- a misdiagnosis, since there is no
// /dev/random path anywhere in src/ or depends/dilithium/ and these suites fail
// in seconds rather than hanging). See
// missions/security-audit-2026-09/artifacts/audit_wallet_keys.md F2.
//
// INTERNAL-chain expectations are deliberately UNCHANGED: wallet.cpp:5284
// leaves nHDInternalChainIndex at 0, so change addresses still start at 0 and
// none of those assertions failed.
//
// Mirrors the private CWallet::HD_GAP_LIMIT (wallet.h:469). Kept honest by the
// assertions themselves -- if the product value moves, these fail.
static const uint32_t kHDPregen = 20;

// The BIP44 EXTERNAL-chain path for an index, so path expectations move with
// the base instead of being frozen strings.
static std::string HDExternalPath(uint32_t index)
{
    return "m/44'/573'/0'/0'/" + std::to_string(index) + "'";
}
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(wallet_hd_tests)

// ============================================================================
// HD Wallet Generation Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(generate_hd_wallet_test) {
    CWallet wallet;
    std::string mnemonic;

    // Generate new HD wallet
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Verify mnemonic is valid
    BOOST_CHECK(CMnemonic::Validate(mnemonic));

    // Verify wallet is marked as HD
    BOOST_CHECK(wallet.IsHDWallet());

    // Verify HD wallet info
    uint32_t account, external_idx, internal_idx;
    BOOST_REQUIRE(wallet.GetHDWalletInfo(account, external_idx, internal_idx));
    BOOST_CHECK_EQUAL(account, 0);
    BOOST_CHECK_EQUAL(external_idx, kHDPregen);  // First address already generated
    BOOST_CHECK_EQUAL(internal_idx, 0);
}

BOOST_AUTO_TEST_CASE(initialize_hd_wallet_from_mnemonic_test) {
    CWallet wallet;

    // Known mnemonic for reproducibility
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";

    // Initialize HD wallet
    BOOST_REQUIRE(wallet.InitializeHDWallet(mnemonic));

    // Verify wallet is HD
    BOOST_CHECK(wallet.IsHDWallet());

    // Verify initial state
    uint32_t account, external_idx, internal_idx;
    BOOST_REQUIRE(wallet.GetHDWalletInfo(account, external_idx, internal_idx));
    BOOST_CHECK_EQUAL(account, 0);
    BOOST_CHECK_EQUAL(external_idx, kHDPregen);
    BOOST_CHECK_EQUAL(internal_idx, 0);
}

BOOST_AUTO_TEST_CASE(hd_wallet_reject_invalid_mnemonic_test) {
    CWallet wallet;

    // Invalid mnemonic (wrong checksum)
    std::string bad_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

    // Should fail
    BOOST_CHECK(!wallet.InitializeHDWallet(bad_mnemonic));
    BOOST_CHECK(!wallet.IsHDWallet());
}

BOOST_AUTO_TEST_CASE(hd_wallet_reject_duplicate_initialization_test) {
    CWallet wallet;
    std::string mnemonic;

    // First initialization should succeed
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Second initialization should fail (wallet already has keys)
    std::string mnemonic2;
    BOOST_CHECK(!wallet.GenerateHDWallet(mnemonic2));
}

// ============================================================================
// Address Derivation Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(derive_receive_addresses_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Derive multiple receive addresses
    CDilithiumAddress addr1 = wallet.GetNewHDAddress();
    CDilithiumAddress addr2 = wallet.GetNewHDAddress();
    CDilithiumAddress addr3 = wallet.GetNewHDAddress();

    // All should be valid and unique
    BOOST_CHECK(addr1.IsValid());
    BOOST_CHECK(addr2.IsValid());
    BOOST_CHECK(addr3.IsValid());
    BOOST_CHECK(!(addr1 == addr2));
    BOOST_CHECK(!(addr2 == addr3));
    BOOST_CHECK(!(addr1 == addr3));

    // Verify chain index updated
    uint32_t account, external_idx, internal_idx;
    BOOST_REQUIRE(wallet.GetHDWalletInfo(account, external_idx, internal_idx));
    BOOST_CHECK_EQUAL(external_idx, kHDPregen + 3);  // 0 generated during init, then 3 more
}

BOOST_AUTO_TEST_CASE(derive_change_addresses_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Derive multiple change addresses
    CDilithiumAddress change1 = wallet.GetChangeAddress();
    CDilithiumAddress change2 = wallet.GetChangeAddress();

    // All should be valid and unique
    BOOST_CHECK(change1.IsValid());
    BOOST_CHECK(change2.IsValid());
    BOOST_CHECK(!(change1 == change2));

    // Verify chain index updated
    uint32_t account, external_idx, internal_idx;
    BOOST_REQUIRE(wallet.GetHDWalletInfo(account, external_idx, internal_idx));
    BOOST_CHECK_EQUAL(internal_idx, 2);
}

BOOST_AUTO_TEST_CASE(derive_custom_path_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Derive address at custom path
    CDilithiumAddress addr = wallet.DeriveAddress("m/44'/573'/0'/0'/5'");
    BOOST_CHECK(addr.IsValid());

    // Verify path lookup
    CHDKeyPath path;
    BOOST_REQUIRE(wallet.GetAddressPath(addr, path));
    BOOST_CHECK_EQUAL(path.ToString(), "m/44'/573'/0'/0'/5'");
}

BOOST_AUTO_TEST_CASE(derive_invalid_path_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Invalid paths should return empty address
    CDilithiumAddress addr1 = wallet.DeriveAddress("m/44/573/0/0/0");  // Not hardened
    CDilithiumAddress addr2 = wallet.DeriveAddress("m/44'/999'/0'/0'/0'");  // Wrong coin type
    CDilithiumAddress addr3 = wallet.DeriveAddress("invalid");

    BOOST_CHECK(!addr1.IsValid());
    BOOST_CHECK(!addr2.IsValid());
    BOOST_CHECK(!addr3.IsValid());
}

BOOST_AUTO_TEST_CASE(address_path_lookup_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Generate some addresses
    CDilithiumAddress receive1 = wallet.GetNewHDAddress();
    CDilithiumAddress receive2 = wallet.GetNewHDAddress();
    CDilithiumAddress change1 = wallet.GetChangeAddress();

    // Verify path lookups
    CHDKeyPath path1, path2, path3;
    BOOST_REQUIRE(wallet.GetAddressPath(receive1, path1));
    BOOST_REQUIRE(wallet.GetAddressPath(receive2, path2));
    BOOST_REQUIRE(wallet.GetAddressPath(change1, path3));

    BOOST_CHECK_EQUAL(path1.ToString(), HDExternalPath(kHDPregen + 0));  // Second receive address (0 was generated at init)
    BOOST_CHECK_EQUAL(path2.ToString(), HDExternalPath(kHDPregen + 1));
    BOOST_CHECK_EQUAL(path3.ToString(), "m/44'/573'/0'/1'/0'");
}

// ============================================================================
// Mnemonic Export Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(export_mnemonic_test) {
    CWallet wallet;
    std::string original_mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(original_mnemonic));

    // Export mnemonic (wallet not encrypted, should work)
    std::string exported_mnemonic;
    BOOST_REQUIRE(wallet.ExportMnemonic(exported_mnemonic));

    // Should match original
    BOOST_CHECK_EQUAL(exported_mnemonic, original_mnemonic);
}

BOOST_AUTO_TEST_CASE(export_mnemonic_from_initialized_wallet_test) {
    CWallet wallet;
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";

    BOOST_REQUIRE(wallet.InitializeHDWallet(mnemonic));

    // Export should return same mnemonic
    std::string exported;
    BOOST_REQUIRE(wallet.ExportMnemonic(exported));
    BOOST_CHECK_EQUAL(exported, mnemonic);
}

BOOST_AUTO_TEST_CASE(export_mnemonic_non_hd_wallet_test) {
    CWallet wallet;

    // Non-HD wallet should fail to export mnemonic
    std::string mnemonic;
    BOOST_CHECK(!wallet.ExportMnemonic(mnemonic));
}

// ============================================================================
// Wallet Persistence Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(save_and_load_hd_wallet_test) {
    std::string filename = "test_hd_wallet.dat";
    std::string original_mnemonic;

    // Create and save HD wallet
    {
        CWallet wallet;
        BOOST_REQUIRE(wallet.GenerateHDWallet(original_mnemonic));

        // Generate some addresses
        CDilithiumAddress addr1 = wallet.GetNewHDAddress();
        CDilithiumAddress addr2 = wallet.GetNewHDAddress();
        CDilithiumAddress change1 = wallet.GetChangeAddress();

        // Save wallet
        BOOST_REQUIRE(wallet.Save(filename));
    }

    // Load wallet and verify
    {
        CWallet loaded_wallet;
        BOOST_REQUIRE(loaded_wallet.Load(filename));

        // Verify it's an HD wallet
        BOOST_CHECK(loaded_wallet.IsHDWallet());

        // Verify HD state
        uint32_t account, external_idx, internal_idx;
        BOOST_REQUIRE(loaded_wallet.GetHDWalletInfo(account, external_idx, internal_idx));
        BOOST_CHECK_EQUAL(account, 0);
        BOOST_CHECK_EQUAL(external_idx, kHDPregen + 2);  // 0 at init + 2 more
        BOOST_CHECK_EQUAL(internal_idx, 1);

        // Verify mnemonic
        std::string loaded_mnemonic;
        BOOST_REQUIRE(loaded_wallet.ExportMnemonic(loaded_mnemonic));
        BOOST_CHECK_EQUAL(loaded_mnemonic, original_mnemonic);

        // Verify can derive more addresses
        CDilithiumAddress new_addr = loaded_wallet.GetNewHDAddress();
        BOOST_CHECK(new_addr.IsValid());
    }

    // Cleanup
    std::remove(filename.c_str());
}

BOOST_AUTO_TEST_CASE(load_v1_wallet_as_non_hd_test) {
    // This test verifies backward compatibility
    // A v1 wallet file should load as non-HD wallet
    // (We'd need to create a v1 wallet file for this test)
    // For now, just verify that a newly created non-HD wallet saves as v1

    std::string filename = "test_v1_wallet.dat";

    // Create non-HD wallet (legacy mode)
    {
        CWallet wallet;
        // Don't initialize as HD
        wallet.GenerateNewKey();  // Generate regular key
        BOOST_REQUIRE(wallet.Save(filename));
    }

    // Load and verify it's not HD
    {
        CWallet loaded;
        BOOST_REQUIRE(loaded.Load(filename));
        BOOST_CHECK(!loaded.IsHDWallet());
    }

    std::remove(filename.c_str());
}

BOOST_AUTO_TEST_CASE(hd_wallet_deterministic_addresses_test) {
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";

    // Create first wallet
    CWallet wallet1;
    BOOST_REQUIRE(wallet1.InitializeHDWallet(mnemonic));
    CDilithiumAddress addr1_1 = wallet1.GetNewHDAddress();
    CDilithiumAddress addr1_2 = wallet1.GetNewHDAddress();

    // Create second wallet with same mnemonic
    CWallet wallet2;
    BOOST_REQUIRE(wallet2.InitializeHDWallet(mnemonic));
    CDilithiumAddress addr2_1 = wallet2.GetNewHDAddress();
    CDilithiumAddress addr2_2 = wallet2.GetNewHDAddress();

    // Addresses should be identical
    BOOST_CHECK(addr1_1 == addr2_1);
    BOOST_CHECK(addr1_2 == addr2_2);
}

// ============================================================================
// Wallet Encryption with HD Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(encrypt_hd_wallet_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Generate an address before encryption
    CDilithiumAddress addr_before = wallet.GetNewHDAddress();
    BOOST_CHECK(addr_before.IsValid());

    // Encrypt wallet - avoid common password substrings
    std::string passphrase = "MyUniqueKey472!##";
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));

    // Verify wallet is encrypted
    BOOST_CHECK(wallet.IsCrypted());

    // Lock wallet to test locked behavior
    // (wallet stays unlocked for 60 seconds after encryption for user convenience)
    wallet.Lock();
    BOOST_CHECK(wallet.IsLocked());

    // Cannot generate addresses while locked
    CDilithiumAddress addr_locked = wallet.GetNewHDAddress();
    BOOST_CHECK(!addr_locked.IsValid());

    // Cannot export mnemonic while locked
    std::string exported;
    BOOST_CHECK(!wallet.ExportMnemonic(exported));

    // Unlock wallet
    BOOST_REQUIRE(wallet.Unlock(passphrase));
    BOOST_CHECK(!wallet.IsLocked());

    // Now can generate addresses
    CDilithiumAddress addr_after = wallet.GetNewHDAddress();
    BOOST_CHECK(addr_after.IsValid());

    // Can export mnemonic
    BOOST_REQUIRE(wallet.ExportMnemonic(exported));
    BOOST_CHECK_EQUAL(exported, mnemonic);
}

BOOST_AUTO_TEST_CASE(save_load_encrypted_hd_wallet_test) {
    std::string filename = "test_encrypted_hd.dat";
    std::string mnemonic;
    std::string passphrase = "SecurePass456!##";

    // Create, encrypt, and save
    {
        CWallet wallet;
        BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

        CDilithiumAddress addr1 = wallet.GetNewHDAddress();
        CDilithiumAddress addr2 = wallet.GetNewHDAddress();

        BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
        BOOST_REQUIRE(wallet.Save(filename));
    }

    // Load encrypted wallet
    {
        CWallet loaded;
        BOOST_REQUIRE(loaded.Load(filename));

        // Should be encrypted and locked
        BOOST_CHECK(loaded.IsCrypted());
        BOOST_CHECK(loaded.IsLocked());
        BOOST_CHECK(loaded.IsHDWallet());

        // Cannot access HD features while locked
        CDilithiumAddress addr = loaded.GetNewHDAddress();
        BOOST_CHECK(!addr.IsValid());

        // Unlock
        BOOST_REQUIRE(loaded.Unlock(passphrase));

        // Now can access
        CDilithiumAddress new_addr = loaded.GetNewHDAddress();
        BOOST_CHECK(new_addr.IsValid());

        // Verify mnemonic
        std::string loaded_mnemonic;
        BOOST_REQUIRE(loaded.ExportMnemonic(loaded_mnemonic));
        BOOST_CHECK_EQUAL(loaded_mnemonic, mnemonic);
    }

    std::remove(filename.c_str());
}

BOOST_AUTO_TEST_CASE(encrypted_hd_wallet_wrong_passphrase_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    std::string passphrase = "MyFreshKey8472!##";  // No common password substrings
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));

    // Lock wallet
    wallet.Lock();
    BOOST_CHECK(wallet.IsLocked());

    // Try wrong passphrase (must be 16+ chars with digit+special to test actual wrong password)
    BOOST_CHECK(!wallet.Unlock("NotThisString99!#"));
    BOOST_CHECK(wallet.IsLocked());

    // Wait 1.1 seconds to bypass rate limiting (exponential backoff after failed attempt)
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Try correct passphrase
    BOOST_REQUIRE(wallet.Unlock(passphrase));
    BOOST_CHECK(!wallet.IsLocked());
}

// ============================================================================
// Restore Workflow Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(restore_hd_wallet_test) {
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";

    CWallet wallet;
    BOOST_REQUIRE(wallet.RestoreHDWallet(mnemonic));

    // Verify wallet is HD
    BOOST_CHECK(wallet.IsHDWallet());

    // Verify can generate addresses
    CDilithiumAddress addr1 = wallet.GetNewHDAddress();
    CDilithiumAddress addr2 = wallet.GetNewHDAddress();
    BOOST_CHECK(addr1.IsValid());
    BOOST_CHECK(addr2.IsValid());
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

BOOST_AUTO_TEST_CASE(hd_wallet_empty_passphrase_test) {
    CWallet wallet;
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";

    // Empty passphrase should work (BIP39 allows it)
    BOOST_REQUIRE(wallet.InitializeHDWallet(mnemonic, ""));
    BOOST_CHECK(wallet.IsHDWallet());
}

BOOST_AUTO_TEST_CASE(hd_wallet_with_passphrase_test) {
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";

    // Same mnemonic, different passphrases = different wallets
    CWallet wallet1, wallet2;
    BOOST_REQUIRE(wallet1.InitializeHDWallet(mnemonic, ""));
    BOOST_REQUIRE(wallet2.InitializeHDWallet(mnemonic, "passphrase"));

    CDilithiumAddress addr1 = wallet1.GetNewHDAddress();
    CDilithiumAddress addr2 = wallet2.GetNewHDAddress();

    // Addresses should be different (different seeds)
    BOOST_CHECK(!(addr1 == addr2));
}

BOOST_AUTO_TEST_CASE(hd_wallet_many_addresses_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Generate addresses to verify no issues
    // Note: Reduced from 100 to 10 for CI - Dilithium3 key generation is slow
    std::vector<CDilithiumAddress> addresses;
    for (int i = 0; i < 10; i++) {
        CDilithiumAddress addr = wallet.GetNewHDAddress();
        BOOST_REQUIRE(addr.IsValid());
        addresses.push_back(addr);
    }

    // Verify all unique
    for (size_t i = 0; i < addresses.size(); i++) {
        for (size_t j = i + 1; j < addresses.size(); j++) {
            BOOST_CHECK(!(addresses[i] == addresses[j]));
        }
    }

    // Verify chain index
    uint32_t account, external_idx, internal_idx;
    BOOST_REQUIRE(wallet.GetHDWalletInfo(account, external_idx, internal_idx));
    BOOST_CHECK_EQUAL(external_idx, kHDPregen + 10);  // 0 at init + 10 more
}

BOOST_AUTO_TEST_CASE(hd_wallet_path_validation_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Test various invalid paths
    BOOST_CHECK(!wallet.DeriveAddress("m/44'/573'/0'/2'/0'").IsValid());  // change must be 0 or 1
    BOOST_CHECK(!wallet.DeriveAddress("m/44'/573'/0'").IsValid());  // Too short
    BOOST_CHECK(!wallet.DeriveAddress("m/44'/999'/0'/0'/0'").IsValid());  // Wrong coin type
    BOOST_CHECK(!wallet.DeriveAddress("m/43'/573'/0'/0'/0'").IsValid());  // Wrong purpose
}

BOOST_AUTO_TEST_CASE(concurrent_address_generation_test) {
    CWallet wallet;
    std::string mnemonic;
    BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));

    // Sequential generation should maintain state correctly
    CDilithiumAddress addr1 = wallet.GetNewHDAddress();
    CDilithiumAddress change1 = wallet.GetChangeAddress();
    CDilithiumAddress addr2 = wallet.GetNewHDAddress();
    CDilithiumAddress change2 = wallet.GetChangeAddress();
    CDilithiumAddress addr3 = wallet.GetNewHDAddress();

    // Verify all unique
    BOOST_CHECK(!(addr1 == addr2));
    BOOST_CHECK(!(addr2 == addr3));
    BOOST_CHECK(!(change1 == change2));
    BOOST_CHECK(!(addr1 == change1));

    // Verify paths
    CHDKeyPath path1, path2, path3, pathc1, pathc2;
    BOOST_REQUIRE(wallet.GetAddressPath(addr1, path1));
    BOOST_REQUIRE(wallet.GetAddressPath(addr2, path2));
    BOOST_REQUIRE(wallet.GetAddressPath(addr3, path3));
    BOOST_REQUIRE(wallet.GetAddressPath(change1, pathc1));
    BOOST_REQUIRE(wallet.GetAddressPath(change2, pathc2));

    BOOST_CHECK_EQUAL(path1.ToString(), HDExternalPath(kHDPregen + 0));
    BOOST_CHECK_EQUAL(path2.ToString(), HDExternalPath(kHDPregen + 1));
    BOOST_CHECK_EQUAL(path3.ToString(), HDExternalPath(kHDPregen + 2));
    BOOST_CHECK_EQUAL(pathc1.ToString(), "m/44'/573'/0'/1'/0'");
    BOOST_CHECK_EQUAL(pathc2.ToString(), "m/44'/573'/0'/1'/1'");
}

BOOST_AUTO_TEST_SUITE_END()
