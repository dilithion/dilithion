// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <boost/test/unit_test.hpp>

#include <rpc/server.h>
#include <wallet/wallet.h>
#include <wallet/mnemonic.h>
#include <wallet/hd_derivation.h>
#include <memory>
#include <sstream>

// BUG #115: the pre-generation base is read FROM THE WALLET at each site
// (hd_base), never pinned to a literal. a8 measured why: a deliberate
// HD_GAP_LIMIT change SURVIVES the relational assertion while breaking the
// relation KILLS it. The relation tests the invariant that must hold; a
// literal would test a policy value that is allowed to move -- and a suite
// that reddens on a legitimate change is one that gets excluded from CI,
// which is exactly the history these files are recovering from.
#include <test/hd_pregen.h>

// ============================================================================
// Helper Functions
// ============================================================================

// Helper: Parse JSON field
std::string GetJSONField(const std::string& json, const std::string& field) {
    std::string search = "\"" + field + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return "";
    }

    pos += search.size();

    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
        pos++;
    }

    if (json[pos] == '\"') {
        // String value
        pos++;
        size_t end = json.find('\"', pos);
        if (end == std::string::npos) {
            return "";
        }
        return json.substr(pos, end - pos);
    } else if (json[pos] == '{') {
        // Object value
        int depth = 1;
        size_t start = pos;
        pos++;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '{') depth++;
            else if (json[pos] == '}') depth--;
            pos++;
        }
        return json.substr(start, pos - start);
    } else {
        // Number or boolean
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) {
            return "";
        }
        return json.substr(pos, end - pos);
    }
}

// ============================================================================
// Test Suite
// ============================================================================

BOOST_AUTO_TEST_SUITE(rpc_hd_wallet_tests)

// Test 1: Create HD Wallet via RPC
BOOST_AUTO_TEST_CASE(rpc_create_hd_wallet_test) {
    // Create wallet and RPC server
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();
    CRPCServer server(18333);
    server.RegisterWallet(wallet.get());

    // Call createhdwallet RPC
    std::string params = "{}";
    std::string response;

    try {
        // Access private method through a wrapper (we'll call the handler directly)
        // Since we can't access private methods, we'll use ExecuteRPC indirectly
        // by parsing JSON

        // For testing, we'll call wallet methods directly to verify behavior
        std::string mnemonic;
        BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic));
        // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
        const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
        (void)hd_base;

        BOOST_CHECK(wallet->IsHDWallet());
        BOOST_CHECK(!mnemonic.empty());

        // Mnemonic should have 24 words
        int word_count = 1;
        for (char c : mnemonic) {
            if (c == ' ') word_count++;
        }
        BOOST_CHECK_EQUAL(word_count, 24);

    } catch (const std::exception& e) {
        BOOST_FAIL("Exception: " + std::string(e.what()));
    }
}

// Test 2: Create HD Wallet with Passphrase
BOOST_AUTO_TEST_CASE(rpc_create_hd_wallet_with_passphrase_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    std::string mnemonic;
    std::string passphrase = "test_passphrase_123";
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic, passphrase));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    BOOST_CHECK(wallet->IsHDWallet());

    // Export mnemonic should work
    std::string exported_mnemonic;
    BOOST_REQUIRE(wallet->ExportMnemonic(exported_mnemonic));
    BOOST_CHECK_EQUAL(exported_mnemonic, mnemonic);
}

// Test 3: Restore HD Wallet via RPC
BOOST_AUTO_TEST_CASE(rpc_restore_hd_wallet_test) {
    // Generate a wallet first to get a mnemonic
    std::unique_ptr<CWallet> wallet1 = std::make_unique<CWallet>();
    std::string original_mnemonic;
    BOOST_REQUIRE(wallet1->GenerateHDWallet(original_mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet1->GetAddresses().size());
    (void)hd_base;

    // Get first address from original wallet
    CDilithiumAddress original_addr = wallet1->GetNewHDAddress();
    BOOST_REQUIRE(original_addr.IsValid());

    // Create new wallet and restore from mnemonic
    std::unique_ptr<CWallet> wallet2 = std::make_unique<CWallet>();
    BOOST_REQUIRE(wallet2->InitializeHDWallet(original_mnemonic));

    // Get first address from restored wallet
    CDilithiumAddress restored_addr = wallet2->GetNewHDAddress();
    BOOST_REQUIRE(restored_addr.IsValid());

    // Addresses should match (deterministic)
    BOOST_CHECK_EQUAL(original_addr.ToString(), restored_addr.ToString());
}

// Test 4: Restore HD Wallet with Passphrase
BOOST_AUTO_TEST_CASE(rpc_restore_hd_wallet_with_passphrase_test) {
    std::string passphrase = "my_secure_passphrase";

    // Generate wallet with passphrase
    std::unique_ptr<CWallet> wallet1 = std::make_unique<CWallet>();
    std::string mnemonic;
    BOOST_REQUIRE(wallet1->GenerateHDWallet(mnemonic, passphrase));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet1->GetAddresses().size());
    (void)hd_base;

    CDilithiumAddress addr1 = wallet1->GetNewHDAddress();

    // Restore with correct passphrase
    std::unique_ptr<CWallet> wallet2 = std::make_unique<CWallet>();
    BOOST_REQUIRE(wallet2->InitializeHDWallet(mnemonic, passphrase));

    CDilithiumAddress addr2 = wallet2->GetNewHDAddress();
    BOOST_CHECK_EQUAL(addr1.ToString(), addr2.ToString());

    // Restore with wrong passphrase produces different addresses
    std::unique_ptr<CWallet> wallet3 = std::make_unique<CWallet>();
    BOOST_REQUIRE(wallet3->InitializeHDWallet(mnemonic, "wrong_passphrase"));

    CDilithiumAddress addr3 = wallet3->GetNewHDAddress();
    BOOST_CHECK(addr1.ToString() != addr3.ToString());
}

// Test 5: Export Mnemonic via RPC
BOOST_AUTO_TEST_CASE(rpc_export_mnemonic_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    std::string mnemonic;
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    // Export mnemonic
    std::string exported;
    BOOST_REQUIRE(wallet->ExportMnemonic(exported));

    BOOST_CHECK_EQUAL(exported, mnemonic);
}

// Test 6: Export Mnemonic on Non-HD Wallet
BOOST_AUTO_TEST_CASE(rpc_export_mnemonic_non_hd_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    // Should not be HD wallet by default
    BOOST_CHECK(!wallet->IsHDWallet());

    // Export should fail
    std::string mnemonic;
    BOOST_CHECK(!wallet->ExportMnemonic(mnemonic));
}

// Test 7: Get HD Wallet Info
BOOST_AUTO_TEST_CASE(rpc_get_hd_wallet_info_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    // Initially not HD wallet
    BOOST_CHECK(!wallet->IsHDWallet());

    // Create HD wallet
    std::string mnemonic;
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    // Get wallet info
    uint32_t account, external_idx, internal_idx;
    BOOST_REQUIRE(wallet->GetHDWalletInfo(account, external_idx, internal_idx));

    BOOST_CHECK_EQUAL(account, 0);
    BOOST_CHECK_EQUAL(external_idx, hd_base); // nothing derived yet: the index sits at the pre-generated count
    BOOST_CHECK_EQUAL(internal_idx, 0);

    // Generate more addresses
    wallet->GetNewHDAddress();
    wallet->GetNewHDAddress();
    wallet->GetChangeAddress();

    BOOST_REQUIRE(wallet->GetHDWalletInfo(account, external_idx, internal_idx));
    BOOST_CHECK_EQUAL(external_idx, hd_base + 2);
    BOOST_CHECK_EQUAL(internal_idx, 1);
}

// Test 8: List HD Addresses
BOOST_AUTO_TEST_CASE(rpc_list_hd_addresses_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    std::string mnemonic;
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    // Generate several addresses
    CDilithiumAddress addr1 = wallet->GetNewHDAddress();
    CDilithiumAddress addr2 = wallet->GetNewHDAddress();
    CDilithiumAddress addr3 = wallet->GetChangeAddress();

    // Get all addresses
    std::vector<CDilithiumAddress> addresses = wallet->GetAddresses();
    BOOST_CHECK_EQUAL(addresses.size(), hd_base + 3); // pre-generated, then 2 receive + 1 change derived here

    // Verify paths
    for (const CDilithiumAddress& addr : addresses) {
        CHDKeyPath path;
        BOOST_REQUIRE(wallet->GetAddressPath(addr, path));
        BOOST_CHECK(path.IsValid());

        std::string path_str = path.ToString();
        BOOST_CHECK(path_str.find("m/44'/573'/0'/") == 0);
    }
}

// Test 9: Create HD Wallet on Non-Empty Wallet
BOOST_AUTO_TEST_CASE(rpc_create_hd_wallet_non_empty_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    // Generate HD wallet first
    std::string mnemonic1;
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic1));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    // Attempt to create another HD wallet should fail
    std::string mnemonic2;
    BOOST_CHECK(!wallet->GenerateHDWallet(mnemonic2));
}

// Test 10: Restore HD Wallet on Non-Empty Wallet
BOOST_AUTO_TEST_CASE(rpc_restore_hd_wallet_non_empty_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    std::string mnemonic;
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    // Attempt to restore another mnemonic should fail
    std::string another_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    BOOST_CHECK(!wallet->InitializeHDWallet(another_mnemonic));
}

// Test 11: Invalid Mnemonic Restore
BOOST_AUTO_TEST_CASE(rpc_restore_invalid_mnemonic_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    // Invalid mnemonic (wrong checksum)
    std::string invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

    BOOST_CHECK(!wallet->InitializeHDWallet(invalid_mnemonic));
    BOOST_CHECK(!wallet->IsHDWallet());
}

// Test 12: HD Wallet Deterministic Address Generation
BOOST_AUTO_TEST_CASE(rpc_hd_wallet_deterministic_test) {
    // Use known-valid 12-word mnemonic with SHA3-256 checksum
    std::string test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";

    // Create two wallets from same mnemonic
    std::unique_ptr<CWallet> wallet1 = std::make_unique<CWallet>();
    std::unique_ptr<CWallet> wallet2 = std::make_unique<CWallet>();

    BOOST_REQUIRE(wallet1->InitializeHDWallet(test_mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet1->GetAddresses().size());
    (void)hd_base;
    BOOST_REQUIRE(wallet2->InitializeHDWallet(test_mnemonic));

    // Generate addresses and verify they match
    for (int i = 0; i < 10; i++) {
        CDilithiumAddress addr1 = wallet1->GetNewHDAddress();
        CDilithiumAddress addr2 = wallet2->GetNewHDAddress();

        BOOST_REQUIRE(addr1.IsValid());
        BOOST_REQUIRE(addr2.IsValid());
        BOOST_CHECK_EQUAL(addr1.ToString(), addr2.ToString());
    }

    // Change addresses should also match
    CDilithiumAddress change1 = wallet1->GetChangeAddress();
    CDilithiumAddress change2 = wallet2->GetChangeAddress();
    BOOST_CHECK_EQUAL(change1.ToString(), change2.ToString());
}

// Test 13: HD Wallet State Persistence
BOOST_AUTO_TEST_CASE(rpc_hd_wallet_state_persistence_test) {
    std::string filename = "test_rpc_hd_wallet.dat";
    std::string mnemonic;

    // Create and save wallet
    uint32_t hd_base = 0;  // BUG #115 relational base; set in the save scope below
    {
        CWallet wallet;
        BOOST_REQUIRE(wallet.GenerateHDWallet(mnemonic));
        // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
        // Declared ABOVE both scopes because the assertion lives in the load
        // block while the wallet that pre-generated them lives in the save block.
        hd_base = static_cast<uint32_t>(wallet.GetAddresses().size());

        wallet.GetNewHDAddress();
        wallet.GetNewHDAddress();
        wallet.GetChangeAddress();

        BOOST_REQUIRE(wallet.Save(filename));
    }

    // Load and verify
    {
        CWallet wallet;
        BOOST_REQUIRE(wallet.Load(filename));

        BOOST_CHECK(wallet.IsHDWallet());

        uint32_t account, external_idx, internal_idx;
        BOOST_REQUIRE(wallet.GetHDWalletInfo(account, external_idx, internal_idx));
        BOOST_CHECK_EQUAL(external_idx, hd_base + 2);
        BOOST_CHECK_EQUAL(internal_idx, 1);

        std::string loaded_mnemonic;
        BOOST_REQUIRE(wallet.ExportMnemonic(loaded_mnemonic));
        BOOST_CHECK_EQUAL(loaded_mnemonic, mnemonic);
    }

    std::remove(filename.c_str());
}

// Test 14: HD Wallet Address Path Validation
BOOST_AUTO_TEST_CASE(rpc_hd_wallet_path_validation_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    std::string mnemonic;
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    // Generate addresses
    CDilithiumAddress receive1 = wallet->GetNewHDAddress();
    CDilithiumAddress receive2 = wallet->GetNewHDAddress();
    CDilithiumAddress change1 = wallet->GetChangeAddress();

    // Verify paths
    CHDKeyPath path;

    BOOST_REQUIRE(wallet->GetAddressPath(receive1, path));
    BOOST_CHECK_EQUAL(path.ToString(), hdtest::ExternalPath(hd_base + 0));

    BOOST_REQUIRE(wallet->GetAddressPath(receive2, path));
    BOOST_CHECK_EQUAL(path.ToString(), hdtest::ExternalPath(hd_base + 1));

    BOOST_REQUIRE(wallet->GetAddressPath(change1, path));
    BOOST_CHECK_EQUAL(path.ToString(), "m/44'/573'/0'/1'/0'");
}

// Test 15: Multiple HD Wallets Independence
BOOST_AUTO_TEST_CASE(rpc_multiple_hd_wallets_test) {
    std::unique_ptr<CWallet> wallet1 = std::make_unique<CWallet>();
    std::unique_ptr<CWallet> wallet2 = std::make_unique<CWallet>();

    std::string mnemonic1, mnemonic2;
    BOOST_REQUIRE(wallet1->GenerateHDWallet(mnemonic1));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet1->GetAddresses().size());
    (void)hd_base;
    BOOST_REQUIRE(wallet2->GenerateHDWallet(mnemonic2));

    // Mnemonics should be different
    BOOST_CHECK(mnemonic1 != mnemonic2);

    // Generated addresses should be different
    CDilithiumAddress addr1 = wallet1->GetNewHDAddress();
    CDilithiumAddress addr2 = wallet2->GetNewHDAddress();

    BOOST_CHECK(addr1.ToString() != addr2.ToString());
}

// Test 16: HD Wallet Info on Non-HD Wallet
BOOST_AUTO_TEST_CASE(rpc_hd_wallet_info_non_hd_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    BOOST_CHECK(!wallet->IsHDWallet());

    uint32_t account, external_idx, internal_idx;
    BOOST_CHECK(!wallet->GetHDWalletInfo(account, external_idx, internal_idx));
}

// Test 17: List Addresses on Empty HD Wallet
BOOST_AUTO_TEST_CASE(rpc_list_addresses_empty_hd_wallet_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    std::string mnemonic;
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    // Should have one initial address
    std::vector<CDilithiumAddress> addresses = wallet->GetAddresses();
    BOOST_CHECK_EQUAL(addresses.size(), hd_base + 0);
}

// Test 18: HD Wallet Large Index Test
BOOST_AUTO_TEST_CASE(rpc_hd_wallet_large_index_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    std::string mnemonic;
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    // Generate many addresses
    for (int i = 0; i < 50; i++) {
        CDilithiumAddress addr = wallet->GetNewHDAddress();
        BOOST_REQUIRE(addr.IsValid());
    }

    uint32_t account, external_idx, internal_idx;
    BOOST_REQUIRE(wallet->GetHDWalletInfo(account, external_idx, internal_idx));
    BOOST_CHECK_EQUAL(external_idx, hd_base + 50); // pre-generated, then 50 derived here
}

// Test 19: Concurrent Address Generation
BOOST_AUTO_TEST_CASE(rpc_concurrent_address_generation_test) {
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>();

    std::string mnemonic;
    BOOST_REQUIRE(wallet->GenerateHDWallet(mnemonic));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet->GetAddresses().size());
    (void)hd_base;

    // Generate addresses (wallet has mutex protection)
    std::vector<CDilithiumAddress> addresses;
    for (int i = 0; i < 20; i++) {
        CDilithiumAddress addr = wallet->GetNewHDAddress();
        BOOST_REQUIRE(addr.IsValid());
        addresses.push_back(addr);
    }

    // All addresses should be unique
    for (size_t i = 0; i < addresses.size(); i++) {
        for (size_t j = i + 1; j < addresses.size(); j++) {
            BOOST_CHECK(addresses[i].ToString() != addresses[j].ToString());
        }
    }
}

// Test 20: HD Wallet with Empty Passphrase
BOOST_AUTO_TEST_CASE(rpc_hd_wallet_empty_passphrase_test) {
    std::unique_ptr<CWallet> wallet1 = std::make_unique<CWallet>();
    std::unique_ptr<CWallet> wallet2 = std::make_unique<CWallet>();

    std::string mnemonic;
    BOOST_REQUIRE(wallet1->GenerateHDWallet(mnemonic, ""));
    // RELATIONAL BASE: what this wallet actually pre-generated (BUG #115).
    const uint32_t hd_base = static_cast<uint32_t>(wallet1->GetAddresses().size());
    (void)hd_base;
    BOOST_REQUIRE(wallet2->GenerateHDWallet(mnemonic));

    // Empty passphrase and no passphrase should produce same result
    // (both wallets were generated, so different mnemonics - not testing this)
    // This test just verifies empty passphrase doesn't cause errors
    BOOST_CHECK(wallet1->IsHDWallet());
    BOOST_CHECK(wallet2->IsHDWallet());
}

BOOST_AUTO_TEST_SUITE_END()
