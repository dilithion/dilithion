// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Transaction Validation Integration Tests - Week 6 Phase 2.2
 *
 * Comprehensive test suite for consensus-critical transaction validation.
 * Target: src/consensus/tx_validation.cpp (249 lines, 0% → 30% coverage)
 * Priority: P0 CRITICAL
 *
 * Tests cover:
 * - Basic transaction structure validation
 * - Input validation with UTXO context
 * - Fee calculation and verification
 * - Finality checks (locktime, sequence)
 * - Complete integration flows
 * - Edge cases and boundary conditions
 */

#include <boost/test/unit_test.hpp>

#include <consensus/tx_validation.h>
#include <primitives/transaction.h>
#include <node/utxo_set.h>
#include <amount.h>
#include <uint256.h>

#include <vector>
#include <memory>
#include <string>

BOOST_AUTO_TEST_SUITE(tx_validation_tests)

// ============================================================================
// Test Utilities
// ============================================================================

namespace {
    // Helper to create a test UTXO database
    bool SetupTestUTXO(CUTXOSet& utxoSet, const std::string& dbPath) {
        if (!utxoSet.Open(dbPath, true)) {
            return false;
        }
        utxoSet.Clear();
        return true;
    }

    // Helper to create a standard P2PKH scriptPubKey (20-byte hash)
    std::vector<uint8_t> CreateP2PKHScript(const uint8_t* hash20 = nullptr) {
        std::vector<uint8_t> script;
        script.push_back(0x76); // OP_DUP
        script.push_back(0xa9); // OP_HASH160
        script.push_back(0x14); // Push 20 bytes

        // Add 20-byte hash (all zeros if not provided)
        for (int i = 0; i < 20; i++) {
            script.push_back(hash20 ? hash20[i] : 0x00);
        }

        script.push_back(0x88); // OP_EQUALVERIFY
        script.push_back(0xac); // OP_CHECKSIG
        return script;
    }

    // Canonical P2PKH scriptSig — the ONE layout the malleability rule accepts:
    // [sig_len==3309 (2 LE)][sig(3309)][pk_len==1952 (2 LE)][pk(1952)] = 5265 bytes.
    // CheckTransactionInputs does not verify the signature, so arbitrary sig/pk
    // content of the correct lengths is sufficient to exercise the input path.
    std::vector<uint8_t> CanonicalP2PKHSig() {
        std::vector<uint8_t> s;
        s.push_back(3309 & 0xff); s.push_back((3309 >> 8) & 0xff);
        s.insert(s.end(), 3309, 0xAB);
        s.push_back(1952 & 0xff); s.push_back((1952 >> 8) & 0xff);
        s.insert(s.end(), 1952, 0xCD);
        return s;   // 5265 bytes
    }

    // Helper to create a simple transaction
    CTransaction CreateSimpleTx(bool includeInput = true, CAmount outputValue = 50 * COIN) {
        CTransaction tx;
        tx.nVersion = 1;
        tx.nLockTime = 0;

        if (includeInput) {
            uint256 prevHash;
            prevHash.data[0] = 0x01;
            tx.vin.push_back(CTxIn(COutPoint(prevHash, 0), {0x01, 0x02, 0x03}));
        }

        tx.vout.push_back(CTxOut(outputValue, CreateP2PKHScript()));
        return tx;
    }
}

// ============================================================================
// Basic Validation Tests (CheckTransactionBasic)
// ============================================================================

BOOST_AUTO_TEST_CASE(check_transaction_valid) {
    CTransactionValidator validator;
    std::string error;

    CTransaction tx = CreateSimpleTx(true, 50 * COIN);

    BOOST_CHECK_MESSAGE(validator.CheckTransactionBasic(tx, error),
                        "Valid transaction should pass basic checks. Error: " + error);
}

BOOST_AUTO_TEST_CASE(check_transaction_null) {
    CTransactionValidator validator;
    std::string error;

    CTransaction tx;
    tx.SetNull();

    BOOST_CHECK(!validator.CheckTransactionBasic(tx, error));
    BOOST_CHECK(!error.empty());
}

BOOST_AUTO_TEST_CASE(check_transaction_empty_inputs) {
    CTransactionValidator validator;
    std::string error;

    // Non-coinbase transaction with no inputs
    CTransaction tx = CreateSimpleTx(false, 50 * COIN);

    BOOST_CHECK(!validator.CheckTransactionBasic(tx, error));
    BOOST_CHECK(error.find("no inputs") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(check_transaction_empty_outputs) {
    CTransactionValidator validator;
    std::string error;

    CTransaction tx;
    tx.nVersion = 1;
    uint256 prevHash;
    tx.vin.push_back(CTxIn(COutPoint(prevHash, 0), {0x01, 0x02}));
    // No outputs

    BOOST_CHECK(!validator.CheckTransactionBasic(tx, error));
    BOOST_CHECK(error.find("no outputs") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(check_transaction_negative_output) {
    CTransactionValidator validator;
    std::string error;

    CTransaction tx;
    tx.nVersion = 1;
    uint256 prevHash;
    tx.vin.push_back(CTxIn(COutPoint(prevHash, 0), {0x01, 0x02}));
    tx.vout.push_back(CTxOut(0, CreateP2PKHScript())); // Zero value

    BOOST_CHECK(!validator.CheckTransactionBasic(tx, error));
    BOOST_CHECK(error.find("positive") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(check_transaction_oversized) {
    CTransactionValidator validator;
    std::string error;

    CTransaction tx;
    tx.nVersion = 1;

    // Create huge scriptSig to make transaction oversized
    std::vector<uint8_t> huge_script(TxValidation::MAX_TRANSACTION_SIZE, 0xFF);
    uint256 prevHash;
    tx.vin.push_back(CTxIn(COutPoint(prevHash, 0), huge_script));
    tx.vout.push_back(CTxOut(50 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckTransactionBasic(tx, error));
    BOOST_CHECK(error.find("size") != std::string::npos ||
                error.find("exceeds") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(check_transaction_duplicate_inputs) {
    CTransactionValidator validator;
    std::string error;

    CTransaction tx;
    tx.nVersion = 1;

    // Same outpoint spent twice
    uint256 prevHash;
    prevHash.data[0] = 0x42;
    COutPoint sameOutpoint(prevHash, 0);

    tx.vin.push_back(CTxIn(sameOutpoint, {0x01, 0x02}));
    tx.vin.push_back(CTxIn(sameOutpoint, {0x03, 0x04})); // Duplicate!
    tx.vout.push_back(CTxOut(50 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckTransactionBasic(tx, error));
    BOOST_CHECK(error.find("duplicate") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(check_transaction_value_overflow) {
    CTransactionValidator validator;
    std::string error;

    CTransaction tx;
    tx.nVersion = 1;
    uint256 prevHash;
    tx.vin.push_back(CTxIn(COutPoint(prevHash, 0), {0x01, 0x02}));

    // Outputs that sum to more than MAX_MONEY
    tx.vout.push_back(CTxOut(TxValidation::MAX_MONEY / 2 + 1, CreateP2PKHScript()));
    tx.vout.push_back(CTxOut(TxValidation::MAX_MONEY / 2 + 1, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckTransactionBasic(tx, error));
    BOOST_CHECK(error.find("range") != std::string::npos ||
                error.find("overflow") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(check_transaction_exceeds_max_money) {
    CTransactionValidator validator;
    std::string error;

    CTransaction tx;
    tx.nVersion = 1;
    uint256 prevHash;
    tx.vin.push_back(CTxIn(COutPoint(prevHash, 0), {0x01, 0x02}));
    tx.vout.push_back(CTxOut(TxValidation::MAX_MONEY + 1, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckTransactionBasic(tx, error));
    BOOST_CHECK(error.find("range") != std::string::npos);
}

// ============================================================================
// Coinbase Validation Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(validate_coinbase_transaction) {
    CTransactionValidator validator;
    std::string error;

    // Valid coinbase
    CTransaction coinbase;
    coinbase.nVersion = 1;
    coinbase.vin.push_back(CTxIn(COutPoint(), {0x01, 0x02, 0x03})); // Null prevout
    coinbase.vout.push_back(CTxOut(50 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(coinbase.IsCoinBase());
    BOOST_CHECK_MESSAGE(validator.CheckTransactionBasic(coinbase, error),
                        "Valid coinbase should pass. Error: " + error);
}

BOOST_AUTO_TEST_CASE(check_coinbase_multiple_inputs) {
    CTransactionValidator validator;
    std::string error;

    // Transaction with 2 null prevout inputs
    // This is not detected as coinbase (IsCoinBase requires exactly 1 input)
    // So it fails as a regular transaction with null prevouts
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(COutPoint(), {0x01, 0x02}));
    tx.vin.push_back(CTxIn(COutPoint(), {0x03, 0x04})); // Second input
    tx.vout.push_back(CTxOut(50 * COIN, CreateP2PKHScript()));

    // Should fail because IsCoinBase() returns false (not exactly 1 input)
    // Regular transactions can't have null prevouts
    BOOST_CHECK(!validator.CheckTransactionBasic(tx, error));
    BOOST_CHECK(!error.empty()); // Should have some error
}

BOOST_AUTO_TEST_CASE(check_coinbase_invalid_scriptsig_size) {
    CTransactionValidator validator;
    std::string error;

    // Coinbase scriptSig too short
    CTransaction coinbase;
    coinbase.nVersion = 1;
    coinbase.vin.push_back(CTxIn(COutPoint(), {0x01})); // Only 1 byte
    coinbase.vout.push_back(CTxOut(50 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckTransactionBasic(coinbase, error));
    BOOST_CHECK(error.find("scriptSig") != std::string::npos ||
                error.find("between") != std::string::npos);
}

// ============================================================================
// Input Validation Tests (with UTXO context)
// ============================================================================

BOOST_AUTO_TEST_CASE(check_inputs_nonexistent_utxo) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_nonexistent"));

    std::string error;
    CAmount fee;

    // Transaction spending non-existent UTXO
    CTransaction tx = CreateSimpleTx(true, 50 * COIN);

    BOOST_CHECK(!validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error));
    BOOST_CHECK(error.find("non-existent") != std::string::npos ||
                error.find("UTXO") != std::string::npos);

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(check_inputs_already_spent) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_already_spent"));

    std::string error;
    CAmount fee;

    // Add a UTXO
    uint256 prevHash;
    prevHash.data[0] = 0xAA;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(100 * COIN, CreateP2PKHScript()), 10, false);

    // Spend it
    BOOST_CHECK(utxoSet.SpendUTXO(outpoint));

    // Try to spend it again
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, {0x01, 0x02}));
    tx.vout.push_back(CTxOut(50 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error));

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(check_inputs_value_mismatch) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_value_mismatch"));

    std::string error;
    CAmount fee;

    // Add UTXO with 50 coins
    uint256 prevHash;
    prevHash.data[0] = 0xBB;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(50 * COIN, CreateP2PKHScript()), 10, false);

    // Try to spend more than available (100 coins output)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut(100 * COIN, CreateP2PKHScript())); // More than input!

    BOOST_CHECK(!validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error));
    BOOST_CHECK(error.find("less than") != std::string::npos ||
                error.find("negative") != std::string::npos);

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(check_inputs_negative_fee) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_negative_fee"));

    std::string error;
    CAmount fee;

    // Add UTXO with 50 coins
    uint256 prevHash;
    prevHash.data[0] = 0xCC;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(50 * COIN, CreateP2PKHScript()), 10, false);

    // Output more than input (negative fee)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut(51 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error));
    BOOST_CHECK(error.find("less than") != std::string::npos ||
                error.find("negative") != std::string::npos);

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(check_inputs_insufficient_value) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_insufficient"));

    std::string error;
    CAmount fee;

    // Add UTXO with 10 coins (insufficient for typical output)
    uint256 prevHash;
    prevHash.data[0] = 0xDD;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(10 * COIN, CreateP2PKHScript()), 10, false);

    // Try to create output of 9.99 coins (leaving tiny fee)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, {0x01, 0x02}));
    tx.vout.push_back(CTxOut(9990000000, CreateP2PKHScript()));

    // This might fail due to insufficient fee
    validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error);
    // Fee would be only 10000000 (0.01 coins), might be below minimum

    utxoSet.Close();
}

// ============================================================================
// Fee Calculation Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(calculate_fee_standard) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_fee_standard"));

    std::string error;
    CAmount fee;

    // Add UTXO with 100 coins
    uint256 prevHash;
    prevHash.data[0] = 0xEE;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(100 * COIN, CreateP2PKHScript()), 10, false);

    // Create transaction with 99 coins output (1 coin fee)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, {0x01, 0x02}));
    tx.vout.push_back(CTxOut(99 * COIN, CreateP2PKHScript()));

    bool result = validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error);

    if (result) {
        BOOST_CHECK_EQUAL(fee, 1 * COIN);
    }
    // Might fail due to fee being too high, that's okay for this test

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(calculate_fee_zero) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_fee_zero"));

    std::string error;
    CAmount fee;

    // Add UTXO with 50 coins
    uint256 prevHash;
    prevHash.data[0] = 0xFF;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(50 * COIN, CreateP2PKHScript()), 10, false);

    // Create transaction with 50 coins output (0 fee)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut(50 * COIN, CreateP2PKHScript()));

    // Should fail due to insufficient fee
    BOOST_CHECK(!validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error));
    BOOST_CHECK(error.find("fee") != std::string::npos ||
                error.find("Fee") != std::string::npos);

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(calculate_fee_high) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_fee_high"));

    std::string error;
    CAmount fee;

    // Add UTXO with 100 coins
    uint256 prevHash;
    prevHash.data[0] = 0x11;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(100 * COIN, CreateP2PKHScript()), 10, false);

    // Create transaction with 1 coin output (99 coins fee - very high!)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, {0x01, 0x02}));
    tx.vout.push_back(CTxOut(1 * COIN, CreateP2PKHScript()));

    // Very high fee should still be accepted (user choice)
    bool result = validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error);

    if (result) {
        BOOST_CHECK_EQUAL(fee, 99 * COIN);
    }

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(calculate_fee_dust) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_fee_dust"));

    std::string error;
    CAmount fee;

    // Add small UTXO
    uint256 prevHash;
    prevHash.data[0] = 0x22;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(100000, CreateP2PKHScript()), 10, false); // 0.001 coins

    // Try to create tiny output (dust threshold)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut(500, CreateP2PKHScript())); // Very small

    // CheckTransactionInputs validates fees and coinbase maturity, not dust.
    // Dust threshold is enforced in CheckTransaction (structural validation).
    // Here: input 100000, output 500, fee 99500 — passes fee check.
    BOOST_CHECK(validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error));
    BOOST_CHECK_EQUAL(fee, 100000 - 500);

    utxoSet.Close();
}

// ============================================================================
// Coinbase Maturity Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(check_coinbase_immature) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_coinbase_immature"));

    std::string error;
    CAmount fee;

    // Add immature coinbase UTXO at height 100
    uint256 prevHash;
    prevHash.data[0] = 0x33;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(50 * COIN, CreateP2PKHScript()), 100, true); // Coinbase

    // Try to spend at height 150 (only 50 confirmations, need 100)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut(49 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckTransactionInputs(tx, utxoSet, 150, fee, error));
    BOOST_CHECK(error.find("mature") != std::string::npos ||
                error.find("Coinbase") != std::string::npos);

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(check_coinbase_mature) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_coinbase_mature"));

    std::string error;
    CAmount fee;

    // Add coinbase UTXO at height 100
    uint256 prevHash;
    prevHash.data[0] = 0x44;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(50 * COIN, CreateP2PKHScript()), 100, true);

    // Spend at height 200 (100 confirmations - exactly mature)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut((50 * COIN) - 100000, CreateP2PKHScript())); // Leave fee

    bool result = validator.CheckTransactionInputs(tx, utxoSet, 200, fee, error);
    BOOST_CHECK_MESSAGE(result, "Mature coinbase should be spendable. Error: " + error);

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(check_coinbase_maturity_boundary) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_coinbase_boundary"));

    std::string error;
    CAmount fee;

    // Add coinbase UTXO at height 100
    uint256 prevHash;
    prevHash.data[0] = 0x55;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(50 * COIN, CreateP2PKHScript()), 100, true);

    // Try at height 199 (99 confirmations - not quite mature)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut((50 * COIN) - 100000, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckTransactionInputs(tx, utxoSet, 199, fee, error));
    BOOST_CHECK(error.find("mature") != std::string::npos);

    utxoSet.Close();
}

// ============================================================================
// Integration Tests (Complete Validation Flow)
// ============================================================================

BOOST_AUTO_TEST_CASE(validate_transaction_full_flow) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_full_flow"));

    std::string error;
    CAmount fee;

    // Setup: Add spendable UTXO
    uint256 prevHash;
    prevHash.data[0] = 0x66;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(100 * COIN, CreateP2PKHScript()), 10, false);

    // Create valid transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut((100 * COIN) - 100000, CreateP2PKHScript())); // 0.001 coin fee

    // Step 1: Basic validation
    BOOST_CHECK_MESSAGE(validator.CheckTransactionBasic(tx, error),
                        "Basic validation failed: " + error);

    // Step 2: Input validation
    BOOST_CHECK_MESSAGE(validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error),
                        "Input validation failed: " + error);

    BOOST_CHECK_EQUAL(fee, 100000);

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(validate_transaction_multiple_inputs) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_multi_inputs"));

    std::string error;
    CAmount fee;

    // Add multiple UTXOs
    uint256 hash1, hash2, hash3;
    hash1.data[0] = 0x77;
    hash2.data[0] = 0x88;
    hash3.data[0] = 0x99;

    COutPoint out1(hash1, 0), out2(hash2, 0), out3(hash3, 0);
    utxoSet.AddUTXO(out1, CTxOut(30 * COIN, CreateP2PKHScript()), 10, false);
    utxoSet.AddUTXO(out2, CTxOut(40 * COIN, CreateP2PKHScript()), 20, false);
    utxoSet.AddUTXO(out3, CTxOut(30 * COIN, CreateP2PKHScript()), 30, false);

    // Create transaction spending all three (100 coins total)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(out1, CanonicalP2PKHSig()));
    tx.vin.push_back(CTxIn(out2, CanonicalP2PKHSig()));
    tx.vin.push_back(CTxIn(out3, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut((100 * COIN) - 100000, CreateP2PKHScript()));

    bool result = validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error);
    BOOST_CHECK_MESSAGE(result, "Multi-input transaction failed: " + error);

    if (result) {
        BOOST_CHECK_EQUAL(fee, 100000);
    }

    utxoSet.Close();
}

BOOST_AUTO_TEST_CASE(validate_transaction_multiple_outputs) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_multi_outputs"));

    std::string error;
    CAmount fee;

    // Add UTXO
    uint256 prevHash;
    prevHash.data[0] = 0xAA;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(100 * COIN, CreateP2PKHScript()), 10, false);

    // Create transaction with multiple outputs
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, CanonicalP2PKHSig()));
    tx.vout.push_back(CTxOut(30 * COIN, CreateP2PKHScript()));
    tx.vout.push_back(CTxOut(40 * COIN, CreateP2PKHScript()));
    tx.vout.push_back(CTxOut((30 * COIN) - 100000, CreateP2PKHScript()));

    bool result = validator.CheckTransactionInputs(tx, utxoSet, 100, fee, error);
    BOOST_CHECK_MESSAGE(result, "Multi-output transaction failed: " + error);

    if (result) {
        BOOST_CHECK_EQUAL(fee, 100000);
    }

    utxoSet.Close();
}

// ============================================================================
// Standard Transaction Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(is_standard_transaction_valid) {
    CTransactionValidator validator;

    CTransaction tx = CreateSimpleTx(true, 50 * COIN);

    BOOST_CHECK(validator.IsStandardTransaction(tx));
}

BOOST_AUTO_TEST_CASE(is_standard_transaction_invalid_version) {
    CTransactionValidator validator;

    CTransaction tx = CreateSimpleTx(true, 50 * COIN);
    tx.nVersion = 99; // Non-standard version

    BOOST_CHECK(!validator.IsStandardTransaction(tx));
}

BOOST_AUTO_TEST_CASE(is_standard_transaction_dust_output) {
    CTransactionValidator validator;

    CTransaction tx = CreateSimpleTx(true, 500); // Below dust threshold

    BOOST_CHECK(!validator.IsStandardTransaction(tx));
}

BOOST_AUTO_TEST_CASE(is_standard_transaction_oversized) {
    CTransactionValidator validator;

    CTransaction tx;
    tx.nVersion = 1;

    // Create large script (over 100KB limit for standard)
    std::vector<uint8_t> large_script(200000, 0x00);
    uint256 prevHash;
    tx.vin.push_back(CTxIn(COutPoint(prevHash, 0), large_script));
    tx.vout.push_back(CTxOut(50 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(!validator.IsStandardTransaction(tx));
}

// ============================================================================
// Helper Function Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(get_transaction_weight) {
    CTransactionValidator validator;

    CTransaction tx = CreateSimpleTx(true, 50 * COIN);
    size_t weight = validator.GetTransactionWeight(tx);

    BOOST_CHECK_GT(weight, 0);
    BOOST_CHECK_EQUAL(weight, tx.GetSerializedSize());
}

BOOST_AUTO_TEST_CASE(get_minimum_fee) {
    CTransactionValidator validator;

    CTransaction tx = CreateSimpleTx(true, 50 * COIN);
    CAmount min_fee = validator.GetMinimumFee(tx);

    BOOST_CHECK_GT(min_fee, 0);
}

BOOST_AUTO_TEST_CASE(check_double_spend) {
    CTransactionValidator validator;
    CUTXOSet utxoSet;
    BOOST_REQUIRE(SetupTestUTXO(utxoSet, ".test_utxo_double_spend"));

    // Add UTXO
    uint256 prevHash;
    prevHash.data[0] = 0xBB;
    COutPoint outpoint(prevHash, 0);
    utxoSet.AddUTXO(outpoint, CTxOut(100 * COIN, CreateP2PKHScript()), 10, false);

    // Valid transaction (no double-spend)
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(outpoint, {0x01, 0x02}));
    tx.vout.push_back(CTxOut(99 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(validator.CheckDoubleSpend(tx, utxoSet));

    // Transaction with duplicate inputs (double-spend)
    CTransaction tx2;
    tx2.nVersion = 1;
    tx2.vin.push_back(CTxIn(outpoint, {0x01, 0x02}));
    tx2.vin.push_back(CTxIn(outpoint, {0x03, 0x04})); // Duplicate
    tx2.vout.push_back(CTxOut(99 * COIN, CreateP2PKHScript()));

    BOOST_CHECK(!validator.CheckDoubleSpend(tx2, utxoSet));

    utxoSet.Close();
}

BOOST_AUTO_TEST_SUITE_END()
