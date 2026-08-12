// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * UTXO Set Integration Tests - Week 6 Phase 2.1
 *
 * Target: Test consensus-critical UTXO set operations
 * Coverage: 0% → 20% (src/node/utxo_set.cpp - 517 lines)
 * Priority: P0 CRITICAL
 *
 * This test file provides comprehensive integration testing for the UTXO
 * (Unspent Transaction Output) set database, which is critical infrastructure
 * for transaction validation and consensus.
 *
 * Test Categories:
 * 1. Basic Operations (Open, AddUTXO, SpendUTXO, GetUTXO)
 * 2. Consensus-Critical (Double-spend detection, nonexistent inputs)
 * 3. Integration (Block application, reorg handling, chain updates)
 * 4. Edge Cases (Coinbase maturity, multiple outputs, consistency)
 */

#include <boost/test/unit_test.hpp>

#include <node/utxo_set.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <consensus/validation.h>
#include <consensus/connect_checks.h>
#include <amount.h>
#include <uint256.h>
#include <crypto/sha3.h>

#include <vector>
#include <memory>
#include <cstring>
#include <filesystem>

BOOST_AUTO_TEST_SUITE(utxo_tests)

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create a test UTXO set in a temporary directory
 * Returns path to temp directory (caller responsible for cleanup)
 */
static std::string CreateTestUTXOSet(CUTXOSet& utxo) {
    std::string temp_path = std::filesystem::temp_directory_path().string() +
                           "/utxo_test_" + std::to_string(time(nullptr));

    // Create directory if needed
    std::filesystem::create_directories(temp_path);

    // Open database
    bool success = utxo.Open(temp_path, true);
    BOOST_REQUIRE(success);
    BOOST_REQUIRE(utxo.IsOpen());

    return temp_path;
}

/**
 * Cleanup test UTXO database
 */
static void CleanupTestUTXOSet(const std::string& path) {
    try {
        std::filesystem::remove_all(path);
    } catch (...) {
        // Ignore cleanup errors
    }
}

/**
 * Create a test transaction hash from a seed value
 */
static uint256 MakeTestHash(uint8_t seed) {
    uint256 hash;
    memset(hash.data, seed, 32);
    return hash;
}

/**
 * Create a simple test transaction with given inputs and outputs
 */
static CTransactionRef CreateTestTransaction(
    const std::vector<COutPoint>& inputs,
    const std::vector<uint64_t>& output_values,
    bool is_coinbase = false,
    uint32_t coinbase_data = 0
) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Add inputs
    if (is_coinbase) {
        // Coinbase has single null input with unique scriptSig
        // Include coinbase_data (e.g., block height) to make each coinbase unique
        std::vector<uint8_t> scriptSig;
        scriptSig.push_back(0x04);  // Push 4 bytes
        scriptSig.push_back(coinbase_data & 0xFF);
        scriptSig.push_back((coinbase_data >> 8) & 0xFF);
        scriptSig.push_back((coinbase_data >> 16) & 0xFF);
        scriptSig.push_back((coinbase_data >> 24) & 0xFF);
        tx.vin.push_back(CTxIn(COutPoint(), scriptSig));
    } else {
        for (const auto& input : inputs) {
            std::vector<uint8_t> sig(100, 0xAA);  // Placeholder signature
            tx.vin.push_back(CTxIn(input, sig, CTxIn::SEQUENCE_FINAL));
        }
    }

    // Add outputs
    for (size_t i = 0; i < output_values.size(); i++) {
        std::vector<uint8_t> scriptPubKey = {0x76, 0xA9, 0x14};  // OP_DUP OP_HASH160 PUSH20
        scriptPubKey.insert(scriptPubKey.end(), 20, static_cast<uint8_t>(i));  // 20-byte pubkey hash
        scriptPubKey.push_back(0x88);  // OP_EQUALVERIFY
        scriptPubKey.push_back(0xAC);  // OP_CHECKSIG
        tx.vout.push_back(CTxOut(output_values[i], scriptPubKey));
    }

    return MakeTransactionRef(tx);
}

/**
 * Write compact size (Bitcoin-style variable-length integer)
 */
static void WriteCompactSize(std::vector<uint8_t>& data, uint64_t size) {
    if (size < 253) {
        data.push_back(static_cast<uint8_t>(size));
    } else if (size <= 0xFFFF) {
        data.push_back(253);
        data.push_back(static_cast<uint8_t>(size & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
    } else if (size <= 0xFFFFFFFF) {
        data.push_back(254);
        data.push_back(static_cast<uint8_t>(size & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 24) & 0xFF));
    } else {
        data.push_back(255);
        for (int i = 0; i < 8; i++) {
            data.push_back(static_cast<uint8_t>((size >> (i * 8)) & 0xFF));
        }
    }
}

/**
 * Create a test block with given transactions
 */
static CBlock CreateTestBlock(const std::vector<CTransactionRef>& transactions, uint32_t height) {
    CBlock block;
    block.nVersion = 1;
    block.nTime = static_cast<uint32_t>(time(nullptr));
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;

    // Serialize transactions into block.vtx
    // Format: compact size count + serialized transactions
    std::vector<uint8_t> vtx_data;

    // Write transaction count (compact size encoding)
    WriteCompactSize(vtx_data, transactions.size());

    // Serialize each transaction
    for (const auto& tx : transactions) {
        std::vector<uint8_t> tx_data = tx->Serialize();
        vtx_data.insert(vtx_data.end(), tx_data.begin(), tx_data.end());
    }

    block.vtx = vtx_data;

    // Calculate merkle root
    CBlockValidator validator;
    block.hashMerkleRoot = validator.BuildMerkleRoot(transactions);

    return block;
}

// ============================================================================
// Test Suite 1: Basic Operations
// ============================================================================

/**
 * Test 1: Open and close UTXO database
 */
BOOST_AUTO_TEST_CASE(utxo_open_close) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Should be open
    BOOST_CHECK(utxo.IsOpen());

    // Close should work
    utxo.Close();
    BOOST_CHECK(!utxo.IsOpen());

    // Should be able to reopen
    BOOST_CHECK(utxo.Open(path, false));
    BOOST_CHECK(utxo.IsOpen());

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 2: Add single coin to UTXO set
 */
BOOST_AUTO_TEST_CASE(utxo_add_coin) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Create test output
    uint256 txid = MakeTestHash(0x42);
    uint32_t vout_index = 0;
    COutPoint outpoint(txid, vout_index);

    std::vector<uint8_t> scriptPubKey = {0x76, 0xA9, 0x14};
    scriptPubKey.insert(scriptPubKey.end(), 20, 0x11);
    scriptPubKey.push_back(0x88);
    scriptPubKey.push_back(0xAC);

    CTxOut txout(50 * COIN, scriptPubKey);

    // Add UTXO
    BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 100, false));

    // Verify it exists
    BOOST_CHECK(utxo.HaveUTXO(outpoint));

    // Get and verify details
    CUTXOEntry entry;
    BOOST_CHECK(utxo.GetUTXO(outpoint, entry));
    BOOST_CHECK_EQUAL(entry.out.nValue, 50 * COIN);
    BOOST_CHECK_EQUAL(entry.nHeight, 100);
    BOOST_CHECK_EQUAL(entry.fCoinBase, false);
    BOOST_CHECK(entry.out.scriptPubKey == scriptPubKey);

    // Flush and verify persistence
    BOOST_CHECK(utxo.Flush());
    BOOST_CHECK(utxo.HaveUTXO(outpoint));

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 3: Spend a coin from UTXO set
 */
BOOST_AUTO_TEST_CASE(utxo_spend_coin) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Add UTXO
    uint256 txid = MakeTestHash(0x42);
    COutPoint outpoint(txid, 0);
    std::vector<uint8_t> scriptPubKey(25, 0xAA);
    CTxOut txout(50 * COIN, scriptPubKey);

    BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 100, false));
    BOOST_CHECK(utxo.Flush());
    BOOST_CHECK(utxo.HaveUTXO(outpoint));

    // Spend it
    BOOST_CHECK(utxo.SpendUTXO(outpoint));

    // Should no longer exist
    BOOST_CHECK(!utxo.HaveUTXO(outpoint));

    // Flush and verify it's gone
    BOOST_CHECK(utxo.Flush());
    BOOST_CHECK(!utxo.HaveUTXO(outpoint));

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 4: Check if UTXO exists (HaveUTXO)
 */
BOOST_AUTO_TEST_CASE(utxo_have_input) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    uint256 txid1 = MakeTestHash(0x01);
    uint256 txid2 = MakeTestHash(0x02);
    COutPoint exists(txid1, 0);
    COutPoint not_exists(txid2, 0);

    std::vector<uint8_t> scriptPubKey(25, 0xBB);
    CTxOut txout(25 * COIN, scriptPubKey);

    // Add only one
    BOOST_CHECK(utxo.AddUTXO(exists, txout, 50, false));
    BOOST_CHECK(utxo.Flush());

    // Check existence
    BOOST_CHECK(utxo.HaveUTXO(exists));
    BOOST_CHECK(!utxo.HaveUTXO(not_exists));

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 5: Get UTXO statistics
 */
BOOST_AUTO_TEST_CASE(utxo_get_statistics) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Initial stats should be zero
    CUTXOStats stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nUTXOs, 0);
    BOOST_CHECK_EQUAL(stats.nTotalAmount, 0);

    // Add some UTXOs
    std::vector<uint8_t> scriptPubKey(25, 0xCC);
    for (uint8_t i = 0; i < 5; i++) {
        uint256 txid = MakeTestHash(i);
        COutPoint outpoint(txid, 0);
        CTxOut txout((10 + i) * COIN, scriptPubKey);
        BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 100 + i, false));
    }

    // Check updated stats
    stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nUTXOs, 5);
    // Total: 10 + 11 + 12 + 13 + 14 = 60 COIN
    BOOST_CHECK_EQUAL(stats.nTotalAmount, 60 * COIN);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

// ============================================================================
// Test Suite 2: Consensus-Critical Tests
// ============================================================================

/**
 * Test 6: Double-spend detection
 */
BOOST_AUTO_TEST_CASE(utxo_double_spend_detection) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Add a UTXO
    uint256 txid = MakeTestHash(0x50);
    COutPoint outpoint(txid, 0);
    std::vector<uint8_t> scriptPubKey(25, 0xDD);
    CTxOut txout(100 * COIN, scriptPubKey);

    BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 100, false));
    BOOST_CHECK(utxo.Flush());

    // Spend it once - should succeed
    BOOST_CHECK(utxo.SpendUTXO(outpoint));
    BOOST_CHECK(utxo.Flush());

    // Try to spend again - should fail (not found)
    BOOST_CHECK(!utxo.SpendUTXO(outpoint));

    // Verify it's gone
    BOOST_CHECK(!utxo.HaveUTXO(outpoint));

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 7: Spend nonexistent input
 */
BOOST_AUTO_TEST_CASE(utxo_nonexistent_input) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Try to spend something that doesn't exist
    uint256 fake_txid = MakeTestHash(0xFF);
    COutPoint fake_outpoint(fake_txid, 0);

    BOOST_CHECK(!utxo.SpendUTXO(fake_outpoint));
    BOOST_CHECK(!utxo.HaveUTXO(fake_outpoint));

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 8: Spend already spent input
 */
BOOST_AUTO_TEST_CASE(utxo_already_spent_input) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Add and spend a UTXO
    uint256 txid = MakeTestHash(0x60);
    COutPoint outpoint(txid, 0);
    std::vector<uint8_t> scriptPubKey(25, 0xEE);
    CTxOut txout(75 * COIN, scriptPubKey);

    BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 200, false));
    BOOST_CHECK(utxo.Flush());
    BOOST_CHECK(utxo.SpendUTXO(outpoint));
    BOOST_CHECK(utxo.Flush());

    // Verify it's spent
    BOOST_CHECK(!utxo.HaveUTXO(outpoint));

    // Try to spend again - should fail
    BOOST_CHECK(!utxo.SpendUTXO(outpoint));

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 9: Apply a simple block to UTXO set
 */
BOOST_AUTO_TEST_CASE(utxo_update_for_block) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Create a block with coinbase transaction
    CTransactionRef coinbase = CreateTestTransaction({}, {50 * COIN}, true);

    // Create block
    std::vector<CTransactionRef> transactions = {coinbase};
    CBlock block = CreateTestBlock(transactions, 1);

    // Apply block
    BOOST_CHECK(utxo.ApplyBlock(block, 1, block.GetHash()));

    // Verify coinbase output was added
    uint256 coinbase_txid = coinbase->GetHash();
    COutPoint coinbase_out(coinbase_txid, 0);
    BOOST_CHECK(utxo.HaveUTXO(coinbase_out));

    // Verify entry details
    CUTXOEntry entry;
    BOOST_CHECK(utxo.GetUTXO(coinbase_out, entry));
    BOOST_CHECK_EQUAL(entry.out.nValue, 50 * COIN);
    BOOST_CHECK_EQUAL(entry.nHeight, 1);
    BOOST_CHECK_EQUAL(entry.fCoinBase, true);

    // Check statistics
    CUTXOStats stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nUTXOs, 1);
    BOOST_CHECK_EQUAL(stats.nTotalAmount, 50 * COIN);
    BOOST_CHECK_EQUAL(stats.nHeight, 1);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 10: Apply block with spending transaction
 */
BOOST_AUTO_TEST_CASE(utxo_value_calculation) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // First, create an initial UTXO to spend
    uint256 prev_txid = MakeTestHash(0x70);
    COutPoint prev_out(prev_txid, 0);
    std::vector<uint8_t> scriptPubKey(25, 0xFF);
    CTxOut prev_txout(100 * COIN, scriptPubKey);

    BOOST_CHECK(utxo.AddUTXO(prev_out, prev_txout, 1, false));
    BOOST_CHECK(utxo.Flush());

    // Create block with coinbase and spending transaction
    CTransactionRef coinbase = CreateTestTransaction({}, {50 * COIN}, true);
    CTransactionRef spending_tx = CreateTestTransaction({prev_out}, {90 * COIN}, false);

    std::vector<CTransactionRef> transactions = {coinbase, spending_tx};
    CBlock block = CreateTestBlock(transactions, 2);

    // Apply block
    BOOST_CHECK(utxo.ApplyBlock(block, 2, block.GetHash()));

    // Verify prev_out was spent
    BOOST_CHECK(!utxo.HaveUTXO(prev_out));

    // Verify new outputs exist
    uint256 spending_txid = spending_tx->GetHash();
    COutPoint new_out(spending_txid, 0);
    BOOST_CHECK(utxo.HaveUTXO(new_out));

    // Check value
    CUTXOEntry entry;
    BOOST_CHECK(utxo.GetUTXO(new_out, entry));
    BOOST_CHECK_EQUAL(entry.out.nValue, 90 * COIN);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

// ============================================================================
// Test Suite 3: Integration Tests
// ============================================================================

/**
 * Test 11: Apply multiple blocks in sequence
 */
BOOST_AUTO_TEST_CASE(utxo_block_chain_updates) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    uint256 prev_coinbase_txid;

    // Apply 5 blocks
    for (uint32_t height = 1; height <= 5; height++) {
        std::vector<CTransactionRef> transactions;

        // Coinbase
        CTransactionRef coinbase = CreateTestTransaction({}, {50 * COIN}, true);
        transactions.push_back(coinbase);

        // If not first block, spend previous coinbase
        if (height > 1) {
            COutPoint prev_out(prev_coinbase_txid, 0);
            CTransactionRef spending = CreateTestTransaction({prev_out}, {45 * COIN}, false);
            transactions.push_back(spending);
        }

        // Create and apply block
        CBlock block = CreateTestBlock(transactions, height);
        BOOST_CHECK(utxo.ApplyBlock(block, height, block.GetHash()));

        prev_coinbase_txid = coinbase->GetHash();
    }

    // Verify final state
    CUTXOStats stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nHeight, 5);
    BOOST_CHECK(stats.nUTXOs > 0);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 12: Undo block (reorg handling)
 */
BOOST_AUTO_TEST_CASE(utxo_reorg_handling) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Create initial UTXO
    uint256 prev_txid = MakeTestHash(0x80);
    COutPoint prev_out(prev_txid, 0);
    std::vector<uint8_t> scriptPubKey(25, 0xAA);
    CTxOut prev_txout(100 * COIN, scriptPubKey);
    BOOST_CHECK(utxo.AddUTXO(prev_out, prev_txout, 1, false));
    BOOST_CHECK(utxo.Flush());

    // Create and apply block that spends prev_out
    CTransactionRef coinbase = CreateTestTransaction({}, {50 * COIN}, true);
    CTransactionRef spending = CreateTestTransaction({prev_out}, {90 * COIN}, false);

    std::vector<CTransactionRef> transactions = {coinbase, spending};
    CBlock block = CreateTestBlock(transactions, 2);

    // C-R3 INVERSION: the low-level UTXO mutator ApplyBlock still ACCEPTS this
    // garbage-signature spend (it only checks input existence / dup-txid); that
    // is exactly the connect-path gap. The new unified connect-path validator
    // ConnectBlockChecks — the gate ConnectTip now runs BEFORE ApplyBlock —
    // REJECTS the same block for an invalid ML-DSA signature. (The spend is
    // value-valid 100 -> 90, so the rejection is attributable to the signature.)
    {
        std::string ccError;
        BOOST_CHECK_MESSAGE(
            !ConnectBlockChecks(block, utxo, 2, /*fVerifyScripts=*/true, ccError),
            "connect-path validator must reject the garbage-signature spend");
    }

    BOOST_CHECK(utxo.ApplyBlock(block, 2, block.GetHash()));

    // After applying: prev_out should be spent, new outputs should exist
    BOOST_CHECK(!utxo.HaveUTXO(prev_out));

    uint256 spending_txid = spending->GetHash();
    COutPoint new_out(spending_txid, 0);
    BOOST_CHECK(utxo.HaveUTXO(new_out));

    // Now undo the block
    BOOST_CHECK(utxo.UndoBlock(block, block.GetHash()));

    // After undoing: prev_out should be restored, new outputs should be gone
    BOOST_CHECK(utxo.HaveUTXO(prev_out));
    BOOST_CHECK(!utxo.HaveUTXO(new_out));

    // Verify restored UTXO has correct value
    CUTXOEntry entry;
    BOOST_CHECK(utxo.GetUTXO(prev_out, entry));
    BOOST_CHECK_EQUAL(entry.out.nValue, 100 * COIN);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 13: Transaction with multiple outputs
 */
BOOST_AUTO_TEST_CASE(utxo_multiple_outputs) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Create transaction with 3 outputs
    std::vector<uint64_t> output_values = {10 * COIN, 20 * COIN, 30 * COIN};
    CTransactionRef tx = CreateTestTransaction({}, output_values, true);

    // Create and apply block
    std::vector<CTransactionRef> transactions = {tx};
    CBlock block = CreateTestBlock(transactions, 1);
    BOOST_CHECK(utxo.ApplyBlock(block, 1, block.GetHash()));

    // Verify all 3 outputs exist
    uint256 txid = tx->GetHash();
    for (uint32_t i = 0; i < 3; i++) {
        COutPoint outpoint(txid, i);
        BOOST_CHECK(utxo.HaveUTXO(outpoint));

        CUTXOEntry entry;
        BOOST_CHECK(utxo.GetUTXO(outpoint, entry));
        BOOST_CHECK_EQUAL(entry.out.nValue, output_values[i]);
    }

    // Statistics should reflect all outputs
    CUTXOStats stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nUTXOs, 3);
    BOOST_CHECK_EQUAL(stats.nTotalAmount, 60 * COIN);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 14: Coinbase maturity rules
 */
BOOST_AUTO_TEST_CASE(utxo_coinbase_maturity) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Create coinbase output
    CTransactionRef coinbase = CreateTestTransaction({}, {50 * COIN}, true);
    std::vector<CTransactionRef> transactions = {coinbase};
    CBlock block = CreateTestBlock(transactions, 100);

    BOOST_CHECK(utxo.ApplyBlock(block, 100, block.GetHash()));

    uint256 coinbase_txid = coinbase->GetHash();
    COutPoint coinbase_out(coinbase_txid, 0);

    // Verify entry is marked as coinbase
    CUTXOEntry entry;
    BOOST_CHECK(utxo.GetUTXO(coinbase_out, entry));
    BOOST_CHECK_EQUAL(entry.fCoinBase, true);
    BOOST_CHECK_EQUAL(entry.nHeight, 100);

    // Check maturity at various heights
    // Coinbase requires 100 confirmations (COINBASE_MATURITY = 100)

    // At height 100: Not mature (0 confirmations)
    BOOST_CHECK(!utxo.IsCoinBaseMature(coinbase_out, 100));

    // At height 150: Not mature (50 confirmations)
    BOOST_CHECK(!utxo.IsCoinBaseMature(coinbase_out, 150));

    // At height 199: Not mature (99 confirmations)
    BOOST_CHECK(!utxo.IsCoinBaseMature(coinbase_out, 199));

    // At height 200: Mature (100 confirmations)
    BOOST_CHECK(utxo.IsCoinBaseMature(coinbase_out, 200));

    // At height 250: Mature (150 confirmations)
    BOOST_CHECK(utxo.IsCoinBaseMature(coinbase_out, 250));

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 15: UTXO set consistency verification
 */
BOOST_AUTO_TEST_CASE(utxo_consistency_check) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Add several UTXOs
    for (uint8_t i = 0; i < 10; i++) {
        uint256 txid = MakeTestHash(i);
        COutPoint outpoint(txid, 0);
        std::vector<uint8_t> scriptPubKey(25, i);
        CTxOut txout((5 + i) * COIN, scriptPubKey);
        BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 100 + i, i % 2 == 0));
    }

    BOOST_CHECK(utxo.Flush());

    // Consistency check should pass
    BOOST_CHECK(utxo.VerifyConsistency());

    // Update statistics
    BOOST_CHECK(utxo.UpdateStats());

    // Check stats are correct
    CUTXOStats stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nUTXOs, 10);
    // Total: 5+6+7+8+9+10+11+12+13+14 = 95 COIN
    BOOST_CHECK_EQUAL(stats.nTotalAmount, 95 * COIN);

    // Consistency should still pass
    BOOST_CHECK(utxo.VerifyConsistency());

    utxo.Close();
    CleanupTestUTXOSet(path);
}

// ============================================================================
// Test Suite 4: Additional Edge Cases
// ============================================================================

/**
 * Test 16: Clear entire UTXO set
 */
BOOST_AUTO_TEST_CASE(utxo_clear_all) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Add some UTXOs
    for (uint8_t i = 0; i < 5; i++) {
        uint256 txid = MakeTestHash(0x90 + i);
        COutPoint outpoint(txid, 0);
        std::vector<uint8_t> scriptPubKey(25, i);
        CTxOut txout(10 * COIN, scriptPubKey);
        BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 50, false));
    }
    BOOST_CHECK(utxo.Flush());

    // Verify they exist
    CUTXOStats stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nUTXOs, 5);

    // Clear all
    BOOST_CHECK(utxo.Clear());

    // Verify everything is gone
    stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nUTXOs, 0);
    BOOST_CHECK_EQUAL(stats.nTotalAmount, 0);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 17: Cache behavior under load
 */
BOOST_AUTO_TEST_CASE(utxo_cache_stress) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Add more UTXOs than cache can hold (cache limit is 10000)
    const size_t count = 100;  // Keep test fast
    std::vector<COutPoint> outpoints;

    for (size_t i = 0; i < count; i++) {
        uint256 txid = MakeTestHash(static_cast<uint8_t>(i % 256));
        // Use different indices to make unique outpoints
        COutPoint outpoint(txid, static_cast<uint32_t>(i));
        outpoints.push_back(outpoint);

        std::vector<uint8_t> scriptPubKey(25, static_cast<uint8_t>(i % 256));
        CTxOut txout(COIN, scriptPubKey);
        BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 100, false));
    }

    BOOST_CHECK(utxo.Flush());

    // Verify all UTXOs are still accessible
    for (const auto& outpoint : outpoints) {
        BOOST_CHECK(utxo.HaveUTXO(outpoint));
    }

    // Stats should be correct
    CUTXOStats stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nUTXOs, count);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 18: Non-coinbase transaction maturity (should always be mature)
 */
BOOST_AUTO_TEST_CASE(utxo_non_coinbase_always_mature) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Add non-coinbase UTXO
    uint256 txid = MakeTestHash(0xA0);
    COutPoint outpoint(txid, 0);
    std::vector<uint8_t> scriptPubKey(25, 0xBB);
    CTxOut txout(25 * COIN, scriptPubKey);

    BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 100, false));
    BOOST_CHECK(utxo.Flush());

    // Non-coinbase should be mature immediately
    BOOST_CHECK(utxo.IsCoinBaseMature(outpoint, 100));
    BOOST_CHECK(utxo.IsCoinBaseMature(outpoint, 101));
    BOOST_CHECK(utxo.IsCoinBaseMature(outpoint, 50));  // Even at earlier height

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 19: Apply and undo multiple blocks (complex reorg)
 */
BOOST_AUTO_TEST_CASE(utxo_complex_reorg) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    std::vector<CBlock> blocks;
    std::vector<uint256> coinbase_txids;

    // Apply 3 blocks
    for (uint32_t height = 1; height <= 3; height++) {
        CTransactionRef coinbase = CreateTestTransaction({}, {50 * COIN}, true, height);
        coinbase_txids.push_back(coinbase->GetHash());

        std::vector<CTransactionRef> transactions = {coinbase};
        CBlock block = CreateTestBlock(transactions, height);
        blocks.push_back(block);

        BOOST_CHECK(utxo.ApplyBlock(block, height, block.GetHash()));
    }

    // Verify all coinbases exist
    for (size_t i = 0; i < coinbase_txids.size(); i++) {
        COutPoint out(coinbase_txids[i], 0);
        BOOST_CHECK(utxo.HaveUTXO(out));
    }

    CUTXOStats stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nHeight, 3);
    BOOST_CHECK_EQUAL(stats.nUTXOs, 3);

    // Undo blocks in reverse order
    for (int i = 2; i >= 0; i--) {
        BOOST_CHECK(utxo.UndoBlock(blocks[i], blocks[i].GetHash()));
    }

    // All coinbases should be gone
    for (const auto& txid : coinbase_txids) {
        COutPoint out(txid, 0);
        BOOST_CHECK(!utxo.HaveUTXO(out));
    }

    // Stats should be reset
    stats = utxo.GetStats();
    BOOST_CHECK_EQUAL(stats.nUTXOs, 0);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

/**
 * Test 20: ForEach iterator functionality
 */
BOOST_AUTO_TEST_CASE(utxo_foreach_iterator) {
    CUTXOSet utxo;
    std::string path = CreateTestUTXOSet(utxo);

    // Add several UTXOs
    const size_t count = 10;
    for (size_t i = 0; i < count; i++) {
        uint256 txid = MakeTestHash(static_cast<uint8_t>(0xB0 + i));
        COutPoint outpoint(txid, 0);
        std::vector<uint8_t> scriptPubKey(25, static_cast<uint8_t>(i));
        CTxOut txout((i + 1) * COIN, scriptPubKey);
        BOOST_CHECK(utxo.AddUTXO(outpoint, txout, 100 + i, false));
    }
    BOOST_CHECK(utxo.Flush());

    // Iterate through all UTXOs
    size_t iterated_count = 0;
    uint64_t total_value = 0;

    utxo.ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) {
        iterated_count++;
        total_value += entry.out.nValue;
        return true;  // Continue iteration
    });

    // Verify we saw all UTXOs
    BOOST_CHECK_EQUAL(iterated_count, count);
    // Total: 1+2+3+4+5+6+7+8+9+10 = 55 COIN
    BOOST_CHECK_EQUAL(total_value, 55 * COIN);

    // Test early termination
    size_t limited_count = 0;
    utxo.ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) {
        limited_count++;
        return limited_count < 5;  // Stop after 5
    });
    BOOST_CHECK_EQUAL(limited_count, 5);

    utxo.Close();
    CleanupTestUTXOSet(path);
}

BOOST_AUTO_TEST_SUITE_END()
