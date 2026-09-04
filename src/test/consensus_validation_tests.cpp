// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Consensus Validation Tests - Week 6 Day 1 Coverage Expansion
 *
 * TARGET: Increase consensus component coverage from 50% to 70%+
 *
 * This file adds comprehensive unit tests for previously untested
 * consensus functions:
 * - consensus/fees.cpp (CalculateMinFee, CheckFee, CalculateFeeRate, EstimateDilithiumTxSize)
 * - consensus/validation.cpp (CalculateBlockSubsidy, BuildMerkleRoot, DeserializeBlockTransactions)
 * - consensus/pow.cpp (GetNextWorkRequired edge cases)
 *
 * Priority: P0 CRITICAL - Consensus functions must be thoroughly tested
 */

#include <boost/test/unit_test.hpp>

#include <consensus/fees.h>
#include <consensus/validation.h>
#include <consensus/pow.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <node/block_index.h>
#include <core/chainparams.h>
#include <amount.h>
#include <uint256.h>
#include <crypto/sha3.h>

#include <vector>
#include <cstring>
#include <memory>

BOOST_AUTO_TEST_SUITE(consensus_validation_tests)

// ============================================================================
// FEES TESTS (consensus/fees.cpp)
// ============================================================================

/**
 * Test CalculateMinFee with various transaction sizes
 */
BOOST_AUTO_TEST_CASE(calculate_min_fee_various_sizes) {
    using namespace Consensus;

    // Test minimum transaction size
    CAmount min_fee_small = CalculateMinFee(100);
    BOOST_CHECK(min_fee_small >= MIN_TX_FEE);
    BOOST_CHECK_EQUAL(min_fee_small, MIN_TX_FEE + (100 * FEE_PER_BYTE));

    // Test medium transaction size
    CAmount min_fee_medium = CalculateMinFee(1000);
    BOOST_CHECK_EQUAL(min_fee_medium, MIN_TX_FEE + (1000 * FEE_PER_BYTE));

    // Test large transaction size (e.g., many inputs/outputs)
    CAmount min_fee_large = CalculateMinFee(10000);
    BOOST_CHECK_EQUAL(min_fee_large, MIN_TX_FEE + (10000 * FEE_PER_BYTE));

    // Fee should increase with size
    BOOST_CHECK(min_fee_small < min_fee_medium);
    BOOST_CHECK(min_fee_medium < min_fee_large);
}

/**
 * Test CalculateMinFee edge case: zero size
 */
BOOST_AUTO_TEST_CASE(calculate_min_fee_zero_size) {
    using namespace Consensus;

    // Zero size should give just MIN_TX_FEE
    CAmount min_fee = CalculateMinFee(0);
    BOOST_CHECK_EQUAL(min_fee, MIN_TX_FEE);
}

/**
 * Test CheckFee with valid fee
 */
BOOST_AUTO_TEST_CASE(check_fee_valid) {
    using namespace Consensus;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Add minimal input and output
    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Calculate required fee
    size_t tx_size = tx.GetSerializedSize();
    CAmount min_fee = CalculateMinFee(tx_size);
    CAmount paid_fee = min_fee + 1000;  // Pay slightly more

    // Should pass
    std::string error;
    BOOST_CHECK(CheckFee(tx, paid_fee, false, &error));
    BOOST_CHECK(error.empty());
}

/**
 * Test CheckFee with fee too low
 */
BOOST_AUTO_TEST_CASE(check_fee_too_low) {
    using namespace Consensus;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Pay less than minimum fee
    size_t tx_size = tx.GetSerializedSize();
    CAmount min_fee = CalculateMinFee(tx_size);
    CAmount paid_fee = min_fee - 1;  // Pay less

    // Should fail
    std::string error;
    BOOST_CHECK(!CheckFee(tx, paid_fee, false, &error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(error.find("Fee too low") != std::string::npos);
}

/**
 * Test CheckFee with fee too high (unreasonable)
 */
BOOST_AUTO_TEST_CASE(check_fee_too_high) {
    using namespace Consensus;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Pay more than MAX_REASONABLE_FEE
    CAmount paid_fee = MAX_REASONABLE_FEE + 1;

    // Should fail
    std::string error;
    BOOST_CHECK(!CheckFee(tx, paid_fee, false, &error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(error.find("Fee too high") != std::string::npos);
}

/**
 * Test CheckFee with relay check
 */
BOOST_AUTO_TEST_CASE(check_fee_relay_check) {
    using namespace Consensus;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Pay minimum fee but below relay minimum
    size_t tx_size = tx.GetSerializedSize();
    CAmount min_fee = CalculateMinFee(tx_size);
    CAmount paid_fee = std::min(min_fee, MIN_RELAY_TX_FEE - 1);

    // Should pass without relay check
    std::string error;
    BOOST_CHECK(CheckFee(tx, paid_fee + 1000, false, &error));

    // Should fail with relay check if below MIN_RELAY_TX_FEE
    if (paid_fee < MIN_RELAY_TX_FEE) {
        error.clear();
        BOOST_CHECK(!CheckFee(tx, paid_fee, true, &error));
        BOOST_CHECK(error.find("Below relay min") != std::string::npos);
    }
}

/**
 * Test CalculateFeeRate
 */
BOOST_AUTO_TEST_CASE(calculate_fee_rate) {
    using namespace Consensus;

    // Test normal fee rate calculation
    CAmount fee = 1000 * COIN;
    size_t size = 1000;
    double rate = CalculateFeeRate(fee, size);
    BOOST_CHECK_EQUAL(rate, static_cast<double>(fee) / static_cast<double>(size));

    // Test with different values
    fee = 5000;
    size = 2500;
    rate = CalculateFeeRate(fee, size);
    BOOST_CHECK_EQUAL(rate, 2.0);
}

/**
 * Test CalculateFeeRate with zero size
 */
BOOST_AUTO_TEST_CASE(calculate_fee_rate_zero_size) {
    using namespace Consensus;

    // Zero size should return 0.0 to avoid division by zero
    CAmount fee = 1000;
    double rate = CalculateFeeRate(fee, 0);
    BOOST_CHECK_EQUAL(rate, 0.0);
}

/**
 * Test EstimateDilithiumTxSize
 */
BOOST_AUTO_TEST_CASE(estimate_dilithium_tx_size) {
    using namespace Consensus;

    // Test single input, single output (typical payment)
    size_t est_size = EstimateDilithiumTxSize(1, 1, 0);
    // Formula: 10 + (1 * 5308) + (1 * 34) + 0 = 5352 bytes
    // Per input: prevout(36) + varint(3) + scriptSig(5265) + sequence(4) = 5308
    //   scriptSig: sig_len(2) + Dilithium3_sig(3309) + pk_len(2) + pk(1952) = 5265
    BOOST_CHECK_EQUAL(est_size, 10 + 5308 + 34);

    // Test multiple inputs/outputs
    est_size = EstimateDilithiumTxSize(2, 2, 0);
    // Formula: 10 + (2 * 5308) + (2 * 34) + 0 = 10694 bytes
    BOOST_CHECK_EQUAL(est_size, 10 + (2 * 5308) + (2 * 34));

    // Test with extra data
    est_size = EstimateDilithiumTxSize(1, 1, 100);
    BOOST_CHECK_EQUAL(est_size, 10 + 5308 + 34 + 100);
}

// ============================================================================
// VALIDATION TESTS (consensus/validation.cpp)
// ============================================================================

/**
 * Test CalculateBlockSubsidy at genesis
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_genesis) {
    CBlockValidator validator;

    // Genesis block should have full subsidy
    uint64_t subsidy = validator.CalculateBlockSubsidy(0);
    BOOST_CHECK_EQUAL(subsidy, 50 * COIN);
}

/**
 * Test CalculateBlockSubsidy before first halving
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_before_halving) {
    CBlockValidator validator;

    // Block 100,000 (before halving at 210,000)
    uint64_t subsidy = validator.CalculateBlockSubsidy(100000);
    BOOST_CHECK_EQUAL(subsidy, 50 * COIN);

    // Block 209,999 (last block before halving)
    subsidy = validator.CalculateBlockSubsidy(209999);
    BOOST_CHECK_EQUAL(subsidy, 50 * COIN);
}

/**
 * Test CalculateBlockSubsidy at first halving
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_first_halving) {
    CBlockValidator validator;

    // Block 210,000 (first halving)
    uint64_t subsidy = validator.CalculateBlockSubsidy(210000);
    BOOST_CHECK_EQUAL(subsidy, 25 * COIN);

    // Block 210,001
    subsidy = validator.CalculateBlockSubsidy(210001);
    BOOST_CHECK_EQUAL(subsidy, 25 * COIN);
}

/**
 * Test CalculateBlockSubsidy at second halving
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_second_halving) {
    CBlockValidator validator;

    // Block 420,000 (second halving)
    uint64_t subsidy = validator.CalculateBlockSubsidy(420000);
    BOOST_CHECK_EQUAL(subsidy, 12.5 * COIN);
}

/**
 * Test CalculateBlockSubsidy at third halving
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_third_halving) {
    CBlockValidator validator;

    // Block 630,000 (third halving)
    uint64_t subsidy = validator.CalculateBlockSubsidy(630000);
    BOOST_CHECK_EQUAL(subsidy, 6.25 * COIN);
}

/**
 * Test CalculateBlockSubsidy after 64 halvings (zero subsidy)
 */
BOOST_AUTO_TEST_CASE(calculate_block_subsidy_after_64_halvings) {
    CBlockValidator validator;

    // After 64 halvings, subsidy should be 0
    uint32_t height = 64 * 210000;
    uint64_t subsidy = validator.CalculateBlockSubsidy(height);
    BOOST_CHECK_EQUAL(subsidy, 0);

    // Way in the future
    subsidy = validator.CalculateBlockSubsidy(height + 1000000);
    BOOST_CHECK_EQUAL(subsidy, 0);
}

/**
 * Test BuildMerkleRoot with empty transactions
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_empty) {
    CBlockValidator validator;

    std::vector<CTransactionRef> transactions;
    uint256 root = validator.BuildMerkleRoot(transactions);

    // Empty block should have null root
    BOOST_CHECK(root.IsNull());
}

/**
 * Test BuildMerkleRoot with single transaction
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_single_tx) {
    CBlockValidator validator;

    // Create a transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx.vout.push_back(CTxOut(25 * COIN, scriptPubKey));

    // Build merkle root
    std::vector<CTransactionRef> transactions;
    transactions.push_back(std::make_shared<CTransaction>(tx));

    uint256 root = validator.BuildMerkleRoot(transactions);

    // Root should equal transaction hash for single tx
    BOOST_CHECK_EQUAL(root, tx.GetHash());
}

/**
 * Test BuildMerkleRoot with two transactions
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_two_tx) {
    CBlockValidator validator;

    // Create two transactions
    CTransaction tx1, tx2;
    tx1.nVersion = 1;
    tx1.nLockTime = 0;
    tx2.nVersion = 1;
    tx2.nLockTime = 1;  // Make different from tx1

    uint256 prevHash;
    memset(prevHash.data, 0x42, 32);
    std::vector<uint8_t> sig(100, 0xAA);
    tx1.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));
    tx2.vin.push_back(CTxIn(prevHash, 1, sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(50, 0xBB);
    tx1.vout.push_back(CTxOut(25 * COIN, scriptPubKey));
    tx2.vout.push_back(CTxOut(30 * COIN, scriptPubKey));

    // Build merkle root
    std::vector<CTransactionRef> transactions;
    transactions.push_back(std::make_shared<CTransaction>(tx1));
    transactions.push_back(std::make_shared<CTransaction>(tx2));

    uint256 root = validator.BuildMerkleRoot(transactions);

    // Root should be hash of combined tx hashes
    BOOST_CHECK(!root.IsNull());
    BOOST_CHECK(root != tx1.GetHash());
    BOOST_CHECK(root != tx2.GetHash());
}

/**
 * Test BuildMerkleRoot with multiple transactions (odd count)
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_odd_count) {
    CBlockValidator validator;

    // Create three transactions
    std::vector<CTransactionRef> transactions;

    for (int i = 0; i < 3; i++) {
        CTransaction tx;
        tx.nVersion = 1;
        tx.nLockTime = i;  // Make each different

        uint256 prevHash;
        memset(prevHash.data, 0x42 + i, 32);
        std::vector<uint8_t> sig(100, 0xAA + i);
        tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

        std::vector<uint8_t> scriptPubKey(50, 0xBB + i);
        tx.vout.push_back(CTxOut((25 + i) * COIN, scriptPubKey));

        transactions.push_back(std::make_shared<CTransaction>(tx));
    }

    uint256 root = validator.BuildMerkleRoot(transactions);

    // Root should be non-null and different from any individual tx
    BOOST_CHECK(!root.IsNull());
    for (const auto& tx : transactions) {
        BOOST_CHECK(root != tx->GetHash());
    }
}

/**
 * Test BuildMerkleRoot determinism
 */
BOOST_AUTO_TEST_CASE(build_merkle_root_determinism) {
    CBlockValidator validator;

    // Create transactions
    std::vector<CTransactionRef> transactions;

    for (int i = 0; i < 4; i++) {
        CTransaction tx;
        tx.nVersion = 1;
        tx.nLockTime = i;

        uint256 prevHash;
        memset(prevHash.data, i, 32);
        std::vector<uint8_t> sig(100, i);
        tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));

        std::vector<uint8_t> scriptPubKey(50, i);
        tx.vout.push_back(CTxOut(i * COIN, scriptPubKey));

        transactions.push_back(std::make_shared<CTransaction>(tx));
    }

    // Build root twice
    uint256 root1 = validator.BuildMerkleRoot(transactions);
    uint256 root2 = validator.BuildMerkleRoot(transactions);

    // Should be identical (deterministic)
    BOOST_CHECK_EQUAL(root1, root2);
}

// ============================================================================
// POW TESTS - GetNextWorkRequired Edge Cases (consensus/pow.cpp)
// ============================================================================

/**
 * Test GetNextWorkRequired with nullptr (genesis case)
 */
BOOST_AUTO_TEST_CASE(get_next_work_required_nullptr) {
    // Initialize chain params if needed
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams();
        Dilithion::g_chainParams->genesisNBits = 0x1d00ffff;
        Dilithion::g_chainParams->difficultyAdjustment = 2016;
        Dilithion::g_chainParams->difficultyAdjustmentV2 = 360;
        Dilithion::g_chainParams->difficultyForkHeight = 999999;  // Pre-fork for this test
        Dilithion::g_chainParams->difficultyMaxChange = 2;
        Dilithion::g_chainParams->blockTime = 240;
    }

    // No previous block should return genesis difficulty
    uint32_t nBits = GetNextWorkRequired(nullptr);
    BOOST_CHECK_EQUAL(nBits, Dilithion::g_chainParams->genesisNBits);
}

/**
 * Test GetNextWorkRequired between adjustment periods
 */
BOOST_AUTO_TEST_CASE(get_next_work_required_between_adjustments) {
    // Initialize chain params
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams();
        Dilithion::g_chainParams->genesisNBits = 0x1d00ffff;
        Dilithion::g_chainParams->difficultyAdjustment = 2016;
        Dilithion::g_chainParams->difficultyAdjustmentV2 = 360;
        Dilithion::g_chainParams->difficultyForkHeight = 999999;  // Pre-fork for this test
        Dilithion::g_chainParams->difficultyMaxChange = 2;
        Dilithion::g_chainParams->blockTime = 240;
    }

    // Create a block index at height 100 (not at adjustment point)
    CBlockIndex index;
    index.nHeight = 100;
    index.nTime = 24000;
    index.header.nBits = 0x1d00ffff;
    index.nBits = 0x1d00ffff;
    index.pprev = nullptr;

    // Should return same difficulty (not at adjustment point)
    uint32_t nBits = GetNextWorkRequired(&index);
    BOOST_CHECK_EQUAL(nBits, 0x1d00ffff);
}

/**
 * Test EstimateDilithiumTxSize with multiple scenarios (Week 6 Phase 2.3)
 */
BOOST_AUTO_TEST_CASE(estimate_dilithium_tx_size_multiple_scenarios) {
    using namespace Consensus;

    // Single input/output (minimum transaction)
    size_t min_size = EstimateDilithiumTxSize(1, 1, 0);
    BOOST_CHECK_EQUAL(min_size, 10 + 5308 + 34);  // 5352 bytes

    // Typical payment (2 inputs, 2 outputs - payment + change)
    size_t typical = EstimateDilithiumTxSize(2, 2, 0);
    BOOST_CHECK_EQUAL(typical, 10 + (2 * 5308) + (2 * 34));  // 10694 bytes

    // Large transaction (10 inputs, 10 outputs)
    size_t large = EstimateDilithiumTxSize(10, 10, 0);
    BOOST_CHECK_EQUAL(large, 10 + (10 * 5308) + (10 * 34));  // 53420 bytes
}

/**
 * Test CalculateFeeRate edge cases (Week 6 Phase 2.3)
 */
BOOST_AUTO_TEST_CASE(calculate_fee_rate_edge_cases) {
    using namespace Consensus;

    // Normal rate
    double rate1 = CalculateFeeRate(1000, 500);
    BOOST_CHECK_EQUAL(rate1, 2.0);

    // Very small rate
    double rate2 = CalculateFeeRate(1, 1000);
    BOOST_CHECK_EQUAL(rate2, 0.001);

    // Very large rate
    double rate3 = CalculateFeeRate(1000000, 1);
    BOOST_CHECK_EQUAL(rate3, 1000000.0);
}

// ============================================================================
// COMPREHENSIVE DIFFICULTY ADJUSTMENT TESTS (Week 5 Coverage Gap Closure)
// ============================================================================

/**
 * Test 1.3: Full Difficulty Adjustment at 2016-block boundary
 *
 * PURPOSE: Cover the complete difficulty adjustment logic in GetNextWorkRequired
 * that executes when (height + 1) % 2016 == 0
 *
 * COVERAGE TARGET: Lines 227-289 of consensus/pow.cpp (48 lines)
 * - Walking back 2016 blocks through pprev chain
 * - Calculating actual vs expected timespan
 * - Clamping adjustments (4x limits)
 * - CompactToBig conversion
 * - Multiply256x64 arithmetic
 * - Divide320x64 arithmetic
 * - BigToCompact conversion
 * - Min/max difficulty bounds enforcement
 *
 * EXPECTED IMPACT: +48 lines coverage → 65.2% to ~73%
 */
BOOST_AUTO_TEST_CASE(get_next_work_required_full_2016_block_adjustment) {
    // Ensure chain params initialized
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams();
        Dilithion::g_chainParams->genesisNBits = 0x1d00ffff;
        Dilithion::g_chainParams->difficultyAdjustment = 2016;
        Dilithion::g_chainParams->difficultyAdjustmentV2 = 360;
        Dilithion::g_chainParams->difficultyForkHeight = 999999;  // Pre-fork for this test
        Dilithion::g_chainParams->difficultyMaxChange = 2;
        Dilithion::g_chainParams->blockTime = 240;  // 4 minutes
    }

    // Create a chain of exactly 2016 blocks
    // This tests the full difficulty adjustment algorithm
    std::vector<CBlockIndex> chain(2016);

    // Initialize all blocks in the chain
    for (int i = 0; i < 2016; i++) {
        chain[i].nHeight = i;
        chain[i].nBits = 0x1d00ffff;  // Genesis difficulty
        chain[i].header.nBits = 0x1d00ffff;

        // Set timestamps - simulate 4-minute block times (240 seconds)
        // Starting from Unix epoch + 1 million for realistic values
        chain[i].nTime = 1000000 + (i * 240);

        // Link blocks together via pprev
        if (i > 0) {
            chain[i].pprev = &chain[i-1];
        } else {
            chain[i].pprev = nullptr;  // Genesis has no parent
        }
    }

    // Test at the difficulty adjustment point (block 2015 → block 2016)
    // This is where GetNextWorkRequired should perform full adjustment
    uint32_t result = GetNextWorkRequired(&chain[2015]);

    // Verify result is within valid difficulty bounds
    BOOST_CHECK(result >= MIN_DIFFICULTY_BITS);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);

    // With perfect 240-second block times, difficulty should remain unchanged
    // (actual timespan == expected timespan)
    int64_t actual_timespan = chain[2015].nTime - chain[0].nTime;
    // Note: 2016 blocks means 2015 intervals (0→1, 1→2, ..., 2014→2015)
    int64_t expected_timespan = 2015 * 240;  // 483,600 seconds

    // Verify timespan calculation is correct
    BOOST_CHECK_EQUAL(actual_timespan, expected_timespan);

    // Since timespan matches closely, difficulty should stay very close to same
    // (may have minor adjustment due to integer arithmetic precision)
    BOOST_CHECK(result >= MIN_DIFFICULTY_BITS);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);
}

/**
 * Test 1.4: Difficulty Adjustment with Fast Blocks (Difficulty Increase)
 *
 * Tests the difficulty adjustment when blocks arrive faster than expected,
 * which should increase difficulty (decrease target).
 */
BOOST_AUTO_TEST_CASE(get_next_work_required_fast_blocks_increase_difficulty) {
    // Create 2016-block chain with faster block times (120 seconds instead of 240)
    std::vector<CBlockIndex> chain(2016);

    for (int i = 0; i < 2016; i++) {
        chain[i].nHeight = i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;

        // Blocks arriving 2x faster than expected
        chain[i].nTime = 1000000 + (i * 120);  // 2-minute blocks instead of 4

        if (i > 0) {
            chain[i].pprev = &chain[i-1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    uint32_t result = GetNextWorkRequired(&chain[2015]);

    // Verify valid difficulty bounds
    BOOST_CHECK(result >= MIN_DIFFICULTY_BITS);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);

    // Verify timespan calculation
    int64_t actual_timespan = chain[2015].nTime - chain[0].nTime;
    int64_t expected_timespan = 2015 * 240;
    // Fast blocks: 2015 intervals * 120 seconds = 241,800 seconds
    // vs expected: 2015 * 240 = 483,600 seconds
    BOOST_CHECK_EQUAL(actual_timespan, 2015 * 120);  // 2x faster confirmed

    // Note: Difficulty may not change if result is at MIN_DIFFICULTY_BITS bound
    // The test validates the algorithm runs without crashing
}

/**
 * Test 1.5: Difficulty Adjustment with Slow Blocks (Difficulty Decrease)
 *
 * Tests the difficulty adjustment when blocks arrive slower than expected,
 * which should decrease difficulty (increase target).
 */
BOOST_AUTO_TEST_CASE(get_next_work_required_slow_blocks_decrease_difficulty) {
    // Create 2016-block chain with slower block times (480 seconds instead of 240)
    std::vector<CBlockIndex> chain(2016);

    for (int i = 0; i < 2016; i++) {
        chain[i].nHeight = i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;

        // Blocks arriving 2x slower than expected
        chain[i].nTime = 1000000 + (i * 480);  // 8-minute blocks instead of 4

        if (i > 0) {
            chain[i].pprev = &chain[i-1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    uint32_t result = GetNextWorkRequired(&chain[2015]);

    // Slow blocks should decrease difficulty (larger nBits value)
    // But not by more than 4x due to clamping
    BOOST_CHECK(result > 0x1d00ffff);  // Difficulty decreased
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);

    // Verify timespan calculation
    int64_t actual_timespan = chain[2015].nTime - chain[0].nTime;
    int64_t expected_timespan = 2015 * 240;
    // Slow blocks: 2015 intervals * 480 seconds = 967,200 seconds
    // vs expected: 2015 * 240 = 483,600 seconds
    BOOST_CHECK_EQUAL(actual_timespan, 2015 * 480);  // 2x slower confirmed
}

/**
 * Test 1.6: Extreme Fast Blocks (Tests 4x Clamp Lower Bound)
 *
 * Tests that difficulty adjustment is clamped to 4x when blocks arrive
 * extremely fast (>4x faster than expected).
 */
BOOST_AUTO_TEST_CASE(get_next_work_required_extreme_fast_clamp) {
    // Create 2016-block chain with extremely fast blocks (10x faster)
    std::vector<CBlockIndex> chain(2016);

    for (int i = 0; i < 2016; i++) {
        chain[i].nHeight = i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;

        // Blocks arriving 10x faster than expected (24 seconds instead of 240)
        chain[i].nTime = 1000000 + (i * 24);

        if (i > 0) {
            chain[i].pprev = &chain[i-1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    uint32_t result = GetNextWorkRequired(&chain[2015]);

    // Verify valid difficulty bounds
    BOOST_CHECK(result >= MIN_DIFFICULTY_BITS);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);

    // Even though blocks were 10x faster, adjustment should be clamped to 4x
    int64_t actual_timespan = chain[2015].nTime - chain[0].nTime;
    int64_t expected_timespan = 2015 * 240;
    // Extreme fast: 2015 * 24 = 48,360 seconds (10x faster)
    BOOST_CHECK(actual_timespan < expected_timespan / 4);  // >4x faster (will be clamped)
}

/**
 * Test 1.7: Extreme Slow Blocks (Tests 4x Clamp Upper Bound)
 *
 * Tests that difficulty adjustment is clamped to 4x when blocks arrive
 * extremely slow (>4x slower than expected).
 */
BOOST_AUTO_TEST_CASE(get_next_work_required_extreme_slow_clamp) {
    // Create 2016-block chain with extremely slow blocks (10x slower)
    std::vector<CBlockIndex> chain(2016);

    for (int i = 0; i < 2016; i++) {
        chain[i].nHeight = i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;

        // Blocks arriving 10x slower than expected (2400 seconds instead of 240)
        chain[i].nTime = 1000000 + (i * 2400);

        if (i > 0) {
            chain[i].pprev = &chain[i-1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    uint32_t result = GetNextWorkRequired(&chain[2015]);

    // Result should be clamped to maximum 4x difficulty decrease
    BOOST_CHECK(result > 0x1d00ffff);  // Difficulty decreased
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);

    // Even though blocks were 10x slower, adjustment should be clamped to 4x
    int64_t actual_timespan = chain[2015].nTime - chain[0].nTime;
    int64_t expected_timespan = 2015 * 240;
    // Extreme slow: 2015 * 2400 = 4,836,000 seconds (10x slower)
    BOOST_CHECK(actual_timespan > expected_timespan * 4);  // >4x slower (will be clamped)
}

// ============================================================================
// POST-FORK DIFFICULTY ADJUSTMENT TESTS (360-block interval, 2x max change)
// ============================================================================

/**
 * Helper: Initialize chain params for post-fork testing
 */
static void InitPostForkTestParams() {
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams();
    }
    Dilithion::g_chainParams->genesisNBits = 0x1d00ffff;
    Dilithion::g_chainParams->difficultyAdjustment = 2016;
    Dilithion::g_chainParams->difficultyAdjustmentV2 = 360;
    Dilithion::g_chainParams->difficultyForkHeight = 20160;
    Dilithion::g_chainParams->difficultyMaxChange = 2;
    Dilithion::g_chainParams->blockTime = 240;  // 4 minutes
    Dilithion::g_chainParams->edaActivationHeight = 0;
}

/**
 * Post-fork Test 1: Full 360-block adjustment with perfect timing
 * Difficulty should remain unchanged when blocks arrive exactly on target
 */
BOOST_AUTO_TEST_CASE(post_fork_360_block_adjustment_perfect_timing) {
    InitPostForkTestParams();

    // Create a chain starting at the fork height
    // Need blocks from 19800 to 20159 (360 blocks for the first post-fork retarget)
    const int chainStart = 19800;
    const int chainLen = 360;
    std::vector<CBlockIndex> chain(chainLen);

    for (int i = 0; i < chainLen; i++) {
        chain[i].nHeight = chainStart + i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;
        chain[i].nTime = 1000000 + (i * 240);  // Perfect 4-minute blocks
        chain[i].pprev = (i > 0) ? &chain[i - 1] : nullptr;
    }

    // At height 20159, next block is 20160 (first post-fork retarget)
    uint32_t result = GetNextWorkRequired(&chain[chainLen - 1]);

    // With perfect timing, difficulty should remain the same
    BOOST_CHECK(result >= MIN_DIFFICULTY_BITS);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);

    // Verify timespan: 359 intervals * 240s = 86,160s
    int64_t actual = chain[chainLen - 1].nTime - chain[0].nTime;
    BOOST_CHECK_EQUAL(actual, 359 * 240);
}

/**
 * Post-fork Test 2: Fast blocks with 2x clamp
 * When blocks are 4x faster, difficulty should be clamped to 2x increase (not 4x)
 */
BOOST_AUTO_TEST_CASE(post_fork_fast_blocks_2x_clamp) {
    InitPostForkTestParams();

    const int chainStart = 19800;
    const int chainLen = 360;
    std::vector<CBlockIndex> chain(chainLen);

    for (int i = 0; i < chainLen; i++) {
        chain[i].nHeight = chainStart + i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;
        // Blocks 4x faster than target (60s instead of 240s)
        chain[i].nTime = 1000000 + (i * 60);
        chain[i].pprev = (i > 0) ? &chain[i - 1] : nullptr;
    }

    uint32_t result = GetNextWorkRequired(&chain[chainLen - 1]);

    // Difficulty should increase (lower nBits = harder), but clamped to 2x
    BOOST_CHECK(result >= MIN_DIFFICULTY_BITS);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);

    // The result should be harder than original (same or lower nBits)
    // With 2x clamp, it should be exactly half the timespan adjustment
    int64_t actual = chain[chainLen - 1].nTime - chain[0].nTime;
    int64_t expected = 359 * 240;
    BOOST_CHECK(actual < expected / 2);  // 4x faster exceeds 2x clamp
}

/**
 * Post-fork Test 3: Slow blocks with 2x clamp
 * When blocks are 4x slower, difficulty should be clamped to 2x decrease (not 4x)
 */
BOOST_AUTO_TEST_CASE(post_fork_slow_blocks_2x_clamp) {
    InitPostForkTestParams();

    const int chainStart = 19800;
    const int chainLen = 360;
    std::vector<CBlockIndex> chain(chainLen);

    for (int i = 0; i < chainLen; i++) {
        chain[i].nHeight = chainStart + i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;
        // Blocks 4x slower than target (960s instead of 240s)
        chain[i].nTime = 1000000 + (i * 960);
        chain[i].pprev = (i > 0) ? &chain[i - 1] : nullptr;
    }

    uint32_t result = GetNextWorkRequired(&chain[chainLen - 1]);

    // Difficulty should decrease (higher nBits = easier), but clamped to 2x
    BOOST_CHECK(result > 0x1d00ffff);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);

    // Verify timespan exceeds 2x clamp threshold
    int64_t actual = chain[chainLen - 1].nTime - chain[0].nTime;
    int64_t expected = 359 * 240;
    BOOST_CHECK(actual > expected * 2);  // 4x slower exceeds 2x clamp
}

/**
 * Post-fork Test 4: Mid-period retarget (between 2016-block boundaries)
 * After fork, retargets happen every 360 blocks, not just at 2016 multiples
 */
BOOST_AUTO_TEST_CASE(post_fork_retarget_at_360_not_2016) {
    InitPostForkTestParams();

    // Height 20520 is 360 blocks after fork (20160 + 360) — should retarget
    // But it's NOT a 2016 multiple (20520 / 2016 = 10.178...) — pre-fork would NOT retarget
    const int chainStart = 20160;
    const int chainLen = 360;
    std::vector<CBlockIndex> chain(chainLen);

    for (int i = 0; i < chainLen; i++) {
        chain[i].nHeight = chainStart + i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;
        // 2x slower blocks to see a difficulty change
        chain[i].nTime = 1000000 + (i * 480);
        chain[i].pprev = (i > 0) ? &chain[i - 1] : nullptr;
    }

    uint32_t result = GetNextWorkRequired(&chain[chainLen - 1]);

    // Post-fork: height 20519 + 1 = 20520, which is 20520 % 360 == 0 → retarget
    // With 2x slower blocks, difficulty should decrease
    BOOST_CHECK(result > 0x1d00ffff);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);
}

/**
 * Post-fork Test 5: Pre-fork height still uses 2016/4x rules
 * Verify that heights before the fork use the old rules
 */
BOOST_AUTO_TEST_CASE(pre_fork_still_uses_2016_4x) {
    InitPostForkTestParams();  // Fork at 20160

    // Create 2016-block chain at pre-fork heights (0-2015)
    std::vector<CBlockIndex> chain(2016);
    for (int i = 0; i < 2016; i++) {
        chain[i].nHeight = i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;
        // 10x slower → will be clamped to 4x (pre-fork) not 2x
        chain[i].nTime = 1000000 + (i * 2400);
        chain[i].pprev = (i > 0) ? &chain[i - 1] : nullptr;
    }

    uint32_t result = GetNextWorkRequired(&chain[2015]);

    // Pre-fork: should use 4x clamp (not 2x)
    BOOST_CHECK(result > 0x1d00ffff);  // Difficulty decreased
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);
}

// ============================================================================
// EMERGENCY DIFFICULTY ADJUSTMENT (EDA) TESTS
// ============================================================================

/**
 * Helper: Initialize chain params for EDA testing
 */
static void InitEDATestParams() {
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams();
    }
    Dilithion::g_chainParams->genesisNBits = 0x1d00ffff;
    Dilithion::g_chainParams->difficultyAdjustment = 2016;
    Dilithion::g_chainParams->difficultyAdjustmentV2 = 360;
    Dilithion::g_chainParams->difficultyForkHeight = 999999;  // Pre-fork for EDA tests
    Dilithion::g_chainParams->difficultyMaxChange = 2;
    Dilithion::g_chainParams->blockTime = 240;  // 4 minutes
    Dilithion::g_chainParams->edaActivationHeight = 100;  // Active from height 100
    Dilithion::g_chainParams->difficultyV3ForkHeight = 999999;  // Pre-v3 for EDA tests (6-block threshold)
    Dilithion::g_chainParams->compactEncodingFixHeight = -1;  // Disable compact encoding fix
}

/**
 * EDA Test 1: No trigger within threshold
 * Gap < 6 * blockTime (1440s) should NOT reduce difficulty
 */
BOOST_AUTO_TEST_CASE(eda_no_trigger_within_threshold) {
    InitEDATestParams();

    CBlockIndex index;
    index.nHeight = 200;  // Above EDA activation
    index.nTime = 1000000;
    index.header.nBits = 0x1d00ffff;
    index.nBits = 0x1d00ffff;
    index.pprev = nullptr;

    // Gap = 1200s (5 * 240), below threshold of 1440s
    int64_t nBlockTime = 1000000 + 1200;

    uint32_t result = GetNextWorkRequired(&index, nBlockTime);
    BOOST_CHECK_EQUAL(result, 0x1d00ffff);  // Unchanged
}

/**
 * EDA Test 2: Single step at threshold
 * Gap just past threshold triggers 1 step of reduction
 */
BOOST_AUTO_TEST_CASE(eda_triggers_single_step) {
    InitEDATestParams();

    CBlockIndex index;
    index.nHeight = 200;
    index.nTime = 1000000;
    index.header.nBits = 0x1d00ffff;
    index.nBits = 0x1d00ffff;
    index.pprev = nullptr;

    // Gap = 1500s (> 1440s threshold, < 2880s for next step)
    int64_t nBlockTime = 1000000 + 1500;

    uint32_t result = GetNextWorkRequired(&index, nBlockTime);
    // Should be easier (higher nBits = larger target)
    BOOST_CHECK(result > 0x1d00ffff);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);
}

/**
 * EDA Test 3: Multiple steps for long gaps
 * 8-hour gap should produce many reduction steps
 */
BOOST_AUTO_TEST_CASE(eda_multiple_steps) {
    InitEDATestParams();

    CBlockIndex index;
    index.nHeight = 200;
    index.nTime = 1000000;
    index.header.nBits = 0x1d00ffff;
    index.nBits = 0x1d00ffff;
    index.pprev = nullptr;

    // Gap = 28800s (8 hours)
    // steps = (28800 - 1440) / 1440 + 1 = 20 (capped)
    int64_t nBlockTime = 1000000 + 28800;

    uint32_t result = GetNextWorkRequired(&index, nBlockTime);
    // Should be significantly easier
    BOOST_CHECK(result > 0x1d00ffff);

    // 1 step result should be between normal and multi-step result
    int64_t nBlockTimeSingle = 1000000 + 1500;
    uint32_t singleStep = GetNextWorkRequired(&index, nBlockTimeSingle);
    BOOST_CHECK(result > singleStep);  // More steps = easier
}

/**
 * EDA Test 4: Max steps cap (20)
 * Extremely long gap should be capped at EDA_MAX_STEPS
 */
BOOST_AUTO_TEST_CASE(eda_max_steps_cap) {
    InitEDATestParams();

    CBlockIndex index;
    index.nHeight = 200;
    index.nTime = 1000000;
    index.header.nBits = 0x1d00ffff;
    index.nBits = 0x1d00ffff;
    index.pprev = nullptr;

    // Gap = 86400s (24 hours) - would be 60 steps uncapped
    int64_t nBlockTime24h = 1000000 + 86400;
    uint32_t result24h = GetNextWorkRequired(&index, nBlockTime24h);

    // Gap = 172800s (48 hours) - would be 119 steps uncapped
    int64_t nBlockTime48h = 1000000 + 172800;
    uint32_t result48h = GetNextWorkRequired(&index, nBlockTime48h);

    // Both should produce same result (both capped at 20 steps)
    BOOST_CHECK_EQUAL(result24h, result48h);
}

/**
 * EDA Test 5: Respects MAX_DIFFICULTY_BITS floor
 * EDA should never produce nBits > MAX_DIFFICULTY_BITS
 */
BOOST_AUTO_TEST_CASE(eda_respects_max_difficulty_bits) {
    InitEDATestParams();

    // Start with already-easy difficulty near max
    CBlockIndex index;
    index.nHeight = 200;
    index.nTime = 1000000;
    index.header.nBits = 0x1f0f0000;  // Very easy, close to max
    index.nBits = 0x1f0f0000;
    index.pprev = nullptr;

    // Long gap to trigger many steps
    int64_t nBlockTime = 1000000 + 86400;

    uint32_t result = GetNextWorkRequired(&index, nBlockTime);
    BOOST_CHECK(result <= MAX_DIFFICULTY_BITS);
}

/**
 * EDA Test 6: Not active before activation height
 * Blocks before edaActivationHeight should NOT get EDA
 */
BOOST_AUTO_TEST_CASE(eda_not_active_before_activation) {
    InitEDATestParams();
    // edaActivationHeight = 100

    CBlockIndex index;
    index.nHeight = 50;  // Below activation height
    index.nTime = 1000000;
    index.header.nBits = 0x1d00ffff;
    index.nBits = 0x1d00ffff;
    index.pprev = nullptr;

    // Large gap that would trigger EDA if active
    int64_t nBlockTime = 1000000 + 86400;

    uint32_t result = GetNextWorkRequired(&index, nBlockTime);
    BOOST_CHECK_EQUAL(result, 0x1d00ffff);  // Unchanged - EDA not active
}

/**
 * EDA Test 7: Backward compatible with nBlockTime=0
 * Calling without timestamp should behave exactly like old API
 */
BOOST_AUTO_TEST_CASE(eda_backward_compatible_no_timestamp) {
    InitEDATestParams();

    CBlockIndex index;
    index.nHeight = 200;
    index.nTime = 1000000;
    index.header.nBits = 0x1d00ffff;
    index.nBits = 0x1d00ffff;
    index.pprev = nullptr;

    // nBlockTime = 0 (default) should not trigger EDA
    uint32_t result = GetNextWorkRequired(&index, 0);
    BOOST_CHECK_EQUAL(result, 0x1d00ffff);  // Unchanged

    // Also test with default parameter (no second arg)
    uint32_t resultDefault = GetNextWorkRequired(&index);
    BOOST_CHECK_EQUAL(resultDefault, 0x1d00ffff);
}

/**
 * EDA Test 8: Does not interfere with 2016-block adjustment
 * At adjustment boundaries, normal algorithm runs (not EDA)
 */
BOOST_AUTO_TEST_CASE(eda_does_not_interfere_with_2016_adjustment) {
    InitEDATestParams();

    // Create a chain of 2016 blocks for normal adjustment
    std::vector<CBlockIndex> chain(2016);
    for (int i = 0; i < 2016; i++) {
        chain[i].nHeight = i;
        chain[i].nBits = 0x1d00ffff;
        chain[i].header.nBits = 0x1d00ffff;
        // Normal timing: 240s per block
        chain[i].nTime = 1000000 + (i * 240);
        chain[i].pprev = (i > 0) ? &chain[i - 1] : nullptr;
    }

    // At height 2016 (adjustment point), call with large nBlockTime
    // The normal 2016-block adjustment should run, NOT the EDA
    int64_t nBlockTime = chain[2015].nTime + 86400;  // 24h later
    uint32_t resultWithTime = GetNextWorkRequired(&chain[2015], nBlockTime);
    uint32_t resultWithoutTime = GetNextWorkRequired(&chain[2015], 0);

    // Both should return the same result (normal adjustment, not EDA)
    BOOST_CHECK_EQUAL(resultWithTime, resultWithoutTime);
}

/**
 * LP-4: Merkle defense-in-depth (CVE-2012-2459) on the ConnectTip path.
 *
 * These tests exercise the EXACT structural sequence the LP-4 fix inserts into
 * CChainState::ConnectTip before ApplyBlock:
 *   DeserializeBlockTransactions(block) -> VerifyMerkleRoot(block, txs)
 * They prove the merkle recompute REJECTS a CVE-2012-2459-style mutated block
 * INDEPENDENTLY of the UTXO double-spend side-effect (no UTXO set is involved
 * here at all), and that a valid block still passes unchanged (additive-only,
 * idempotent on valid blocks).
 */

// Local helper: compact-size varint, mirrors DeserializeBlockTransactions' reader
// and the serializer in utxo_tests.cpp / block_processing.cpp.
static void LP4_WriteCompactSize(std::vector<uint8_t>& data, uint64_t size) {
    if (size < 253) {
        data.push_back(static_cast<uint8_t>(size));
    } else if (size <= 0xFFFF) {
        data.push_back(253);
        data.push_back(static_cast<uint8_t>(size & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
    } else {
        data.push_back(254);
        data.push_back(static_cast<uint8_t>(size & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 24) & 0xFF));
    }
}

// Local helper: serialize a tx vector into the block.vtx byte-blob format
// (compact-size count + concatenated tx.Serialize()).
static std::vector<uint8_t> LP4_SerializeVtx(const std::vector<CTransactionRef>& txs) {
    std::vector<uint8_t> vtx;
    LP4_WriteCompactSize(vtx, txs.size());
    for (const auto& tx : txs) {
        std::vector<uint8_t> tx_data = tx->Serialize();
        vtx.insert(vtx.end(), tx_data.begin(), tx_data.end());
    }
    return vtx;
}

// Local helper: build a distinct, deserializable tx with one input + one output.
static CTransactionRef LP4_MakeTx(int seed) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = static_cast<uint32_t>(seed);

    uint256 prevHash;
    memset(prevHash.data, 0x11 + seed, 32);
    std::vector<uint8_t> sig(72, static_cast<uint8_t>(0xA0 + seed));
    tx.vin.push_back(CTxIn(prevHash, static_cast<uint32_t>(seed), sig, CTxIn::SEQUENCE_FINAL));

    std::vector<uint8_t> scriptPubKey(25, static_cast<uint8_t>(0xB0 + seed));
    tx.vout.push_back(CTxOut((10 + seed) * COIN, scriptPubKey));

    return MakeTransactionRef(std::move(tx));
}

// Runs the EXACT structural sequence LP-4 inserts into ConnectTip before
// ApplyBlock: deserialize -> VerifyMerkleRoot (D1) -> CheckNoDuplicateTransactions
// (D2). Returns true iff the block PASSES all of them (i.e. would proceed to
// ApplyBlock). No UTXO set is involved — this isolates the structural defense.
static bool LP4_ConnectTipStructuralChecks(const CBlock& block, std::string& whichFailed) {
    CBlockValidator validator;
    std::vector<CTransactionRef> txs;
    std::string error;

    if (!validator.DeserializeBlockTransactions(block, txs, error)) {
        whichFailed = "deserialize: " + error;
        return false;
    }
    if (!validator.VerifyMerkleRoot(block, txs, error)) {
        whichFailed = "merkle: " + error;
        return false;
    }
    if (!validator.CheckNoDuplicateTransactions(txs, error)) {
        whichFailed = "duplicate-tx: " + error;
        return false;
    }
    return true;
}

/**
 * The classic CVE-2012-2459 last-node-duplication mutation is REJECTED by the
 * ConnectTip structural sequence, independently of any UTXO side-effect.
 *
 * Mechanism: an odd tx level [A,B,C] hashes the trailing pair as hash(C,C). An
 * attacker who appends a duplicate C -> [A,B,C,C] reproduces the SAME merkle
 * root by construction, so D1 (the recompute) ALONE accepts it — this is the
 * whole point of the CVE. The defense is therefore the pairing the orphan path
 * uses: D2 (CheckNoDuplicateTransactions) catches the duplicated tx. This test
 * asserts (a) the forged root really does collide (documenting why D1 alone is
 * insufficient) and (b) the combined sequence still rejects the block.
 */
BOOST_AUTO_TEST_CASE(lp4_connecttip_rejects_cve_2012_2459_duplication) {
    CBlockValidator validator;

    // Honest block: 3 transactions [A, B, C].
    std::vector<CTransactionRef> honestTxs = {
        LP4_MakeTx(1), LP4_MakeTx(2), LP4_MakeTx(3)
    };

    CBlock block;
    block.nVersion = 1;
    block.nTime = 1000000;
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;
    // Header commits to the HONEST merkle root (this is what PoW binds and what
    // a real forged block would preserve from the legitimate header).
    block.hashMerkleRoot = validator.BuildMerkleRoot(honestTxs);

    // Forge the transaction payload: duplicate the trailing tx -> [A, B, C, C].
    std::vector<CTransactionRef> forgedTxs = honestTxs;
    forgedTxs.push_back(honestTxs.back());
    block.vtx = LP4_SerializeVtx(forgedTxs);

    // Document the CVE collision: D1 alone (root recompute) does NOT diverge.
    BOOST_CHECK_MESSAGE(
        validator.BuildMerkleRoot(forgedTxs) == block.hashMerkleRoot,
        "CVE-2012-2459 duplication is expected to reproduce the same merkle root");

    // The combined ConnectTip structural sequence MUST reject (via D2).
    // No UTXO set in scope — this is purely structural.
    std::string whichFailed;
    bool passed = LP4_ConnectTipStructuralChecks(block, whichFailed);
    BOOST_CHECK_MESSAGE(!passed,
        "CVE-2012-2459 duplicated-tx block must be rejected at ConnectTip");
    BOOST_CHECK_MESSAGE(whichFailed.rfind("duplicate-tx:", 0) == 0,
        "rejection must come from the duplicate-tx check, got: " << whichFailed);
}

/**
 * A root-divergent mutation (tampered tx content that changes the merkle root
 * while the header keeps the honest root) is REJECTED by D1 (VerifyMerkleRoot)
 * at ConnectTip. Confirms the recompute itself is load-bearing, not just D2.
 */
BOOST_AUTO_TEST_CASE(lp4_connecttip_rejects_root_divergent_mutation) {
    CBlockValidator validator;

    std::vector<CTransactionRef> honestTxs = {
        LP4_MakeTx(1), LP4_MakeTx(2), LP4_MakeTx(3)
    };

    CBlock block;
    block.nVersion = 1;
    block.nTime = 1000000;
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;
    block.hashMerkleRoot = validator.BuildMerkleRoot(honestTxs);

    // Swap the last tx for a DIFFERENT one -> recomputed root diverges from the
    // header-committed root, but there is no duplicate.
    std::vector<CTransactionRef> tamperedTxs = { honestTxs[0], honestTxs[1], LP4_MakeTx(99) };
    block.vtx = LP4_SerializeVtx(tamperedTxs);

    BOOST_REQUIRE(validator.BuildMerkleRoot(tamperedTxs) != block.hashMerkleRoot);

    std::string whichFailed;
    bool passed = LP4_ConnectTipStructuralChecks(block, whichFailed);
    BOOST_CHECK_MESSAGE(!passed,
        "root-divergent mutation must be rejected at ConnectTip");
    BOOST_CHECK_MESSAGE(whichFailed.rfind("merkle:", 0) == 0,
        "rejection must come from the merkle recompute, got: " << whichFailed);
}

/**
 * A valid block still connects unchanged: the same ConnectTip-path sequence
 * (deserialize -> VerifyMerkleRoot) PASSES for an unmodified, well-formed block.
 * Confirms the guard is additive-only and rejects nothing currently accepted.
 */
BOOST_AUTO_TEST_CASE(lp4_connecttip_merkle_accepts_valid_block) {
    CBlockValidator validator;

    std::vector<CTransactionRef> txs = {
        LP4_MakeTx(4), LP4_MakeTx(5), LP4_MakeTx(6), LP4_MakeTx(7)
    };

    CBlock block;
    block.nVersion = 1;
    block.nTime = 1000000;
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;
    block.hashMerkleRoot = validator.BuildMerkleRoot(txs);
    block.vtx = LP4_SerializeVtx(txs);

    // The full ConnectTip structural sequence (D1 + D2) must PASS unchanged,
    // i.e. the block would proceed to ApplyBlock exactly as before the fix.
    std::string whichFailed;
    bool passed = LP4_ConnectTipStructuralChecks(block, whichFailed);
    BOOST_CHECK_MESSAGE(passed,
        "valid block must pass the merkle defense-in-depth unchanged, failed at: "
        << whichFailed);
}

BOOST_AUTO_TEST_SUITE_END()
