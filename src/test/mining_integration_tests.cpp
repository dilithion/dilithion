// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Phase 5.4: Mining Integration Tests
 *
 * Comprehensive test suite for transaction-mining integration.
 * Tests CreateBlockTemplate, fee collection, block validation, etc.
 */

#include <miner/controller.h>
#include <consensus/validation.h>
#include <consensus/tx_validation.h>
#include <consensus/params.h>
#include <node/mempool.h>
#include <node/utxo_set.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <amount.h>
#include <dfmp/mik.h>  // DFMP v2.0: MIK data for coinbase

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <filesystem>  // MEM-MED-001 FIX: Replace system() with std::filesystem

// ANSI color codes
#define RESET   "\033[0m"
#define GREEN   "\033[32m"
#define RED     "\033[31m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"

// Test result tracking
int g_tests_passed = 0;
int g_tests_failed = 0;

// Helper macros
#define TEST(name) \
    void test_##name(); \
    void test_##name##_wrapper() { \
        std::cout << BLUE << "[TEST] " << #name << RESET << std::endl; \
        try { \
            test_##name(); \
            std::cout << GREEN << "  ✓ PASSED" << RESET << std::endl; \
            g_tests_passed++; \
        } catch (const std::exception& e) { \
            std::cout << RED << "  ✗ FAILED: " << e.what() << RESET << std::endl; \
            g_tests_failed++; \
        } catch (...) { \
            std::cout << RED << "  ✗ FAILED: Unknown exception" << RESET << std::endl; \
            g_tests_failed++; \
        } \
    } \
    void test_##name()

#define ASSERT(condition, message) \
    if (!(condition)) { \
        throw std::runtime_error(message); \
    }

#define ASSERT_EQ(a, b, message) \
    if ((a) != (b)) { \
        throw std::runtime_error(std::string(message) + " (expected " + std::to_string(b) + ", got " + std::to_string(a) + ")"); \
    }

// Helper function to create a dummy miner address
std::vector<uint8_t> CreateMinerAddress() {
    std::vector<uint8_t> addr(25);  // P2PKH address (1 + 20 + 4 bytes)
    addr[0] = 0x76;  // OP_DUP
    addr[1] = 0xa9;  // OP_HASH160
    addr[2] = 0x14;  // Push 20 bytes
    // 20 bytes of address hash (dummy data)
    for (int i = 0; i < 20; i++) {
        addr[3 + i] = static_cast<uint8_t>(i);
    }
    addr[23] = 0x88;  // OP_EQUALVERIFY
    addr[24] = 0xac;  // OP_CHECKSIG
    return addr;
}

// =======================================================================
// Test 1: Block Subsidy Calculation
// =======================================================================
TEST(block_subsidy_calculation) {
    CMiningController miner(1);

    // Test initial subsidy (50 DIL)
    uint64_t subsidy0 = miner.CalculateBlockSubsidy(0);
    ASSERT_EQ(subsidy0, 50 * COIN, "Initial subsidy should be 50 DIL");

    // Test after first halving (210,000 blocks)
    uint64_t subsidy1 = miner.CalculateBlockSubsidy(210000);
    ASSERT_EQ(subsidy1, 25 * COIN, "First halving should give 25 DIL");

    // Test after second halving (420,000 blocks)
    uint64_t subsidy2 = miner.CalculateBlockSubsidy(420000);
    ASSERT_EQ(subsidy2, 12.5 * COIN, "Second halving should give 12.5 DIL");

    // Test very far in future (subsidy should be 0)
    uint64_t subsidy64 = miner.CalculateBlockSubsidy(210000 * 64);
    ASSERT_EQ(subsidy64, 0, "Subsidy after 64 halvings should be 0");

    std::cout << "    Initial subsidy: " << subsidy0 / COIN << " DIL" << std::endl;
    std::cout << "    After 1st halving: " << subsidy1 / COIN << " DIL" << std::endl;
    std::cout << "    After 2nd halving: " << (subsidy2 / (double)COIN) << " DIL" << std::endl;
}

// =======================================================================
// Test 2: Coinbase Transaction Creation
// =======================================================================
TEST(coinbase_transaction_creation) {
    CMiningController miner(1);
    std::vector<uint8_t> minerAddr = CreateMinerAddress();
    CMIKCoinbaseData mikData;  // Empty MIK data for tests (DFMP v2.0)

    // Create coinbase for block 1 with no fees
    CTransactionRef coinbase1 = miner.CreateCoinbaseTransaction(1, 0, minerAddr, mikData);

    ASSERT(coinbase1 != nullptr, "Coinbase transaction should not be null");
    ASSERT(coinbase1->IsCoinBase(), "Transaction should be coinbase");
    ASSERT_EQ(coinbase1->vin.size(), 1, "Coinbase should have exactly 1 input");
    ASSERT(coinbase1->vin[0].prevout.IsNull(), "Coinbase input prevout should be null");

    // K3 FIX (stale test): this asserted a single output and the full 50 DIL on
    // vout[0]. Mainnet coinbases have carried three outputs — miner, Dev Fund,
    // Dev Reward — since cb07e238 (2026-01-15) added the 2% mining development
    // contribution. The assertion has been wrong for ~7 months; nothing caught it
    // because this suite had never been executed.
    ASSERT_EQ(coinbase1->vout.size(), 3, "Mainnet coinbase should have 3 outputs (miner + dev fund + dev reward)");

    // Miner takes 98% of subsidy; Dev Fund and Dev Reward take 1% each.
    const uint64_t subsidy = 50 * COIN;
    const uint64_t taxTotal = (subsidy * Consensus::MINING_TAX_PERCENT) / 100;
    const uint64_t expectedDevFund = (taxTotal * Consensus::DEV_FUND_SHARE) / 100;
    const uint64_t expectedDevReward = taxTotal - expectedDevFund;
    const uint64_t expectedMiner = subsidy - taxTotal;

    ASSERT_EQ(coinbase1->vout[0].nValue, expectedMiner, "Miner output should be 98% of subsidy");
    ASSERT_EQ(coinbase1->vout[1].nValue, expectedDevFund, "Dev Fund output should be 1% of subsidy");
    ASSERT_EQ(coinbase1->vout[2].nValue, expectedDevReward, "Dev Reward output should be 1% of subsidy");

    // Total across all outputs must still equal exactly the subsidy — the tax
    // redistributes the reward, it does not mint extra.
    uint64_t total1 = 0;
    for (const auto& o : coinbase1->vout) total1 += o.nValue;
    ASSERT_EQ(total1, subsidy, "Total coinbase value must equal the subsidy");

    // Create coinbase with fees — fees go entirely to the miner output.
    uint64_t fees = 0.5 * COIN;  // 0.5 DIL in fees
    CTransactionRef coinbase2 = miner.CreateCoinbaseTransaction(1, fees, minerAddr, mikData);

    ASSERT_EQ(coinbase2->vout[0].nValue, expectedMiner + fees, "Fees should be added to the miner output");
    uint64_t total2 = 0;
    for (const auto& o : coinbase2->vout) total2 += o.nValue;
    ASSERT_EQ(total2, subsidy + fees, "Total coinbase value must equal subsidy + fees");

    std::cout << "    Coinbase outputs: " << coinbase1->vout.size()
              << " (miner " << (coinbase1->vout[0].nValue / (double)COIN)
              << " DIL, dev fund " << (coinbase1->vout[1].nValue / (double)COIN)
              << " DIL, dev reward " << (coinbase1->vout[2].nValue / (double)COIN) << " DIL)" << std::endl;
    std::cout << "    Total (no fees): " << (total1 / (double)COIN) << " DIL" << std::endl;
    std::cout << "    Total (with 0.5 DIL fees): " << (total2 / (double)COIN) << " DIL" << std::endl;
}

// =======================================================================
// Test 3: Merkle Root Calculation
// =======================================================================
TEST(merkle_root_calculation) {
    CMiningController miner(1);
    std::vector<uint8_t> minerAddr = CreateMinerAddress();
    CMIKCoinbaseData mikData;  // Empty MIK data for tests (DFMP v2.0)

    // Create a few test transactions
    CTransactionRef tx1 = miner.CreateCoinbaseTransaction(1, 0, minerAddr, mikData);

    std::vector<CTransactionRef> txs;
    txs.push_back(tx1);

    // Build merkle root
    uint256 merkleRoot = miner.BuildMerkleRoot(txs);

    ASSERT(!merkleRoot.IsNull(), "Merkle root should not be null");

    // For single transaction, merkle root should equal transaction hash
    uint256 tx1Hash = tx1->GetHash();
    ASSERT(merkleRoot == tx1Hash, "Merkle root of single TX should equal TX hash");

    std::cout << "    Merkle root (1 TX): " << merkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
}

// =======================================================================
// Test 4: CreateBlockTemplate - Empty Mempool
// =======================================================================
TEST(block_template_empty_mempool) {
    CMiningController miner(1);
    CTxMemPool mempool;
    CUTXOSet utxoSet;

    // Initialize UTXO set
    std::string utxoPath = ".test-mining-utxo";
    // MEM-MED-001 FIX: Use std::filesystem instead of system()
    std::error_code ec;
    std::filesystem::remove_all(utxoPath, ec);
    ASSERT(utxoSet.Open(utxoPath, true), "Failed to open UTXO set");

    std::vector<uint8_t> minerAddr = CreateMinerAddress();
    uint256 hashPrevBlock;
    hashPrevBlock.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    CMIKCoinbaseData mikData;  // Empty MIK data for tests (DFMP v2.0)

    std::string error;
    auto templateOpt = miner.CreateBlockTemplate(
        mempool,
        utxoSet,
        hashPrevBlock,
        1,  // height
        0x1f00ffff,  // nBits
        minerAddr,
        mikData,
        error
    );

    ASSERT(templateOpt.has_value(), std::string("CreateBlockTemplate failed: ") + error);

    CBlockTemplate& blockTemplate = templateOpt.value();
    ASSERT_EQ(blockTemplate.nHeight, 1, "Block height incorrect");
    ASSERT(!blockTemplate.block.hashMerkleRoot.IsNull(), "Merkle root should not be null");
    ASSERT(!blockTemplate.block.vtx.empty(), "Block should have transaction data");

    std::cout << "    Block height: " << blockTemplate.nHeight << std::endl;
    std::cout << "    Merkle root: " << blockTemplate.block.hashMerkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
    std::cout << "    TX data size: " << blockTemplate.block.vtx.size() << " bytes" << std::endl;

    // Cleanup
    utxoSet.Close();
    // MEM-MED-001 FIX: Use std::filesystem instead of system()
    std::filesystem::remove_all(utxoPath, ec);
}

// =======================================================================
// Test 5: Block Validation - Coinbase Check
// =======================================================================
TEST(block_validation_coinbase) {
    // K3 FIX (mis-targeted test): this test previously called CheckCoinbase with
    // nHeight == 0. Height 0 is genesis, and CheckCoinbase returns true
    // unconditionally at that height (consensus/validation.cpp:255-257) because
    // genesis pre-funded addresses legitimately exceed the subsidy. The
    // "excessive value should be rejected" assertion could therefore never hold,
    // and the test proved nothing about the subsidy cap.
    //
    // It also hand-built a single-output coinbase, which has been invalid on
    // mainnet since cb07e238 (2026-01-15) introduced the 2% dev contribution —
    // mainnet coinbases must carry Dev Fund and Dev Reward outputs.
    //
    // Both are fixed by exercising a real height with a miner-built coinbase.
    CBlockValidator validator;

    const uint32_t kHeight = 1;
    const uint64_t kFees = 0;

    const uint64_t subsidy = 50 * COIN;
    const uint64_t taxTotal = (subsidy * Consensus::MINING_TAX_PERCENT) / 100;
    const uint64_t devFundAmount = (taxTotal * Consensus::DEV_FUND_SHARE) / 100;
    const uint64_t devRewardAmount = taxTotal - devFundAmount;
    const uint64_t minerAmount = subsidy - taxTotal;

    // Build a mainnet-shaped coinbase: miner + Dev Fund + Dev Reward.
    // (Built here rather than via CMiningController::CreateCoinbaseTransaction,
    // which is private with an explicit per-test friend list.)
    CTransaction coinbase;
    coinbase.nVersion = 1;
    coinbase.nLockTime = 0;

    CTxIn coinbaseIn;
    coinbaseIn.prevout.SetNull();
    coinbaseIn.scriptSig.push_back(0x01);
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>(kHeight));
    coinbaseIn.scriptSig.insert(coinbaseIn.scriptSig.end(), {'t', 'e', 's', 't'});
    coinbase.vin.push_back(coinbaseIn);

    auto p2pkh = [](const uint8_t* pubKeyHash) {
        std::vector<uint8_t> s{0x76, 0xa9, 0x14};
        s.insert(s.end(), pubKeyHash, pubKeyHash + 20);
        s.push_back(0x88);
        s.push_back(0xac);
        return s;
    };

    CTxOut minerOut;
    minerOut.nValue = minerAmount;
    minerOut.scriptPubKey = CreateMinerAddress();
    coinbase.vout.push_back(minerOut);

    CTxOut devFundOut;
    devFundOut.nValue = devFundAmount;
    devFundOut.scriptPubKey = p2pkh(Consensus::DEV_FUND_PUBKEY_HASH);
    coinbase.vout.push_back(devFundOut);

    CTxOut devRewardOut;
    devRewardOut.nValue = devRewardAmount;
    devRewardOut.scriptPubKey = p2pkh(Consensus::DEV_REWARD_PUBKEY_HASH);
    coinbase.vout.push_back(devRewardOut);

    std::string error;

    // A miner-built coinbase at the exact subsidy must be accepted.
    bool valid = validator.CheckCoinbase(coinbase, kHeight, kFees, error);
    ASSERT(valid, std::string("Valid coinbase rejected: ") + error);

    // Paying one extra satoshi over subsidy + fees must be rejected. One satoshi
    // (not 50 DIL) pins the boundary exactly: a check that is off by any amount,
    // or absent, fails this.
    coinbase.vout[0].nValue += 1;
    valid = validator.CheckCoinbase(coinbase, kHeight, kFees, error);
    ASSERT(!valid, "Coinbase exceeding subsidy by 1 satoshi should be rejected");
    ASSERT(error.find("exceeds subsidy") != std::string::npos,
           std::string("Rejected for the wrong reason: ") + error);

    // Grossly excessive value must also be rejected.
    coinbase.vout[0].nValue = 100 * COIN;
    valid = validator.CheckCoinbase(coinbase, kHeight, kFees, error);
    ASSERT(!valid, "Coinbase with excessive value should be rejected");

    // Genesis (height 0) is a deliberate exemption — pin it so the exemption
    // cannot be widened silently.
    valid = validator.CheckCoinbase(coinbase, 0, kFees, error);
    ASSERT(valid, "Height 0 is exempt from the subsidy cap by design");

    std::cout << "    Valid coinbase accepted at height 1" << std::endl;
    std::cout << "    Coinbase over subsidy by 1 satoshi rejected" << std::endl;
    std::cout << "    Excessive coinbase rejected" << std::endl;
    std::cout << "    Genesis exemption confirmed" << std::endl;
}

// =======================================================================
// Test 6: Block Validation - No Duplicates
// =======================================================================
TEST(block_validation_no_duplicates) {
    CBlockValidator validator;
    CMiningController miner(1);
    std::vector<uint8_t> minerAddr = CreateMinerAddress();
    CMIKCoinbaseData mikData;  // Empty MIK data for tests (DFMP v2.0)

    // Create two different transactions
    CTransactionRef tx1 = miner.CreateCoinbaseTransaction(1, 0, minerAddr, mikData);
    CTransactionRef tx2 = miner.CreateCoinbaseTransaction(2, 100000, minerAddr, mikData);

    std::vector<CTransactionRef> txs1;
    txs1.push_back(tx1);
    txs1.push_back(tx2);

    std::string error;
    bool valid = validator.CheckNoDuplicateTransactions(txs1, error);
    ASSERT(valid, "Should accept transactions with different IDs");

    // Try with duplicates
    std::vector<CTransactionRef> txs2;
    txs2.push_back(tx1);
    txs2.push_back(tx1);  // Duplicate!

    valid = validator.CheckNoDuplicateTransactions(txs2, error);
    ASSERT(!valid, "Should reject duplicate transactions");

    std::cout << "    Unique transactions accepted" << std::endl;
    std::cout << "    Duplicate transactions rejected" << std::endl;
}

// =======================================================================
// Test 7: Subsidy Consistency Check
// =======================================================================
TEST(subsidy_consistency) {
    // Verify that block subsidy calculation is consistent between
    // CMiningController and CBlockValidator

    CMiningController miner(1);

    for (uint32_t height : {0, 1, 100, 210000, 420000, 1000000}) {
        uint64_t minerSubsidy = miner.CalculateBlockSubsidy(height);
        uint64_t validatorSubsidy = CBlockValidator::CalculateBlockSubsidy(height);

        ASSERT_EQ(minerSubsidy, validatorSubsidy,
                  "Subsidy mismatch at height " + std::to_string(height));
    }

    std::cout << "    Subsidy calculations are consistent" << std::endl;
}

// =======================================================================
// Main Test Runner
// =======================================================================
int main() {
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << YELLOW << "Phase 5.4: Mining Integration Tests" << RESET << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << std::endl;

    // Run all tests
    test_block_subsidy_calculation_wrapper();
    test_coinbase_transaction_creation_wrapper();
    test_merkle_root_calculation_wrapper();
    test_block_template_empty_mempool_wrapper();
    test_block_validation_coinbase_wrapper();
    test_block_validation_no_duplicates_wrapper();
    test_subsidy_consistency_wrapper();

    // Print summary
    std::cout << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << YELLOW << "Test Summary" << RESET << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << GREEN << "Passed: " << g_tests_passed << RESET << std::endl;
    std::cout << RED << "Failed: " << g_tests_failed << RESET << std::endl;
    std::cout << YELLOW << "Total:  " << (g_tests_passed + g_tests_failed) << RESET << std::endl;
    std::cout << std::endl;

    if (g_tests_failed == 0) {
        std::cout << GREEN << "✓ ALL TESTS PASSED!" << RESET << std::endl;
        return 0;
    } else {
        std::cout << RED << "✗ SOME TESTS FAILED" << RESET << std::endl;
        return 1;
    }
}
