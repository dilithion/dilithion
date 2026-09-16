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
#include <consensus/params.h>  // Consensus::DEV_FUND_PUBKEY_HASH / DEV_REWARD_PUBKEY_HASH
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

// P2PKH scriptPubKey for a 20-byte pubkey hash (the exact byte shape
// CheckCoinbase's extractPubKeyHash accepts: 76 a9 14 <20> 88 ac).
static std::vector<uint8_t> P2PKHScript(const uint8_t* pubKeyHash20) {
    std::vector<uint8_t> script;
    script.reserve(25);
    script.push_back(0x76);
    script.push_back(0xa9);
    script.push_back(0x14);
    script.insert(script.end(), pubKeyHash20, pubKeyHash20 + 20);
    script.push_back(0x88);
    script.push_back(0xac);
    return script;
}

static CTxOut Out(uint64_t nValue, std::vector<uint8_t> scriptPubKey) {
    CTxOut out;
    out.nValue = nValue;
    out.scriptPubKey = std::move(scriptPubKey);
    return out;
}

// Hand-built coinbase: one null-prevout input carrying the height (4 LE bytes
// plus a tag, so scriptSig is inside CheckCoinbase's 2..20000-byte bound) and
// exactly the outputs given. Deliberately NOT built through
// CMiningController::CreateCoinbaseTransaction: the validator arms below must
// not inherit whatever layout the producer emits, or a producer drift would
// move the oracle with the subject.
static CTransaction BuildCoinbase(uint32_t nHeight, std::vector<CTxOut> outs) {
    CTransaction cb;
    cb.nVersion = 1;
    cb.nLockTime = 0;

    CTxIn in;
    in.prevout.SetNull();
    in.scriptSig.push_back(static_cast<uint8_t>(nHeight & 0xFF));
    in.scriptSig.push_back(static_cast<uint8_t>((nHeight >> 8) & 0xFF));
    in.scriptSig.push_back(static_cast<uint8_t>((nHeight >> 16) & 0xFF));
    in.scriptSig.push_back(static_cast<uint8_t>((nHeight >> 24) & 0xFF));
    in.scriptSig.insert(in.scriptSig.end(), {'t', 'e', 's', 't'});
    cb.vin.push_back(std::move(in));

    cb.vout = std::move(outs);
    return cb;
}

// Mainnet coinbase economics at height 1 with the default params. This binary
// never sets Dilithion::g_chainParams, so CalculateBlockSubsidy falls back to
// 50 DIL / 210000 (consensus/validation.cpp:19-23) and both the producer
// (miner/controller.cpp CreateCoinbaseTransaction) and the validator
// (CheckCoinbase) take the !IsTestnet() branch, i.e. MAINNET rules, which is
// the rule set that matters. The 2% mining development contribution
// (MINING_TAX_PERCENT=2, DEV_FUND_SHARE=50; consensus/params.h:49-52) splits
// 1 DIL into 0.5 DIL Dev Fund + 0.5 DIL Dev Reward; the miner keeps 49 DIL plus
// all fees. Written as literals, not derived from the constants, so the
// expectation cannot drift in step with the code under test.
static const uint64_t kSubsidyH1   = 50 * COIN;
static const uint64_t kDevFundH1   = COIN / 2;   // 1% of 50 DIL
static const uint64_t kDevRewardH1 = COIN / 2;   // 1% of 50 DIL
static const uint64_t kMinerH1     = 49 * COIN;  // 98% of 50 DIL

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

    // DFMP mining development contribution: under mainnet rules every coinbase
    // carries THREE outputs -- miner, Dev Fund, Dev Reward -- and CheckCoinbase
    // rejects fewer ("Coinbase must have at least 3 outputs for mining
    // development contribution", consensus/validation.cpp:304-307). The
    // original 2025 assertion here ("exactly 1 output") predates that rule and
    // was the roster's quarantine reason (a).
    const std::vector<uint8_t> devFundScript   = P2PKHScript(Consensus::DEV_FUND_PUBKEY_HASH);
    const std::vector<uint8_t> devRewardScript = P2PKHScript(Consensus::DEV_REWARD_PUBKEY_HASH);

    // Create coinbase for block 1 with no fees
    CTransactionRef coinbase1 = miner.CreateCoinbaseTransaction(1, 0, minerAddr, mikData);

    ASSERT(coinbase1 != nullptr, "Coinbase transaction should not be null");
    ASSERT(coinbase1->IsCoinBase(), "Transaction should be coinbase");
    ASSERT_EQ(coinbase1->vin.size(), 1, "Coinbase should have exactly 1 input");
    ASSERT(coinbase1->vin[0].prevout.IsNull(), "Coinbase input prevout should be null");
    ASSERT_EQ(coinbase1->vout.size(), 3, "Coinbase should have exactly 3 outputs (miner + Dev Fund + Dev Reward)");

    // Output 0: miner keeps 98% of the subsidy (49 DIL) + 0 fees
    ASSERT_EQ(coinbase1->vout[0].nValue, kMinerH1, "Miner output should be 98% of subsidy");
    // Output 1: Dev Fund, 1% of subsidy, to the pinned Dev Fund pubkey hash
    ASSERT_EQ(coinbase1->vout[1].nValue, kDevFundH1, "Dev Fund output should be 1% of subsidy");
    ASSERT(coinbase1->vout[1].scriptPubKey == devFundScript, "Dev Fund output should pay DEV_FUND_PUBKEY_HASH");
    // Output 2: Dev Reward, 1% of subsidy, to the pinned Dev Reward pubkey hash
    ASSERT_EQ(coinbase1->vout[2].nValue, kDevRewardH1, "Dev Reward output should be 1% of subsidy");
    ASSERT(coinbase1->vout[2].scriptPubKey == devRewardScript, "Dev Reward output should pay DEV_REWARD_PUBKEY_HASH");
    // The three outputs sum to exactly the subsidy: the tax is a split, not an addition
    uint64_t total1 = coinbase1->vout[0].nValue + coinbase1->vout[1].nValue + coinbase1->vout[2].nValue;
    ASSERT_EQ(total1, kSubsidyH1, "Coinbase outputs should sum to the subsidy");

    // Create coinbase with fees: fees go 100% to the miner, tax outputs unchanged
    uint64_t fees = COIN / 2;  // 0.5 DIL in fees
    CTransactionRef coinbase2 = miner.CreateCoinbaseTransaction(1, fees, minerAddr, mikData);

    ASSERT_EQ(coinbase2->vout.size(), 3, "Coinbase with fees should still have exactly 3 outputs");
    ASSERT_EQ(coinbase2->vout[0].nValue, kMinerH1 + fees, "Miner output should be 98% of subsidy + all fees");
    ASSERT_EQ(coinbase2->vout[1].nValue, kDevFundH1, "Dev Fund output should not change with fees");
    ASSERT_EQ(coinbase2->vout[2].nValue, kDevRewardH1, "Dev Reward output should not change with fees");
    uint64_t total2 = coinbase2->vout[0].nValue + coinbase2->vout[1].nValue + coinbase2->vout[2].nValue;
    ASSERT_EQ(total2, kSubsidyH1 + fees, "Coinbase outputs should sum to subsidy + fees");

    // Producer/validator agreement: the coinbase the miner builds must pass the
    // predicate it will face on the connect path (CheckCoinbase, same height,
    // same fees). A layout the miner emits and the validator refuses would be
    // an unmineable chain, and neither unit assertion above would notice.
    CBlockValidator validator;
    std::string error;
    ASSERT(validator.CheckCoinbase(*coinbase1, 1, 0, error),
           std::string("Miner's fee-less coinbase rejected by CheckCoinbase: ") + error);
    ASSERT(validator.CheckCoinbase(*coinbase2, 1, fees, error),
           std::string("Miner's fee-bearing coinbase rejected by CheckCoinbase: ") + error);

    std::cout << "    Coinbase (no fees): miner " << (coinbase1->vout[0].nValue / (double)COIN)
              << " + dev fund " << (coinbase1->vout[1].nValue / (double)COIN)
              << " + dev reward " << (coinbase1->vout[2].nValue / (double)COIN) << " DIL" << std::endl;
    std::cout << "    Coinbase (0.5 DIL fees): miner " << (coinbase2->vout[0].nValue / (double)COIN) << " DIL" << std::endl;
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
//
// HISTORY. As written in c677b051 (2025-10-27) both arms ran at HEIGHT 0 and
// were correct: CheckCoinbase then applied the value cap at every height.
// 827b1c0f (v4.0.0, 2026-03-28) added `if (nHeight == 0) return true;`
// ("Genesis block: pre-funded addresses can exceed normal subsidy",
// consensus/validation.cpp:254-257) without touching this file, so the
// over-subsidy arm silently began asserting the opposite of the design and the
// suite was quarantined as a "possible missing consensus check" (roster reason
// (b)). It is not: at every height >= 1 the cap `coinbase <= subsidy + fees`
// (validation.cpp:282-285) is enforced unconditionally, and genesis is the
// only block that can reach CheckCoinbase at height 0 (hash-pinned, no pprev).
//
// The value arms now run at HEIGHT 1, under the default (mainnet) params this
// binary already runs under -- see the kMinerH1 note above for why mainnet and
// not testnet -- so they must carry the 3-output DFMP layout or the tax check
// (validation.cpp:294-359) would reject them for the wrong reason. The
// over-subsidy arm therefore also asserts the ERROR STRING, so a rejection is
// attributed to the value cap and nothing else.
//
// KILL ARMS (each verified by scratch mutation, see the PR):
//   delete the value cap (validation.cpp:282-285)      -> "1 satoshi over" arm RED
//   delete the genesis exemption (validation.cpp:254-257) -> height-0 ACCEPT arm RED
TEST(block_validation_coinbase) {
    CBlockValidator validator;
    std::string error;

    const std::vector<uint8_t> minerScript     = CreateMinerAddress();
    const std::vector<uint8_t> devFundScript   = P2PKHScript(Consensus::DEV_FUND_PUBKEY_HASH);
    const std::vector<uint8_t> devRewardScript = P2PKHScript(Consensus::DEV_REWARD_PUBKEY_HASH);

    // --- Height 1, exact subsidy, 3-output layout: ACCEPT (positive control) ---
    CTransaction coinbase = BuildCoinbase(1, {
        Out(kMinerH1,     minerScript),
        Out(kDevFundH1,   devFundScript),
        Out(kDevRewardH1, devRewardScript),
    });
    ASSERT(validator.CheckCoinbase(coinbase, 1, 0, error),
           std::string("Exact-subsidy coinbase at height 1 rejected: ") + error);

    // --- Height 1, one satoshi over subsidy: REJECT, by the VALUE CAP ---
    // Dev outputs are still present and sufficient, so only the cap can fire.
    coinbase.vout[0].nValue = kMinerH1 + 1;
    ASSERT(!validator.CheckCoinbase(coinbase, 1, 0, error),
           "Coinbase one satoshi over subsidy at height 1 should be rejected");
    ASSERT(error == "Coinbase value exceeds subsidy + fees",
           std::string("Rejection must come from the value cap, got: ") + error);

    // --- Height 1, gross overpay (the original 2025 arm, re-pointed): REJECT ---
    coinbase.vout[0].nValue = kMinerH1 + 50 * COIN;  // 100 DIL total, 2x subsidy
    ASSERT(!validator.CheckCoinbase(coinbase, 1, 0, error),
           "Coinbase paying 2x subsidy at height 1 should be rejected");
    ASSERT(error == "Coinbase value exceeds subsidy + fees",
           std::string("Rejection must come from the value cap, got: ") + error);

    // --- Height 1, fees raise the ceiling by exactly the fees ---
    const uint64_t fees = 12345;
    coinbase.vout[0].nValue = kMinerH1 + fees;
    ASSERT(validator.CheckCoinbase(coinbase, 1, fees, error),
           std::string("Coinbase claiming exactly subsidy + fees rejected: ") + error);
    coinbase.vout[0].nValue = kMinerH1 + fees + 1;
    ASSERT(!validator.CheckCoinbase(coinbase, 1, fees, error),
           "Coinbase claiming subsidy + fees + 1 should be rejected");
    ASSERT(error == "Coinbase value exceeds subsidy + fees",
           std::string("Rejection must come from the value cap, got: ") + error);

    // --- Height 0: EXEMPT from the value cap and the tax check, by design ---
    // validation.cpp:254-257 (`if (nHeight == 0) return true;`, added by
    // 827b1c0f for the pre-funded genesis). A single-output coinbase paying 2x
    // the subsidy is ACCEPTED at height 0 ...
    CTransaction genesisLike = BuildCoinbase(0, { Out(100 * COIN, minerScript) });
    ASSERT(validator.CheckCoinbase(genesisLike, 0, 0, error),
           std::string("Over-subsidy coinbase at height 0 must be ACCEPTED (genesis exemption): ") + error);
    // ... and the SAME transaction is rejected one height later, so the
    // exemption is keyed on height, not blind to value. (100 DIL > 50 DIL trips
    // the cap before the 3-output rule is reached.)
    ASSERT(!validator.CheckCoinbase(genesisLike, 1, 0, error),
           "The height-0-exempt coinbase must be rejected at height 1");
    ASSERT(error == "Coinbase value exceeds subsidy + fees",
           std::string("Height-1 rejection must come from the value cap, got: ") + error);

    std::cout << "    Height 1: exact subsidy accepted; +1 satoshi, 2x, and +fees+1 rejected by the value cap" << std::endl;
    std::cout << "    Height 0: 2x subsidy accepted (genesis exemption, validation.cpp:254-257)" << std::endl;
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
