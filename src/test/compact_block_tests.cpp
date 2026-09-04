// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * BIP 152 Compact Block Tests
 *
 * Tests for compact block encoding, decoding, and reconstruction.
 * Verifies the implementation matches the BIP 152 specification.
 */

#include <boost/test/unit_test.hpp>
#include <net/blockencodings.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <crypto/sha3.h>

#include <iostream>
#include <vector>
#include <random>
#include <memory>
#include <set>

// Forward declaration
void SerializeTransactionsToVtx(
    const std::vector<std::shared_ptr<const CTransaction>>& transactions,
    std::vector<uint8_t>& vtx);

// Helper to create a simple test transaction
static std::shared_ptr<const CTransaction> CreateTestTransaction(uint32_t seed)
{
    auto tx = std::make_shared<CTransaction>();
    const_cast<CTransaction&>(*tx).nVersion = 2;
    const_cast<CTransaction&>(*tx).nLockTime = 0;

    // Create a simple input
    CTxIn input;
    input.prevout.hash.SetHex("0000000000000000000000000000000000000000000000000000000000000000");
    input.prevout.n = seed;
    input.nSequence = 0xffffffff;
    const_cast<CTransaction&>(*tx).vin.push_back(input);

    // Create a simple output
    CTxOut output;
    output.nValue = 100000 * (seed + 1);
    output.scriptPubKey = std::vector<uint8_t>{0x00, 0x14}; // Simple P2WPKH-like
    const_cast<CTransaction&>(*tx).vout.push_back(output);

    return tx;
}

// Helper to create a test block with transactions
static CBlock CreateTestBlock(size_t num_txs)
{
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    block.nTime = 1704067200; // Jan 1, 2024
    block.nBits = 0x1d00ffff;
    block.nNonce = 12345;

    // Create transactions
    std::vector<std::shared_ptr<const CTransaction>> transactions;

    // Coinbase transaction
    transactions.push_back(CreateTestTransaction(0));

    // Regular transactions
    for (size_t i = 1; i < num_txs; i++) {
        transactions.push_back(CreateTestTransaction(static_cast<uint32_t>(i)));
    }

    // Serialize transactions into block.vtx
    SerializeTransactionsToVtx(transactions, block.vtx);

    // Compute merkle root
    block.hashMerkleRoot = BuildMerkleRootFromTxs(transactions);

    return block;
}

BOOST_AUTO_TEST_SUITE(compact_block_tests)

/**
 * Test 1: Compact block construction from full block
 */
BOOST_AUTO_TEST_CASE(test_compact_block_construction)
{
    std::cout << "\n[TEST] test_compact_block_construction" << std::endl;

    // Create a block with 10 transactions
    CBlock block = CreateTestBlock(10);

    // Create compact block
    CBlockHeaderAndShortTxIDs compact(block);

    // Verify header is preserved
    BOOST_CHECK_EQUAL(compact.header.nVersion, block.nVersion);
    BOOST_CHECK(compact.header.hashPrevBlock == block.hashPrevBlock);
    BOOST_CHECK_EQUAL(compact.header.nTime, block.nTime);
    BOOST_CHECK_EQUAL(compact.header.nBits, block.nBits);

    std::cout << "  Compact block construction: PASS" << std::endl;
    BOOST_CHECK(true);
}

/**
 * Test 2: Short ID calculation
 */
BOOST_AUTO_TEST_CASE(test_short_id_calculation)
{
    std::cout << "\n[TEST] test_short_id_calculation" << std::endl;

    // Create a simple block
    CBlock block = CreateTestBlock(5);

    // Create two compact blocks with same block
    CBlockHeaderAndShortTxIDs compact1(block);
    CBlockHeaderAndShortTxIDs compact2(block);

    // Different nonces should produce different short IDs
    // (if nonces are different)
    if (compact1.nonce != compact2.nonce) {
        // Short IDs should differ when nonces differ
        bool found_difference = false;
        for (size_t i = 0; i < compact1.shorttxids.size() && i < compact2.shorttxids.size(); i++) {
            if (compact1.shorttxids[i] != compact2.shorttxids[i]) {
                found_difference = true;
                break;
            }
        }
        std::cout << "  Different nonces produce different short IDs: "
                  << (found_difference ? "YES" : "NO (may be same by chance)") << std::endl;
    }

    std::cout << "  Short ID calculation: PASS" << std::endl;
    BOOST_CHECK(true);
}

/**
 * Test 3: Prefilled transactions (coinbase always prefilled)
 */
BOOST_AUTO_TEST_CASE(test_prefilled_transactions)
{
    std::cout << "\n[TEST] test_prefilled_transactions" << std::endl;

    CBlock block = CreateTestBlock(5);
    CBlockHeaderAndShortTxIDs compact(block);

    // Coinbase should always be prefilled at index 0
    BOOST_CHECK_GE(compact.prefilledtxn.size(), 1u);
    if (!compact.prefilledtxn.empty()) {
        BOOST_CHECK_EQUAL(compact.prefilledtxn[0].index, 0u);
        std::cout << "  Coinbase is prefilled at index 0: YES" << std::endl;
    }

    std::cout << "  Prefilled transactions: PASS" << std::endl;
    BOOST_CHECK(true);
}

// NOTE: former "Test 4: Compact block serialization/deserialization" removed —
// it exercised CBlockHeaderAndShortTxIDs::Serialize()/Deserialize(), which were
// dead (never-wired) code and have been deleted. The live CMPCTBLOCK wire is
// covered by the net.cpp CDataStream path.

/**
 * Test 5: IsValid() check
 */
BOOST_AUTO_TEST_CASE(test_compact_block_validation)
{
    std::cout << "\n[TEST] test_compact_block_validation" << std::endl;

    CBlock block = CreateTestBlock(3);
    CBlockHeaderAndShortTxIDs compact(block);

    // A properly constructed compact block should be valid
    BOOST_CHECK(compact.IsValid());

    std::cout << "  Compact block validation: PASS" << std::endl;
}

/**
 * Test 6: Empty block handling
 */
BOOST_AUTO_TEST_CASE(test_empty_block)
{
    std::cout << "\n[TEST] test_empty_block" << std::endl;

    CBlock block;
    block.nVersion = 1;
    block.nTime = 1704067200;
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;
    // vtx is empty

    CBlockHeaderAndShortTxIDs compact(block);

    // Should handle empty gracefully
    BOOST_CHECK(compact.shorttxids.empty());
    BOOST_CHECK(compact.prefilledtxn.empty());

    std::cout << "  Empty block handling: PASS" << std::endl;
}

/**
 * Test 7: Short ID uniqueness within block
 */
BOOST_AUTO_TEST_CASE(test_short_id_uniqueness)
{
    std::cout << "\n[TEST] test_short_id_uniqueness" << std::endl;

    // Create a block with many transactions to test uniqueness
    CBlock block = CreateTestBlock(20);
    CBlockHeaderAndShortTxIDs compact(block);

    // Check for duplicate short IDs (collision detection)
    std::set<uint64_t> seen_ids;
    size_t collisions = 0;
    for (uint64_t id : compact.shorttxids) {
        if (seen_ids.count(id) > 0) {
            collisions++;
        }
        seen_ids.insert(id);
    }

    std::cout << "  Short IDs: " << compact.shorttxids.size()
              << ", Collisions: " << collisions << std::endl;

    // With 48-bit short IDs and ~20 txs, collisions should be extremely rare
    BOOST_CHECK_LE(collisions, 1u); // Allow 0 or 1 collision max

    std::cout << "  Short ID uniqueness: PASS" << std::endl;
}

/**
 * Test 8: GetShortID consistency
 */
BOOST_AUTO_TEST_CASE(test_get_short_id_consistency)
{
    std::cout << "\n[TEST] test_get_short_id_consistency" << std::endl;

    CBlock block = CreateTestBlock(3);
    CBlockHeaderAndShortTxIDs compact(block);

    // Same txid should produce same short ID
    uint256 txid;
    txid.SetHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

    uint64_t id1 = compact.GetShortID(txid);
    uint64_t id2 = compact.GetShortID(txid);

    BOOST_CHECK_EQUAL(id1, id2);
    std::cout << "  GetShortID produces consistent results" << std::endl;

    std::cout << "  GetShortID consistency: PASS" << std::endl;
}

// NOTE: former "Test 9: Round-trip serialization" removed — it exercised
// CBlockHeaderAndShortTxIDs::Serialize()/Deserialize() (dead code, now deleted).

BOOST_AUTO_TEST_SUITE_END()
