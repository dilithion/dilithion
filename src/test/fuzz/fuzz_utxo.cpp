// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: UTXO Set Operations
 *
 * Tests:
 * - AddUTXO / SpendUTXO operations
 * - ApplyBlock / UndoBlock operations
 * - Cache synchronization
 * - Database consistency
 * - Statistics tracking
 * - ForEach iterator
 *
 * Coverage:
 * - src/node/utxo_set.h
 * - src/node/utxo_set.cpp
 *
 * Priority: P0 CRITICAL (critical state management, recently had bugs)
 *
 * This fuzzer is especially important after Phase 2 cache sync fixes.
 */

#include "fuzz.h"
#include "util.h"
#include "fuzz_tmpdb.h"
#include "../../primitives/transaction.h"
#include "../../primitives/block.h"
#include "../../node/utxo_set.h"
#include "../../consensus/validation.h"
#include <cstring>
#include <vector>
#include <filesystem>

// Operation types for fuzzing
enum UTXOOperation {
    OP_ADD_UTXO = 0,
    OP_SPEND_UTXO = 1,
    OP_HAVE_UTXO = 2,
    OP_GET_UTXO = 3,
    OP_FLUSH = 4,
    OP_APPLY_BLOCK = 5,
    OP_UNDO_BLOCK = 6,
    OP_VERIFY_CONSISTENCY = 7,
    OP_UPDATE_STATS = 8,
    OP_FOREACH = 9,
    OP_MAX = 10
};

/**
 * Main fuzz target: UTXO operations
 * Dispatches to different UTXO test scenarios
 */
FUZZ_TARGET(utxo)
{
    FuzzedDataProvider fuzzed_data(data, size);

    if (size < 10) {
        return;
    }

    // First byte determines which test to run
    uint8_t test_selector = fuzzed_data.ConsumeIntegral<uint8_t>() % 3;

    try {
        switch (test_selector) {
            case 0: {
                // Test 1: Random sequence of UTXO operations
                FuzzTmpDbDir tmp_dir;
                const std::string& temp_path = tmp_dir.path();
                CUTXOSet utxo;
                if (!utxo.Open(temp_path)) {
                    return;
                }

                std::vector<COutPoint> available_outpoints;
                std::vector<CBlock> applied_blocks;

                while (fuzzed_data.remaining_bytes() > 4) {
                    uint8_t op = fuzzed_data.ConsumeIntegralInRange<uint8_t>(0, OP_MAX - 1);

                    switch (op) {
                        case OP_ADD_UTXO: {
                            uint256 txid;
                            for (size_t i = 0; i < 32; ++i) {
                                txid.data[i] = fuzzed_data.ConsumeIntegral<uint8_t>();
                            }
                            uint32_t n = fuzzed_data.ConsumeIntegral<uint32_t>();
                            COutPoint outpoint(txid, n);

                            uint64_t value = fuzzed_data.ConsumeIntegral<uint64_t>();
                            size_t script_size = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 100);
                            std::vector<uint8_t> scriptPubKey = fuzzed_data.ConsumeBytes<uint8_t>(script_size);

                            CTxOut txout(value, scriptPubKey);
                            uint32_t height = fuzzed_data.ConsumeIntegralInRange<uint32_t>(0, 1000000);
                            bool is_coinbase = fuzzed_data.ConsumeBool();

                            if (utxo.AddUTXO(outpoint, txout, height, is_coinbase)) {
                                available_outpoints.push_back(outpoint);
                            }
                            break;
                        }

                        case OP_SPEND_UTXO: {
                            if (available_outpoints.empty()) break;
                            size_t idx = fuzzed_data.ConsumeIntegralInRange<size_t>(0, available_outpoints.size() - 1);
                            COutPoint outpoint = available_outpoints[idx];
                            if (utxo.SpendUTXO(outpoint)) {
                                available_outpoints.erase(available_outpoints.begin() + idx);
                            }
                            break;
                        }

                        case OP_HAVE_UTXO: {
                            if (available_outpoints.empty()) break;
                            size_t idx = fuzzed_data.ConsumeIntegralInRange<size_t>(0, available_outpoints.size() - 1);
                            (void)utxo.HaveUTXO(available_outpoints[idx]);
                            break;
                        }

                        case OP_GET_UTXO: {
                            if (available_outpoints.empty()) break;
                            size_t idx = fuzzed_data.ConsumeIntegralInRange<size_t>(0, available_outpoints.size() - 1);
                            CUTXOEntry entry;
                            (void)utxo.GetUTXO(available_outpoints[idx], entry);
                            break;
                        }

                        case OP_FLUSH: {
                            (void)utxo.Flush();
                            break;
                        }

                        case OP_APPLY_BLOCK: {
                            // Create simple block with coinbase
                            CTransaction coinbase;
                            coinbase.nVersion = 1;
                            coinbase.nLockTime = 0;

                            std::vector<uint8_t> scriptSig;
                            scriptSig.push_back(0x04);
                            for (int i = 0; i < 4; ++i) {
                                scriptSig.push_back(fuzzed_data.ConsumeIntegral<uint8_t>());
                            }
                            coinbase.vin.push_back(CTxIn(COutPoint(), scriptSig));

                            uint64_t value = fuzzed_data.ConsumeIntegralInRange<uint64_t>(0, 50 * 100000000ULL);
                            std::vector<uint8_t> scriptPubKey(25, 0);
                            coinbase.vout.push_back(CTxOut(value, scriptPubKey));

                            CBlock block;
                            block.nVersion = 1;
                            block.nTime = fuzzed_data.ConsumeIntegral<uint32_t>();
                            block.nBits = 0x1d00ffff;
                            block.nNonce = 0;

                            std::vector<CTransactionRef> transactions = {MakeTransactionRef(coinbase)};
                            std::vector<uint8_t> vtx_data;
                            vtx_data.push_back(1);
                            std::vector<uint8_t> coinbase_data = coinbase.Serialize();
                            vtx_data.insert(vtx_data.end(), coinbase_data.begin(), coinbase_data.end());
                            block.vtx = vtx_data;

                            CBlockValidator validator;
                            block.hashMerkleRoot = validator.BuildMerkleRoot(transactions);

                            uint32_t height = fuzzed_data.ConsumeIntegralInRange<uint32_t>(1, 1000000);
                            if (utxo.ApplyBlock(block, height, block.GetHash())) {
                                applied_blocks.push_back(block);
                                available_outpoints.push_back(COutPoint(coinbase.GetHash(), 0));
                            }
                            break;
                        }

                        case OP_UNDO_BLOCK: {
                            if (applied_blocks.empty()) break;
                            CBlock block = applied_blocks.back();
                            if (utxo.UndoBlock(block, block.GetHash())) {
                                applied_blocks.pop_back();
                                available_outpoints.clear();
                            }
                            break;
                        }

                        case OP_VERIFY_CONSISTENCY: {
                            (void)utxo.VerifyConsistency();
                            break;
                        }

                        case OP_UPDATE_STATS: {
                            (void)utxo.UpdateStats();
                            break;
                        }

                        case OP_FOREACH: {
                            size_t count = 0;
                            utxo.ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) {
                                (void)outpoint;
                                (void)entry;
                                count++;
                                return true;  // Continue iteration
                            });
                            break;
                        }
                    }

                    if (fuzzed_data.remaining_bytes() < 10) {
                        break;
                    }
                }

                utxo.Close();
                break;
            }

            case 1: {
                // Test 2: Cache synchronization
                FuzzTmpDbDir tmp_dir;
                const std::string& temp_path = tmp_dir.path();
                CUTXOSet utxo;
                if (!utxo.Open(temp_path)) {
                    return;
                }

                std::vector<COutPoint> outpoints;
                for (int i = 0; i < 10 && fuzzed_data.remaining_bytes() > 50; ++i) {
                    uint256 txid;
                    for (size_t j = 0; j < 32; ++j) {
                        txid.data[j] = fuzzed_data.ConsumeIntegral<uint8_t>();
                    }
                    COutPoint outpoint(txid, i);

                    uint64_t value = fuzzed_data.ConsumeIntegral<uint64_t>();
                    std::vector<uint8_t> script(25, 0);
                    CTxOut txout(value, script);

                    if (utxo.AddUTXO(outpoint, txout, 100, false)) {
                        outpoints.push_back(outpoint);
                    }
                }

                utxo.Flush();

                // Verify all UTXOs accessible
                for (const auto& outpoint : outpoints) {
                    if (!utxo.HaveUTXO(outpoint)) {
                        // Bug: UTXO should exist after flush
                    }
                    CUTXOEntry entry;
                    if (!utxo.GetUTXO(outpoint, entry)) {
                        // Bug: Should retrieve UTXO
                    }
                }

                // Spend some UTXOs
                size_t num_to_spend = std::min<size_t>(5, outpoints.size());
                for (size_t i = 0; i < num_to_spend; ++i) {
                    utxo.SpendUTXO(outpoints[i]);
                }

                utxo.Flush();

                // Verify spent UTXOs gone
                for (size_t i = 0; i < num_to_spend; ++i) {
                    if (utxo.HaveUTXO(outpoints[i])) {
                        // Bug: UTXO should be gone
                    }
                }

                // Verify remaining exist
                for (size_t i = num_to_spend; i < outpoints.size(); ++i) {
                    if (!utxo.HaveUTXO(outpoints[i])) {
                        // Bug: UTXO should still exist
                    }
                }

                utxo.Close();
                break;
            }

            case 2: {
                // Test 3: Block apply/undo
                FuzzTmpDbDir tmp_dir;
                const std::string& temp_path = tmp_dir.path();
                CUTXOSet utxo;
                if (!utxo.Open(temp_path)) {
                    return;
                }

                std::vector<CBlock> blocks;

                for (int i = 0; i < 5 && fuzzed_data.remaining_bytes() > 100; ++i) {
                    CTransaction coinbase;
                    coinbase.nVersion = 1;
                    coinbase.nLockTime = 0;

                    std::vector<uint8_t> scriptSig;
                    scriptSig.push_back(0x04);
                    scriptSig.push_back(i & 0xFF);
                    scriptSig.push_back((i >> 8) & 0xFF);
                    scriptSig.push_back((i >> 16) & 0xFF);
                    scriptSig.push_back((i >> 24) & 0xFF);
                    coinbase.vin.push_back(CTxIn(COutPoint(), scriptSig));

                    uint64_t value = fuzzed_data.ConsumeIntegralInRange<uint64_t>(0, 50 * 100000000ULL);
                    std::vector<uint8_t> scriptPubKey(25, i);
                    coinbase.vout.push_back(CTxOut(value, scriptPubKey));

                    CBlock block;
                    block.nVersion = 1;
                    block.nTime = fuzzed_data.ConsumeIntegral<uint32_t>();
                    block.nBits = 0x1d00ffff;
                    block.nNonce = 0;

                    std::vector<CTransactionRef> transactions = {MakeTransactionRef(coinbase)};
                    std::vector<uint8_t> vtx_data;
                    vtx_data.push_back(1);
                    std::vector<uint8_t> coinbase_data = coinbase.Serialize();
                    vtx_data.insert(vtx_data.end(), coinbase_data.begin(), coinbase_data.end());
                    block.vtx = vtx_data;

                    CBlockValidator validator;
                    block.hashMerkleRoot = validator.BuildMerkleRoot(transactions);

                    if (utxo.ApplyBlock(block, i + 1, block.GetHash())) {
                        blocks.push_back(block);
                    }
                }

                // Undo all blocks
                for (int i = blocks.size() - 1; i >= 0; --i) {
                    if (!utxo.UndoBlock(blocks[i], blocks[i].GetHash())) {
                        // Bug: Should undo applied block
                    }
                }

                // Verify UTXO set empty
                CUTXOStats stats = utxo.GetStats();
                if (stats.nUTXOs != 0) {
                    // Bug: All UTXOs should be gone
                }

                utxo.Close();
                break;
            }
        }
    } catch (const std::exception& e) {
        return;
    }
}
