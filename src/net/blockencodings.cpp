// Copyright (c) 2016-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/blockencodings.h>
#include <crypto/sha3.h>
#include <crypto/siphash.h>

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <random>

// ============================================================================
// Helper functions for transaction serialization
// ============================================================================

bool DeserializeTransactionsFromVtx(
    const std::vector<uint8_t>& vtx,
    std::vector<CTransaction>& transactions)
{
    transactions.clear();

    if (vtx.empty()) {
        return false;
    }

    const uint8_t* data = vtx.data();
    size_t offset = 0;
    size_t dataSize = vtx.size();

    // Read transaction count (compact size encoding)
    if (offset >= dataSize) {
        return false;
    }

    uint64_t txCount = 0;
    uint8_t firstByte = data[offset++];

    if (firstByte < 253) {
        txCount = firstByte;
    } else if (firstByte == 253) {
        if (offset + 2 > dataSize) {
            return false;
        }
        txCount = data[offset] | (static_cast<uint64_t>(data[offset + 1]) << 8);
        offset += 2;
    } else if (firstByte == 254) {
        if (offset + 4 > dataSize) {
            return false;
        }
        txCount = data[offset] |
                  (static_cast<uint64_t>(data[offset + 1]) << 8) |
                  (static_cast<uint64_t>(data[offset + 2]) << 16) |
                  (static_cast<uint64_t>(data[offset + 3]) << 24);
        offset += 4;
    } else {
        if (offset + 8 > dataSize) {
            return false;
        }
        txCount = data[offset] |
                  (static_cast<uint64_t>(data[offset + 1]) << 8) |
                  (static_cast<uint64_t>(data[offset + 2]) << 16) |
                  (static_cast<uint64_t>(data[offset + 3]) << 24) |
                  (static_cast<uint64_t>(data[offset + 4]) << 32) |
                  (static_cast<uint64_t>(data[offset + 5]) << 40) |
                  (static_cast<uint64_t>(data[offset + 6]) << 48) |
                  (static_cast<uint64_t>(data[offset + 7]) << 56);
        offset += 8;
    }

    // Sanity check
    if (txCount > 100000) {
        return false;
    }

    // Deserialize each transaction
    transactions.reserve(txCount);
    for (uint64_t i = 0; i < txCount; i++) {
        CTransaction tx;
        size_t bytesConsumed = 0;
        std::string error;

        if (!tx.Deserialize(data + offset, dataSize - offset, &error, &bytesConsumed)) {
            std::cerr << "[CompactBlock] Failed to deserialize transaction " << i
                      << ": " << error << std::endl;
            return false;
        }

        transactions.push_back(std::move(tx));
        offset += bytesConsumed;
    }

    return true;
}

void SerializeTransactionsToVtx(
    const std::vector<std::shared_ptr<const CTransaction>>& transactions,
    std::vector<uint8_t>& vtx)
{
    vtx.clear();

    uint64_t txCount = transactions.size();

    // Serialize transaction count (compact size encoding)
    if (txCount < 253) {
        vtx.push_back(static_cast<uint8_t>(txCount));
    } else if (txCount <= 0xFFFF) {
        vtx.push_back(253);
        vtx.push_back(static_cast<uint8_t>(txCount));
        vtx.push_back(static_cast<uint8_t>(txCount >> 8));
    } else if (txCount <= 0xFFFFFFFF) {
        vtx.push_back(254);
        vtx.push_back(static_cast<uint8_t>(txCount));
        vtx.push_back(static_cast<uint8_t>(txCount >> 8));
        vtx.push_back(static_cast<uint8_t>(txCount >> 16));
        vtx.push_back(static_cast<uint8_t>(txCount >> 24));
    } else {
        vtx.push_back(255);
        vtx.push_back(static_cast<uint8_t>(txCount));
        vtx.push_back(static_cast<uint8_t>(txCount >> 8));
        vtx.push_back(static_cast<uint8_t>(txCount >> 16));
        vtx.push_back(static_cast<uint8_t>(txCount >> 24));
        vtx.push_back(static_cast<uint8_t>(txCount >> 32));
        vtx.push_back(static_cast<uint8_t>(txCount >> 40));
        vtx.push_back(static_cast<uint8_t>(txCount >> 48));
        vtx.push_back(static_cast<uint8_t>(txCount >> 56));
    }

    // Serialize each transaction
    for (const auto& tx : transactions) {
        if (tx) {
            std::vector<uint8_t> txData = tx->Serialize();
            // CID 1675171 FIX: Use move iterators to avoid unnecessary copy
            // txData is a local variable that's no longer used after insert
            vtx.insert(vtx.end(), std::make_move_iterator(txData.begin()), std::make_move_iterator(txData.end()));
        }
    }
}

uint256 BuildMerkleRootFromTxs(const std::vector<std::shared_ptr<const CTransaction>>& transactions)
{
    if (transactions.empty()) {
        return uint256();
    }

    // Get transaction hashes
    std::vector<uint256> merkleTree;
    merkleTree.reserve(transactions.size() * 2);

    for (const auto& tx : transactions) {
        if (tx) {
            merkleTree.push_back(tx->GetHash());
        } else {
            merkleTree.push_back(uint256());
        }
    }

    // Build merkle tree iteratively
    size_t levelOffset = 0;
    for (size_t levelSize = transactions.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
        for (size_t i = 0; i < levelSize; i += 2) {
            size_t i2 = std::min(i + 1, levelSize - 1);

            // Concatenate two hashes
            std::vector<uint8_t> combined;
            combined.reserve(64);
            combined.insert(combined.end(),
                          merkleTree[levelOffset + i].begin(),
                          merkleTree[levelOffset + i].end());
            combined.insert(combined.end(),
                          merkleTree[levelOffset + i2].begin(),
                          merkleTree[levelOffset + i2].end());

            // Hash the combination (SHA3-256)
            uint256 hash;
            SHA3_256(combined.data(), combined.size(), hash.data);
            merkleTree.push_back(hash);
        }
        levelOffset += levelSize;
    }

    return merkleTree.empty() ? uint256() : merkleTree.back();
}

// ============================================================================
// CBlockHeaderAndShortTxIDs
// ============================================================================

CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs(const CBlock& block, bool use_wtxid)
    : shorttxidk0(0), shorttxidk1(0)
{
    // Copy header fields
    header.nVersion = block.nVersion;
    header.hashPrevBlock = block.hashPrevBlock;
    header.hashMerkleRoot = block.hashMerkleRoot;
    header.nTime = block.nTime;
    header.nBits = block.nBits;
    header.nNonce = block.nNonce;
    // VDF extension fields (version >= 4)
    if (block.nVersion >= 4) {
        header.vdfOutput = block.vdfOutput;
        header.vdfProofHash = block.vdfProofHash;
    }

    // Generate random nonce for short ID calculation
    std::random_device rd;
    nonce = (static_cast<uint64_t>(rd()) << 32) | rd();

    // Fill SipHash keys
    FillShortTxIDSelector();

    // Deserialize transactions from block.vtx
    std::vector<CTransaction> transactions;
    if (!DeserializeTransactionsFromVtx(block.vtx, transactions)) {
        std::cerr << "[CompactBlock] Failed to deserialize transactions from block" << std::endl;
        return;
    }

    if (transactions.empty()) {
        return;
    }

    // Always prefill coinbase (index 0)
    prefilledtxn.push_back(PrefilledTransaction(0, transactions[0]));

    // Calculate short IDs for remaining transactions
    for (size_t i = 1; i < transactions.size(); i++) {
        uint256 txid = transactions[i].GetHash();
        uint64_t shortid = GetShortID(txid);
        shorttxids.push_back(shortid);
    }

    std::cout << "[CompactBlock] Created from block " << block.GetHash().GetHex().substr(0, 16)
              << "... with " << transactions.size() << " txs"
              << " (" << prefilledtxn.size() << " prefilled, "
              << shorttxids.size() << " short IDs)" << std::endl;
}

void CBlockHeaderAndShortTxIDs::FillShortTxIDSelector() const
{
    // Derive SipHash keys from SHA3-256(header || nonce)
    // Using first 16 bytes as two 64-bit keys

    // MAINNET FIX: Document buffer layout and add compile-time bounds verification
    // Serialize header (80 bytes) + nonce (8 bytes) = 88 bytes total
    // Layout: [version:4][prevhash:32][merkle:32][time:4][bits:4][nonce:4][shortnonce:8]
    static constexpr size_t HEADER_WITH_NONCE_SIZE = 88;
    uint8_t data[HEADER_WITH_NONCE_SIZE];

    // Compile-time bounds verification
    static_assert(0 + 4 <= HEADER_WITH_NONCE_SIZE, "version overflow");
    static_assert(4 + 32 <= HEADER_WITH_NONCE_SIZE, "prevhash overflow");
    static_assert(36 + 32 <= HEADER_WITH_NONCE_SIZE, "merkle overflow");
    static_assert(68 + 4 <= HEADER_WITH_NONCE_SIZE, "time overflow");
    static_assert(72 + 4 <= HEADER_WITH_NONCE_SIZE, "bits overflow");
    static_assert(76 + 4 <= HEADER_WITH_NONCE_SIZE, "nonce overflow");
    static_assert(80 + 8 <= HEADER_WITH_NONCE_SIZE, "shortnonce overflow");

    // Header serialization (bounds verified at compile time)
    // WF-1: explicit little-endian for the multi-byte scalars so the SHA3
    // short-txid selector key is computed identically on every architecture.
    // Byte-identical to the previous host-endian memcpy on LE hosts.
    WriteLE32(data, static_cast<uint32_t>(header.nVersion));
    memcpy(data + 4, header.hashPrevBlock.data, 32);
    memcpy(data + 36, header.hashMerkleRoot.data, 32);
    WriteLE32(data + 68, header.nTime);
    WriteLE32(data + 72, header.nBits);
    WriteLE32(data + 76, header.nNonce);
    WriteLE64(data + 80, nonce);

    // SHA3-256 hash
    uint8_t hash[32];
    SHA3_256(data, 88, hash);

    // Extract two 64-bit keys (little-endian)
    shorttxidk0 = 0;
    shorttxidk1 = 0;
    for (int i = 0; i < 8; i++) {
        shorttxidk0 |= static_cast<uint64_t>(hash[i]) << (i * 8);
        shorttxidk1 |= static_cast<uint64_t>(hash[i + 8]) << (i * 8);
    }
}

uint64_t CBlockHeaderAndShortTxIDs::GetShortID(const uint256& txid) const
{
    // Ensure keys are initialized
    if (shorttxidk0 == 0 && shorttxidk1 == 0) {
        FillShortTxIDSelector();
    }

    // SipHash-2-4 of txid with our keys
    uint64_t hash = SipHashUint256(shorttxidk0, shorttxidk1, txid);

    // Return lower 48 bits (6 bytes)
    return hash & 0xffffffffffffULL;
}

bool CBlockHeaderAndShortTxIDs::IsValid() const
{
    // Check for reasonable sizes
    if (shorttxids.size() > 100000) {
        return false;  // Too many transactions
    }

    if (prefilledtxn.size() > shorttxids.size() + 1) {
        return false;  // More prefilled than total
    }

    // Check prefilled indices are in range
    for (const auto& prefilled : prefilledtxn) {
        if (prefilled.index > shorttxids.size()) {
            return false;
        }
    }

    return true;
}

// NOTE: CBlockHeaderAndShortTxIDs::Serialize()/Deserialize() were removed as dead
// code. The live CMPCTBLOCK wire is produced/consumed by CreateCmpctBlockMessage /
// ProcessCmpctBlockMessage in net.cpp via CDataStream (little-endian); these methods
// implemented a separate, never-wired byte format and were only exercised by tests.

// ============================================================================
// PartiallyDownloadedBlock
// ============================================================================

ReadStatus PartiallyDownloadedBlock::InitData(
    const CBlockHeaderAndShortTxIDs& cmpctblock,
    const std::vector<CTransaction>& mempool_txs)
{
    if (!cmpctblock.IsValid()) {
        return ReadStatus::INVALID;
    }

    header = cmpctblock.header;

    // Total transaction count = prefilled + short IDs
    size_t tx_count = cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size();
    txn_available.resize(tx_count);

    // Place prefilled transactions
    for (const auto& prefilled : cmpctblock.prefilledtxn) {
        if (prefilled.index >= tx_count) {
            return ReadStatus::INVALID;
        }
        txn_available[prefilled.index] = std::make_shared<CTransaction>(prefilled.tx);
        prefilled_indices.insert(prefilled.index);
    }

    // Build short ID to index mapping for non-prefilled positions
    size_t shortid_idx = 0;
    for (size_t i = 0; i < tx_count; i++) {
        if (prefilled_indices.find(i) == prefilled_indices.end()) {
            if (shortid_idx >= cmpctblock.shorttxids.size()) {
                return ReadStatus::INVALID;
            }
            uint64_t shortid = cmpctblock.shorttxids[shortid_idx];
            shortid_to_index[shortid] = static_cast<uint16_t>(i);
            shortid_idx++;
        }
    }

    // Try to fill from mempool
    for (const auto& tx : mempool_txs) {
        uint256 txid = tx.GetHash();
        uint64_t shortid = cmpctblock.GetShortID(txid);

        auto it = shortid_to_index.find(shortid);
        if (it != shortid_to_index.end() && !txn_available[it->second]) {
            txn_available[it->second] = std::make_shared<CTransaction>(tx);
        }
    }

    is_initialized = true;

    std::cout << "[CompactBlock] InitData: " << tx_count << " total txs, "
              << GetMissingTxCount() << " still missing" << std::endl;

    if (GetMissingTxCount() > 0) {
        return ReadStatus::EXTRA_TXN;
    }

    return ReadStatus::OK;
}

bool PartiallyDownloadedBlock::IsTxAvailable(size_t index) const
{
    if (index >= txn_available.size()) {
        return false;
    }
    return txn_available[index] != nullptr;
}

size_t PartiallyDownloadedBlock::GetMissingTxCount() const
{
    size_t missing = 0;
    for (const auto& tx : txn_available) {
        if (!tx) {
            missing++;
        }
    }
    return missing;
}

std::vector<uint16_t> PartiallyDownloadedBlock::GetMissingTxIndices() const
{
    std::vector<uint16_t> missing;
    for (size_t i = 0; i < txn_available.size(); i++) {
        if (!txn_available[i]) {
            missing.push_back(static_cast<uint16_t>(i));
        }
    }
    return missing;
}

ReadStatus PartiallyDownloadedBlock::FillMissingTxs(const std::vector<CTransaction>& txn)
{
    auto missing = GetMissingTxIndices();

    if (txn.size() != missing.size()) {
        std::cerr << "[CompactBlock] Transaction count mismatch: got " << txn.size()
                  << ", expected " << missing.size() << std::endl;
        return ReadStatus::INVALID;
    }

    for (size_t i = 0; i < txn.size(); i++) {
        txn_available[missing[i]] = std::make_shared<CTransaction>(txn[i]);
    }

    std::cout << "[CompactBlock] Filled " << txn.size() << " missing transactions" << std::endl;

    return ReadStatus::OK;
}

bool PartiallyDownloadedBlock::GetBlock(CBlock& block) const
{
    if (!is_initialized) {
        return false;
    }

    if (GetMissingTxCount() > 0) {
        return false;
    }

    // Copy header (all fields including VDF extension)
    block.SetNull();
    block.nVersion = header.nVersion;
    block.hashPrevBlock = header.hashPrevBlock;
    block.hashMerkleRoot = header.hashMerkleRoot;
    block.nTime = header.nTime;
    block.nBits = header.nBits;
    block.nNonce = header.nNonce;
    // VDF extension fields (version >= 4)
    block.vdfOutput = header.vdfOutput;
    block.vdfProofHash = header.vdfProofHash;

    // Serialize transactions into block.vtx format
    SerializeTransactionsToVtx(txn_available, block.vtx);

    // Verify merkle root matches
    uint256 computed_merkle = BuildMerkleRootFromTxs(txn_available);
    if (computed_merkle != header.hashMerkleRoot) {
        std::cerr << "[CompactBlock] Merkle root mismatch after reconstruction!" << std::endl;
        std::cerr << "  Expected: " << header.hashMerkleRoot.GetHex() << std::endl;
        std::cerr << "  Computed: " << computed_merkle.GetHex() << std::endl;
        return false;
    }

    std::cout << "[CompactBlock] Successfully reconstructed block "
              << block.GetHash().GetHex().substr(0, 16) << "..." << std::endl;

    return true;
}

// ============================================================================
// BlockTransactionsRequest
// ============================================================================

std::vector<uint8_t> BlockTransactionsRequest::Serialize() const
{
    std::vector<uint8_t> result;
    result.reserve(32 + 2 + indexes.size() * 2);

    // Block hash
    result.insert(result.end(), blockhash.data, blockhash.data + 32);

    // Index count
    uint16_t count = static_cast<uint16_t>(indexes.size());
    result.push_back(count & 0xFF);
    result.push_back((count >> 8) & 0xFF);

    // Differential encoding
    uint16_t last_index = 0;
    for (uint16_t idx : indexes) {
        uint16_t diff = idx - last_index;
        result.push_back(diff & 0xFF);
        result.push_back((diff >> 8) & 0xFF);
        last_index = idx + 1;
    }

    // MAINNET FIX: Return without std::move to allow RVO
    return result;
}

bool BlockTransactionsRequest::Deserialize(const uint8_t* data, size_t len)
{
    if (len < 34) {
        return false;
    }

    size_t offset = 0;

    // Block hash
    memcpy(blockhash.data, data, 32);
    offset += 32;

    // Index count
    uint16_t count = data[offset] | (static_cast<uint16_t>(data[offset + 1]) << 8);
    offset += 2;

    // CID 1675261 FIX: Validate untrusted allocation size to prevent DoS attacks
    // An attacker could send a malicious message with a very large count value,
    // causing excessive memory allocation. Limit to a reasonable maximum.
    // A block typically has at most a few thousand transactions, and we're only requesting
    // missing ones, so 10000 is a safe upper bound (well below uint16_t max of 65535).
    const uint16_t MAX_INDEX_COUNT = 10000;
    if (count > MAX_INDEX_COUNT) {
        return false;  // Reject maliciously large count values
    }
    // Note: No SIZE_MAX overflow check needed - count is uint16_t (max 65535) and
    // validated <= 10000 above. count*2 is at most 20000, which can't overflow.
    // (CWE-1025 fix: removed always-false check that had no effect)

    if (offset + static_cast<size_t>(count) * 2 > len) {
        return false;
    }

    // Differential decoding
    indexes.resize(count);
    uint16_t last_index = 0;
    for (size_t i = 0; i < count; i++) {
        uint16_t diff = data[offset] | (static_cast<uint16_t>(data[offset + 1]) << 8);
        offset += 2;
        indexes[i] = last_index + diff;
        last_index = indexes[i] + 1;
    }

    return true;
}

// ============================================================================
// BlockTransactions
// ============================================================================

std::vector<uint8_t> BlockTransactions::Serialize() const
{
    std::vector<uint8_t> result;

    // Block hash
    result.insert(result.end(), blockhash.data, blockhash.data + 32);

    // Transaction count
    uint16_t count = static_cast<uint16_t>(txn.size());
    result.push_back(count & 0xFF);
    result.push_back((count >> 8) & 0xFF);

    // Transactions
    for (const auto& tx : txn) {
        std::vector<uint8_t> txData = tx.Serialize();
        // CID 1675171 FIX: Use move iterators to avoid unnecessary copy
        // txData is a local variable that's no longer used after insert
        result.insert(result.end(), std::make_move_iterator(txData.begin()), std::make_move_iterator(txData.end()));
    }

    // MAINNET FIX: Return without std::move to allow RVO
    return result;
}

bool BlockTransactions::Deserialize(const uint8_t* data, size_t len)
{
    if (len < 34) {
        return false;
    }

    size_t offset = 0;

    // Block hash
    memcpy(blockhash.data, data, 32);
    offset += 32;

    // Transaction count
    uint16_t count = data[offset] | (static_cast<uint16_t>(data[offset + 1]) << 8);
    offset += 2;

    // CID 1675268 FIX: Validate untrusted allocation size to prevent DoS attacks
    // An attacker could send a malicious message with a very large count value,
    // causing excessive memory allocation. Limit to a reasonable maximum.
    // A block typically has at most a few thousand transactions. Since count is uint16_t,
    // the maximum value is 65535, but we limit to 10000 as a reasonable upper bound
    // to prevent DoS attacks while still allowing legitimate large blocks.
    const uint16_t MAX_TX_COUNT = 10000;
    if (count > MAX_TX_COUNT) {
        return false;  // Reject maliciously large count values
    }
    // Note: No need for SIZE_MAX overflow check - count is uint16_t (max 65535)
    // and already validated <= 10000 above (CWE-561 fix: removed dead code)

    // Transactions
    txn.resize(count);
    for (size_t i = 0; i < count; i++) {
        size_t bytesConsumed = 0;
        std::string error;
        if (!txn[i].Deserialize(data + offset, len - offset, &error, &bytesConsumed)) {
            return false;
        }
        offset += bytesConsumed;
    }

    return true;
}
