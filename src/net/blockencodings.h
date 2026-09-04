// Copyright (c) 2016-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DILITHION_NET_BLOCKENCODINGS_H
#define DILITHION_NET_BLOCKENCODINGS_H

#include <primitives/block.h>
#include <primitives/transaction.h>

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <vector>

/**
 * @file blockencodings.h
 * @brief Compact Block Relay (BIP 152) implementation
 *
 * Compact blocks significantly reduce block propagation bandwidth:
 * - Instead of ~1MB for a full block, sends ~20KB compact block
 * - Transactions referenced by 6-byte short IDs instead of 32-byte txids
 * - Receiver reconstructs block from mempool + prefilled transactions
 * - Only missing transactions requested individually
 *
 * This is CRITICAL for miner efficiency at scale:
 * - Faster block propagation = less stale blocks
 * - Less bandwidth = more nodes can participate
 * - Essential for mainnet operation with 17k+ nodes
 *
 * Based on BIP 152: https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 */

//! Size of short transaction IDs in bytes (48 bits = 6 bytes)
static constexpr size_t SHORTTXIDS_LENGTH = 6;

/**
 * Prefilled transaction in a compact block
 *
 * Some transactions are sent in full rather than as short IDs:
 * - Coinbase transaction (always prefilled at index 0)
 * - Transactions unlikely to be in receiver's mempool
 */
struct PrefilledTransaction {
    //! Index in the block (differentially encoded in serialization)
    uint16_t index;

    //! Full transaction data
    CTransaction tx;

    PrefilledTransaction() : index(0) {}
    PrefilledTransaction(uint16_t idx, const CTransaction& transaction)
        : index(idx), tx(transaction) {}
};

/**
 * Compact block: header + short transaction IDs + prefilled transactions
 *
 * Structure:
 * - Block header (80 bytes)
 * - Nonce for short ID calculation (8 bytes)
 * - Short transaction IDs (6 bytes each)
 * - Prefilled transactions (variable)
 *
 * Total size: ~20KB for typical 2000-tx block vs ~1MB for full block
 */
class CBlockHeaderAndShortTxIDs {
public:
    CBlockHeaderAndShortTxIDs() : nonce(0), shorttxidk0(0), shorttxidk1(0) {}

    /**
     * Construct from full block
     *
     * Deserializes transactions from block.vtx and creates compact representation.
     *
     * @param block Full block to compress
     * @param use_wtxid Use witness txid (true) or regular txid (false)
     */
    explicit CBlockHeaderAndShortTxIDs(const CBlock& block, bool use_wtxid = false);

    //! Block header
    CBlockHeader header;

    //! Random nonce for short ID calculation (prevents collision attacks)
    uint64_t nonce;

    //! Short transaction IDs (6 bytes each, stored as uint64_t with upper 16 bits zero)
    std::vector<uint64_t> shorttxids;

    //! Prefilled transactions (always includes coinbase)
    std::vector<PrefilledTransaction> prefilledtxn;

    /**
     * Calculate short ID for a transaction
     *
     * Uses SipHash with keys derived from header+nonce:
     * shortid = SipHash(k0, k1, txid) & 0xffffffffffff
     *
     * @param txid Transaction ID (or witness txid)
     * @return 6-byte short ID as uint64_t
     */
    uint64_t GetShortID(const uint256& txid) const;

    /**
     * Get block hash
     */
    uint256 GetBlockHash() const { return header.GetHash(); }

    /**
     * Check if this is a valid compact block structure
     */
    bool IsValid() const;

    // NOTE: Serialize()/Deserialize() were removed as dead code. The live
    // CMPCTBLOCK wire is handled by CreateCmpctBlockMessage /
    // ProcessCmpctBlockMessage in net.cpp (CDataStream, little-endian); these
    // methods were a separate, never-wired format exercised only by tests.

private:
    //! SipHash keys derived from header+nonce
    mutable uint64_t shorttxidk0;
    mutable uint64_t shorttxidk1;

    //! Fill SipHash keys from header+nonce
    void FillShortTxIDSelector() const;
};

/**
 * Request for missing transactions in a compact block
 */
struct BlockTransactionsRequest {
    //! Block hash
    uint256 blockhash;

    //! Indices of missing transactions
    std::vector<uint16_t> indexes;

    BlockTransactionsRequest() {}
    explicit BlockTransactionsRequest(const uint256& hash) : blockhash(hash) {}

    /**
     * Serialize to bytes
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * Deserialize from data
     */
    bool Deserialize(const uint8_t* data, size_t len);
};

/**
 * Response with requested transactions
 */
struct BlockTransactions {
    //! Block hash
    uint256 blockhash;

    //! Requested transactions
    std::vector<CTransaction> txn;

    BlockTransactions() {}
    explicit BlockTransactions(const uint256& hash) : blockhash(hash) {}

    /**
     * Serialize to bytes
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * Deserialize from data
     */
    bool Deserialize(const uint8_t* data, size_t len);
};

/**
 * Result codes for compact block operations
 */
enum class ReadStatus {
    OK,
    INVALID,           //! Invalid compact block structure
    FAILED,            //! Operation failed (collision, etc.)
    CHECKBLOCK_FAILED, //! Block validation failed
    EXTRA_TXN          //! Need additional transactions
};

/**
 * Partially downloaded block being reconstructed
 *
 * Manages the reconstruction of a full block from:
 * 1. Compact block header + short IDs
 * 2. Mempool transactions
 * 3. Additional requested transactions
 */
class PartiallyDownloadedBlock {
public:
    PartiallyDownloadedBlock() : is_initialized(false) {}

    /**
     * Initialize from compact block
     *
     * @param cmpctblock Compact block received from peer
     * @param mempool_txs Transactions from our mempool
     * @return Status code
     */
    ReadStatus InitData(
        const CBlockHeaderAndShortTxIDs& cmpctblock,
        const std::vector<CTransaction>& mempool_txs);

    /**
     * Check if block is fully reconstructed
     */
    bool IsTxAvailable(size_t index) const;

    /**
     * Get number of transactions still missing
     */
    size_t GetMissingTxCount() const;

    /**
     * Get indices of missing transactions
     */
    std::vector<uint16_t> GetMissingTxIndices() const;

    /**
     * Fill in missing transactions from response
     *
     * @param txn Transactions from BlockTransactions response
     * @return Status code
     */
    ReadStatus FillMissingTxs(const std::vector<CTransaction>& txn);

    /**
     * Reconstruct full block
     *
     * Serializes transactions into block.vtx format and verifies merkle root.
     *
     * @param block Output parameter for reconstructed block
     * @return true if block successfully reconstructed
     */
    bool GetBlock(CBlock& block) const;

    /**
     * Get the block header
     */
    const CBlockHeader& GetHeader() const { return header; }

private:
    bool is_initialized;
    CBlockHeader header;

    //! Transactions in block order (nullptr for missing)
    std::vector<std::shared_ptr<const CTransaction>> txn_available;

    //! Short ID to index mapping for reconstruction
    std::map<uint64_t, uint16_t> shortid_to_index;

    //! Indices of prefilled transactions
    std::set<uint16_t> prefilled_indices;
};

// ============================================================================
// Helper functions for transaction serialization
// ============================================================================

/**
 * Deserialize transactions from block.vtx byte format
 *
 * @param vtx Serialized transaction data (compact size + transactions)
 * @param transactions Output vector for deserialized transactions
 * @return true if successful
 */
bool DeserializeTransactionsFromVtx(
    const std::vector<uint8_t>& vtx,
    std::vector<CTransaction>& transactions);

/**
 * Serialize transactions to block.vtx byte format
 *
 * @param transactions Transactions to serialize
 * @param vtx Output vector for serialized data
 */
void SerializeTransactionsToVtx(
    const std::vector<std::shared_ptr<const CTransaction>>& transactions,
    std::vector<uint8_t>& vtx);

/**
 * Build merkle root from transaction hashes
 *
 * @param transactions Transactions (coinbase first)
 * @return Merkle root hash
 */
uint256 BuildMerkleRootFromTxs(const std::vector<std::shared_ptr<const CTransaction>>& transactions);

#endif // DILITHION_NET_BLOCKENCODINGS_H
