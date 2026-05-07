// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_UTXO_SET_H
#define DILITHION_NODE_UTXO_SET_H

#include <primitives/transaction.h>
#include <primitives/block.h>
#include <leveldb/db.h>
#include <string>
#include <memory>
#include <mutex>
#include <map>
#include <list>

// Forward declaration — VerifyUndoDataInRange takes CBlockIndex* without needing the full type.
class CBlockIndex;

/**
 * v4.4: Result info for chainstate integrity walk failure.
 * Populated by CUTXOSet::VerifyUndoDataInRange when the walk detects a missing
 * or corrupt undo record. The cause field distinguishes failure modes for
 * operator diagnostics + auto-rebuild marker reason text.
 */
struct UndoIntegrityFailure {
    int height = -1;
    uint256 blockHash;
    std::string cause;  // "missing" | "checksum_mismatch" | "size_invalid" | "db_not_open" | "block_index_missing"
};

/**
 * UTXO (Unspent Transaction Output) entry
 * Stores information about a single unspent output
 */
struct CUTXOEntry {
    CTxOut out;           // The transaction output itself
    uint32_t nHeight;     // Block height where this UTXO was created
    bool fCoinBase;       // True if this is from a coinbase transaction

    CUTXOEntry() : nHeight(0), fCoinBase(false) {}
    CUTXOEntry(const CTxOut& outIn, uint32_t nHeightIn, bool fCoinBaseIn)
        : out(outIn), nHeight(nHeightIn), fCoinBase(fCoinBaseIn) {}

    bool IsNull() const { return out.IsNull(); }
    void SetNull() { out.SetNull(); nHeight = 0; fCoinBase = false; }
};

/**
 * UTXO Set Statistics
 * Tracks overall UTXO set metrics
 */
struct CUTXOStats {
    uint64_t nUTXOs;           // Total number of UTXOs
    uint64_t nTotalAmount;     // Total amount in all UTXOs
    uint32_t nHeight;          // Current block height

    CUTXOStats() : nUTXOs(0), nTotalAmount(0), nHeight(0) {}
};

/**
 * UTXO Set Database
 *
 * Manages the set of all unspent transaction outputs (UTXOs) using LevelDB.
 * This is critical infrastructure for transaction validation and wallet balance calculation.
 *
 * Features:
 * - Persistent storage via LevelDB
 * - Memory cache for frequently accessed UTXOs
 * - Batch operations for block application/rollback
 * - Thread-safe operations
 * - Coinbase maturity handling
 */
class CUTXOSet
{
private:
    std::unique_ptr<leveldb::DB> db;
    // TX-001 FIX: Changed to recursive_mutex to prevent deadlock when ApplyBlock/UndoBlock
    // call other member functions (like GetUTXO) that also acquire the lock
    mutable std::recursive_mutex cs_utxo;
    std::string datadir;

    // TX-004 FIX: Proper LRU cache implementation
    // Memory cache for frequently accessed UTXOs with LRU eviction policy
    // Using list for LRU ordering (front = most recently used, back = least recently used)
    // and map for O(1) lookup with iterator to list position
    mutable std::list<COutPoint> lru_list;
    mutable std::map<COutPoint, std::pair<CUTXOEntry, std::list<COutPoint>::iterator>> cache;

    // Phase 3.2: Increased cache from 10K to 1M entries (~100MB RAM)
    // This provides ~50% faster UTXO lookups for recent transactions
    static const size_t MAX_CACHE_SIZE = 1000000;

    // Track modifications for batch updates
    std::map<COutPoint, CUTXOEntry> cache_additions;
    std::map<COutPoint, bool> cache_deletions;  // bool is just a placeholder

    // Statistics
    CUTXOStats stats;

    // Coinbase maturity requirement (100 blocks like Bitcoin)
    static const uint32_t COINBASE_MATURITY = 100;

    // Helper functions for serialization
    std::string SerializeOutPoint(const COutPoint& outpoint) const;
    std::string SerializeUTXOEntry(const CUTXOEntry& entry) const;
    bool DeserializeUTXOEntry(const std::string& data, CUTXOEntry& entry, bool silent = false) const;

    // Internal cache management
    void UpdateCache(const COutPoint& outpoint, const CUTXOEntry& entry) const;
    void RemoveFromCache(const COutPoint& outpoint) const;
    bool GetFromCache(const COutPoint& outpoint, CUTXOEntry& entry) const;

public:
    CUTXOSet();
    ~CUTXOSet();

    /**
     * Open the UTXO database at the specified path
     * @param path Directory path for the UTXO database
     * @param create_if_missing Create database if it doesn't exist
     * @return true if successful
     */
    bool Open(const std::string& path, bool create_if_missing = true);

    /**
     * Close the UTXO database
     */
    void Close();

    /**
     * Check if the database is open
     * @return true if database is open
     */
    bool IsOpen() const;

    /**
     * Lookup a UTXO by outpoint
     * @param outpoint The transaction output point to lookup
     * @param entry Reference to store the UTXO entry if found
     * @return true if UTXO exists and is unspent
     */
    bool GetUTXO(const COutPoint& outpoint, CUTXOEntry& entry) const;

    /**
     * Check if a UTXO exists without retrieving it
     * @param outpoint The transaction output point to check
     * @return true if UTXO exists and is unspent
     */
    bool HaveUTXO(const COutPoint& outpoint) const;

    /**
     * Add a new UTXO to the set
     * @param outpoint The transaction output point
     * @param out The transaction output data
     * @param height Block height where this UTXO was created
     * @param fCoinBase Whether this is from a coinbase transaction
     * @return true if successful
     */
    bool AddUTXO(const COutPoint& outpoint, const CTxOut& out, uint32_t height, bool fCoinBase);

    /**
     * Spend (remove) a UTXO from the set
     * @param outpoint The transaction output point to spend
     * @return true if successful (UTXO existed and was removed)
     */
    bool SpendUTXO(const COutPoint& outpoint);

    /**
     * Apply all transactions from a block to the UTXO set
     * This adds all outputs and spends all inputs (except coinbase)
     * @param block The block to apply
     * @param height The height of this block
     * @param blockHash Block hash (passed to avoid RandomX recomputation)
     * @return true if successful
     */
    bool ApplyBlock(const CBlock& block, uint32_t height, const uint256& blockHash);

    /**
     * Undo all transactions from a block (for chain reorganization)
     * This reverses the effects of ApplyBlock
     * @param block The block to undo
     * @param blockHash Block hash from block index (used for undo data lookup;
     *                  must match the hash passed to ApplyBlock)
     * @return true if successful
     */
    bool UndoBlock(const CBlock& block, const uint256& blockHash);

    /**
     * v4.0.19: Cheap probe for whether undo data exists for a given block hash.
     * Reads the value from LevelDB to confirm presence (no atomicity guarantees
     * against concurrent writes, but used at startup before block processing
     * begins, so concurrency is not a concern).
     * Used by CChainState::VerifyRecentUndoIntegrity during startup to detect
     * the missing-undo-data corruption mode (incident 2026-04-25).
     * @param blockHash The block hash to probe
     * @return true if an undo_<blockhash> entry exists in LevelDB
     */
    bool HasUndoData(const uint256& blockHash) const;

    /**
     * v4.4: Walk the chain backward from pindexFrom via pprev, verifying every
     * block in the inclusive height range [fromHeight, toHeight] has its undo
     * record present in LevelDB and SHA3-256-checksummed correctly. Used by
     * CChainState::VerifyRecentUndoIntegrity (delegator) and
     * ChainstateIntegrityMonitor (periodic) to detect the missing/corrupt
     * undo-data corruption mode (incident 2026-04-25).
     *
     * Walk pattern: pindexFrom, pindexFrom->pprev, ... — RT F-1 fix; explicitly
     * NOT lambda-per-height GetAncestor (would be O(N log N)) or naive
     * retry-from-tip (O(N^2)). Total cost is O(N) where N = (toHeight - fromHeight + 1).
     *
     * Lock discipline: the caller is responsible for cs_main (or for guaranteeing
     * pindexFrom is otherwise stable, e.g. during single-threaded startup before
     * block processing begins). This method acquires cs_utxo internally.
     *
     * @param pindexFrom    Starting CBlockIndex (typically pindexTip). Walk pprev from here.
     * @param fromHeight    Inclusive lower bound of verification window.
     * @param toHeight      Inclusive upper bound of verification window.
     * @param failure_out   Populated on failure with height + blockHash + cause.
     * @return true iff every block in [fromHeight, toHeight] has valid undo data.
     */
    bool VerifyUndoDataInRange(CBlockIndex* pindexFrom,
                               int fromHeight,
                               int toHeight,
                               UndoIntegrityFailure& failure_out);

    /**
     * Flush all pending changes to disk
     * This writes all cached additions/deletions to LevelDB
     * @return true if successful
     */
    bool Flush();

    /**
     * Get UTXO set statistics
     * @return Current UTXO statistics
     */
    CUTXOStats GetStats() const;

    /**
     * Update statistics by scanning the entire UTXO set
     * This is expensive and should only be called during initialization
     * or periodic consistency checks
     * @return true if successful
     */
    bool UpdateStats();

    /**
     * Iterate over all UTXOs in the set (WS-002)
     * Calls callback for each UTXO
     * @param callback Function to call for each UTXO: bool callback(COutPoint, CUTXOEntry)
     *                 Return true to continue iteration, false to stop
     * @return Number of UTXOs processed
     */
    template<typename Callback>
    size_t ForEach(Callback callback) const;

    /**
     * Check if a coinbase UTXO is mature (can be spent)
     * Coinbase outputs require COINBASE_MATURITY confirmations
     * @param outpoint The UTXO to check
     * @param currentHeight Current blockchain height
     * @return true if UTXO is spendable at currentHeight
     */
    bool IsCoinBaseMature(const COutPoint& outpoint, uint32_t currentHeight) const;

    /**
     * Verify UTXO set consistency
     * Checks internal data structures for corruption
     * @return true if UTXO set is consistent
     */
    bool VerifyConsistency() const;

    /**
     * Clear all UTXOs (use with caution - for testing/reindexing only)
     * @return true if successful
     */
    bool Clear();

    /**
     * Get the total number of UTXOs in the set
     * @return UTXO count
     */
    uint64_t GetUTXOCount() const { return stats.nUTXOs; }

    /**
     * Get the total amount in all UTXOs (monetary supply)
     * @return Total amount in ions
     */
    uint64_t GetTotalAmount() const { return stats.nTotalAmount; }
};

// ============================================================================
// Template Implementation (WS-002)
// ============================================================================

template<typename Callback>
size_t CUTXOSet::ForEach(Callback callback) const {
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    if (!db) {
        return 0;
    }

    size_t count = 0;
    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());

    // Seek to first UTXO key (prefix "u")
    std::string prefix = "u";
    it->Seek(prefix);

    while (it->Valid()) {
        leveldb::Slice key = it->key();
        leveldb::Slice value = it->value();

        // Check if we're still in UTXO keys (start with "u")
        if (key.size() == 0 || key.data()[0] != 'u') {
            break;
        }

        // Key format: "u" + 32-byte hash + 4-byte index = 37 bytes
        if (key.size() != 37) {
            it->Next();
            continue;
        }

        // Deserialize COutPoint from key
        COutPoint outpoint;
        const uint8_t* keyData = reinterpret_cast<const uint8_t*>(key.data());

        // Skip "u" prefix, read 32-byte hash
        std::copy(keyData + 1, keyData + 33, outpoint.hash.begin());

        // Read 4-byte index (little-endian)
        outpoint.n = keyData[33] | (keyData[34] << 8) | (keyData[35] << 16) | (keyData[36] << 24);

        // Deserialize CUTXOEntry from value
        CUTXOEntry entry;
        std::string valueStr(value.data(), value.size());

        if (DeserializeUTXOEntry(valueStr, entry, true)) {
            // Call callback - if it returns false, stop iteration
            if (!callback(outpoint, entry)) {
                delete it;
                return count;
            }
            count++;
        }

        it->Next();
    }

    delete it;
    return count;
}

#endif // DILITHION_NODE_UTXO_SET_H
