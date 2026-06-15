// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_UTXO_SET_H
#define DILITHION_NODE_UTXO_SET_H

#include <primitives/transaction.h>
#include <primitives/block.h>
#include <node/undo_data.h>
#include <leveldb/db.h>
#include <string>
#include <memory>
#include <mutex>
#include <map>
#include <list>
#include <vector>
#include <cstdint>
#include <atomic>
#include <utility>
#include <functional>

// Forward declaration — VerifyUndoDataInRange takes CBlockIndex* without needing the full type.
class CBlockIndex;

/**
 * v4.4: Result info for chainstate integrity walk failure.
 * Populated by CUTXOSet::VerifyUndoDataInRange when the walk detects a missing
 * or corrupt undo record. The cause field distinguishes failure modes for
 * operator diagnostics + auto-rebuild marker reason text.
 *
 * `transient`: true ONLY when the underlying LevelDB read failed with an
 * IsIOError() status (a recoverable storage-layer fault — open-file-handle
 * exhaustion, an EIO blip, an AV file lock on Windows) that may clear across
 * the monitor's retry loop. The periodic ChainstateIntegrityMonitor uses this
 * flag to AVOID self-bricking a healthy node on a transient fault: a transient
 * failure that does not clear across retries is logged + tolerated, never
 * marker-written.
 *
 * IsCorruption() is deliberately NOT transient. It is LevelDB's signal for REAL
 * on-disk data damage (a failed SST CRC32C checksum, a bad block handle, a
 * corrupt manifest); it reproduces on every read, so it survives the retry loop
 * and must route through the corruption gate -> marker + shutdown + rebuild.
 * Treating it as transient would mask genuine corruption forever (the inverse,
 * more-dangerous failure mode). It is hard-fail, like checksum_mismatch /
 * size_invalid.
 */
struct UndoIntegrityFailure {
    int height = -1;
    uint256 blockHash;
    std::string cause;  // "missing" | "checksum_mismatch" | "size_invalid" | "io_error" | "io_corruption" | "db_not_open" | "block_index_missing"
    bool transient = false;  // true => recoverable IsIOError storage blip (do NOT brick); false => hard-fail
};

/**
 * v4.4: Classify a non-ok leveldb::Status from an undo-record Get() into the
 * (cause, transient) taxonomy. Extracted as a free, side-effect-free function so
 * the safety-critical mapping can be unit-tested directly with synthetic
 * leveldb::Status values (a real on-disk IsCorruption is otherwise impractical
 * to inject). Sets failure_out.cause and failure_out.transient; callers fill in
 * height/blockHash. MUST be called only when st is NOT ok.
 *
 * Mapping (see definition for full rationale):
 *   IsCorruption() -> cause="io_corruption", transient=false  (real on-disk damage; hard-fail)
 *   IsIOError()    -> cause="io_error",      transient=true   (recoverable storage blip)
 *   else           -> cause="missing",       transient=false  (absent key / fail-safe default)
 */
void ClassifyUndoFetchStatus(const leveldb::Status& st, UndoIntegrityFailure& failure_out);

/**
 * v4.4 test-only fault injection for the undo-fetch seam.
 *
 * When g_undo_fetch_fault_injector is non-null, FetchAndVerifyUndo consults it
 * BEFORE the real db->Get(): the hook may return a non-ok leveldb::Status to
 * simulate a storage-layer fault (IsCorruption / IsIOError) that is otherwise
 * impractical to produce on real on-disk data. Returning an ok() Status means
 * "no injected fault — proceed with the real read". This lets the integrity
 * tests drive the full ChainstateIntegrityMonitor retry/tolerate/confirm
 * routing through a synthetic persistent-Corruption or transient-IOError fault.
 *
 * Production code MUST leave this null. It is a std::function so a test can
 * decrement a counter per call (persistent vs clears-on-retry).
 */
extern std::function<leveldb::Status()> g_undo_fetch_fault_injector;

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
     * Read undo data for a block as a structured CBlockUndo.
     *
     * Read-only accessor on the existing on-disk format (key "undo_<blockhash>"
     * written by ApplyBlock; consumed and deleted by UndoBlock). Does NOT
     * mutate disk or the UTXO cache.
     *
     * Layout, validation, and the deviation from Bitcoin Core's per-tx
     * grouping are documented in node/undo_data.h. The SHA3-256 footer is
     * verified before parsing; corruption surfaces as a `false` return with
     * `undo_out` left in an unspecified state, never a crash.
     *
     * Foundational accessor for block-analytics consumers (per-block fee
     * aggregation, coinstatsindex). PR-BA-1 in the block-analytics bundle.
     *
     * Behaviour notes for downstream consumers (PR-BA-2 / PR-BA-3):
     *
     *   - **Reorged-out blocks return false.** UndoBlock deletes the entry
     *     after applying the rollback. A successful write followed by a
     *     reorg produces "missing-block" on this reader. Consumers querying
     *     historical blocks should ensure the block is on the active chain
     *     before invoking; otherwise a false-negative window exists during
     *     reorg processing.
     *   - **Memory bounds.** Allocates O(spentCount) records; with the
     *     writer's current block-size cap (`maxBlockSize` in chainparams)
     *     this is bounded by ~maxBlockSize / kMinRecordBytes records and
     *     ~maxBlockSize bytes of script payload. Consumers should not call
     *     this in unbounded loops over arbitrary blockhashes; rate-limit at
     *     the caller (e.g. RPC handler) if invoked from operator input.
     *   - **No schema version byte.** The on-disk format is the writer's
     *     existing layout (see node/undo_data.h). Any future writer-side
     *     schema change must be coordinated with all readers in the same
     *     commit (currently `UndoBlock` and `ReadUndoBlock`); a content-
     *     compatible-shape change without a version byte will be silently
     *     misparsed by stale readers.
     *
     * @param blockHash The block hash whose undo data to read
     * @param undo_out  Filled with the parsed block undo on success
     * @return true on success; false if the entry is missing (never
     *         written or reorged out), truncated, or the SHA3-256 footer
     *         fails to verify.
     */
    bool ReadUndoBlock(const uint256& blockHash, CBlockUndo& undo_out) const;

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
     * v4.4 Block 6: walk a caller-supplied (height, blockHash) snapshot,
     * verifying every entry has a present, SHA3-checksummed undo record.
     * Used by ChainstateIntegrityMonitor's periodic check; the snapshot is
     * built under cs_main by CChainState::SnapshotIntegrityWindow before the
     * walk, so this method is lock-free w.r.t. cs_main (acquires cs_utxo
     * internally for the LevelDB reads).
     *
     * Stop-flag discipline (Inverse Adversarial trap 3B): if abortFlag is
     * non-null and reads true with std::memory_order_seq_cst, the walk
     * returns early with cause="aborted_for_shutdown". Checked between every
     * 10 LevelDB reads so mid-walk shutdown latency is bounded by ~10 reads
     * (millisecond range), not the full walk duration.
     *
     * @param snapshot      Vector of (height, blockHash) pairs to verify.
     * @param failure_out   Populated on failure with height + blockHash + cause.
     * @param abortFlag     Optional shutdown signal; nullable.
     * @return true iff every entry has valid undo data; false on first failure
     *         OR shutdown abort.
     */
    bool VerifyUndoDataFromSnapshot(
        const std::vector<std::pair<int, uint256>>& snapshot,
        UndoIntegrityFailure& failure_out,
        const std::atomic<bool>* abortFlag = nullptr);

    /**
     * v4.4 test-only: write a synthetic undo record for the given block hash.
     * The payload is SHA3-256-framed (P1-3 protocol) before write so it passes
     * VerifyUndoChecksum. Production code MUST NOT call this; it exists for
     * chainstate-integrity test fixtures only.
     */
    bool WriteFramedUndoForTesting(const uint256& blockHash,
                                   const std::vector<uint8_t>& payload);

    /**
     * v4.4 test-only: delete the undo record for the given block hash.
     * Simulates the missing-undo corruption mode (incident 2026-04-25).
     */
    bool DeleteUndoForTesting(const uint256& blockHash);

    /**
     * v4.4 test-only: corrupt the undo record for the given block hash by
     * flipping one byte in the payload (NOT the trailing 32-byte checksum).
     * After this call, VerifyUndoChecksum returns ChecksumMismatch on the entry.
     */
    bool CorruptUndoForTesting(const uint256& blockHash);

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
