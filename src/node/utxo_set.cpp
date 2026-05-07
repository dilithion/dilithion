// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/utxo_set.h>
#include <node/block_index.h>  // v4.4: VerifyUndoDataInRange takes CBlockIndex*
#include <consensus/validation.h>
#include <core/chainparams.h>
#include <crypto/sha3.h>  // P1-3: For undo data integrity checksum
#include <leveldb/write_batch.h>
#include <leveldb/options.h>
#include <cstring>
#include <iostream>
#include <atomic>

namespace {

// v4.4 trap-7 (storage-of-record) fix: single canonical undo-checksum verifier.
// Both CUTXOSet::UndoBlock (existing P1-3 disconnect path) and the new
// CUTXOSet::VerifyUndoDataInRange call into here so any future change to the
// undo-record framing lands once, not in two places that drift apart.
enum class UndoChecksumResult {
    Valid,
    SizeInvalid,
    ChecksumMismatch,
};

UndoChecksumResult VerifyUndoChecksum(const std::string& undoValue) {
    // P1-3 framing: payload || checksum, where checksum = SHA3-256(payload), 32 bytes.
    // Minimum size: 4 (spentCount) + 32 (checksum) = 36 bytes.
    if (undoValue.size() < 36) {
        return UndoChecksumResult::SizeInvalid;
    }
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(undoValue.data());
    const size_t payloadSize = undoValue.size() - 32;
    uint8_t expected[32];
    SHA3_256(raw, payloadSize, expected);
    if (std::memcmp(expected, raw + payloadSize, 32) != 0) {
        return UndoChecksumResult::ChecksumMismatch;
    }
    return UndoChecksumResult::Valid;
}

// v4.4 Block 6: single canonical fetch+verify primitive shared by both
// VerifyUndoDataInRange (pprev walk, Block 3) and VerifyUndoDataFromSnapshot
// (vector walk, Block 6). Storage-of-record principle: any future change to
// undo-record fetch or framing lands once. Returns true iff the entry exists
// and verifies clean; populates failure_out with cause taxonomy on failure.
bool FetchAndVerifyUndo(leveldb::DB* db,
                        const uint256& blockHash,
                        int height,
                        UndoIntegrityFailure& failure_out) {
    std::string undoKey = "undo_";
    undoKey.append(reinterpret_cast<const char*>(blockHash.data), 32);

    std::string undoValue;
    leveldb::Status st = db->Get(leveldb::ReadOptions(), undoKey, &undoValue);
    if (!st.ok()) {
        failure_out.height = height;
        failure_out.blockHash = blockHash;
        failure_out.cause = "missing";
        return false;
    }
    switch (VerifyUndoChecksum(undoValue)) {
        case UndoChecksumResult::Valid:
            return true;
        case UndoChecksumResult::SizeInvalid:
            failure_out.height = height;
            failure_out.blockHash = blockHash;
            failure_out.cause = "size_invalid";
            return false;
        case UndoChecksumResult::ChecksumMismatch:
            failure_out.height = height;
            failure_out.blockHash = blockHash;
            failure_out.cause = "checksum_mismatch";
            return false;
    }
    return false;  // Unreachable; silences -Werror=return-type warnings.
}

} // anonymous namespace

// Global flag to track IBD state for disk sync optimization
// Set by IBD coordinator, read by UTXO set
// During IBD: sync=false (speed), After IBD: sync=true (durability)
std::atomic<bool> g_utxo_sync_enabled{false};

// ============================================================================
// Constructor and Destructor
// ============================================================================

CUTXOSet::CUTXOSet() : db(nullptr) {
    stats.nUTXOs = 0;
    stats.nTotalAmount = 0;
    stats.nHeight = 0;
}

CUTXOSet::~CUTXOSet() {
    Close();
}

// ============================================================================
// Database Management
// ============================================================================

bool CUTXOSet::Open(const std::string& path, bool create_if_missing) {
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    if (db != nullptr) {
        return true;  // Already open
    }

    datadir = path;

    leveldb::Options options;
    options.create_if_missing = create_if_missing;
    options.compression = leveldb::kSnappyCompression;
    // Larger cache for UTXO set (can be very large)
    options.write_buffer_size = 32 * 1024 * 1024;  // 32MB write buffer

    leveldb::DB* raw_db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, path, &raw_db);

    if (!status.ok()) {
        std::cerr << "[ERROR] CUTXOSet::Open: Failed to open database: " << status.ToString() << std::endl;
        return false;
    }

    db.reset(raw_db);

    // Load statistics from database
    std::string stats_key = "utxo_stats";
    std::string stats_value;
    status = db->Get(leveldb::ReadOptions(), stats_key, &stats_value);

    if (status.ok() && stats_value.size() >= 20) {
        // Deserialize stats: nUTXOs (8 bytes) + nTotalAmount (8 bytes) + nHeight (4 bytes)
        const char* ptr = stats_value.data();
        std::memcpy(&stats.nUTXOs, ptr, 8);
        std::memcpy(&stats.nTotalAmount, ptr + 8, 8);
        std::memcpy(&stats.nHeight, ptr + 16, 4);

    }

    return true;
}

void CUTXOSet::Close() {
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    if (db != nullptr) {
        // P0-3 FIX: Flush all pending cache changes FIRST
        // This ensures cache_additions and cache_deletions are persisted
        if (!cache_additions.empty() || !cache_deletions.empty()) {
            // Use batch write with sync for durability
            leveldb::WriteBatch batch;

            for (const auto& pair : cache_additions) {
                std::string key = SerializeOutPoint(pair.first);
                std::string value = SerializeUTXOEntry(pair.second);
                batch.Put(key, value);
            }

            for (const auto& pair : cache_deletions) {
                std::string key = SerializeOutPoint(pair.first);
                batch.Delete(key);
            }

            leveldb::WriteOptions write_options;
            write_options.sync = true;  // P0-2 FIX: Ensure durability
            db->Write(write_options, &batch);
        }

        // Write final statistics with sync=true
        std::string stats_key = "utxo_stats";
        std::string stats_value;
        stats_value.resize(20);
        std::memcpy(&stats_value[0], &stats.nUTXOs, 8);
        std::memcpy(&stats_value[8], &stats.nTotalAmount, 8);
        std::memcpy(&stats_value[16], &stats.nHeight, 4);

        leveldb::WriteOptions sync_options;
        sync_options.sync = true;  // P0-2 FIX: Ensure stats survive crash
        db->Put(sync_options, stats_key, stats_value);
    }

    cache.clear();
    lru_list.clear();  // TX-004: Clear LRU list
    cache_additions.clear();
    cache_deletions.clear();
    db.reset();
}

bool CUTXOSet::IsOpen() const {
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);
    return db != nullptr;
}

// ============================================================================
// Serialization Helpers
// ============================================================================

std::string CUTXOSet::SerializeOutPoint(const COutPoint& outpoint) const {
    // Key format: 'u' + txid (32 bytes) + index (4 bytes)
    std::string key;
    key.reserve(37);
    key.push_back('u');  // UTXO prefix
    key.append(reinterpret_cast<const char*>(outpoint.hash.begin()), 32);

    uint32_t n = outpoint.n;
    key.append(reinterpret_cast<const char*>(&n), 4);

    return key;
}

std::string CUTXOSet::SerializeUTXOEntry(const CUTXOEntry& entry) const {
    // Value format: height (4 bytes) + fCoinBase (1 byte) + nValue (8 bytes) + scriptPubKey_size (4 bytes) + scriptPubKey
    std::string value;
    value.reserve(17 + entry.out.scriptPubKey.size());

    // Height
    value.append(reinterpret_cast<const char*>(&entry.nHeight), 4);

    // fCoinBase flag
    uint8_t coinbase_flag = entry.fCoinBase ? 1 : 0;
    value.append(reinterpret_cast<const char*>(&coinbase_flag), 1);

    // nValue
    value.append(reinterpret_cast<const char*>(&entry.out.nValue), 8);

    // scriptPubKey size
    uint32_t script_size = static_cast<uint32_t>(entry.out.scriptPubKey.size());
    value.append(reinterpret_cast<const char*>(&script_size), 4);

    // scriptPubKey data
    if (script_size > 0) {
        value.append(reinterpret_cast<const char*>(entry.out.scriptPubKey.data()), script_size);
    }

    return value;
}

bool CUTXOSet::DeserializeUTXOEntry(const std::string& data, CUTXOEntry& entry, bool silent) const {
    if (data.size() < 17) {
        if (!silent)
            std::cerr << "[ERROR] CUTXOSet::DeserializeUTXOEntry: Data too small (" << data.size() << " bytes)" << std::endl;
        return false;
    }

    const char* ptr = data.data();
    size_t offset = 0;

    // Height
    std::memcpy(&entry.nHeight, ptr + offset, 4);
    offset += 4;

    // fCoinBase flag
    uint8_t coinbase_flag;
    std::memcpy(&coinbase_flag, ptr + offset, 1);
    entry.fCoinBase = (coinbase_flag != 0);
    offset += 1;

    // nValue
    std::memcpy(&entry.out.nValue, ptr + offset, 8);
    offset += 8;

    // scriptPubKey size
    uint32_t script_size;
    std::memcpy(&script_size, ptr + offset, 4);
    offset += 4;

    // Validate script size
    if (offset + script_size != data.size()) {
        if (!silent)
            std::cerr << "[ERROR] CUTXOSet::DeserializeUTXOEntry: Size mismatch" << std::endl;
        return false;
    }

    // scriptPubKey data
    entry.out.scriptPubKey.resize(script_size);
    if (script_size > 0) {
        std::memcpy(entry.out.scriptPubKey.data(), ptr + offset, script_size);
    }

    return true;
}

// ============================================================================
// Cache Management
// ============================================================================

void CUTXOSet::UpdateCache(const COutPoint& outpoint, const CUTXOEntry& entry) const {
    // TX-004 FIX: Proper LRU cache with eviction of least recently used entry
    auto it = cache.find(outpoint);

    if (it != cache.end()) {
        // Already in cache - move to front (most recently used)
        lru_list.erase(it->second.second);  // Remove old list position
        lru_list.push_front(outpoint);       // Add to front
        it->second.first = entry;            // Update value
        it->second.second = lru_list.begin(); // Update list iterator
    } else {
        // Not in cache - add new entry
        if (cache.size() >= MAX_CACHE_SIZE) {
            // Evict least recently used (back of list)
            COutPoint lru = lru_list.back();
            lru_list.pop_back();
            cache.erase(lru);
        }

        // Add to front of list and cache
        lru_list.push_front(outpoint);
        cache[outpoint] = std::make_pair(entry, lru_list.begin());
    }
}

void CUTXOSet::RemoveFromCache(const COutPoint& outpoint) const {
    // TX-004 FIX: Remove from both LRU list and cache map
    auto it = cache.find(outpoint);
    if (it != cache.end()) {
        lru_list.erase(it->second.second);  // Remove from LRU list
        cache.erase(it);                    // Remove from cache map
    }
}

bool CUTXOSet::GetFromCache(const COutPoint& outpoint, CUTXOEntry& entry) const {
    // TX-004 FIX: Access cache value from pair (first element is CUTXOEntry, second is list iterator)
    auto it = cache.find(outpoint);
    if (it != cache.end()) {
        entry = it->second.first;  // Extract CUTXOEntry from pair
        // Note: Not updating LRU on read to avoid complexity - UpdateCache handles LRU on writes
        return true;
    }
    return false;
}

// ============================================================================
// UTXO Operations
// ============================================================================

bool CUTXOSet::GetUTXO(const COutPoint& outpoint, CUTXOEntry& entry) const {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::GetUTXO: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    // Check if marked for deletion in pending changes
    if (cache_deletions.find(outpoint) != cache_deletions.end()) {
        return false;
    }

    // Check pending additions first
    auto add_it = cache_additions.find(outpoint);
    if (add_it != cache_additions.end()) {
        entry = add_it->second;
        return true;
    }

    // Check memory cache
    if (GetFromCache(outpoint, entry)) {
        return true;
    }

    // Query database
    std::string key = SerializeOutPoint(outpoint);
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) {
        return false;
    }

    // Deserialize entry
    if (!DeserializeUTXOEntry(value, entry)) {
        return false;
    }

    // Update cache
    UpdateCache(outpoint, entry);

    return true;
}

bool CUTXOSet::HaveUTXO(const COutPoint& outpoint) const {
    CUTXOEntry entry;
    return GetUTXO(outpoint, entry);
}

bool CUTXOSet::AddUTXO(const COutPoint& outpoint, const CTxOut& out, uint32_t height, bool fCoinBase) {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::AddUTXO: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    // Create UTXO entry
    CUTXOEntry entry(out, height, fCoinBase);

    // Add to pending additions (will be flushed later)
    cache_additions[outpoint] = entry;

    // Remove from deletions if present
    cache_deletions.erase(outpoint);

    // Update cache
    UpdateCache(outpoint, entry);

    // Update statistics
    stats.nUTXOs++;
    stats.nTotalAmount += out.nValue;

    return true;
}

bool CUTXOSet::SpendUTXO(const COutPoint& outpoint) {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::SpendUTXO: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    // Get the UTXO to update statistics
    CUTXOEntry entry;

    // Check pending additions first
    auto add_it = cache_additions.find(outpoint);
    if (add_it != cache_additions.end()) {
        entry = add_it->second;
        cache_additions.erase(add_it);
    } else if (GetFromCache(outpoint, entry)) {
        // Found in cache
    } else {
        // Query database
        std::string key = SerializeOutPoint(outpoint);
        std::string value;

        leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
        if (!status.ok()) {
            std::cerr << "[ERROR] CUTXOSet::SpendUTXO: UTXO not found" << std::endl;
            return false;
        }

        if (!DeserializeUTXOEntry(value, entry)) {
            return false;
        }
    }

    // Mark for deletion
    cache_deletions[outpoint] = true;

    // Remove from cache
    RemoveFromCache(outpoint);

    // Update statistics
    if (stats.nUTXOs > 0) {
        stats.nUTXOs--;
    }
    if (stats.nTotalAmount >= entry.out.nValue) {
        stats.nTotalAmount -= entry.out.nValue;
    }

    return true;
}

bool CUTXOSet::ApplyBlock(const CBlock& block, uint32_t height, const uint256& blockHash) {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::ApplyBlock: Database not open" << std::endl;
        return false;
    }

    // TX-001 FIX: Lock for entire block application to prevent cache races
    // Using recursive_mutex allows this to call other member functions (like GetUTXO)
    // that also acquire the lock
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    // ============================================================================
    // CS-004: UTXO Set Updates - ApplyBlock Implementation
    // ============================================================================

    // Step 1: Deserialize transactions from block (CS-002)
    std::vector<CTransactionRef> transactions;
    std::string error;

    CBlockValidator validator;
    if (!validator.DeserializeBlockTransactions(block, transactions, error)) {
        std::cerr << "[ERROR] CUTXOSet::ApplyBlock: Failed to deserialize transactions: "
                  << error << std::endl;
        return false;
    }

    if (transactions.empty()) {
        std::cerr << "[ERROR] CUTXOSet::ApplyBlock: No transactions in block" << std::endl;
        return false;
    }

    // Step 2: Prepare undo data (spent UTXOs) for potential rollback
    // Format: count (4 bytes) + for each UTXO: hash (32) + n (4) + CUTXOEntry
    std::vector<uint8_t> undoData;
    uint32_t spentCount = 0;

    // Reserve space for count (will write at end)
    undoData.resize(4, 0);

    // Step 3: Process each transaction
    leveldb::WriteBatch batch;

    for (size_t tx_idx = 0; tx_idx < transactions.size(); ++tx_idx) {
        const CTransactionRef& tx = transactions[tx_idx];
        bool is_coinbase = (tx_idx == 0);
        uint256 txid = tx->GetHash();

        // Step 3a: Spend inputs (skip for coinbase)
        if (!is_coinbase) {
            for (const auto& txin : tx->vin) {
                // Get UTXO entry before spending (for undo data)
                CUTXOEntry entry;
                if (!GetUTXO(txin.prevout, entry)) {
                    std::cerr << "[ERROR] CUTXOSet::ApplyBlock: Input not found in UTXO set: "
                              << "tx " << tx_idx << ", input spending "
                              << txin.prevout.hash.GetHex() << ":" << txin.prevout.n << std::endl;
                    return false;
                }

                // Save to undo data
                undoData.insert(undoData.end(), txin.prevout.hash.begin(), txin.prevout.hash.end());

                uint8_t n_bytes[4];
                std::memcpy(n_bytes, &txin.prevout.n, 4);
                undoData.insert(undoData.end(), n_bytes, n_bytes + 4);

                // Serialize CUTXOEntry: nValue (8) + scriptPubKey length (4) + scriptPubKey + nHeight (4) + fCoinBase (1)
                uint8_t value_bytes[8];
                std::memcpy(value_bytes, &entry.out.nValue, 8);
                undoData.insert(undoData.end(), value_bytes, value_bytes + 8);

                uint32_t script_len = entry.out.scriptPubKey.size();
                uint8_t len_bytes[4];
                std::memcpy(len_bytes, &script_len, 4);
                undoData.insert(undoData.end(), len_bytes, len_bytes + 4);
                undoData.insert(undoData.end(), entry.out.scriptPubKey.begin(), entry.out.scriptPubKey.end());

                uint8_t height_bytes[4];
                std::memcpy(height_bytes, &entry.nHeight, 4);
                undoData.insert(undoData.end(), height_bytes, height_bytes + 4);

                undoData.push_back(entry.fCoinBase ? 1 : 0);

                spentCount++;

                // Remove from UTXO set
                std::string key = "u";
                key.append(reinterpret_cast<const char*>(txin.prevout.hash.data), 32);
                key.append(reinterpret_cast<const char*>(&txin.prevout.n), 4);
                batch.Delete(key);

                // Remove from cache (critical: must sync cache with database state)
                RemoveFromCache(txin.prevout);

                // Update statistics
                if (stats.nUTXOs > 0) stats.nUTXOs--;
                if (stats.nTotalAmount >= entry.out.nValue) {
                    stats.nTotalAmount -= entry.out.nValue;
                }
            }
        }

        // Step 3b: Add new UTXOs from outputs
        for (uint32_t n = 0; n < tx->vout.size(); ++n) {
            COutPoint outpoint(txid, n);
            const CTxOut& txout = tx->vout[n];

            // Build key: "u" + txhash (32 bytes) + n (4 bytes)
            std::string key = "u";
            key.append(reinterpret_cast<const char*>(outpoint.hash.data), 32);
            key.append(reinterpret_cast<const char*>(&outpoint.n), 4);

            // Build value: CUTXOEntry serialization
            // Format: height (4) + fCoinBase (1) + nValue (8) + scriptPubKey_size (4) + scriptPubKey
            std::vector<uint8_t> value;
            value.resize(4 + 1 + 8 + 4 + txout.scriptPubKey.size());

            uint8_t* ptr = value.data();

            // Height (4 bytes)
            std::memcpy(ptr, &height, 4);
            ptr += 4;

            // fCoinBase flag (1 byte)
            *ptr = is_coinbase ? 1 : 0;
            ptr++;

            // nValue (8 bytes)
            std::memcpy(ptr, &txout.nValue, 8);
            ptr += 8;

            // scriptPubKey size (4 bytes)
            uint32_t script_len = txout.scriptPubKey.size();
            std::memcpy(ptr, &script_len, 4);
            ptr += 4;

            // scriptPubKey data
            std::memcpy(ptr, txout.scriptPubKey.data(), script_len);

            batch.Put(key, leveldb::Slice(reinterpret_cast<const char*>(value.data()), value.size()));

            // Update cache (critical: must sync cache with database state)
            CUTXOEntry entry(txout, height, is_coinbase);
            UpdateCache(outpoint, entry);

            // Update statistics
            stats.nUTXOs++;
            stats.nTotalAmount += txout.nValue;
        }
    }

    // Step 4: Write spent count to undo data
    std::memcpy(undoData.data(), &spentCount, 4);

    // P1-3 FIX: Add SHA3-256 integrity checksum to undo data
    // This detects corruption during reorgs and prevents invalid state
    uint8_t checksum[32];
    SHA3_256(undoData.data(), undoData.size(), checksum);
    undoData.insert(undoData.end(), checksum, checksum + 32);

    // Step 5: Store undo data with key "undo_<blockhash>"
    // IBD OPTIMIZATION: Use passed blockHash instead of computing RandomX
    std::string undoKey = "undo_";
    undoKey.append(reinterpret_cast<const char*>(blockHash.data), 32);
    batch.Put(undoKey, leveldb::Slice(reinterpret_cast<const char*>(undoData.data()), undoData.size()));

    // Step 6: Update height
    stats.nHeight = height;

    // Step 7: Write batch to database
    // During IBD: sync=false for speed (blocks can be re-downloaded on crash)
    // After IBD: sync=true for durability (critical for mined/received blocks)
    leveldb::WriteOptions write_options;
    write_options.sync = g_utxo_sync_enabled.load(std::memory_order_relaxed);
    leveldb::Status status = db->Write(write_options, &batch);
    if (!status.ok()) {
        std::cerr << "[ERROR] CUTXOSet::ApplyBlock: Database write failed: " << status.ToString() << std::endl;
        return false;
    }

    // Step 8: Flush statistics
    if (!Flush()) {
        std::cerr << "[ERROR] CUTXOSet::ApplyBlock: Failed to flush statistics" << std::endl;
        return false;
    }

    return true;
}

bool CUTXOSet::UndoBlock(const CBlock& block, const uint256& blockHash) {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::UndoBlock: Database not open" << std::endl;
        return false;
    }

    // TX-001 FIX: Lock for entire block undo to prevent cache races
    // Using recursive_mutex allows this to call other member functions
    // that also acquire the lock
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    // ============================================================================
    // CS-004: UTXO Set Updates - UndoBlock Implementation
    // ============================================================================

    // Step 1: Load undo data for this block
    // Use the block hash from the block index (same hash used in ApplyBlock)
    std::string undoKey = "undo_";
    undoKey.append(reinterpret_cast<const char*>(blockHash.data), 32);

    std::string undoValue;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), undoKey, &undoValue);

    // BUG #271 FIX: If undo data not found, try block.GetHash() as fallback
    // This catches hash mismatches between block index hash and computed hash
    if (!status.ok()) {
        uint256 computedHash = block.GetHash();
        if (computedHash != blockHash) {
            std::cerr << "[WARN] CUTXOSet::UndoBlock: Hash mismatch detected!"
                      << " index=" << blockHash.GetHex().substr(0, 16)
                      << " computed=" << computedHash.GetHex().substr(0, 16) << std::endl;
            std::string fallbackKey = "undo_";
            fallbackKey.append(reinterpret_cast<const char*>(computedHash.data), 32);
            status = db->Get(leveldb::ReadOptions(), fallbackKey, &undoValue);
            if (status.ok()) {
                std::cout << "[WARN] CUTXOSet::UndoBlock: Found undo data under computed hash (fallback)" << std::endl;
                // Use the fallback key for deletion later
                undoKey = fallbackKey;
            }
        }
    }

    // BUG #271 FIX: If undo data still not found, try to reconstruct
    // For coinbase-only blocks (common in VDF chains), undo is trivial:
    // just remove coinbase outputs, no inputs to restore.
    if (!status.ok()) {
        std::cerr << "[WARN] CUTXOSet::UndoBlock: Undo data not found, attempting reconstruction"
                  << " (hash=" << blockHash.GetHex().substr(0, 16) << "...)" << std::endl;

        CBlockValidator validator;
        std::vector<CTransactionRef> transactions;
        std::string deserr;
        if (!validator.DeserializeBlockTransactions(block, transactions, deserr) || transactions.empty()) {
            std::cerr << "[ERROR] CUTXOSet::UndoBlock: Cannot reconstruct - failed to deserialize: "
                      << deserr << std::endl;
            return false;
        }

        // Check if any non-coinbase transactions have inputs that need restoring
        bool has_regular_txs = false;
        for (size_t i = 1; i < transactions.size(); ++i) {
            if (!transactions[i]->vin.empty()) {
                has_regular_txs = true;
                break;
            }
        }

        if (has_regular_txs) {
            std::cerr << "[ERROR] CUTXOSet::UndoBlock: Block has regular transactions - "
                      << "cannot reconstruct undo data without tx index. "
                      << "Consider using --reindex to rebuild UTXO set." << std::endl;
            return false;
        }

        // Coinbase-only block: just remove outputs (no inputs to restore)
        std::cout << "[Chain] Reconstructing undo for coinbase-only block (no spent inputs)" << std::endl;

        leveldb::WriteBatch batch;
        for (int tx_idx = transactions.size() - 1; tx_idx >= 0; --tx_idx) {
            const CTransactionRef& tx = transactions[tx_idx];
            uint256 txid = tx->GetHash();
            for (uint32_t n = 0; n < tx->vout.size(); ++n) {
                COutPoint outpoint(txid, n);
                const CTxOut& txout = tx->vout[n];
                std::string key = "u";
                key.append(reinterpret_cast<const char*>(outpoint.hash.data), 32);
                key.append(reinterpret_cast<const char*>(&outpoint.n), 4);
                batch.Delete(key);
                RemoveFromCache(outpoint);
                if (stats.nUTXOs > 0) stats.nUTXOs--;
                if (stats.nTotalAmount >= txout.nValue) {
                    stats.nTotalAmount -= txout.nValue;
                }
            }
        }

        if (stats.nHeight > 0) stats.nHeight--;

        leveldb::WriteOptions wo;
        wo.sync = true;
        status = db->Write(wo, &batch);
        if (!status.ok()) {
            std::cerr << "[ERROR] CUTXOSet::UndoBlock: Reconstructed undo write failed: "
                      << status.ToString() << std::endl;
            return false;
        }
        if (!Flush()) {
            std::cerr << "[ERROR] CUTXOSet::UndoBlock: Failed to flush after reconstructed undo" << std::endl;
            return false;
        }
        std::cout << "[Chain] Successfully reconstructed undo for coinbase-only block" << std::endl;
        return true;
    }

    // P1-3 FIX: Verify SHA3-256 integrity checksum (last 32 bytes).
    // v4.4: delegated to canonical helper VerifyUndoChecksum (anon ns above) so
    // CUTXOSet::VerifyUndoDataInRange uses the same single source of truth.
    UndoChecksumResult chk = VerifyUndoChecksum(undoValue);
    if (chk == UndoChecksumResult::SizeInvalid) {
        std::cerr << "[ERROR] CUTXOSet::UndoBlock: Invalid undo data (too small: " << undoValue.size() << " bytes)" << std::endl;
        return false;
    }
    if (chk == UndoChecksumResult::ChecksumMismatch) {
        std::cerr << "[ERROR] CUTXOSet::UndoBlock: Undo data checksum mismatch - CORRUPTION DETECTED!" << std::endl;
        std::cerr << "        Block hash: " << blockHash.GetHex() << std::endl;
        return false;
    }

    // Parse undo data (excluding 32-byte trailing checksum).
    const uint8_t* raw_data = reinterpret_cast<const uint8_t*>(undoValue.data());
    size_t data_size = undoValue.size() - 32;
    const uint8_t* data = raw_data;
    const uint8_t* ptr = data;
    const uint8_t* end = data + data_size;

    uint32_t spentCount;
    std::memcpy(&spentCount, ptr, 4);
    ptr += 4;

    // Step 2: Deserialize transactions from block (CS-002)
    std::vector<CTransactionRef> transactions;
    std::string error;

    CBlockValidator validator;
    if (!validator.DeserializeBlockTransactions(block, transactions, error)) {
        std::cerr << "[ERROR] CUTXOSet::UndoBlock: Failed to deserialize transactions: "
                  << error << std::endl;
        return false;
    }

    if (transactions.empty()) {
        std::cerr << "[ERROR] CUTXOSet::UndoBlock: No transactions in block" << std::endl;
        return false;
    }

    // Step 3: Process in reverse order
    leveldb::WriteBatch batch;

    // Step 3a: Remove all outputs created by this block (process txs in reverse)
    for (int tx_idx = transactions.size() - 1; tx_idx >= 0; --tx_idx) {
        const CTransactionRef& tx = transactions[tx_idx];
        uint256 txid = tx->GetHash();

        for (uint32_t n = 0; n < tx->vout.size(); ++n) {
            COutPoint outpoint(txid, n);
            const CTxOut& txout = tx->vout[n];

            // Build key
            std::string key = "u";
            key.append(reinterpret_cast<const char*>(outpoint.hash.data), 32);
            key.append(reinterpret_cast<const char*>(&outpoint.n), 4);

            // Remove from database
            batch.Delete(key);

            // Remove from cache (critical: must sync cache with database state)
            RemoveFromCache(outpoint);

            // Update statistics
            if (stats.nUTXOs > 0) stats.nUTXOs--;
            if (stats.nTotalAmount >= txout.nValue) {
                stats.nTotalAmount -= txout.nValue;
            }
        }
    }

    // Step 3b: Restore all spent inputs from undo data
    for (uint32_t i = 0; i < spentCount; ++i) {
        if (end - ptr < 32 + 4) {
            std::cerr << "[ERROR] CUTXOSet::UndoBlock: Insufficient undo data (outpoint)" << std::endl;
            return false;
        }

        // Read outpoint
        uint256 hash;
        std::memcpy(hash.data, ptr, 32);
        ptr += 32;

        uint32_t n;
        std::memcpy(&n, ptr, 4);
        ptr += 4;

        // Read CUTXOEntry
        if (end - ptr < 8) {
            std::cerr << "[ERROR] CUTXOSet::UndoBlock: Insufficient undo data (nValue)" << std::endl;
            return false;
        }

        uint64_t nValue;
        std::memcpy(&nValue, ptr, 8);
        ptr += 8;

        if (end - ptr < 4) {
            std::cerr << "[ERROR] CUTXOSet::UndoBlock: Insufficient undo data (script length)" << std::endl;
            return false;
        }

        uint32_t script_len;
        std::memcpy(&script_len, ptr, 4);
        ptr += 4;

        if (end - ptr < script_len) {
            std::cerr << "[ERROR] CUTXOSet::UndoBlock: Insufficient undo data (scriptPubKey)" << std::endl;
            return false;
        }

        std::vector<uint8_t> scriptPubKey(ptr, ptr + script_len);
        ptr += script_len;

        if (end - ptr < 4 + 1) {
            std::cerr << "[ERROR] CUTXOSet::UndoBlock: Insufficient undo data (height/coinbase)" << std::endl;
            return false;
        }

        uint32_t height;
        std::memcpy(&height, ptr, 4);
        ptr += 4;

        bool fCoinBase = (*ptr != 0);
        ptr++;

        // Restore UTXO to database
        COutPoint outpoint(hash, n);
        std::string key = "u";
        key.append(reinterpret_cast<const char*>(outpoint.hash.data), 32);
        key.append(reinterpret_cast<const char*>(&outpoint.n), 4);

        // Build value: CUTXOEntry serialization
        // Format: height (4) + fCoinBase (1) + nValue (8) + scriptPubKey_size (4) + scriptPubKey
        std::vector<uint8_t> value;
        value.resize(4 + 1 + 8 + 4 + scriptPubKey.size());

        uint8_t* value_ptr = value.data();

        // Height (4 bytes)
        std::memcpy(value_ptr, &height, 4);
        value_ptr += 4;

        // fCoinBase flag (1 byte)
        *value_ptr = fCoinBase ? 1 : 0;
        value_ptr++;

        // nValue (8 bytes)
        std::memcpy(value_ptr, &nValue, 8);
        value_ptr += 8;

        // scriptPubKey size (4 bytes)
        std::memcpy(value_ptr, &script_len, 4);
        value_ptr += 4;

        // scriptPubKey data
        std::memcpy(value_ptr, scriptPubKey.data(), script_len);

        batch.Put(key, leveldb::Slice(reinterpret_cast<const char*>(value.data()), value.size()));

        // Update cache (critical: must sync cache with database state)
        CTxOut txout(nValue, scriptPubKey);
        CUTXOEntry entry(txout, height, fCoinBase);
        UpdateCache(outpoint, entry);

        // Update statistics
        stats.nUTXOs++;
        stats.nTotalAmount += nValue;
    }

    // Step 4: Delete undo data (no longer needed)
    batch.Delete(undoKey);

    // Step 5: Update height
    if (stats.nHeight > 0) {
        stats.nHeight--;
    }

    // Step 6: Write batch to database with sync for durability (P0-4 FIX)
    leveldb::WriteOptions undo_write_options;
    undo_write_options.sync = true;  // Critical: ensure undo changes survive crash
    status = db->Write(undo_write_options, &batch);
    if (!status.ok()) {
        std::cerr << "[ERROR] CUTXOSet::UndoBlock: Database write failed: " << status.ToString() << std::endl;
        return false;
    }

    // Step 7: Flush statistics
    if (!Flush()) {
        std::cerr << "[ERROR] CUTXOSet::UndoBlock: Failed to flush statistics" << std::endl;
        return false;
    }

    return true;
}

bool CUTXOSet::Flush() {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::Flush: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    // Use batch write for efficiency
    leveldb::WriteBatch batch;

    // Apply all additions
    for (const auto& pair : cache_additions) {
        std::string key = SerializeOutPoint(pair.first);
        std::string value = SerializeUTXOEntry(pair.second);
        batch.Put(key, value);
    }

    // Apply all deletions
    for (const auto& pair : cache_deletions) {
        std::string key = SerializeOutPoint(pair.first);
        batch.Delete(key);
    }

    // Write statistics
    std::string stats_key = "utxo_stats";
    std::string stats_value;
    stats_value.resize(20);
    std::memcpy(&stats_value[0], &stats.nUTXOs, 8);
    std::memcpy(&stats_value[8], &stats.nTotalAmount, 8);
    std::memcpy(&stats_value[16], &stats.nHeight, 4);
    batch.Put(stats_key, stats_value);

    // Write batch to database
    leveldb::WriteOptions write_options;
    write_options.sync = true;  // Ensure durability
    leveldb::Status status = db->Write(write_options, &batch);

    if (!status.ok()) {
        std::cerr << "[ERROR] CUTXOSet::Flush: Failed to write batch: " << status.ToString() << std::endl;
        return false;
    }

    // Clear pending changes
    cache_additions.clear();
    cache_deletions.clear();

    return true;
}

// ============================================================================
// Statistics and Verification
// ============================================================================

CUTXOStats CUTXOSet::GetStats() const {
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);
    return stats;
}

bool CUTXOSet::UpdateStats() {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::UpdateStats: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    // Reset statistics
    uint64_t utxo_count = 0;
    uint64_t total_amount = 0;

    // Iterate through all UTXOs in database
    std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();

        // Skip non-UTXO keys
        if (key.empty() || key[0] != 'u') {
            continue;
        }

        // Skip statistics metadata key
        if (key == "utxo_stats") {
            continue;
        }

        // Deserialize UTXO entry
        CUTXOEntry entry;
        if (!DeserializeUTXOEntry(it->value().ToString(), entry)) {
            std::cerr << "[ERROR] CUTXOSet::UpdateStats: Failed to deserialize UTXO" << std::endl;
            continue;
        }

        utxo_count++;
        total_amount += entry.out.nValue;
    }

    if (!it->status().ok()) {
        std::cerr << "[ERROR] CUTXOSet::UpdateStats: Iterator error: " << it->status().ToString() << std::endl;
        return false;
    }

    stats.nUTXOs = utxo_count;
    stats.nTotalAmount = total_amount;

    return true;
}

bool CUTXOSet::IsCoinBaseMature(const COutPoint& outpoint, uint32_t currentHeight) const {
    CUTXOEntry entry;
    if (!GetUTXO(outpoint, entry)) {
        return false;
    }

    // Non-coinbase transactions are always mature
    if (!entry.fCoinBase) {
        return true;
    }

    // Coinbase requires coinbaseMaturity confirmations (chain-specific)
    // currentHeight must be at least (entry.nHeight + coinbaseMaturity)
    unsigned int coinbaseMaturity = Dilithion::g_chainParams
        ? static_cast<unsigned int>(Dilithion::g_chainParams->coinbaseMaturity)
        : COINBASE_MATURITY;
    if (currentHeight < entry.nHeight + coinbaseMaturity) {
        return false;
    }

    return true;
}

bool CUTXOSet::VerifyConsistency() const {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    uint64_t utxo_count = 0;
    uint64_t total_amount = 0;

    // Iterate through all UTXOs and verify they can be deserialized
    std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();

        // Skip non-UTXO keys (including "utxo_stats" metadata key)
        if (key.empty() || key[0] != 'u') {
            continue;
        }

        // Skip statistics metadata key
        if (key == "utxo_stats") {
            continue;
        }

        // Verify key format (1 byte prefix + 32 byte hash + 4 byte index = 37 bytes)
        if (key.size() != 37) {
            std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Invalid key size: " << key.size() << std::endl;
            return false;
        }

        // Deserialize and validate UTXO entry
        CUTXOEntry entry;
        if (!DeserializeUTXOEntry(it->value().ToString(), entry)) {
            std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Failed to deserialize UTXO" << std::endl;
            return false;
        }

        // Check for null/invalid entries
        if (entry.IsNull()) {
            std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Found null UTXO entry" << std::endl;
            return false;
        }

        utxo_count++;
        total_amount += entry.out.nValue;
    }

    if (!it->status().ok()) {
        std::cerr << "[ERROR] CUTXOSet::VerifyConsistency: Iterator error: " << it->status().ToString() << std::endl;
        return false;
    }

    return true;
}

bool CUTXOSet::Clear() {
    if (!IsOpen()) {
        std::cerr << "[ERROR] CUTXOSet::Clear: Database not open" << std::endl;
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    std::cout << "[WARNING] CUTXOSet::Clear: Clearing entire UTXO set!" << std::endl;

    // Use batch delete for efficiency
    leveldb::WriteBatch batch;

    // Iterate through all UTXOs and delete them
    std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();

        // Delete all UTXO keys (starting with 'u')
        if (!key.empty() && key[0] == 'u') {
            batch.Delete(key);
        }
    }

    // Write batch to database with sync for durability (P0-4 FIX)
    leveldb::WriteOptions clear_write_options;
    clear_write_options.sync = true;  // Critical: ensure clear operation survives crash
    leveldb::Status status = db->Write(clear_write_options, &batch);
    if (!status.ok()) {
        std::cerr << "[ERROR] CUTXOSet::Clear: Failed to clear database: " << status.ToString() << std::endl;
        return false;
    }

    // Reset statistics
    stats.nUTXOs = 0;
    stats.nTotalAmount = 0;
    stats.nHeight = 0;

    // Clear caches
    cache.clear();
    lru_list.clear();  // TX-004: Clear LRU list
    cache_additions.clear();
    cache_deletions.clear();

    return true;
}

// ============================================================================
// v4.0.19: HasUndoData — cheap existence probe for undo_<blockhash> entry
// ============================================================================
// Used at startup by CChainState::VerifyRecentUndoIntegrity to detect the
// missing-undo-data corruption mode (incident 2026-04-25). Symmetric with the
// undo key construction in ApplyBlock (line ~562) and UndoBlock (line ~606):
// key format is "undo_" + 32 bytes of blockHash.data.

bool CUTXOSet::HasUndoData(const uint256& blockHash) const {
    if (!IsOpen()) {
        return false;
    }
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    std::string undoKey = "undo_";
    undoKey.append(reinterpret_cast<const char*>(blockHash.data), 32);

    std::string undoValue;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), undoKey, &undoValue);
    return status.ok();
}

// ============================================================================
// v4.4: VerifyUndoDataInRange — chainstate integrity walk
// ============================================================================
// pprev walk pattern (RT F-1 fix). Used by CChainState::VerifyRecentUndoIntegrity
// (thin delegator) and ChainstateIntegrityMonitor (periodic) to detect the
// missing/corrupt undo-data corruption mode (incident 2026-04-25).
//
// Walk pattern: pwalker = pindexFrom; pwalker = pwalker->pprev; ... until
// pwalker is null or pwalker->nHeight < fromHeight. Each iteration is O(1):
// single pointer dereference + single LevelDB point-read + 32-byte SHA3 compare.
// Total cost O(N) where N = (toHeight - fromHeight + 1).
//
// Lock discipline: caller holds cs_main (or guarantees pindexFrom is otherwise
// stable). This method acquires cs_utxo internally.

bool CUTXOSet::VerifyUndoDataInRange(
    CBlockIndex* pindexFrom,
    int fromHeight,
    int toHeight,
    UndoIntegrityFailure& failure_out)
{
    if (!IsOpen()) {
        failure_out.cause = "db_not_open";
        return false;
    }
    if (pindexFrom == nullptr) {
        failure_out.cause = "block_index_missing";
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    CBlockIndex* pwalker = pindexFrom;
    while (pwalker != nullptr && pwalker->nHeight >= fromHeight) {
        if (pwalker->nHeight > toHeight) {
            // Block above the verification window — keep walking pprev.
            pwalker = pwalker->pprev;
            continue;
        }

        // pwalker->nHeight is in [fromHeight, toHeight].
        if (!FetchAndVerifyUndo(db.get(), pwalker->GetBlockHash(), pwalker->nHeight, failure_out)) {
            return false;
        }

        pwalker = pwalker->pprev;
    }

    return true;
}

// ============================================================================
// v4.4 Block 6: VerifyUndoDataFromSnapshot — periodic-monitor walk
// ============================================================================
// Walks a caller-supplied (height, blockHash) snapshot, calling the canonical
// FetchAndVerifyUndo primitive per entry. Snapshot is taken under cs_main by
// the caller (CChainState::SnapshotIntegrityWindow) so this method is
// lock-free w.r.t. cs_main; it acquires cs_utxo internally for the LevelDB
// reads.
//
// Stop-flag discipline (Inverse Adversarial trap 3B): if abortFlag is non-null
// and reads true with seq_cst, the walk returns early with cause=
// "aborted_for_shutdown". Checked between every 10 LevelDB reads so mid-walk
// shutdown latency is bounded by ~10 reads (millisecond range on commodity
// hardware), regardless of disk pressure.

bool CUTXOSet::VerifyUndoDataFromSnapshot(
    const std::vector<std::pair<int, uint256>>& snapshot,
    UndoIntegrityFailure& failure_out,
    const std::atomic<bool>* abortFlag)
{
    if (!IsOpen()) {
        failure_out.cause = "db_not_open";
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    int readsSinceCheck = 0;
    for (const auto& entry : snapshot) {
        if (++readsSinceCheck >= 10) {
            readsSinceCheck = 0;
            if (abortFlag && abortFlag->load(std::memory_order_seq_cst)) {
                failure_out.cause = "aborted_for_shutdown";
                return false;
            }
        }
        if (!FetchAndVerifyUndo(db.get(), entry.second, entry.first, failure_out)) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// v4.4 test-only helpers — surgical mutation of undo records for the
// chainstate-integrity test suite (src/test/chainstate_integrity_tests.cpp).
// ============================================================================
// Production code MUST NOT call these. They exist solely so the integrity-walk
// test fixtures can simulate the corruption modes the walk is designed to catch.

bool CUTXOSet::WriteFramedUndoForTesting(const uint256& blockHash,
                                         const std::vector<uint8_t>& payload) {
    if (!IsOpen()) return false;
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    // Frame: payload || SHA3-256(payload), per the P1-3 undo-record protocol.
    std::vector<uint8_t> framed;
    framed.reserve(payload.size() + 32);
    framed.insert(framed.end(), payload.begin(), payload.end());
    uint8_t cs[32];
    SHA3_256(payload.data(), payload.size(), cs);
    framed.insert(framed.end(), cs, cs + 32);

    std::string undoKey = "undo_";
    undoKey.append(reinterpret_cast<const char*>(blockHash.data), 32);

    leveldb::Slice value(reinterpret_cast<const char*>(framed.data()), framed.size());
    leveldb::Status st = db->Put(leveldb::WriteOptions(), undoKey, value);
    return st.ok();
}

bool CUTXOSet::DeleteUndoForTesting(const uint256& blockHash) {
    if (!IsOpen()) return false;
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    std::string undoKey = "undo_";
    undoKey.append(reinterpret_cast<const char*>(blockHash.data), 32);
    return db->Delete(leveldb::WriteOptions(), undoKey).ok();
}

bool CUTXOSet::CorruptUndoForTesting(const uint256& blockHash) {
    if (!IsOpen()) return false;
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    std::string undoKey = "undo_";
    undoKey.append(reinterpret_cast<const char*>(blockHash.data), 32);

    std::string undoValue;
    leveldb::Status st = db->Get(leveldb::ReadOptions(), undoKey, &undoValue);
    if (!st.ok()) return false;
    if (undoValue.size() < 36) return false;  // No payload byte to flip safely.

    // Flip a bit inside the payload (offset 1 — within the 4-byte spentCount
    // field). The trailing 32-byte SHA3 checksum is left untouched, so
    // VerifyUndoChecksum recomputes SHA3 over the new payload and gets a
    // different value than the stored trailer ⇒ ChecksumMismatch.
    std::string corrupted = undoValue;
    corrupted[1] = static_cast<char>(corrupted[1] ^ 0x80);

    return db->Put(leveldb::WriteOptions(), undoKey, corrupted).ok();
}
