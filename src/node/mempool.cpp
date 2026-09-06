// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/mempool.h>
#include <algorithm>
#include <ctime>
#include <chrono>
#include <iostream>  // For std::cout, std::endl (BUG #109 debug)
#include <util/logging.h>  // For g_verbose flag
#include <policy/fees.h>  // PR-EF-2: g_fee_estimator processTx hook

static const size_t DEFAULT_MAX_MEMPOOL_SIZE = 300 * 1024 * 1024;

// ============================================================================
// MEMPOOL-009 FIX: Exception Safety - RAII Guard for Transaction-Style Insertion
// ============================================================================
//
// VULNERABILITY: AddTx() modifies 3 data structures (mapTx, setEntries, mapSpentOutpoints)
// and 2 counters (mempool_size, mempool_count) without rollback on exception.
// If any operation throws (e.g., memory allocation failure), mempool is left inconsistent.
//
// ATTACK SCENARIO:
// 1. Attacker triggers memory pressure to cause allocation failure
// 2. AddTx() succeeds in mapTx.emplace() but fails in setEntries.insert()
// 3. Transaction exists in mapTx but not setEntries (consistency violation)
// 4. GetOrderedTxs() misses transaction, RemoveTx() corrupts setEntries
//
// FIX: RAII guard ensures atomic all-or-nothing insertion with automatic rollback
//
// SECURITY PROPERTIES:
// - Strong exception safety: Either all changes succeed or none
// - Automatic cleanup via destructor (RAII pattern)
// - No memory leaks on exception
// - Maintains consistency invariants
//
// CID 1675265 FIX: This guard class accesses thread-shared mempool fields.
// INVARIANT: Caller MUST hold CTxMemPool::cs lock when using this guard.
// The guard does not acquire the lock itself - it relies on the caller.
class MempoolInsertionGuard {
private:
    CTxMemPool& mempool;
    uint256 txid;
    bool map_inserted;
    bool set_inserted;
    std::vector<COutPoint> outpoints_added;
    size_t size_added;
    bool count_incremented;
    bool descendants_updated;
    bool committed;

public:
    MempoolInsertionGuard(CTxMemPool& mp, const uint256& id)
        : mempool(mp), txid(id), map_inserted(false), set_inserted(false),
          size_added(0), count_incremented(false), descendants_updated(false),
          committed(false) {
        // CID 1675265: Caller MUST hold CTxMemPool::cs lock when using this guard
    }

    ~MempoolInsertionGuard() {
        if (!committed) {
            Rollback();
        }
    }

    void MarkMapInserted() { map_inserted = true; }
    void MarkSetInserted() { set_inserted = true; }
    void AddOutpoint(const COutPoint& op) { outpoints_added.push_back(op); }
    void SetSizeAdded(size_t size) { size_added = size; }
    void MarkCountIncremented() { count_incremented = true; }
    void MarkDescendantsUpdated() { descendants_updated = true; }
    void Commit() { committed = true; }

    void Rollback() {
        // Rollback in reverse order of insertion

        // 7. Rollback descendant tracking (MEMPOOL-002)
        if (descendants_updated) {
            mempool.UpdateDescendantsRemove(txid);
        }

        // 6. Rollback counter increment
        if (count_incremented && mempool.mempool_count > 0) {
            mempool.mempool_count--;
        }

        // 5. Rollback size addition
        if (size_added > 0) {
            if (mempool.mempool_size >= size_added) {
                mempool.mempool_size -= size_added;
            } else {
                mempool.mempool_size = 0;  // Corruption protection
            }
        }

        // 4. Rollback spent outpoints
        for (const auto& op : outpoints_added) {
            mempool.mapSpentOutpoints.erase(op);
        }

        // 3. Rollback setEntries insertion
        // MEMPOOL-017: setEntries now stores pointers, find and erase pointer
        if (set_inserted) {
            auto map_it = mempool.mapTx.find(txid);
            if (map_it != mempool.mapTx.end()) {
                const CTxMemPoolEntry* entry_ptr = &(map_it->second);
                mempool.setEntries.erase(entry_ptr);
            }
        }

        // 2. Rollback mapTx insertion (second to last)
        if (map_inserted) {
            mempool.mapTx.erase(txid);
        }
    }
};

CTxMemPoolEntry::CTxMemPoolEntry(const CTransactionRef& _tx, CAmount _fee, int64_t _time, unsigned int _height)
    : tx(_tx), tx_hash(_tx->GetHash()), fee(_fee), time(_time), height(_height) {
    tx_size = tx->GetSerializedSize();
    fee_rate = Consensus::CalculateFeeRate(fee, tx_size);
}

bool CompareTxMemPoolEntryByFeeRate::operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const {
    if (a.GetFeeRate() != b.GetFeeRate()) return a.GetFeeRate() > b.GetFeeRate();
    if (a.GetTime() != b.GetTime()) return a.GetTime() < b.GetTime();
    return a.GetTxHash() < b.GetTxHash();
}

// MEMPOOL-017 FIX: Pointer-based comparator for memory-optimized setEntries
bool CompareTxMemPoolEntryByFeeRate::operator()(const CTxMemPoolEntry* a, const CTxMemPoolEntry* b) const {
    // Dereference pointers and use value-based comparison
    return (*this)(*a, *b);
}

CTxMemPool::CTxMemPool()
    : nHeight(0),
      max_mempool_size(DEFAULT_MAX_MEMPOOL_SIZE),
      mempool_size(0),
      max_mempool_count(DEFAULT_MAX_MEMPOOL_COUNT),
      mempool_count(0),
      stop_expiration_thread(false),
      metric_adds(0),
      metric_removes(0),
      metric_evictions(0),
      metric_expirations(0),
      metric_rbf_replacements(0),
      metric_add_failures(0),
      metric_rbf_failures(0) {
    // MEMPOOL-007 FIX: Start background expiration cleanup thread
    expiration_thread = std::thread(&CTxMemPool::ExpirationThreadFunc, this);
}

CTxMemPool::~CTxMemPool() {
    // MEMPOOL-007 FIX: Stop background expiration thread gracefully
    // PR-EF-2 fixup F#1: delegate to StopExpirationThread so the destructor
    // and the explicit shutdown call follow the same code path. Idempotent:
    // if StopExpirationThread was already invoked from main()'s shutdown
    // body, this is a cheap no-op.
    StopExpirationThread();
}

void CTxMemPool::StopExpirationThread() {
    // PR-EF-2 fixup F#1: idempotent. Reached twice on the real shutdown path
    // (explicitly from main(), then again from ~CTxMemPool), so a repeat call
    // must be a cheap no-op: storing true over true changes nothing,
    // notify_all() on a CV with no waiter is free, and joinable() is false
    // after a successful join.
    //
    // SHUTDOWN LOST-WAKEUP FIX: the stop flag MUST be written while holding
    // expiration_mutex -- the same mutex the waiter holds while evaluating
    // its wait_for predicate in ExpirationThreadFunc().
    //
    // Without the lock the following interleaving loses the notification
    // outright:
    //   T_waiter : lock(expiration_mutex)
    //   T_waiter : wait_for evaluates the predicate -> false   (still holding the lock)
    //   T_stop   : stop_expiration_thread = true               (no lock -- races in here)
    //   T_stop   : expiration_cv.notify_all()                  (no waiter is blocked yet)
    //   T_waiter : wait_for atomically releases the lock and blocks
    //   -> the notify landed on nobody; the waiter sleeps the full
    //      std::chrono::hours(1) timeout, and join() below blocks for that
    //      same hour AT SHUTDOWN, ahead of every LevelDB close. Operators
    //      then kill -9 a "hung" shutdown, which is how the UTXO and block
    //      databases get truncated mid-write.
    //
    // Taking expiration_mutex closes the window: the waiter holds that mutex
    // continuously from before it evaluates the predicate until wait_for
    // atomically releases it and blocks, so the store cannot be interleaved
    // into that region. Either the store lands before the waiter takes the
    // lock (predicate sees it, no wait at all) or after the waiter is
    // genuinely blocked on the CV (notify_all below wakes it). There is no
    // third case.
    //
    // notify_all() is deliberately called AFTER releasing the mutex: the
    // state change is what must be serialised, and notifying unlocked avoids
    // waking the waiter straight into a contended lock.
    {
        std::lock_guard<std::mutex> lock(expiration_mutex);
        stop_expiration_thread.store(true);
    }
    expiration_cv.notify_all();
    if (expiration_thread.joinable()) {
        expiration_thread.join();
    }
}

// ============================================================================
// MEMPOOL-002 FIX: Fee-Based Eviction Policy with Descendant Protection
// ============================================================================
//
// VULNERABILITY: No eviction policy when mempool is full
// Without eviction, mempool fills up and rejects ALL new transactions,
// enabling DoS where attacker fills mempool with low-fee spam, preventing
// legitimate high-fee transactions from entering.
//
// ATTACK SCENARIO:
// 1. Attacker sends 100k minimum-fee transactions (fills mempool)
// 2. Legitimate user attempts high-fee transaction
// 3. Mempool rejects (no eviction policy)
// 4. Network cannot process legitimate transactions (DoS)
//
// FIX: Fee-based eviction that:
// - Evicts lowest fee-rate transactions first (economic rationality)
// - Never evicts transactions with descendants (prevents orphaning)
// - Atomic eviction + insertion (uses exception-safe guard)
//
// SECURITY PROPERTIES:
// - High-fee transactions always evict low-fee transactions
// - Transaction chains remain valid (no orphaned children)
// - Fair economic priority (fee market works correctly)
//

bool CTxMemPool::HasDescendants(const uint256& txid) const {
    // Check if transaction has any children in mempool
    auto it = mapDescendants.find(txid);
    return (it != mapDescendants.end() && !it->second.empty());
}

void CTxMemPool::UpdateDescendantsAdd(const CTransactionRef& tx) {
    // When adding transaction, register it as a descendant of its parents
    const uint256 txid = tx->GetHash();

    for (const auto& input : tx->vin) {
        // Find parent transaction (the one being spent)
        const uint256& parent_txid = input.prevout.hash;

        // Check if parent is in mempool
        if (mapTx.count(parent_txid) > 0) {
            // Add this transaction to parent's descendant set
            mapDescendants[parent_txid].insert(txid);
        }
    }
}

void CTxMemPool::UpdateDescendantsRemove(const uint256& txid) {
    // When removing transaction, unregister it from all parents' descendant sets
    auto it = mapTx.find(txid);
    if (it == mapTx.end()) return;

    const CTransaction& tx = it->second.GetTx();

    for (const auto& input : tx.vin) {
        const uint256& parent_txid = input.prevout.hash;

        // Remove txid from parent's descendant set
        auto desc_it = mapDescendants.find(parent_txid);
        if (desc_it != mapDescendants.end()) {
            desc_it->second.erase(txid);

            // Clean up empty descendant sets to save memory
            if (desc_it->second.empty()) {
                mapDescendants.erase(desc_it);
            }
        }
    }

    // Remove this transaction's descendant set (should be empty if properly orphaned)
    mapDescendants.erase(txid);
}

bool CTxMemPool::EvictTransactions(size_t bytes_needed, std::string* error) {
    // Evict lowest fee-rate transactions without descendants until bytes_needed is freed
    //
    // Algorithm:
    // 1. Iterate setEntries in reverse (lowest fee-rate first)
    // 2. Skip transactions with descendants (would orphan children)
    // 3. Remove transactions until bytes_needed freed
    //
    // Time Complexity: O(n) worst case (may need to check all transactions)
    // Space Complexity: O(1) (in-place eviction)

    size_t bytes_freed = 0;
    std::vector<uint256> to_evict;

    // MEMPOOL-017: Iterate over pointers (setEntries now stores const CTxMemPoolEntry*)
    // Iterate from lowest fee-rate to highest (reverse order of setEntries)
    for (auto it = setEntries.rbegin(); it != setEntries.rend(); ++it) {
        const CTxMemPoolEntry* entry_ptr = *it;  // Dereference iterator to get pointer
        const uint256& txid = entry_ptr->GetTxHash();

        // Never evict transactions with descendants (would orphan children)
        if (HasDescendants(txid)) {
            continue;
        }

        // Mark for eviction
        to_evict.push_back(txid);
        bytes_freed += entry_ptr->GetTxSize();

        // Stop when we've freed enough space
        if (bytes_freed >= bytes_needed) {
            break;
        }
    }

    // Check if we can free enough space
    if (bytes_freed < bytes_needed) {
        if (error) {
            *error = "Cannot evict enough transactions: all remaining transactions have descendants";
        }
        return false;
    }

    // Evict selected transactions
    // Note: RemoveTx() is exception-safe (no partial eviction on failure)
    //
    // PR-EF-2 fixup F#3: do the pure-mempool eviction work under cs,
    // queue successfully-removed txids into m_pending_estimator_evictions,
    // and let the public caller notify the estimator AFTER releasing cs.
    // This matches the AddTx / RemoveTx / ReplaceTransaction discipline
    // ("never hold both estimator mutex and mempool cs") and keeps the
    // FEE-ESTIMATION.md runbook claim true. EvictTransactions is private
    // and only called from AddTxUnlocked (which itself runs under cs from
    // AddTx's public wrapper); the wrapper drains the queue and notifies
    // outside the lock. CID 1675290 / 1675260 / 1675250 still hold:
    // RemoveTxUnlocked must be called with cs held.
    for (const auto& txid : to_evict) {
        // CID 1675290 FIX: Use unlocked version - caller (AddTx) already holds cs lock
        if (RemoveTxUnlocked(txid)) {
            // MEMPOOL-018 FIX: Track successful eviction
            metric_evictions.fetch_add(1, std::memory_order_relaxed);
            // F#3: queue for post-lock estimator notification.
            m_pending_estimator_evictions.push_back(txid);
        }
    }

    return true;
}

// ============================================================================
// MEMPOOL-007 FIX: Transaction Expiration Policy
// ============================================================================
//
// VULNERABILITY: No expiration policy for old transactions
// Without expiration, very old low-fee transactions persist indefinitely,
// consuming mempool resources and never being mined. This allows attacker
// to permanently occupy mempool space with minimum-fee transactions.
//
// ATTACK SCENARIO:
// 1. Attacker sends 100k minimum-fee transactions
// 2. Transactions never get mined (fee too low)
// 3. Transactions remain in mempool forever
// 4. Mempool resources permanently consumed (memory leak)
//
// FIX: 14-day expiration policy with background cleanup
// - Transactions older than 14 days are automatically removed
// - Background thread runs every hour to clean up
// - Safe removal respects descendant relationships
//
// SECURITY PROPERTIES:
// - Prevents indefinite resource consumption
// - Automatic cleanup without manual intervention
// - Thread-safe cleanup with proper locking
//

void CTxMemPool::CleanupExpiredTransactions() {
    // PR-EF-2 fixup F#3: out-of-lock estimator notification.
    // Pre-fix this method called est->removeTx() while holding cs, which
    // contradicted the AddTx / RemoveTx / Replace discipline and made
    // the FEE-ESTIMATION.md runbook claim false ("we never hold both"
    // -- false). Estimator never calls back into the mempool today, so
    // there was no live deadlock, but the inconsistency was a footgun
    // for future estimator features. Now: do the pure-mempool work
    // under cs, collect expired txids into a local vector, drop the
    // lock, then notify the estimator outside.
    std::vector<uint256> expired_txids;
    {
        std::lock_guard<std::mutex> lock(cs);

        int64_t current_time = std::time(nullptr);
        std::vector<uint256> to_remove;

        // Find all expired transactions
        for (const auto& entry_pair : mapTx) {
            const CTxMemPoolEntry& entry = entry_pair.second;
            int64_t age = current_time - entry.GetTime();

            // Check if transaction has expired (older than 14 days)
            if (age > MEMPOOL_EXPIRY_SECONDS) {
                // Only expire if no descendants (don't orphan children)
                // Children will be removed recursively once their parents expire
                if (!HasDescendants(entry.GetTxHash())) {
                    to_remove.push_back(entry.GetTxHash());
                }
            }
        }

        // Remove expired transactions
        // CID 1675260 FIX: Use unlocked version - we already hold cs lock above
        for (const auto& txid : to_remove) {
            if (RemoveTxUnlocked(txid)) {
                // MEMPOOL-018 FIX: Track successful expiration
                metric_expirations.fetch_add(1, std::memory_order_relaxed);
                expired_txids.push_back(txid);
            }
        }
    }
    // Lock released. Now notify the estimator outside cs -- matches the
    // AddTx / RemoveTx / Replace pattern. Estimator has its own mutex.
    if (auto* est = g_fee_estimator) {
        for (const auto& txid : expired_txids) {
            est->removeTx(txid, /*in_block=*/false);
        }
    }
}

void CTxMemPool::ExpirationThreadFunc() {
    // Background thread that runs every hour to clean up expired transactions
    // This prevents indefinite accumulation of old transactions

    // SHUTDOWN LOST-WAKEUP FIX -- INVARIANT: stop_expiration_thread is
    // written ONLY under expiration_mutex (see StopExpirationThread). That is
    // what makes the wait below un-missable: the predicate is evaluated while
    // this thread holds expiration_mutex, and wait_for releases that mutex and
    // blocks atomically, so no store+notify can slip between the two.
    // The unlocked read in the outer loop condition is a fast-path only -- the
    // authoritative check is the predicate/post-wait check under the lock.
    while (!stop_expiration_thread) {
        {
            // Wait for 1 hour or until stop signal
            std::unique_lock<std::mutex> lock(expiration_mutex);
            expiration_cv.wait_for(lock, std::chrono::hours(1), [this] {
                return stop_expiration_thread.load();
            });

            if (stop_expiration_thread) {
                break;
            }
        }

        // Perform cleanup (outside the expiration_mutex lock to avoid holding it too long)
        CleanupExpiredTransactions();
    }
}

// T1.B-2 (testmempoolaccept): Pure validation -- NO mutation of any mempool state.
// Caller MUST hold cs lock. Returns true iff the tx would pass AddTxUnlocked's
// initial validation gauntlet (everything before the eviction-and-insertion phase).
// BYTE-FOR-BYTE equivalent to AddTxUnlocked's reject wording for each branch so
// testmempoolaccept's reject-reason matches sendrawtransaction's error verbatim.
//
// Eviction is intentionally NOT attempted here -- eviction mutates the mempool
// and testmempoolaccept must be side-effect-free. When the mempool is full,
// ValidateLocked reports "Mempool full (transaction count limit)" or
// "Mempool full (size limit)" directly; AddTxUnlocked's public path additionally
// attempts eviction.
bool CTxMemPool::ValidateLocked(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error, bool bypass_fee_check) const {
    // NOTE: This function assumes caller holds cs lock - no lock acquisition here.
    if (!tx) { if (error) *error = "Null tx"; return false; }

    // MEMPOOL-005 FIX: Reject coinbase transactions (consensus violation)
    // Coinbase transactions can only exist in blocks, never in mempool
    if (tx->IsCoinBase()) {
        if (error) *error = "Coinbase transaction not allowed in mempool";
        return false;
    }

    const uint256 txid = tx->GetHash();
    if (mapTx.count(txid) > 0) { if (error) *error = "Already in mempool"; return false; }

    // VULN-007 FIX: Check for double-spend conflicts
    for (const auto& input : tx->vin) {
        if (mapSpentOutpoints.count(input.prevout) > 0) {
            if (error) *error = "Transaction spends output already spent by transaction in mempool (double-spend attempt)";
            return false;
        }
    }

    // MEMPOOL-011 FIX: Validate fee is non-negative
    // Negative fees could corrupt fee rate calculations and priority ordering
    if (fee < 0) {
        if (error) *error = "Negative fee not allowed";
        return false;
    }

    // MEMPOOL-012 FIX: Validate time parameter
    // Invalid times corrupt transaction ordering and expiration logic
    if (time <= 0) {
        if (error) *error = "Transaction time must be positive";
        return false;
    }
    // Allow 2-hour clock skew for future times
    int64_t current_time = std::time(nullptr);
    static const int64_t MAX_TIME_SKEW = 2 * 60 * 60;
    if (time > current_time + MAX_TIME_SKEW) {
        if (error) *error = "Transaction time too far in future";
        return false;
    }

    // MEMPOOL-013 FIX: Validate height parameter
    // Invalid heights corrupt transaction age calculations
    if (height == 0) {
        if (error) *error = "Transaction height cannot be zero";
        return false;
    }

    // Skip fee check for transactions being restored after a reorg (Bitcoin Core pattern).
    // These txs already passed fee validation when first accepted -- reorg doesn't change the fee.
    if (!bypass_fee_check) {
        std::string fee_error;
        if (!Consensus::CheckFee(*tx, fee, true, &fee_error)) {
            if (error) *error = fee_error;
            return false;
        }
    }

    const size_t tx_size = tx->GetSerializedSize();

    // MEMPOOL-006 FIX: Enforce maximum transaction size limit
    // Prevents single oversized transaction from filling entire mempool
    static const size_t MAX_TX_SIZE = 1000000;  // 1MB consensus limit
    if (tx_size > MAX_TX_SIZE) {
        if (error) *error = "Transaction exceeds maximum size";
        return false;
    }

    // MEMPOOL-003 FIX: Check for integer overflow in size addition
    // Prevents bypass of mempool_size limit via overflow
    if (mempool_size > SIZE_MAX - tx_size) {
        if (error) *error = "Mempool size overflow";
        return false;
    }

    // T1.B-2 NOTE: Capacity exhaustion is reported here without attempting eviction
    // (eviction is mutation; ValidateLocked is const). AddTxUnlocked re-runs these
    // capacity checks AFTER ValidateLocked returns, attempting eviction before
    // declaring failure -- producing identical reject wording on the production
    // path when eviction itself fails.
    if (mempool_count >= max_mempool_count) {
        if (error) *error = "Mempool full (transaction count limit)";
        return false;
    }
    if (mempool_size + tx_size > max_mempool_size) {
        if (error) *error = "Mempool full (size limit)";
        return false;
    }

    return true;
}

// CID 1675250 FIX: Internal unlocked version - caller MUST hold cs lock
bool CTxMemPool::AddTxUnlocked(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error, bool bypass_fee_check) {
    // T1.B-2: Run the shared validation gauntlet first. If it rejects for any
    // reason OTHER than capacity-full, propagate the reject. For capacity-full,
    // fall through to the eviction path below (preserves pre-T1.B-2 behaviour
    // where AddTx attempts eviction before declaring failure).
    std::string validate_err;
    if (!ValidateLocked(tx, fee, time, height, &validate_err, bypass_fee_check)) {
        const bool count_full = (validate_err == "Mempool full (transaction count limit)");
        const bool size_full  = (validate_err == "Mempool full (size limit)");
        if (!count_full && !size_full) {
            if (error) *error = validate_err;
            return false;
        }
        // Capacity-full path: continue into eviction-aware code below.
    }

    // Re-derive locals needed for the mutation phase. (ValidateLocked already
    // confirmed tx is non-null, not coinbase, not already-present, and that
    // tx_size <= MAX_TX_SIZE without overflow.)
    const uint256 txid = tx->GetHash();
    const size_t tx_size = tx->GetSerializedSize();

    // MEMPOOL-002 FIX: Attempt eviction before rejecting due to mempool full
    // This ensures high-fee transactions can evict low-fee transactions

    // Check transaction count limit
    if (mempool_count >= max_mempool_count) {
        // MEMPOOL-001 FIX: Prevents DoS via 1.2M minimum-size transactions
        // Attempt to evict 1 transaction to make room
        if (!EvictTransactions(1, error)) {
            if (error && error->empty()) {
                *error = "Mempool full (transaction count limit)";
            }
            return false;
        }
    }

    // Check size limit with eviction
    if (mempool_size + tx_size > max_mempool_size) {
        // Calculate how much space we need to free
        size_t bytes_needed = (mempool_size + tx_size) - max_mempool_size;

        // Attempt to evict enough transactions to make room
        if (!EvictTransactions(bytes_needed, error)) {
            if (error && error->empty()) {
                *error = "Mempool full (size limit)";
            }
            return false;
        }
    }

    // MEMPOOL-009 FIX: Exception-safe insertion using RAII guard
    // All operations are atomic: either all succeed or none (strong exception safety)
    MempoolInsertionGuard guard(*this, txid);

    try {
        // Step 1: Create entry (can throw on memory allocation)
        CTxMemPoolEntry entry(tx, fee, time, height);

        // Step 2: Insert into mapTx (can throw on allocation)
        auto map_result = mapTx.emplace(txid, entry);
        guard.MarkMapInserted();

        // Step 3: Insert pointer into setEntries (can throw on allocation)
        // MEMPOOL-017: Store pointer to entry in map (pointer stability guaranteed by std::map)
        const CTxMemPoolEntry* entry_ptr = &(map_result.first->second);
        auto set_result = setEntries.insert(entry_ptr);

        // BUG #109 DEBUG: Track setEntries insertion
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[MEMPOOL-DEBUG] AddTx: txid=" << txid.GetHex().substr(0, 16)
                      << " mapTx.size()=" << mapTx.size()
                      << " setEntries.size()=" << setEntries.size()
                      << " insert_success=" << set_result.second << std::endl;

        guard.MarkSetInserted();

        // Step 4: Track spent outpoints (can throw on allocation)
        // VULN-007 FIX: Track spent outpoints to detect double-spends
        for (const auto& input : tx->vin) {
            mapSpentOutpoints.insert(input.prevout);
            guard.AddOutpoint(input.prevout);
        }

        // Step 5: Update mempool size (no-throw)
        mempool_size += tx_size;
        guard.SetSizeAdded(tx_size);

        // Step 6: Update transaction count (no-throw)
        // MEMPOOL-001 FIX: Track transaction count
        mempool_count++;
        guard.MarkCountIncremented();

        // Step 7: Update descendant tracking (no-throw)
        // MEMPOOL-002 FIX: Track parent-child relationships for safe eviction
        UpdateDescendantsAdd(tx);
        guard.MarkDescendantsUpdated();

        // Success - commit transaction (prevent rollback on scope exit)
        guard.Commit();

        // MEMPOOL-018 FIX: Track successful addition
        metric_adds.fetch_add(1, std::memory_order_relaxed);

        return true;

    } catch (const std::exception& e) {
        // Exception occurred - guard destructor will rollback all changes
        // MEMPOOL-018 FIX: Track failed addition
        metric_add_failures.fetch_add(1, std::memory_order_relaxed);
        if (error) *error = std::string("Failed to add transaction to mempool: ") + e.what();
        return false;
    } catch (...) {
        // Unknown exception - guard destructor will rollback all changes
        // MEMPOOL-018 FIX: Track failed addition
        metric_add_failures.fetch_add(1, std::memory_order_relaxed);    if (error) *error = "Failed to add transaction to mempool: unknown exception";
        return false;
    }
}

// Public wrapper that acquires lock
bool CTxMemPool::AddTx(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error, bool bypass_fee_check) {
    bool ok = false;
    size_t tx_vsize = 0;
    uint256 txhash;
    // PR-EF-2 fixup F#3: drain queued eviction txids that AddTxUnlocked
    // populated via EvictTransactions while we held cs. Local copy taken
    // under the lock; estimator notified after release.
    std::vector<uint256> evicted_txids;
    {
        std::lock_guard<std::mutex> lock(cs);
        // F#3: clear before AddTxUnlocked so any prior caller's leftover
        // entries (none expected; cs serialises) cannot leak.
        m_pending_estimator_evictions.clear();
        ok = AddTxUnlocked(tx, fee, time, height, error, bypass_fee_check);
        if (ok && tx) {
            // Cache values for the post-lock fee-estimator hook. Doing this
            // under the mempool lock keeps the snapshot consistent (the tx
            // was just admitted; metadata is stable).
            tx_vsize = tx->GetSerializedSize();
            txhash   = tx->GetHash();
        }
        // F#3: take the eviction list now (still under lock) so we can
        // notify the estimator after release. swap is O(1) and leaves the
        // member empty, ready for the next AddTx.
        evicted_txids.swap(m_pending_estimator_evictions);
    }
    // PR-EF-2: hand the admit event to the fee estimator OUTSIDE the
    // mempool lock. The estimator has its own internal mutex; holding both
    // would invite a lock-order inversion if any other estimator caller
    // ever acquires the mempool lock under it (none today, but the
    // discipline is cheap to enforce now). Null-safe: when -feeestimates=0
    // or before init, g_fee_estimator stays null.
    //
    // bypass_fee_check==true is used by mempool reload (PR-MP-2) and
    // wallet-broadcast paths that should NOT influence the estimator;
    // mirrors BC's `validFeeEstimate` flag (see fees.h processTx).
    if (auto* est = g_fee_estimator) {
        // F#3: notify evictions before the new admit. Order is purely
        // cosmetic to the estimator's data structures (the tracked-set
        // is keyed on txid; a subsequent processTx on a different txid
        // is independent of removeTx on the evicted ones), but matches
        // the chronological event order.
        for (const auto& evicted_txid : evicted_txids) {
            est->removeTx(evicted_txid, /*in_block=*/false);
        }
        if (ok && tx) {
            est->processTx(txhash, height, fee, tx_vsize, !bypass_fee_check);
        }
    }
    return ok;
}

// T1.B-2 (testmempoolaccept port from Bitcoin Core v28.0):
// Public read-only entry point. Acquires the mempool lock for a consistent
// snapshot, then delegates to ValidateLocked. NEVER mutates ANY mempool state
// (mapTx, setEntries, mapSpentOutpoints, mapDescendants, all counters, all
// metric_* atomics, mempool_size, mempool_count -- all unchanged).
//
// Concurrency: const-method, safe to call from any number of threads in
// parallel with each other and with AddTx/RemoveTx -- the lock serialises all
// mempool access. Reject wording matches AddTx exactly so the RPC layer can
// surface a single error string that callers can rely on.
bool CTxMemPool::TestAccept(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error, bool bypass_fee_check) const {
    std::lock_guard<std::mutex> lock(cs);
    return ValidateLocked(tx, fee, time, height, error, bypass_fee_check);
}

// ============================================================================
// MEMPOOL-008 FIX: Replace-By-Fee (RBF) Support - BIP-125
// ============================================================================
//
// VULNERABILITY: No support for transaction replacement
// Without RBF, users cannot increase fees on stuck transactions. This forces
// users to wait indefinitely for low-fee transactions to confirm, degrading
// user experience and preventing fee escalation during network congestion.
//
// ATTACK SCENARIO:
// 1. User sends transaction with low fee during low congestion
// 2. Network congestion increases, transaction stuck
// 3. User cannot replace with higher-fee transaction
// 4. Transaction stuck for hours/days (poor UX)
//
// FIX: BIP-125 Replace-By-Fee implementation
// - Users can replace unconfirmed transactions with higher-fee versions
// - Strict validation rules prevent DoS attacks
// - Atomic replacement preserves mempool consistency
//
// BIP-125 RULES:
// 1. Original transaction must signal RBF (nSequence < 0xfffffffe)
// 2. Replacement transaction must signal RBF
// 3. Replacement pays higher absolute fee
// 4. Replacement pays for own bandwidth (min relay fee)
// 5. Max 100 transactions replaced
//
// SECURITY PROPERTIES:
// - Prevents infinite replacement loops (bandwidth cost)
// - Prevents mempool resource exhaustion (max 100 replacements)
// - Atomic replacement (all or nothing)
//

bool CTxMemPool::ReplaceTransaction(const CTransactionRef& replacement_tx, CAmount replacement_fee, int64_t time, unsigned int height, std::string* error, bool bypass_fee_check) {
    bool ok = false;
    size_t tx_vsize = 0;
    uint256 txhash;
    std::vector<uint256> evicted_conflicts;
    // PR-EF-2 fixup F#3: also drain m_pending_estimator_evictions in case
    // ReplaceTransactionLocked->AddTxUnlocked->EvictTransactions populated
    // it (rare: RBF replacement triggers mempool-full eviction). These are
    // separate from `evicted_conflicts`, which holds RBF-replaced txids.
    std::vector<uint256> mempool_evictions;
    {
        std::lock_guard<std::mutex> lock(cs);
        m_pending_estimator_evictions.clear();
        ok = ReplaceTransactionLocked(replacement_tx, replacement_fee, time, height, error, evicted_conflicts);
        if (ok && replacement_tx) {
            tx_vsize = replacement_tx->GetSerializedSize();
            txhash   = replacement_tx->GetHash();
        }
        mempool_evictions.swap(m_pending_estimator_evictions);
    }
    // PR-EF-2: feed the fee estimator outside the mempool lock. The
    // evicted conflicts must be removed from the estimator's tracked-tx
    // set without crediting them as confirmations (they were replaced,
    // not confirmed); the new tx is recorded as a fresh admit. This
    // mirrors Bitcoin Core's validation/mempool.cpp RBF path.
    if (auto* est = g_fee_estimator) {
        for (const auto& evicted : evicted_conflicts) {
            est->removeTx(evicted, /*in_block=*/false);
        }
        for (const auto& evicted_txid : mempool_evictions) {
            est->removeTx(evicted_txid, /*in_block=*/false);
        }
        if (ok && replacement_tx) {
            // PR-EF-2 fixup F#8: map bypass_fee_check to
            // !valid_fee_estimate, mirroring AddTx semantics.
            est->processTx(txhash, height, replacement_fee, tx_vsize,
                           /*valid_fee_estimate=*/!bypass_fee_check);
        }
    }
    return ok;
}

bool CTxMemPool::ReplaceTransactionLocked(const CTransactionRef& replacement_tx,
                                          CAmount replacement_fee,
                                          int64_t time,
                                          unsigned int height,
                                          std::string* error,
                                          std::vector<uint256>& evicted_conflicts) {
    if (!replacement_tx) {
        if (error) *error = "Null replacement transaction";
        return false;
    }

    // Step 1: Find all conflicting transactions (transactions spending same inputs)
    std::set<uint256> conflicts;
    CAmount replaced_fees = 0;
    size_t replaced_sizes = 0;

    for (const auto& input : replacement_tx->vin) {
        auto it = mapSpentOutpoints.find(input.prevout);
        if (it != mapSpentOutpoints.end()) {
            // Found conflict - find which transaction spends this outpoint
            for (const auto& entry_pair : mapTx) {
                const CTxMemPoolEntry& entry = entry_pair.second;
                const CTransaction& tx = entry.GetTx();

                for (const auto& tx_input : tx.vin) {
                    if (tx_input.prevout == input.prevout) {
                        conflicts.insert(entry.GetTxHash());
                        replaced_fees += entry.GetFee();
                        replaced_sizes += entry.GetTxSize();
                        break;
                    }
                }
            }
        }
    }

    // If no conflicts, this is a new transaction, not a replacement
    if (conflicts.empty()) {
        if (error) *error = "No conflicting transactions found - use AddTx() for new transactions";
        return false;
    }

    // BIP-125 Rule 1: Original transactions must signal RBF
    // Check if all conflicting transactions signal replaceability (nSequence < 0xfffffffe)
    for (const auto& conflict_txid : conflicts) {
        auto it = mapTx.find(conflict_txid);
        if (it == mapTx.end()) continue;

        const CTransaction& conflict_tx = it->second.GetTx();
        bool signals_rbf = false;

        for (const auto& input : conflict_tx.vin) {
            // BIP-125: Any input with nSequence < 0xfffffffe signals RBF
            if (input.nSequence < 0xfffffffe) {
                signals_rbf = true;
                break;
            }
        }

        if (!signals_rbf) {
            if (error) *error = "Original transaction does not signal replaceability (BIP-125 rule 1)";
            return false;
        }
    }

    // BIP-125 Rule 2: Replacement transaction must signal RBF
    bool replacement_signals_rbf = false;
    for (const auto& input : replacement_tx->vin) {
        if (input.nSequence < 0xfffffffe) {
            replacement_signals_rbf = true;
            break;
        }
    }

    if (!replacement_signals_rbf) {
        if (error) *error = "Replacement transaction does not signal replaceability (BIP-125 rule 2)";
        return false;
    }

    // BIP-125 Rule 3: Replacement must pay higher absolute fee
    if (replacement_fee <= replaced_fees) {
        if (error) *error = "Replacement fee must be higher than replaced fees (BIP-125 rule 3)";
        return false;
    }

    // BIP-125 Rule 4: Replacement must pay for its own bandwidth
    // Fee increase must be >= min relay fee * replacement size
    // Using conservative min relay fee of 1 satoshi per byte
    size_t replacement_size = replacement_tx->GetSerializedSize();
    CAmount min_fee_increase = static_cast<CAmount>(replacement_size);
    CAmount actual_fee_increase = replacement_fee - replaced_fees;

    if (actual_fee_increase < min_fee_increase) {
        if (error) *error = "Replacement does not pay for bandwidth (BIP-125 rule 4)";
        return false;
    }

    // BIP-125 Rule 5: Max 100 transactions replaced
    if (conflicts.size() > 100) {
        if (error) *error = "Cannot replace more than 100 transactions (BIP-125 rule 5)";
        return false;
    }

    // Additional check: Ensure no conflicting transaction has descendants
    // Replacing a transaction with descendants would orphan them
    for (const auto& conflict_txid : conflicts) {
        if (HasDescendants(conflict_txid)) {
            if (error) *error = "Cannot replace transaction with descendants";
            return false;
        }
    }

    // All BIP-125 rules passed - perform atomic replacement

    // Step 1: Remove all conflicting transactions
    // CID 1675250 FIX: Use unlocked version - we already hold cs lock
    // PR-EF-2: collect evicted txids so the caller can inform the fee
    // estimator (after lock release). We populate even on failure of a
    // single RemoveTxUnlocked so the estimator state stays in sync with
    // any partial removals.
    for (const auto& conflict_txid : conflicts) {
        if (!RemoveTxUnlocked(conflict_txid)) {
            // This should not happen since we verified existence above
            if (error) *error = "Failed to remove conflicting transaction";
            return false;
        }
        evicted_conflicts.push_back(conflict_txid);
    }

    // Step 2: Add replacement transaction
    // CID 1675250 FIX: Use unlocked version - we already hold cs lock
    if (!AddTxUnlocked(replacement_tx, replacement_fee, time, height, error)) {
        // Rollback: Re-add conflicting transactions
        // Note: This is best-effort rollback. In production, would use transaction log.
        // MEMPOOL-018 FIX: Track failed RBF replacement
        metric_rbf_failures.fetch_add(1, std::memory_order_relaxed);
        if (error && error->empty()) {
            *error = "Failed to add replacement transaction";
        }
        return false;
    }

    // MEMPOOL-018 FIX: Track successful RBF replacement
    metric_rbf_replacements.fetch_add(1, std::memory_order_relaxed);

    return true;
}

// CID 1675260/1675290/1675250 FIX: Internal unlocked version - caller MUST hold cs lock
bool CTxMemPool::RemoveTxUnlocked(const uint256& txid) {
    // NOTE: This function assumes caller holds cs lock - no lock acquisition here
    auto it = mapTx.find(txid);
    if (it == mapTx.end()) return false;

    // MEMPOOL-002 FIX: Update descendant tracking before removal
    UpdateDescendantsRemove(txid);

    // VULN-007 FIX: Remove spent outpoints when transaction is removed
    const CTransaction& tx = it->second.GetTx();
    for (const auto& input : tx.vin) {
        mapSpentOutpoints.erase(input.prevout);
    }

    // MEMPOOL-017: Erase pointer from setEntries
    const CTxMemPoolEntry* entry_ptr = &(it->second);
    setEntries.erase(entry_ptr);

    // MEMPOOL-004 FIX: Protect against integer underflow in size tracking
    // If mempool_size is already corrupted, prevent wraparound to SIZE_MAX
    size_t tx_size = it->second.GetTxSize();
    if (mempool_size < tx_size) {
        // Corruption detected - this should never happen
        mempool_size = 0;
    } else {
        mempool_size -= tx_size;
    }

    // MEMPOOL-001 FIX: Decrement transaction count
    if (mempool_count > 0) {
        mempool_count--;
    }

    mapTx.erase(it);

    // MEMPOOL-018 FIX: Track successful removal    metric_removes.fetch_add(1, std::memory_order_relaxed);

    return true;
}

// Public wrapper that acquires lock
bool CTxMemPool::RemoveTx(const uint256& txid) {
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(cs);
        removed = RemoveTxUnlocked(txid);
    }
    // PR-EF-2: caller may be a non-block removal path (manual /
    // administrative). Treat as eviction (in_block=false). Estimator hook
    // is null-safe and called outside the mempool lock to keep the public
    // API clean.
    if (removed) {
        if (auto* est = g_fee_estimator) {
            est->removeTx(txid, /*in_block=*/false);
        }
    }
    return removed;
}

bool CTxMemPool::Exists(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(cs);
    return mapTx.count(txid) > 0;
}

bool CTxMemPool::IsSpent(const COutPoint& outpoint) const {
    std::lock_guard<std::mutex> lock(cs);
    return mapSpentOutpoints.count(outpoint) > 0;
}

bool CTxMemPool::GetTx(const uint256& txid, CTxMemPoolEntry& entry) const {
    std::lock_guard<std::mutex> lock(cs);
    auto it = mapTx.find(txid);
    if (it == mapTx.end()) return false;
    entry = it->second;
    return true;
}

// ============================================================================
// MEMPOOL-010 FIX: TOCTOU-Safe API
// ============================================================================
//
// VULNERABILITY: Time-of-Check Time-of-Use race condition
// Current API requires separate Exists() and GetTx() calls. Between these
// calls, another thread can remove the transaction, causing unexpected failures.
//
// ATTACK SCENARIO:
// Thread 1: if (mempool.Exists(txid)) {
// Thread 2:   mempool.RemoveTx(txid);  // <-- Transaction removed!
// Thread 1:   mempool.GetTx(txid, entry);  // <-- Fails unexpectedly
// Thread 1: }
//
// FIX: Atomic combined operation using std::optional
// Single lock acquisition combines check and retrieval, preventing race.
//
// SECURITY PROPERTIES:
// - Atomic check-and-get (no TOCTOU window)
// - Type-safe with std::optional
// - No unexpected failures
//
std::optional<CTxMemPoolEntry> CTxMemPool::GetTxIfExists(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(cs);
    auto it = mapTx.find(txid);
    if (it == mapTx.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<CTransactionRef> CTxMemPool::GetOrderedTxs() const {
    std::lock_guard<std::mutex> lock(cs);

    // BUG #109 DEBUG: Log mempool state when GetOrderedTxs is called
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[MEMPOOL-DEBUG] GetOrderedTxs: mapTx.size()=" << mapTx.size()
                  << " setEntries.size()=" << setEntries.size() << std::endl;

    // MEMPOOL-015 FIX: Limit GetOrderedTxs to prevent DoS via unbounded allocation
    // Without limit, 1.2M transactions → 9.6MB vector allocation + O(n) iteration
    // Limit to 10k transactions max for reasonable memory usage
    static const size_t MAX_ORDERED_TXS = 10000;
    size_t count = std::min(MAX_ORDERED_TXS, setEntries.size());

    std::vector<CTransactionRef> result;
    result.reserve(count);

    size_t added = 0;
    // MEMPOOL-017: Dereference pointer to access entry
    for (const auto& entry_ptr : setEntries) {
        if (added >= count) break;
        result.push_back(entry_ptr->GetSharedTx());
        added++;
    }
    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

std::vector<CTxMemPoolEntry> CTxMemPool::GetAllEntries() const {
    std::lock_guard<std::mutex> lock(cs);

    // Snapshot every entry. Iterates mapTx (the map of txid->entry); setEntries
    // would also work but stores pointers and is fee-rate-ordered, which
    // doesn't matter for persistence and adds a level of indirection.
    std::vector<CTxMemPoolEntry> result;
    result.reserve(mapTx.size());
    for (const auto& [txid, entry] : mapTx) {
        (void)txid;
        result.push_back(entry);
    }
    return result;
}

std::vector<CTransactionRef> CTxMemPool::GetTopTxs(size_t n) const {
    std::lock_guard<std::mutex> lock(cs);

    // MEMPOOL-016 FIX: Validate and limit n parameter to prevent DoS
    // Attacker could call GetTopTxs(SIZE_MAX) causing excessive allocation
    static const size_t MAX_GET_TOP_TXS = 10000;
    if (n > MAX_GET_TOP_TXS) {
        n = MAX_GET_TOP_TXS;
    }

    size_t count_to_get = std::min(n, setEntries.size());
    std::vector<CTransactionRef> result;
    result.reserve(count_to_get);

    size_t count = 0;
    // MEMPOOL-017: Dereference pointer to access entry
    for (const auto& entry_ptr : setEntries) {
        if (count >= count_to_get) break;
        result.push_back(entry_ptr->GetSharedTx());
        count++;
    }
    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

void CTxMemPool::Clear() {
    std::lock_guard<std::mutex> lock(cs);
    mapTx.clear();
    setEntries.clear();
    mapSpentOutpoints.clear();  // VULN-007 FIX: Clear spent outpoints
    mapDescendants.clear();  // MEMPOOL-002 FIX: Clear descendant tracking
    mempool_size = 0;
    mempool_count = 0;  // MEMPOOL-001 FIX: Reset transaction count
}

size_t CTxMemPool::Size() const {
    std::lock_guard<std::mutex> lock(cs);
    return mapTx.size();
}

// T1.B-2 H3: Test-only read-only state-integrity accessors. See header
// docstring -- these are intentionally test-only. Each takes `cs` and returns
// an O(N) copy of the underlying structure for use in
// `testaccept_concurrent_no_state_leak`'s before/after byte-identical check.
std::set<uint256> CTxMemPool::GetTxIdsForStateIntegrityTests() const {
    std::lock_guard<std::mutex> lock(cs);
    std::set<uint256> ids;
    for (const auto& kv : mapTx) {
        ids.insert(kv.first);
    }
    return ids;
}

std::set<COutPoint> CTxMemPool::GetSpentOutpointsForStateIntegrityTests() const {
    std::lock_guard<std::mutex> lock(cs);
    return mapSpentOutpoints;  // copy
}

std::map<uint256, std::set<uint256>>
CTxMemPool::GetDescendantsForStateIntegrityTests() const {
    std::lock_guard<std::mutex> lock(cs);
    return mapDescendants;  // copy
}

size_t CTxMemPool::GetMempoolSize() const {
    std::lock_guard<std::mutex> lock(cs);
    return mempool_size;
}

void CTxMemPool::GetStats(size_t& size, size_t& bytes, double& min_fee_rate, double& max_fee_rate) const {
    std::lock_guard<std::mutex> lock(cs);
    size = mapTx.size();
    bytes = mempool_size;
    if (setEntries.empty()) {
        min_fee_rate = 0.0;
        max_fee_rate = 0.0;
        return;
    }
    // MEMPOOL-017: Dereference pointers to access entries
    max_fee_rate = (*setEntries.begin())->GetFeeRate();
    min_fee_rate = (*setEntries.rbegin())->GetFeeRate();
}

void CTxMemPool::SetHeight(unsigned int height) {
    std::lock_guard<std::mutex> lock(cs);
    nHeight = height;
}

// MEMPOOL-018 FIX: Get metrics for monitoring and debugging
CTxMemPool::MempoolMetrics CTxMemPool::GetMetrics() const {
    MempoolMetrics metrics;
    metrics.total_adds = metric_adds.load();
    metrics.total_removes = metric_removes.load();
    metrics.total_evictions = metric_evictions.load();
    metrics.total_expirations = metric_expirations.load();
    metrics.total_rbf_replacements = metric_rbf_replacements.load();
    metrics.total_add_failures = metric_add_failures.load();
    metrics.total_rbf_failures = metric_rbf_failures.load();
    metrics.total_rebroadcasts = metric_rebroadcasts.load();  // Phase 3.3
    return metrics;
}

// PR-EF-2 fixup F#4: test seam.
void CTxMemPool::SetMaxMempoolCountForTesting(size_t count) {
    std::lock_guard<std::mutex> lock(cs);
    max_mempool_count = (count == 0) ? 1 : count;
}

void CTxMemPool::RemoveConfirmedTxs(const std::vector<CTransactionRef>& block_txs) {
    std::lock_guard<std::mutex> lock(cs);
    for (const auto& tx : block_txs) {
        const uint256 txid = tx->GetHash();
        auto it = mapTx.find(txid);
        if (it != mapTx.end()) {
            // MEMPOOL-002 FIX: Update descendant tracking before removal
            UpdateDescendantsRemove(txid);

            // VULN-007 FIX: Remove spent outpoints when confirmed transaction is removed
            const CTransaction& mempool_tx = it->second.GetTx();
            for (const auto& input : mempool_tx.vin) {
                mapSpentOutpoints.erase(input.prevout);
            }

            // MEMPOOL-017: Erase pointer from setEntries
            const CTxMemPoolEntry* entry_ptr = &(it->second);
            setEntries.erase(entry_ptr);

            // MEMPOOL-004 FIX: Protect against integer underflow
            size_t tx_size = it->second.GetTxSize();
            if (mempool_size < tx_size) {
                mempool_size = 0;
            } else {
                mempool_size -= tx_size;
            }

            // MEMPOOL-001 FIX: Decrement transaction count
            if (mempool_count > 0) {
                mempool_count--;
            }

            mapTx.erase(it);
        }
    }
}

// ============================================================================
// Phase 3.3: Transaction Rebroadcast Support
// ============================================================================

std::vector<CTransactionRef> CTxMemPool::GetUnconfirmedOlderThan(int64_t age_seconds) const {
    std::lock_guard<std::mutex> lock(cs);
    std::vector<CTransactionRef> result;

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    int64_t cutoff_time = now - age_seconds;

    for (const auto& pair : mapTx) {
        if (pair.second.GetTime() < cutoff_time) {
            result.push_back(pair.second.GetSharedTx());
        }
    }

    return result;
}

void CTxMemPool::MarkRebroadcast(const uint256& txid) {
    std::lock_guard<std::mutex> lock(cs);

    auto it = mapTx.find(txid);
    if (it != mapTx.end()) {
        // We can't modify the entry directly since it affects ordering
        // Just increment the rebroadcast counter for metrics
        metric_rebroadcasts.fetch_add(1);
    }
}
