// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_MEMPOOL_H
#define DILITHION_NODE_MEMPOOL_H

#include <primitives/transaction.h>
#include <consensus/fees.h>
#include <amount.h>
#include <uint256.h>
#include <map>
#include <set>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <optional>

class CTxMemPoolEntry {
private:
    CTransactionRef tx;
    uint256 tx_hash;  // Cached transaction hash
    CAmount fee;
    size_t tx_size;
    double fee_rate;
    int64_t time;
    unsigned int height;
public:
    CTxMemPoolEntry(const CTransactionRef& _tx, CAmount _fee, int64_t _time, unsigned int _height);
    const CTransaction& GetTx() const { return *tx; }
    CTransactionRef GetSharedTx() const { return tx; }
    const uint256& GetTxHash() const { return tx_hash; }
    CAmount GetFee() const { return fee; }
    size_t GetTxSize() const { return tx_size; }
    double GetFeeRate() const { return fee_rate; }
    int64_t GetTime() const { return time; }
    unsigned int GetHeight() const { return height; }
};

// MEMPOOL-017 FIX: Pointer-based comparator for memory optimization
// Allows setEntries to store pointers instead of copies, reducing memory usage by 50%
struct CompareTxMemPoolEntryByFeeRate {
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const;
    bool operator()(const CTxMemPoolEntry* a, const CTxMemPoolEntry* b) const;
};

// MEMPOOL-009 FIX: Forward declaration for exception safety guard
class MempoolInsertionGuard;

class CTxMemPool {
private:
    // MEMPOOL-009 FIX: Grant friend access to RAII guard for rollback operations
    friend class MempoolInsertionGuard;
    mutable std::mutex cs;
    std::map<uint256, CTxMemPoolEntry> mapTx;
    // MEMPOOL-017 FIX: Store pointers instead of copies to reduce memory usage by 50%
    // std::map provides pointer stability in C++11+, so pointers remain valid until element erased
    std::set<const CTxMemPoolEntry*, CompareTxMemPoolEntryByFeeRate> setEntries;
    std::set<COutPoint> mapSpentOutpoints;  // VULN-007 FIX: Track spent outpoints to detect double-spends

    // MEMPOOL-002 FIX: Descendant tracking to prevent orphaning child transactions during eviction
    // Maps transaction hash → set of transaction hashes that spend its outputs (children)
    // This ensures we never evict a transaction that has descendants in the mempool
    std::map<uint256, std::set<uint256>> mapDescendants;

    unsigned int nHeight;

    // MEMPOOL-001 FIX: Add transaction count limit to prevent DoS
    // Without count limit, attacker can fill mempool with 1.2M minimum-size transactions
    // causing excessive std::map/std::set overhead (160 bytes per transaction = 192MB overhead)
    // and severe O(n) performance degradation
    static const size_t DEFAULT_MAX_MEMPOOL_COUNT = 100000;  // 100k transactions limit

    size_t max_mempool_size;
    size_t mempool_size;
    size_t max_mempool_count;
    size_t mempool_count;

    // MEMPOOL-007 FIX: Transaction expiration with background cleanup
    // Transactions older than 14 days are automatically removed
    static const int64_t MEMPOOL_EXPIRY_SECONDS = 14 * 24 * 60 * 60;  // 14 days
    std::thread expiration_thread;
    // SHUTDOWN LOST-WAKEUP FIX -- LOCKING RULE: stop_expiration_thread is
    // atomic so the expiration thread's outer loop can read it unlocked as a
    // fast path, but every WRITE must happen while holding expiration_mutex
    // (StopExpirationThread is the only writer). Writing it outside that mutex
    // reintroduces a lost wakeup that stalls shutdown for a full hour ahead of
    // every database close. Regression test: mempool_shutdown_wakeup_tests.
    std::atomic<bool> stop_expiration_thread;
    std::condition_variable expiration_cv;
    std::mutex expiration_mutex;

    // Test seam, production-inert: no production code names this type. The
    // shutdown lost-wakeup regression test needs to hold expiration_mutex
    // while a second thread calls StopExpirationThread(), which is the only
    // way to observe -- deterministically, without racing -- whether the stop
    // flag is written under that mutex.
    friend struct MempoolShutdownWakeupTestAccess;

    // MEMPOOL-018 FIX: Metrics tracking for monitoring and debugging
    // Atomic counters to track mempool operations without lock contention
    std::atomic<uint64_t> metric_adds;
    std::atomic<uint64_t> metric_removes;
    std::atomic<uint64_t> metric_evictions;
    std::atomic<uint64_t> metric_expirations;
    std::atomic<uint64_t> metric_rbf_replacements;
    std::atomic<uint64_t> metric_add_failures;
    std::atomic<uint64_t> metric_rbf_failures;

    // MEMPOOL-002 FIX: Private helper methods for eviction policy
    bool EvictTransactions(size_t bytes_needed, std::string* error = nullptr);
    bool HasDescendants(const uint256& txid) const;
    void UpdateDescendantsAdd(const CTransactionRef& tx);
    void UpdateDescendantsRemove(const uint256& txid);

    // MEMPOOL-007 FIX: Expiration cleanup methods
    void ExpirationThreadFunc();
public:
    // PR-EF-2 fixup F#3: public so tests can drive it directly. Called
    // from the background expiration thread and from tests that want to
    // verify the estimator-notify path. Internally takes cs, then notifies
    // g_fee_estimator OUTSIDE the lock (matches AddTx/RemoveTx/Replace
    // discipline).
    void CleanupExpiredTransactions();
private:

    // PR-EF-2 fixup F#3: queue of txids evicted during the most recent
    // EvictTransactions(...) call, populated under cs and drained by the
    // public AddTx wrapper AFTER the lock is released. Keeps the
    // estimator-notify call out-of-lock, matching the AddTx / RemoveTx /
    // ReplaceTransaction discipline. Implementation detail: lives on the
    // CTxMemPool instance (not a thread-local) because cs serialises
    // EvictTransactions calls.
    std::vector<uint256> m_pending_estimator_evictions;

    // CID 1675260/1675290/1675250 FIX: Internal unlocked versions to prevent deadlock
    // These MUST only be called while holding cs lock
    bool RemoveTxUnlocked(const uint256& txid);
    bool AddTxUnlocked(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error, bool bypass_fee_check = false);
    // PR-EF-2: ReplaceTransaction body. Caller MUST hold cs. Returns the
    // list of evicted txids so the public ReplaceTransaction wrapper can
    // notify the fee estimator outside the mempool lock. (Mempool's `cs`
    // and the estimator's internal mutex are independent; we serialize
    // the pure-mempool work first to keep the lock release / estimator
    // notify ordering uniform with AddTx.)
    bool ReplaceTransactionLocked(const CTransactionRef& replacement_tx,
                                  CAmount replacement_fee,
                                  int64_t time,
                                  unsigned int height,
                                  std::string* error,
                                  std::vector<uint256>& evicted_conflicts);

    // T1.B-2 (testmempoolaccept): Pure validation, NO mutation. Caller MUST hold cs lock.
    // Returns true iff the tx WOULD be accepted by AddTxUnlocked under the same arguments.
    // BYTE-FOR-BYTE equivalent to AddTxUnlocked's accept/reject logic; both paths share
    // this helper. Used by TestAccept() (read-only) and AddTxUnlocked() (validation phase).
    // On failure, sets *error to the same wording AddTxUnlocked uses for the same condition.
    // Note: cannot evaluate eviction (which is a mutation); when the mempool is full and
    // eviction would be required, ValidateLocked reports the would-be-full reject reason.
    // For testmempoolaccept this matches BC v28.0 semantics: "mempool full" is a reject.
    bool ValidateLocked(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error, bool bypass_fee_check) const;

public:
    CTxMemPool();
    ~CTxMemPool();  // MEMPOOL-007 FIX: Destructor to stop expiration thread
    bool AddTx(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error = nullptr, bool bypass_fee_check = false);
    bool RemoveTx(const uint256& txid);
    // T1.B-2 (testmempoolaccept port from Bitcoin Core v28.0): Run AddTx's full validation
    // pipeline against `tx` and return whether it WOULD be accepted, WITHOUT mutating any
    // mempool state (mapTx, setEntries, mapSpentOutpoints, mapDescendants, counters,
    // metrics -- all unchanged). Acquires cs internally. On failure, sets *error to the
    // exact reject reason that AddTx would have produced for the same condition (so the
    // RPC's reject-reason field matches sendrawtransaction's error verbatim).
    // Safe to call concurrently from multiple threads; const-method, read-only on the
    // shared mempool state guarded by cs.
    bool TestAccept(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, std::string* error = nullptr, bool bypass_fee_check = false) const;

    // MEMPOOL-008 FIX: RBF support.
    //
    // PR-EF-2 fixup F#8: bypass_fee_check defaults to false for live RBF.
    // Set true on mempool replay paths so the estimator records the
    // replacement with valid_fee_estimate=false, mirroring AddTx and
    // Bitcoin Core's validFeeEstimate flag. No production callers pass
    // true today; the parameter exists for symmetry with AddTx and to
    // give future replay/restore paths a clean way to opt out of
    // estimator pollution.
    bool ReplaceTransaction(const CTransactionRef& replacement_tx, CAmount replacement_fee, int64_t time, unsigned int height, std::string* error = nullptr, bool bypass_fee_check = false);
    bool Exists(const uint256& txid) const;
    bool GetTx(const uint256& txid, CTxMemPoolEntry& entry) const;
    std::optional<CTxMemPoolEntry> GetTxIfExists(const uint256& txid) const;  // MEMPOOL-010 FIX: TOCTOU-safe API
    std::vector<CTransactionRef> GetOrderedTxs() const;
    std::vector<CTransactionRef> GetTopTxs(size_t n) const;

    /**
     * Snapshot every CTxMemPoolEntry currently in the mempool.
     *
     * Used by the mempool-persist subsystem (see src/kernel/mempool_persist.h)
     * to dump the full mempool to disk on shutdown. Unlike GetOrderedTxs() and
     * GetTopTxs(), this returns the FULL ENTRY (with fee, time, height
     * metadata) rather than just CTransactionRef -- because mempool.dat needs
     * to round-trip the metadata for fee-estimator continuity.
     *
     * The returned vector is a SNAPSHOT under the mempool lock; copies are
     * cheap (CTxMemPoolEntry is small + holds a CTransactionRef which is
     * shared_ptr).
     *
     * No DoS limit on the count -- caller is the persist module which always
     * dumps the full mempool. If a future caller needs a bounded snapshot,
     * add a separate method.
     */
    std::vector<CTxMemPoolEntry> GetAllEntries() const;
    void Clear();
    size_t Size() const;
    size_t GetMempoolSize() const;
    void GetStats(size_t& size, size_t& bytes, double& min_fee_rate, double& max_fee_rate) const;
    void SetHeight(unsigned int height);
    void RemoveConfirmedTxs(const std::vector<CTransactionRef>& block_txs);

    // PR-EF-2 fixup F#4: test seam. Tests want to force eviction without
    // having to fill 300MB / 100k entries. Production callers do not set
    // this. New value is clamped to max(1, requested) to keep the eviction
    // loop well-defined; setting it below current count does NOT
    // retroactively evict (next AddTx will).
    void SetMaxMempoolCountForTesting(size_t count);

    // MEMPOOL-018 FIX: Get metrics for monitoring
    struct MempoolMetrics {
        uint64_t total_adds;
        uint64_t total_removes;
        uint64_t total_evictions;
        uint64_t total_expirations;
        uint64_t total_rbf_replacements;
        uint64_t total_add_failures;
        uint64_t total_rbf_failures;
        uint64_t total_rebroadcasts;  // Phase 3.3
    };
    MempoolMetrics GetMetrics() const;

    /**
     * x402 VMA: Check if an outpoint is spent by a mempool transaction
     * @param outpoint The outpoint to check
     * @return true if spent by a transaction in the mempool
     */
    bool IsSpent(const COutPoint& outpoint) const;

    /**
     * Phase 3.3: Get transactions older than specified age for rebroadcast
     * @param age_seconds Minimum age in seconds
     * @return Vector of transactions older than age_seconds
     */
    std::vector<CTransactionRef> GetUnconfirmedOlderThan(int64_t age_seconds) const;

    /**
     * Phase 3.3: Mark transaction as recently broadcast
     * Updates the transaction's time to prevent immediate re-broadcast
     * @param txid Transaction hash
     */
    void MarkRebroadcast(const uint256& txid);

    /**
     * Phase 3.3: Get rebroadcast count
     */
    uint64_t GetRebroadcastCount() const { return metric_rebroadcasts.load(); }

    // PR-EF-2 fixup F#1: Explicit, idempotent shutdown of the background
    // expiration thread. The destructor also stops it, but call sites that
    // share lifetime with other globals (e.g. g_fee_estimator) MUST stop the
    // expiration thread BEFORE freeing the estimator, otherwise the snapshot
    // pattern in CleanupExpiredTransactions can use-after-free.
    //
    // Safe to call multiple times (idempotent: second call is a no-op).
    // After this returns, no further calls into g_fee_estimator originate
    // from the expiration thread.
    void StopExpirationThread();

    /**
     * T1.B-2 H3: Read-only state-integrity accessors used by
     * `testaccept_concurrent_no_state_leak` to assert that a no-mutation
     * RPC like `testmempoolaccept` leaves the mempool BYTE-IDENTICAL.
     *
     * NOT for production use -- the names carry the
     * `*ForStateIntegrityTests` suffix to make their test-only purpose clear
     * at every call site. If a non-test caller needs these views, add a
     * separate accessor with a production-grade name and contract.
     *
     * Each method takes `cs` and returns a snapshot copy of the underlying
     * data structure. Cost is O(N); fine for tests, not for hot paths.
     */
    std::set<uint256> GetTxIdsForStateIntegrityTests() const;
    std::set<COutPoint> GetSpentOutpointsForStateIntegrityTests() const;
    std::map<uint256, std::set<uint256>> GetDescendantsForStateIntegrityTests() const;

private:
    // Phase 3.3: Rebroadcast tracking
    std::atomic<uint64_t> metric_rebroadcasts{0};
};

#endif
