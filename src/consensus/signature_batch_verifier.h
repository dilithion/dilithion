// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_SIGNATURE_BATCH_VERIFIER_H
#define DILITHION_CONSENSUS_SIGNATURE_BATCH_VERIFIER_H

/**
 * CSignatureBatchVerifier - Parallel signature verification for Dilithium3
 *
 * PHASE 3.2 PERFORMANCE OPTIMIZATION: Batch signature verification
 *
 * Problem: Dilithium3 signature verification takes ~2-3ms per signature.
 * A block with 1000 transactions (each with 1 input) takes ~2-3 seconds
 * for signature verification alone, blocking the validation thread.
 *
 * Solution: Verify signatures in parallel using a thread pool.
 * With 4 workers, a block with 1000 signatures takes ~500-750ms instead.
 *
 * Architecture (based on Bitcoin Core's CCheckQueue):
 * - Main thread collects signature verification tasks
 * - Worker threads verify signatures in parallel
 * - Results aggregated - any failure fails the batch
 *
 * Usage:
 *   CSignatureBatchVerifier verifier(4);  // 4 worker threads
 *   verifier.Start();
 *
 *   for (const auto& input : tx.vin) {
 *       verifier.Add(signature, message, pubkey);
 *   }
 *
 *   bool allValid = verifier.Wait();  // Blocks until all verified
 */

#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>
#include <functional>
#include <cstdint>
#include <string>
#include <memory>

/**
 * CBatchSession - Per-batch verification state (CCheckQueueControl pattern)
 *
 * CRITICAL-1 fix (LP-5): the mutable per-batch state used to live as instance
 * members of the process-wide CSignatureBatchVerifier global, so two concurrent
 * callers (the RPC worker pool races itself and the P2P thread) would clobber
 * each other's pending-count / failure flag / first-error and one caller's
 * Wait() could read another caller's verdict — accepting an invalid signature,
 * underflowing the shared counter (DoS hang), or diverging batch-vs-sequential.
 *
 * The fix mirrors Bitcoin Core's CCheckQueue/CCheckQueueControl split: the
 * worker POOL stays shared (preserving parallelism), but each batch owns its
 * own session. Every task carries a pointer to the session it belongs to;
 * a worker decrements THAT session's counter, records errors into THAT
 * session, and notifies THAT session's completion CV. Two concurrent batches
 * therefore cannot see or mutate each other's state.
 *
 * Lifetime: a session is created by BeginBatch(), kept alive (shared_ptr) by
 * both the caller's session handle AND every queued task referencing it, and
 * destroyed only after Wait() returns and all tasks have run. This makes
 * use-after-free of session state at teardown structurally impossible even if
 * the caller's handle is released while tasks are still draining.
 */
struct CBatchSession {
    std::atomic<size_t> pending_count{0};   // Tasks pending in THIS batch
    std::atomic<bool>   batch_failed{false}; // Any task in THIS batch failed?

    std::mutex          error_mutex;        // Guards first_error
    std::string         first_error;        // First error encountered in THIS batch

    // Completion notification for THIS batch. The mutex guards the wait
    // predicate (pending_count==0) AND the notify, so no wakeup is lost
    // (MED-2 fix): a worker driving pending_count to zero takes complete_mutex
    // before notifying, so a Wait() that has read a non-zero count but not yet
    // blocked cannot miss the notification.
    std::mutex              complete_mutex;
    std::condition_variable complete_cv;
};

/**
 * CSignatureTask - A single signature verification task
 */
struct CSignatureTask {
    std::vector<uint8_t> signature;      // Dilithium3 signature (3309 bytes)
    std::vector<uint8_t> message;        // Message that was signed (32 bytes hash)
    std::vector<uint8_t> pubkey;         // Dilithium3 public key (1952 bytes)
    std::shared_ptr<CBatchSession> session; // Batch this task belongs to (CRITICAL-1)
    size_t input_index;                  // Input index for error reporting
};

/**
 * CSignatureBatchVerifier - Parallel Dilithium3 signature verifier
 */
class CSignatureBatchVerifier {
public:
    /**
     * Constructor
     * @param num_workers Number of worker threads (default: 4)
     */
    explicit CSignatureBatchVerifier(size_t num_workers = DEFAULT_WORKERS);

    /**
     * Destructor - ensures all workers are stopped
     */
    ~CSignatureBatchVerifier();

    // Disable copy/move
    CSignatureBatchVerifier(const CSignatureBatchVerifier&) = delete;
    CSignatureBatchVerifier& operator=(const CSignatureBatchVerifier&) = delete;

    /**
     * Start worker threads
     * Must be called before adding tasks
     */
    void Start();

    /**
     * Stop worker threads
     * Called automatically by destructor
     */
    void Stop();

    /**
     * Begin a new batch of verifications.
     * Returns a fresh per-batch session that the caller owns for the whole
     * BeginBatch -> Add... -> Wait lifetime. Concurrent callers each get their
     * own session, so their batch state cannot cross-contaminate (CRITICAL-1).
     *
     * @return a shared_ptr to the new session; pass it to Add()/Wait().
     */
    std::shared_ptr<CBatchSession> BeginBatch();

    /**
     * Add a signature verification task to the given batch session.
     * Thread-safe, can be called from any thread.
     *
     * @param session The session returned by BeginBatch() for this batch
     * @param signature Dilithium3 signature bytes
     * @param message Message hash (32 bytes)
     * @param pubkey Dilithium3 public key bytes
     * @param input_index Input index for error reporting
     */
    void Add(const std::shared_ptr<CBatchSession>& session,
             const std::vector<uint8_t>& signature,
             const std::vector<uint8_t>& message,
             const std::vector<uint8_t>& pubkey,
             size_t input_index);

    /**
     * Wait for all tasks in the given batch session to complete.
     * @param session The session returned by BeginBatch() for this batch
     * @param error Output parameter - set to first error if any verification fails
     * @return true if ALL signatures verified successfully
     */
    bool Wait(const std::shared_ptr<CBatchSession>& session, std::string& error);

    /**
     * Check if verifier is running
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Get number of worker threads
     */
    size_t NumWorkers() const { return m_num_workers; }

    // Configuration constants
    static constexpr size_t DEFAULT_WORKERS = 4;
    static constexpr size_t MAX_WORKERS = 16;

private:
    /**
     * Worker thread main loop
     * Continuously processes tasks from the queue
     */
    void WorkerThread();

    /**
     * Verify a single signature
     * Called by worker threads
     * @param task The signature task to verify
     * @return true if signature is valid
     */
    bool VerifySingle(CSignatureTask& task);

    // Configuration
    size_t m_num_workers;

    // Worker threads
    std::vector<std::thread> m_workers;
    std::atomic<bool> m_running{false};

    // Task queue (the shared worker pool — CCheckQueue). Each queued task
    // carries its own CBatchSession pointer, so no per-batch state lives here.
    std::queue<CSignatureTask> m_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    // NOTE (CRITICAL-1 / LP-5): the former shared per-batch members
    // (m_pending_count / m_batch_failed / m_first_error / m_complete_*) have
    // been moved into CBatchSession so that each in-flight batch owns its own
    // state. The verifier object now holds ONLY the shared worker pool +
    // queue, which is concurrency-safe to share across batches.
};

/**
 * Global batch signature verifier instance
 * Initialized once, reused for all block/transaction validation
 */
extern CSignatureBatchVerifier* g_signature_verifier;

/**
 * Initialize global signature verifier
 * Called during node startup
 */
void InitSignatureVerifier(size_t num_workers = CSignatureBatchVerifier::DEFAULT_WORKERS);

/**
 * Shutdown global signature verifier
 * Called during node shutdown
 */
void ShutdownSignatureVerifier();

#endif // DILITHION_CONSENSUS_SIGNATURE_BATCH_VERIFIER_H
