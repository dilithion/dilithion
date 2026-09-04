// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// ============================================================================
// LP-5 / CRITICAL-1 CONTROL ARTIFACT — FROZEN PRE-FIX VERIFIER. DO NOT "FIX".
// ============================================================================
//
// This is a VERBATIM copy of the pre-fix CSignatureBatchVerifier as it existed
// at commit bb933d53 (`src/consensus/signature_batch_verifier.h`), BEFORE the
// LP-5 per-batch-session refactor. It exists ONLY to build the A-010 "control"
// variant of the race harness (`batch_verifier_race_tests.cpp` compiled with
// -DPREFIX_API), which deterministically HANGS on this code — proving the
// harness is a real discriminator, not a no-op that would pass on anything.
//
// Provenance: `git show bb933d53:src/consensus/signature_batch_verifier.h`.
// The ONLY edits relative to that source are:
//   - the include guard renamed (…_PREFIX_H) so it can coexist in-tree with the
//     fixed header without a redefinition clash;
//   - this provenance banner.
// The class shape, the shared per-batch members (m_pending_count /
// m_batch_failed / m_first_error / m_complete_*), and the sessionless
// BeginBatch()/Add()/Wait() signatures are EXACTLY the pre-fix code — that
// shared mutable batch state IS the bug the control reproduces.
//
// If you are tempted to make this compile "more cleanly" or share state with
// the fixed verifier: don't. The whole point is that it is the broken code.
// ============================================================================

#ifndef DILITHION_TEST_LP5_CONTROL_SIGNATURE_BATCH_VERIFIER_PREFIX_H
#define DILITHION_TEST_LP5_CONTROL_SIGNATURE_BATCH_VERIFIER_PREFIX_H

#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>
#include <functional>
#include <cstdint>
#include <string>

/**
 * CSignatureTask - A single signature verification task (PRE-FIX shape)
 */
struct CSignatureTask {
    std::vector<uint8_t> signature;      // Dilithium3 signature (3309 bytes)
    std::vector<uint8_t> message;        // Message that was signed (32 bytes hash)
    std::vector<uint8_t> pubkey;         // Dilithium3 public key (1952 bytes)
    std::string* error_out;              // Where to store error message if failed
    size_t input_index;                  // Input index for error reporting
};

/**
 * CSignatureBatchVerifier - Parallel Dilithium3 signature verifier (PRE-FIX)
 *
 * NOTE: shared per-batch state lives as instance members here — this is the
 * CRITICAL-1 race. Two concurrent BeginBatch/Add/Wait callers clobber each
 * other's m_pending_count, which the control harness drives into a size_t
 * underflow and a permanent Wait() hang.
 */
class CSignatureBatchVerifier {
public:
    explicit CSignatureBatchVerifier(size_t num_workers = DEFAULT_WORKERS);
    ~CSignatureBatchVerifier();

    CSignatureBatchVerifier(const CSignatureBatchVerifier&) = delete;
    CSignatureBatchVerifier& operator=(const CSignatureBatchVerifier&) = delete;

    void Start();
    void Stop();

    // PRE-FIX sessionless API (the shape the LP-5 fix replaced).
    void BeginBatch();
    void Add(const std::vector<uint8_t>& signature,
             const std::vector<uint8_t>& message,
             const std::vector<uint8_t>& pubkey,
             size_t input_index);
    bool Wait(std::string& error);

    bool IsRunning() const { return m_running.load(); }
    size_t NumWorkers() const { return m_num_workers; }

    static constexpr size_t DEFAULT_WORKERS = 4;
    static constexpr size_t MAX_WORKERS = 16;

private:
    void WorkerThread();
    bool VerifySingle(CSignatureTask& task);

    size_t m_num_workers;

    std::vector<std::thread> m_workers;
    std::atomic<bool> m_running{false};

    std::queue<CSignatureTask> m_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    // SHARED batch state — the bug.
    std::atomic<size_t> m_pending_count{0};
    std::atomic<bool> m_batch_failed{false};
    std::string m_first_error;
    std::mutex m_error_mutex;

    std::mutex m_complete_mutex;
    std::condition_variable m_complete_cv;
};

extern CSignatureBatchVerifier* g_signature_verifier;

void InitSignatureVerifier(size_t num_workers = CSignatureBatchVerifier::DEFAULT_WORKERS);
void ShutdownSignatureVerifier();

#endif // DILITHION_TEST_LP5_CONTROL_SIGNATURE_BATCH_VERIFIER_PREFIX_H
