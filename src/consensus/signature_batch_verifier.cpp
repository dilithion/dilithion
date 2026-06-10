// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/signature_batch_verifier.h>
#include <iostream>
#include <cstdio>

// Dilithium3 external API
extern "C" {
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

// Global instance
CSignatureBatchVerifier* g_signature_verifier = nullptr;

// Dilithium3 sizes
static constexpr size_t DILITHIUM3_SIG_SIZE = 3309;
static constexpr size_t DILITHIUM3_PK_SIZE = 1952;

// ============================================================================
// CSignatureBatchVerifier Implementation
// ============================================================================

CSignatureBatchVerifier::CSignatureBatchVerifier(size_t num_workers)
    : m_num_workers(std::min(num_workers, MAX_WORKERS)) {
    if (m_num_workers == 0) {
        m_num_workers = 1;
    }
}

CSignatureBatchVerifier::~CSignatureBatchVerifier() {
    Stop();
}

void CSignatureBatchVerifier::Start() {
    if (m_running.load()) {
        return;  // Already running
    }

    m_running.store(true);

    // Launch worker threads
    for (size_t i = 0; i < m_num_workers; ++i) {
        m_workers.emplace_back(&CSignatureBatchVerifier::WorkerThread, this);
    }

    std::cout << "[SignatureVerifier] Started with " << m_num_workers << " worker threads" << std::endl;
}

void CSignatureBatchVerifier::Stop() {
    if (!m_running.load()) {
        return;  // Already stopped
    }

    m_running.store(false);

    // Wake all workers
    m_queue_cv.notify_all();

    // Wait for workers to finish
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    m_workers.clear();

    std::cout << "[SignatureVerifier] Stopped" << std::endl;
}

std::shared_ptr<CBatchSession> CSignatureBatchVerifier::BeginBatch() {
    // Each batch gets a fresh, independently-owned session. No shared global
    // batch state is touched here (CRITICAL-1 fix), so concurrent BeginBatch()
    // calls cannot clobber one another.
    return std::make_shared<CBatchSession>();
}

void CSignatureBatchVerifier::Add(const std::shared_ptr<CBatchSession>& session,
                                   const std::vector<uint8_t>& signature,
                                   const std::vector<uint8_t>& message,
                                   const std::vector<uint8_t>& pubkey,
                                   size_t input_index) {
    // Increment THIS session's pending count BEFORE adding to queue so its
    // Wait() won't return prematurely.
    session->pending_count.fetch_add(1);

    // Create task, binding it to its owning session.
    CSignatureTask task;
    task.signature = signature;
    task.message = message;
    task.pubkey = pubkey;
    task.session = session;   // keeps the session alive while queued (S-005)
    task.input_index = input_index;

    // Add to the shared worker queue
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_queue.push(std::move(task));
    }

    // Wake a worker
    m_queue_cv.notify_one();
}

bool CSignatureBatchVerifier::Wait(const std::shared_ptr<CBatchSession>& session,
                                   std::string& error) {
    // Wait for all pending tasks in THIS session to complete.
    // The predicate (pending_count==0) is checked under complete_mutex, and the
    // worker that drives the count to zero notifies under the SAME mutex
    // (MED-2 lost-wakeup fix), so a Wait() entered just before the final
    // decrement still wakes.
    {
        std::unique_lock<std::mutex> lock(session->complete_mutex);
        session->complete_cv.wait(lock, [&session] {
            return session->pending_count.load() == 0;
        });
    }

    // Check if THIS batch failed
    if (session->batch_failed.load()) {
        std::lock_guard<std::mutex> err_lock(session->error_mutex);
        error = session->first_error;
        return false;
    }

    return true;
}

void CSignatureBatchVerifier::WorkerThread() {
    while (m_running.load()) {
        CSignatureTask task;
        bool has_task = false;

        // Wait for task
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait(lock, [this] {
                return !m_queue.empty() || !m_running.load();
            });

            if (!m_running.load() && m_queue.empty()) {
                break;  // Shutdown
            }

            if (!m_queue.empty()) {
                task = std::move(m_queue.front());
                m_queue.pop();
                has_task = true;
            }
        }

        if (!has_task) {
            continue;
        }

        // Resolve the owning session for this task (always set by Add()).
        std::shared_ptr<CBatchSession> session = task.session;

        // Verify signature
        bool valid = VerifySingle(task);

        if (!valid && session) {
            // Mark THIS batch as failed
            bool expected = false;
            if (session->batch_failed.compare_exchange_strong(expected, true)) {
                // First failure in this batch - store error
                char buf[256];
                snprintf(buf, sizeof(buf), "Signature verification failed for input %zu",
                         task.input_index);

                std::lock_guard<std::mutex> lock(session->error_mutex);
                session->first_error = buf;
            }
        }

        // Decrement THIS session's pending count and notify its waiter if the
        // batch is complete. The notify is done under complete_mutex so the
        // waiter cannot miss it (MED-2). We capture the session in a local
        // shared_ptr above and release the task (which may hold the last other
        // reference) only after notifying, so the session stays alive across
        // the notify even if Wait() has already returned and dropped its handle.
        if (session) {
            std::unique_lock<std::mutex> lock(session->complete_mutex);
            size_t remaining = session->pending_count.fetch_sub(1) - 1;
            if (remaining == 0) {
                session->complete_cv.notify_all();
            }
        }
    }
}

bool CSignatureBatchVerifier::VerifySingle(CSignatureTask& task) {
    // Validate sizes
    if (task.signature.size() != DILITHIUM3_SIG_SIZE) {
        return false;
    }
    if (task.pubkey.size() != DILITHIUM3_PK_SIZE) {
        return false;
    }
    if (task.message.size() != 32) {
        return false;
    }

    // Call Dilithium3 verification
    int result = pqcrystals_dilithium3_ref_verify(
        task.signature.data(), task.signature.size(),
        task.message.data(), task.message.size(),
        nullptr, 0,  // No context
        task.pubkey.data()
    );

    return result == 0;
}

// ============================================================================
// Global Functions
// ============================================================================

void InitSignatureVerifier(size_t num_workers) {
    if (g_signature_verifier) {
        return;  // Already initialized
    }

    g_signature_verifier = new CSignatureBatchVerifier(num_workers);
    g_signature_verifier->Start();
}

void ShutdownSignatureVerifier() {
    if (g_signature_verifier) {
        g_signature_verifier->Stop();
        delete g_signature_verifier;
        g_signature_verifier = nullptr;
    }
}
