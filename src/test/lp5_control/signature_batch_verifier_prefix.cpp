// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// ============================================================================
// LP-5 / CRITICAL-1 CONTROL ARTIFACT — FROZEN PRE-FIX VERIFIER. DO NOT "FIX".
// ============================================================================
//
// VERBATIM copy of the pre-fix CSignatureBatchVerifier implementation at commit
// bb933d53 (`src/consensus/signature_batch_verifier.cpp`). Provenance:
// `git show bb933d53:src/consensus/signature_batch_verifier.cpp`. The ONLY edit
// is the #include pointing at the renamed control header. See the header banner
// for why this exists (A-010 control: this code HANGS under the race harness).
// ============================================================================

#include "signature_batch_verifier_prefix.h"
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

void CSignatureBatchVerifier::BeginBatch() {
    // Reset batch state
    m_pending_count.store(0);
    m_batch_failed.store(false);

    std::lock_guard<std::mutex> lock(m_error_mutex);
    m_first_error.clear();
}

void CSignatureBatchVerifier::Add(const std::vector<uint8_t>& signature,
                                   const std::vector<uint8_t>& message,
                                   const std::vector<uint8_t>& pubkey,
                                   size_t input_index) {
    // Increment pending count BEFORE adding to queue
    // This ensures Wait() won't return prematurely
    m_pending_count.fetch_add(1);

    // Create task
    CSignatureTask task;
    task.signature = signature;
    task.message = message;
    task.pubkey = pubkey;
    task.input_index = input_index;
    task.error_out = nullptr;

    // Add to queue
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_queue.push(std::move(task));
    }

    // Wake a worker
    m_queue_cv.notify_one();
}

bool CSignatureBatchVerifier::Wait(std::string& error) {
    // Wait for all pending tasks to complete
    std::unique_lock<std::mutex> lock(m_complete_mutex);
    m_complete_cv.wait(lock, [this] {
        return m_pending_count.load() == 0;
    });

    // Check if batch failed
    if (m_batch_failed.load()) {
        std::lock_guard<std::mutex> err_lock(m_error_mutex);
        error = m_first_error;
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

        // Verify signature
        bool valid = VerifySingle(task);

        if (!valid) {
            // Mark batch as failed
            bool expected = false;
            if (m_batch_failed.compare_exchange_strong(expected, true)) {
                // First failure - store error
                char buf[256];
                snprintf(buf, sizeof(buf), "Signature verification failed for input %zu",
                         task.input_index);

                std::lock_guard<std::mutex> lock(m_error_mutex);
                m_first_error = buf;
            }
        }

        // Decrement pending count and notify if batch complete
        size_t remaining = m_pending_count.fetch_sub(1) - 1;
        if (remaining == 0) {
            m_complete_cv.notify_all();
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
