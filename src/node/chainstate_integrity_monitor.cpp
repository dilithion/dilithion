// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/chainstate_integrity_monitor.h>

#include <consensus/chain.h>
#include <node/utxo_set.h>
#include <util/chain_reset.h>

#include <iostream>
#include <stdexcept>
#include <string>

namespace Dilithion {

std::atomic<bool> ChainstateIntegrityMonitor::s_instance_alive{false};

ChainstateIntegrityMonitor::ChainstateIntegrityMonitor(
    CChainState& chainstate,
    CUTXOSet& utxo_set,
    const std::string& datadir,
    std::atomic<bool>* running_flag)
    : m_chainstate(chainstate),
      m_utxo_set(utxo_set),
      m_datadir(datadir),
      m_running_flag(running_flag)
{
    // Trap-9 / RT F-8: throw, NOT assert. Assertions compile to no-op in
    // NDEBUG release builds, allowing two instances to silently produce
    // duplicate auto_rebuild marker writes. throw fires regardless of mode.
    bool expected = false;
    if (!s_instance_alive.compare_exchange_strong(
            expected, true,
            std::memory_order_seq_cst, std::memory_order_seq_cst)) {
        throw std::runtime_error(
            "ChainstateIntegrityMonitor: another instance is already alive in this process");
    }
}

ChainstateIntegrityMonitor::~ChainstateIntegrityMonitor() {
    Stop();
    s_instance_alive.store(false, std::memory_order_seq_cst);
}

void ChainstateIntegrityMonitor::Start() {
    if (m_worker.joinable()) return;  // Already started.
    m_stop_requested.store(false, std::memory_order_seq_cst);
    m_worker = std::thread(&ChainstateIntegrityMonitor::WorkerLoop, this);
}

void ChainstateIntegrityMonitor::Stop() {
    m_stop_requested.store(true, std::memory_order_seq_cst);
    {
        std::lock_guard<std::mutex> lk(m_cv_mutex);
        m_cv.notify_all();
    }
    if (m_worker.joinable()) {
        m_worker.join();
    }
}

void ChainstateIntegrityMonitor::WorkerLoop() {
    while (!m_stop_requested.load(std::memory_order_seq_cst)) {
        // Trap-8 / RT F-11: condition_variable::wait_for with predicate, NOT
        // std::this_thread::sleep_for. wait_for returns immediately when
        // notify_all fires from Stop(), so shutdown latency is bounded by
        // the cv-wakeup, not by the 6h cycle.
        {
            std::unique_lock<std::mutex> lk(m_cv_mutex);
            m_cv.wait_for(lk, kCycleInterval,
                [this] { return m_stop_requested.load(std::memory_order_seq_cst); });
        }
        if (m_stop_requested.load(std::memory_order_seq_cst)) break;

        ExecuteSingleCycle();
    }
}

bool ChainstateIntegrityMonitor::RunOneCycleForTesting() {
    return ExecuteSingleCycle();
}

bool ChainstateIntegrityMonitor::InterruptibleWait(std::chrono::milliseconds dur) {
    if (dur <= std::chrono::milliseconds::zero()) {
        return !m_stop_requested.load(std::memory_order_seq_cst);
    }
    std::unique_lock<std::mutex> lk(m_cv_mutex);
    // Returns true if the predicate (stop requested) became true => interrupted.
    const bool stopped = m_cv.wait_for(
        lk, dur,
        [this] { return m_stop_requested.load(std::memory_order_seq_cst); });
    return !stopped;  // true => full duration elapsed without a stop.
}

bool ChainstateIntegrityMonitor::RunSingleWalk(UndoIntegrityFailure& failure_out) {
    // Phase 1 — snapshot under cs_main (briefly).
    auto snapshot = m_chainstate.SnapshotIntegrityWindow(kWindowBlocks);
    if (snapshot.empty()) {
        // Chain too short, no tip, or genesis-only. Nothing to verify.
        return true;
    }

    // Phase 2 — walk lock-free w.r.t. cs_main; uses cs_utxo internally.
    return m_utxo_set.VerifyUndoDataFromSnapshot(
        snapshot, failure_out, &m_stop_requested);
}

bool ChainstateIntegrityMonitor::ExecuteSingleCycle() {
    // ---------------------------------------------------------------------
    // Self-heal retry loop (fix/integrity-monitor-self-heal).
    //
    // A single failed walk is NEVER sufficient to brick the node. We re-verify
    // up to kRevalidateAttempts times with backoff. Rationale:
    //   * A transient storage-layer fault (flaky disk, fsync lag, AV file lock
    //     on Windows, a momentary LevelDB IsIOError) clears across retries — the
    //     re-walk passes and we return healthy.
    //   * Genuine corruption (a clean missing key on an active-chain block, or a
    //     checksum/size mismatch) is reproducible — it fails every attempt.
    // Only a reproducible failure that ALSO survives the cs_main revalidation
    // gate (not a reorg orphan-skip) is allowed to write the marker + shut down.
    // A failure that remains transient-class after all retries is logged loudly
    // and TOLERATED — the node keeps running; next cycle re-checks. We must not
    // wipe-and-resync a node whose disk is merely throwing transient IOErrors.
    // ---------------------------------------------------------------------
    UndoIntegrityFailure failure;
    bool walkPass = false;
    for (int attempt = 1; attempt <= kRevalidateAttempts; ++attempt) {
        failure = UndoIntegrityFailure{};  // reset between attempts
        walkPass = RunSingleWalk(failure);
        if (walkPass) {
            if (attempt > 1) {
                std::cerr << "[IntegrityMonitor] walk passed on retry attempt "
                          << attempt << "/" << kRevalidateAttempts
                          << " — earlier failure was transient (node healthy)."
                          << std::endl;
            }
            return true;  // Healthy (possibly after a transient fault cleared).
        }

        if (failure.cause == "aborted_for_shutdown") {
            // Mid-walk shutdown — bail without any state change.
            return true;
        }

        // Failed this attempt. If more attempts remain, back off and retry so a
        // transient fault has time to clear. The wait is interruptible by Stop()
        // so shutdown latency is not extended by the retry backoff.
        if (attempt < kRevalidateAttempts) {
            std::cerr << "[IntegrityMonitor] walk attempt " << attempt << "/"
                      << kRevalidateAttempts << " failed (cause=" << failure.cause
                      << ", transient=" << (failure.transient ? "yes" : "no")
                      << ") at height " << failure.height
                      << " — re-verifying after backoff before acting."
                      << std::endl;
            if (!InterruptibleWait(m_revalidate_backoff)) {
                // Stop requested during backoff — bail without state change.
                return true;
            }
        }
    }

    // All retries exhausted and every attempt failed.
    if (failure.transient) {
        // Still a transient-class storage fault after kRevalidateAttempts. This
        // is NOT confirmed corruption — bricking here would wipe a healthy chain
        // because of a flaky disk. Log loudly + persistently and keep running.
        std::cerr << "\n=========================================================="
                  << std::endl;
        std::cerr << "[WARNING] ChainstateIntegrityMonitor: persistent TRANSIENT "
                  << "read fault (cause=" << failure.cause << ") at height "
                  << failure.height << " hash="
                  << failure.blockHash.GetHex() << " after "
                  << kRevalidateAttempts << " attempts." << std::endl;
        std::cerr << "This indicates a storage-layer problem (failing disk, "
                  << "fsync lag, or a file lock — e.g. antivirus on Windows), "
                  << "NOT chainstate corruption." << std::endl;
        std::cerr << "Node will KEEP RUNNING and re-check next cycle. If this "
                  << "recurs, inspect the disk / move the data directory off the "
                  << "failing volume." << std::endl;
        std::cerr << "=========================================================="
                  << std::endl;
        return true;  // Do NOT brick on a transient fault.
    }

    // Phase 3 — revalidation gate (Inverse Adversarial traps 2A + 2B).
    // RevalidateUnderCsMain holds cs_main throughout; the marker-write
    // callback runs under that same lock acquisition. If the snapshotted
    // block was reorged out of the active chain between snapshot and walk,
    // RevalidateUnderCsMain returns false and the callback is never called.
    const bool genuine = m_chainstate.RevalidateUnderCsMain(
        failure.height, failure.blockHash,
        [this, &failure] {
            const std::string reason =
                "Periodic integrity check failed at height "
                + std::to_string(failure.height)
                + " hash=" + failure.blockHash.GetHex()
                + " cause=" + failure.cause;
            std::cerr << "\n=========================================================="
                      << std::endl;
            std::cerr << "[CRITICAL] Periodic integrity monitor detected corruption: "
                      << reason << std::endl;
            std::cerr << "Writing auto_rebuild marker; node will wipe + resync on next launch."
                      << std::endl;
            std::cerr << "=========================================================="
                      << std::endl;
            // Layer-3 RT F-1 fix: capture marker-write result and log failure.
            // We still proceed to flip running_flag below (caller's job) so the
            // node shuts down — startup-integrity-check is the defense-in-depth
            // path that re-detects + re-attempts the marker on next launch.
            // Failure here adds one extra restart cycle, not a stuck loop.
            const bool wrote = Dilithion::WriteAutoRebuildMarker(m_datadir, reason);
            if (!wrote) {
                std::cerr << "[CRITICAL] ChainstateIntegrityMonitor: auto_rebuild marker "
                          << "write FAILED (datadir='" << m_datadir << "'). Forcing "
                          << "shutdown anyway — startup-integrity-check on next launch "
                          << "will re-detect and re-attempt the marker write."
                          << std::endl;
            }
        });

    if (!genuine) {
        // Orphan-skip: failing block was reorged out, UndoBlock deleted its
        // undo entry as part of disconnect. Not corruption. Log INFO + keep
        // running — next cycle re-walks whatever's on the new active chain.
        std::cerr << "[IntegrityMonitor] orphan-skip at height "
                  << failure.height
                  << ": snapshotted block hash "
                  << failure.blockHash.GetHex().substr(0, 16)
                  << "... was reorged out of active chain (no corruption)"
                  << std::endl;
        return true;
    }

    // Confirmed corruption — marker written. Signal main-loop shutdown.
    if (m_running_flag != nullptr) {
        m_running_flag->store(false, std::memory_order_seq_cst);
    }
    return false;
}

}  // namespace Dilithion
