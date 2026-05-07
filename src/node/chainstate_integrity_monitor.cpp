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

bool ChainstateIntegrityMonitor::ExecuteSingleCycle() {
    // Phase 1 — snapshot under cs_main (briefly).
    auto snapshot = m_chainstate.SnapshotIntegrityWindow(kWindowBlocks);
    if (snapshot.empty()) {
        // Chain too short, no tip, or genesis-only. Nothing to verify.
        return true;
    }

    // Phase 2 — walk lock-free w.r.t. cs_main; uses cs_utxo internally.
    UndoIntegrityFailure failure;
    const bool walkPass = m_utxo_set.VerifyUndoDataFromSnapshot(
        snapshot, failure, &m_stop_requested);
    if (walkPass) return true;  // Healthy.

    if (failure.cause == "aborted_for_shutdown") {
        // Mid-walk shutdown — bail without any state change.
        return true;
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
            Dilithion::WriteAutoRebuildMarker(m_datadir, reason);
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
