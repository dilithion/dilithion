// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_CHAINSTATE_INTEGRITY_MONITOR_H
#define DILITHION_NODE_CHAINSTATE_INTEGRITY_MONITOR_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

class CChainState;
class CUTXOSet;
struct UndoIntegrityFailure;

namespace Dilithion {

/**
 * v4.4 Block 6: periodic chainstate integrity monitor.
 *
 * One dedicated thread that wakes every 6 hours, builds a (height, blockHash)
 * snapshot of the most-recent 500 blocks of the active chain (under cs_main,
 * briefly), then walks the snapshot lock-free against the UTXO LevelDB,
 * verifying each block's undo record is present and SHA3-checksummed correctly.
 *
 * On apparent failure, a revalidation gate re-acquires cs_main and queries a
 * FRESH active tip, walking back to the failing height. If the snapshotted
 * hash is still on the active chain, the failure is genuine corruption: the
 * monitor writes the auto_rebuild marker (under that same cs_main acquisition)
 * and signals the main loop to shut down. If a reorg disconnected the
 * snapshotted block between snapshot and walk (UndoBlock at
 * src/node/utxo_set.cpp:881-882 deletes the undo entry as part of disconnect),
 * the failure is an orphan-skip: monitor logs at INFO and continues.
 *
 * Singleton: at most one ChainstateIntegrityMonitor exists per process.
 * Construction throws std::runtime_error on collision (NOT assert — assertions
 * compile to no-op in NDEBUG release builds).
 *
 * Lifecycle gate: Start() must only be called after BOTH (a) the one-time
 * startup integrity check passes and (b) g_utxo_sync_enabled.load() == true
 * (i.e. IBD has fully exited). This is the responsibility of the caller in
 * dilv-node.cpp / dilithion-node.cpp; the monitor itself does not introspect
 * those flags.
 *
 * Recovery semantic on confirmed corruption: identical to startup-time check.
 * Marker is written via Dilithion::WriteAutoRebuildMarker; running flag is
 * flipped to false to initiate clean shutdown; wrapper-restart loop + marker
 * presence triggers chain rebuild on next startup.
 */
class ChainstateIntegrityMonitor {
public:
    // Hardcoded operational constants (resolved decision (g)).
    static constexpr int kWindowBlocks = 500;
    static constexpr std::chrono::hours kCycleInterval{6};

    // Self-heal / anti-false-positive (fix/integrity-monitor-self-heal).
    // A first failed walk is re-verified up to kRevalidateAttempts-1 more times
    // with backoff before the node is allowed to act. A transient storage-layer
    // fault (flaky disk / fsync lag / AV file lock) clears across retries; only
    // a reproducible, data-level failure on a still-active-chain block survives
    // all attempts AND the cs_main revalidation gate, and only THAT writes the
    // auto_rebuild marker + shuts down. A failure that is still transient-class
    // after all retries is logged loudly + tolerated (node keeps running).
    static constexpr int kRevalidateAttempts = 3;
    static constexpr std::chrono::seconds kRevalidateBackoff{30};

    /**
     * @param chainstate     Shared chainstate; the monitor calls
     *                       SnapshotIntegrityWindow + RevalidateUnderCsMain.
     * @param utxo_set       Shared UTXO set; the monitor calls
     *                       VerifyUndoDataFromSnapshot.
     * @param datadir        Runtime data directory; per RT F-5, this should
     *                       come from `config.datadir` (matching MaybeTrigger
     *                       ChainRebuild's runtime path), not
     *                       g_chainParams->dataDir.
     * @param running_flag   Optional pointer to the main-loop running flag
     *                       (typically &g_node_state.running). On confirmed
     *                       corruption the monitor stores false here to
     *                       initiate clean shutdown. nullable for tests.
     *
     * @throws std::runtime_error if another monitor is already alive.
     */
    ChainstateIntegrityMonitor(CChainState& chainstate,
                                CUTXOSet& utxo_set,
                                const std::string& datadir,
                                std::atomic<bool>* running_flag);

    /// Joins the worker thread (if started) and clears the singleton flag.
    ~ChainstateIntegrityMonitor();

    ChainstateIntegrityMonitor(const ChainstateIntegrityMonitor&) = delete;
    ChainstateIntegrityMonitor& operator=(const ChainstateIntegrityMonitor&) = delete;

    /// Spawn the worker thread. First cycle fires after kCycleInterval.
    /// Idempotent (no-op if already started).
    void Start();

    /// Signal the worker to stop and join. Idempotent.
    void Stop();

    /**
     * Test-only: synchronously execute one cycle. Returns true if the cycle
     * passed (clean, abort, or orphan-skip), false if it confirmed
     * corruption. Used by chainstate-integrity tests where waiting 6h is
     * impractical. The caller must NOT have a running worker thread when
     * invoking this.
     */
    bool RunOneCycleForTesting();

    /// Test hook: true iff the worker thread is alive.
    bool IsRunningForTesting() const { return m_worker.joinable(); }

    /// Test-only: override the inter-retry backoff so retry-loop tests don't
    /// stall for kRevalidateBackoff * (kRevalidateAttempts-1). Production never
    /// calls this; the worker uses kRevalidateBackoff.
    void SetRevalidateBackoffForTesting(std::chrono::milliseconds backoff) {
        m_revalidate_backoff = backoff;
    }

private:
    void WorkerLoop();
    bool ExecuteSingleCycle();

    /// Run one snapshot→walk attempt. Returns true on a clean/healthy walk;
    /// false on failure (populating failure_out) or shutdown abort. Shared by
    /// the retry loop inside ExecuteSingleCycle.
    bool RunSingleWalk(UndoIntegrityFailure& failure_out);

    /// Interruptible sleep used between retries. Returns immediately (false) if
    /// stop was requested during the wait; true if the full duration elapsed.
    bool InterruptibleWait(std::chrono::milliseconds dur);

    CChainState& m_chainstate;
    CUTXOSet& m_utxo_set;
    std::string m_datadir;
    std::atomic<bool>* m_running_flag;  // External; not owned. nullable for tests.
    std::chrono::milliseconds m_revalidate_backoff{
        std::chrono::duration_cast<std::chrono::milliseconds>(kRevalidateBackoff)};

    std::thread m_worker;
    std::mutex m_cv_mutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_stop_requested{false};

    static std::atomic<bool> s_instance_alive;
};

}  // namespace Dilithion

#endif  // DILITHION_NODE_CHAINSTATE_INTEGRITY_MONITOR_H
