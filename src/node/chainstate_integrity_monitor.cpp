// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/chainstate_integrity_monitor.h>

#include <consensus/chain.h>
#include <node/utxo_set.h>
#include <util/chain_reset.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace Dilithion {

namespace {
/// MEDIUM-2 fold (fresh pass 2026-09-07): wiping is now an ALLOWLIST, not the
/// default. Before this, DecideStartupIntegrityAction returned WipeRebuild for
/// anything not flagged transient -- including causes that are not evidence of
/// on-disk corruption at all ("db_not_open", "block_index_missing", and any
/// cause added later). Destroying a healthy chain is the most expensive action
/// this code can take, so it now requires a POSITIVE match on a cause that
/// actually means damaged data. Anything unrecognised stops for inspection.
///
/// The direction matters more than the list: a new cause added tomorrow gets
/// the SAFE default automatically, where previously it would silently inherit
/// "wipe".
bool CauseWarrantsWipe(const std::string& cause)
{
    return cause == "missing"
        || cause == "checksum_mismatch"
        || cause == "size_invalid"
        || cause == "io_corruption";
}
}  // namespace

int RunStartupIntegrityCheck(CUTXOSet& utxo_set,
                             CBlockIndex* pindexTip,
                             int fromHeight,
                             int toHeight,
                             const std::string& datadir,
                             int attempts,
                             std::chrono::milliseconds backoff,
                             UndoIntegrityFailure& failure_out)
{
    failure_out = UndoIntegrityFailure{};
    bool walkPass = false;

    // MEDIUM-4 fold: classification is STICKY, not last-attempt-wins.
    //
    // The loop used to reset `failure` every attempt and decide from the final
    // one alone. Scenario that breaks: a real checksum_mismatch at a lower
    // height and an intermittent IOError at a higher one. The walk stops at the
    // first failing block tip-downward, so attempts 1-2 report corruption and
    // attempt 3 catches the blip -> StopNoWipe -> real corruption is KEPT and
    // the node crash-loops, where pre-#127 it self-healed.
    //
    // So: if ANY attempt saw a cause that warrants a wipe, that verdict sticks
    // even if a later attempt reports something transient. A transient blip can
    // hide corruption; it cannot un-corrupt a block.
    bool sawWipeWorthyCause = false;
    UndoIntegrityFailure wipeWorthyFailure;

    for (int attempt = 1; attempt <= attempts; ++attempt) {
        UndoIntegrityFailure attemptFailure;  // fresh per attempt
        walkPass = utxo_set.VerifyUndoDataInRange(pindexTip, fromHeight, toHeight, attemptFailure);
        if (walkPass) {
            if (attempt > 1) {
                std::cerr << "  [v4.4] Startup integrity check passed on retry attempt "
                          << attempt << "/" << attempts
                          << " — earlier failure was transient." << std::endl;
            }
            return 0;
        }

        failure_out = attemptFailure;
        if (!sawWipeWorthyCause && CauseWarrantsWipe(attemptFailure.cause) && !attemptFailure.transient) {
            sawWipeWorthyCause = true;
            wipeWorthyFailure = attemptFailure;
        }

        if (attempt < attempts) {
            std::cerr << "  [v4.4] Startup integrity walk attempt " << attempt << "/"
                      << attempts << " failed (cause=" << attemptFailure.cause
                      << ", transient=" << (attemptFailure.transient ? "yes" : "no")
                      << ") at height " << attemptFailure.height
                      << " — re-verifying after backoff before acting." << std::endl;
            if (backoff.count() > 0) {
                std::this_thread::sleep_for(backoff);
            }
        }
    }

    // A wipe-worthy cause seen at ANY point outranks a transient final attempt.
    if (sawWipeWorthyCause) {
        failure_out = wipeWorthyFailure;
    }

    const bool wipe = sawWipeWorthyCause
                      || (!failure_out.transient && CauseWarrantsWipe(failure_out.cause));

    if (!wipe) {
        // Persistent transient fault, OR a cause that is not evidence of
        // corruption. FAIL LOUD, do NOT wipe: a rebuild cannot fix failing
        // hardware and would destroy a healthy chain over a blip.
        std::cerr << "\n==========================================================" << std::endl;
        std::cerr << "[ERROR] Startup integrity check: NOT confirmed corruption "
                  << "(cause=" << failure_out.cause
                  << ", transient=" << (failure_out.transient ? "yes" : "no")
                  << ") at height " << failure_out.height
                  << " hash=" << failure_out.blockHash.GetHex() << " after "
                  << attempts << " attempts." << std::endl;
        std::cerr << "This indicates a storage-layer problem (failing disk, fsync lag, "
                  << "or a file lock — e.g. antivirus on Windows), NOT chainstate "
                  << "corruption." << std::endl;
        std::cerr << "The node will STOP and will NOT auto-rebuild (a rebuild cannot fix "
                  << "failing hardware and would destroy a healthy chain). No auto_rebuild "
                  << "marker written." << std::endl;
        std::cerr << "ACTION REQUIRED: inspect the disk (SMART), close any process locking "
                  << "the data directory, move the data directory off the failing volume, "
                  << "or restore from a known-good backup — then restart." << std::endl;
        std::cerr << "==========================================================" << std::endl;
        return 1;
    }

    // Confirmed corruption / missing undo. Existing v4.4 behaviour: marker + wipe.
    std::cerr << "\n==========================================================" << std::endl;
    std::cerr << "[CRITICAL] Startup integrity check FAILED at height "
              << failure_out.height << " hash=" << failure_out.blockHash.GetHex()
              << " cause=" << failure_out.cause << std::endl;
    std::cerr << "This node cannot perform reorgs without manual recovery."
              << " Writing auto_rebuild marker — node will wipe and resync"
              << " on next launch." << std::endl;
    std::cerr << "==========================================================" << std::endl;

    const std::string reason =
        "Startup integrity check failed at height "
        + std::to_string(failure_out.height)
        + " cause=" + failure_out.cause
        + " hash=" + failure_out.blockHash.GetHex();
    WriteAutoRebuildMarker(datadir, reason);
    return 2;
}


std::atomic<bool> ChainstateIntegrityMonitor::s_instance_alive{false};
std::atomic<bool> ChainstateIntegrityMonitor::s_health_degraded{false};

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
    // Fresh monitor starts from a clean health slate — defends against a stale
    // s_health_degraded surviving a destroy/reconstruct within one process.
    s_health_degraded.store(false, std::memory_order_seq_cst);
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

void ChainstateIntegrityMonitor::MarkCycleHealthy() {
    m_consecutive_transient_cycles = 0;
    s_health_degraded.store(false, std::memory_order_seq_cst);
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
            // Healthy cycle — clear any persistent-transient escalation state.
            MarkCycleHealthy();
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
        // because of a flaky disk, and an auto-rebuild can't fix a dying disk.
        // We NEVER write the marker or shut down for a transient/IsIOError fault.
        //
        // extreview PR #120 B1 (Will's decision): keep tolerating, but escalate
        // a PERSISTENT fault from a per-cycle warning to a sustained, louder
        // signal so it can't scroll past an operator unnoticed. Count consecutive
        // cycles that end here; at kEscalateAfterCycles, promote to a sustained
        // ERROR + raise the operator/RPC-observable degraded-health flag.
        ++m_consecutive_transient_cycles;
        const bool escalated =
            m_consecutive_transient_cycles >= kEscalateAfterCycles;

        std::cerr << "\n=========================================================="
                  << std::endl;
        std::cerr << (escalated ? "[ERROR] " : "[WARNING] ")
                  << "ChainstateIntegrityMonitor: persistent TRANSIENT "
                  << "read fault (cause=" << failure.cause << ") at height "
                  << failure.height << " hash="
                  << failure.blockHash.GetHex() << " after "
                  << kRevalidateAttempts << " attempts (consecutive cycle "
                  << m_consecutive_transient_cycles << ")." << std::endl;
        std::cerr << "This indicates a storage-layer problem (failing disk, "
                  << "fsync lag, or a file lock — e.g. antivirus on Windows), "
                  << "NOT chainstate corruption." << std::endl;
        if (escalated) {
            // Raise the durable, observable degraded-health signal. Sustained
            // ERROR (re-emitted every cycle while the fault persists) + a flag
            // the operator / an RPC (getblockchaininfo) can poll.
            s_health_degraded.store(true, std::memory_order_seq_cst);
            std::cerr << "[ERROR] This storage fault has now persisted across "
                      << m_consecutive_transient_cycles << " consecutive monitor "
                      << "cycles (~" << (kCycleInterval.count()
                                         * m_consecutive_transient_cycles)
                      << "h). The node is STILL RUNNING and will NOT auto-rebuild "
                      << "(a rebuild cannot fix failing hardware), but the "
                      << "chainstate-integrity monitor is now in a DEGRADED state "
                      << "and requires operator attention." << std::endl;
            std::cerr << "[ERROR] ACTION REQUIRED: inspect the disk (SMART), move "
                      << "the data directory off the failing volume, or restore "
                      << "from a known-good backup. integrity_health=degraded is "
                      << "now visible via getblockchaininfo." << std::endl;
        } else {
            std::cerr << "Node will KEEP RUNNING and re-check next cycle. If this "
                      << "recurs across " << kEscalateAfterCycles << " cycles it "
                      << "will escalate to a sustained ERROR + degraded-health "
                      << "flag. Inspect the disk / move the data directory off "
                      << "the failing volume." << std::endl;
        }
        std::cerr << "=========================================================="
                  << std::endl;
        return true;  // Do NOT brick on a transient fault (ever).
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
        // Not a storage fault — the chain is healthy. Clear escalation state.
        MarkCycleHealthy();
        return true;
    }

    // Confirmed corruption — marker written. Signal main-loop shutdown.
    if (m_running_flag != nullptr) {
        m_running_flag->store(false, std::memory_order_seq_cst);
    }
    return false;
}

}  // namespace Dilithion
