// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// J1: bounded, observable shutdown.
//
// The node's shutdown sequence is a long chain of subsystem stops, thread
// joins and database closes. Before this file existed, a stall anywhere in
// that chain was indistinguishable from a slow shutdown: the operator saw a
// process that would not exit and no way to tell which stage it was parked in.
// The only remaining move was SIGKILL, which is precisely the fault class the
// startup-integrity work exists to protect against.
//
// Two things are provided:
//
//   ShutdownProgress::Stage("...")  -- records the stage the shutdown sequence
//       has just entered, with a timestamp, and prints it. Cheap, lock-free,
//       safe to call from the shutdown thread only (it is a single-threaded
//       sequence by construction).
//
//   ShutdownProgress::ArmWatchdog(seconds)  -- starts a detached thread that
//       waits for the deadline and, if Disarm() has not been called by then,
//       prints the stage the sequence is stuck in plus how long it has been
//       there, and terminates the process with std::_Exit().
//
// WHY _Exit IS THE RIGHT BOUND HERE, and why it is not "a self-inflicted
// SIGKILL": by the time the watchdog can fire, every durable write this node
// makes has already been handed to LevelDB, whose WriteBatch commits are
// atomic and survive process death (they are in the write-ahead log; only a
// machine-level power loss can lose an unsynced batch, and _Exit is not that).
// What _Exit skips is graceful teardown -- freeing memory, joining threads,
// closing handles -- none of which is state the next start depends on. The
// alternative on the table is not "a clean exit", it is an operator running
// `kill -9` after a timeout with no idea what was in flight. The watchdog does
// the same thing deterministically, on a known deadline, and leaves a log line
// naming the stage that hung. That log line is the whole point: a hang that
// reaches the watchdog is a BUG REPORT, not a routine event.
//
// The deadline is deliberately generous (default 120s, --shutdowntimeout=N to
// override, 0 to disable) so that a merely slow shutdown -- a large mempool
// dump, a busy UTXO flush -- always completes on its own. Anything past it is
// not slow, it is stuck.

#ifndef DILITHION_UTIL_SHUTDOWN_PROGRESS_H
#define DILITHION_UTIL_SHUTDOWN_PROGRESS_H

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

namespace Dilithion {
namespace ShutdownProgress {

// The stage currently being executed. A pointer to a string LITERAL only --
// never to a heap string -- so the watchdog thread can read it without any
// lifetime or locking concern.
inline std::atomic<const char*>& CurrentStage() {
    static std::atomic<const char*> stage{"(shutdown not started)"};
    return stage;
}

inline std::atomic<long long>& StageStartedAtMs() {
    static std::atomic<long long> t{0};
    return t;
}

inline std::atomic<bool>& Disarmed() {
    static std::atomic<bool> d{false};
    return d;
}

inline long long NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// Enter a shutdown stage. `name` MUST be a string literal (see CurrentStage()).
inline void Stage(const char* name) {
    const long long now = NowMs();
    const long long prev_started = StageStartedAtMs().exchange(now, std::memory_order_acq_rel);
    const char* prev = CurrentStage().exchange(name, std::memory_order_acq_rel);
    if (prev_started != 0) {
        std::cout << "[Shutdown] " << prev << " -- done in "
                  << (now - prev_started) << "ms" << std::endl;
    }
    std::cout << "[Shutdown] -> " << name << std::endl;
}

// Mark the sequence finished. After this the watchdog will not fire.
inline void Disarm() {
    const long long now = NowMs();
    const long long prev_started = StageStartedAtMs().load(std::memory_order_acquire);
    if (prev_started != 0) {
        std::cout << "[Shutdown] " << CurrentStage().load(std::memory_order_acquire)
                  << " -- done in " << (now - prev_started) << "ms" << std::endl;
    }
    Disarmed().store(true, std::memory_order_release);
}

// Start the deadline thread. timeout_seconds <= 0 disables the watchdog
// entirely (for operators who would rather hang than risk an abrupt exit).
inline void ArmWatchdog(int timeout_seconds) {
    if (timeout_seconds <= 0) {
        std::cout << "[Shutdown] exit watchdog DISABLED (--shutdowntimeout=0): "
                     "a stalled subsystem will hang this process indefinitely"
                  << std::endl;
        return;
    }
    const long long armed_at = NowMs();
    std::thread([timeout_seconds, armed_at]() {
        // Poll rather than sleep the whole deadline, so a normal shutdown
        // does not leave a thread parked for two minutes after the process
        // is otherwise done.
        for (int i = 0; i < timeout_seconds * 10; ++i) {
            if (Disarmed().load(std::memory_order_acquire)) return;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (Disarmed().load(std::memory_order_acquire)) return;

        const char* stage = CurrentStage().load(std::memory_order_acquire);
        const long long stage_started = StageStartedAtMs().load(std::memory_order_acquire);
        const long long now = NowMs();

        std::cerr << "\n[Shutdown] ==================== WATCHDOG ===================="
                  << "\n[Shutdown] Graceful shutdown did not complete within "
                  << timeout_seconds << "s."
                  << "\n[Shutdown] STUCK IN STAGE: " << stage
                  << "\n[Shutdown] time in that stage: "
                  << (stage_started ? (now - stage_started) : 0) << "ms"
                  << "\n[Shutdown] total shutdown time: " << (now - armed_at) << "ms"
                  << "\n[Shutdown] Forcing exit. Committed LevelDB batches are durable;"
                  << "\n[Shutdown] this is not a data-loss event, but the stage named"
                  << "\n[Shutdown] above is a BUG -- please report it with this log."
                  << "\n[Shutdown] ===================================================="
                  << std::endl;
        std::cerr.flush();
        std::cout.flush();
        std::_Exit(0);
    }).detach();
}

}  // namespace ShutdownProgress
}  // namespace Dilithion

#endif  // DILITHION_UTIL_SHUTDOWN_PROGRESS_H
