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
// WHY _Exit IS THE BOUND HERE, and why it is not "a self-inflicted SIGKILL":
// the alternative on the table is not "a clean exit", it is an operator
// running `kill -9` after a timeout with no idea what was in flight. The
// watchdog does the same thing deterministically, on a known deadline, and
// leaves a log line naming the stage that hung. That log line is the whole
// point: a hang that reaches the watchdog is a BUG REPORT, not a routine event.
//
// WHAT IS AND IS NOT GUARANTEED ACROSS A FORCED EXIT (K2-(3) -- the previous
// wording here claimed more than the code delivers, and the claim was false):
//   * LevelDB-backed state (chainstate, UTXO, block index) IS durable. A
//     committed WriteBatch is in the write-ahead log and survives process
//     death; _Exit is not a power loss.
//   * Flat-file persistence is safe ONLY where the writer stages to a temp
//     file and PUBLISHES WITH AN ATOMIC REPLACE. DFMP heat (src/dfmp/dfmp.cpp)
//     and the attestation key (src/attestation/seed_attestation.cpp) do:
//     rename(2) on POSIX, MoveFileExW(MOVEFILE_REPLACE_EXISTING) on Windows.
//     KNOWN RESIDUAL GAP, not fixed here (out of this change's scope):
//     src/dfmp/mik_registration_file.cpp:88 and src/node/mempool_persist.cpp:176
//     stage to a temp file but publish with std::filesystem::rename(), which
//     libstdc++ implements via _wrename() -- it FAILS when the destination
//     exists, so both fall back to remove-then-rename and leave a window in
//     which the file is ABSENT. Neither tears a file in half, and both callers
//     treat a missing file as "rebuild", so this is an availability nit rather
//     than a corruption risk -- but it is NOT the atomic replace the word
//     "rename" suggests. Any NEW flat-file writer added to the shutdown
//     sequence must use a real atomic replace: the deadline is GLOBAL, not per
//     stage, so a sequence that burns its budget in an earlier stage can be
//     killed part-way through a later one.
//   * In-memory-only state is lost, as it is on any exit.
// What _Exit additionally skips is graceful teardown -- freeing memory,
// joining threads, closing handles -- none of which the next start depends on.
//
// EXIT CODE (K2-(1)): a forced exit reports kExitForcedAfterShutdownTimeout,
// never 0. This whole lineage exists because a wrong exit code masked a real
// outcome; a watchdog that exited 0 would have reproduced that exact fault --
// systemd `Restart=on-failure` and the seed rolling-restart tooling would read
// a deadlocked node as a clean stop, with the evidence only in scrollback.
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

// Process exit code for "graceful shutdown did not complete; forced after the
// deadline". MUST be non-zero and MUST NOT collide with any other exit code
// this project assigns a meaning to. Currently assigned:
//   0  clean exit
//   1  general startup/config failure, and the wallet-load refusal
//   2  undo-data integrity failure (wrapper restarts and wipes)
//   3  lifetime-miner-snapshot mismatch (dilv-node)
//   4  THIS -- forced exit after the shutdown deadline expired
// Anyone adding a new exit code: take 5 or above, not this one.
inline constexpr int kExitForcedAfterShutdownTimeout = 4;

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

// Set once, by whichever call first takes ownership of the shutdown sequence.
// Makes ArmWatchdog() idempotent so the normal path and the RAII-unwind path
// (K2-(2)) can both call it without the second one starting a duplicate
// deadline thread.
inline std::atomic<bool>& Armed() {
    static std::atomic<bool> a{false};
    return a;
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
//
// Returns TRUE if this call took ownership of the shutdown sequence, i.e. the
// caller is the one that must Stage()/Disarm() it. Returns FALSE if the
// sequence is already armed, or already finished -- so the RAII unwind guard
// can call this unconditionally and correctly do nothing on the normal path.
// Without the Disarmed() check, the guard destructor (which runs AFTER main's
// Disarm()) would arm a fresh deadline that nothing ever disarms, and force-
// exit a perfectly clean shutdown.
inline bool ArmWatchdog(int timeout_seconds) {
    if (Disarmed().load(std::memory_order_acquire)) return false;
    if (Armed().exchange(true, std::memory_order_acq_rel)) return false;
    if (timeout_seconds <= 0) {
        std::cout << "[Shutdown] exit watchdog DISABLED (--shutdowntimeout=0): "
                     "a stalled subsystem will hang this process indefinitely"
                  << std::endl;
        return true;  // owns the sequence; there is simply no deadline on it
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
                  << "\n[Shutdown] Forcing exit with code "
                  << kExitForcedAfterShutdownTimeout
                  << " (FORCED AFTER TIMEOUT -- not a clean stop)."
                  << "\n[Shutdown] Committed LevelDB batches and completed tmp+rename"
                  << "\n[Shutdown] file writes are durable, but the stage named above"
                  << "\n[Shutdown] is a BUG -- please report it with this log."
                  << "\n[Shutdown] ===================================================="
                  << std::endl;
        std::cerr.flush();
        std::cout.flush();
        // NOT _Exit(0). See the EXIT CODE note at the top of this file: a
        // forced exit that reports success is indistinguishable from a clean
        // stop to systemd, to monitoring, and to the seed rolling-restart
        // tooling -- which is the precise fault class this lineage exists to
        // remove.
        std::_Exit(kExitForcedAfterShutdownTimeout);
    }).detach();
    return true;
}

}  // namespace ShutdownProgress
}  // namespace Dilithion

#endif  // DILITHION_UTIL_SHUTDOWN_PROGRESS_H
