// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Regression suite: mempool shutdown lost-wakeup (N4).
 *
 * THE DEFECT (src/node/mempool.cpp, CTxMemPool::StopExpirationThread):
 *   the stop flag was written, and expiration_cv.notify_all() called, WITHOUT
 *   holding expiration_mutex -- the mutex the expiration thread holds while it
 *   evaluates its wait_for predicate. Interleaving that loses the notify:
 *
 *     T_waiter : lock(expiration_mutex)
 *     T_waiter : wait_for predicate -> false        (still holding the lock)
 *     T_stop   : stop_expiration_thread = true      (no lock -- slips in here)
 *     T_stop   : notify_all()                       (nobody is blocked yet)
 *     T_waiter : wait_for releases the lock and blocks -> sleeps the FULL
 *                std::chrono::hours(1) timeout
 *
 *   StopExpirationThread() then sits in expiration_thread.join() for that hour.
 *   It runs at shutdown for BOTH dilithion-node and dilv-node, ahead of every
 *   LevelDB close, so an operator kill -9'ing the "hung" shutdown truncates the
 *   UTXO and block databases mid-write.
 *
 * THE FIX: write the flag under expiration_mutex, notify after releasing it.
 *
 * WHY THIS SUITE IS SHAPED THE WAY IT IS:
 *   The losing window is a few instructions wide, so a test that merely races
 *   construct-then-stop is a lottery ticket, not a regression test. The first
 *   test below is therefore DETERMINISTIC: it holds expiration_mutex itself and
 *   checks whether a concurrent StopExpirationThread() can still mutate the
 *   flag. On the buggy build it can (no lock is taken), and the test goes RED
 *   every run; on the fixed build the stopper is blocked on the mutex and the
 *   flag is still clear. That is precisely the property whose absence causes
 *   the lost wakeup. The remaining tests corroborate the observable behaviour
 *   (shutdown returns promptly, stop is idempotent) and hammer the real window.
 *
 * NOTE: no test here shortens the wait interval. Shortening it would hide the
 * bug rather than prove it fixed.
 */

#include <boost/test/unit_test.hpp>

#include <node/mempool.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

// Test seam declared as a friend of CTxMemPool in src/node/mempool.h.
// Production code never names this type.
struct MempoolShutdownWakeupTestAccess {
    static std::mutex& ExpirationMutex(CTxMemPool& pool) { return pool.expiration_mutex; }
    static bool StopFlag(const CTxMemPool& pool) { return pool.stop_expiration_thread.load(); }
};

BOOST_AUTO_TEST_SUITE(mempool_shutdown_wakeup_tests)

namespace {

// Long enough for the freshly-spawned expiration thread to reach wait_for and
// park on the condition variable. Generous on purpose -- an over-long settle is
// only slow, an under-long one is flaky.
constexpr std::chrono::milliseconds kSettle{300};

// How long we let a concurrent stopper run before deciding it did NOT take the
// lock. Only used on the deterministic test, where the buggy build sets the
// flag in microseconds.
constexpr std::chrono::milliseconds kProbe{400};

struct StopOutcome {
    bool completed = false;   // StopExpirationThread() returned before deadline
    double seconds = 0.0;
};

// Calls pool->StopExpirationThread() on a helper thread and waits up to
// `deadline` for it to return.
//
// The deadline exists so that a REGRESSED build fails the suite in seconds
// instead of hanging CI for the full one-hour wait interval. On timeout the
// helper thread is detached and the caller must leak the pool -- deliberately,
// because destroying a CTxMemPool whose expiration thread is still parked, or
// joining that thread, is exactly the hour-long block we are reporting.
//
// (This helper itself uses the correct pattern the production code was missing:
// `done` is written under `m`, and the notify happens after the state change.)
StopOutcome RunStopWithDeadline(CTxMemPool* pool, std::chrono::milliseconds deadline) {
    auto m = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto done = std::make_shared<bool>(false);

    const auto start = std::chrono::steady_clock::now();
    std::thread stopper([pool, m, cv, done] {
        pool->StopExpirationThread();
        {
            std::lock_guard<std::mutex> lk(*m);
            *done = true;
        }
        cv->notify_all();
    });

    bool ok;
    {
        std::unique_lock<std::mutex> lk(*m);
        ok = cv->wait_for(lk, deadline, [&done] { return *done; });
    }
    const double secs =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    if (ok) {
        stopper.join();
    } else {
        stopper.detach();
    }
    return StopOutcome{ok, secs};
}

}  // namespace

// ============================================================================
// 1. DETERMINISTIC GUARD -- this is the test that goes RED without the fix.
// ============================================================================
//
// Holds expiration_mutex, then asks another thread to stop the expiration
// thread. If the stop path writes the flag under the mutex (fixed), that write
// CANNOT have happened while we hold the lock. If it writes the flag with no
// lock (buggy), the write lands immediately -- which is the same freedom that
// lets it slip between the waiter's predicate evaluation and its block.
//
// Deterministic in both directions and cannot hang: on the buggy build the
// waiter is already parked on the CV by the time we signal, so its notify is
// delivered; only the assertion fails.
BOOST_AUTO_TEST_CASE(stop_flag_is_written_under_expiration_mutex)
{
    CTxMemPool pool;
    std::this_thread::sleep_for(kSettle);  // let the expiration thread park

    std::atomic<bool> observed_flag_while_locked{false};
    std::thread stopper;

    {
        std::unique_lock<std::mutex> held(
            MempoolShutdownWakeupTestAccess::ExpirationMutex(pool));

        BOOST_CHECK_MESSAGE(!MempoolShutdownWakeupTestAccess::StopFlag(pool),
                            "precondition: stop flag must still be clear");

        stopper = std::thread([&pool] { pool.StopExpirationThread(); });

        // Give the stopper time to run to completion IF it is not blocked on
        // the mutex we are holding.
        std::this_thread::sleep_for(kProbe);
        observed_flag_while_locked.store(MempoolShutdownWakeupTestAccess::StopFlag(pool));

        BOOST_CHECK_MESSAGE(
            !observed_flag_while_locked.load(),
            "LOST-WAKEUP REGRESSION: stop_expiration_thread was set while this "
            "test held expiration_mutex, so StopExpirationThread() writes the "
            "flag without taking that mutex. The same freedom lets the write "
            "and its notify_all() slip between the waiter's predicate check and "
            "its block in wait_for, losing the notification and stalling "
            "shutdown for the full 1-hour interval ahead of every LevelDB "
            "close. Fix: set the flag under expiration_mutex in "
            "CTxMemPool::StopExpirationThread().");

        // Release the lock -- the (correct) stopper can now proceed.
    }

    stopper.join();

    // Whichever build we are on, the stop must have taken effect by now.
    BOOST_CHECK_MESSAGE(MempoolShutdownWakeupTestAccess::StopFlag(pool),
                        "stop flag must be set once StopExpirationThread() returns");
}

// ============================================================================
// 2. Observable consequence: stopping a PARKED expiration thread returns fast.
// ============================================================================
//
// This is the operator-visible symptom -- shutdown must not block. It is green
// on the fixed build. It is not the primary red-without-fix guard (the buggy
// build usually wins this one too, because the waiter is already blocked when
// the notify fires), which is exactly why test 1 exists.
BOOST_AUTO_TEST_CASE(stop_returns_promptly_when_expiration_thread_is_parked)
{
    auto* pool = new CTxMemPool();
    std::this_thread::sleep_for(kSettle);

    const StopOutcome outcome = RunStopWithDeadline(pool, std::chrono::seconds(10));

    BOOST_CHECK_MESSAGE(outcome.completed,
                        "StopExpirationThread() did not return within 10s -- the "
                        "expiration thread's notification was lost and shutdown is "
                        "stalled on the 1-hour wait interval");

    if (outcome.completed) {
        BOOST_CHECK_LT(outcome.seconds, 5.0);
        delete pool;
    }
    // else: pool intentionally leaked; its thread is still parked (see helper).
}

// ============================================================================
// 3. Hammer the real window: construct and stop immediately, many times.
// ============================================================================
//
// This drives the exact interleaving the defect needs -- a stop issued while
// the expiration thread is still on its way into wait_for. PROBABILISTIC by
// nature: the losing window is a few instructions wide, so this will not
// reliably go red on a buggy build. It is corroboration that the fixed build
// never stalls across many attempts, not the guard. Test 1 is the guard.
BOOST_AUTO_TEST_CASE(immediate_stop_after_construction_never_stalls)
{
    constexpr int kIterations = 150;
    for (int i = 0; i < kIterations; ++i) {
        auto* pool = new CTxMemPool();
        // No settle: stop as close as possible to the thread entering wait_for.
        const StopOutcome outcome = RunStopWithDeadline(pool, std::chrono::seconds(10));
        if (!outcome.completed) {
            BOOST_ERROR(std::string("StopExpirationThread() stalled on iteration ")
                        + std::to_string(i)
                        + " -- lost wakeup while the expiration thread was entering wait_for");
            return;  // pool intentionally leaked; do not join a parked thread
        }
        BOOST_CHECK_LT(outcome.seconds, 5.0);
        delete pool;
    }
}

// ============================================================================
// 4. Idempotency must survive the fix (the flag write moved under a lock).
// ============================================================================
//
// StopExpirationThread() is reached twice on the real shutdown path: explicitly
// from main(), then again from ~CTxMemPool. A second call must not block, must
// not double-join, and must not deadlock on the mutex the first call took.
BOOST_AUTO_TEST_CASE(repeated_stop_and_destructor_are_safe)
{
    auto* pool = new CTxMemPool();
    std::this_thread::sleep_for(kSettle);

    StopOutcome first = RunStopWithDeadline(pool, std::chrono::seconds(10));
    BOOST_REQUIRE_MESSAGE(first.completed, "first StopExpirationThread() stalled");

    StopOutcome second = RunStopWithDeadline(pool, std::chrono::seconds(10));
    BOOST_CHECK_MESSAGE(second.completed, "second StopExpirationThread() stalled");
    if (!second.completed) return;  // leak rather than destruct a stuck pool
    BOOST_CHECK_LT(second.seconds, 1.0);

    BOOST_CHECK(MempoolShutdownWakeupTestAccess::StopFlag(*pool));

    // Destructor delegates to StopExpirationThread() a third time.
    delete pool;
}

BOOST_AUTO_TEST_SUITE_END()
