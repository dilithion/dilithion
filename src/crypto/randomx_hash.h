// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef BITCOIN_CRYPTO_RANDOMX_HASH_H
#define BITCOIN_CRYPTO_RANDOMX_HASH_H

#include <stdint.h>
#include <stdlib.h>

static const size_t RANDOMX_HASH_SIZE = 32;

#ifdef __cplusplus
extern "C" {
#endif

void randomx_hash(const void* input, size_t input_len, void* output,
                  const void* key, size_t key_len);

// LEGACY API: Uses global VM with mutex (serialized access)
// USE CASE: Block verification, tests, and other non-performance-critical operations
// For mining hot loops, use randomx_hash_thread() instead (BUG #28 fix)
void randomx_hash_fast(const void* input, size_t input_len, void* output);

void randomx_init_for_hashing(const void* key, size_t key_len, int light_mode);

void randomx_cleanup();

// Async initialization (Monero-style)
// Returns immediately, initialization happens in background thread
void randomx_init_async(const void* key, size_t key_len, int light_mode);

// Check if RandomX is ready for hashing
int randomx_is_ready();

// Wait for RandomX initialization to complete
void randomx_wait_for_init();

// Shut the module's background init threads down. MUST be called on every exit
// path of any binary that can reach randomx_init_async() or
// randomx_init_mining_mode_async() -- normal shutdown AND every early return.
//
// The async initializers run in namespace-scope std::thread objects. A joinable
// std::thread destroyed at static-destruction time calls std::terminate(), which
// happens after main() has returned and so REPLACES the process's intended exit
// code with an abort code. Both node binaries therefore hold an RAII guard local
// to main() whose destructor calls this; the module also registers it with
// std::atexit as a backstop.
//
// Sets a cancellation flag first, so an in-flight FULL-mode dataset build stops
// at the next batch boundary rather than making shutdown wait it out. Joins (never
// detaches): the init threads write objects with static storage duration in the
// RandomX translation unit, and letting them outlive teardown would be a
// use-after-free. Safe to call more than once, and safe to call having never
// initialized anything.
void randomx_shutdown();

// ============================================================================
// BUG #55 FIX: Monero-Style Dual-Mode RandomX Architecture
// ============================================================================
// Following Monero's proven pattern:
// - LIGHT mode (256MB): Used for ALL block validation (instant startup)
// - FULL mode (2GB): Used ONLY for mining (async background init)
// ============================================================================

// Initialize LIGHT mode for block validation (fast, blocking, 1-2 seconds)
// Call this first during node startup - enables immediate block validation
void randomx_init_validation_mode(const void* key, size_t key_len);

// Initialize FULL mode for mining (async, background, 30-60 seconds)
// Call this after validation mode is ready, only if mining is enabled
// Mining can proceed with LIGHT mode while FULL mode initializes
void randomx_init_mining_mode_async(const void* key, size_t key_len);

// Opt in to large-page backing for the FULL-mode dataset and mining scratchpads.
// Worth roughly 2x hashrate when the OS grants it, and a silent no-op when it does
// not (allocation falls back to standard pages).
//
// OFF by default, and it must stay that way: FULL mode is also initialized on
// NON-mining nodes with 8GB+ RAM purely to speed up IBD verification. Large pages
// are locked, non-swappable memory, so enabling this unconditionally would pin ~2GB
// on every relay node that never mines a block -- memory the kernel could otherwise
// reclaim under pressure. Relay nodes gain almost nothing in exchange, because IBD
// verification runs at ~100 H/s where TLB pressure is not the bottleneck.
//
// Call with allowed=1 only on a path that is actually about to mine, and call it
// BEFORE anything checks randomx_is_mining_mode_ready() -- the request is honoured only
// if it arrives before the FULL-mode dataset allocation reads it. This setter is silent;
// use randomx_log_large_page_status_for_mining() to report the outcome.
void randomx_set_large_pages_allowed(int allowed);

// Emit the "Large pages:" line describing what a MINING node got. Call it from every
// path that starts mining, after randomx_set_large_pages_allowed(1).
//
// full_mode_expected: 0 if this host will never build the 2GB FULL-mode dataset (RAM
// below the FULL-mode threshold), in which case the line reports N/A. Pass 1 otherwise.
//
// Contract: a node that mines always gets a line -- ENABLED, UNAVAILABLE, REQUESTED
// (dataset not allocated yet), IGNORED (the dataset was already built on standard pages
// before mining asked, which is what happens when a node is started without --mine on an
// 8GB+ host and told to mine later), or N/A. A relay node that never calls this stays
// silent, which is correct: it never asked for large pages.
//
// The IGNORED case is reported off a latch taken at the moment the dataset allocation
// reads the opt-in, NOT off "the dataset has finished building" -- so a request landing
// during the 30-120s build is reported as ignored instead of vanishing.
//
// Prints only when the status text CHANGES, because mining restarts once per block
// template; call it as often as you like.
void randomx_log_large_page_status_for_mining(int full_mode_expected);

// Did the most recently allocated FULL-mode dataset actually get large pages?
// Returns 1 if yes, 0 if it fell back to standard pages or was never requested.
//
// This is the observable half of the feature. Without it, "I enabled large pages
// and nothing happened" is diagnosable only by reading source: the request can be
// silently ignored (flag set after the dataset was already built), or silently
// refused (privilege missing, or the hugetlb pool too small for the 1040 pages the
// dataset needs). It is also what lets a test distinguish this feature working from
// this feature having been deleted.
int randomx_large_pages_active();

// Check if mining (FULL) mode is ready
// Returns 1 if FULL mode is ready, 0 if still initializing or LIGHT mode only
int randomx_is_mining_mode_ready();

// Wait for mining mode to complete (blocking)
void randomx_wait_for_mining_mode();

// Hash for block validation (uses LIGHT mode, always available after init)
// Use this for: verifying received blocks, checking PoW, IBD sync
void randomx_hash_for_validation(const void* input, size_t input_len, void* output);

// Hash for mining (uses FULL mode if ready, falls back to LIGHT mode)
// Use this for: creating new blocks during mining
// Returns 1 if FULL mode was used, 0 if LIGHT mode fallback
int randomx_hash_for_mining(const void* input, size_t input_len, void* output);

// BUG #28 FIX: Per-Thread RandomX VM API
// Create VM for thread (call once per mining thread)
// Returns: opaque VM pointer, or NULL on failure
void* randomx_create_thread_vm();

// Destroy VM when thread exits (call once per mining thread)
// Parameter: VM pointer returned by randomx_create_thread_vm()
void randomx_destroy_thread_vm(void* vm);

// Hash with thread-local VM (no mutex, fully parallel)
// Parameters:
//   vm: VM pointer from randomx_create_thread_vm()
//   input: data to hash
//   input_len: length of input data
//   output: buffer for hash result (must be 32 bytes)
void randomx_hash_thread(void* vm, const void* input, size_t input_len, void* output);

#ifdef __cplusplus
}

#include <util/shutdown_progress.h>  // the guard below owns the FINAL Disarm

// Declare ONE of these as the first local in main(). Its destructor runs on
// every return from main -- the early config/genesis/wallet-refusal returns
// included -- so no exit path can forget randomx_shutdown() and leave a joinable
// namespace-scope std::thread to std::terminate() at static destruction.
//
// Single-sourced here on purpose: dilithion-node and dilv-node both need it, and
// a copy per binary is exactly how the DilV half of the previous wallet-guard fix
// got missed.
struct RandomXShutdownGuard {
    RandomXShutdownGuard() = default;
    ~RandomXShutdownGuard() {
        // First local of main => destructs LAST, making this the final teardown
        // actor on every exit path. It therefore owns the final watchdog
        // disarm: anything disarming earlier leaves the
        // joins below to hang with the watchdog already stood down -- the exact
        // step the shutdown-deadline work exists to bound. Gated on an armed,
        // not-yet-disarmed watchdog so trivial exits (--version, config
        // refusals, pre-shutdown failures) behave exactly as before.
        const bool covered =
            Dilithion::ShutdownProgress::Armed().load(std::memory_order_acquire) &&
            !Dilithion::ShutdownProgress::Disarmed().load(std::memory_order_acquire);
        if (covered) {
            Dilithion::ShutdownProgress::Stage("randomx thread join (final, RAII guard)");
        }
        randomx_shutdown();
        if (covered) {
            Dilithion::ShutdownProgress::Disarm();
        }
    }
    RandomXShutdownGuard(const RandomXShutdownGuard&) = delete;
    RandomXShutdownGuard& operator=(const RandomXShutdownGuard&) = delete;
};
#endif

#endif // BITCOIN_CRYPTO_RANDOMX_HASH_H
