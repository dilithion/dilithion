// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <crypto/randomx_hash.h>
#include <randomx.h>

#include <algorithm>
#include <string>
#include <vector>
#include <mutex>
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>

namespace {
    randomx_cache* g_randomx_cache = nullptr;
    randomx_dataset* g_randomx_dataset = nullptr;
    randomx_vm* g_randomx_vm = nullptr;
    std::mutex g_randomx_mutex;
    std::vector<uint8_t> g_current_key;
    bool g_is_light_mode = false;

    // Async initialization state (Monero-style)
    std::atomic<bool> g_randomx_ready{false};
    std::atomic<bool> g_randomx_initializing{false};
    std::thread g_randomx_init_thread;
    std::atomic<int> g_randomx_progress{0};  // 0-100%

    // ========================================================================
    // BUG #55 FIX: Monero-Style Dual-Mode RandomX Architecture
    // ========================================================================
    // Separate instances for validation (LIGHT) and mining (FULL)
    // Following Monero's proven pattern for instant node startup
    // ========================================================================

    // Validation mode (LIGHT) - always available after init, instant startup
    randomx_cache* g_validation_cache = nullptr;
    randomx_vm* g_validation_vm = nullptr;
    std::mutex g_validation_mutex;
    std::atomic<bool> g_validation_ready{false};
    std::vector<uint8_t> g_validation_key;

    // Mining mode (FULL) - async background initialization
    randomx_cache* g_mining_cache = nullptr;
    randomx_dataset* g_mining_dataset = nullptr;
    randomx_vm* g_mining_vm = nullptr;
    std::mutex g_mining_mutex;
    std::atomic<bool> g_mining_ready{false};
    std::atomic<bool> g_mining_initializing{false};
    std::thread g_mining_init_thread;
    std::vector<uint8_t> g_mining_key;

    // ========================================================================
    // Background-init thread lifecycle
    // ========================================================================
    // g_randomx_init_thread and g_mining_init_thread are namespace-scope
    // std::thread objects. A std::thread that is still joinable when its
    // destructor runs calls std::terminate() -- and for a namespace-scope
    // object that destructor runs at static-destruction time, i.e. AFTER
    // main() has returned its exit code. Every exit path that launched a
    // background init but never joined it therefore ended in
    // "terminate called without an active exception" and an abort exit code
    // (3 under the MSVC runtime, 134 on Linux) in place of the intended one.
    //
    // That is not hypothetical: dilithion-node.cpp starts FULL-mode init
    // unconditionally on any host with >=8GB RAM, including relay-only runs
    // and runs that are about to refuse at wallet init. The wallet guard's
    // "this is a deliberate stop, not a crash" message was printed by a
    // process that then aborted, and its `return 1` never reached the shell.
    //
    // Fix: a single randomx_shutdown() that JOINS both threads, called from an
    // RAII guard local to main() in both node binaries (so it runs on every
    // return, early or not) and additionally registered with std::atexit as a
    // backstop for any exit path that bypasses main's scope.
    //
    // JOIN, not detach: the init threads write g_mining_cache /
    // g_mining_dataset / g_mining_vm / g_mining_key, which are objects in this
    // TU with static storage duration. A detached thread still running while
    // those are being destroyed is a use-after-free during teardown -- trading
    // a deterministic abort for a nondeterministic one. Nothing is detached
    // anywhere in this module.
    //
    // Joining is bounded because g_randomx_shutdown is a cancellation flag the
    // dataset build polls between batches: without it, a shutdown one second
    // into a 2GB dataset build would block the process for the remainder of
    // that build (tens of seconds), which on the wallet-refusal path is a
    // regression the user would experience as a hang.
    std::atomic<bool> g_randomx_shutdown{false};

    // Guards the two thread handles themselves (joinable()/join()/assignment).
    // Deliberately NOT g_mining_mutex: the mining-init lambda holds that one for
    // its whole run, so waiting on it here would make shutdown block on the very
    // work it is trying to cancel. No code path takes this mutex and then
    // g_mining_mutex, so the two cannot deadlock against each other.
    std::mutex g_init_threads_mutex;

    // Registered on first async launch, which is necessarily after this TU's
    // statics are constructed -- and handlers registered later run earlier
    // ([basic.start.term]), so this is guaranteed to run before the std::thread
    // destructors it exists to protect.
    std::once_flag g_atexit_once;

    void RegisterShutdownAtExit() {
        std::call_once(g_atexit_once, []() {
            std::atexit([]() { randomx_shutdown(); });
        });
    }

    // ========================================================================
    // Large-page allocation (miner throughput)
    // ========================================================================
    // RandomX flags are an allocation/codegen choice, NOT a consensus input: the
    // hash of a given input is byte-identical whether or not large pages are used.
    // What they buy is speed. Fast mode walks a 2GB dataset, and on 4KB pages that
    // is ~500k TLB entries -- the resulting translation-miss rate costs roughly half
    // the achievable hashrate on a modern desktop CPU.
    //
    // randomx_get_flags() deliberately omits RANDOMX_FLAG_LARGE_PAGES -- upstream's
    // header says it "must be added manually if desired" -- because the allocation
    // needs OS privileges that may not be present:
    //     Linux:   the EXPLICIT hugetlb pool (vm.nr_hugepages). NOT transparent
    //              hugepages -- upstream allocates with mmap(MAP_HUGETLB)
    //              (depends/randomx/src/virtual_memory.c:226), which draws from the
    //              reserved pool and ignores THP entirely. Setting
    //              transparent_hugepage=always accomplishes nothing here.
    //     Windows: the "Lock pages in memory" right (SeLockMemoryPrivilege). Upstream
    //              enables it in the process token itself before allocating
    //              (virtual_memory.c:210), so granting the right is sufficient -- but
    //              note it stays enabled on the token for the process lifetime.
    //     macOS:   supported, via VM_FLAGS_SUPERPAGE_SIZE_2MB (virtual_memory.c:220).
    //
    // So we request it explicitly and MUST survive it being refused. Every RandomX
    // allocator returns nullptr (never throws) when large pages are unavailable, so
    // each helper below retries the same allocation without the flag. A node with no
    // large-page privilege keeps starting and mining exactly as before -- that
    // fallback is load-bearing, not defensive dressing: without it this change would
    // stop every such miner from starting at all.
    //
    // Scope note: the DATASET and the per-thread VM scratchpads get large pages. The
    // 256MB cache deliberately does NOT, and neither does the light-mode validation
    // cache. This is not squeamishness -- it is an ordering hazard. Exact page counts
    // (2MiB pages, from depends/randomx/src/common.hpp:83-86):
    //     cache      CacheSize      = 268,435,456 B =  128 pages
    //     dataset    DatasetSize  ~= 2,181,038,016 B = 1040 pages (rounded up by mmap)
    //     scratchpad ScratchpadSize =   2,097,152 B =    1 page, per mining thread
    // The cache is allocated first. If it took large pages, then on the very common
    // `vm.nr_hugepages=1024` recipe it would consume 128 of them and leave too few for
    // the dataset -- so the 256MB win would destroy the 2GB win that is the entire
    // point of this change, and the failure would be silent. Skipping the cache makes
    // pool exhaustion degrade monotonically instead of inverting.
    //
    // Gating: OFF unless the node explicitly opts in via
    // randomx_set_large_pages_allowed(1). FULL mode is initialized on non-mining
    // nodes too (8GB+ RAM, to speed up IBD verification), and pinning ~2GB of
    // non-swappable memory on a relay node that never mines is a bad trade -- see
    // the header comment for the full reasoning.

    // The opt-in, and what the FULL-mode mining dataset did with it. Both under one
    // mutex because the question that matters is a compound one -- "was the flag set
    // before or after the dataset committed to a page size?" -- and answering that from
    // independent atomics is a race, not an answer.
    std::mutex g_lp_mutex;
    bool g_lp_allowed = false;    // current opt-in
    // Single state variable for the dataset's use of the opt-in. Deliberately ONE
    // variable and not a (latched, latched_value, outcome) trio: the trio had a member
    // no test could distinguish, and an untestable field in a correctness mechanism is
    // where the next silent regression lives.
    enum class LargePageOutcome {
        Pending,       // the mining dataset has not read the opt-in yet
        Requested,     // read with the opt-in ON; allocating, result not known yet
        Granted,       // requested and the OS gave large pages
        Refused,       // requested and the OS refused; running on 4KB pages
        NotRequested   // read with the opt-in OFF -- committed to 4KB, too late to change
    };
    LargePageOutcome g_lp_outcome = LargePageOutcome::Pending;
    // Last line emitted by randomx_log_large_page_status_for_mining(), for change-only
    // printing -- mining restarts once per block template.
    std::string g_lp_last_logged;

    // Whether the most recent FULL-mode dataset allocation actually landed on large
    // pages. Reported via randomx_large_pages_active().
    std::atomic<bool> g_large_pages_active{false};

    bool LargePagesAllowed() {
        std::lock_guard<std::mutex> lock(g_lp_mutex);
        return g_lp_allowed;
    }

    // Called once by the FULL-mode mining init, immediately before it allocates the
    // dataset. Returns the opt-in it must honour and, atomically with that read, moves
    // the state off Pending.
    //
    // Recording it HERE rather than after the allocation is the fix. "Is it too late to
    // opt in?" was previously approximated by g_mining_ready, which is not set until the
    // 2GB dataset has finished BUILDING 30-120 seconds later -- so a request landing in
    // that window was swallowed in silence while the dataset it was meant to affect had
    // already been committed to 4KB pages. Deciding at the read makes the boundary
    // exact: before it the request is honoured, after it the request is known-too-late
    // and reportable as such.
    //
    // Lock ordering note: callers may hold g_mining_mutex when they get here. Nothing
    // takes g_lp_mutex and then g_mining_mutex, so the two cannot deadlock.
    bool DecideLargePagesForMining() {
        std::lock_guard<std::mutex> lock(g_lp_mutex);
        const bool requested = g_lp_allowed;
        g_lp_outcome = requested ? LargePageOutcome::Requested
                                 : LargePageOutcome::NotRequested;
        return requested;
    }

    void RecordMiningDatasetOutcome(bool requested, bool got_large_pages) {
        std::lock_guard<std::mutex> lock(g_lp_mutex);
        g_lp_outcome = !requested ? LargePageOutcome::NotRequested
                     : got_large_pages ? LargePageOutcome::Granted
                                       : LargePageOutcome::Refused;
    }

    // Takes the caller's snapshot of the flag rather than re-reading it, so a setter
    // call landing mid-init cannot make the allocations and the log line disagree.
    randomx_dataset* AllocDatasetLargePages(randomx_flags flags, bool allowed, bool& got_large_pages) {
        if (allowed) {
            if (randomx_dataset* dataset = randomx_alloc_dataset(flags | RANDOMX_FLAG_LARGE_PAGES)) {
                got_large_pages = true;
                g_large_pages_active.store(true, std::memory_order_relaxed);
                return dataset;
            }
        }
        got_large_pages = false;
        g_large_pages_active.store(false, std::memory_order_relaxed);
        return randomx_alloc_dataset(flags);
    }

    // Large pages here back the VM's 2MB scratchpad, which is independent of how the
    // cache and dataset were allocated -- so this is tried per VM and falls back on
    // its own. Mining threads call this once each at startup; a partial pool simply
    // means some threads get large pages and the rest do not.
    randomx_vm* CreateVmLargePages(randomx_flags flags, randomx_cache* cache, randomx_dataset* dataset) {
        if (LargePagesAllowed()) {
            if (randomx_vm* vm = randomx_create_vm(flags | RANDOMX_FLAG_LARGE_PAGES, cache, dataset)) {
                return vm;
            }
        }
        return randomx_create_vm(flags, cache, dataset);
    }

    // Single place that reports the outcome, so both full-mode entry points say the
    // same thing and neither can silently skip it.
    void ReportLargePageStatus(bool allowed, bool dataset_got_large_pages) {
        if (!allowed) {
            return;  // never requested (relay node): the warning would be meaningless
        }
        if (dataset_got_large_pages) {
            std::cout << "  [MINING] Large pages: ENABLED (2GB dataset)" << std::endl;
        } else {
            std::cout << "  [MINING] Large pages: UNAVAILABLE - mining on standard 4KB pages,"
                      << " expect roughly half the achievable hashrate." << std::endl;
            std::cout << "  [MINING] To enable, see docs/MINING-LARGE-PAGES.md"
                      << " (Linux: vm.nr_hugepages; Windows: Lock pages in memory)." << std::endl;
        }
    }
}

extern "C" int randomx_large_pages_active() {
    return g_large_pages_active.load(std::memory_order_relaxed) ? 1 : 0;
}

extern "C" void randomx_set_large_pages_allowed(int allowed) {
    std::lock_guard<std::mutex> lock(g_lp_mutex);
    g_lp_allowed = (allowed != 0);
    // Deliberately silent. Whether this request will be honoured is not knowable from
    // the setter alone -- it depends on whether the mining dataset has already read the
    // flag (see DecideLargePagesForMining) -- and an earlier revision that guessed from
    // g_mining_ready got it wrong in the common case: a set(1) landing while the dataset
    // build was still in flight saw g_mining_ready==false, printed nothing, and was
    // swallowed anyway. Reporting is single-sourced in
    // randomx_log_large_page_status_for_mining(), which reads the recorded decision.
}

// One line, always, for a node that is actually mining. See the contract in the header.
//
// This exists because the status was previously reported only from inside the dataset
// allocator, and only when the opt-in was already on. A node started without --mine on
// an 8GB+ host builds its dataset at startup with the opt-in off, so when the user later
// began mining the allocator had long since run, the "not requested" branch had returned
// early, and the log contained no large-page line of any kind. The operator saw half the
// hashrate and nothing explaining it.
extern "C" void randomx_log_large_page_status_for_mining(int full_mode_expected) {
    bool allowed;
    LargePageOutcome outcome;
    {
        std::lock_guard<std::mutex> lock(g_lp_mutex);
        allowed = g_lp_allowed;
        outcome = g_lp_outcome;
    }

    std::string msg;

    if (!full_mode_expected) {
        // No 2GB dataset will ever exist on this host, so "large pages" has no referent.
        // Say that rather than saying nothing -- silence is what hid the original defect.
        msg = "  [MINING] Large pages: N/A - LIGHT mode only (the 2GB FULL-mode dataset"
              " that large pages back needs >= 3072 MB RAM).";
    } else {
        switch (outcome) {
        case LargePageOutcome::Requested:
            // In flight: the allocation has read the opt-in but has not reported what it
            // got. Promise the follow-up rather than claiming an outcome.
            msg = "  [MINING] Large pages: REQUESTED - the 2GB dataset is being allocated"
                  " now; the ENABLED/UNAVAILABLE result follows.";
            break;
        case LargePageOutcome::Granted:
            msg = "  [MINING] Large pages: ENABLED (2GB dataset)";
            break;
        case LargePageOutcome::Refused:
            msg = "  [MINING] Large pages: UNAVAILABLE - mining on standard 4KB pages, expect"
                  " roughly half the achievable hashrate.\n"
                  "  [MINING] To enable, see docs/MINING-LARGE-PAGES.md"
                  " (Linux: vm.nr_hugepages; Windows: Lock pages in memory).";
            break;
        case LargePageOutcome::NotRequested:
            // The dataset READ the opt-in while it was off, so it is committed to 4KB
            // pages -- whether or not it has finished building. The node was started
            // without --mine on an 8GB+ host and the IBD speedup got there first.
            // Re-allocating is not safe (mining VMs hold pointers into the dataset), so
            // this is terminal for the process.
            msg = "  [MINING] Large pages: IGNORED - the 2GB dataset was already allocated on"
                  " standard pages before mining started, and cannot be moved.\n"
                  "  [MINING] Restart the node with --mine to allocate it with large pages.";
            break;
        case LargePageOutcome::Pending:
            msg = allowed
                ? "  [MINING] Large pages: REQUESTED - will be applied when the 2GB FULL-mode"
                  " dataset is allocated."
                : "  [MINING] Large pages: NOT REQUESTED (no opt-in on this path).";
            break;
        }
    }

    // Print only on change. Mining is (re)started once per block template, so an
    // unconditional print here would put this line in the log every few seconds. Keyed on
    // the message rather than a once-flag so the genuine transition REQUESTED -> ENABLED
    // is still reported -- a once-flag would freeze the log on the provisional answer.
    {
        std::lock_guard<std::mutex> lock(g_lp_mutex);
        if (msg == g_lp_last_logged) {
            return;
        }
        g_lp_last_logged = msg;
    }
    std::cout << msg << std::endl;
}

extern "C" void randomx_init_for_hashing(const void* key, size_t key_len, int light_mode) {
    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    std::vector<uint8_t> new_key((const uint8_t*)key, (const uint8_t*)key + key_len);
    if (g_randomx_cache != nullptr && g_current_key == new_key && g_is_light_mode == (bool)light_mode) {
        return;
    }

    // Cleanup existing resources
    if (g_randomx_vm != nullptr) {
        randomx_destroy_vm(g_randomx_vm);
        g_randomx_vm = nullptr;
    }
    if (g_randomx_dataset != nullptr) {
        randomx_release_dataset(g_randomx_dataset);
        g_randomx_dataset = nullptr;
    }
    if (g_randomx_cache != nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
    }

    // BUG #73 FIX: Use optimal RandomX flags for full performance
    //
    // RandomX is deterministic: flags select an implementation and an allocation
    // strategy, they never change the hash of a given input. Two nodes with different
    // CPU features therefore agree on every hash, and using the fast paths costs no
    // consensus safety. (An earlier revision of this comment claimed the opposite and
    // said we "enforce RANDOMX_FLAG_DEFAULT" -- that was never what the code did, and
    // the belief behind it is why large pages went unrequested for so long.)
    //
    // So: take everything randomx_get_flags() detects (JIT, hardware AES, Argon2
    // AVX2/SSSE3), add FULL_MEM for mining, and add LARGE_PAGES opportunistically in
    // the allocators below.
    //
    // Note: LIGHT vs FULL mode affects memory usage and speed, NOT hash output.
    randomx_flags flags = randomx_get_flags();

    if (!light_mode) {
        // Full mode: Add FULL_MEM flag for 2GB dataset (faster hashing)
        flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM;
    }

    // Snapshot the opt-in once, so the allocations below and the status line reported
    // afterwards cannot disagree if a setter call lands mid-init.
    const bool large_pages_allowed = !light_mode && LargePagesAllowed();

    // Allocate and initialize cache (required for both modes). The cache never takes
    // large pages -- see the ordering hazard in the scope note on the helpers above.
    g_randomx_cache = randomx_alloc_cache(flags);
    if (g_randomx_cache == nullptr) {
        throw std::runtime_error("Failed to allocate RandomX cache");
    }
    randomx_init_cache(g_randomx_cache, key, key_len);

    if (light_mode) {
        // LIGHT MODE: Create VM from cache (fast init, slower hashing)
        g_randomx_vm = randomx_create_vm(flags, g_randomx_cache, nullptr);
        if (g_randomx_vm == nullptr) {
            randomx_release_cache(g_randomx_cache);
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to create RandomX VM in light mode");
        }
    } else {
        // FULL MODE: Allocate dataset, initialize it from cache, create VM from dataset
        // This is the correct mode for production mining and consensus verification
        bool dataset_large_pages = false;
        g_randomx_dataset = AllocDatasetLargePages(flags, large_pages_allowed, dataset_large_pages);
        if (g_randomx_dataset == nullptr) {
            randomx_release_cache(g_randomx_cache);
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to allocate RandomX dataset");
        }
        ReportLargePageStatus(large_pages_allowed, dataset_large_pages);

        // BUG #51 FIX: Thread-safe multi-threaded dataset initialization
        // Following XMRig PR #1146 and Monero patterns for proper synchronization
        // Ensures dataset allocation is complete and visible before thread creation
        std::atomic_thread_fence(std::memory_order_release);

        // Get local copies of pointers for thread-safe capture
        auto dataset_ptr = g_randomx_dataset;
        auto cache_ptr = g_randomx_cache;

        unsigned long dataset_item_count = randomx_dataset_item_count();
        unsigned int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 2;  // Default to 2 if detection fails

        std::cout << "  [FULL MODE] Initializing RandomX dataset with " << num_threads << " threads..." << std::endl;

        std::vector<std::thread> init_threads;
        init_threads.reserve(num_threads);  // Pre-allocate to avoid reallocation during push

        unsigned long items_per_thread = dataset_item_count / num_threads;
        unsigned long items_remainder = dataset_item_count % num_threads;

        auto start_time = std::chrono::steady_clock::now();

        for (unsigned int t = 0; t < num_threads; t++) {
            unsigned long start_item = t * items_per_thread;
            unsigned long count = items_per_thread;

            // Last thread gets any remainder items
            if (t == num_threads - 1) {
                count += items_remainder;
            }

            // Capture local pointer copies, not globals - prevents race condition
            init_threads.emplace_back([dataset_ptr, cache_ptr, start_item, count]() {
                randomx_init_dataset(dataset_ptr, cache_ptr, start_item, count);
            });
        }

        // Wait for all threads to complete
        for (auto& thread : init_threads) {
            thread.join();
        }

        // Ensure all dataset writes are visible before creating VM
        std::atomic_thread_fence(std::memory_order_acquire);

        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
        std::cout << "  [FULL MODE] Dataset initialized in " << duration.count() << "s" << std::endl;

        // Create VM with dataset (cache is still needed for some operations)
        g_randomx_vm = CreateVmLargePages(flags, g_randomx_cache, g_randomx_dataset);
        if (g_randomx_vm == nullptr) {
            randomx_release_dataset(g_randomx_dataset);
            randomx_release_cache(g_randomx_cache);
            g_randomx_dataset = nullptr;
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to create RandomX VM in full mode");
        }
    }

    g_current_key = std::move(new_key);
    g_is_light_mode = light_mode;
    g_randomx_ready = true;  // Mark as ready for thread VM creation
}

void randomx_cleanup() {
    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    if (g_randomx_vm != nullptr) {
        randomx_destroy_vm(g_randomx_vm);
        g_randomx_vm = nullptr;
    }
    if (g_randomx_dataset != nullptr) {
        randomx_release_dataset(g_randomx_dataset);
        g_randomx_dataset = nullptr;
    }
    if (g_randomx_cache != nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
    }
    g_current_key.clear();
    g_is_light_mode = false;
}

void randomx_hash(const void* input, size_t input_len, void* output,
                  const void* key, size_t key_len) {
    randomx_init_for_hashing(key, key_len, 0 /* full mode */);
    randomx_hash_fast(input, input_len, output);
}

void randomx_hash_fast(const void* input, size_t input_len, void* output) {
    // Validate inputs
    if (input == nullptr && input_len > 0) {
        throw std::invalid_argument("randomx_hash_fast: input is NULL but input_len > 0");
    }
    if (output == nullptr) {
        throw std::invalid_argument("randomx_hash_fast: output buffer is NULL");
    }

    // BUG #55 FIX: Prefer validation mode (dual-mode architecture)
    // This ensures block validation works immediately after startup
    if (g_validation_ready.load()) {
        std::lock_guard<std::mutex> lock(g_validation_mutex);
        if (g_validation_vm != nullptr) {
            randomx_calculate_hash(g_validation_vm, input, input_len, output);
            return;
        }
    }

    // Fallback to legacy global VM (for backward compatibility)
    std::lock_guard<std::mutex> lock(g_randomx_mutex);

    if (g_randomx_vm == nullptr) {
        throw std::runtime_error("RandomX VM not initialized");
    }

    randomx_calculate_hash(g_randomx_vm, input, input_len, output);
}

// Async initialization (Monero-style)
// Returns immediately, initialization happens in background thread
extern "C" void randomx_init_async(const void* key, size_t key_len, int light_mode) {
    // CRITICAL-3 FIX: Atomic compare-exchange to prevent TOCTOU race condition
    // Two threads could both pass the check and start duplicate initialization threads
    bool expected = false;
    if (!g_randomx_initializing.compare_exchange_strong(expected, true)) {
        // Another thread is already initializing or initialization failed to start
        std::cout << "  RandomX already initializing or ready" << std::endl;
        return;
    }

    // Check if already ready (after winning the race)
    if (g_randomx_ready.load()) {
        g_randomx_initializing = false;  // Release the lock
        std::cout << "  RandomX already initialized" << std::endl;
        return;
    }

    // Refuse to start new background work once shutdown has begun -- otherwise
    // a late call could hand randomx_shutdown() a thread it has already joined
    // past, and we would be back to terminating at static destruction.
    if (g_randomx_shutdown.load(std::memory_order_acquire)) {
        g_randomx_initializing = false;
        return;
    }

    // Start background initialization thread (we won the race)
    g_randomx_ready = false;
    g_randomx_progress = 0;

    // Backstop for exit paths that never reach main's guard.
    RegisterShutdownAtExit();

    // Copy key data for thread safety
    std::vector<uint8_t> key_copy((const uint8_t*)key, (const uint8_t*)key + key_len);

    std::lock_guard<std::mutex> thread_lock(g_init_threads_mutex);

    // Join any existing thread
    if (g_randomx_init_thread.joinable()) {
        g_randomx_init_thread.join();
    }

    // Launch async initialization thread (move key_copy into lambda to avoid copy)
    g_randomx_init_thread = std::thread([key_copy = std::move(key_copy), light_mode]() {
        try {
            std::cout << "  [ASYNC] RandomX initialization started in background thread" << std::endl;
            std::cout << "  [ASYNC] Mode: " << (light_mode ? "LIGHT" : "FULL") << std::endl;

            auto start_time = std::chrono::steady_clock::now();

            // Call existing blocking init
            randomx_init_for_hashing(key_copy.data(), key_copy.size(), light_mode);

            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

            g_randomx_ready = true;
            g_randomx_progress = 100;

            std::cout << "  [OK] RandomX initialized (async, " << duration.count() << "s)" << std::endl;

        } catch (const std::exception& e) {
            std::cerr << "  [ERROR] RandomX async init failed: " << e.what() << std::endl;
            g_randomx_ready = false;
            g_randomx_progress = 0;
        }
        g_randomx_initializing = false;
    });

    std::cout << "  [ASYNC] RandomX initialization thread launched (non-blocking)" << std::endl;
}

// Check if RandomX is ready for hashing
extern "C" int randomx_is_ready() {
    return g_randomx_ready.load() ? 1 : 0;
}

// Wait for RandomX initialization to complete
extern "C" void randomx_wait_for_init() {
    std::lock_guard<std::mutex> thread_lock(g_init_threads_mutex);
    if (g_randomx_init_thread.joinable()) {
        std::cout << "  [WAIT] Waiting for RandomX initialization to complete..." << std::endl;
        g_randomx_init_thread.join();
        std::cout << "  [WAIT] RandomX initialization complete" << std::endl;
    }
}

// BUG #28 FIX: Per-Thread RandomX VM Implementation
// Each mining thread creates its own VM for true parallel mining

extern "C" void* randomx_create_thread_vm() {
    // BUG #55 FIX: Monero-style dual-mode VM creation
    // Try FULL mode first (mining), fall back to LIGHT mode (validation)

    randomx_flags flags = randomx_get_flags();
    randomx_vm* vm = nullptr;

    // Option 1: Use mining mode (FULL) if ready
    if (g_mining_ready.load()) {
        std::lock_guard<std::mutex> lock(g_mining_mutex);
        if (g_mining_dataset && g_mining_cache) {
            flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM;
            vm = CreateVmLargePages(flags, g_mining_cache, g_mining_dataset);
            if (vm) {
                return static_cast<void*>(vm);
            }
            std::cerr << "[WARN] Failed to create thread VM (FULL mode), trying LIGHT mode" << std::endl;
        }
    }

    // Option 2: Use validation mode (LIGHT) - always available after startup
    if (g_validation_ready.load()) {
        std::lock_guard<std::mutex> lock(g_validation_mutex);
        if (g_validation_cache) {
            flags = RANDOMX_FLAG_DEFAULT;
            vm = randomx_create_vm(flags, g_validation_cache, nullptr);
            if (vm) {
                return static_cast<void*>(vm);
            }
            std::cerr << "[ERROR] Failed to create thread VM (LIGHT mode)" << std::endl;
        }
    }

    // Option 3: Fallback to legacy global VM (for backward compatibility)
    if (g_randomx_ready.load()) {
        std::lock_guard<std::mutex> lock(g_randomx_mutex);
        if (g_randomx_dataset || g_randomx_cache) {
            if (g_is_light_mode) {
                vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, g_randomx_cache, nullptr);
            } else {
                flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM;
                vm = CreateVmLargePages(flags, g_randomx_cache, g_randomx_dataset);
            }
            if (vm) {
                return static_cast<void*>(vm);
            }
        }
    }

    std::cerr << "[ERROR] RandomX not initialized - cannot create thread VM" << std::endl;
    return nullptr;
}

extern "C" void randomx_destroy_thread_vm(void* vm) {
    if (!vm) return;

    randomx_vm* rx_vm = static_cast<randomx_vm*>(vm);
    randomx_destroy_vm(rx_vm);
}

extern "C" void randomx_hash_thread(void* vm, const void* input, size_t input_len, void* output) {
    // Validate inputs
    if (!vm) {
        throw std::invalid_argument("randomx_hash_thread: vm is NULL");
    }
    if (input == nullptr && input_len > 0) {
        throw std::invalid_argument("randomx_hash_thread: input is NULL but input_len > 0");
    }
    if (output == nullptr) {
        throw std::invalid_argument("randomx_hash_thread: output buffer is NULL");
    }

    // NO MUTEX NEEDED! Each thread owns its VM, enabling true parallel mining
    // This is the key fix: instead of serializing on g_randomx_mutex,
    // each thread hashes independently using its own VM
    randomx_vm* rx_vm = static_cast<randomx_vm*>(vm);
    randomx_calculate_hash(rx_vm, input, input_len, output);
}

// ============================================================================
// BUG #55 FIX: Monero-Style Dual-Mode RandomX Implementation
// ============================================================================
// Following Monero's proven pattern:
// - LIGHT mode (256MB): Used for ALL block validation (instant startup)
// - FULL mode (2GB): Used ONLY for mining (async background init)
// This allows nodes to start validating blocks immediately while mining
// dataset initializes in the background.
// ============================================================================

extern "C" void randomx_init_validation_mode(const void* key, size_t key_len) {
    std::lock_guard<std::mutex> lock(g_validation_mutex);

    // Check if already initialized with same key
    std::vector<uint8_t> new_key((const uint8_t*)key, (const uint8_t*)key + key_len);
    if (g_validation_cache != nullptr && g_validation_key == new_key) {
        std::cout << "  [VALIDATION] Already initialized with same key" << std::endl;
        return;
    }

    std::cout << "  [VALIDATION] Initializing LIGHT mode for block validation..." << std::endl;
    auto start_time = std::chrono::steady_clock::now();

    // Cleanup existing resources
    if (g_validation_vm != nullptr) {
        randomx_destroy_vm(g_validation_vm);
        g_validation_vm = nullptr;
    }
    if (g_validation_cache != nullptr) {
        randomx_release_cache(g_validation_cache);
        g_validation_cache = nullptr;
    }

    // Always use LIGHT mode for validation (RANDOMX_FLAG_DEFAULT only)
    randomx_flags flags = randomx_get_flags();

    // Allocate and initialize cache
    g_validation_cache = randomx_alloc_cache(flags);
    if (g_validation_cache == nullptr) {
        throw std::runtime_error("Failed to allocate RandomX validation cache");
    }
    randomx_init_cache(g_validation_cache, key, key_len);

    // Create VM with cache (LIGHT mode)
    g_validation_vm = randomx_create_vm(flags, g_validation_cache, nullptr);
    if (g_validation_vm == nullptr) {
        randomx_release_cache(g_validation_cache);
        g_validation_cache = nullptr;
        throw std::runtime_error("Failed to create RandomX validation VM");
    }

    g_validation_key = std::move(new_key);
    g_validation_ready = true;

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    std::cout << "  [OK] Validation mode ready (LIGHT, " << duration.count() << "ms)" << std::endl;
}

extern "C" void randomx_init_mining_mode_async(const void* key, size_t key_len) {
    // Atomic compare-exchange to prevent race condition
    bool expected = false;
    if (!g_mining_initializing.compare_exchange_strong(expected, true)) {
        return;  // Already initializing
    }

    // Check if already ready
    if (g_mining_ready.load()) {
        g_mining_initializing = false;
        return;  // Already initialized
    }

    // Refuse to start new background work once shutdown has begun. See the same
    // guard in randomx_init_async().
    if (g_randomx_shutdown.load(std::memory_order_acquire)) {
        g_mining_initializing = false;
        return;
    }

    // Backstop for exit paths that never reach main's guard.
    RegisterShutdownAtExit();

    // Copy key for thread safety
    std::vector<uint8_t> key_copy((const uint8_t*)key, (const uint8_t*)key + key_len);

    std::lock_guard<std::mutex> thread_lock(g_init_threads_mutex);

    // Join any existing thread
    if (g_mining_init_thread.joinable()) {
        g_mining_init_thread.join();
    }

    // Launch async initialization thread (move key_copy into lambda to avoid copy)
    g_mining_init_thread = std::thread([key_copy = std::move(key_copy)]() {
        try {
            auto start_time = std::chrono::steady_clock::now();

            std::lock_guard<std::mutex> lock(g_mining_mutex);

            // Cheapest cancellation point: shutdown may already have been
            // requested between the launch above and this thread being scheduled.
            if (g_randomx_shutdown.load(std::memory_order_acquire)) {
                g_mining_initializing = false;
                return;
            }

            // Cleanup existing resources
            if (g_mining_vm != nullptr) {
                randomx_destroy_vm(g_mining_vm);
                g_mining_vm = nullptr;
            }
            if (g_mining_dataset != nullptr) {
                randomx_release_dataset(g_mining_dataset);
                g_mining_dataset = nullptr;
            }
            if (g_mining_cache != nullptr) {
                randomx_release_cache(g_mining_cache);
                g_mining_cache = nullptr;
            }

            // FULL mode flags
            randomx_flags flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM;

            // Read the opt-in once, and record the decision atomically with the read:
            // the allocation below and the status line afterwards must describe the same
            // decision even if a setter call lands in between, and any set(1) arriving
            // after this point must be reportable as too-late instead of being silently
            // swallowed.
            const bool large_pages_allowed = DecideLargePagesForMining();

            // Allocate cache. Never large pages -- it would eat the pages the dataset
            // needs; see the ordering hazard in the scope note on the helpers above.
            g_mining_cache = randomx_alloc_cache(flags);
            if (g_mining_cache == nullptr) {
                throw std::runtime_error("Failed to allocate RandomX mining cache");
            }
            randomx_init_cache(g_mining_cache, key_copy.data(), key_copy.size());

            // Allocate dataset (2GB) -- this is the allocation that dominates hashrate
            bool dataset_large_pages = false;
            g_mining_dataset = AllocDatasetLargePages(flags, large_pages_allowed, dataset_large_pages);
            if (g_mining_dataset == nullptr) {
                randomx_release_cache(g_mining_cache);
                g_mining_cache = nullptr;
                throw std::runtime_error("Failed to allocate RandomX mining dataset");
            }

            // Record the outcome before reporting it, so a mining start racing this
            // allocation reads the settled answer rather than "pending".
            RecordMiningDatasetOutcome(large_pages_allowed, dataset_large_pages);

            // Tell the miner which path they got. Without this a user has no way to
            // tell a ~2x hashrate deficit from normal behaviour for their hardware.
            // Silent when large pages were never requested -- a relay node has nothing
            // to report. A node that IS mining gets its guaranteed line from
            // randomx_log_large_page_status_for_mining() instead.
            ReportLargePageStatus(large_pages_allowed, dataset_large_pages);

            // Multi-threaded dataset initialization
            std::atomic_thread_fence(std::memory_order_release);

            auto dataset_ptr = g_mining_dataset;
            auto cache_ptr = g_mining_cache;

            unsigned long dataset_item_count = randomx_dataset_item_count();
            unsigned int num_threads = std::thread::hardware_concurrency();
            if (num_threads == 0) num_threads = 2;

            std::cout << "  [MINING] Initializing dataset with " << num_threads << " threads..." << std::endl;

            std::vector<std::thread> init_threads;
            init_threads.reserve(num_threads);

            unsigned long items_per_thread = dataset_item_count / num_threads;
            unsigned long items_remainder = dataset_item_count % num_threads;

            for (unsigned int t = 0; t < num_threads; t++) {
                unsigned long start_item = t * items_per_thread;
                unsigned long count = items_per_thread;
                if (t == num_threads - 1) {
                    count += items_remainder;
                }

                init_threads.emplace_back([dataset_ptr, cache_ptr, start_item, count]() {
                    // Built in batches rather than one call so a shutdown request
                    // is observed within a batch instead of after the whole 2GB
                    // dataset. randomx_init_dataset() itself is uninterruptible,
                    // and the enclosing thread is JOINED at shutdown, so an
                    // unbatched call would make every exit wait out the full build.
                    // 64Ki items is ~4MB of dataset -- microseconds of work.
                    const unsigned long kBatchItems = 65536;
                    for (unsigned long done = 0; done < count; done += kBatchItems) {
                        if (g_randomx_shutdown.load(std::memory_order_acquire)) {
                            return;  // partial dataset; the caller below discards it
                        }
                        const unsigned long n =
                            std::min<unsigned long>(kBatchItems, count - done);
                        randomx_init_dataset(dataset_ptr, cache_ptr, start_item + done, n);
                    }
                });
            }

            for (auto& thread : init_threads) {
                thread.join();
            }

            // Cancelled: the dataset is partially initialized and must never be
            // used for hashing. Leave the cache/dataset allocations to process
            // teardown -- we are on the way out, and releasing a 2GB dataset buys
            // nothing but latency on the exit path.
            if (g_randomx_shutdown.load(std::memory_order_acquire)) {
                g_mining_ready = false;
                g_mining_initializing = false;
                return;
            }

            std::atomic_thread_fence(std::memory_order_acquire);

            // Create VM with dataset
            g_mining_vm = CreateVmLargePages(flags, g_mining_cache, g_mining_dataset);
            if (g_mining_vm == nullptr) {
                randomx_release_dataset(g_mining_dataset);
                randomx_release_cache(g_mining_cache);
                g_mining_dataset = nullptr;
                g_mining_cache = nullptr;
                throw std::runtime_error("Failed to create RandomX mining VM");
            }

            g_mining_key = key_copy;
            g_mining_ready = true;

            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
            std::cout << "  [OK] Mining mode ready (FULL, " << duration.count() << "s)" << std::endl;

        } catch (const std::exception& e) {
            std::cerr << "  [ERROR] Mining mode init failed: " << e.what() << std::endl;
            g_mining_ready = false;
        }
        g_mining_initializing = false;
    });
}

extern "C" int randomx_is_mining_mode_ready() {
    return g_mining_ready.load() ? 1 : 0;
}

extern "C" void randomx_wait_for_mining_mode() {
    std::lock_guard<std::mutex> thread_lock(g_init_threads_mutex);
    if (g_mining_init_thread.joinable()) {
        std::cout << "  [WAIT] Waiting for mining mode initialization..." << std::endl;
        g_mining_init_thread.join();
        std::cout << "  [WAIT] Mining mode initialization complete" << std::endl;
    }
}

// See the contract in randomx_hash.h. Idempotent, and a no-op if nothing was
// ever initialized.
extern "C" void randomx_shutdown() {
    // Publish the cancellation BEFORE taking the handle lock: an in-flight
    // dataset build must be able to observe it while we are still waiting to
    // acquire, otherwise we would serialise behind the very work we are cancelling.
    g_randomx_shutdown.store(true, std::memory_order_release);

    std::lock_guard<std::mutex> thread_lock(g_init_threads_mutex);
    if (g_randomx_init_thread.joinable()) {
        g_randomx_init_thread.join();
    }
    if (g_mining_init_thread.joinable()) {
        g_mining_init_thread.join();
    }
}

extern "C" void randomx_hash_for_validation(const void* input, size_t input_len, void* output) {
    if (input == nullptr && input_len > 0) {
        throw std::invalid_argument("randomx_hash_for_validation: input is NULL");
    }
    if (output == nullptr) {
        throw std::invalid_argument("randomx_hash_for_validation: output is NULL");
    }

    std::lock_guard<std::mutex> lock(g_validation_mutex);

    if (!g_validation_ready.load() || g_validation_vm == nullptr) {
        throw std::runtime_error("Validation mode not initialized");
    }

    randomx_calculate_hash(g_validation_vm, input, input_len, output);
}

extern "C" int randomx_hash_for_mining(const void* input, size_t input_len, void* output) {
    if (input == nullptr && input_len > 0) {
        throw std::invalid_argument("randomx_hash_for_mining: input is NULL");
    }
    if (output == nullptr) {
        throw std::invalid_argument("randomx_hash_for_mining: output is NULL");
    }

    // Try FULL mode first (faster)
    if (g_mining_ready.load()) {
        std::lock_guard<std::mutex> lock(g_mining_mutex);
        if (g_mining_vm != nullptr) {
            randomx_calculate_hash(g_mining_vm, input, input_len, output);
            return 1;  // Used FULL mode
        }
    }

    // Fallback to LIGHT mode (slower but always available)
    std::lock_guard<std::mutex> lock(g_validation_mutex);
    if (!g_validation_ready.load() || g_validation_vm == nullptr) {
        throw std::runtime_error("Neither mining nor validation mode initialized");
    }

    randomx_calculate_hash(g_validation_vm, input, input_len, output);
    return 0;  // Used LIGHT mode fallback
}
