// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <crypto/randomx_hash.h>
#include <randomx.h>

#include <vector>
#include <mutex>
#include <stdexcept>
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
    //     Linux:   vm.nr_hugepages, or transparent hugepages
    //     Windows: the "Lock pages in memory" right (SeLockMemoryPrivilege)
    //     macOS:   not supported by RandomX
    //
    // So we request it explicitly and MUST survive it being refused. Every RandomX
    // allocator returns nullptr (never throws) when large pages are unavailable, so
    // each helper below retries the same allocation without the flag. A node with no
    // large-page privilege keeps starting and mining exactly as before -- that
    // fallback is load-bearing, not defensive dressing: without it this change would
    // stop every such miner from starting at all.
    //
    // Scope note: applied to the mining/full-mode path only. The light-mode
    // validation cache is deliberately left on standard pages so it cannot consume
    // the limited large-page pool that the 2GB mining dataset and the per-thread
    // scratchpads need.
    //
    // Gating: OFF unless the node explicitly opts in via
    // randomx_set_large_pages_allowed(1). FULL mode is initialized on non-mining
    // nodes too (8GB+ RAM, to speed up IBD verification), and pinning ~2GB of
    // non-swappable memory on a relay node that never mines is a bad trade -- see
    // the header comment for the full reasoning.

    std::atomic<bool> g_large_pages_allowed{false};

    randomx_cache* AllocCacheLargePages(randomx_flags flags, bool& got_large_pages) {
        if (g_large_pages_allowed.load(std::memory_order_relaxed)) {
            if (randomx_cache* cache = randomx_alloc_cache(flags | RANDOMX_FLAG_LARGE_PAGES)) {
                got_large_pages = true;
                return cache;
            }
        }
        got_large_pages = false;
        return randomx_alloc_cache(flags);
    }

    randomx_dataset* AllocDatasetLargePages(randomx_flags flags, bool& got_large_pages) {
        if (g_large_pages_allowed.load(std::memory_order_relaxed)) {
            if (randomx_dataset* dataset = randomx_alloc_dataset(flags | RANDOMX_FLAG_LARGE_PAGES)) {
                got_large_pages = true;
                return dataset;
            }
        }
        got_large_pages = false;
        return randomx_alloc_dataset(flags);
    }

    // Large pages here back the VM's 2MB scratchpad, which is independent of how the
    // cache and dataset were allocated -- so this is tried per VM and falls back on
    // its own. Mining threads call this once each at startup; a partial pool simply
    // means some threads get large pages and the rest do not.
    randomx_vm* CreateVmLargePages(randomx_flags flags, randomx_cache* cache, randomx_dataset* dataset) {
        if (g_large_pages_allowed.load(std::memory_order_relaxed)) {
            if (randomx_vm* vm = randomx_create_vm(flags | RANDOMX_FLAG_LARGE_PAGES, cache, dataset)) {
                return vm;
            }
        }
        return randomx_create_vm(flags, cache, dataset);
    }
}

extern "C" void randomx_set_large_pages_allowed(int allowed) {
    g_large_pages_allowed.store(allowed != 0, std::memory_order_relaxed);
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

    // Allocate and initialize cache (required for both modes). Large pages are only
    // requested for full/mining mode -- see the scope note on the helpers above.
    if (light_mode) {
        g_randomx_cache = randomx_alloc_cache(flags);
    } else {
        bool cache_large_pages = false;
        g_randomx_cache = AllocCacheLargePages(flags, cache_large_pages);
    }
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
        g_randomx_dataset = AllocDatasetLargePages(flags, dataset_large_pages);
        if (g_randomx_dataset == nullptr) {
            randomx_release_cache(g_randomx_cache);
            g_randomx_cache = nullptr;
            throw std::runtime_error("Failed to allocate RandomX dataset");
        }

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

    // Start background initialization thread (we won the race)
    g_randomx_ready = false;
    g_randomx_progress = 0;

    // Join any existing thread
    if (g_randomx_init_thread.joinable()) {
        g_randomx_init_thread.join();
    }

    // Copy key data for thread safety
    std::vector<uint8_t> key_copy((const uint8_t*)key, (const uint8_t*)key + key_len);

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

    // Join any existing thread
    if (g_mining_init_thread.joinable()) {
        g_mining_init_thread.join();
    }

    // Copy key for thread safety
    std::vector<uint8_t> key_copy((const uint8_t*)key, (const uint8_t*)key + key_len);

    // Launch async initialization thread (move key_copy into lambda to avoid copy)
    g_mining_init_thread = std::thread([key_copy = std::move(key_copy)]() {
        try {
            auto start_time = std::chrono::steady_clock::now();

            std::lock_guard<std::mutex> lock(g_mining_mutex);

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

            // Allocate cache (large pages if the OS allows, standard pages otherwise)
            bool cache_large_pages = false;
            g_mining_cache = AllocCacheLargePages(flags, cache_large_pages);
            if (g_mining_cache == nullptr) {
                throw std::runtime_error("Failed to allocate RandomX mining cache");
            }
            randomx_init_cache(g_mining_cache, key_copy.data(), key_copy.size());

            // Allocate dataset (2GB) -- this is the allocation that dominates hashrate
            bool dataset_large_pages = false;
            g_mining_dataset = AllocDatasetLargePages(flags, dataset_large_pages);
            if (g_mining_dataset == nullptr) {
                randomx_release_cache(g_mining_cache);
                g_mining_cache = nullptr;
                throw std::runtime_error("Failed to allocate RandomX mining dataset");
            }

            // Tell the miner which path they got. Without this line a user has no way
            // to tell a ~2x hashrate deficit from normal behaviour for their hardware.
            // Stay quiet when large pages were never requested (non-mining node): the
            // "half your hashrate" warning would be alarming and meaningless there.
            if (g_large_pages_allowed.load(std::memory_order_relaxed)) {
                if (dataset_large_pages && cache_large_pages) {
                    std::cout << "  [MINING] Large pages: ENABLED" << std::endl;
                } else {
                    std::cout << "  [MINING] Large pages: UNAVAILABLE - mining on standard 4KB pages,"
                              << " expect roughly half the achievable hashrate." << std::endl;
                    std::cout << "  [MINING] To enable, see docs/MINING-LARGE-PAGES.md"
                              << " (Linux: vm.nr_hugepages; Windows: Lock pages in memory)." << std::endl;
                }
            }

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
                    randomx_init_dataset(dataset_ptr, cache_ptr, start_item, count);
                });
            }

            for (auto& thread : init_threads) {
                thread.join();
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
    if (g_mining_init_thread.joinable()) {
        std::cout << "  [WAIT] Waiting for mining mode initialization..." << std::endl;
        g_mining_init_thread.join();
        std::cout << "  [WAIT] Mining mode initialization complete" << std::endl;
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
