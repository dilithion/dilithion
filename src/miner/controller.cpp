// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <miner/controller.h>
#include <crypto/randomx_hash.h>
#include <crypto/sha3.h>
#include <consensus/pow.h>
#include <consensus/tx_validation.h>
#include <consensus/params.h>
#include <core/chainparams.h>
#include <node/mempool.h>
#include <node/utxo_set.h>
#include <util/time.h>
#include <util/bench.h>  // Performance: Benchmarking
#include <util/error_format.h>  // UX: Better error messages
#include <dfmp/dfmp.h>         // DFMP: Fair Mining Protocol
#include <dfmp/identity_db.h>  // DFMP: Identity persistence
#include <amount.h>

#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <set>
#include <stdexcept>

#ifdef _WIN32
    #include <windows.h>  // For GlobalMemoryStatusEx
#endif

// BUG #28 FIX: RAII wrapper for RandomX VM (prevents leaks)
// LIGHT→FULL auto-upgrade implemented via TryUpgrade() (checked every 1000 hashes)
namespace {
    class RandomXVMGuard {
    private:
        void* m_vm;
        bool m_isFullMode;

    public:
        RandomXVMGuard() : m_vm(nullptr), m_isFullMode(false) {
            // Check if FULL mode is ready before creating VM
            m_isFullMode = randomx_is_mining_mode_ready() != 0;
            m_vm = randomx_create_thread_vm();
            if (!m_vm) {
                throw std::runtime_error("Failed to create RandomX VM for mining thread");
            }
        }

        ~RandomXVMGuard() {
            if (m_vm) {
                randomx_destroy_thread_vm(m_vm);
            }
        }

        // Prevent copying (VM is owned by this guard)
        RandomXVMGuard(const RandomXVMGuard&) = delete;
        RandomXVMGuard& operator=(const RandomXVMGuard&) = delete;

        void* get() const { return m_vm; }

        bool isFullMode() const { return m_isFullMode; }

        // Try to upgrade from LIGHT to FULL mode
        // Returns true if upgrade occurred
        bool TryUpgrade() {
            // Already in FULL mode - no upgrade needed
            if (m_isFullMode) {
                return false;
            }

            // Check if FULL mode is now available
            if (!randomx_is_mining_mode_ready()) {
                return false;
            }

            // FULL mode is ready - upgrade!
            // Destroy old LIGHT mode VM
            if (m_vm) {
                randomx_destroy_thread_vm(m_vm);
                m_vm = nullptr;
            }

            // Create new FULL mode VM
            m_isFullMode = true;
            m_vm = randomx_create_thread_vm();
            if (!m_vm) {
                // Failed to create FULL mode VM - this shouldn't happen
                // but handle gracefully by falling back
                m_isFullMode = false;
                m_vm = randomx_create_thread_vm();
                if (!m_vm) {
                    throw std::runtime_error("Failed to recreate RandomX VM after upgrade attempt");
                }
                return false;
            }

            return true;
        }
    };
}

// Get current time in milliseconds
static uint64_t GetTimeMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

uint64_t CMiningStats::GetUptime() const {
    if (nStartTime == 0) return 0;
    return GetTime() - nStartTime; // Uses util/time.h GetTime()
}

CMiningController::CMiningController(uint32_t nThreads, const std::string& randomxKey)
    : m_nThreads(nThreads), m_randomxKey(randomxKey)
{
    // MINE-016 FIX: Store configurable RandomX key
    // Default is "Dilithion" for mainnet
    // Testnets/regtest can use different keys for separate PoW

    // Auto-detect CPU cores if not specified
    if (m_nThreads == 0) {
        m_nThreads = std::thread::hardware_concurrency();
        if (m_nThreads == 0) {
            m_nThreads = 1; // Fallback to single thread
        }
    }

    // Limit to consensus max threads
    m_nThreads = std::min(m_nThreads.load(), static_cast<uint32_t>(Consensus::MAX_MINING_THREADS));
}

bool CMiningController::SetThreadCount(uint32_t nThreads) {
    if (m_mining) return false; // Can't change while mining
    if (nThreads == 0) {
        nThreads = std::thread::hardware_concurrency();
        if (nThreads == 0) nThreads = 1;
    }
    m_nThreads = std::min(nThreads, static_cast<uint32_t>(Consensus::MAX_MINING_THREADS));
    return true;
}

CMiningController::~CMiningController() {
    StopMining();
}

bool CMiningController::StartMining(const CBlockTemplate& blockTemplate) {
    // MINE-002 FIX: Atomic state transition to prevent race condition
    // Use compare_exchange to atomically check and set mining flag
    bool expected = false;
    if (!m_mining.compare_exchange_strong(expected, true)) {
        // Already mining - another thread won the race
        return false;
    }

    // At this point, m_mining is atomically set to true
    // If any error occurs below, we must reset m_mining to false

    // MINE-008 FIX: Validate block template and difficulty
    if (blockTemplate.hashTarget.IsNull()) {
        m_mining = false;  // Reset flag before returning
        return false;
    }

    // Validate difficulty target is reasonable (not all zeros, not impossible)
    // Minimum difficulty: at least some bits must be zero (not all 0xFF)
    // Maximum difficulty: target must be achievable (not all 0x00)
    bool allZeros = true;
    bool allOnes = true;
    for (size_t i = 0; i < 32; ++i) {
        if (blockTemplate.hashTarget.begin()[i] != 0x00) allZeros = false;
        if (blockTemplate.hashTarget.begin()[i] != 0xFF) allOnes = false;
    }

    if (allZeros || allOnes) {
        m_mining = false;
        return false;  // Invalid target
    }

    // MINE-005 FIX: Initialize RandomX cache with thread synchronization
    // MINE-016 FIX: Use configurable RandomX key instead of hardcoded value
    // Auto-detect RAM to choose appropriate RandomX mode
    // LIGHT mode: ~256MB RAM, ~3-10 H/s (works on 2GB nodes)
    // FULL mode: ~2.5GB RAM, ~100 H/s (requires 4GB+ nodes)

    // Detect available RAM
    size_t total_ram_mb = 0;

#ifdef _WIN32
    // Windows: Use GlobalMemoryStatusEx()
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        total_ram_mb = memInfo.ullTotalPhys / (1024 * 1024);  // Convert bytes to MB
    }
#else
    // Linux: Read /proc/meminfo
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.substr(0, 9) == "MemTotal:") {
                size_t ram_kb = std::stoull(line.substr(9));
                total_ram_mb = ram_kb / 1024;
                break;
            }
        }
        meminfo.close();
    }
#endif

    // BUG #55 FIX: Monero-style dual-mode mining
    // - Validation mode (LIGHT) is already initialized by node startup
    // - Mining can start immediately using LIGHT mode
    // - Mining will automatically upgrade to FULL mode when ready
    // Reaching this line means this process is mining, so record the large-page opt-in
    // NOW -- unconditionally, and before anything looks at mining-mode readiness.
    //
    // This used to sit inside the `else` branch below, which made it unreachable on the
    // primary path: dilithion-node.cpp starts FULL-mode init at startup on any host with
    // >= 8192 MB RAM, mining or not, so by the time a user starts mining
    // randomx_is_mining_mode_ready() is already true, the `else` never runs, and the
    // opt-in was never recorded. Large pages -- the headline of this feature -- were
    // inert on exactly the machines that can use them.
    //
    // Ordering matters more than the branch did: whether the request is honoured depends
    // only on whether it lands before the dataset allocation reads it. Setting it here
    // honours it on every host where the dataset has not been built yet, and makes it
    // reportable as too-late on every host where it has.
    randomx_set_large_pages_allowed(1);

    std::cout << "[Mining] Detected RAM: " << total_ram_mb << " MB" << std::endl;
    // Will this process ever build the 2GB FULL-mode dataset that large pages back?
    // Either it already has, or it is about to below. Below 3GB of RAM it never will,
    // and "large pages" has no referent -- reported as N/A rather than left unsaid.
    const bool full_mode_expected = randomx_is_mining_mode_ready() || total_ram_mb >= 3072;
    if (randomx_is_mining_mode_ready()) {
        std::cout << "[Mining] Using RandomX FULL mode (~100 H/s)" << std::endl;
    } else {
        std::cout << "[Mining] Using RandomX LIGHT mode (~3-10 H/s)" << std::endl;
        if (total_ram_mb >= 3072) {
            // BUG FIX: Actually start FULL mode initialization (was missing!)
            const char* rx_key = "Dilithion-RandomX-v1";
            randomx_init_mining_mode_async(rx_key, strlen(rx_key));
            std::cout << "[Mining] FULL mode initializing in background - will auto-upgrade" << std::endl;
        }
    }

    // A "Large pages:" line on every mining path. A miner who gets half the achievable
    // hashrate must be able to see why in the log without reading source; silence here is
    // what made the previous defect invisible. The call self-dedupes -- StartMining runs
    // once per block template -- so it prints on the first start and again only when the
    // status genuinely changes (REQUESTED -> ENABLED once the dataset lands).
    randomx_log_large_page_status_for_mining(full_mode_expected ? 1 : 0);
    // Note: Mining proceeds immediately, no wait required

    // Store block template
    {
        std::lock_guard<std::mutex> lock(m_templateMutex);
        m_pTemplate = std::make_unique<CBlockTemplate>(blockTemplate);
    }

    // Reset statistics
    m_stats.Reset();
    m_stats.nStartTime = GetTime();

    // Start mining worker threads
    m_workers.clear();
    m_workers.reserve(m_nThreads);
    for (uint32_t i = 0; i < m_nThreads; ++i) {
        m_workers.emplace_back(&CMiningController::MiningWorker, this, i);
    }

    // Start hash rate monitoring thread
    m_monitoring = true;
    m_monitorThread = std::thread(&CMiningController::HashRateMonitor, this);

    return true;
}

void CMiningController::StopMining() {
    // MINE-002 FIX: Atomic state transition to prevent race condition
    // Use compare_exchange to atomically check and set mining flag
    bool expected = true;
    if (!m_mining.compare_exchange_strong(expected, false)) {
        // Not mining - another thread already stopped, or never started
        return;
    }

    // At this point, m_mining is atomically set to false
    // Worker threads will see this and terminate their loops

    // Stop monitoring flag
    m_monitoring = false;

    // Wait for worker threads to complete
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    m_workers.clear();

    // Wait for monitoring thread
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }

    // CRITICAL-8 FIX: Do NOT cleanup RandomX when stopping mining!
    // RandomX VM is initialized once at node startup and persists across mining restarts.
    // This allows template updates (when new blocks are found) without destroying the VM.
    // RandomX cleanup only happens at node shutdown via global cleanup handlers.
    //
    // Old code (BUG): randomx_cleanup() here caused "RandomX VM not initialized" errors
    // after finding blocks, because template update calls StopMining() then StartMining().
}

void CMiningController::UpdateTemplate(const CBlockTemplate& blockTemplate) {
    std::lock_guard<std::mutex> lock(m_templateMutex);
    m_pTemplate = std::make_unique<CBlockTemplate>(blockTemplate);
}

void CMiningController::SetBlockFoundCallback(std::function<void(const CBlock&)> callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_blockFoundCallback = std::move(callback);
}

bool CMiningController::CheckProofOfWork(const uint256& hash, const uint256& target) const {
    // Hash must be less than target (using big-endian comparison for PoW)
    // CRITICAL: Must use HashLessThan(), NOT operator<
    // operator< uses memcmp (little-endian byte order)
    // PoW requires big-endian comparison (MSB first)
    return HashLessThan(hash, target);
}

void CMiningController::MiningWorker(uint32_t threadId) {
    // MINE-011 FIX: Comprehensive exception handling to prevent silent thread termination
    try {
        // BUG #28 FIX: Create per-thread RandomX VM (eliminates global mutex bottleneck)
        // Each thread gets its own VM, enabling true parallel mining
        // The VM shares the read-only 2GB dataset but has its own ~200MB VM state
        // RAII pattern ensures automatic cleanup when thread exits
        RandomXVMGuard vm;

        // MINE-009 FIX: Extended nonce space to prevent collisions
        // Use 64-bit counter internally, wrap to 32-bit for header
        // Each thread gets its own range to avoid collisions between threads
        const uint32_t nonceStep = m_nThreads;
        uint64_t nonce64 = threadId;  // 64-bit counter
        uint64_t templateVersion = 0;  // BUG #109 FIX: Track template version for race detection

        // Hash buffer
        uint8_t hashBuffer[RANDOMX_HASH_SIZE];

        // BUG #24 FIX: Pre-allocated header buffer (reused across all hash attempts)
        // CRITICAL PERFORMANCE: Avoids vector allocations in hot loop
        // Header format: version(4) + prevBlock(32) + merkleRoot(32) + time(4) + bits(4) + nonce(4) = 80 bytes
        uint8_t header[80];
        uint256 lastHashTarget;
        CBlock cachedBlock;
        bool headerInitialized = false;

        // BUG #27 FIX: Cache block copy outside hot loop (only copy on template change)
        // CRITICAL: Copying CBlock on every iteration is the REAL bottleneck
        CBlock currentBlock;
        uint256 currentHashTarget;
        bool templateValid = false;

        // DEBUG: Counters to diagnose Bug #24 fix performance
        uint64_t debug_serializations = 0;
        uint64_t debug_hashes = 0;

        // BUG FIX: Track hashes for periodic LIGHT→FULL mode upgrade check
        uint64_t hashesForUpgradeCheck = 0;
        const uint64_t UPGRADE_CHECK_INTERVAL = 1000;  // Check every 1000 hashes

        while (m_mining) {
        // BUG FIX: Periodically check for LIGHT→FULL mode upgrade
        // Only thread 0 logs to avoid spam
        if (!vm.isFullMode() && ++hashesForUpgradeCheck >= UPGRADE_CHECK_INTERVAL) {
            hashesForUpgradeCheck = 0;
            if (vm.TryUpgrade()) {
                if (threadId == 0) {
                    std::cout << "[Mining] Upgraded to FULL mode (~1800 H/s)" << std::endl;
                }
            }
        }

        // MINE-009 FIX: Check for nonce space exhaustion
        // If we've wrapped around the 32-bit space, request new template
        if (nonce64 > UINT32_MAX && (nonce64 % UINT32_MAX) < nonceStep) {
            // Nonce space exhausted - brief pause to allow template update
            // In production, would trigger callback to request new template
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            nonce64 = threadId;  // Reset to start of this thread's range
        }

        // BUG #27 FIX: Only fetch template when changed (check pointer, not copy block)
        // BUG #109 FIX: Use template version counter for race detection
        // This eliminates millions of block copies per second and prevents race conditions
        bool needNewTemplate = false;
        {
            std::lock_guard<std::mutex> lock(m_templateMutex);
            if (!m_pTemplate) {
                templateValid = false;
                // CID 1675230 FIX: Release lock before sleeping to prevent blocking other threads
                // The lock is automatically released when the lock_guard goes out of scope
            } else {
                // BUG #109 FIX: Primary check - use template version for race detection
                // Version counter is atomically incremented when template is built, ensuring
                // all threads see the same version for the same template
                uint64_t newVersion = m_pTemplate->nVersion;
                
                // Check if template version changed (primary detection method)
                bool versionChanged = (newVersion != templateVersion);
                
                // Fallback: Also check header fields in case version wasn't set
                // This provides defense-in-depth against version counter bugs
                bool headerChanged = !templateValid ||
                    !(m_pTemplate->block.hashPrevBlock == currentBlock.hashPrevBlock) ||
                    !(m_pTemplate->block.hashMerkleRoot == currentBlock.hashMerkleRoot) ||
                    m_pTemplate->block.nTime != currentBlock.nTime ||
                    m_pTemplate->block.nBits != currentBlock.nBits;

                if (versionChanged || headerChanged) {
                    // Template changed - copy it once
                    currentBlock = m_pTemplate->block;
                    currentHashTarget = m_pTemplate->hashTarget;
                    templateVersion = newVersion;  // Update tracked version
                    templateValid = true;
                    needNewTemplate = true;
                }
            }
        }
        
        // CID 1675230 FIX: Sleep outside the lock to prevent blocking other threads
        // If template is not available, sleep briefly and retry
        if (!templateValid) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // BUG #24 + #26 + #27 FIX: Only re-serialize header when template changes
        // Template change already detected above, just use the flag
        if (needNewTemplate) {
            // Template changed - re-serialize the static parts of header
            // Format: version(4) + prevBlock(32) + merkleRoot(32) + time(4) + bits(4) + nonce(4)
            //
            // WF-1: assemble the 80-byte legacy PoW preimage through the single
            // canonical helper (WriteMiningHeaderLE), which routes the four 32-bit
            // scalars through WriteLE32 so the miner's PoW input is byte-identical
            // to the validator's CBlockHeader::SerializeHeader() on any host. The
            // nonce field (offset 76) is (re)written per iteration in the hot loop
            // below; the value passed here is a placeholder that gets overwritten.
            WriteMiningHeaderLE(header, currentBlock, currentBlock.nNonce);

            cachedBlock = currentBlock;
            lastHashTarget = currentHashTarget;
            headerInitialized = true;

            // DEBUG: Count header serializations
            debug_serializations++;
        }

        // BUG #24 FIX: Fast nonce update (only 4 bytes, no allocations)
        // Update nonce in place at offset 76 (last 4 bytes of 80-byte header)
        uint32_t nonce32 = static_cast<uint32_t>(nonce64 & 0xFFFFFFFF);
        // WF-1: explicit LE, byte-equal on LE hosts. The offset lives in
        // WriteMiningNonceLE (primitives/block.h) so this hot-loop write and
        // WriteMiningHeaderLE's template-change write cannot drift apart —
        // the bare `header + 76` literal that used to be here was untested and
        // a wrong offset silently invalidates every block this miner finds.
        WriteMiningNonceLE(header, nonce32);

        // Compute RandomX hash
        try {
            // BUG #28 FIX: Use thread-local VM (no mutex, fully parallel)
            // This eliminates the global mutex bottleneck that was serializing all threads
            BENCHMARK_START("mining_hash");
            randomx_hash_thread(vm.get(), header, 80, hashBuffer);
            (void)BENCHMARK_END("mining_hash");

            // Convert to uint256
            uint256 hash;
            std::memcpy(hash.begin(), hashBuffer, RANDOMX_HASH_SIZE);

            // Update hash counter (CRITICAL-1 FIX: Use atomic fetch_add for thread safety)
            // Multiple mining threads increment this counter; operator++ is NOT atomic for atomic types
            m_stats.nHashesComputed.fetch_add(1, std::memory_order_relaxed);

            // DEBUG: Count hashes and periodically report serialization ratio (DISABLED - too spammy)
            // debug_hashes++;
            // if (debug_hashes % 1000 == 0) {
            //     std::cout << "[DEBUG Thread " << threadId << "] Hashes: " << debug_hashes
            //               << ", Serializations: " << debug_serializations
            //               << " (Ratio: 1 serialization per " << (debug_hashes / std::max((uint64_t)1, debug_serializations)) << " hashes)"
            //               << std::endl;
            // }

            // Check if valid block
            if (CheckProofOfWork(hash, currentHashTarget)) {
                // BUG #109 FIX: Verify template version hasn't changed before submitting block
                // This prevents submitting a block built with a stale template
                // (e.g., if template was updated while we were mining)
                bool templateStillValid = false;
                {
                    std::lock_guard<std::mutex> lock(m_templateMutex);
                    if (m_pTemplate && m_pTemplate->nVersion == templateVersion) {
                        templateStillValid = true;
                    }
                }
                
                if (!templateStillValid) {
                    // Template changed while we were mining - discard this block
                    // The new template will be picked up on next iteration
                    continue;
                }
                
                // Double-check mining flag to prevent race during shutdown
                // If StopMining() was called between finding block and this check,
                // discard the block to prevent database corruption
                if (!m_mining) {
                    break;  // Shutdown in progress, exit immediately
                }

                // Found valid block!
                m_stats.nBlocksFound++;

                // BUG #24 FIX: Set the winning nonce in the block before callback
                currentBlock.nNonce = nonce32;

                // MINE-015 FIX: Safely call callback with null check and exception handling
                // MAINNET: See SetBlockFoundCallback() documentation for safety requirements
                {
                    std::lock_guard<std::mutex> lock(m_callbackMutex);
                    if (m_blockFoundCallback) {
                        try {
                            m_blockFoundCallback(currentBlock);
                        } catch (const std::exception& e) {
                            std::cerr << "[Miner] WARNING: Block callback threw exception: "
                                      << e.what() << std::endl;
                            // Continue mining - don't let callback failure stop the miner
                        }
                    }
                    // If no callback set, block is found but not reported (silent mining)
                }

                // Continue mining (in production, would update template)
            }
        } catch (const std::exception& e) {
            // CRITICAL-4 FIX: Log RandomX exceptions instead of silently continuing
            // This helps identify VM corruption or initialization failures
            ErrorMessage error = CErrorFormatter::ValidationError("RandomX hash computation", 
                "Thread " + std::to_string(threadId) + ": " + e.what());
            error.severity = ErrorSeverity::WARNING;
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            // Continue mining - may be transient error
        } catch (...) {
            // CRITICAL-4 FIX: Log unknown exceptions
            ErrorMessage error(ErrorSeverity::WARNING, "Mining Error", 
                "Thread " + std::to_string(threadId) + ": unknown RandomX error");
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            // Continue mining
        }

            // Increment nonce for this thread
            nonce64 += nonceStep;
        }

        // NOTE: For high hash rate scenarios, implement extra nonce in coinbase
        // This extends the search space beyond 2^32:
        // 1. Add 4-8 bytes to coinbase scriptSig as "extra nonce"
        // 2. When nonce exhausted, increment extra nonce and reset main nonce
        // 3. Recalculate merkle root with new coinbase
        // This gives 2^32 * 2^32 = 2^64 total search space

    } catch (const std::exception& e) {
        // MINE-011 FIX: Caught exception in mining worker thread
        // Log error and terminate gracefully
        ErrorMessage error = CErrorFormatter::ValidationError("Mining worker thread", 
            "Thread " + std::to_string(threadId) + ": " + e.what());
        error.severity = ErrorSeverity::ERR;
        error.recovery_steps.push_back("Check system resources (CPU, memory)");
        error.recovery_steps.push_back("Restart mining if problem persists");
        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
        return;
    } catch (...) {
        // MINE-011 FIX: Caught unknown exception in mining worker thread
        // Unknown exception type - terminate gracefully
        ErrorMessage error(ErrorSeverity::ERR, "Mining Worker Error", 
            "Thread " + std::to_string(threadId) + ": unknown exception");
        error.recovery_steps.push_back("Check system resources");
        error.recovery_steps.push_back("Restart mining");
        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
        return;
    }
}

void CMiningController::HashRateMonitor() {
    uint64_t lastHashes = 0;
    uint64_t lastTime = GetTimeMillis();

    while (m_monitoring) {
        // Sleep for 1 second
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Calculate hash rate
        uint64_t currentHashes = m_stats.nHashesComputed;
        uint64_t currentTime = GetTimeMillis();

        uint64_t hashDelta = currentHashes - lastHashes;
        uint64_t timeDelta = currentTime - lastTime;

        if (timeDelta > 0) {
            // Hashes per second
            uint64_t hashRate = (hashDelta * 1000) / timeDelta;
            m_stats.nLastHashRate = hashRate;
        }

        lastHashes = currentHashes;
        lastTime = currentTime;
    }
}

// ============================================================================
// Phase 5.4: Mining Integration - Transaction Selection and Block Assembly
// ============================================================================

uint64_t CMiningController::CalculateBlockSubsidy(uint32_t nHeight) const {
    // Use chain params for reward and halving interval (supports DIL and DilV)
    uint64_t nSubsidy = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->initialReward : 50 * COIN;

    uint64_t nHalvingInterval = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->halvingInterval : 210000;

    // Number of halvings that have occurred
    uint32_t nHalvings = static_cast<uint32_t>(nHeight / nHalvingInterval);

    // Subsidy goes to zero after 64 halvings (very far in future)
    if (nHalvings >= 64) {
        return 0;
    }

    // Apply halving: subsidy >> halvings
    nSubsidy >>= nHalvings;

    return nSubsidy;
}

CTransactionRef CMiningController::CreateCoinbaseTransaction(
    uint32_t nHeight,
    uint64_t totalFees,
    const std::vector<uint8_t>& minerAddress,
    const CMIKCoinbaseData& mikData
) {
    // Calculate block subsidy
    uint64_t nSubsidy = CalculateBlockSubsidy(nHeight);

    // Check if we're on testnet (no mining tax on testnet)
    bool isTestnet = Dilithion::g_chainParams && Dilithion::g_chainParams->IsTestnet();

    // =========================================================================
    // Mining Development Contribution (2% of subsidy, MAINNET ONLY)
    // - Dev Fund:   1% of subsidy (infrastructure, audits, community)
    // - Dev Reward: 1% of subsidy (core developer compensation)
    // - Miner:      98% of subsidy + 100% of fees (mainnet)
    //               100% of subsidy + 100% of fees (testnet)
    // =========================================================================
    uint64_t devFundAmount = 0;
    uint64_t devRewardAmount = 0;
    uint64_t minerSubsidy = nSubsidy;

    if (!isTestnet) {
        // MAINNET: Apply 2% mining tax
        uint64_t taxTotal = (nSubsidy * Consensus::MINING_TAX_PERCENT) / 100;
        devFundAmount = (taxTotal * Consensus::DEV_FUND_SHARE) / 100;
        devRewardAmount = taxTotal - devFundAmount;  // Remainder avoids rounding loss
        minerSubsidy = nSubsidy - taxTotal;
    }

    // MINE-001 FIX: Proper overflow handling
    // Check for overflow when adding fees to miner subsidy
    uint64_t minerAmount = minerSubsidy;
    if (totalFees > 0) {
        if (minerAmount > UINT64_MAX - totalFees) {
            throw std::runtime_error(
                "CreateCoinbaseTransaction: Integer overflow - totalFees too large " +
                std::to_string(totalFees) + " + minerSubsidy " + std::to_string(minerSubsidy)
            );
        }
        minerAmount += totalFees;
    }

    // Validate total coinbase value is within monetary policy limits
    uint64_t nCoinbaseValue = minerAmount + devFundAmount + devRewardAmount;
    if (nCoinbaseValue > static_cast<uint64_t>(MAX_MONEY)) {
        throw std::runtime_error(
            "CreateCoinbaseTransaction: Coinbase value exceeds MAX_MONEY: " +
            std::to_string(nCoinbaseValue) + " > " + std::to_string(MAX_MONEY)
        );
    }

    // Create coinbase transaction
    CTransaction coinbase;
    coinbase.nVersion = 1;
    coinbase.nLockTime = 0;

    // Coinbase input: null prevout with height in scriptSig
    CTxIn coinbaseIn;
    coinbaseIn.prevout.SetNull();

    // Encode height in scriptSig (BIP34-style)
    std::string coinbaseMsg = "Block " + std::to_string(nHeight) + " - Dilithion";
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>(nHeight & 0xFF));
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>((nHeight >> 8) & 0xFF));
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>((nHeight >> 16) & 0xFF));
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>((nHeight >> 24) & 0xFF));
    coinbaseIn.scriptSig.insert(coinbaseIn.scriptSig.end(),
                                 coinbaseMsg.begin(), coinbaseMsg.end());

    // DFMP v2.0/v3.0: Add MIK data to scriptSig if present
    if (mikData.hasMIK) {
        std::vector<uint8_t> mikScriptData;
        if (mikData.isRegistration) {
            // DFMP v3.0: Registration format with PoW nonce: [marker][type][pubkey][signature][nonce]
            if (!DFMP::BuildMIKScriptSigRegistration(mikData.pubkey, mikData.signature, mikData.registrationNonce, mikScriptData)) {
                throw std::runtime_error("Failed to build MIK registration scriptSig data");
            }
        } else {
            // Reference format: [marker][type][identity][signature]
            if (!DFMP::BuildMIKScriptSigReference(mikData.identity, mikData.signature, mikScriptData)) {
                throw std::runtime_error("Failed to build MIK reference scriptSig data");
            }
        }
        // Append MIK data to scriptSig
        coinbaseIn.scriptSig.insert(coinbaseIn.scriptSig.end(),
                                     mikScriptData.begin(), mikScriptData.end());
    }

    coinbaseIn.nSequence = CTxIn::SEQUENCE_FINAL;
    coinbase.vin.push_back(std::move(coinbaseIn));

    // Helper lambda to create P2PKH scriptPubKey from pubkey hash
    auto createP2PKHScript = [](const uint8_t* pubKeyHash) -> std::vector<uint8_t> {
        std::vector<uint8_t> script;
        script.push_back(0x76);  // OP_DUP
        script.push_back(0xa9);  // OP_HASH160
        script.push_back(0x14);  // Push 20 bytes
        script.insert(script.end(), pubKeyHash, pubKeyHash + 20);
        script.push_back(0x88);  // OP_EQUALVERIFY
        script.push_back(0xac);  // OP_CHECKSIG
        return script;
    };

    // OUTPUT 0: Miner reward
    // Mainnet: 98% of subsidy + all fees
    // Testnet: 100% of subsidy + all fees
    CTxOut minerOut;
    minerOut.nValue = minerAmount;
    std::vector<uint8_t> minerScript;
    minerScript.push_back(0x76);  // OP_DUP
    minerScript.push_back(0xa9);  // OP_HASH160
    minerScript.push_back(0x14);  // Push 20 bytes
    minerScript.insert(minerScript.end(), minerAddress.begin() + 1, minerAddress.begin() + 21);
    minerScript.push_back(0x88);  // OP_EQUALVERIFY
    minerScript.push_back(0xac);  // OP_CHECKSIG
    minerOut.scriptPubKey = std::move(minerScript);  // Move instead of copy (CWE-1098 perf fix)
    coinbase.vout.push_back(std::move(minerOut));

    // MAINNET ONLY: Add Dev Fund and Dev Reward outputs
    if (!isTestnet) {
        // OUTPUT 1: Dev Fund (1% of subsidy)
        CTxOut devFundOut;
        devFundOut.nValue = devFundAmount;
        devFundOut.scriptPubKey = createP2PKHScript(Consensus::DEV_FUND_PUBKEY_HASH);
        coinbase.vout.push_back(std::move(devFundOut));

        // OUTPUT 2: Developer Reward (1% of subsidy)
        CTxOut devRewardOut;
        devRewardOut.nValue = devRewardAmount;
        devRewardOut.scriptPubKey = createP2PKHScript(Consensus::DEV_REWARD_PUBKEY_HASH);
        coinbase.vout.push_back(std::move(devRewardOut));
    }

    return MakeTransactionRef(coinbase);
}

uint256 CMiningController::BuildMerkleRoot(const std::vector<CTransactionRef>& transactions) const {
    if (transactions.empty()) {
        return uint256();  // Null hash for empty block
    }

    // Build merkle tree from transaction hashes
    std::vector<uint256> merkleTree;
    merkleTree.reserve(transactions.size());

    // Level 0: transaction hashes
    for (const auto& tx : transactions) {
        merkleTree.push_back(tx->GetHash());
    }

    // Build tree levels until we reach root
    size_t levelOffset = 0;
    for (size_t levelSize = transactions.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
        for (size_t i = 0; i < levelSize; i += 2) {
            size_t i2 = std::min(i + 1, levelSize - 1);

            // Concatenate two hashes
            std::vector<uint8_t> combined;
            combined.reserve(64);
            combined.insert(combined.end(),
                          merkleTree[levelOffset + i].begin(),
                          merkleTree[levelOffset + i].end());
            combined.insert(combined.end(),
                          merkleTree[levelOffset + i2].begin(),
                          merkleTree[levelOffset + i2].end());

            // Hash the combination (SHA3-256)
            uint256 hash;
            SHA3_256(combined.data(), combined.size(), hash.data);
            merkleTree.push_back(hash);
        }
        levelOffset += levelSize;
    }

    // Return root (last element in tree)
    return merkleTree.empty() ? uint256() : merkleTree.back();
}

std::vector<CTransactionRef> CMiningController::SelectTransactionsForBlock(
    CTxMemPool& mempool,
    CUTXOSet& utxoSet,
    uint32_t nHeight,
    size_t maxBlockSize,
    size_t coinbaseReserve,
    uint64_t& totalFees
) {
    std::vector<CTransactionRef> selectedTxs;
    totalFees = 0;

    // BUG-003 Bug B: seed the size budget from the coinbase's REAL serialized
    // size (passed in by the caller), not a flat 200-byte estimate. The real
    // coinbase carries up to ~5.3 KB of MIK scriptSig + up to 3 outputs.
    // Add a generous varint allowance for the block tx-count prefix.
    static constexpr size_t TX_COUNT_VARINT_ALLOWANCE = 9;  // max varint width
    size_t currentBlockSize = coinbaseReserve + TX_COUNT_VARINT_ALLOWANCE;

    // Maximum block size — single source of truth Consensus::MAX_BLOCK_SIZE (4 MB).
    const size_t cap = maxBlockSize > 0 ? maxBlockSize : Consensus::MAX_BLOCK_SIZE;
    // BUG-003 F-05: budget against the cap minus a safety margin so size-estimate
    // jitter never produces a block the storage/consensus layer rejects.
    const size_t MAX_BLOCK_SIZE = cap > Consensus::BLOCK_SIZE_SAFETY_MARGIN
                                      ? cap - Consensus::BLOCK_SIZE_SAFETY_MARGIN
                                      : cap;

    // MINE-007 FIX: Resource limits to prevent DoS
    // Limit number of candidates to prevent unbounded iteration
    const size_t MAX_CANDIDATES = 50000;  // Maximum transactions to consider
    const uint64_t MAX_SELECTION_TIME_MS = 5000;  // 5 seconds maximum
    uint64_t startTime = GetTimeMillis();

    // Get transactions ordered by fee rate (highest first)
    std::vector<CTransactionRef> candidateTxs = mempool.GetOrderedTxs();

    // Limit number of candidates to prevent excessive iteration
    if (candidateTxs.size() > MAX_CANDIDATES) {
        candidateTxs.resize(MAX_CANDIDATES);
    }

    // Track which outpoints are spent in this block (to handle dependencies)
    std::set<COutPoint> spentInBlock;

    // Validator for checking transactions
    CTransactionValidator validator;

    // Select transactions greedily by fee rate
    size_t candidatesProcessed = 0;
    for (const auto& tx : candidateTxs) {
        // MINE-007 FIX: Check time limit to prevent CPU exhaustion
        if (GetTimeMillis() - startTime > MAX_SELECTION_TIME_MS) {
            // Time limit exceeded - return what we have so far
            break;
        }

        candidatesProcessed++;
        // Skip coinbase transactions (shouldn't be in mempool, but be safe)
        if (tx->IsCoinBase()) {
            continue;
        }

        // Calculate transaction size
        size_t txSize = tx->GetSerializedSize();

        // Check if transaction fits in block
        if (currentBlockSize + txSize > MAX_BLOCK_SIZE) {
            continue;  // Skip this transaction, try next
        }

        // Verify all inputs are available (either in UTXO set or created in this block)
        bool allInputsAvailable = true;
        bool hasConflict = false;

        for (const auto& txin : tx->vin) {
            // Check if input was spent in this block already (conflict)
            if (spentInBlock.count(txin.prevout) > 0) {
                hasConflict = true;
                break;
            }

            // Check if input exists in UTXO set
            CUTXOEntry utxoEntry;
            bool foundInUTXO = utxoSet.GetUTXO(txin.prevout, utxoEntry);

            // Check if input was created in this block
            bool foundInBlock = false;
            for (const auto& selectedTx : selectedTxs) {
                uint256 selectedTxHash = selectedTx->GetHash();
                if (selectedTxHash == txin.prevout.hash &&
                    txin.prevout.n < selectedTx->vout.size()) {
                    foundInBlock = true;
                    break;
                }
            }

            if (!foundInUTXO && !foundInBlock) {
                allInputsAvailable = false;
                break;
            }
        }

        // Skip transactions with conflicts or missing inputs
        if (hasConflict || !allInputsAvailable) {
            continue;
        }

        // MINE-003 FIX: Comprehensive transaction validation
        // MINE-010 FIX: Include coinbase maturity validation with correct height
        std::string validationError;
        CAmount txFee = 0;

        // Use CTransactionValidator to perform complete validation:
        // - Basic structural checks
        // - Input validation against UTXO set
        // - Coinbase maturity check (100 blocks)
        // - Dilithium signature verification
        // - Script execution
        // - Fee calculation
        if (!validator.CheckTransaction(*tx, utxoSet, nHeight, txFee, validationError)) {
            // Transaction is invalid - skip it
            // Reasons include: invalid signature, immature coinbase, double-spend, etc.
            continue;
        }

        // Sanity check: fee should be reasonable (not more than 10 DIL)
        const uint64_t MAX_REASONABLE_FEE = 10 * COIN;
        if (txFee > MAX_REASONABLE_FEE) {
            continue;  // Skip suspiciously high fee transactions
        }

        // Convert CAmount (int64_t) to uint64_t for accumulation
        uint64_t txFeeUint = static_cast<uint64_t>(txFee);

        // Add transaction to block
        selectedTxs.push_back(tx);
        currentBlockSize += txSize;

        // MINE-006 FIX (partial): Check for overflow when adding fees
        if (totalFees > UINT64_MAX - txFeeUint) {
            // Overflow would occur - stop adding transactions
            break;
        }
        totalFees += txFeeUint;

        // Mark inputs as spent in this block
        for (const auto& txin : tx->vin) {
            spentInBlock.insert(txin.prevout);
        }
    }

    // MAINNET FIX: Return without std::move to allow RVO (copy elision)
    return selectedTxs;
}

std::optional<CBlockTemplate> CMiningController::CreateBlockTemplate(
    CTxMemPool& mempool,
    CUTXOSet& utxoSet,
    const uint256& hashPrevBlock,
    uint32_t nHeight,
    uint32_t nBits,
    const std::vector<uint8_t>& minerAddress,
    const CMIKCoinbaseData& mikData,
    std::string& error
) {
    BENCHMARK_START("mining_create_template");
    
    // Validate inputs
    if (minerAddress.empty()) {
        error = "Invalid miner address (empty)";
        (void)BENCHMARK_END("mining_create_template");
        return std::nullopt;
    }

    if (hashPrevBlock.IsNull() && nHeight != 0) {
        error = "Invalid previous block hash for non-genesis block";
        (void)BENCHMARK_END("mining_create_template");
        return std::nullopt;
    }

    // BUG-003 Bug B: build the coinbase BEFORE transaction selection so the
    // selection loop can budget against the coinbase's real serialized size.
    // The coinbase serialized size is fee-independent — fees change only the
    // fixed-width 8-byte nValue; output count and script sizes do not depend on
    // fees (contract R2). We therefore build a probe coinbase with totalFees=0
    // here purely to measure its size, then rebuild with the real fees below.
    BENCHMARK_START("mining_create_coinbase");
    CTransactionRef coinbaseTx;
    try {
        coinbaseTx = CreateCoinbaseTransaction(nHeight, /*totalFees=*/0, minerAddress, mikData);
    } catch (const std::runtime_error& e) {
        error = std::string("Coinbase creation failed: ") + e.what();
        (void)BENCHMARK_END("mining_create_coinbase");
        (void)BENCHMARK_END("mining_create_template");
        return std::nullopt;
    }
    const size_t coinbaseReserve = coinbaseTx->GetSerializedSize();
    (void)BENCHMARK_END("mining_create_coinbase");

    // Step 1: Select transactions from mempool
    BENCHMARK_START("mining_select_txs");
    uint64_t totalFees = 0;
    std::vector<CTransactionRef> selectedTxs = SelectTransactionsForBlock(
        mempool,
        utxoSet,
        nHeight,  // Pass height for coinbase maturity validation
        Consensus::MAX_BLOCK_SIZE,  // BUG-003: single source of truth (4 MB)
        coinbaseReserve,            // BUG-003 Bug B: real coinbase size
        totalFees
    );
    (void)BENCHMARK_END("mining_select_txs");

    // Step 2: Rebuild the coinbase with the real total fees now that selection
    // is done. Size is unchanged vs. the probe coinbase above (fee-independent).
    BENCHMARK_START("mining_create_coinbase");
    try {
        coinbaseTx = CreateCoinbaseTransaction(nHeight, totalFees, minerAddress, mikData);
    } catch (const std::runtime_error& e) {
        error = std::string("Coinbase creation failed: ") + e.what();
        (void)BENCHMARK_END("mining_create_coinbase");
        (void)BENCHMARK_END("mining_create_template");
        return std::nullopt;
    }
    (void)BENCHMARK_END("mining_create_coinbase");

    // Step 3: Build complete transaction list (coinbase first)
    std::vector<CTransactionRef> allTxs;
    allTxs.reserve(1 + selectedTxs.size());
    allTxs.push_back(coinbaseTx);
    allTxs.insert(allTxs.end(), selectedTxs.begin(), selectedTxs.end());

    // MINE-013 FIX: Check for duplicate transactions (CVE-2012-2459 protection)
    // Duplicate transactions in a block can be used to create multiple merkle roots
    std::set<uint256> txHashes;
    for (const auto& tx : allTxs) {
        uint256 txHash = tx->GetHash();
        if (txHashes.count(txHash) > 0) {
            error = "Duplicate transaction detected in block: " + txHash.GetHex();
            return std::nullopt;
        }
        txHashes.insert(txHash);
    }

    // Step 4: Calculate merkle root
    BENCHMARK_START("mining_merkle_root");
    uint256 hashMerkleRoot = BuildMerkleRoot(allTxs);
    (void)BENCHMARK_END("mining_merkle_root");

    // BUG #71 DEBUG: Log miner's merkle root computation
    if (!allTxs.empty()) {
    }

    // Step 5: Serialize all transactions into block.vtx
    // For now, CBlock.vtx is std::vector<uint8_t> representing raw transaction data
    // We'll serialize all transactions concatenated
    std::vector<uint8_t> blockTxData;

    // BUG #11 DEBUG: Log transaction details

    // Serialize transaction count (compact size)
    uint64_t txCount = allTxs.size();
    if (txCount < 253) {
        blockTxData.push_back(static_cast<uint8_t>(txCount));
    } else if (txCount <= 0xFFFF) {
        blockTxData.push_back(253);
        blockTxData.push_back(static_cast<uint8_t>(txCount));
        blockTxData.push_back(static_cast<uint8_t>(txCount >> 8));
    } else {
        blockTxData.push_back(254);
        blockTxData.push_back(static_cast<uint8_t>(txCount));
        blockTxData.push_back(static_cast<uint8_t>(txCount >> 8));
        blockTxData.push_back(static_cast<uint8_t>(txCount >> 16));
        blockTxData.push_back(static_cast<uint8_t>(txCount >> 24));
    }

    // Serialize each transaction
    for (size_t i = 0; i < allTxs.size(); ++i) {
        const auto& tx = allTxs[i];
        std::vector<uint8_t> txData = tx->Serialize();
        // CID 1675171 FIX: Use move iterators to avoid unnecessary copy
        // txData is a local variable that's no longer used after insert
        blockTxData.insert(blockTxData.end(), std::make_move_iterator(txData.begin()), std::make_move_iterator(txData.end()));
    }


    // Step 6: Build block header
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = hashPrevBlock;
    block.hashMerkleRoot = hashMerkleRoot;

    // MINE-004 FIX: Proper timestamp handling with validation
    int64_t currentTime = GetTime();

    // Validate current time is reasonable (basic sanity check)
    // Ensure we're not in some absurd future (system clock error)
    const int64_t MIN_VALID_TIMESTAMP = 1420070400;  // Jan 1, 2015 00:00:00 UTC (before Bitcoin genesis)
    const int64_t MAX_VALID_TIMESTAMP = 4102444800;  // Jan 1, 2100 00:00:00 UTC (far future)

    if (currentTime < MIN_VALID_TIMESTAMP || currentTime > MAX_VALID_TIMESTAMP) {
        error = "System clock error: timestamp out of valid range";
        return std::nullopt;
    }

    // NOTE: MTP validation is performed at the call site (BuildMiningTemplate)
    // where CBlockIndex* is available. If the current time is behind the
    // Median-Time-Past, the timestamp is bumped to MTP + 1 before this
    // function is called. Consensus also enforces MTP in CheckBlockHeader().

    block.nTime = static_cast<uint32_t>(currentTime);

    // MINE-008 FIX: Validate nBits before using it
    if (nBits == 0) {
        error = "Invalid nBits: zero difficulty";
        return std::nullopt;
    }

    // Validate nBits is in valid compact format
    // Compact format: 0xNNSSAAAA where NN = exponent, SSAAAA = significand
    uint32_t exponent = nBits >> 24;
    uint32_t significand = nBits & 0x00FFFFFF;

    // Exponent must be in range [0x03, 0x20] (3 to 32 bytes)
    if (exponent < 0x03 || exponent > 0x20) {
        error = "Invalid nBits: exponent out of range";
        return std::nullopt;
    }

    // Significand must have high bit clear (positive number)
    if (significand > 0x007FFFFF) {
        error = "Invalid nBits: negative target not allowed";
        return std::nullopt;
    }

    block.nBits = nBits;
    block.nNonce = 0;  // Miner will increment this
    // CID 1675171 FIX: Use std::move to avoid unnecessary copy
    // blockTxData is no longer used after this assignment, so we can move it
    block.vtx = std::move(blockTxData);

    // Step 7: Calculate target from nBits
    uint256 hashTarget = CompactToBig(nBits);

    // Validate the expanded target is not all zeros
    if (hashTarget.IsNull()) {
        error = "Invalid nBits: expands to zero target";
        return std::nullopt;
    }

    // Step 7b: Apply DFMP difficulty adjustment
    // DFMP adjusts the target based on miner's identity (pending penalty + heat)
    if (Dilithion::g_chainParams && nHeight >= static_cast<uint32_t>(Dilithion::g_chainParams->dfmpActivationHeight)) {
        // Derive miner identity from coinbase scriptPubKey (same as will be in block)
        // The coinbase output[0].scriptPubKey is the P2PKH script we just created
        std::vector<uint8_t> coinbaseScript = coinbaseTx->vout[0].scriptPubKey;
        DFMP::Identity minerIdentity = DFMP::DeriveIdentityFromScript(coinbaseScript);

        if (!minerIdentity.IsNull()) {
            // Get first-seen height (-1 for new identity)
            int firstSeen = -1;
            if (DFMP::g_identityDb != nullptr) {
                firstSeen = DFMP::g_identityDb->GetFirstSeen(minerIdentity);
            }

            // Get current heat from tracker
            int heat = 0;
            if (DFMP::g_heatTracker != nullptr) {
                heat = DFMP::g_heatTracker->GetHeat(minerIdentity);
            }

            // Calculate total DFMP multiplier (pending × heat)
            // Use version-appropriate parameters
            int dfmpV31Height = Dilithion::g_chainParams ?
                Dilithion::g_chainParams->dfmpV31ActivationHeight : 999999999;
            int dfmpV32Height = Dilithion::g_chainParams ?
                Dilithion::g_chainParams->dfmpV32ActivationHeight : 999999999;
            int dfmpV33Height = Dilithion::g_chainParams ?
                Dilithion::g_chainParams->dfmpV33ActivationHeight : 999999999;
            // C-3: saturating heat math gate — single-sourced with the validator.
            bool dfmpSat = DFMP::DfmpSaturatingMathActive(static_cast<int>(nHeight));
            int64_t multiplierFP;
            if (static_cast<int>(nHeight) >= dfmpV33Height) {
                multiplierFP = DFMP::CalculateTotalMultiplierFP_V33(nHeight, firstSeen, heat, dfmpSat);
            } else if (static_cast<int>(nHeight) >= dfmpV32Height) {
                multiplierFP = DFMP::CalculateTotalMultiplierFP_V32(nHeight, firstSeen, heat, 0, dfmpSat);
            } else if (static_cast<int>(nHeight) >= dfmpV31Height) {
                multiplierFP = DFMP::CalculateTotalMultiplierFP_V31(nHeight, firstSeen, heat, 0, dfmpSat);
            } else {
                multiplierFP = DFMP::CalculateTotalMultiplierFP(nHeight, firstSeen, heat, 0, dfmpSat);
            }

            // Apply multiplier to get effective target
            hashTarget = DFMP::CalculateEffectiveTarget(hashTarget, multiplierFP);

            // Log DFMP info for miner awareness (only if multiplier > 1.0)
            double multiplier = static_cast<double>(multiplierFP) / DFMP::FP_SCALE;
            if (multiplier > 1.01) {
                double pendingMult, heatMult;
                const char* vTag;
                if (static_cast<int>(nHeight) >= dfmpV33Height) {
                    pendingMult = static_cast<double>(DFMP::CalculatePendingPenaltyFP_V33(nHeight, firstSeen)) / DFMP::FP_SCALE;
                    heatMult = static_cast<double>(DFMP::CalculateHeatMultiplierFP_V33(heat)) / DFMP::FP_SCALE;
                    vTag = "v3.3";
                } else if (static_cast<int>(nHeight) >= dfmpV32Height) {
                    pendingMult = static_cast<double>(DFMP::CalculatePendingPenaltyFP_V32(nHeight, firstSeen)) / DFMP::FP_SCALE;
                    heatMult = static_cast<double>(DFMP::CalculateHeatMultiplierFP_V32(heat)) / DFMP::FP_SCALE;
                    vTag = "v3.2";
                } else if (static_cast<int>(nHeight) >= dfmpV31Height) {
                    pendingMult = static_cast<double>(DFMP::CalculatePendingPenaltyFP_V31(nHeight, firstSeen)) / DFMP::FP_SCALE;
                    heatMult = static_cast<double>(DFMP::CalculateHeatMultiplierFP_V31(heat)) / DFMP::FP_SCALE;
                    vTag = "v3.1";
                } else {
                    pendingMult = static_cast<double>(DFMP::CalculatePendingPenaltyFP(nHeight, firstSeen)) / DFMP::FP_SCALE;
                    heatMult = static_cast<double>(DFMP::CalculateHeatMultiplierFP(heat)) / DFMP::FP_SCALE;
                    vTag = "v3.0";
                }

                std::cout << "[DFMP " << vTag << "] Mining at height " << nHeight
                          << " identity " << minerIdentity.GetHex().substr(0, 8) << "..."
                          << " firstSeen=" << firstSeen
                          << " heat=" << heat
                          << " pending=" << std::fixed << std::setprecision(2) << pendingMult << "x"
                          << " heatMult=" << heatMult << "x"
                          << " total=" << multiplier << "x" << std::endl;
            }
        }
    }

    // MINE-012 FIX: Validate final block size
    // Calculate total block size: header (80 bytes) + vtx data
    const size_t BLOCK_HEADER_SIZE = 80;
    size_t totalBlockSize = BLOCK_HEADER_SIZE + block.vtx.size();

    // Enforce consensus maximum block size (Consensus::MAX_BLOCK_SIZE, 4 MB).
    // Conservative: counts the 80-byte header on top of the vtx blob, whereas
    // the storage layer caps the vtx blob alone — so this never lets through a
    // block the storage layer would reject.
    if (totalBlockSize > Consensus::MAX_BLOCK_SIZE) {
        error = "Block size exceeds consensus maximum: " +
                std::to_string(totalBlockSize) + " > " +
                std::to_string(Consensus::MAX_BLOCK_SIZE);
        return std::nullopt;
    }

    // Step 8: Create and return block template
    CBlockTemplate blockTemplate(block, hashTarget, nHeight);

    (void)BENCHMARK_END("mining_create_template");
    // MAINNET FIX: Return without std::move to allow RVO (copy elision)
    return blockTemplate;
}
