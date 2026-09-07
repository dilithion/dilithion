// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// P2P-14/15 second edge — cs_headers -> g_validation_mutex, CONSTRUCTED as a
// STALL, not as a deadlock.
//
// WHAT THIS IS AND IS NOT. There is no cycle here and this harness does not
// pretend to find one. `crypto/randomx_hash.cpp` contains no net symbol and no
// callback registry, so `g_validation_mutex -> cs_headers` cannot exist; the
// edge is one-way. TSan's lock-order-inversion detector only reports CYCLES, so
// it is the wrong instrument, and `g_validation_mutex` is file-scope in
// randomx_hash.cpp and cannot be taken from a test to fabricate one. The
// fabrication would be dishonest anyway.
//
// The load-bearing claim is therefore about LATENCY, and that is what is
// measured: a RandomX hash is computed WHILE cs_headers is held, stalling every
// other thread that needs the headers lock.
//
// THE EDGE (cites against origin/main f47b9b24):
//   headers_manager.cpp:222   ProcessHeaders takes cs_headers
//   headers_manager.cpp:331   `uint256 storageHash = header.GetHash();`  <- under the lock
//   primitives/block.cpp:77   CBlockHeader::GetHash, cache MISS on a fresh wire header
//                             (`fHashCached{false}`, block.h:136) and a LEGACY
//                             (non-VDF) header takes the RandomX branch
//   crypto/randomx_hash.cpp:554 randomx_hash_fast
//   crypto/randomx_hash.cpp:565 lock_guard(g_validation_mutex)
//
// WHY IT MATTERS: the mitigation exists on ONE path only.
//   QueueHeadersForValidation:2789  parallel pre-warm OUTSIDE the lock -> cache HIT
//   ProcessHeaders:331              no pre-warm                        -> cache MISS
//   ProcessHeadersWithDoSProtection:649  no pre-warm                   -> cache MISS
// and QueueHeadersForValidation:2536 falls back to ProcessHeaders when the
// validation thread is not running, i.e. onto the unwarmed path.
//
// BOTH ARMS, one binary, differing ONLY in whether the hash is pre-warmed
// outside the lock — which is exactly the difference between the two production
// paths above:
//
//   ./p2p14_headers_randomx_stall_tsan_tests unwarmed    EXPECT a long stall
//   ./p2p14_headers_randomx_stall_tsan_tests prewarmed   EXPECT no long stall
//
// The prewarmed arm is the RED control: without it, "the headers lock was held
// for N ms" could just as easily be this machine being slow.
//
// REACHABILITY GUARD: `fHashCached` is public and mutable (block.h:136), so the
// harness asserts the cache actually flipped false->true INSIDE ProcessHeaders
// in the unwarmed arm. If it did not, GetHash never ran under the lock and any
// timing printed here would be meaningless — the harness exits 3 rather than
// report a number it has not earned.

#include <consensus/chain.h>
#include <consensus/chain_work.h>
#include <core/chainparams.h>
#include <core/node_context.h>
#include <crypto/randomx_hash.h>
#include <net/headers_manager.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

// Batch size is argv[2] so the stall can be MEASURED at realistic batch sizes
// rather than extrapolated from a small one. Production batches run up to
// MAX_HEADERS_RESULTS = 2000.
int kHeaders = 12;

// LEGACY header (nVersion < VDF_VERSION) so IsVDFBlock() is false and GetHash()
// takes the RandomX branch rather than SHA3. That choice is the whole point of
// this harness: a VDF header would never reach g_validation_mutex.
CBlockHeader MakeLegacyHeader(const uint256& parent_hash, uint32_t nTime)
{
    CBlockHeader h;
    h.nVersion = 1;
    h.hashPrevBlock = parent_hash;
    std::memset(h.hashMerkleRoot.data, 0, 32);
    h.nTime = nTime;
    h.nBits = 0x1d00ffff;
    h.nNonce = 0;
    return h;
}

std::atomic<bool> g_stop{false};
std::atomic<long long> g_max_stall_us{0};

}  // namespace

int main(int argc, char* argv[])
{
    const std::string arm = (argc > 1) ? argv[1] : "unwarmed";
    if (arm != "unwarmed" && arm != "prewarmed") {
        std::cerr << "usage: " << argv[0] << " unwarmed|prewarmed\n";
        return 2;
    }
    const bool prewarm = (arm == "prewarmed");
    if (argc > 2) kHeaders = std::max(1, atoi(argv[2]));
    std::cout << "[p2p14-stall] arm=" << arm << std::endl;

    // Light mode: the tests' pattern (bug_003_block_size_tests.cpp:636).
    const char* rxKey = "dilithion-p2p14-stall-harness";
    randomx_init_for_hashing(rxKey, std::strlen(rxKey), 1);

    if (Dilithion::g_chainParams == nullptr) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
        // Regtest ships no checkpoints, so FAST PATH 1 (headers_manager.cpp:317)
        // is never taken and headers are silently dropped while ProcessHeaders
        // still returns true. One checkpoint far above the heights used here
        // puts them on the real fast path — which is the path that calls
        // GetHash() under the lock at :331.
        uint256 cp;
        std::memset(cp.data, 0xab, 32);
        Dilithion::g_chainParams->checkpoints.push_back(Dilithion::CCheckpoint(1000, cp));
    }

    g_node_context.headers_manager = std::make_unique<CHeadersManager>();

    // Seed a legacy genesis so the children are not orphans.
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    CBlockHeader genesis = MakeLegacyHeader(null_hash, 1700000000);
    const uint256 genesis_hash = genesis.GetHash();
    {
        std::vector<CBlockHeader> seed{genesis};
        g_node_context.headers_manager->ProcessHeaders(/*peer=*/1, seed);
    }

    std::vector<CBlockHeader> batch;
    batch.reserve(kHeaders);
    for (int i = 0; i < kHeaders; ++i) {
        batch.push_back(MakeLegacyHeader(genesis_hash, 1700100000u + i));
    }

    // THE ONLY DIFFERENCE BETWEEN THE ARMS.
    // prewarmed mirrors QueueHeadersForValidation:2789 (hash computed OUTSIDE
    // the lock); unwarmed mirrors ProcessHeaders:331 (computed under it).
    for (auto& h : batch) h.InvalidateCache();
    if (prewarm) {
        for (auto& h : batch) (void)h.GetHash();
    }

    int cached_before = 0;
    for (const auto& h : batch) cached_before += h.fHashCached ? 1 : 0;

    // Probe thread: does nothing but take cs_headers and time how long it waits.
    // GetHeaderCount (headers_manager.cpp:1496) locks cs_headers and returns a
    // map size — it contributes no work of its own to the measurement.
    std::thread probe([&]() {
        while (!g_stop.load()) {
            const auto t0 = std::chrono::steady_clock::now();
            (void)g_node_context.headers_manager->GetHeaderCount();
            const auto t1 = std::chrono::steady_clock::now();
            const long long us =
                std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            long long prev = g_max_stall_us.load();
            while (us > prev && !g_max_stall_us.compare_exchange_weak(prev, us)) {}
            std::this_thread::yield();
        }
    });

    const auto b0 = std::chrono::steady_clock::now();
    g_node_context.headers_manager->ProcessHeaders(/*peer=*/1, batch);
    const auto b1 = std::chrono::steady_clock::now();

    g_stop.store(true);
    probe.join();

    int cached_after = 0;
    for (const auto& h : batch) cached_after += h.fHashCached ? 1 : 0;

    const long long batch_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(b1 - b0).count();
    const long long stall_us = g_max_stall_us.load();

    std::cout << "[p2p14-stall] headers=" << kHeaders
              << "  cached_before=" << cached_before
              << "  cached_after=" << cached_after << std::endl;
    std::cout << "[p2p14-stall] ProcessHeaders wall=" << batch_ms << "ms"
              << "  MAX_PROBE_STALL=" << stall_us << "us" << std::endl;

    // REACHABILITY. In the unwarmed arm the cache MUST flip inside
    // ProcessHeaders; if it did not, GetHash never ran under cs_headers and the
    // timing above measured nothing of interest.
    if (!prewarm && !(cached_before == 0 && cached_after == kHeaders)) {
        std::cerr << "[p2p14-stall] HARNESS DEFECT: cache did not flip inside "
                     "ProcessHeaders (before=" << cached_before
                  << " after=" << cached_after << "); the stall number is meaningless\n";
        return 3;
    }
    if (prewarm && cached_before != kHeaders) {
        std::cerr << "[p2p14-stall] HARNESS DEFECT: prewarm arm did not warm the cache\n";
        return 3;
    }
    return 0;
}
