// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// graveyard_occupancy_bench — REPLACES ARITHMETIC WITH OBSERVATIONS.
//
// The quiescence proof carried "~3.3 MB / ~33 MB of graveyard at the ingress
// ceiling" for one commit. Those were CALCULATIONS — evictions/s x sizeof x a
// grace window I picked — and they were marked as not-to-be-quoted for exactly
// that reason. This measures the thing instead.
//
// WHAT SETS OCCUPANCY. An entry sits in the graveyard from its unlink until every
// registered thread has published an epoch at or beyond it. So peak occupancy is
// governed by TWO intervals, and by the larger of them:
//
//     peak ~= eviction_rate x max(drain_interval, slowest_checkpoint_interval)
//
// which is why this bench sweeps both, rather than assuming one and multiplying.
// The slowest participant is the one that matters — a single thread checkpointing
// every 10 s pins ten seconds of evictions no matter how often the drain runs.
//
// USAGE
//   graveyard_occupancy_bench [entries] [pinned_pct] [drain_ms] [checkpoint_ms]
//                             [run_ms] [target_rate] [parked_mode]
//
// Defaults reproduce the wired production shape: a 1 Hz drain from the node main
// loop and a 1 Hz slowest checkpoint.

#include <consensus/chain.h>
#include <core/chainparams.h>
#include <node/block_index.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace {

long CurrentRssKb()
{
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return static_cast<long>(pmc.WorkingSetSize / 1024);
    }
    return -1;
#else
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) { sscanf(line + 6, "%ld", &kb); break; }
    }
    fclose(f);
    return kb;
#endif
}

uint256 HashFromCounter(uint64_t i)
{
    uint256 h;
    std::memset(h.data, 0, 32);
    std::memcpy(h.data, &i, sizeof(i));
    // Spread the counter so map ordering is not simply sequential — the same
    // helper evict_cost_bench uses, so the two benches share a key distribution.
    h.data[31] = static_cast<uint8_t>((i * 2654435761u) & 0xff);
    h.data[30] = static_cast<uint8_t>(((i * 2654435761u) >> 8) & 0xff);
    return h;
}

double MsSince(std::chrono::steady_clock::time_point t)
{
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t).count();
}

}  // namespace

int main(int argc, char** argv)
{
    const size_t entries       = (argc > 1) ? std::stoul(argv[1]) : 500000;
    const int    pinned_pct    = (argc > 2) ? std::stoi(argv[2])  : 50;
    const int    drain_ms      = (argc > 3) ? std::stoi(argv[3])  : 1000;
    const int    checkpoint_ms = (argc > 4) ? std::stoi(argv[4])  : 1000;
    const int    run_ms        = (argc > 5) ? std::stoi(argv[5])  : 10000;
    // Evictions per second to sustain. 0 = unthrottled, which measures the
    // evictor's own ceiling rather than the node's: in production the eviction
    // rate is set by HEADER INGRESS, not by how fast the evictor could run, so an
    // unthrottled run consumes the whole evictable set in milliseconds and its
    // "peak" is just the size of that set. The throttled run is the one that
    // answers the occupancy question.
    const double target_rate   = (argc > 6) ? std::stod(argv[6])  : 10400.0;
    // PARKED-PARTICIPANT ARM (external panel round 1, finding 3). 0 = none;
    // 1 = a participant parks for the whole run WITHOUT going offline, which is
    // what "checkpoint before the wait" produced and what the design note wrongly
    // called "pins nothing"; 2 = the same thread parks inside an EpochOfflineScope,
    // which is the fix. Run 1 and 2 and compare the peaks — that difference is the
    // measurement, and it is also the pinned-regime drain-cost measurement, since
    // arm 1 IS the pinned regime.
    const int    parked_mode   = (argc > 7) ? std::stoi(argv[7])  : 0;

    std::cout << "\n=== graveyard occupancy: " << entries << " entries, "
              << pinned_pct << "% pinned, drain every " << drain_ms
              << " ms, slowest checkpoint every " << checkpoint_ms << " ms, "
              << run_ms << " ms run ===\n\n";
    std::cout << "  sizeof(CBlockIndex)   : " << sizeof(CBlockIndex) << " bytes\n";

    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::ChainParams params = Dilithion::ChainParams::Regtest();
    params.nMapBlockIndexCap = static_cast<int>(entries);
    Dilithion::g_chainParams = &params;

    CChainState cs;

    // A linear chain: the worst case for the pinned walk and the realistic shape
    // for a synced node. Eviction peels unpinned leaves off the far end.
    const size_t pinned_target = entries * static_cast<size_t>(pinned_pct) / 100;
    std::cout << "  building..." << std::flush;
    const auto build_start = std::chrono::steady_clock::now();
    CBlockIndex* prev = nullptr;
    uint256 pinned_tip_hash;
    for (size_t i = 0; i < entries; ++i) {
        auto up = std::make_unique<CBlockIndex>();
        up->pprev = prev;
        up->nHeight = static_cast<int>(i);
        up->nStatus = CBlockIndex::BLOCK_VALID_HEADER;
        up->nSequenceId = static_cast<int32_t>(i + 1);
        const uint256 h = HashFromCounter(i);
        up->phashBlock = h;
        CBlockIndex* raw = up.get();
        if (!cs.AddBlockIndex(h, std::move(up))) {
            std::cerr << "\n  FATAL: AddBlockIndex failed at " << i << "\n";
            Dilithion::g_chainParams = saved;
            return 2;
        }
        prev = raw;
        if (i + 1 == pinned_target) pinned_tip_hash = h;
    }
    std::cout << " " << MsSince(build_start) << " ms\n";

    if (pinned_target > 0) {
        CBlockIndex* tip = cs.GetBlockIndex(pinned_tip_hash);
        if (!tip) { std::cerr << "  FATAL: pinned tip missing\n"; return 2; }
        cs.SetTip(tip);
    }
    std::cout << "  index size            : " << cs.GetBlockIndexSize() << "\n";
    std::cout << "  pinned (active chain) : " << pinned_target << "\n";
    std::cout << "  evictable             : " << (entries - pinned_target) << "\n\n";

    // ⚠️ THIS THREAD IS A PARTICIPANT AND MUST SAY SO BEFORE THE RUN. It resolved
    // the pinned tip above, and since the round-1 fold a thread that resolves
    // without ever checkpointing gets a slot at 0 that PINS THE WHOLE GRAVEYARD --
    // which is the intended safe direction, and which silently made this bench
    // report "freed 0" for every configuration until the checkpoint below was
    // added. The bench was measuring its own missing promise.
    cs.EpochCheckpoint("bench-main");

    const long rss_before = CurrentRssKb();

    // ── the participants. `checkpoint_ms` is the SLOWEST one, which is the one
    // that sets the floor; a second thread checkpoints ten times faster so the
    // measurement shows the max rather than the mean.
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> checkpoints{0};
    std::thread slow([&] {
        while (!stop.load()) {
            cs.EpochCheckpoint("bench-slow");
            checkpoints.fetch_add(1);
            // EPOCH-WAIT-EXEMPT: THE INSTRUMENT'S PURPOSE: this bench exists to MEASURE what a parked participant costs, so its threads park online deliberately
            std::this_thread::sleep_for(std::chrono::milliseconds(checkpoint_ms));
        }
    });
    std::thread fast([&] {
        while (!stop.load()) {
            cs.EpochCheckpoint("bench-fast");
            checkpoints.fetch_add(1);
            // EPOCH-WAIT-EXEMPT: THE INSTRUMENT'S PURPOSE: deliberate park, see the file header
            std::this_thread::sleep_for(
                std::chrono::milliseconds(std::max(1, checkpoint_ms / 10)));
        }
    });

    // ── the parked participant, if this arm asked for one.
    std::mutex park_m;
    std::condition_variable park_cv;
    bool park_ready = false, park_release = false;
    std::thread parked;
    if (parked_mode != 0) {
        parked = std::thread([&] {
            cs.EpochCheckpoint("bench-parked");   // a registered participant
            std::unique_lock<std::mutex> lk(park_m);
            if (parked_mode == 2) {
                // THE FIX: leave the quiescent-state calculation while blocked.
                EpochOfflineScope offline(&cs);
                park_ready = true;
                park_cv.notify_all();
                park_cv.wait(lk, [&] { return park_release; });
            } else {
                // THE DEFECT: an epoch published and then frozen for the whole park.
                park_ready = true;
                park_cv.notify_all();
                // EPOCH-WAIT-EXEMPT: THE INSTRUMENT'S PURPOSE: deliberate park, see the file header
                park_cv.wait(lk, [&] { return park_release; });
            }
        });
        std::unique_lock<std::mutex> lk(park_m);
        // EPOCH-WAIT-EXEMPT: THE INSTRUMENT'S PURPOSE: deliberate park, see the file header
        park_cv.wait(lk, [&] { return park_ready; });
        std::cout << "  parked participant    : mode " << parked_mode
                  << (parked_mode == 2 ? " (OFFLINE — the fix)"
                                       : " (checkpointed then parked — the defect)")
                  << "\n";
    }

    // ── the drain, on its own thread at the wired cadence, timed per call.
    std::atomic<uint64_t> freed_total{0};
    std::atomic<uint64_t> drain_calls{0};
    std::atomic<double> drain_ms_max{0.0};
    std::atomic<double> drain_ms_total{0.0};
    std::thread drainer([&] {
        while (!stop.load()) {
            // ⚠️ THE CHECKPOINT GOES INSIDE THE LOOP, BEFORE EACH DRAIN, exactly as
            // the node main loop does it. The first version of this bench
            // checkpointed ONCE before the loop, so the drainer's own slot froze at
            // the starting epoch and it became the minimum — pinning everything it
            // was trying to free. It freed 11 entries in a 15-second run and the
            // graveyard grew monotonically to 47 MB. A bench defect, not a product
            // one, and an instructive one: ANY participant that stops checkpointing
            // pins the graveyard, including the thread doing the draining.
            cs.EpochCheckpoint("bench-drainer");
            const auto t = std::chrono::steady_clock::now();
            const size_t n = cs.DrainGraveyard();
            const double ms = MsSince(t);
            freed_total.fetch_add(n);
            drain_calls.fetch_add(1);
            drain_ms_total.store(drain_ms_total.load() + ms);
            if (ms > drain_ms_max.load()) drain_ms_max.store(ms);
            // EPOCH-WAIT-EXEMPT: THE INSTRUMENT'S PURPOSE: deliberate park, see the file header
            std::this_thread::sleep_for(std::chrono::milliseconds(drain_ms));
        }
    });

    // ── the evictor: as fast as it will go, which measures the ingress ceiling
    // on this machine rather than assuming the 10,400/s figure.
    size_t peak_entries = 0;
    uint64_t evictions = 0;
    const auto t_start = std::chrono::steady_clock::now();
    size_t target = cs.GetBlockIndexSize();
    while (MsSince(t_start) < run_ms) {
        if (target == 0) break;
        // Throttle to the requested ingress rate: sleep until this eviction is due.
        if (target_rate > 0) {
            const double due_ms = evictions * 1000.0 / target_rate;
            const double now_ms = MsSince(t_start);
            if (now_ms < due_ms) {
                const int nap = static_cast<int>(due_ms - now_ms);
                // EPOCH-WAIT-EXEMPT: THE INSTRUMENT'S PURPOSE: deliberate park, see the file header
                if (nap >= 1) std::this_thread::sleep_for(std::chrono::milliseconds(nap));
            }
        }
        --target;
        if (!cs.EvictLowestWorkLeafNotPinned(target)) break;  // nothing evictable
        ++evictions;
        // The evicting thread holds nothing between calls; without this its slot
        // would sit at the pre-run epoch and pin every entry it just unlinked.
        cs.EpochCheckpoint("bench-main");
        const size_t g = cs.GraveyardSize();
        if (g > peak_entries) peak_entries = g;
    }
    const double elapsed_ms = MsSince(t_start);

    stop.store(true);
    if (parked.joinable()) {
        { std::lock_guard<std::mutex> lk(park_m); park_release = true; }
        park_cv.notify_all();
        // EPOCH-WAIT-EXEMPT: BENCH DRIVER THREAD, teardown. This is the instrument joining the parked participant it deliberately created to MEASURE what a park costs
        parked.join();
    }
    // EPOCH-WAIT-EXEMPT: BENCH DRIVER THREAD, teardown -- joining a deliberately-parked worker
    slow.join();
    // EPOCH-WAIT-EXEMPT: BENCH DRIVER THREAD, teardown -- joining a deliberately-parked worker
    fast.join();
    // EPOCH-WAIT-EXEMPT: BENCH DRIVER THREAD, teardown -- joining a deliberately-parked worker
    drainer.join();

    const long rss_after = CurrentRssKb();

    // One last drain with everyone quiescent, to show the graveyard does empty.
    cs.EpochCheckpoint("bench-main");
    const size_t final_freed = cs.DrainGraveyard();

    const double rate = (elapsed_ms > 0) ? (evictions * 1000.0 / elapsed_ms) : 0.0;
    const double peak_mb = peak_entries * static_cast<double>(sizeof(CBlockIndex))
                           / (1024.0 * 1024.0);

    std::cout << std::fixed << std::setprecision(1);
    std::cout << "  --- MEASURED ---\n";
    std::cout << "  evictions             : " << evictions << " in " << elapsed_ms
              << " ms\n";
    std::cout << "  eviction rate         : " << rate << " /s\n";
    std::cout << "  PEAK graveyard        : " << peak_entries << " entries = "
              << std::setprecision(2) << peak_mb << " MB\n";
    std::cout << std::setprecision(1);
    std::cout << "  freed during the run  : " << freed_total.load() << " over "
              << drain_calls.load() << " drain calls\n";
    std::cout << "  drain cost            : max " << drain_ms_max.load()
              << " ms, mean "
              << (drain_calls.load() ? drain_ms_total.load() / drain_calls.load() : 0.0)
              << " ms  ⚠️ HELD UNDER cs_main\n";
    std::cout << "  freed after the run   : " << final_freed << "\n";
    std::cout << "  graveyard at exit     : " << cs.GraveyardSize() << "\n";
    std::cout << "  checkpoints           : " << checkpoints.load() << "\n";
    std::cout << "  resolves while OFFLINE: " << CChainState::OfflineResolveCount()
              << "  (non-zero = a mispaired quiesce/checkpoint somewhere)\n";
    std::cout << "  RSS                   : " << rss_before << " -> " << rss_after
              << " KB (delta " << (rss_after - rss_before) << " KB)\n\n";

    // The arithmetic this bench exists to replace, printed beside the measurement
    // so a divergence is visible rather than quietly forgotten.
    const double predicted_mb = rate * (std::max(drain_ms, checkpoint_ms) / 1000.0)
                                * sizeof(CBlockIndex) / (1024.0 * 1024.0);
    std::cout << std::setprecision(2);
    std::cout << "  arithmetic would say  : " << predicted_mb
              << " MB (rate x max(drain, slowest checkpoint) x sizeof)\n";
    std::cout << "  measured / predicted  : "
              << (predicted_mb > 0 ? peak_mb / predicted_mb : 0.0) << "x\n\n";

    Dilithion::g_chainParams = saved;
    return 0;
}
