// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// evict_cost_bench — what one over-cap insert COSTS at a 500,000-entry index.
//
// WHY THIS EXISTS. PR #129 replaces a single-pass, single-erase evictor with a
// leaf-only one that, per call, builds an in-degree map over the WHOLE index,
// builds a pinned set, and then rescans the surviving map once per eviction.
// That is a materially different cost, and it applies AT THE CAPS THAT ALREADY
// SHIP — DIL is at 500,000 on main today — not only if a cap is ever lowered.
//
// It matters because saturation is attacker-inducible: header spam drives
// mapBlockIndex to the cap, and past that point this routine runs under cs_main
// on EVERY new header. An unmeasured O(n log n)-with-allocations rebuild in that
// position is a CPU lever, so the number belongs in the PR that introduces it.
//
// NOT A ROSTER SUITE, deliberately: it allocates ~500K CBlockIndex objects and
// takes seconds to minutes. It is a tool you run when you change the evictor.
//
//   make evict_cost_bench && ./evict_cost_bench [entries] [pinned_percent]
//
// WHAT IS AND IS NOT MEASURED. Wall time and the cs_main hold are the same span
// here — the evictor takes cs_main for its whole body, so timing the call IS
// timing the hold. Peak transient allocation is measured from the process RSS
// high-water mark across the call, not computed from sizeof() reasoning: an
// estimate presented as a measurement is the failure this PR keeps finding.

#include <consensus/chain.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#ifdef __linux__
#include <cstdio>
#endif

namespace {

// Peak resident set in KB, read from /proc/self/status (Linux). Returns 0 where
// unavailable — reported as "unavailable" rather than silently as zero.
long PeakRssKb()
{
#ifdef __linux__
    std::FILE* f = std::fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    long kb = 0;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "VmHWM:", 6) == 0) {
            std::sscanf(line + 6, "%ld", &kb);
            break;
        }
    }
    std::fclose(f);
    return kb;
#else
    return 0;
#endif
}

long CurrentRssKb()
{
#ifdef __linux__
    std::FILE* f = std::fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    long kb = 0;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "VmRSS:", 6) == 0) {
            std::sscanf(line + 6, "%ld", &kb);
            break;
        }
    }
    std::fclose(f);
    return kb;
#else
    return 0;
#endif
}

uint256 HashFromCounter(uint64_t i)
{
    uint256 h;
    std::memset(h.data, 0, 32);
    std::memcpy(h.data, &i, sizeof(i));
    // Spread the counter so map ordering is not simply sequential — a perfectly
    // sorted key order would give std::map an unrepresentatively friendly layout.
    h.data[31] = static_cast<uint8_t>((i * 2654435761u) & 0xff);
    h.data[30] = static_cast<uint8_t>(((i * 2654435761u) >> 8) & 0xff);
    return h;
}

}  // namespace

int main(int argc, char** argv)
{
    const size_t entries = (argc > 1) ? std::stoul(argv[1]) : 500000;
    const int pinned_pct = (argc > 2) ? std::stoi(argv[2]) : 100;

    std::cout << "\n=== evict_cost_bench: one over-cap insert at "
              << entries << " entries, " << pinned_pct << "% pinned ===\n\n";

    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::ChainParams params = Dilithion::ChainParams::Regtest();
    params.nMapBlockIndexCap = static_cast<int>(entries);
    Dilithion::g_chainParams = &params;

    CChainState chainstate;

    // Build a linear chain of `entries` block indices directly. Linear is the
    // WORST case for the pinned-set walk and the most realistic shape for a
    // synced node, which is the state the cap is reached in.
    const size_t pinned_target = entries * static_cast<size_t>(pinned_pct) / 100;

    std::cout << "  building " << entries << " entries..." << std::flush;
    const auto build_start = std::chrono::steady_clock::now();

    CBlockIndex* prev = nullptr;
    uint256 pinned_tip_hash;
    for (size_t i = 0; i < entries; ++i) {
        auto up = std::make_unique<CBlockIndex>();
        up->pprev = prev;
        up->nHeight = static_cast<int>(i);
        up->nStatus = CBlockIndex::BLOCK_VALID_HEADER;
        up->nSequenceId = static_cast<int32_t>(i + 1);
        // phashBlock is the index's OWN copy of its hash and AddBlockIndex
        // asserts pindex->GetBlockHash() == hash. Set it before adding; leaving
        // it default aborts on the invariant (which is what the first run of
        // this fixture did — a fixture bug, not a product one).
        const uint256 h = HashFromCounter(i);
        up->phashBlock = h;
        CBlockIndex* raw = up.get();
        if (!chainstate.AddBlockIndex(h, std::move(up))) {
            std::cerr << "\n  FATAL: AddBlockIndex failed at " << i << "\n";
            Dilithion::g_chainParams = saved;
            return 2;
        }
        prev = raw;
        if (i + 1 == pinned_target) pinned_tip_hash = h;
    }
    const auto build_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - build_start).count();
    std::cout << " done in " << build_ms << " ms\n";

    // Pin a prefix of the chain by making it the active chain: SetTip(x) pins x
    // and every ancestor via clause (a). pinned_pct=100 pins everything, which is
    // the steady state once active height reaches the cap and is the case the
    // advisory fall-through exists for.
    if (pinned_target > 0) {
        CBlockIndex* tip = chainstate.GetBlockIndex(pinned_tip_hash);
        if (!tip) {
            std::cerr << "  FATAL: pinned tip not found\n";
            Dilithion::g_chainParams = saved;
            return 2;
        }
        chainstate.SetTip(tip);
    }

    std::cout << "  index size            : " << chainstate.GetBlockIndexSize() << "\n";
    std::cout << "  pinned (active chain) : " << pinned_target << "\n";

    const long rss_before  = CurrentRssKb();
    const long peak_before = PeakRssKb();

    // THE MEASUREMENT: exactly what a caller does on one over-cap insert —
    // evict down to cap-1 to make room for a single new header.
    const auto t0 = std::chrono::steady_clock::now();
    const bool evicted = chainstate.EvictLowestWorkLeafNotPinned(entries - 1);
    const auto t1 = std::chrono::steady_clock::now();

    const long peak_after = PeakRssKb();
    const long rss_after  = CurrentRssKb();

    const double us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

    std::cout << "\n  --- one over-cap insert ---\n";
    std::cout << "  evicted_any           : " << (evicted ? "true" : "false") << "\n";
    std::cout << "  index size after      : " << chainstate.GetBlockIndexSize() << "\n";
    std::cout << "  WALL TIME             : " << us / 1000.0 << " ms\n";
    std::cout << "  cs_main HOLD          : " << us / 1000.0
              << " ms (the evictor holds cs_main for its whole body, so the\n"
              << "                          call duration IS the hold; not a separate number)\n";
    if (peak_before > 0) {
        std::cout << "  RSS before / after    : " << rss_before << " / " << rss_after << " KB\n";
        std::cout << "  PEAK RSS delta        : " << (peak_after - peak_before)
                  << " KB (VmHWM high-water across the call)\n";
    } else {
        std::cout << "  PEAK RSS delta        : unavailable on this platform "
                     "(no /proc/self/status)\n";
    }

    std::cout << "\n  NOTE ON THE ALL-PINNED CASE: when every entry is pinned the\n"
                 "  routine still builds the full in-degree map and the full pinned\n"
                 "  set before discovering there is nothing to evict, so this is the\n"
                 "  cost paid per header once a node's active height reaches the cap\n"
                 "  — the steady state, not an edge case.\n";

    Dilithion::g_chainParams = saved;
    std::cout << std::endl;
    return 0;
}
