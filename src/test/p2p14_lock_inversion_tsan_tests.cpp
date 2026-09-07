// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// P2P-14/15 — CONSTRUCT the cs_headers <-> cs_main lock-order inversion.
//
// WHY THIS FILE EXISTS. Two independent readers (CI12B and this session)
// reached the cycle by inspection, from opposite directions, and agreed. That
// is still two arguments, not an observation. This harness exists to make an
// instrument say it.
//
// THE CYCLE (cites against origin/main f47b9b24):
//
//   forward   cs_headers -> cs_main
//             headers_manager.cpp:369,546,689,1027,2922,2991  (cs_headers held)
//               -> chain_selector->ProcessNewHeader
//               -> m_chainstate.{Has,Get,Add}BlockIndex / Evict... -> cs_main
//
//   reverse   cs_main -> cs_headers
//             chain.cpp:662,727,781,1302 inside ActivateBestChain (cs_main held)
//               -> NotifyTipUpdate (chain.cpp:2516) -> m_tipCallbacks[i] (:2527)
//               -> the lambda registered at dilithion-node.cpp:3551
//               -> CHeadersManager::OnBlockActivated -> cs_headers (:960)
//
// WHY A PURPOSE-BUILT HARNESS AND NOT THE EXISTING SUITES: zero tests in
// src/test register ANY of the three chain.h callbacks. The reverse edge is
// therefore unreachable from the entire existing suite by construction, so a
// TSan run over those suites reports clean and that clean is FALSE. That is
// `unreached, not unwritten`. The registration below is the whole point.
//
// BOTH ARMS LIVE IN ONE BINARY, selected by argv, so the control cannot drift
// between two builds:
//
//   ./p2p14_lock_inversion_tsan_tests registered     EXPECT a TSan
//                                                    lock-order-inversion report
//   ./p2p14_lock_inversion_tsan_tests unregistered   EXPECT NO such report
//
// The unregistered arm is the arm that matters. Without it, "no inversion"
// and "the harness never wired the cycle up" look identical -- the same
// over-determination that made a peer's mutation pass with the fix removed.
//
// Run BOTH under: setarch $(uname -m) -R  (ASLR, else TSan aborts before main)
//
// RESULT ON THE UNFIXED TREE (origin/main f47b9b24), measured:
//
//   registered     EXIT=124 (TIMED OUT -- the process HUNG)   2 inversion reports
//   unregistered   EXIT=0   (clean, 200 rounds)               0 inversion reports
//                  forward edge reached 200/200 in BOTH arms
//
// TSan's own words:  Cycle in lock order graph: M0 => M1 => M0
//   M0 = cs_headers, M1 = cs_main
//   M1 under M0:  HasBlockIndex <- ProcessNewHeader <- ProcessHeaders
//   M0 under M1:  OnBlockActivated <- the registered tip-callback std::function
//
// So this file is a RED baseline: it is expected to HANG until the lock order
// is fixed, and to go green afterwards. That makes the both-arms control the
// regression test for the fix rather than a one-off demonstration.
//
// WHEN THIS RUNS IN CI: once #165 arms the TSan leg, a hang here surfaces
// through the `[TIMEOUT]` arm of `scripts/run_test_suites.sh` -- which only
// classifies hangs correctly as of #180 (exit 143 from `timeout
// --preserve-status` was previously falling through to `[FAIL]`, so a suite
// that HUNG was reported as a suite whose tests BROKE, and the TIMEOUT count
// was structurally zero). Without #180 this harness's headline signal --
// "it hangs" -- would be mislabelled as an assertion failure in CI.

#include <consensus/chain.h>
#include <consensus/chain_work.h>
#include <core/chainparams.h>
#include <consensus/port/chain_selector_impl.h>
#include <core/node_context.h>
#include <net/headers_manager.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <atomic>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

const int kRounds = 200;

// VDF-style header: SHA3-256, so GetHash() never enters RandomX and the
// harness does not drag g_validation_mutex into the report we are reading.
CBlockHeader MakeVDFHeader(const uint256& parent_hash, uint32_t nTime)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;
    h.hashPrevBlock = parent_hash;
    std::memset(h.hashMerkleRoot.data, 0, 32);
    h.nTime = nTime;
    h.nBits = 0x1d00ffff;
    h.nNonce = 0;
    for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0;
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i] = static_cast<uint8_t>(nTime & 0xff);
    return h;
}

std::atomic<int>  g_reverse_fired{0};   // callback -> OnBlockActivated -> cs_headers
std::atomic<int>  g_headers_accepted{0};// ProcessHeaders returned true
std::atomic<bool> g_go{false};
std::atomic<int>  g_ready{0};

void WaitForGo()
{
    g_ready.fetch_add(1);
    while (!g_go.load()) std::this_thread::yield();
}

}  // namespace

int main(int argc, char* argv[])
{
    const std::string arm = (argc > 1) ? argv[1] : "registered";
    const bool register_callback = (arm == "registered");
    const bool accessor_arm = (arm == "accessor-unsafe" || arm == "accessor-safe");
    if (arm != "registered" && arm != "unregistered" && !accessor_arm) {
        std::cerr << "usage: " << argv[0]
                  << " registered|unregistered|accessor-unsafe|accessor-safe\n";
        return 2;
    }

    std::cout << "[p2p14-tsan] arm=" << arm
              << "  tip callback " << (register_callback ? "REGISTERED" : "NOT registered")
              << std::endl;

    // Without this the harness aborts in genesis.cpp before touching a lock,
    // and BOTH arms report zero inversions -- a zero that means "the binary
    // died early", not "no cycle". That is why the arms print their exit code
    // alongside the report count.
    if (Dilithion::g_chainParams == nullptr) {
        // Regtest (SHA3 only -- Mainnet aborts with "RandomX VM not
        // initialized"), PLUS one checkpoint so the real fast path is taken.
        // ProcessHeaders' FAST PATH 1 is gated on
        // `expectedHeight <= highestCheckpoint` (headers_manager.cpp:317-318),
        // and Regtest ships no checkpoints -- so every height-1 header fell to
        // the slow PoW path and was dropped, ProcessNewHeader (site :369) was
        // never reached, and ProcessHeaders STILL returned true. The checkpoint
        // sits far above the heights used here, so the fast path is enabled
        // without triggering checkpoint enforcement on these headers.
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
        uint256 cp_hash;
        std::memset(cp_hash.data, 0xab, 32);
        Dilithion::g_chainParams->checkpoints.push_back(Dilithion::CCheckpoint(1000, cp_hash));
    }

    CChainState chainstate;

    // ================================================================
    // P2P-14/15 §0.3-POST — VALUE-ACCESSOR ARMS (a8, 2026-09-07)
    // ================================================================
    // Separate question from the lock-order arms above, needing its own
    // control: NOT "do two locks invert" but "does a pointer escape its lock".
    //
    // GetBlockIndex acquires cs_main, RELEASES it, and returns a raw
    // CBlockIndex*. Any caller that then dereferences it is reading an object
    // another thread may be writing under the lock — LP10's measured shape at
    // 6353bc33 ("a mutex on one side buys nothing"). OnBlockActivated did
    // exactly this and was safe ONLY because its caller still held cs_main;
    // the P2P-14/15 fix fires that callback with cs_main released, which
    // deleted the guarantee. GetBlockHeightByHash reads and dereferences
    // inside one lock scope and copies the value out.
    //
    // The writer: AddBlockIndex on an EXISTING hash takes cs_main and merges
    // into the live entry (`existing->nStatus |= incoming`). cs_main is
    // private, so a test cannot hold it directly — this is the available way
    // to get a lock-held write to the same object.
    //
    // ⚠️ CONFOUND, STATED RATHER THAN HIDDEN: the unsafe arm reads nStatus
    // (the field the writer touches) while the safe arm reads nHeight via the
    // value accessor, because the accessor added by this fix returns height.
    // The arms therefore differ in field as well as in mechanism. That makes
    // this a demonstration that POINTER ESCAPE races and VALUE RETURN does
    // not — it is NOT a same-field A/B. A same-field control would need a
    // value accessor for nStatus, which this contract does not add. Read the
    // result with that limit in mind.
    if (accessor_arm) {
        const bool unsafe = (arm == "accessor-unsafe");
        std::cout << "[p2p1415-accessor] arm=" << arm << "  pattern="
                  << (unsafe ? "GetBlockIndex + deref AFTER release (pre-fix)"
                             : "GetBlockHeightByHash (value, under lock)")
                  << std::endl;

        // The key MUST be the header's own computed hash — AddBlockIndex trips
        // `INVARIANT VIOLATION: pindex->GetBlockHash() == hash` (chain.cpp:98)
        // otherwise. An invented key aborts the process before either thread
        // runs, which reads as EXIT=134 with zero races: a fixture failure
        // wearing the costume of a clean result.
        uint256 prev;
        std::memset(prev.data, 0, 32);
        const CBlockHeader targetHeader = MakeVDFHeader(prev, 1700000042);
        const uint256 target = targetHeader.GetHash();
        {
            auto idx = std::make_unique<CBlockIndex>();
            idx->header = targetHeader;
            idx->phashBlock = target;   // GetBlockHash() aborts without this
            idx->nHeight = 0;   // null hashPrevBlock => genesis-shaped; AddBlockIndex requires 0
            idx->nStatus = 0;
            chainstate.AddBlockIndex(target, std::move(idx));
        }

        std::atomic<bool> stop{false};
        std::atomic<uint64_t> reads{0}, writes{0};

        std::thread reader([&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                if (unsafe) {
                    // PRE-FIX PATTERN — the pointer outlives the lock.
                    CBlockIndex* p = chainstate.GetBlockIndex(target);
                    if (p) {
                        volatile uint32_t observed = p->nStatus;  // unlocked read
                        (void)observed;
                    }
                } else {
                    // POST-FIX PATTERN — nothing escapes the lock scope.
                    int h = 0;
                    (void)chainstate.GetBlockHeightByHash(target, h);
                }
                reads.fetch_add(1, std::memory_order_relaxed);
            }
        });

        std::thread writer([&]() {
            for (int i = 0; i < 4000 && !stop.load(std::memory_order_relaxed); ++i) {
                auto dup = std::make_unique<CBlockIndex>();
                dup->header = targetHeader;       // same hash → merge path, invariant holds
                dup->phashBlock = target;         // GetBlockHash() aborts without this
                dup->nHeight = 0;                 // same topology → no disagreement trip
                dup->nStatus = (i & 1) ? 0x2 : 0x4;
                chainstate.AddBlockIndex(target, std::move(dup));  // writes under cs_main
                writes.fetch_add(1, std::memory_order_relaxed);
            }
            stop.store(true, std::memory_order_relaxed);
        });

        writer.join();
        stop.store(true, std::memory_order_relaxed);
        reader.join();

        std::cout << "[p2p1415-accessor] reads=" << reads.load()
                  << " writes=" << writes.load() << std::endl;
        // Both counters must be non-zero or the arm proved nothing: a zero
        // means one thread never ran and the result is about scheduling, not
        // about the pattern.
        if (reads.load() == 0 || writes.load() == 0) {
            std::cerr << "[p2p1415-accessor] HARNESS DEFECT: a thread did no work; "
                         "any race count from this run is meaningless" << std::endl;
            return 3;
        }
        return 0;
    }

    // Bypass the DB/UTXO work of the real ConnectTip. This does NOT bypass the
    // lock: ActivateBestChain still holds cs_main across the override and still
    // reaches NotifyTipUpdate, which is the only part of that path this harness
    // is about.
    chainstate.SetTestConnectTipOverride(
        [](CBlockIndex*, const CBlock&) { return true; });

    g_node_context.headers_manager = std::make_unique<CHeadersManager>();
    g_node_context.chain_selector =
        std::make_unique<dilithion::consensus::port::ChainSelectorAdapter>(chainstate);

    // THE REGISTRATION — byte-for-byte the shape of dilithion-node.cpp:3551
    // and dilv-node.cpp:3371. This single line is the difference between the
    // two arms, and it is the line that puts the reverse edge in the binary.
    if (register_callback) {
        // P2P-14/15 SIGNATURE UPDATE (a8, 2026-09-07). This registration was
        // written against the pre-fix `void(const CBlockIndex*)` signature. The
        // fix passes the header and hash BY VALUE, so the old form no longer
        // compiles and this had to change with it.
        //
        // WHAT DID NOT CHANGE — and this is what keeps the two arms comparable:
        // the callback still calls OnBlockActivated, which still takes
        // cs_headers. The reverse edge this harness exists to put in the binary
        // is identical; only the parameter list differs. If this arm ever stops
        // reaching cs_headers, the harness stops testing anything.
        //
        // The RED baseline in docs/p2p14-lock-inversion/*.err was produced by
        // the PRE-FIX harness against the PRE-FIX tree — the correct pairing.
        // A post-fix green from this updated harness is evidence about the
        // post-fix tree; it is NOT a re-run of the recorded baseline, and must
        // not be presented as one.
        chainstate.RegisterTipUpdateCallback([](const CBlockHeader& header, const uint256& hash) {
            if (g_node_context.headers_manager) {
                g_reverse_fired.fetch_add(1);
                g_node_context.headers_manager->OnBlockActivated(header, hash);
            }
        });
    }

    // Seed a genesis-ish index so ActivateBestChain has something to activate.
    uint256 null_hash;
    std::memset(null_hash.data, 0, 32);
    CBlockHeader genesis = MakeVDFHeader(null_hash, 1700000000);
    const uint256 genesis_hash = genesis.GetHash();
    {
        auto idx = std::make_unique<CBlockIndex>();
        idx->header = genesis;
        idx->phashBlock = genesis_hash;
        idx->nHeight = 0;
        idx->pprev = nullptr;
        idx->nStatus = CBlockIndex::BLOCK_VALID_HEADER;
        idx->nChainWork = ::dilithion::consensus::ComputeChainWork(genesis.nBits);
        chainstate.AddBlockIndex(genesis_hash, std::move(idx));
    }
    CBlockIndex* pgenesis = chainstate.GetBlockIndex(genesis_hash);

    // EDGE-B REQUIRES CASE 2, NOT CASE 1.
    // ActivateBestChain's "Case 1: genesis" arm (pindexTip == nullptr) returns
    // at chain.cpp:685 WITHOUT calling NotifyTipUpdate. Only "Case 2: extends
    // current tip" notifies, at :727. The first harness run left pindexTip null,
    // took Case 1 every round, and fired the callback zero times -- which is why
    // EDGE-B read 0 and why that 0 said nothing about the cycle.
    //
    // So: set a real tip, then pre-build a real chain of extensions. Each round
    // activates the NEXT block, whose pprev IS the current tip, so every round
    // is a genuine Case 2. We drive the real caller (ActivateBestChain) rather
    // than NotifyTipUpdate directly -- per a8's red-team note, cs_main is owned
    // by ActivateBestChain at chain.cpp:375 and is RECURSIVE, so calling the
    // private notify directly would observe an order pair that is not the
    // production one.
    chainstate.SetTipForTest(pgenesis);

    std::vector<CBlockIndex*> chain;
    std::vector<CBlock> blocks;
    chain.reserve(kRounds);
    blocks.reserve(kRounds);
    {
        CBlockIndex* prev = pgenesis;
        uint256 work = prev->nChainWork;
        for (int i = 0; i < kRounds; ++i) {
            CBlockHeader h = MakeVDFHeader(prev->GetBlockHash(), 1700500000u + i);
            const uint256 h_hash = h.GetHash();
            work = ::dilithion::consensus::AddChainWork(
                work, ::dilithion::consensus::ComputeChainWork(h.nBits));
            auto idx = std::make_unique<CBlockIndex>();
            idx->header = h;
            idx->phashBlock = h_hash;
            idx->nHeight = prev->nHeight + 1;
            idx->pprev = prev;
            idx->nStatus = CBlockIndex::BLOCK_VALID_HEADER;
            idx->nChainWork = work;
            chainstate.AddBlockIndex(h_hash, std::move(idx));
            CBlockIndex* added = chainstate.GetBlockIndex(h_hash);
            chain.push_back(added);

            CBlock b;
            b.nVersion = h.nVersion;
            b.hashPrevBlock = h.hashPrevBlock;
            b.hashMerkleRoot = h.hashMerkleRoot;
            b.nTime = h.nTime;
            b.nBits = h.nBits;
            b.nNonce = h.nNonce;
            b.vdfProofHash = h.vdfProofHash;
            b.vdfOutput = h.vdfOutput;
            blocks.push_back(b);
            prev = added;
        }
    }

    // THREAD A — the forward edge: cs_headers -> cs_main.
    // ProcessHeaders takes cs_headers (headers_manager.cpp:222) and, per site,
    // calls chain_selector->ProcessNewHeader, which enters CChainState and
    // takes cs_main.
    // The headers manager keeps its OWN mapHeaders, separate from the
    // chainstate's mapBlockIndex. Seeding the chainstate is NOT enough: without
    // genesis in mapHeaders, every child is an orphan, ProcessHeaders takes the
    // "FORK: Parent unknown" early return, and ProcessNewHeader is never
    // reached -- so cs_main is never taken under cs_headers and the run reports
    // zero inversions for a reason that has nothing to do with the cycle.
    {
        std::vector<CBlockHeader> seed;
        seed.push_back(genesis);
        g_node_context.headers_manager->ProcessHeaders(/*peer=*/1, seed);
    }

    // Thread A's headers are built UP FRONT and kept, so the reachability proof
    // can name them. Pre-building the tip chain above made mapBlockIndex grow on
    // its own, which would have made a bare "index size > 1" check pass whether
    // or not thread A ever reached ProcessNewHeader -- an over-determined check
    // that proves the harness, not the edge.
    std::vector<CBlockHeader> a_headers;
    a_headers.reserve(kRounds);
    for (int i = 0; i < kRounds; ++i) {
        a_headers.push_back(MakeVDFHeader(genesis_hash, 1700001000u + i));
    }

    std::thread ta([&]() {
        WaitForGo();
        for (int i = 0; i < kRounds; ++i) {
            std::vector<CBlockHeader> batch;
            batch.push_back(a_headers[i]);
            if (g_node_context.headers_manager->ProcessHeaders(/*peer=*/1, batch)) g_headers_accepted.fetch_add(1);
        }
    });

    // THREAD B — the reverse edge: cs_main -> cs_headers.
    // ActivateBestChain holds cs_main across NotifyTipUpdate, which fires the
    // registered callback into OnBlockActivated -> cs_headers.
    std::thread tb([&]() {
        WaitForGo();
        for (int i = 0; i < kRounds; ++i) {
            bool reorg = false;
            chainstate.ActivateBestChain(chain[i], blocks[i], reorg);
        }
    });

    while (g_ready.load() < 2) std::this_thread::yield();
    g_go.store(true);
    ta.join();
    tb.join();

    // Deliberately exit 0 in BOTH arms. The verdict is not this exit code --
    // it is whether TSan printed "lock-order-inversion" on stderr. Returning
    // non-zero here would let a harness crash masquerade as a detection.
    // REACHABILITY PROOF — the harness must not be allowed to report a zero it
    // has not earned. ProcessNewHeader is the ONLY thing here that adds to the
    // chainstate's mapBlockIndex, and it does so under cs_main while thread A
    // holds cs_headers. So a grown index size is positive evidence that the
    // FORWARD edge was actually traversed. Without this line, "0 inversions"
    // and "thread A early-returned every round" are indistinguishable -- which
    // is exactly what the first run of this harness did.
    // Count how many of THREAD A's OWN headers reached the chainstate. Only
    // ProcessNewHeader puts them there, and it does so under cs_main while
    // thread A holds cs_headers -- so a non-zero count is specific positive
    // evidence that the FORWARD edge was traversed, and it cannot be satisfied
    // by the tip chain that thread B's setup pre-added.
    int a_landed = 0;
    for (const auto& h : a_headers) {
        if (chainstate.GetBlockIndex(h.GetHash()) != nullptr) ++a_landed;
    }
    const size_t idx_size = static_cast<size_t>(a_landed);
    std::cout << "[p2p14-tsan] EDGE-A ProcessHeaders accepted=" << g_headers_accepted.load()
              << "  EDGE-B callback fired=" << g_reverse_fired.load() << std::endl;
    std::cout << "[p2p14-tsan] REACH forward-edge: threadA headers landed=" << idx_size << "/" << kRounds
              << " (>0 means ProcessNewHeader ran under cs_headers)" << std::endl;
    std::cout << "[p2p14-tsan] arm=" << arm << " completed " << kRounds
              << " rounds on each thread" << std::endl;
    if (idx_size == 0) {
        std::cerr << "[p2p14-tsan] HARNESS DEFECT: forward edge never reached; "
                     "any inversion count from this run is meaningless\n";
        return 3;
    }
    return 0;
}
