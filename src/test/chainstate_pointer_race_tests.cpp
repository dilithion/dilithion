// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// TSan harness for the CChainState raw-pointer escape.
//
// THE CLAIM UNDER TEST. `CChainState` hands out raw `CBlockIndex*` from under
// its own lock, and callers dereference them WITHOUT it:
//
//   [source] chain.cpp:2377  GetTip()  { lock_guard(cs_main); return pindexTip; }
//   [source] block_index.h:57 IsOnMainChain() const { return pnext != nullptr; }  // no lock
//   [source] pnext WRITTEN under cs_main by ConnectTip (chain.cpp:1898) and
//            DisconnectTip (chain.cpp:2069 / :2073)
//
// `cs_main` is PRIVATE, so an index thread cannot synchronise even if it wanted
// to — and both index modules run their own std::thread (coinstatsindex.h:199,
// tx_index.h:82) calling IsOnMainChain on pointers obtained from the chainstate
// (coinstatsindex.cpp:305-316, tx_index.cpp:230/:621).
//
// ⚠️ THIS HARNESS IS ITSELF UNVERIFIED SURFACE, so it ships with a
// DISCRIMINATING CONTROL rather than a single expectation. A harness that
// reports a race unconditionally proves nothing; one that reports none may
// simply not be instrumented. So it runs the SAME writer against TWO readers:
//
//   RACE    reader touches `pnext`   -- the field the writer writes -> expect a TSan report
//   CONTROL reader touches `nHeight` -- never written concurrently  -> expect NO report
//
// If BOTH report, the harness is over-reporting and its RACE result means
// nothing. If NEITHER reports, TSan is not instrumenting this binary — check
// `nm -C <binary> | grep -c __tsan` before believing a green.
//
// Run it as: setarch $(uname -m) -R ./chainstate_pointer_race_tests <mode>
// (ASLR must be off or the TSan runtime aborts before main; see the recipe.)

#include <consensus/chain.h>
#include <node/block_index.h>
#include <primitives/block.h>
#include <crypto/sha3.h>

#include <atomic>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> g_stop{false};

// A minimal NON-VDF block whose vtx deserializes and whose merkle root matches,
// so ConnectTip reaches the point where it writes pprev->pnext. Deliberately
// not a VDF block: the LP-10 checks are irrelevant here and a real Wesolowski
// proof would cost ~500k iterations per construction.
CBlock MakeConnectableBlock(const uint256& prevHash, int height)
{
    CBlock block;
    block.nVersion      = 3;                 // < VDF_VERSION, so IsVDFBlock() is false
    block.hashPrevBlock = prevHash;
    block.nBits         = 0x1d00ffff;
    block.nTime         = 1700000000u + static_cast<uint32_t>(height);
    block.nNonce        = 0;

    std::vector<uint8_t> vtx;
    vtx.push_back(1);                        // tx count
    int32_t txVersion = 1;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&txVersion),
               reinterpret_cast<uint8_t*>(&txVersion) + 4);
    vtx.push_back(1);                        // vin count
    for (int i = 0; i < 32; ++i) vtx.push_back(0);
    uint32_t coinbaseIndex = 0xFFFFFFFF;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&coinbaseIndex),
               reinterpret_cast<uint8_t*>(&coinbaseIndex) + 4);

    std::vector<uint8_t> scriptSig;
    scriptSig.push_back(0x03);
    uint32_t h = static_cast<uint32_t>(height);
    scriptSig.push_back(static_cast<uint8_t>(h & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 8) & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 16) & 0xFF));
    vtx.push_back(static_cast<uint8_t>(scriptSig.size()));
    vtx.insert(vtx.end(), scriptSig.begin(), scriptSig.end());

    uint32_t seq = 0xFFFFFFFF;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&seq),
               reinterpret_cast<uint8_t*>(&seq) + 4);
    vtx.push_back(1);                        // vout count
    uint64_t value = 50ULL * 100000000ULL;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&value),
               reinterpret_cast<uint8_t*>(&value) + 8);
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) spk.push_back(static_cast<uint8_t>(i));
    spk.push_back(0x88); spk.push_back(0xac);
    vtx.push_back(static_cast<uint8_t>(spk.size()));
    vtx.insert(vtx.end(), spk.begin(), spk.end());
    uint32_t locktime = 0;
    vtx.insert(vtx.end(), reinterpret_cast<uint8_t*>(&locktime),
               reinterpret_cast<uint8_t*>(&locktime) + 4);

    block.vtx = vtx;
    SHA3_256(vtx.data() + 1, vtx.size() - 1, block.hashMerkleRoot.data);
    return block;
}

uint256 HashFor(uint8_t tag, int height)
{
    uint256 h;
    h.data[0]  = tag;
    h.data[1]  = static_cast<uint8_t>(height & 0xFF);
    h.data[2]  = static_cast<uint8_t>((height >> 8) & 0xFF);
    h.data[31] = 0x01;
    return h;
}

// mode: "race" -> the reader touches pnext (the written field)
//       "control" -> the reader touches nHeight (never written concurrently)
int Run(const std::string& mode)
{
    // "race" and "class" both read the field the writer writes; they differ only
    // in HOW the pointer is obtained (GetTip vs GetBlockIndex). "control" uses
    // the same acquisition as "race" but reads a field nothing writes.
    const bool readsWrittenField = (mode != "control");

    CChainState chain;

    const uint256 hashA = HashFor(0xA0, 0);
    const uint256 hashB = HashFor(0xB0, 1);

    auto upA = std::make_unique<CBlockIndex>();
    upA->nHeight = 0; upA->phashBlock = hashA; upA->nVersion = 3;
    CBlockIndex* pA = upA.get();
    chain.AddBlockIndex(hashA, std::move(upA));

    auto upB = std::make_unique<CBlockIndex>();
    upB->nHeight = 1; upB->phashBlock = hashB; upB->nVersion = 3; upB->pprev = pA;
    CBlockIndex* pB = upB.get();
    chain.AddBlockIndex(hashB, std::move(upB));

    chain.SetTipForTest(pA);
    const CBlock blockB = MakeConnectableBlock(hashA, 1);

    // WRITER: the production path. ConnectTip writes pA->pnext = pB under
    // cs_main (chain.cpp:1898). Nothing here reaches around the lock.
    std::thread writer([&]() {
        while (!g_stop.load(std::memory_order_relaxed)) {
            chain.ConnectTip(pB, blockB, /*skipValidation=*/true);
        }
    });

    // READER: exactly what an index thread does — obtain a pointer from the
    // chainstate (GetTip takes the lock, then releases it) and dereference it
    // afterwards, holding nothing.
    std::atomic<long long> observed{0};
    std::thread reader([&]() {
        while (!g_stop.load(std::memory_order_relaxed)) {
            // "class" mode reads through GetBlockIndex rather than GetTip.
            //
            // GetBlockIndex is the ROOT of the nine-site class: it takes
            // cs_main, returns `it->second.get()` -- a raw pointer out of a
            // unique_ptr -- and drops the lock at return (chain.cpp, and note
            // its own comment "HIGH-C001 FIX: Return raw pointer (non-owning)
            // via .get()", so the shape was introduced deliberately). Eight
            // further callers dereference the result without cs_main, and
            // cs_main is PRIVATE so none of them could take it even if they
            // tried. Observing this path proves the class root, not just the
            // GetTip instance.
            CBlockIndex* t = (mode == "class") ? chain.GetBlockIndex(hashA)
                                               : chain.GetTip();
            if (t == nullptr) continue;
            if (readsWrittenField) {
                if (t->IsOnMainChain()) observed.fetch_add(1, std::memory_order_relaxed);
            } else {
                if (t->nHeight >= 0)    observed.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    std::this_thread::sleep_for(std::chrono::seconds(3));
    g_stop.store(true, std::memory_order_relaxed);
    writer.join();
    reader.join();

    std::cout << "mode=" << mode
              << "  acquired via " << (mode == "class" ? "GetBlockIndex" : "GetTip")
              << "  reader touched " << (readsWrittenField ? "pnext (via IsOnMainChain)" : "nHeight (control)")
              << "  iterations=" << observed.load() << "\n";
    std::cout << "TSan reports, if any, are on stderr above. Exit code is TSan's.\n";

    // Leave the chainstate alive: Cleanup() would destroy the indexes and the
    // point of this harness is the pointer escape, not teardown.
    return 0;
}

}  // namespace

int main(int argc, char* argv[])
{
    const std::string mode = (argc > 1) ? argv[1] : "race";
    if (mode != "race" && mode != "control" && mode != "class") {
        std::cerr << "usage: chainstate_pointer_race_tests [race|control]\n"
                  << "  race    reader reads pnext   (the field ConnectTip writes) -> expect a TSan report\n"
                  << "  control reader reads nHeight (never written concurrently)  -> expect NO report\n"
                  << "  class   same as race but the pointer comes from GetBlockIndex, the root of\n"
                  << "          the nine-site class -> expect a TSan report\n";
        return 2;
    }
    std::cout << "=== CChainState raw-pointer escape, mode=" << mode << " ===\n";
    return Run(mode);
}
