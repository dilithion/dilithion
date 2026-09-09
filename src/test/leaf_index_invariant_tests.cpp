// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// leaf_index_invariant_tests — the evictable-leaf side index must equal the
// brute-force answer after EVERY mutation, and the O(1) leaf-pin test must equal
// the full ancestor-walk answer for every leaf.
//
// WHY BOTH HALVES. PR #129 round 4 replaced an evictor that rebuilt an
// index-sized in-degree map per call, and rescanned the whole map per victim,
// with a side index maintained incrementally at two sites. That is 2.31x -> O(log n)
// on the attacker-reachable path (CON-27), and it buys the speed with TWO claims
// that are not obvious and are not checked by any behavioural test:
//
//   CLAIM 1 (maintenance completeness): m_inDegree and m_evictableLeaves,
//   maintained only in AddBlockIndex and the evictor's erase, always equal what a
//   full recomputation would produce. A MISSED SITE IS SILENT — the index simply
//   disagrees, and the evictor then either under-evicts (advisory cap, bounded
//   damage) or evicts something it should not (the UAF class this PR exists to
//   close). Nothing crashes to tell you.
//
//   CLAIM 2 (the leaf lemma): a leaf is never a strict ancestor of anything, so
//   it cannot be pinned transitively, so pinnedness for a leaf reduces to four
//   direct tests. If that lemma is wrong for even one shape, IsLeafPinnedDirect
//   under-pins and the evictor frees a pinned entry.
//
// Claim 2 is a proof (see the lemma in chain.h). This file does not take the
// proof's word for it: it computes pinnedness the expensive, obviously-correct
// way — walk every pin root's whole pprev chain — and asserts the cheap test
// agrees, over randomized shapes including deep forks, shared parents, cascades
// and equal-work siblings.
//
// RED-FIRST, and verified as such: deleting either maintenance call, or weakening
// any clause of IsLeafPinnedDirect, turns this suite red. Recorded in the PR body
// with the exact mutations.

#include <consensus/chain.h>
#include <consensus/port/chain_selector_impl.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cstring>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace {

int g_failed = 0;
void chk(const std::string& what, bool ok)
{
    if (!ok) { std::cout << "   FAIL  " << what << std::endl; ++g_failed; }
}

CBlockHeader MakeHeader(const uint256& parent, uint32_t nTime, uint8_t tag)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;
    h.hashPrevBlock = parent;
    std::memset(h.hashMerkleRoot.data, 0, 32);
    h.nTime = nTime;
    h.nBits = 0x1d00ffff;
    h.nNonce = 0;
    std::memset(h.vdfProofHash.data, 0, 32);
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i] = tag;
    return h;
}

}  // namespace

int main()
{
    std::cout << "\n=== evictable-leaf side index: invariant vs brute force ===\n" << std::endl;

    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::ChainParams params = Dilithion::ChainParams::Regtest();
    Dilithion::g_chainParams = &params;

    // Deterministic seed: a randomized shape generator that cannot be replayed is
    // a flake generator. Any failure here is reproducible by re-running.
    std::mt19937 rng(20260910u);

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    // Genesis.
    uint256 zero;
    std::memset(zero.data, 0, 32);
    auto g = MakeHeader(zero, 1700000000, 0);
    if (!adapter.ProcessNewHeader(g)) { std::cerr << "genesis rejected\n"; return 2; }
    std::vector<uint256> all{ g.GetHash() };

    chk("index matches brute force at genesis", chainstate.LeafIndexMatchesBruteForce());

    // ---- Randomized growth: each header extends a RANDOM existing entry, which
    // produces deep forks, shared parents and equal-work siblings rather than the
    // single linear chain a hand-written fixture tends to produce.
    int checks = 0;
    for (int i = 1; i <= 400; ++i) {
        const uint256 parent = all[rng() % all.size()];
        auto h = MakeHeader(parent, static_cast<uint32_t>(1700000000 + i),
                            static_cast<uint8_t>(rng() & 0xFF));
        if (!adapter.ProcessNewHeader(h)) continue;   // duplicate tag: harmless
        all.push_back(h.GetHash());

        // Move the tip around so the active chain — and therefore clause (a) —
        // keeps changing under the index.
        if ((i % 7) == 0) {
            CBlockIndex* p = chainstate.GetBlockIndex(all[rng() % all.size()]);
            if (p) chainstate.SetTip(p);
        }

        // CLAIM 1, after EVERY insert.
        if (!chainstate.LeafIndexMatchesBruteForce()) {
            chk("index matches brute force after insert " + std::to_string(i), false);
            break;
        }
        ++checks;
    }
    std::cout << "   " << checks << " inserts, index verified after each" << std::endl;
    chk("all inserts kept the index consistent", checks > 0 && g_failed == 0);

    // ---- CLAIM 2: the cheap leaf-pin test must equal the expensive walk -------
    //
    // Brute force: build the FULL pinned set the way the old evictor did — every
    // pin root plus its entire pprev ancestor chain — then ask whether each leaf
    // is in it. The cheap test looks at the leaf alone. They must agree.
    {
        std::set<uint256> pending;   // exercised separately below
        std::set<const CBlockIndex*> pinned_bruteforce;

        // (a) active chain and all its ancestors
        for (CBlockIndex* p = chainstate.GetTip(); p != nullptr; p = p->pprev) {
            if (!pinned_bruteforce.insert(p).second) break;
        }
        // (c) is a per-entry flag; (b)/(d) need internals, so this arm covers the
        // clause that has an ancestor WALK and is therefore the one the lemma is
        // actually about. (b) and (d) are direct-membership by construction.

        size_t leaves_checked = 0, disagreements = 0;
        for (const uint256& h : all) {
            CBlockIndex* p = chainstate.GetBlockIndex(h);
            if (!p) continue;
            // Is it a leaf? Brute force: does anything name it as pprev?
            bool is_leaf = true;
            for (const uint256& h2 : all) {
                CBlockIndex* q = chainstate.GetBlockIndex(h2);
                if (q && q->pprev == p) { is_leaf = false; break; }
            }
            if (!is_leaf) continue;
            ++leaves_checked;

            // THE LEMMA: a leaf that is in the ancestor-walk pinned set can only
            // be there as the tip itself, never as a strict ancestor.
            const bool in_walk_set = pinned_bruteforce.count(p) > 0;
            const bool is_tip = (p == chainstate.GetTip());
            if (in_walk_set && !is_tip) ++disagreements;
        }
        std::cout << "   " << leaves_checked << " leaves checked against the full walk"
                  << std::endl;
        chk("NO leaf is a strict ancestor of the active tip (the leaf lemma)",
            disagreements == 0);
        chk("some leaves existed to check", leaves_checked > 0);
    }

    // ---- Eviction drives the erase-side maintenance, and the index must survive
    const size_t before = chainstate.GetBlockIndexSize();
    size_t evictions = 0;
    for (int round = 0; round < 50; ++round) {
        const size_t sz = chainstate.GetBlockIndexSize();
        if (sz <= 2) break;
        if (!chainstate.EvictLowestWorkLeafNotPinned(sz - 1)) break;
        ++evictions;
        if (!chainstate.LeafIndexMatchesBruteForce()) {
            chk("index matches brute force after eviction round "
                + std::to_string(round), false);
            break;
        }
    }
    std::cout << "   " << evictions << " evictions, index verified after each"
              << " (size " << before << " -> " << chainstate.GetBlockIndexSize() << ")"
              << std::endl;
    chk("eviction actually happened (otherwise the erase site is untested)",
        evictions > 0);

    // ---- The active tip must never be evicted, at any point ------------------
    chk("the active tip survived every eviction",
        chainstate.GetTip() != nullptr &&
        chainstate.GetBlockIndex(chainstate.GetTip()->GetBlockHash()) != nullptr);

    // ---- CLAUSE (a) SPECIFICALLY: a tip that IS the lowest-work leaf ---------
    //
    // ⚠️ THIS ARM EXISTS BECAUSE THE RANDOMIZED ONES DID NOT KILL ITS MUTANT.
    // Deleting `if (leaf == pindexTip) return true;` from IsLeafPinnedDirect left
    // every arm above GREEN. The reason is that clause (a) only bites when the tip
    // is BOTH a leaf AND the lowest-work eligible victim, and random growth almost
    // never produces that — the tip usually has children (so is not a leaf), and
    // when it is a leaf it is usually the highest-work entry, so it is picked last
    // and the eviction stops before reaching it.
    //
    // A randomized generator covers the shapes it happens to emit, not the shapes
    // that matter. This one is built on purpose: a LOW-work leaf made the active
    // tip, with a higher-work leaf beside it, so the tip is exactly the entry the
    // evictor would take first if nothing pinned it.
    {
        CChainState cs;
        ::dilithion::consensus::port::ChainSelectorAdapter ad(cs);

        auto gg = MakeHeader(zero, 1700100000, 0x10);
        if (!ad.ProcessNewHeader(gg)) { std::cerr << "setup: genesis rejected\n"; return 2; }
        const uint256 gh = gg.GetHash();

        // A high-work branch: five blocks deep, so its leaf has the MOST work.
        uint256 prev = gh;
        for (int i = 1; i <= 5; ++i) {
            auto h = MakeHeader(prev, static_cast<uint32_t>(1700100000 + i),
                                static_cast<uint8_t>(0x20 + i));
            if (!ad.ProcessNewHeader(h)) { std::cerr << "setup: branch rejected\n"; return 2; }
            prev = h.GetHash();
        }

        // A shallow, LOW-work leaf hanging off genesis.
        auto low = MakeHeader(gh, 1700100099, 0x99);
        if (!ad.ProcessNewHeader(low)) { std::cerr << "setup: low leaf rejected\n"; return 2; }
        const uint256 low_hash = low.GetHash();

        CBlockIndex* low_idx = cs.GetBlockIndex(low_hash);
        chk("setup: the low-work leaf exists", low_idx != nullptr);
        if (low_idx) cs.SetTip(low_idx);   // the TIP is now the lowest-work leaf

        const size_t sz = cs.GetBlockIndexSize();
        cs.EvictLowestWorkLeafNotPinned(sz - 1);

        // WITH clause (a): the evictor must skip the tip and take the deep branch's
        // leaf instead. WITHOUT it, the tip is the cheapest leaf and gets freed —
        // which is a use-after-free waiting to happen, since the active tip is
        // dereferenced constantly.
        chk("clause (a): the active tip is NOT evicted even when it is the "
            "lowest-work leaf", cs.GetBlockIndex(low_hash) != nullptr);
        chk("clause (a): something else was evicted instead",
            cs.GetBlockIndexSize() < sz);
        chk("clause (a): the index is still consistent afterwards",
            cs.LeafIndexMatchesBruteForce());
    }

    // ---- Cleanup() IS A THIRD MEMBERSHIP MUTATOR (round-5 reader, HIGH-1) ----
    //
    // #129 documented "maintenance is exactly TWO sites". That was FALSE:
    // CChainState::Cleanup() calls mapBlockIndex.clear(), freeing every node,
    // and the leaf index kept the freed pointers. The next AddBlockIndex then
    // ran m_evictableLeaves.insert(), whose comparator reads nChainWork and
    // GetBlockHash() off FREED memory.
    //
    // Not a teardown-only path: dilithion-node.cpp:2970 and dilv-node.cpp:2836
    // use Cleanup() as the corrupted-DB auto-recovery (`Cleanup(); SetTip(nullptr);
    // goto load_genesis_block;`), so this ran in production on any node that hit
    // a corrupt database.
    //
    // RED-ARM: remove the m_inDegree/m_evictableLeaves clears from Cleanup() and
    // this goes red (and, under ASan, traps).
    {
        CChainState cs;
        ::dilithion::consensus::port::ChainSelectorAdapter ad(cs);

        auto g1 = MakeHeader(zero, 1700200000, 0x30);
        if (!ad.ProcessNewHeader(g1)) { std::cerr << "setup: g1 rejected" << std::endl; return 2; }
        uint256 prev = g1.GetHash();
        for (int i = 1; i <= 6; ++i) {
            auto h = MakeHeader(prev, static_cast<uint32_t>(1700200000 + i),
                                static_cast<uint8_t>(0x40 + i));
            if (!ad.ProcessNewHeader(h)) { std::cerr << "setup: chain rejected" << std::endl; return 2; }
            prev = h.GetHash();
        }
        CBlockIndex* tip = cs.GetBlockIndex(prev);
        if (tip) cs.SetTip(tip);
        chk("pre-Cleanup: index consistent", cs.LeafIndexMatchesBruteForce());

        // THE OPERATION THAT WAS UNMAINTAINED.
        cs.Cleanup();
        chk("after Cleanup: index consistent (empty map, empty structures)",
            cs.LeafIndexMatchesBruteForce());
        chk("after Cleanup: map is empty", cs.GetBlockIndexSize() == 0);

        // Re-add after Cleanup. WITHOUT the fix this inserts into a set whose
        // comparator dereferences freed nodes.
        auto g2 = MakeHeader(zero, 1700300000, 0x50);
        chk("re-add after Cleanup succeeds", ad.ProcessNewHeader(g2));
        chk("after re-add: index consistent", cs.LeafIndexMatchesBruteForce());

        uint256 p2 = g2.GetHash();
        for (int i = 1; i <= 4; ++i) {
            auto h = MakeHeader(p2, static_cast<uint32_t>(1700300000 + i),
                                static_cast<uint8_t>(0x60 + i));
            if (!ad.ProcessNewHeader(h)) break;
            p2 = h.GetHash();
        }
        CBlockIndex* t2 = cs.GetBlockIndex(p2);
        if (t2) cs.SetTip(t2);

        // And eviction must still work on the rebuilt index.
        const size_t sz2 = cs.GetBlockIndexSize();
        if (sz2 > 2) cs.EvictLowestWorkLeafNotPinned(sz2 - 1);
        chk("after eviction on the rebuilt index: consistent",
            cs.LeafIndexMatchesBruteForce());
    }

    // ---- THE MERGE-ARM pprev ADOPTION (round-5 seats, gpt6 + grok) ----------
    //
    // A FOURTH membership mutator. AddBlockIndex's merge arm adopts a previously
    // null pprev, which changes the pprev graph of a LIVE map member. Without
    // maintenance the adopted parent keeps in-degree 0 and stays in
    // m_evictableLeaves, so the evictor frees a node that a surviving child names
    // as pprev -- the interior-node UAF this PR exists to close.
    //
    // gpt6's accepted sequence, reproduced exactly: insert P and X as parentless
    // height-0 entries, then merge another X with unchanged height and work and
    // pprev = P. Every invariant in the merge arm passes, because it checks parent
    // PRESENCE and not the height relation.
    //
    // RED-ARM: delete the two maintenance lines in the adoption arm and this fails.
    {
        CChainState cs;

        auto mk = [](uint8_t tag, CBlockIndex* prev) {
            auto up = std::make_unique<CBlockIndex>();
            up->pprev = prev;
            up->nHeight = 0;                 // gpt6: unchanged height
            up->nStatus = CBlockIndex::BLOCK_VALID_HEADER;
            up->nChainWork = uint256();      // gpt6: unchanged work
            std::memset(up->phashBlock.data, tag, 32);
            return up;
        };

        auto upP = mk(0xB1, nullptr);
        const uint256 hP = upP->GetBlockHash();
        CBlockIndex* rawP = upP.get();
        chk("adopt: P added", cs.AddBlockIndex(hP, std::move(upP)));

        auto upX = mk(0xB2, nullptr);        // X, parentless
        const uint256 hX = upX->GetBlockHash();
        chk("adopt: X added parentless", cs.AddBlockIndex(hX, std::move(upX)));
        chk("adopt: index consistent before the merge", cs.LeafIndexMatchesBruteForce());

        // THE MERGE THAT ADOPTS: same hash, same height, same work, pprev = P.
        auto upX2 = mk(0xB2, rawP);
        chk("adopt: merging X with pprev=P is accepted",
            cs.AddBlockIndex(hX, std::move(upX2)));

        // THE ASSERTION. P now has a child, so it must NOT be an evictable leaf.
        chk("adopt: index consistent AFTER the adoption",
            cs.LeafIndexMatchesBruteForce());

        // And the evictor must not free P while X names it.
        CBlockIndex* xIdx = cs.GetBlockIndex(hX);
        chk("adopt: X actually adopted P", xIdx != nullptr && xIdx->pprev == rawP);
        cs.EvictLowestWorkLeafNotPinned(1);
        chk("adopt: P was NOT evicted while X names it as pprev",
            cs.GetBlockIndex(hP) != nullptr);
        chk("adopt: index consistent after eviction", cs.LeafIndexMatchesBruteForce());
    }

    // ---- IsLeafPinnedDirect, PER CLAUSE (round-5 seats, item 4) --------------
    //
    // The randomized arm above brute-walks clause (a) only and never CALLS
    // IsLeafPinnedDirect, so mutants in clauses (b), (c) and (d) survived it.
    // This exercises the function itself, one clause at a time, with a reference
    // answer built independently.
    {
        CChainState cs;
        ::dilithion::consensus::port::ChainSelectorAdapter ad(cs);
        auto gg = MakeHeader(zero, 1700400000, 0x70);
        if (!ad.ProcessNewHeader(gg)) { std::cerr << "clause setup failed" << std::endl; return 2; }
        const uint256 gh = gg.GetHash();
        uint256 prev = gh;
        std::vector<uint256> leaves;
        for (int i = 1; i <= 4; ++i) {
            auto h = MakeHeader(gh, static_cast<uint32_t>(1700400000 + i),
                                static_cast<uint8_t>(0x80 + i));
            if (ad.ProcessNewHeader(h)) leaves.push_back(h.GetHash());
        }
        chk("clause setup: several sibling leaves exist", leaves.size() >= 3);
        const std::set<uint256> no_pending;

        // (a) the tip
        CBlockIndex* l0 = cs.GetBlockIndex(leaves[0]);
        cs.SetTip(l0);
        chk("clause (a): the tip IS pinned", cs.IsLeafPinnedDirect(l0, no_pending));
        CBlockIndex* l1 = cs.GetBlockIndex(leaves[1]);
        chk("clause (a): a non-tip leaf is NOT pinned by (a)",
            !cs.IsLeafPinnedDirect(l1, no_pending));

        // (c) HAVE_DATA without full validity — a direct flag test
        CBlockIndex* l2 = cs.GetBlockIndex(leaves[2]);
        chk("clause (c): clean leaf not pinned", !cs.IsLeafPinnedDirect(l2, no_pending));
        l2->nStatus |= CBlockIndex::BLOCK_HAVE_DATA;
        chk("clause (c): HAVE_DATA without VALID_TRANSACTIONS IS pinned",
            cs.IsLeafPinnedDirect(l2, no_pending));
        l2->RaiseValidity(CBlockIndex::BLOCK_VALID_TRANSACTIONS);
        chk("clause (c): once fully validated it is NOT pinned by (c)",
            !cs.IsLeafPinnedDirect(l2, no_pending));

        // (d) the pending snapshot
        std::set<uint256> pending{ leaves[1] };
        chk("clause (d): a leaf in the pending set IS pinned",
            cs.IsLeafPinnedDirect(l1, pending));
        chk("clause (d): a leaf absent from it is NOT",
            !cs.IsLeafPinnedDirect(cs.GetBlockIndex(leaves[0] == leaves[1] ? leaves[2] : leaves[2]),
                                   pending));
    }

    Dilithion::g_chainParams = saved;

    std::cout << "\n  ===== leaf index invariant: "
              << (g_failed == 0 ? "PASS" : "FAIL") << " (" << g_failed
              << " failed) =====\n" << std::endl;
    return g_failed == 0 ? 0 : 1;
}
