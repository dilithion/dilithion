// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// regtest_cap_rejection_tests — a linear chain longer than the mapBlockIndex cap
// must be accepted in full.
//
// ⚠️ READ THE TWO SIDES BEFORE READING THE NARRATION BELOW. This file documents a
// defect that exists on `main` and is FIXED on this branch, so the same source
// behaves differently depending on where you build it:
//
//   on origin/main          EXIT 1 — the header at height 1000 is REJECTED
//                           (index size 1000, cap 1000). The narration below
//                           describes THIS.
//   on this branch          EXIT 0 — 1002 headers accepted, an advisory NOTE on
//                           stderr, nothing rejected. The cap no longer gates
//                           chain progress.
//
// The assertion is written as the PROPERTY a node must have, not as the bug, so
// it is red where the bug is and green where it is not — and it stays meaningful
// as a regression guard rather than needing to be inverted when the fix lands.
// Everything below describing a rejection is describing main.
//
// THE FINDING. Eviction is the only path that frees a CBlockIndex at runtime,
// and it fires on one purely count-based condition
// (chain_selector_impl.cpp: size() >= nMapBlockIndexCap, while adding a NEW
// header). Its victim search deliberately SKIPS every entry on the active chain
// (chain.cpp:226-231, walking pindexTip -> genesis). So when the index is at cap
// and the active chain accounts for ALL of it, there is no victim:
// EvictLowestWorkNotOnBestChain() returns false and the caller REJECTS the new
// header.
//
// On the production networks that state is unreachable -- the cap is 500000
// against a chain of ~24000, so it takes hundreds of thousands of low-work
// spam headers to approach it. On REGTEST the cap is 1000
// (chainparams.cpp Regtest()), and regtest chains routinely pass 1000 blocks.
// Past that height ordinary generation walks into the fail-closed branch whose
// own comment calls it "unreachable at production sizes ... a safety net for
// misconfigured caps".
//
// This test builds that state through the REAL path -- ChainSelectorAdapter::
// ProcessNewHeader, the same entry point the node uses -- rather than calling
// the evictor directly, because the claim under test is about what a node does
// at height 1000, not about the evictor in isolation.

#include <consensus/port/chain_selector_impl.h>
#include <consensus/chain.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

namespace {

CBlockHeader MakeHeader(const uint256& parent_hash, uint32_t nTime)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;
    h.hashPrevBlock = parent_hash;
    std::memset(h.hashMerkleRoot.data, 0, 32);
    h.nTime = nTime;
    h.nBits = 0x1d00ffff;
    h.nNonce = 0;
    std::memset(h.vdfProofHash.data, 0, 32);
    // Distinct vdfOutput per height keeps every hash distinct.
    for (int i = 0; i < 4; ++i) {
        h.vdfOutput.data[i] = static_cast<uint8_t>((nTime >> (8 * i)) & 0xff);
    }
    for (int i = 4; i < 32; ++i) h.vdfOutput.data[i] = 0;
    return h;
}

int g_failed = 0;
void chk(const std::string& what, bool ok)
{
    std::cout << (ok ? "   PASS  " : "   FAIL  ") << what << std::endl;
    if (!ok) ++g_failed;
}

// Build a LINEAR chain of `count` headers through ProcessNewHeader, keeping the
// tip set so every entry is on the active chain. Returns the last hash.
uint256 BuildLinearChain(CChainState& chainstate,
                         ::dilithion::consensus::port::ChainSelectorAdapter& adapter,
                         int count, bool& all_accepted, int& first_rejected_height)
{
    uint256 parent;
    std::memset(parent.data, 0, 32);
    uint256 last = parent;
    all_accepted = true;
    first_rejected_height = -1;

    for (int h = 0; h < count; ++h) {
        CBlockHeader hdr = MakeHeader(h == 0 ? parent : last,
                                      static_cast<uint32_t>(1700000000 + h));
        if (!adapter.ProcessNewHeader(hdr)) {
            all_accepted = false;
            if (first_rejected_height < 0) first_rejected_height = h;
            break;
        }
        last = hdr.GetHash();
        // Keep the active chain equal to everything we have added, which is
        // what a synced node looks like and what makes eviction victimless.
        CBlockIndex* pnew = chainstate.GetBlockIndex(last);
        if (pnew) chainstate.SetTip(pnew);
    }
    return last;
}

} // namespace

int main()
{
    std::cout << "\n=== regtest mapBlockIndex cap: valid headers rejected at ordinary height ===\n"
              << std::endl;

    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::ChainParams params = Dilithion::ChainParams::Regtest();
    Dilithion::g_chainParams = &params;

    const int cap = params.nMapBlockIndexCap;
    std::cout << "  regtest nMapBlockIndexCap = " << cap << std::endl;
    chk("the regtest cap is a small positive number", cap > 0 && cap < 100000);

    CChainState chainstate;
    ::dilithion::consensus::port::ChainSelectorAdapter adapter(chainstate);

    bool all_accepted = false;
    int first_rejected = -1;
    // Ask for cap + 2 so the rejection, if it happens, is inside the range.
    BuildLinearChain(chainstate, adapter, cap + 2, all_accepted, first_rejected);

    std::cout << "  headers accepted before the first rejection: "
              << (first_rejected < 0 ? cap + 2 : first_rejected) << std::endl;
    std::cout << "  index size at that point                   : "
              << chainstate.GetBlockIndexSize() << std::endl;

    // THE ASSERTION THIS FILE EXISTS FOR.
    //
    // A node whose active chain has simply grown past the cap must not start
    // refusing valid headers. If this fails, the cap is behaving as a hard
    // ceiling on chain height rather than as a bound on non-chain entries.
    chk("a linear chain longer than the cap is accepted in full "
        "(no valid header is rejected)", all_accepted);

    if (!all_accepted) {
        std::cout << "\n  REPRODUCED: header at height " << first_rejected
                  << " was REJECTED with an index size of "
                  << chainstate.GetBlockIndexSize() << " and a cap of " << cap << "."
                  << std::endl;
        std::cout << "  Every entry is on the active chain, so "
                  << "EvictLowestWorkNotOnBestChain() finds no victim, returns false,"
                  << std::endl;
        std::cout << "  and ProcessNewHeader fails closed. No attacker, no spam -- "
                  << "just a chain longer than the cap." << std::endl;
    }

    Dilithion::g_chainParams = saved;

    std::cout << "\n  ===== regtest cap rejection: "
              << (g_failed == 0 ? "PASS" : "FAIL") << " (" << g_failed
              << " failed) =====\n" << std::endl;
    return g_failed == 0 ? 0 : 1;
}
