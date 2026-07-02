// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// ION VDF-dispatch functional test (red-team PR #142 follow-up).
//
// The scaffold set ION's params to a VDF chain but left the identity-keyed
// IsDilV() dispatch sites un-widened, so ION was routed into RandomX/PoW code
// paths (cannot sync — CRITICAL — and a modulo-by-zero — HIGH). The fix
// introduces ChainParams::IsVdfChain() (== IsDilV() || IsIon()) and sweeps the
// VDF-CLASS sites, while giving ION its OWN arm at the identity sites.
//
// This test proves the CRITICAL/HIGH fixes WITHOUT a slow full sync:
//   (a) the proof-checker factory predicate selects the VDF proof checker for
//       ION (not RandomX), and the VDF checker actually accepts an ION-genesis
//       header while rejecting a legacy (v1) header;
//   (b) the genesis seeded for ION equals CreateIonGenesisBlock()'s hash — a
//       VDF block distinct from the legacy CreateGenesisBlock() fallback;
//   (c) GetNextWorkRequired() under ION returns the fixed genesisNBits and does
//       NOT fall through to the periodic-retarget modulo-by-zero
//       (difficultyAdjustment == 0 on ION).
//
// It also re-asserts the BYTE-NEUTRAL invariant: IsVdfChain() has the exact
// truth table {DIL:false, Testnet:false, DilV:true, ION:true, Regtest:false},
// so replacing IsDilV() with IsVdfChain() at a VDF-CLASS site changes behavior
// for ION only — DIL/DilV are unchanged.

#include <core/chainparams.h>
#include <node/genesis.h>
#include <node/block_index.h>
#include <consensus/pow.h>
#include <primitives/block.h>
#include <net/port/header_proof_checkers.h>

#include <cassert>
#include <iostream>
#include <memory>

using namespace Dilithion;

namespace {

// Set a chain's params as the global, keeping ownership in a static so the
// pointer stays valid for the duration of each test.
void SetChain(const ChainParams& p) {
    static ChainParams s_holder;
    s_holder = p;
    g_chainParams = &s_holder;
}

// ---------------------------------------------------------------------------
// BYTE-NEUTRALITY: IsVdfChain() truth table.
// ---------------------------------------------------------------------------
void test_isvdfchain_truth_table() {
    std::cout << "  test_isvdfchain_truth_table..." << std::flush;

    ChainParams dil     = ChainParams::Mainnet();
    ChainParams testnet = ChainParams::Testnet();
    ChainParams dilv    = ChainParams::DilV();
    ChainParams ion     = ChainParams::Ion();
    ChainParams regtest = ChainParams::Regtest();

    // The whole sweep's safety rests on this: DIL/DilV keep the SAME truth
    // value they had under IsDilV(), only ION newly enters the VDF arm.
    assert(dil.IsVdfChain()     == false);   // was IsDilV()==false → unchanged
    assert(testnet.IsVdfChain() == false);   // was IsDilV()==false → unchanged
    assert(dilv.IsVdfChain()    == true);    // was IsDilV()==true  → unchanged
    assert(ion.IsVdfChain()     == true);    // was IsDilV()==false → ION newly included
    assert(regtest.IsVdfChain() == false);   // regtest keeps its own explicit arms

    // Byte-neutral identity: for every existing chain, IsVdfChain() == IsDilV().
    assert(dil.IsVdfChain()     == dil.IsDilV());
    assert(testnet.IsVdfChain() == testnet.IsDilV());
    assert(dilv.IsVdfChain()    == dilv.IsDilV());
    assert(regtest.IsVdfChain() == regtest.IsDilV());
    // ...and ONLY ION diverges (the intended new inclusion).
    assert(ion.IsVdfChain() != ion.IsDilV());

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// (a) CRITICAL-1 — ION gets the VDF proof checker, not RandomX.
// ---------------------------------------------------------------------------
void test_ion_selects_vdf_proof_checker() {
    std::cout << "  test_ion_selects_vdf_proof_checker..." << std::flush;

    SetChain(ChainParams::Ion());

    // This is the exact predicate the HeadersManager proof-checker factory now
    // uses (headers_manager.cpp:99). Under ION it is TRUE → the VDF checker is
    // installed; under the old IsDilV() gate it was FALSE → RandomX checker.
    assert(g_chainParams->IsVdfChain());

    // Behavioral proof the VDF checker is the CORRECT one for ION headers:
    // build the ION genesis (a real VDF header) and confirm the VDF checker
    // accepts it while the RandomX checker's contract does not apply.
    ::dilithion::net::port::VDFHeaderProofChecker vdf;
    ::dilithion::net::port::RandomXHeaderProofChecker randomx;

    CBlock ionGenesis = Genesis::CreateIonGenesisBlock();
    CBlockHeader ionHeader = static_cast<CBlockHeader>(ionGenesis);

    // ION genesis is a VDF block (nVersion >= VDF_VERSION) with populated VDF
    // fields → VDF checker accepts it.
    assert(ionHeader.IsVDFBlock());
    assert(vdf.CheckHeaderProof(ionHeader));

    // A non-VDF (legacy v1) header is rejected by the VDF checker — i.e. the
    // checker is genuinely VDF-specific, so installing it for a VDF chain is
    // load-bearing (installing RandomX instead would mis-validate ION headers).
    CBlockHeader legacyHeader;
    legacyHeader.nVersion = 1;                 // RandomX-era block
    assert(!legacyHeader.IsVDFBlock());
    assert(!vdf.CheckHeaderProof(legacyHeader));

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// (b) CRITICAL-2 — ION seeds its OWN genesis (CreateIonGenesisBlock), whose
//     live-computed hash is self-consistent and distinct from the legacy
//     CreateGenesisBlock() fallback.
// ---------------------------------------------------------------------------
void test_ion_seeds_own_genesis() {
    std::cout << "  test_ion_seeds_own_genesis..." << std::flush;

    SetChain(ChainParams::Ion());

    // The genesis the headers_manager identity arm now seeds for ION.
    CBlock ionGenesis = Genesis::CreateIonGenesisBlock();
    uint256 ionGenesisHash = ionGenesis.GetHash();   // VDF → SHA3, no RandomX

    // GetGenesisHash() is the live authoritative genesis hash. Under ION it must
    // resolve to the ION genesis (proving the seeded genesis matches the real
    // one → block 1's pprev lookup finds it → sync past height 1).
    uint256 authoritative = Genesis::GetGenesisHash();
    assert(ionGenesisHash == authoritative);

    // ION genesis is a VDF block, NOT the legacy v1 block the old else-branch
    // (CreateGenesisBlock) would have seeded. We compare the structural marker
    // (nVersion) rather than hashing the v1 block, so this stays RandomX-free.
    CBlock legacyGenesis = Genesis::CreateGenesisBlock();
    assert(ionGenesis.nVersion >= CBlockHeader::VDF_VERSION);
    assert(legacyGenesis.nVersion < CBlockHeader::VDF_VERSION);
    assert(ionGenesis.nVersion != legacyGenesis.nVersion);

    // And IsGenesisBlock() (the consensus-facing predicate) recognizes the ION
    // genesis under ION params.
    assert(Genesis::IsGenesisBlock(ionGenesis));

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// (c) HIGH-1 — GetNextWorkRequired() under ION returns the fixed genesisNBits
//     and does NOT reach the periodic-retarget modulo-by-zero.
// ---------------------------------------------------------------------------
void test_ion_getnextwork_fixed_nbits_no_div_by_zero() {
    std::cout << "  test_ion_getnextwork_fixed_nbits_no_div_by_zero..." << std::flush;

    SetChain(ChainParams::Ion());

    // Document the latent coupling the fix protects against: ION's retarget
    // interval is 0, so falling through to `newBlockHeight % nInterval` (the
    // legacy branch) would be a modulo-by-zero. The fixed-nBits early return
    // must fire BEFORE that.
    assert(g_chainParams->difficultyAdjustment == 0);

    // Build a minimal but valid pindexLast (non-null, above the 0x10000 sanity
    // floor, real nHeight). Under ION the VDF early-return at pow.cpp fires
    // before pindexLast is dereferenced, so this returns fixed nBits without
    // touching the retarget machinery — no div-by-zero.
    CBlockIndex tip;
    tip.nHeight = 0;
    tip.pprev = nullptr;
    tip.header = static_cast<CBlockHeader>(Genesis::CreateIonGenesisBlock());
    tip.nBits = g_chainParams->genesisNBits;

    uint32_t nBits = GetNextWorkRequired(&tip, /*nBlockTime=*/0);
    assert(nBits == g_chainParams->genesisNBits);

    std::cout << " OK\n";
}

// ---------------------------------------------------------------------------
// Negative control: DIL (RandomX/PoW) must NOT take the VDF arms — proves the
// sweep didn't accidentally broaden the VDF class to a PoW chain.
// ---------------------------------------------------------------------------
void test_dil_still_not_vdf() {
    std::cout << "  test_dil_still_not_vdf..." << std::flush;

    SetChain(ChainParams::Mainnet());
    assert(!g_chainParams->IsVdfChain());   // DIL keeps RandomX proof checker / retarget path

    SetChain(ChainParams::DilV());
    assert(g_chainParams->IsVdfChain());    // DilV unchanged: still VDF

    std::cout << " OK\n";
}

}  // namespace

int main() {
    std::cout << "\n=== ION VDF-dispatch functional test (PR #142 red-team fix) ===\n"
              << std::endl;
    try {
        test_isvdfchain_truth_table();
        test_ion_selects_vdf_proof_checker();
        test_ion_seeds_own_genesis();
        test_ion_getnextwork_fixed_nbits_no_div_by_zero();
        test_dil_still_not_vdf();
        std::cout << "\n=== All ION VDF-dispatch tests passed (5/5) ===\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTest FAILED: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\nTest FAILED (unknown exception)" << std::endl;
        return 1;
    }
}
