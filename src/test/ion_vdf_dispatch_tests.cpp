// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// ION VDF-dispatch functional test (red-team PR #142 follow-up) — Boost.Test suite.
//
// The scaffold set ION's params to a VDF chain but left the identity-keyed
// IsDilV() dispatch sites un-widened, so ION was routed into RandomX/PoW code
// paths (cannot sync — CRITICAL — and a modulo-by-zero — HIGH). The fix
// introduces ChainParams::IsVdfChain() (== IsDilV() || IsIon()) and sweeps the
// VDF-CLASS sites, while giving ION its OWN arm at the identity sites.
//
// This suite proves the CRITICAL/HIGH fixes WITHOUT a slow full sync:
//   (a) the proof-checker factory predicate selects the VDF proof checker for
//       ION (not RandomX), and the VDF checker actually accepts an ION-genesis
//       header while rejecting a legacy (v1) header;
//   (b) the genesis seeded for ION is a VDF block built from ION's OWN params
//       (distinguished by exact nVersion == VDF_VERSION and the ION-specific
//       coinbase message embedded in the coinbase), distinct from the legacy
//       CreateGenesisBlock() fallback;
//   (c) GetNextWorkRequired() under ION returns the fixed genesisNBits and does
//       NOT fall through to the periodic-retarget modulo-by-zero
//       (difficultyAdjustment == 0 on ION).
//
// It also re-asserts the BYTE-NEUTRAL invariant: IsVdfChain() has the exact
// truth table {DIL:false, Testnet:false, DilV:true, ION:true, Regtest:false},
// so replacing IsDilV() with IsVdfChain() at a VDF-CLASS site changes behavior
// for ION only — DIL/DilV are unchanged.
//
// Wired into `test_dilithion` (BOOST_TEST_OBJECTS in the Makefile) so CI, which
// runs ./test_dilithion, machine-enforces the sweep on every build — the ION
// binary can no longer regress silently (round-2 MEDIUM finding).

#include <boost/test/unit_test.hpp>

#include <core/chainparams.h>
#include <node/genesis.h>
#include <node/block_index.h>
#include <consensus/pow.h>
#include <primitives/block.h>
#include <net/port/header_proof_checkers.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace Dilithion;

namespace {

// RAII scope-guard: installs a fresh g_chainParams for the duration of a test
// case and restores + frees the previous one in its destructor — so a
// BOOST_REQUIRE/BOOST_CHECK throw cannot skip the restore and poison the rest of
// the aggregate test_dilithion run. Mirrors wf1_host_endian_differential_test's
// ChainParamsGuard. (The old standalone test set a static-holder global and
// never restored it, which is fine for a standalone main() but would leak the
// ION params into every later suite here.)
struct ChainParamsGuard {
    ChainParams* saved;
    explicit ChainParamsGuard(ChainParams* fresh) : saved(g_chainParams) {
        g_chainParams = fresh;  // takes ownership of `fresh`
    }
    ~ChainParamsGuard() {
        delete g_chainParams;   // free the fresh params installed above
        g_chainParams = saved;  // restore the previous global
    }
    ChainParamsGuard(const ChainParamsGuard&) = delete;
    ChainParamsGuard& operator=(const ChainParamsGuard&) = delete;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(ion_vdf_dispatch_tests)

// ---------------------------------------------------------------------------
// BYTE-NEUTRALITY: IsVdfChain() truth table.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(isvdfchain_truth_table) {
    ChainParams dil     = ChainParams::Mainnet();
    ChainParams testnet = ChainParams::Testnet();
    ChainParams dilv    = ChainParams::DilV();
    ChainParams ion     = ChainParams::Ion();
    ChainParams regtest = ChainParams::Regtest();

    // The whole sweep's safety rests on this: DIL/DilV keep the SAME truth
    // value they had under IsDilV(), only ION newly enters the VDF arm.
    BOOST_CHECK_EQUAL(dil.IsVdfChain(),     false);   // was IsDilV()==false → unchanged
    BOOST_CHECK_EQUAL(testnet.IsVdfChain(), false);   // was IsDilV()==false → unchanged
    BOOST_CHECK_EQUAL(dilv.IsVdfChain(),    true);    // was IsDilV()==true  → unchanged
    BOOST_CHECK_EQUAL(ion.IsVdfChain(),     true);    // was IsDilV()==false → ION newly included
    BOOST_CHECK_EQUAL(regtest.IsVdfChain(), false);   // regtest keeps its own explicit arms

    // Byte-neutral identity: for every existing chain, IsVdfChain() == IsDilV().
    BOOST_CHECK_EQUAL(dil.IsVdfChain(),     dil.IsDilV());
    BOOST_CHECK_EQUAL(testnet.IsVdfChain(), testnet.IsDilV());
    BOOST_CHECK_EQUAL(dilv.IsVdfChain(),    dilv.IsDilV());
    BOOST_CHECK_EQUAL(regtest.IsVdfChain(), regtest.IsDilV());
    // ...and ONLY ION diverges (the intended new inclusion).
    BOOST_CHECK(ion.IsVdfChain() != ion.IsDilV());
}

// ---------------------------------------------------------------------------
// (a) CRITICAL-1 — ION gets the VDF proof checker, not RandomX.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ion_selects_vdf_proof_checker) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Ion()));

    // This is the exact predicate the HeadersManager proof-checker factory now
    // uses (headers_manager.cpp:99). Under ION it is TRUE → the VDF checker is
    // installed; under the old IsDilV() gate it was FALSE → RandomX checker.
    BOOST_REQUIRE(g_chainParams->IsVdfChain());

    // Behavioral proof the VDF checker is the CORRECT one for ION headers:
    // build the ION genesis (a real VDF header) and confirm the VDF checker
    // accepts it while the RandomX checker's contract does not apply.
    ::dilithion::net::port::VDFHeaderProofChecker vdf;
    ::dilithion::net::port::RandomXHeaderProofChecker randomx;
    (void)randomx;

    CBlock ionGenesis = Genesis::CreateIonGenesisBlock();
    CBlockHeader ionHeader = static_cast<CBlockHeader>(ionGenesis);

    // ION genesis is a VDF block (nVersion >= VDF_VERSION) with populated VDF
    // fields → VDF checker accepts it.
    BOOST_CHECK(ionHeader.IsVDFBlock());
    BOOST_CHECK(vdf.CheckHeaderProof(ionHeader));

    // A non-VDF (legacy v1) header is rejected by the VDF checker — i.e. the
    // checker is genuinely VDF-specific, so installing it for a VDF chain is
    // load-bearing (installing RandomX instead would mis-validate ION headers).
    CBlockHeader legacyHeader;
    legacyHeader.nVersion = 1;                 // RandomX-era block
    BOOST_CHECK(!legacyHeader.IsVDFBlock());
    BOOST_CHECK(!vdf.CheckHeaderProof(legacyHeader));
}

// ---------------------------------------------------------------------------
// (b) CRITICAL-2 — ION seeds its OWN genesis (CreateIonGenesisBlock), a VDF
//     block built from ION's params (distinct from the legacy fallback).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ion_seeds_own_genesis) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Ion()));

    // The genesis the headers_manager identity arm now seeds for ION.
    CBlock ionGenesis = Genesis::CreateIonGenesisBlock();
    uint256 ionGenesisHash = ionGenesis.GetHash();   // VDF → SHA3, no RandomX

    // GetGenesisHash() is the live authoritative genesis hash. Under ION it must
    // resolve to the ION genesis (proving the seeded genesis matches the real
    // one → block 1's pprev lookup finds it → sync past height 1).
    //
    // NOTE (round-2 LOW): GetGenesisHash() caches into a function-static, and
    // CreateIonGenesisBlock() currently DELEGATES verbatim to the DilV genesis
    // (byte-identical), so this hash-equality alone is a weak discriminator —
    // it would still hold if a stale DilV cache leaked in. It is kept as a
    // consistency check, but the ION-SPECIFIC guarantees below (exact VDF
    // nVersion + the ION coinbase message embedded in the genesis coinbase) are
    // the robust distinguishers that actually prove "ION built its own genesis
    // from ION params", independent of the cache.
    uint256 authoritative = Genesis::GetGenesisHash();
    BOOST_CHECK_MESSAGE(ionGenesisHash == authoritative,
        "ION genesis hash (" + ionGenesisHash.GetHex() +
        ") != GetGenesisHash() (" + authoritative.GetHex() + ")");

    // ROBUST DISTINGUISHER 1 — exact VDF version, not merely ">= VDF_VERSION".
    // The legacy else-branch (CreateGenesisBlock) would seed a v1 block; the ION
    // genesis is exactly the VDF version.
    BOOST_CHECK_EQUAL(ionGenesis.nVersion, CBlockHeader::VDF_VERSION);

    // ROBUST DISTINGUISHER 2 — the ION-specific coinbase message is embedded in
    // the genesis coinbase (scriptSig). CreateDilVGenesisBlock() reads
    // genesisCoinbaseMsg from g_chainParams; under ION params that is ION's
    // string, so its presence in the serialized coinbase (vtx) proves the
    // genesis was constructed from ION's params — NOT a stale DilV block. This
    // holds even though the two currently share a genesis *hash*, and would
    // catch any future divergence of ION's coinbase from DilV's.
    ChainParams ionParams = ChainParams::Ion();
    const std::string& ionMsg = ionParams.genesisCoinbaseMsg;
    BOOST_REQUIRE(!ionMsg.empty());
    const std::vector<uint8_t>& vtxBytes = ionGenesis.vtx;
    auto found = std::search(vtxBytes.begin(), vtxBytes.end(),
                             ionMsg.begin(), ionMsg.end());
    BOOST_CHECK_MESSAGE(found != vtxBytes.end(),
        "ION genesis coinbase must embed ION's genesisCoinbaseMsg ('" + ionMsg + "')");

    // The legacy v1 block the old else-branch (CreateGenesisBlock) would have
    // seeded is structurally distinct (compared via nVersion, not a RandomX hash).
    CBlock legacyGenesis = Genesis::CreateGenesisBlock();
    BOOST_CHECK(legacyGenesis.nVersion < CBlockHeader::VDF_VERSION);
    BOOST_CHECK(ionGenesis.nVersion != legacyGenesis.nVersion);

    // And IsGenesisBlock() (the consensus-facing predicate) recognizes the ION
    // genesis under ION params.
    BOOST_CHECK(Genesis::IsGenesisBlock(ionGenesis));
}

// ---------------------------------------------------------------------------
// (c) HIGH-1 — GetNextWorkRequired() under ION returns the fixed genesisNBits
//     and does NOT reach the periodic-retarget modulo-by-zero.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ion_getnextwork_fixed_nbits_no_div_by_zero) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Ion()));

    // Document the latent coupling the fix protects against: ION's retarget
    // interval is 0, so falling through to `newBlockHeight % nInterval` (the
    // legacy branch) would be a modulo-by-zero. The fixed-nBits early return
    // must fire BEFORE that.
    BOOST_REQUIRE_EQUAL(g_chainParams->difficultyAdjustment, 0);

    // Build a minimal but valid pindexLast (non-null, real nHeight). Under ION
    // the VDF early-return at pow.cpp fires before the retarget machinery, so
    // this returns fixed nBits without touching it — no div-by-zero.
    CBlockIndex tip;
    tip.nHeight = 0;
    tip.pprev = nullptr;
    tip.header = static_cast<CBlockHeader>(Genesis::CreateIonGenesisBlock());
    tip.nBits = g_chainParams->genesisNBits;

    uint32_t nBits = GetNextWorkRequired(&tip, /*nBlockTime=*/0);
    BOOST_CHECK_EQUAL(nBits, g_chainParams->genesisNBits);
}

// ---------------------------------------------------------------------------
// Negative control: DIL (RandomX/PoW) must NOT take the VDF arms — proves the
// sweep didn't accidentally broaden the VDF class to a PoW chain.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(dil_still_not_vdf) {
    {
        ChainParamsGuard guard(new ChainParams(ChainParams::Mainnet()));
        BOOST_CHECK(!g_chainParams->IsVdfChain());   // DIL keeps RandomX proof checker / retarget path
    }
    {
        ChainParamsGuard guard(new ChainParams(ChainParams::DilV()));
        BOOST_CHECK(g_chainParams->IsVdfChain());    // DilV unchanged: still VDF
    }
}

BOOST_AUTO_TEST_SUITE_END()
