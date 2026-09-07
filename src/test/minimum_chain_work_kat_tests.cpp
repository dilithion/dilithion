// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 (2026-09-07): known-answer tests pinning nMinimumChainWork.
//
// A KAT pins what a constant IS. It does not, and must not, assert who chose
// it or that anyone ratified it -- the values here are marked PROPOSED in
// chainparams.cpp and carry no decision-row citation because no decision row
// exists yet.
//
// ⚠️ WHAT THIS SUITE DOES *NOT* PROVE.
// It does not prove the gate works, because as of this commit the gate is not
// wired: CHeadersManager::nMinimumChainWork (headers_manager.cpp:91) is
// assigned and never read, and InitializeDoSProtectedSync /
// ProcessHeadersWithDoSProtection have zero call sites, so HeadersSyncState is
// never constructed in production and header processing falls through to the
// legacy ProcessHeaders, which applies no chain-work threshold. A
// reject/accept test written today could only call HeadersSyncState directly
// -- which is exactly the "correct check that nothing reaches" defect LP-10
// exists to close. That test belongs with the wiring, and must assert the
// WIRING. This suite pins the constants and the UNITS so that when the wiring
// lands, the numbers it enforces are the measured ones.

#include <consensus/chain_work.h>
#include <core/chainparams.h>
#include <primitives/block.h>

#include <cassert>
#include <iostream>
#include <string>

namespace {

const std::string DIL_EXPECT =
    "000000000000000000000000000000000000000000028c85dd20c10003e46900";
const std::string DILV_EXPECT =
    "00000000000000000000000000000000000000000105ba05ba05ba05b9000000";

// Fails the process with a message rather than a bare assert, so a mismatch
// prints the two values -- a consensus constant that silently differs by one
// nibble is the worst possible failure mode to debug from "assertion failed".
void RequireEqual(const char* what, const uint256& got, const uint256& want)
{
    if (!(got == want)) {
        std::cerr << "\n  FAIL " << what << "\n    got  " << got.GetHex()
                  << "\n    want " << want.GetHex() << "\n";
        std::abort();
    }
}

void test_hex_literals_round_trip()
{
    std::cout << "  test_hex_literals_round_trip..." << std::flush;
    // Guards the literals themselves: if uint256S/GetHex ever disagree, every
    // other assertion in this file would be comparing a value against itself.
    RequireEqual("DIL round-trip",  uint256S(uint256S(DIL_EXPECT).GetHex()),  uint256S(DIL_EXPECT));
    RequireEqual("DilV round-trip", uint256S(uint256S(DILV_EXPECT).GetHex()), uint256S(DILV_EXPECT));
    assert(uint256S(DIL_EXPECT).GetHex()  == DIL_EXPECT);
    assert(uint256S(DILV_EXPECT).GetHex() == DILV_EXPECT);
    assert(!uint256S(DIL_EXPECT).IsNull());
    assert(!uint256S(DILV_EXPECT).IsNull());
    std::cout << " OK" << std::endl;
}

void test_work_units_are_this_ports_units_not_bitcoin_cores()
{
    std::cout << "  test_work_units_are_this_ports_units_not_bitcoin_cores..." << std::flush;
    using namespace dilithion::consensus;

    // This port computes 2^(320-8*size)/mantissa; Bitcoin Core computes
    // 2^(280-8*size)/mantissa -- our unit is 2^40 times Core's for the same
    // nBits. Pinning two exact per-block values makes any change to the
    // formula, or any value lifted from a Core chainparams file, fail here
    // rather than silently mis-gate IBD by a factor of ~10^12.
    RequireEqual("work(0x1d00ffff)",  // DilV, every block
                 ComputeChainWork(0x1d00ffff),
                 uint256S("0000000000000000000000000000000000000000000001000100010001000000"));
    RequireEqual("work(0x1d1ea6b8)",  // DIL at its checkpoint height
                 ComputeChainWork(0x1d1ea6b8),
                 uint256S("0000000000000000000000000000000000000000000000085a1e6258a9000000"));
    std::cout << " OK" << std::endl;
}

void test_dilv_constant_is_re_derived_not_just_restated()
{
    std::cout << "  test_dilv_constant_is_re_derived_not_just_restated..." << std::flush;
    using namespace dilithion::consensus;

    // DilV nBits was measured as 0x1d00ffff on ALL 255,028 canonical blocks --
    // difficulty has never retargeted -- so the work at height H is exactly
    // (H+1) single-block contributions. Re-derive the checkpoint constant by
    // summing, rather than restating the literal. If the constant is ever
    // edited to a value that is not the measured chain work at height 67000,
    // this fails even though the literal above would still "match".
    uint256 sum;
    for (int h = 0; h <= 67000; ++h)
        sum = AddChainWork(sum, ComputeChainWork(0x1d00ffff));
    RequireEqual("DilV re-derived work at height 67000", sum, uint256S(DILV_EXPECT));
    std::cout << " OK" << std::endl;
}

void test_chainparams_carry_the_measured_values()
{
    std::cout << "  test_chainparams_carry_the_measured_values..." << std::flush;
    using Dilithion::ChainParams;

    RequireEqual("DIL mainnet nMinimumChainWork",
                 ChainParams::Mainnet().nMinimumChainWork, uint256S(DIL_EXPECT));
    RequireEqual("DilV nMinimumChainWork",
                 ChainParams::DilV().nMinimumChainWork, uint256S(DILV_EXPECT));

    // Testnet and regtest stay zero deliberately: there is no measurement for
    // either, testnet is reset and relaunched, and regtest chains are a handful
    // of blocks. A non-zero value on either would lock honest nodes out.
    assert(ChainParams::Testnet().nMinimumChainWork.IsNull());
    assert(ChainParams::Regtest().nMinimumChainWork.IsNull());
    std::cout << " OK" << std::endl;
}

void test_thresholds_sit_below_measured_tip_work()
{
    std::cout << "  test_thresholds_sit_below_measured_tip_work..." << std::flush;
    using namespace dilithion::consensus;
    using Dilithion::ChainParams;

    // A threshold at or above the live tip work would reject the real chain and
    // brick IBD. These bounds are the tip chain work measured when the values
    // were derived (DIL height 94,221 over seed RPC; DilV height 255,027 from a
    // block-database walk), so the assertion is that each threshold is strictly
    // below the work its own chain had already accumulated.
    const uint256 dil_tip_work  = uint256S(
        "0000000000000000000000000000000000000000000382e20fa3c40eaa90d100");
    const uint256 dilv_tip_work = uint256S(
        "000000000000000000000000000000000000000003e437e437e437e434000000");

    assert(!ChainWorkGreaterOrEqual(ChainParams::Mainnet().nMinimumChainWork, dil_tip_work));
    assert(!ChainWorkGreaterOrEqual(ChainParams::DilV().nMinimumChainWork,    dilv_tip_work));

    // ...and strictly above zero, or the gate is a no-op even once wired.
    assert(ChainWorkGreaterOrEqual(ChainParams::Mainnet().nMinimumChainWork, uint256S("1")));
    assert(ChainWorkGreaterOrEqual(ChainParams::DilV().nMinimumChainWork,    uint256S("1")));
    std::cout << " OK" << std::endl;
}

} // namespace

int main()
{
    std::cout << "minimum_chain_work_kat_tests" << std::endl;
    test_hex_literals_round_trip();
    test_work_units_are_this_ports_units_not_bitcoin_cores();
    test_dilv_constant_is_re_derived_not_just_restated();
    test_chainparams_carry_the_measured_values();
    test_thresholds_sit_below_measured_tip_work();
    std::cout << "minimum_chain_work_kat_tests: ALL PASS" << std::endl;
    return 0;
}
