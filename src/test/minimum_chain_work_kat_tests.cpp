// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 (2026-09-07): known-answer tests pinning nMinimumChainWork.
//
// A KAT pins what a constant IS. It does not, and must not, assert who chose it
// or that anyone ratified it. The approval lives in decision row
// D-DIL-2026-09-07-2 (dilithion-strategy 00-context/DECISION_REGISTER.md) and is
// cited from chainparams.cpp; this suite deliberately asserts nothing about it.
// If the row were withdrawn tomorrow these assertions would all still be
// correct, because they are about arithmetic, not authority.
//
// ⚠️ WHAT THIS SUITE DOES *NOT* PROVE.
// It does not prove the gate works, because as of this commit the gate is not
// wired: CHeadersManager::nMinimumChainWork (headers_manager.cpp:91) is
// assigned and never read, and InitializeDoSProtectedSync /
// ProcessHeadersWithDoSProtection have zero call sites, so HeadersSyncState is
// never constructed in production. The LIVE header path is the node's
// SetHeadersHandler lambda -> QueueRawHeadersForProcessing (:3317) ->
// HeaderProcessorThread (:3350) -> QueueHeadersForValidation (:2514), and it
// applies no chain-work threshold either. (An earlier revision of this comment
// named ProcessHeaders as the live path. That was wrong: ProcessHeaders is
// itself near-dead, reachable only when the async validation thread fails to
// start.) A reject/accept test written today could only call HeadersSyncState
// directly -- which is exactly the "correct check that nothing reaches" defect
// LP-10 exists to close. That test belongs with the wiring, and must assert the
// WIRING.
//
// ⚠️ AND SEE chainparams.cpp: wiring is NOT a one-line change. These thresholds
// are ABSOLUTE sums from genesis, while HeadersSyncState zeroes its accumulator
// (headerssync.cpp:42-44) and starts from the LOCAL TIP. Comparing the two
// would stall header sync on any non-fresh node.
//
// This suite pins the constants and the UNITS so that when the wiring lands,
// the numbers it enforces are the measured ones.

#include "dil_nbits_census.h"

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

// Load-bearing boolean check. Deliberately NOT the standard library's
// assertion macro: this repo ships -DNDEBUG release builds (build-release.sh:62
// passes it, and Makefile's `CXXFLAGS ?=` means an environment CXXFLAGS
// replaces the default wholesale), under which every such assertion here would
// compile to nothing and the suite would print ALL PASS with its guards
// hollowed out -- including the single check
// standing between a silently-short census and a plausible wrong total.
// Found by red-team round 2; the same reasoning as util/assert.h's Invariant().
void RequireTrue(const char* what, bool ok)
{
    if (!ok) {
        std::cerr << "\n  FAIL " << what << std::endl;
        std::abort();
    }
}
#define REQUIRE(cond) RequireTrue(#cond, (cond))

void test_hex_literals_round_trip()
{
    std::cout << "  test_hex_literals_round_trip..." << std::flush;
    // Guards the literals themselves: if uint256S/GetHex ever disagree, every
    // other assertion in this file would be comparing a value against itself.
    RequireEqual("DIL round-trip",  uint256S(uint256S(DIL_EXPECT).GetHex()),  uint256S(DIL_EXPECT));
    RequireEqual("DilV round-trip", uint256S(uint256S(DILV_EXPECT).GetHex()), uint256S(DILV_EXPECT));
    REQUIRE(uint256S(DIL_EXPECT).GetHex()  == DIL_EXPECT);
    REQUIRE(uint256S(DILV_EXPECT).GetHex() == DILV_EXPECT);
    REQUIRE(!uint256S(DIL_EXPECT).IsNull());
    REQUIRE(!uint256S(DILV_EXPECT).IsNull());
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

    // A THIRD value, with the compact-encoding SIGN BIT SET (mantissa >=
    // 0x800000). 1,667 blocks in the DIL census carry such nBits -- the "EDA +
    // sign bit compounding" history fixed at compactEncodingFixHeight = 18500.
    // In Bitcoin's compact encoding those are negative targets; ComputeChainWork
    // here ignores the sign bit and divides by the full 24-bit mantissa, and so
    // does the node, so there is no mismatch today. The hazard is forward: if
    // anyone "ports ComputeChainWork closer to Core" by adding Core's
    // negative/overflow handling, the work of those 1,667 historical blocks
    // changes and nMinimumChainWork silently becomes wrong. The two values above
    // are both sign-CLEAR and would not fire. This one does, and names the cause.
    RequireEqual("work(0x1ef0c7e6) -- sign bit SET, 898 blocks in the census",
                 ComputeChainWork(0x1ef0c7e6),
                 uint256S("00000000000000000000000000000000000000000000000001102e5d3fd90000"));
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

void test_dil_constant_is_re_derived_from_the_committed_census()
{
    std::cout << "  test_dil_constant_is_re_derived_from_the_committed_census..." << std::flush;
    using namespace dilithion::consensus;
    using namespace dilithion::test;

    // Closes the provenance gap the red-team found: previously DIL was pinned
    // only literal-against-literal, which detects an EDIT but cannot detect an
    // ERROR. DIL retargets on roughly half its blocks, so unlike DilV there is
    // no closed form -- the per-block evidence has to be committed, and it is,
    // in dil_nbits_census.h (generated under a write gate from a seed dump
    // whose sha256 the header records).
    //
    // Chain work is a SUM, so aggregating equal nBits is exact. Guard the
    // coverage first: a census that silently covered fewer blocks would produce
    // a smaller, entirely plausible total.
    REQUIRE(DIL_CENSUS_TIP_HEIGHT == 54000);
    REQUIRE(DIL_CENSUS_TOTAL_BLOCKS == DIL_CENSUS_TIP_HEIGHT + 1);

    long long counted = 0;
    uint256 sum;
    for (size_t i = 0; i < DIL_NBITS_CENSUS_LEN; ++i) {
        const uint32_t nbits = DIL_NBITS_CENSUS[i].nBits;
        REQUIRE(nbits != 0);  // a zero mantissa saturates work to MAX, invisibly
        for (uint32_t n = 0; n < DIL_NBITS_CENSUS[i].count; ++n)
            sum = AddChainWork(sum, ComputeChainWork(nbits));
        counted += DIL_NBITS_CENSUS[i].count;
    }
    // The census must account for every block from genesis to the checkpoint,
    // or the sum is short in a way no comparison against itself would reveal.
    REQUIRE(counted == DIL_CENSUS_TOTAL_BLOCKS);

    RequireEqual("DIL re-derived work at height 54000", sum, uint256S(DIL_EXPECT));
    RequireEqual("DIL census sum vs chainparams",
                 sum, Dilithion::ChainParams::Mainnet().nMinimumChainWork);
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
    REQUIRE(ChainParams::Testnet().nMinimumChainWork.IsNull());
    REQUIRE(ChainParams::Regtest().nMinimumChainWork.IsNull());
    std::cout << " OK" << std::endl;
}

void test_thresholds_are_nonzero_and_dilv_margin_is_re_derived()
{
    std::cout << "  test_thresholds_are_nonzero_and_dilv_margin_is_re_derived..." << std::flush;
    using namespace dilithion::consensus;
    using Dilithion::ChainParams;

    // A threshold at or above the live tip work would reject the real chain and
    // brick IBD -- so this test asserted "threshold < tip work" against two
    // hardcoded tip literals.
    //
    // ⚠️ BOTH LITERALS ARE DELETED, and the assertion they backed is replaced,
    // because red-team round 2 was right that they were unverifiable -- and
    // looking at WHY, the assertion itself was hollow:
    //
    //   Chain work is a CUMULATIVE SUM over blocks, and every block contributes
    //   strictly positive work (ComputeChainWork returns 0 only for a mantissa
    //   the census gate now rejects). So work is STRICTLY INCREASING in height.
    //   Each threshold is by construction the work at a CHECKPOINT height that
    //   is BELOW its chain's tip -- DIL 54,000 vs tip 94,221; DilV 67,000 vs tip
    //   255,027. "Threshold < tip work" is therefore true by construction and
    //   cannot fail, whatever the literals say. It was ceremony: a green
    //   assertion that could never go red, backed by a number nobody could
    //   check. dil_tip_work in particular came from a relayed RPC read with an
    //   elided prefix and was verifiable by no one.
    //
    // What is asserted instead is the property that CAN fail and that the
    // literals were a proxy for: each threshold is the work at its own
    // checkpoint height, on the same chain, strictly above zero. The DIL half is
    // proven against the committed census in the test above; the DilV half is
    // re-derived here, from its own measured tip height, with no literal.
    //
    // The live tip figures are recorded where they belong -- as provenance, in
    // missions/lp10-headerssync-wiring/PROVENANCE_dil_nbits_dump.md -- not as
    // assertions pretending to be checks.

    // Strictly above zero, or the gate is a no-op even once wired. This one CAN
    // fail: it is what catches a value being reset to uint256() in a merge.
    REQUIRE(ChainWorkGreaterOrEqual(ChainParams::Mainnet().nMinimumChainWork, uint256S("1")));
    REQUIRE(ChainWorkGreaterOrEqual(ChainParams::DilV().nMinimumChainWork,    uint256S("1")));

    // DilV: re-derive the tip work rather than quote it. DilV's nBits is
    // 0x1d00ffff on all 255,028 canonical blocks (measured), so the tip work is
    // exactly (tipHeight + 1) contributions -- no literal, and it fails if
    // either the formula or the threshold changes.
    const int kDilvTipHeight = 255027;  // measured from a DilV block-database walk
    uint256 dilv_tip_derived;
    for (int h = 0; h <= kDilvTipHeight; ++h)
        dilv_tip_derived = AddChainWork(dilv_tip_derived, ComputeChainWork(0x1d00ffff));
    REQUIRE(!ChainWorkGreaterOrEqual(ChainParams::DilV().nMinimumChainWork, dilv_tip_derived));

    // ...and the margin is real, not marginal: the DilV tip carries strictly
    // more than 3x the threshold. This is the assertion that would actually
    // notice the threshold creeping up toward the tip.
    uint256 three_x = ChainParams::DilV().nMinimumChainWork;
    three_x = AddChainWork(three_x, ChainParams::DilV().nMinimumChainWork);
    three_x = AddChainWork(three_x, ChainParams::DilV().nMinimumChainWork);
    REQUIRE(ChainWorkGreaterOrEqual(dilv_tip_derived, three_x));
    std::cout << " OK" << std::endl;
}

} // namespace

int main()
{
    std::cout << "minimum_chain_work_kat_tests" << std::endl;
    test_hex_literals_round_trip();
    test_work_units_are_this_ports_units_not_bitcoin_cores();
    test_dilv_constant_is_re_derived_not_just_restated();
    test_dil_constant_is_re_derived_from_the_committed_census();
    test_chainparams_carry_the_measured_values();
    test_thresholds_are_nonzero_and_dilv_margin_is_re_derived();
    std::cout << "minimum_chain_work_kat_tests: ALL PASS" << std::endl;
    return 0;
}
