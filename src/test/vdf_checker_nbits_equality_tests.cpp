// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 A-2 / blocker 4 — VDFHeaderProofChecker must pin nBits to the chain's
// CONSTANT, not merely reject one bad value.
//
// ⚠️ THIS SUITE EXISTS BECAUSE THE FIRST FIX CLOSED AN INSTANCE AND WAS
// DESCRIBED AS CLOSING A CLASS. The original guard was
// `(nBits & 0x00FFFFFF) == 0` — a zero-MANTISSA test. A reviewer's probe found
// that a TINY mantissa passes it and still opens DilV's measured work gate,
// because work is inversely proportional to the mantissa:
//
//   nBits        mantissa   chain work           opens DilV's measured gate?
//   0x1e000000   0          2^256-1 saturated    YES   <- mantissa test blocks
//   0x01000001   1          1.15e77              YES   <- mantissa test PASSES
//   0x1c000001   1          7.92e28              YES   <- mantissa test PASSES
//   0x1d00ffff   65535      4.72e21              no    (honest DilV)
//
// The class-closing rule is EQUALITY against the chain's constant, and it is
// safe because the producer emits exactly that value:
//   pow.cpp:1143-1145  GetNextWorkRequired returns genesisNBits unconditionally
//                      for IsDilV() and IsRegtest()
//   chainparams (DilV) "nBits is 0x1d00ffff on ALL 255,028 canonical blocks
//                      measured; difficulty has NEVER retargeted"
//
// IN-TREE ON PURPOSE. A review finding on the previous round was that the
// harnesses proving these fixes lived outside the repository and could not fail
// in CI. This suite runs in the fast tier against production code.

#include <net/port/header_proof_checkers.h>

#include <consensus/chain_work.h>
#include <core/chainparams.h>
#include <primitives/block.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

namespace {

int g_failures = 0;
void Check(const char* what, bool ok)
{
    if (!ok) { std::cerr << "  FAIL " << what << std::endl; ++g_failures; }
}

// A header that satisfies EVERY other condition the checker tests, so that the
// only variable across arms is nBits. Without this the arms would be
// indistinguishable from a rejection on some other field.
CBlockHeader MakeOtherwiseValidVdfHeader(uint32_t nBits)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;      // IsVDFBlock() -> true
    h.nBits = nBits;
    h.nTime = 1700000000;
    h.nNonce = 1;
    std::memset(h.vdfOutput.data, 0xAB, 32);     // non-null
    std::memset(h.vdfProofHash.data, 0xCD, 32);  // non-null
    std::memset(h.cachedHash.data, 0x11, 32);    // avoid RandomX in GetHash()
    h.fHashCached = true;
    return h;
}

void test_only_the_chain_constant_is_accepted()
{
    std::cout << "  test_only_the_chain_constant_is_accepted..." << std::flush;
    ::dilithion::net::port::VDFHeaderProofChecker checker;
    const uint32_t genesis = Dilithion::g_chainParams->genesisNBits;

    // ACCEPT: the chain's own constant, whatever it is on this network. Read from
    // chainparams rather than hardcoded, so the arm tracks the chain.
    Check("the chain's genesisNBits is ACCEPTED",
          checker.CheckHeaderProof(MakeOtherwiseValidVdfHeader(genesis)));

    // REJECT: the zero-mantissa saturation (the original instance).
    Check("zero mantissa 0x1e000000 REJECTED",
          !checker.CheckHeaderProof(MakeOtherwiseValidVdfHeader(0x1e000000u)));

    // REJECT: THE RESIDUAL CLASS the first fix missed. Tiny mantissa, non-zero,
    // near-maximal work. These are the arms that would have caught it.
    Check("tiny mantissa 0x01000001 REJECTED (was PASSING the mantissa test)",
          !checker.CheckHeaderProof(MakeOtherwiseValidVdfHeader(0x01000001u)));
    Check("tiny mantissa 0x1c000001 REJECTED (was PASSING the mantissa test)",
          !checker.CheckHeaderProof(MakeOtherwiseValidVdfHeader(0x1c000001u)));

    // REJECT: an ordinary-looking but WRONG value. Not absurd, not saturating —
    // simply not this chain's constant. A range-based guard would accept it.
    Check("plausible-but-wrong 0x1d00fffe REJECTED",
          !checker.CheckHeaderProof(MakeOtherwiseValidVdfHeader(0x1d00fffeu)));
    Check("DIL's genesis value REJECTED on a VDF chain (0x1e01fffe)",
          !checker.CheckHeaderProof(MakeOtherwiseValidVdfHeader(0x1e01fffeu)));

    std::cout << " done" << std::endl;
}

// The nBits rule must not have swallowed the checks that were already there: a
// guard that rejects everything would pass every arm above except the accept.
void test_the_other_conditions_still_discriminate()
{
    std::cout << "  test_the_other_conditions_still_discriminate..." << std::flush;
    ::dilithion::net::port::VDFHeaderProofChecker checker;
    const uint32_t genesis = Dilithion::g_chainParams->genesisNBits;

    CBlockHeader not_vdf = MakeOtherwiseValidVdfHeader(genesis);
    not_vdf.nVersion = 1;                       // IsVDFBlock() -> false
    Check("a non-VDF header is still REJECTED", !checker.CheckHeaderProof(not_vdf));

    CBlockHeader null_out = MakeOtherwiseValidVdfHeader(genesis);
    std::memset(null_out.vdfOutput.data, 0, 32);
    Check("a null vdfOutput is still REJECTED", !checker.CheckHeaderProof(null_out));

    CBlockHeader null_proof = MakeOtherwiseValidVdfHeader(genesis);
    std::memset(null_proof.vdfProofHash.data, 0, 32);
    Check("a null vdfProofHash is still REJECTED", !checker.CheckHeaderProof(null_proof));

    std::cout << " done" << std::endl;
}

// The work consequence, asserted directly: the rejected values are exactly the
// ones that would have cleared DilV's measured threshold. This ties the guard to
// WHY it exists rather than to a list of literals.
void test_rejected_values_are_the_ones_that_clear_the_threshold()
{
    std::cout << "  test_rejected_values_are_the_ones_that_clear_the_threshold..." << std::flush;
    using namespace dilithion::consensus;

    // DilV's measured nMinimumChainWork.
    const uint256 threshold = uint256S(
        "00000000000000000000000000000000000000000105ba05ba05ba05b9000000");

    for (uint32_t nb : {0x1e000000u, 0x01000001u, 0x1c000001u}) {
        Check("a rejected nBits would indeed have cleared the threshold in ONE header",
              ChainWorkGreaterOrEqual(ComputeChainWork(nb), threshold));
    }
    // And the honest constant would NOT, which is why one honest header cannot
    // open the gate and the guard is not merely rejecting everything useful.
    Check("the honest constant does NOT clear the threshold in one header",
          !ChainWorkGreaterOrEqual(
              ComputeChainWork(Dilithion::g_chainParams->genesisNBits), threshold));

    std::cout << " done" << std::endl;
}

}  // namespace

int main()
{
    // Regtest is a VDF chain (chainparams: "regtest IS a VDF chain"), so the
    // checker's equality rule reads regtest's own genesisNBits here.
    Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    std::cout << "vdf_checker_nbits_equality_tests (genesisNBits=0x"
              << std::hex << Dilithion::g_chainParams->genesisNBits << std::dec << ")"
              << std::endl;

    test_only_the_chain_constant_is_accepted();
    test_the_other_conditions_still_discriminate();
    test_rejected_values_are_the_ones_that_clear_the_threshold();

    if (g_failures != 0) {
        std::cerr << "vdf_checker_nbits_equality_tests: " << g_failures
                  << " FAILURE(S)" << std::endl;
        return 1;
    }
    std::cout << "vdf_checker_nbits_equality_tests: ALL PASS" << std::endl;
    return 0;
}
