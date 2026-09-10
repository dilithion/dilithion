// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 3 Day 1 PM: header-proof-checker unit tests. Verifies both
// concrete IHeaderProofChecker implementations (RandomXHeaderProofChecker,
// VDFHeaderProofChecker) plus the maybe_punish_node.h wrappers' enum
// coverage (drift detection per the three-enum bridge).

#include <net/port/header_proof_checkers.h>
#include <net/port/maybe_punish_node.h>
#include <net/port/misbehavior_policy.h>
#include <consensus/chain_work.h>
#include <primitives/block.h>
#include <core/chainparams.h>
#include <consensus/pow.h>

#include <cassert>
#include <cstring>
#include <iostream>

using ::dilithion::net::port::RandomXHeaderProofChecker;
using ::dilithion::net::port::VDFHeaderProofChecker;
using ::dilithion::net::port::HeaderRejectReason;
using ::dilithion::net::port::BlockRejectReason;
using ::dilithion::net::port::TxRejectReason;
using ::dilithion::net::port::MapHeaderRejectToMisbehaviorType;
using ::dilithion::net::port::MapBlockRejectToMisbehaviorType;
using ::dilithion::net::port::MapTxRejectToMisbehaviorType;
using ::dilithion::net::port::HeaderRejectWeight;

namespace {

// Build a CBlockHeader with a given nBits and (for VDF tests) optional
// VDF fields. nVersion controls IsVDFBlock dispatch.
CBlockHeader MakeRandomXHeader(uint32_t nBits)
{
    CBlockHeader h;
    h.nVersion = 1;
    h.nBits = nBits;
    h.nTime = 1700000000;
    h.nNonce = 0;
    return h;
}

CBlockHeader MakeVDFHeader(uint32_t nBits, bool null_proof = false, bool null_output = false)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;  // marks as VDF block
    h.nBits = nBits;
    h.nTime = 1700000000;
    h.nNonce = 0;
    if (!null_proof) {
        // populate vdfProofHash with sentinel non-zero
        for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0x42;
    }
    if (!null_output) {
        for (int i = 0; i < 32; ++i) h.vdfOutput.data[i] = 0x37;
    }
    return h;
}

}  // anonymous

// ============================================================================
// RandomXHeaderProofChecker
// ============================================================================

void test_randomx_chain_work_via_helper()
{
    std::cout << "  test_randomx_chain_work_via_helper..." << std::flush;
    RandomXHeaderProofChecker c;
    auto h = MakeRandomXHeader(0x1d00ffff);  // genesis-like difficulty
    uint256 via_checker = c.ChainWorkContribution(h);
    uint256 via_helper  = ::dilithion::consensus::ComputeChainWork(0x1d00ffff);
    assert(std::memcmp(via_checker.data, via_helper.data, 32) == 0);
    std::cout << " OK\n";
}

void test_randomx_chain_work_monotone()
{
    std::cout << "  test_randomx_chain_work_monotone..." << std::flush;
    RandomXHeaderProofChecker c;
    // Smaller nBits "size" byte = larger work (more trailing zeros required).
    auto easy = MakeRandomXHeader(0x1d00ffff);
    auto hard = MakeRandomXHeader(0x1c00ffff);
    uint256 w_easy = c.ChainWorkContribution(easy);
    uint256 w_hard = c.ChainWorkContribution(hard);
    // hard should require more work than easy.
    assert(c.ChainWorkGreaterThan(w_hard, w_easy));
    assert(!c.ChainWorkGreaterThan(w_easy, w_hard));
    std::cout << " OK\n";
}

void test_randomx_chain_work_greater_than_strict()
{
    std::cout << "  test_randomx_chain_work_greater_than_strict..." << std::flush;
    RandomXHeaderProofChecker c;
    uint256 a, b;
    std::memset(a.data, 0, 32); std::memset(b.data, 0, 32);
    a.data[0] = 5;  // a = 5, b = 5 (LE)
    b.data[0] = 5;
    assert(!c.ChainWorkGreaterThan(a, b));  // 5 > 5 is false (strict)
    assert(!c.ChainWorkGreaterThan(b, a));
    a.data[0] = 6;
    assert( c.ChainWorkGreaterThan(a, b));
    assert(!c.ChainWorkGreaterThan(b, a));
    std::cout << " OK\n";
}

// ============================================================================
// VDFHeaderProofChecker
// ============================================================================

void test_vdf_checker_accepts_well_formed()
{
    std::cout << "  test_vdf_checker_accepts_well_formed..." << std::flush;
    VDFHeaderProofChecker c;
    // 0x1d00ffff is the VDF chains' genesisNBits (DilV and regtest alike), which
    // the checker now requires by EQUALITY — see the nBits rule in
    // header_proof_checkers.h. main() sets g_chainParams for that reason.
    auto h = MakeVDFHeader(0x1d00ffff);
    assert(c.CheckHeaderProof(h));
    std::cout << " OK\n";
}

// ⚠️ THIS ARM EXISTS BECAUSE THE SUITE ABOVE BROKE, AND WHY IT BROKE MATTERS.
// The VDF checker's nBits rule reads g_chainParams->genesisNBits and FAILS CLOSED
// when chainparams is absent. This suite never set g_chainParams, so every
// well-formed header was rejected the moment that rule landed.
//
// The correct fix was to the TEST — production always has chainparams — and NOT
// to weaken the rule to a `g_chainParams ? ... : <permissive default>`, which is
// the fail-OPEN shape #189 shipped once and two external seats caught. Pinning
// the behaviour here so that a future reader who hits this failure fixes the
// setup rather than the rule.
void test_vdf_checker_fails_closed_without_chainparams()
{
    std::cout << "  test_vdf_checker_fails_closed_without_chainparams..." << std::flush;
    VDFHeaderProofChecker c;
    auto h = MakeVDFHeader(0x1d00ffff);

    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::g_chainParams = nullptr;
    const bool accepted_without_params = c.CheckHeaderProof(h);
    Dilithion::g_chainParams = saved;

    // A missing consensus parameter must never become a permissive verdict on a
    // work-accounting input.
    assert(!accepted_without_params);
    // And the same header is accepted once chainparams is back, so this arm is
    // pinning fail-closed rather than a checker that rejects everything.
    assert(c.CheckHeaderProof(h));
    std::cout << " OK\n";
}

void test_vdf_checker_rejects_non_vdf_header()
{
    std::cout << "  test_vdf_checker_rejects_non_vdf_header..." << std::flush;
    VDFHeaderProofChecker c;
    auto h = MakeRandomXHeader(0x1d00ffff);  // nVersion = 1, not VDF
    assert(!c.CheckHeaderProof(h));
    std::cout << " OK\n";
}

void test_vdf_checker_rejects_null_proof_hash()
{
    std::cout << "  test_vdf_checker_rejects_null_proof_hash..." << std::flush;
    VDFHeaderProofChecker c;
    auto h = MakeVDFHeader(0x1d00ffff, /*null_proof=*/true);
    assert(!c.CheckHeaderProof(h));
    std::cout << " OK\n";
}

void test_vdf_checker_rejects_null_output()
{
    std::cout << "  test_vdf_checker_rejects_null_output..." << std::flush;
    VDFHeaderProofChecker c;
    auto h = MakeVDFHeader(0x1d00ffff, /*null_proof=*/false, /*null_output=*/true);
    assert(!c.CheckHeaderProof(h));
    std::cout << " OK\n";
}

void test_vdf_chain_work_uses_same_helper_as_randomx()
{
    std::cout << "  test_vdf_chain_work_uses_same_helper_as_randomx..." << std::flush;
    // Q4 codifier: both checkers share the formula.
    RandomXHeaderProofChecker rc;
    VDFHeaderProofChecker     vc;
    auto rh = MakeRandomXHeader(0x1d00ffff);
    auto vh = MakeVDFHeader(0x1d00ffff);
    uint256 wr = rc.ChainWorkContribution(rh);
    uint256 wv = vc.ChainWorkContribution(vh);
    assert(std::memcmp(wr.data, wv.data, 32) == 0);  // same nBits, same work
    std::cout << " OK\n";
}

// ============================================================================
// Three-enum bridge — drift detection
// ============================================================================

void test_header_reject_reason_maps_exhaustively()
{
    std::cout << "  test_header_reject_reason_maps_exhaustively..." << std::flush;
    using R = HeaderRejectReason;
    using T = ::dilithion::net::MisbehaviorType;
    // Every value of HeaderRejectReason must produce a non-Unknown
    // MisbehaviorType. Catches drift if a future contributor adds an
    // enum entry without updating the map.
    assert(MapHeaderRejectToMisbehaviorType(R::InvalidProof)                  != T::UnknownMessage);
    assert(MapHeaderRejectToMisbehaviorType(R::InvalidHeaderFields)           != T::UnknownMessage);
    assert(MapHeaderRejectToMisbehaviorType(R::NonContinuousChain)            != T::UnknownMessage);
    assert(MapHeaderRejectToMisbehaviorType(R::InsufficientChainWork)         != T::UnknownMessage);
    assert(MapHeaderRejectToMisbehaviorType(R::RedownloadCommitmentMismatch)  != T::UnknownMessage);
    assert(MapHeaderRejectToMisbehaviorType(R::MemoryBoundExceeded)           != T::UnknownMessage);
    assert(MapHeaderRejectToMisbehaviorType(R::FutureTimestamp)               != T::UnknownMessage);
    std::cout << " OK\n";
}

void test_header_reject_weights_honest_signals_score_zero()
{
    std::cout << "  test_header_reject_weights_honest_signals_score_zero..." << std::flush;
    using R = HeaderRejectReason;

    // ⚠️ THIS TEST PREVIOUSLY PINNED THE OPPOSITE VALUE (Q6=B, weight 100) and
    // was renamed rather than deleted, so the reversal is visible in history.
    // LP-10 A-2 blocker 3 reversed it: both of these are signals an HONEST peer
    // CAN emit, and Will's standing rule (2026-07-05) bans only on signals an
    // honest peer CANNOT emit.
    //
    //   InsufficientChainWork -- indistinguishable from an honest peer on a
    //     losing fork, or one with nothing more to give.
    //   RedownloadCommitmentMismatch -- a peer that REORGS between PRESYNC and
    //     REDOWNLOAD emits exactly this: commitments recorded against the
    //     phase-1 chain, phase 2 re-requests and compares against the OLD ones.
    //
    // Measured by ENUMERATION: Core v28.0 net_processing.cpp has 21 Misbehaving()
    // sites; none is for a low-work chain and none is for a commitment mismatch.
    assert(HeaderRejectWeight(R::RedownloadCommitmentMismatch) == 0);
    assert(HeaderRejectWeight(R::InsufficientChainWork) == 0);

    // THE DISCRIMINATING HALF. Zeroing the two honest-emittable reasons must not
    // quietly disarm the scorer: signals an honest peer genuinely cannot emit
    // keep their weight. Without these, "everything scores 0" would pass.
    assert(HeaderRejectWeight(R::InvalidProof) == 100);  // InvalidPoW default
    assert(HeaderRejectWeight(R::MemoryBoundExceeded) == 20);  // OversizedMessage default
    assert(HeaderRejectWeight(R::NonContinuousChain) == 20);   // NonContinuousHeaders default
    std::cout << " OK\n";
}

void test_block_and_tx_reject_reasons_map_exhaustively()
{
    std::cout << "  test_block_and_tx_reject_reasons_map_exhaustively..." << std::flush;
    using BR = BlockRejectReason;
    using TR = TxRejectReason;
    using T = ::dilithion::net::MisbehaviorType;
    assert(MapBlockRejectToMisbehaviorType(BR::InvalidProof)          != T::UnknownMessage);
    assert(MapBlockRejectToMisbehaviorType(BR::InvalidMerkleRoot)     != T::UnknownMessage);
    assert(MapBlockRejectToMisbehaviorType(BR::InvalidCoinbase)       != T::UnknownMessage);
    assert(MapBlockRejectToMisbehaviorType(BR::DuplicateTransactions) != T::UnknownMessage);
    assert(MapBlockRejectToMisbehaviorType(BR::DoubleSpend)           != T::UnknownMessage);
    assert(MapTxRejectToMisbehaviorType(TR::InvalidSignature)         != T::UnknownMessage);
    assert(MapTxRejectToMisbehaviorType(TR::DuplicateInputs)          != T::UnknownMessage);
    assert(MapTxRejectToMisbehaviorType(TR::Oversized)                != T::UnknownMessage);
    assert(MapTxRejectToMisbehaviorType(TR::DoubleSpend)              != T::UnknownMessage);
    std::cout << " OK\n";
}

// ============================================================================
// main
// ============================================================================

int main()
{
    // The VDF checker's nBits rule reads g_chainParams->genesisNBits and FAILS
    // CLOSED without it, so this suite must set chainparams up as production
    // does. Regtest is a VDF chain and its genesisNBits is 0x1d00ffff, the value
    // MakeVDFHeader uses below.
    Dilithion::g_chainParams =
        new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());

    std::cout << "\n=== Phase 3: HeaderProofChecker Tests ===\n" << std::endl;

    try {
        std::cout << "--- RandomXHeaderProofChecker ---" << std::endl;
        test_randomx_chain_work_via_helper();
        test_randomx_chain_work_monotone();
        test_randomx_chain_work_greater_than_strict();

        std::cout << "\n--- VDFHeaderProofChecker ---" << std::endl;
        test_vdf_checker_accepts_well_formed();
        test_vdf_checker_fails_closed_without_chainparams();
        test_vdf_checker_rejects_non_vdf_header();
        test_vdf_checker_rejects_null_proof_hash();
        test_vdf_checker_rejects_null_output();
        test_vdf_chain_work_uses_same_helper_as_randomx();

        std::cout << "\n--- MaybePunishNodeFor* enum bridges ---" << std::endl;
        test_header_reject_reason_maps_exhaustively();
        test_header_reject_weights_honest_signals_score_zero();
        test_block_and_tx_reject_reasons_map_exhaustively();

        std::cout << "\n=== All Phase 3 HeaderProofChecker Tests Passed (11 tests) ===" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}
