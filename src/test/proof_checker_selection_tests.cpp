// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 — the header proof-checker's predicate must MIRROR THE PRODUCER'S.
//
// THE DEFECT THIS PINS. CHeadersManager's constructor chose
// VDFHeaderProofChecker when `IsDilV()` was true, so REGTEST — a VDF chain whose
// network is not DILV — was handed RandomXHeaderProofChecker, which calls
// CheckProofOfWork(header.GetHash(), nBits) on a VDF header. A VDF header's hash
// is not mined against a target, so honest regtest VDF headers failed their
// proof check.
//
// ⚠️ AND THE OBVIOUS FIX IS WRONG, WHICH IS THE REAL LESSON HERE.
// The comment fifteen lines below the bug points at `IsVdfFromGenesis()` as the
// shared dispatcher, and an earlier draft of this suite used it. **That would
// have broken TESTNET.** Testnet satisfies IsVdfFromGenesis() (activation and
// exclusive heights are both 0) but the PRODUCER's constant branch is
// `IsDilV() || IsRegtest()` (pow.cpp:1142-1146) — testnet is not in it and
// retargets via ASERT, so its honest headers carry non-genesis nBits. Handing
// testnet the VDF checker would apply an nBits-EQUALITY rule that its own honest
// headers violate: banning honest peers, while fixing a different instance of
// exactly that class. An external seat caught it before it was opened.
//
// THE RULE, and it generalises past this file: when a checker asserts a property
// only the producer can guarantee, its predicate must be the producer's
// predicate. Two predicates verified separately, against different things, are
// not the same predicate — and here they differ on exactly one network.
//
// ⚠️ TESTNET REMAINS BROKEN, KNOWINGLY. It keeps the RandomX checker and its VDF
// headers still fail. This change does not regress it — it declines to swap one
// breakage for a subtler one. Testnet needs its own rule, because equality does
// not hold under retargeting; that is an activation prerequisite tracked
// separately.
//
// Dormant when written — the DoS-protected path has no production callers — but
// it becomes a live break the day the gate is armed, which is why it lands
// before any activation contract rather than with one.

#include <net/headers_manager.h>

#include <core/chainparams.h>

#include <cstdlib>
#include <iostream>

namespace {

int g_failures = 0;
void Check(const char* what, bool ok)
{
    if (!ok) { std::cerr << "  FAIL " << what << std::endl; ++g_failures; }
}

// Build a manager under a given chainparams and report which checker it chose.
// Constructing the real CHeadersManager is the point: a test that re-evaluated
// the predicate itself would pass even if the constructor ignored it, which is
// exactly how the original defect survived.
bool SelectsVdfCheckerUnder(const Dilithion::ChainParams& params)
{
    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::g_chainParams = new Dilithion::ChainParams(params);
    const bool uses_vdf = CHeadersManager().UsesVdfProofChecker();
    delete Dilithion::g_chainParams;
    Dilithion::g_chainParams = saved;
    return uses_vdf;
}

// THE DISCRIMINATING PAIR. Every VDF-from-genesis network must select the VDF
// checker; the RandomX chain must not. Testnet and regtest are the arms that
// were RED before the fix — under IsDilV() both returned false.
void test_vdf_chains_select_the_vdf_checker()
{
    std::cout << "  test_vdf_chains_select_the_vdf_checker..." << std::flush;

    // The two networks where the PRODUCER emits a constant, which is the only
    // condition under which the checker's nBits-equality rule is sound.
    Check("DilV selects the VDF checker",
          SelectsVdfCheckerUnder(Dilithion::ChainParams::DilV()));
    Check("REGTEST selects the VDF checker (RED under IsDilV alone)",
          SelectsVdfCheckerUnder(Dilithion::ChainParams::Regtest()));

    // ⛔ TESTNET MUST **NOT** SELECT IT, and this arm exists because an earlier
    // draft of this fix got it wrong. Testnet is VDF-from-genesis
    // (IsVdfFromGenesis() == true) but the producer's constant branch is
    // `IsDilV() || IsRegtest()` (pow.cpp:1142-1146), so testnet RETARGETS via
    // ASERT and its honest headers carry non-genesis nBits. Handing it the VDF
    // checker would apply an equality rule its own honest headers violate.
    Check("TESTNET does NOT select the VDF checker (its producer RETARGETS)",
          !SelectsVdfCheckerUnder(Dilithion::ChainParams::Testnet()));

    std::cout << " done" << std::endl;
}

// THE OTHER HALF, without which "always pick VDF" would pass everything above.
// DIL is a RandomX chain and must keep the RandomX checker.
void test_randomx_chain_keeps_the_randomx_checker()
{
    std::cout << "  test_randomx_chain_keeps_the_randomx_checker..." << std::flush;

    Check("DIL mainnet does NOT select the VDF checker",
          !SelectsVdfCheckerUnder(Dilithion::ChainParams::Mainnet()));

    std::cout << " done" << std::endl;
}

// The predicates must actually DISAGREE on testnet/regtest — otherwise this
// whole suite is testing a distinction that does not exist, and would keep
// passing if someone reverted the fix on a build where they happened to agree.
void test_the_two_predicates_really_disagree()
{
    std::cout << "  test_the_two_predicates_really_disagree..." << std::flush;

    const auto testnet = Dilithion::ChainParams::Testnet();
    const auto regtest = Dilithion::ChainParams::Regtest();
    const auto dilv    = Dilithion::ChainParams::DilV();
    const auto mainnet = Dilithion::ChainParams::Mainnet();

    // ⛔ THE TRAP, pinned: testnet satisfies IsVdfFromGenesis() but NOT the
    // producer's constant branch. Anyone reaching for IsVdfFromGenesis() as the
    // checker predicate must fail this arm.
    Check("testnet: IsVdfFromGenesis TRUE but producer NOT constant — the trap",
          testnet.IsVdfFromGenesis() && !(testnet.IsDilV() || testnet.IsRegtest()));
    Check("regtest: IsVdfFromGenesis TRUE but IsDilV FALSE — the bug's cause",
          regtest.IsVdfFromGenesis() && !regtest.IsDilV());
    Check("DilV: both predicates agree TRUE (why the bug hid on the live chain)",
          dilv.IsVdfFromGenesis() && dilv.IsDilV());
    Check("DIL mainnet: both predicates agree FALSE",
          !mainnet.IsVdfFromGenesis() && !mainnet.IsDilV());

    std::cout << " done" << std::endl;
}

}  // namespace

int main()
{
    std::cout << "proof_checker_selection_tests" << std::endl;

    test_the_two_predicates_really_disagree();
    test_vdf_chains_select_the_vdf_checker();
    test_randomx_chain_keeps_the_randomx_checker();

    if (g_failures != 0) {
        std::cerr << "proof_checker_selection_tests: " << g_failures
                  << " FAILURE(S)" << std::endl;
        return 1;
    }
    std::cout << "proof_checker_selection_tests: ALL PASS" << std::endl;
    return 0;
}
