// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 — a peer-supplied nBits with a ZERO MANTISSA must not be usable for
// chain-work accounting, on the LIVE header path.
//
// ⚠️ THIS SUITE IS IN-TREE ON PURPOSE. The previous round of this fix was
// verified by harnesses that lived outside the repository, needed hooks the
// committed code did not have, and therefore NEVER RAN against committed code —
// so no in-tree test could fail if any fix regressed. That was a fair review
// finding and this file is the response to it: the arms below run in the fast
// tier, against production code, with no test-only hooks.
//
// ---------------------------------------------------------------------------
// THE DEFECT, measured before the fix (probe P4, COORD shell reader 2026-09-10)
// ---------------------------------------------------------------------------
// ComputeChainWork SATURATES to 0xFF..FF when the MANTISSA is zero
// (chain_work.h). A zero mantissa is NOT a zero word — 0x1e000000 has a
// non-zero nBits — so the `nBits == 0` guard that stood at
// CHeadersManager::ValidateHeader and ::QuickValidateHeader did not catch it.
// VDF headers skip CheckProofOfWork entirely, so nothing else constrained nBits
// on that path, and a single fabricated sibling OVERTOOK an honest sibling as
// best header with newWork = 0xffff...
//
// Block-level consensus still refuses to connect such a block, so the impact
// was best-header DoS rather than a consensus split. It was live and
// peer-triggerable, which is why it was fixed separately from the dormant
// header-sync work rather than folded into it.
//
// ---------------------------------------------------------------------------
// WHAT EACH ARM PROVES, and why the honest arms are not padding
// ---------------------------------------------------------------------------
// A guard that rejects everything would pass a "poison rejected" test. So every
// poison arm here is paired with an HONEST arm that must still be ACCEPTED, on
// both chains' real difficulty values. Without those, "reject all nBits" would
// look identical to the correct fix.

#include <consensus/chain_work.h>
#include <core/chainparams.h>
#include <primitives/block.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace {

// Not assert(): a release build with -DNDEBUG would compile these away and the
// suite would print ALL PASS while checking nothing.
int g_failures = 0;
void Check(const char* what, bool ok)
{
    if (!ok) {
        std::cerr << "  FAIL " << what << std::endl;
        ++g_failures;
    }
}

bool IsSaturated(const uint256& w)
{
    for (int i = 0; i < 32; ++i) {
        if (w.data[i] != 0xFF) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Arm 1 — the saturation itself still exists, and the predicate sees it.
// If ComputeChainWork ever stops saturating, the guard becomes unnecessary and
// this suite should be revisited rather than silently passing for a new reason.
// ---------------------------------------------------------------------------
void test_zero_mantissa_saturates_and_is_rejected()
{
    std::cout << "  test_zero_mantissa_saturates_and_is_rejected..." << std::flush;
    using namespace dilithion::consensus;

    // Several zero-mantissa forms, all with a NON-ZERO word: the old
    // `nBits == 0` guard accepted every one of these.
    const uint32_t poison[] = {0x1e000000u, 0x1d000000u, 0x01000000u, 0xff000000u};
    for (uint32_t nb : poison) {
        Check("zero-mantissa nBits saturates ComputeChainWork",
              IsSaturated(ComputeChainWork(nb)));
        Check("zero-mantissa nBits is REJECTED by NBitsUsableForWork",
              !NBitsUsableForWork(nb));
        // The property that made it slip through: it is not zero.
        Check("poison nBits is NOT zero (so `nBits == 0` would have passed it)",
              nb != 0);
    }
    std::cout << " done" << std::endl;
}

// ---------------------------------------------------------------------------
// Arm 2 — THE DISCRIMINATING ARM. Real difficulty values must be ACCEPTED.
// This is what distinguishes the fix from "reject everything".
// ---------------------------------------------------------------------------
void test_honest_nbits_still_accepted()
{
    std::cout << "  test_honest_nbits_still_accepted..." << std::flush;
    using namespace dilithion::consensus;

    // DilV's constant difficulty (it has never retargeted), DIL's genesis value,
    // Bitcoin's classic minimum, and regtest.
    const uint32_t honest[] = {0x1d00ffffu, 0x1e01fffeu, 0x1c00ffffu, 0x207fffffu};
    for (uint32_t nb : honest) {
        Check("honest nBits accepted by NBitsUsableForWork", NBitsUsableForWork(nb));
        Check("honest nBits does NOT saturate", !IsSaturated(ComputeChainWork(nb)));
    }

    // And the live chainparams values, so the arm tracks the chain rather than a
    // hardcoded list that could drift away from it.
    Check("g_chainParams genesisNBits is usable",
          NBitsUsableForWork(Dilithion::g_chainParams->genesisNBits));
    Check("g_chainParams genesisNBits does not saturate",
          !IsSaturated(ComputeChainWork(Dilithion::g_chainParams->genesisNBits)));

    std::cout << " done" << std::endl;
}

// ---------------------------------------------------------------------------
// Arm 3 — the boundary. Mantissa 1 is the smallest usable value; it must be
// ACCEPTED (it is legitimate, if absurdly hard) while mantissa 0 is rejected.
// A guard written as `<= 1` or `< 2` would pass arms 1-2 and fail here.
// ---------------------------------------------------------------------------
void test_mantissa_one_is_accepted_zero_is_not()
{
    std::cout << "  test_mantissa_one_is_accepted_zero_is_not..." << std::flush;
    using namespace dilithion::consensus;

    Check("mantissa 1 is USABLE (legitimate, merely very hard)",
          NBitsUsableForWork(0x1d000001u));
    Check("mantissa 0 at the same exponent is NOT usable",
          !NBitsUsableForWork(0x1d000000u));

    // Only the low 24 bits matter: the exponent must not affect the verdict.
    Check("exponent does not change the mantissa verdict (0x01000001 usable)",
          NBitsUsableForWork(0x01000001u));
    Check("exponent does not change the mantissa verdict (0x01000000 unusable)",
          !NBitsUsableForWork(0x01000000u));

    std::cout << " done" << std::endl;
}

}  // namespace

int main()
{
    Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    std::cout << "nbits_work_saturation_tests" << std::endl;

    test_zero_mantissa_saturates_and_is_rejected();
    test_honest_nbits_still_accepted();
    test_mantissa_one_is_accepted_zero_is_not();

    if (g_failures != 0) {
        std::cerr << "nbits_work_saturation_tests: " << g_failures << " FAILURE(S)" << std::endl;
        return 1;
    }
    std::cout << "nbits_work_saturation_tests: ALL PASS" << std::endl;
    return 0;
}
