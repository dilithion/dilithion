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
#include <net/headers_manager.h>
#include <node/genesis.h>
#include <primitives/block.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
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

// ---------------------------------------------------------------------------
// ⛔ ARM 4 — THE PRODUCTION PATH. Every arm above calls the predicates DIRECTLY,
// and an external panel found all three of them insufficient for the same reason,
// independently: *"removing both production validator changes while retaining the
// helper would leave these tests passing."* That is true, and it was the defect
// this whole change exists to fix, one level up — #196 guarded a predicate on a
// path nothing called, and a suite that proves a predicate while leaving the
// WIRING unverified is the same mistake with the pieces rearranged.
//
// So this arm drives headers through the REAL public validators —
// CHeadersManager::ValidateHeader and ::QuickValidateHeader — and asserts on their
// verdicts and on the manager's ACCUMULATED BEST-HEADER WORK, never on the
// predicates.
//
// IT COVERS BOTH CLASSES, because they are two different predicates:
//   * SATURATION  — 0x1e000000, zero mantissa, ComputeChainWork returns 0xFF..FF
//   * INFLATION   — 0x01000001 / 0x00000001 / 0x03000001, mantissa 1 with a small
//                   `size`, which passes the saturation guard and still yields
//                   ~2^248. An arm covering only saturation would leave the newer
//                   finding untested, which is how the first round of this fix
//                   shipped with a hole.
// ---------------------------------------------------------------------------

// A threshold BETWEEN an honest header's work and the inflation class's work, so
// the bound is live without rejecting honest values:
//   honest 0x1d00ffff -> top set byte 9   (~2^76)
//   inflation         -> top set byte 31  (~2^248)
// 2^200 sits between them. Chosen by measurement, not by taste, and both sides are
// asserted below so a wrong choice cannot pass quietly.
uint256 ThresholdBetweenHonestAndInflated()
{
    uint256 t;
    std::memset(t.data, 0, 32);
    t.data[25] = 0x01;  // 2^200, little-endian
    return t;
}

CBlockHeader HeaderWithNBits(uint32_t nBits)
{
    CBlockHeader h;
    h.nVersion      = CBlockHeader::VDF_VERSION;  // the path that skips CheckProofOfWork
    h.nBits         = nBits;
    h.nTime         = 1700000000;
    h.nNonce        = 0;
    for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0x42;
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i]    = 0x37;
    return h;
}

void test_production_validators_reject_both_classes()
{
    std::cout << "  test_production_validators_reject_both_classes..." << std::flush;

    CHeadersManager mgr(ThresholdBetweenHonestAndInflated());

    // Genesis is the one parent a fresh manager knows (the constructor inserts it into
    // mapHeaders), so it is how any arm reaches the post-parent-resolution branch.
    const CBlock genesisBlock = Genesis::CreateGenesisBlockForChain();
    const CBlockHeader genesisHeader = genesisBlock;
    auto ChildOf = [&](uint32_t nBits) {
        CBlockHeader c = HeaderWithNBits(nBits);
        c.hashPrevBlock = genesisHeader.GetHash();
        c.nTime = genesisHeader.nTime + 100;
        return c;
    };

    // ---- QuickValidateHeader: checks nBits UNCONDITIONALLY ------------------
    // Its two nBits guards precede any pprev handling, so it is the validator that
    // covers a header whose parent we do not have.

    // NON-VACUITY FIRST: honest nBits must still be ACCEPTED with the bound live.
    // Without this, "reject everything" passes every assertion below, and a badly
    // chosen threshold would pass quietly.
    const CBlockHeader honest = HeaderWithNBits(0x1d00ffffu);
    Check("PROD/Quick: honest nBits accepted",
          mgr.QuickValidateHeader(honest, nullptr));

    // SATURATION class.
    Check("PROD/Quick: zero-mantissa REJECTED",
          !mgr.QuickValidateHeader(HeaderWithNBits(0x1e000000u), nullptr));

    // INFLATION class — the half the saturation guard passes. Three encodings,
    // because one exponent could be a special case.
    for (uint32_t nBits : {0x01000001u, 0x00000001u, 0x03000001u}) {
        // Stated for the reader: this DOES pass the saturation predicate, so the
        // rejection below can only come from the magnitude bound.
        Check("PROD/Quick: inflation encoding passes the SATURATION predicate, so "
              "the rejection is the BOUND and not the mask",
              ::dilithion::consensus::NBitsUsableForWork(nBits));
        Check("PROD/Quick: inflated single-header work REJECTED",
              !mgr.QuickValidateHeader(HeaderWithNBits(nBits), nullptr));
    }

    // ---- ⛔ ValidateHeader: ITS GUARDS SIT BELOW TWO EARLY RETURNS -----------
    // MEASURED, and this arm is how it was found. ValidateHeader returns TRUE at
    // `if (pprev == nullptr)` and again at `if (parent not in mapHeaders)`, BOTH of
    // which precede its nBits guards. So for a header with no known parent it checks
    // neither the saturation class nor the inflation class.
    //
    // ⛔ THIS PIN ASSERTS MEASURED CURRENT BEHAVIOUR, NOT DESIRED BEHAVIOUR.
    // Read it as a description, never as an endorsement. Three things must stay
    // attached to it or it becomes the wrong kind of documentation:
    //
    //   1. It is a PIN, not a fix. Moving the guards above those early returns
    //      changes WHICH HEADERS ARE ACCEPTED on a live path, so it is a behaviour
    //      change that needs its own contract and its own review. It is deliberately
    //      not done inside this change.
    //   2. ⛔ REACHABILITY IS NOT TRACED. Whether an unknown-parent header reaches
    //      CalculateChainWork in production is UNKNOWN. "the guard is skipped" is NOT
    //      the same claim as "work is accumulated for it", and nobody has measured
    //      the second. Do not upgrade this to an exploitable path without doing so.
    //   3. The two validators DISAGREE about when nBits is checked at all —
    //      QuickValidateHeader unconditionally, ValidateHeader only after the parent
    //      resolves. Two paths, one predicate, different reachability. That asymmetry
    //      is the shape to recognise, not this one instance of it.
    //
    // If this assertion ever FAILS, the behaviour changed and that is good news — but
    // update the row and the reasoning rather than deleting the arm.
    Check("PROD/Validate: MEASURED LIMITATION — a poison header with an UNKNOWN "
          "parent is accepted, because both nBits guards sit below the "
          "pprev/parent early returns",
          mgr.ValidateHeader(HeaderWithNBits(0x1e000000u), nullptr));

    // And with a KNOWN parent the guards ARE reached, which is what makes the fix
    // load-bearing on the path that resolves parents.
    //
    // ⚠️ HOW TO REACH THIS PATH AT ALL, recorded so the next arm does not burn the
    // same hour. The lookup is `mapHeaders.find(pprev->GetHash())` — it keys on the
    // PARENT'S OWN HASH in the manager's map, not on header.hashPrevBlock and not on
    // the pointer. So passing a stack-allocated header as `pprev` is NOT enough: it
    // is not in mapHeaders, the `parentIt == mapHeaders.end()` early return fires, and
    // ValidateHeader returns true without checking anything. The first version of this
    // arm did exactly that and its four failures looked like a broken fix.
    //
    // GENESIS is the one parent a FRESH manager genuinely knows, because the
    // constructor inserts it into mapHeaders. That makes it the cheapest — and
    // currently the only cheap — way to exercise the post-parent-resolution branch.
    Check("PROD/Validate: honest nBits accepted with a KNOWN parent",
          mgr.ValidateHeader(ChildOf(0x1d00ffffu), &genesisHeader));
    Check("PROD/Validate: zero-mantissa REJECTED with a KNOWN parent",
          !mgr.ValidateHeader(ChildOf(0x1e000000u), &genesisHeader));
    Check("PROD/Validate: inflated work REJECTED with a KNOWN parent",
          !mgr.ValidateHeader(ChildOf(0x01000001u), &genesisHeader));

    // ---- ACCUMULATED WORK, the observable rather than a verdict --------------
    //
    // ⛔ THE FIRST VERSION OF THIS BLOCK COULD PASS FOR THE WRONG REASON, and review
    // caught it. Its poison headers were PARENTLESS — hashPrevBlock was never set —
    // so they were liable to be dropped as unknown-parent orphans BEFORE any nBits
    // guard ran. "work did not advance" is then true because nothing was processed,
    // which is indistinguishable from "the guard rejected it".
    //
    // Two changes make the arm discriminate:
    //   1. the poison headers are PARENTED TO GENESIS, so they transit the guarded
    //      path rather than being discarded upstream of it;
    //   2. an HONEST control must make best-header work ADVANCE. Without it, a build
    //      in which ProcessHeaders silently did nothing at all would pass every
    //      assertion here.
    // ⛔ ZERO BOUND — THE REGTEST/TESTNET CONFIGURATION, AND THE ONE THAT PROVES THE
    // SATURATION GUARD IS WIRED AT ALL.
    //
    // CONFIRMED BY FIXTURE MUTATION before this arm existed: removing the saturation
    // guard from BOTH production validators left the whole suite PASSING, because the
    // 2^200 bound below rejects saturated work anyway. So every arm in this file was
    // consistent with the saturation guard never having been wired.
    //
    // With a ZERO bound the magnitude predicate is inert by design, so saturation is
    // the ONLY guard — which is exactly the configuration regtest and testnet run.
    {
        uint256 zeroBound; std::memset(zeroBound.data, 0, 32);
        CHeadersManager z(zeroBound);

        // The inflation class is ACCEPTED here, and that is correct, not a bug: the
        // bound is what rejects it and the bound is inert. Asserted so the arm states
        // the exposure rather than leaving it implied.
        Check("ZERO-BOUND: inflated nBits is ACCEPTED when the bound is inert "
              "(the class is unguarded on a zero-bound network)",
              z.QuickValidateHeader(HeaderWithNBits(0x01000001u), nullptr));

        // ⛔ But saturation must STILL be rejected — this is the arm that dies if the
        // saturation guard is removed from the validators.
        Check("ZERO-BOUND: zero-mantissa is STILL REJECTED with an inert bound "
              "(saturation is the only guard here)",
              !z.QuickValidateHeader(HeaderWithNBits(0x1e000000u), nullptr));
        Check("ZERO-BOUND: zero-mantissa is STILL REJECTED by ValidateHeader with a known parent",
              !z.ValidateHeader(ChildOf(0x1e000000u), &genesisHeader));

        // And an honest header still passes, so the arm is not "reject everything".
        Check("ZERO-BOUND: honest nBits still accepted",
              z.QuickValidateHeader(HeaderWithNBits(0x1d00ffffu), nullptr));
    }

    {
        // The control FIRST: if this does not advance, every "did not advance" below
        // proves nothing, and the arm says so by failing here rather than passing
        // quietly further down.
        CHeadersManager ctrl(ThresholdBetweenHonestAndInflated());
        const uint256 ctrl_before = ctrl.GetBestHeaderChainWork();
        ctrl.ProcessHeaders(7, std::vector<CBlockHeader>{ChildOf(0x1d00ffffu)});
        const uint256 ctrl_after = ctrl.GetBestHeaderChainWork();
        // ADVANCED, not merely CHANGED. `memcmp != 0` would also be satisfied by work
        // going DOWN, which is not the property being relied on below.
        Check("PROD/Process CONTROL: an HONEST parented header ADVANCES best-header "
              "work (without this, the 'did not advance' arms below are vacuous)",
              ::dilithion::consensus::ChainWorkGreaterOrEqual(ctrl_after, ctrl_before) &&
                  std::memcmp(ctrl_before.data, ctrl_after.data, 32) != 0);
    }

    for (uint32_t nBits : {0x1e000000u, 0x01000001u}) {
        CHeadersManager fresh(ThresholdBetweenHonestAndInflated());
        const uint256 before = fresh.GetBestHeaderChainWork();
        fresh.ProcessHeaders(7, std::vector<CBlockHeader>{ChildOf(nBits)});
        const uint256 after = fresh.GetBestHeaderChainWork();
        Check("PROD/Process: best-header work is not SATURATED after a poison header",
              !IsSaturated(after));
        Check("PROD/Process: best-header work did not advance on a rejected header",
              std::memcmp(before.data, after.data, 32) == 0);
    }

    std::cout << " OK" << std::endl;
}


// ---------------------------------------------------------------------------
// ⛔ ARM 5 — PIN THE MASK. Review found that the refuted 0x007FFFFF mask, and also
// 0x0000FFFF and 0x000000FF, would pass every arm in this file: every honest arm
// has low mantissa bytes set and every poison arm has a zero mantissa, so a
// NARROWER mask accepts everything the honest arms accept and rejects everything
// the poison arms reject. The suite could not tell the masks apart.
//
// These arms fail for any mask narrower than the producer's 0x00FFFFFF, which also
// converts the settled-by-measurement sign-bit question into a test so it cannot be
// re-raised as a finding.
// ---------------------------------------------------------------------------
void test_mask_matches_the_producer_and_is_pinned()
{
    std::cout << "  test_mask_matches_the_producer_and_is_pinned..." << std::flush;
    using ::dilithion::consensus::NBitsUsableForWork;
    using ::dilithion::consensus::ComputeChainWork;

    // ⛔ EVERY ONE OF THE 24 MANTISSA BITS, not four hand-picked vectors.
    //
    // The previous version tested bit 23 and bit 16 only, and review found that
    // 0x0081FFFF passes both while still wrongly rejecting mantissas of bits 17-22.
    // Hand-picked vectors can only refute the masks someone thought of; this loop
    // refutes EVERY mask narrower than the producer's, because a narrower mask must
    // drop at least one bit and that bit's arm then fails.
    //
    // This is the whole input space for the property, so it is exhaustive rather than
    // sampled — the point review made about hand-picked vectors, taken to its end.
    for (int bit = 0; bit < 24; ++bit) {
        const uint32_t nBits = 0x1d000000u | (1u << bit);
        Check("MASK: every isolated mantissa bit is accepted (a narrower mask fails here)",
              NBitsUsableForWork(nBits));
        Check("MASK: an isolated mantissa bit does not saturate",
              !IsSaturated(ComputeChainWork(nBits)));
    }

    // And the boundary the mask exists for is still rejected.
    Check("MASK: 0x1e000000 (zero mantissa) is still rejected",
          !NBitsUsableForWork(0x1e000000u));

    std::cout << " OK" << std::endl;
}

// ---------------------------------------------------------------------------
// ⛔ ARM 6 — DIRECT ARMS FOR THE BOUND. Review found it had none, so four distinct
// mutations went uncaught: deleting the zero-bound early return; weakening >= to >;
// an off-by-one in the 32-byte zero scan; and substituting a hardcoded 2^200 cap for
// the parameter, which arm 4 could not detect because arm 4 injects exactly 2^200.
// ---------------------------------------------------------------------------
void test_single_header_bound_direct()
{
    std::cout << "  test_single_header_bound_direct..." << std::flush;
    using ::dilithion::consensus::SingleHeaderWorkIsWithinBound;
    using ::dilithion::consensus::ComputeChainWork;

    // ZERO BOUND is inert — and this is load-bearing in production, not a nicety:
    // regtest and testnet run nMinimumChainWork = 0, and without the early return
    // every header on those networks would be REJECTED.
    uint256 zero; std::memset(zero.data, 0, 32);
    Check("BOUND: a zero bound is inert (honest)", SingleHeaderWorkIsWithinBound(0x1d00ffffu, zero));
    Check("BOUND: a zero bound is inert (inflated)", SingleHeaderWorkIsWithinBound(0x01000001u, zero));

    // Off-by-one in the 32-byte zero scan: a bound that is non-zero ONLY in the first
    // or ONLY in the last byte must NOT be treated as zero.
    uint256 lowByte; std::memset(lowByte.data, 0, 32); lowByte.data[0] = 0x01;
    Check("BOUND: non-zero in byte 0 is not treated as a zero bound",
          !SingleHeaderWorkIsWithinBound(0x1d00ffffu, lowByte));
    // ⛔ THIS ARM USED HONEST WORK AND WAS NON-DISCRIMINATING. Honest work (~2^76) is
    // below 2^248 whether byte 31 is scanned or the bound is wrongly treated as zero,
    // so an `i < 31` off-by-one passed it unchanged — review found that, and the
    // previous comment claimed the case was covered. SATURATED work is the only input
    // that separates the two: it is ABOVE 2^248, so it is rejected only if byte 31 is
    // actually scanned; treat the bound as zero and the inert path accepts it.
    uint256 highByte; std::memset(highByte.data, 0, 32); highByte.data[31] = 0x01;
    Check("BOUND: byte 31 IS scanned — saturated work is rejected against a "
          "bound that is non-zero only in its top byte",
          !SingleHeaderWorkIsWithinBound(0x1e000000u, highByte));

    // EQUALITY: single work EXACTLY equal to the bound must be REJECTED (>= not >).
    const uint256 honestWork = ComputeChainWork(0x1d00ffffu);
    Check("BOUND: work exactly EQUAL to the bound is rejected (>= not >)",
          !SingleHeaderWorkIsWithinBound(0x1d00ffffu, honestWork));

    // JUST BELOW: a bound one unit above that work must accept it.
    uint256 justAbove = honestWork;
    for (int i = 0; i < 32; ++i) { if (++justAbove.data[i] != 0) break; }
    Check("BOUND: work just BELOW the bound is accepted",
          SingleHeaderWorkIsWithinBound(0x1d00ffffu, justAbove));

    // ⛔ THE PRODUCTION PARAMETER, not a test constant. Arm 4 injects exactly 2^200,
    // so a hardcoded 2^200 substituted for the parameter would pass it. This uses the
    // chain's real nMinimumChainWork against its real genesisNBits.
    // ⛔ A NETWORK WITH A NON-ZERO BOUND, because main() runs Regtest where
    // nMinimumChainWork == 0 and the arm below therefore only ever exercised the
    // INERT path — asserting the accept direction and nothing else. Any constant
    // between honest work and the inflation class passed it, and arm 4 injects
    // exactly 2^200 so it could not catch a hardcoded substitution either.
    // This uses a REAL ChainParams whose bound is non-zero, so the reject direction
    // is exercised against a value nothing in this file chose.
    {
        const Dilithion::ChainParams dilv = Dilithion::ChainParams::DilV();
        bool nonZero = false;
        for (int i = 0; i < 32; ++i) if (dilv.nMinimumChainWork.data[i] != 0) { nonZero = true; break; }
        Check("BOUND/prod: the DilV parameters carry a NON-ZERO nMinimumChainWork "
              "(if this fails the arm below is inert and proves nothing)", nonZero);
        if (nonZero) {
            Check("BOUND/prod: an inflated header is REJECTED against the real DilV bound",
                  !SingleHeaderWorkIsWithinBound(0x01000001u, dilv.nMinimumChainWork));
            Check("BOUND/prod: the real DilV genesisNBits is ACCEPTED against the real bound",
                  SingleHeaderWorkIsWithinBound(dilv.genesisNBits, dilv.nMinimumChainWork));
        }
    }

    if (Dilithion::g_chainParams != nullptr) {
        const uint256 prodBound = Dilithion::g_chainParams->nMinimumChainWork;
        const uint32_t prodNBits = Dilithion::g_chainParams->genesisNBits;
        bool boundIsZero = true;
        for (int i = 0; i < 32; ++i) if (prodBound.data[i] != 0) { boundIsZero = false; break; }
        // An honest genesis header must never be rejected by this bound on any network.
        Check("BOUND: real genesisNBits is within the real nMinimumChainWork",
              SingleHeaderWorkIsWithinBound(prodNBits, prodBound));
        // Stated rather than asserted: on this network the bound may be zero, in which
        // case the check above passed via the inert path. That is recorded, not hidden.
        if (boundIsZero) {
            std::cout << "\n    [note] this network's nMinimumChainWork is ZERO, so the "
                         "production arm above exercised the INERT path" << std::flush;
        }
    }

    std::cout << " OK" << std::endl;
}

int main()
{
    Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    std::cout << "nbits_work_saturation_tests" << std::endl;

    test_zero_mantissa_saturates_and_is_rejected();
    test_honest_nbits_still_accepted();
    test_mantissa_one_is_accepted_zero_is_not();
    test_production_validators_reject_both_classes();
    test_mask_matches_the_producer_and_is_pinned();
    test_single_header_bound_direct();

    if (g_failures != 0) {
        std::cerr << "nbits_work_saturation_tests: " << g_failures << " FAILURE(S)" << std::endl;
        return 1;
    }
    std::cout << "nbits_work_saturation_tests: ALL PASS" << std::endl;
    return 0;
}
