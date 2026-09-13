// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 A-2 / F3 — a SINGLE header must not satisfy the minimum-chain-work gate
// on its own, and a VDF header must not pass unchecked.
//
// WHY THIS SUITE EXISTS. Blocker 1 added a saturation predicate (then named
// NBitsIsSaneForWorkAccounting, since UNIFIED into
// dilithion::consensus::NBitsUsableForWork in chain_work.h — there were two copies
// of one predicate and they could drift), which
// rejects a ZERO MANTISSA because ComputeChainWork saturates there. F3 asked
// whether zero mantissa was the only shape that mattered. It is not. Measured
// against ComputeChainWork directly:
//
//   nBits        size  mantissa   work, top 4 bytes (LE, MSB side)
//   0x1d00ffff    29   0x00ffff   00000000…   DilV genesis, ~2^80, honest
//   0x1e000000    30   0x000000   ffffffff…   saturated — rejected by blocker 1
//   0x00000001     0   0x000001   ff000000…   ~2^255 — ACCEPTED by blocker 1
//   0x01000001     1   0x000001   ff000000…   ~2^255 — ACCEPTED by blocker 1
//
// A SMALL exponent lands the quotient at the top of the 256-bit word. One header
// then claims within a factor of two of the maximum without ever touching the
// mantissa test — the same defeat of the gate that blocker 1 closed, through a
// different door. Enumerating encodings was the wrong instrument, so the fix
// bounds the PROPERTY instead: no single header may reach nMinimumChainWork.
//
// ⚠️ WHAT THIS SUITE DOES NOT CLAIM. The PRESYNC gate has no production callers
// on this tree — the F4 census measured that, and it has not changed. These arms
// construct HeadersSyncState directly. They prove the bound holds WHEN the gate
// is armed; they are not evidence that anything arms it.
//
// ⚠️ WHY A CHECKER IS INJECTED IN EVERY ARM, and this is load-bearing: with
// proof_checker = nullptr the fallback runs CheckProofOfWork(hash, nBits), which
// would reject nBits = 0x00000001 all by itself — for having an unreachable
// target, not for inflating the gate. The arm would then pass for the wrong
// reason and would keep passing with the bound deleted. An always-valid checker
// removes that confound, and mirrors production, which always injects one.

#include <net/headerssync.h>
#include <net/iheader_proof_checker.h>

#include <consensus/chain_work.h>
#include <primitives/block.h>

#include <iostream>
#include <vector>

namespace {

// Not assert(), and the REASON matters because the obvious one is WRONG.
//
// The obvious reason -- "this repo ships -DNDEBUG release builds, so assert()
// compiles away" -- does not apply to test objects. The Makefile carries the rule
// `$(OBJ_DIR)/test/%.o: override CXXFLAGS += -UNDEBUG` (:1443 on this branch,
// :1429 on main -- grep the rule, not the line), added precisely so an
// assert-based suite cannot be silently disarmed, and `override` specifically so
// that `make CXXFLAGS=...` cannot drop it. Anything built through this Makefile
// keeps its assertions.
//
// What REQUIRE() actually buys: the -UNDEBUG rule protects only objects built
// THROUGH the Makefile. A suite compiled by another path -- an IDE, a hand-written
// g++ line, a future CMake target -- would strip assert() and print ALL PASS while
// checking nothing. REQUIRE() holds the property for every build path, not just
// the one we control.
void RequireTrue(const char* what, bool ok)
{
    if (!ok) {
        std::cerr << "\n  FAIL " << what << std::endl;
        std::abort();
    }
}
#define REQUIRE(cond) RequireTrue(#cond, (cond))

using dilithion::consensus::AddChainWork;
using dilithion::consensus::ComputeChainWork;

// Accepts every proof, so the ONLY thing that can reject a header in these arms
// is the work bound under test. See the note at the top of the file.
class AlwaysValidChecker final : public ::dilithion::net::IHeaderProofChecker {
public:
    bool CheckHeaderProof(const CBlockHeader&) const override { return true; }
    uint256 ChainWorkContribution(const CBlockHeader& h) const override
    {
        return ComputeChainWork(h.nBits);
    }
    bool ChainWorkGreaterThan(const uint256& a, const uint256& b) const override
    {
        for (int i = 31; i >= 0; --i) {
            if (a.data[i] > b.data[i]) return true;
            if (a.data[i] < b.data[i]) return false;
        }
        return false;
    }
};

uint256 ChainStartHash()
{
    uint256 h;
    h.data[0] = 0xA1;  // opaque; PRESYNC never dereferences it
    return h;
}

CBlockHeader MakeHeader(uint32_t nBits, const uint256& prev, bool vdf = false)
{
    CBlockHeader h;
    h.nVersion = vdf ? CBlockHeader::VDF_VERSION : 1;
    h.nBits = nBits;
    h.nTime = 1700000000;
    h.nNonce = 0;
    h.hashPrevBlock = prev;
    if (vdf) {
        for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0x42;
        for (int i = 0; i < 32; ++i) h.vdfOutput.data[i] = 0x37;
    }
    return h;
}

// ⚠️ THIS NUMBER WAS MEASURED, AND THE FIRST ONE I CHOSE WAS WRONG.
//
// The bound refuses a header whose OWN work reaches the threshold, so it is only
// honest while nMinimumChainWork exceeds a single block's work at the chain's
// HARDEST REACHABLE difficulty. My first threshold, 1,000 units, made the arm
// below fail on 0x1b0404cb, and that failure forced this measurement.
//
// ⛔ CORRECTED 2026-09-13 — 0x1b0404cb IS NOT A REACHABLE DIFFICULTY ON ANY
// DILITHION NETWORK. An earlier revision of this comment described it as a real,
// reachable difficulty. That was never measured, and it is false: every retarget
// path clamps at MIN_DIFFICULTY_BITS = 0x1d00ffff, the hardest target any network
// can emit, and consensus enforces nBits == GetNextWorkRequired, so no honest
// header carries 0x1b0404cb (it is a Bitcoin fixture). The failure at 1,000 units
// was therefore not an honest-ban. The vector is kept for a different reason —
// see the arm.
//
// Crossovers, ramping the threshold in integer multiples of one unit =
// work(0x1d00ffff) = 2^72 exactly, against ComputeChainWork:
//
//   nBits        refused while the threshold is below …   reachable?
//   0x1e01fffe   1 unit (ramp granularity; true 1/512)     DIL mainnet genesis
//   0x1d00ffff   2 units                                   yes: the hardest any network emits
//   0x1b0404cb   16,308 units (16,307.4 measured)          NO: synthetic, see the arm
//   0x00000001   still refused at 2,000,000                no: the abusive shape
//
// The honest crossover is 2 units. This suite's 200,000-unit threshold sits five
// orders of magnitude above it and 10x below the abusive floor, so the bound
// discriminates rather than merely fires.
//
// ⛔ ACTIVATION PREREQUISITE, WRITTEN HERE BECAUSE THIS IS WHERE IT IS PROVABLE:
// whoever sets nMinimumChainWork must keep it above one block's work at the
// hardest difficulty the chain reaches. It holds today by ~5 orders of
// magnitude; a fixed threshold plus a large difficulty rise erodes it, and the
// failure mode is refusing HONEST headers.
uint256 Threshold()
{
    uint256 t;
    for (int i = 0; i < 200000; ++i) t = AddChainWork(t, ComputeChainWork(0x1d00ffff));
    return t;
}

// Feed exactly one PRESYNC header and report whether it was accepted.
bool PresyncAcceptsHeader(uint32_t nBits, bool vdf, bool inject_checker)
{
    HeadersSyncParams params;
    AlwaysValidChecker checker;

    HeadersSyncState state(/*peer_id=*/1, params, ChainStartHash(),
                           /*chain_start_height=*/54000,
                           /*chain_start_work=*/uint256(), Threshold(),
                           inject_checker ? &checker : nullptr);

    std::vector<CBlockHeader> batch{MakeHeader(nBits, ChainStartHash(), vdf)};
    return state.ProcessNextHeaders(batch, /*full_headers_available=*/false).success;
}


// ============================================================================
// REDOWNLOAD — the sibling site, which the mutation matrix caught UNPROVEN
// ============================================================================
//
// ⛔ WHY THIS SECTION EXISTS. The first version of this suite drove PRESYNC only.
// Mutant N2 — delete the bound from ValidateAndStoreRedownloadedHeader, leave
// PRESYNC's — SURVIVED: 5/5 arms still green. A guard at one site with its
// sibling untested is the exact shape this mission keeps hitting, so the arm was
// added rather than the gap reported.
//
// ⚠️ THE COMMITMENT MACHINERY IS DELIBERATELY TAKEN OUT OF THE PICTURE.
// m_commit_offset is `std::random_device{}() % commitment_period`, so with the
// default 584 a commitment check would land on one of these heights often enough
// to make the arm flaky — and a flaky arm would attribute a rejection to the
// bound that actually came from a commitment mismatch. Setting the period to
// 1,000,000 means no commitment is recorded in phase 1 and none is consulted in
// phase 2. Residual, computed rather than counted: the offset collides with one
// of the ~5 heights used here with probability 5e-6.
HeadersSyncParams MakeWidePeriodParams()
{
    HeadersSyncParams p;
    p.commitment_period = 1000000;  // see the note above — not a tuning choice
    return p;
}

// Two honest headers linked from the chain start.
//
// VDF headers, and not by preference: linking requires calling GetHash() on the
// first header, and a RandomX header's GetHash() throws "RandomX VM not
// initialized" outside a mining context. VDF is also the chain this gate
// protects, and an AlwaysValidChecker is injected either way, so the proof path
// is not what is under test here.
std::vector<CBlockHeader> HonestChain()
{
    CBlockHeader h1 = MakeHeader(0x1d00ffff, ChainStartHash(), /*vdf=*/true);
    CBlockHeader h2 = MakeHeader(0x1d00ffff, h1.GetHash(),     /*vdf=*/true);
    h2.nNonce = 1;  // distinct header, still linked
    return {h1, h2};
}

// Run PRESYNC -> promote -> REDOWNLOAD, and report whether the phase-2 batch was
// accepted by ValidateAndStoreRedownloadedHeader.
bool RedownloadAcceptsBatch(const std::vector<CBlockHeader>& phase2)
{
    HeadersSyncParams params = MakeWidePeriodParams();
    AlwaysValidChecker checker;
    HeadersSyncState state(/*peer_id=*/1, params, ChainStartHash(),
                           /*chain_start_height=*/0,
                           /*chain_start_work=*/Threshold(), Threshold(), &checker);

    // ⛔ REWRITTEN FOR LP-10 F5/D-2. This used to promote by sending an EMPTY
    // batch — the invented transition Core refuses outright (headerssync.cpp:74).
    // Now it promotes the way upstream does: a REAL batch whose cumulative work
    // crosses the threshold. chain_start_work is seeded AT the threshold, so one
    // honest header is enough, and the work check inside the PRESYNC branch calls
    // EnterRedownloadPhase before this call returns.
    //
    // full_headers_available = true here so the promotion is the ONLY thing under
    // way; a non-full batch would also abort if the work check had not fired, and
    // this helper exists to reach REDOWNLOAD, not to test termination.
    state.ProcessNextHeaders({MakeHeader(0x1d00ffff, ChainStartHash(), /*vdf=*/true)},
                             /*full_headers_available=*/true);
    REQUIRE(state.GetState() == HeadersSyncState::State::REDOWNLOAD);

    return state.ProcessNextHeaders(phase2, /*full_headers_available=*/true).success;
}

}  // namespace

// ============================================================================
// The bound
// ============================================================================

void test_a_single_header_cannot_reach_the_gate()
{
    std::cout << "  test_a_single_header_cannot_reach_the_gate..." << std::flush;

    // THE HOLE, three encodings of it. Each yields ~2^255 work from one header
    // and each was accepted by the mantissa guard alone.
    // vdf=true, DELIBERATELY — keep it, even though THESE vectors could never flake. They are
    // REFUSED inside ValidateAndProcessSingleHeader (by the single-header work bound) before
    // ValidateAndStoreHeadersCommitments reaches the commitment hash, so as non-VDF headers they
    // never threw. They are flipped ONLY to keep this arm single-variable against its partner,
    // test_an_honest_header_still_passes_the_same_bound, which accepts — and as non-VDF DID throw "RandomX VM
    // not initialized" (this binary never creates a VM). Reverting these alone breaks the pairing.
    REQUIRE(!PresyncAcceptsHeader(0x00000001, /*vdf=*/true, /*inject_checker=*/true));
    REQUIRE(!PresyncAcceptsHeader(0x00000002, /*vdf=*/true, /*inject_checker=*/true));
    REQUIRE(!PresyncAcceptsHeader(0x01000001, /*vdf=*/true, /*inject_checker=*/true));

    // The shape blocker 1 already closed, re-pinned here. ⚠️ It pins the BOUND only: at this
    // 200,000-unit threshold saturated work is refused by the single-header work bound BEFORE the
    // mantissa guard runs, so this vector cannot detect a deleted mantissa guard.
    // test_zero_mantissa_is_refused_even_with_no_threshold covers that guard, with the bound inert.
    REQUIRE(!PresyncAcceptsHeader(0x1e000000, /*vdf=*/true, /*inject_checker=*/true));

    std::cout << " OK" << std::endl;
}

// THE DISCRIMINATING HALF. Without it, "reject every header" passes the arm
// above — and that is not a hypothetical: the bound compares against a
// threshold, and an inverted comparison would reject exactly everything honest.
void test_an_honest_header_still_passes_the_same_bound()
{
    std::cout << "  test_an_honest_header_still_passes_the_same_bound..." << std::flush;

    // Same threshold, same checker, same message shape — only nBits differs.
    // vdf=true, DELIBERATELY — do not return to MakeHeader's default. HeadersSyncState draws its
    // commitment offset at random per state and hashes an accepted header when it lands on that
    // slot (ValidateAndStoreHeadersCommitments). A NON-VDF header hashes through RandomX, and this
    // binary never initializes a RandomX VM, so a non-VDF vector threw "RandomX VM not initialized"
    // in 5 of 1,000 runs. With the proof checker injected, header type is incidental to the bound.
    REQUIRE(PresyncAcceptsHeader(0x1d00ffff, /*vdf=*/true, /*inject_checker=*/true));
    // ⛔ A SYNTHETIC MAGNITUDE PROBE, NOT A REACHABLE DIFFICULTY. DO NOT SWAP IT FOR
    // A PRODUCIBLE nBits.
    //
    // 0x1b0404cb is reachable on no Dilithion network (see the table above), and an
    // earlier revision of this comment was wrong to call it real. Its purpose
    // survives, though not the one that comment gave: this is the suite's ONLY
    // accept-direction vector anywhere near the threshold. The vector above is 1
    // unit; this one is ~16,307 against 200,000, so it pins the MAGNITUDE of the
    // comparison and not merely its direction.
    //
    // MEASURED 2026-09-13, MUTANT_M (the bound compared against bound / 256, an
    // effective threshold of ~781 units): the 0x1d00ffff REQUIRE above PASSED and
    // this one FAILED. The 1-unit vector cannot see that error and this one can,
    // so swapping it for a producible value deletes the only arm that catches it.
    // Resolution, derived rather than run: it catches an error that pushes the
    // effective threshold below ~16,307 units (more than ~12x); a smaller error
    // passes both vectors.
    REQUIRE(PresyncAcceptsHeader(0x1b0404cb, /*vdf=*/true, /*inject_checker=*/true));

    std::cout << " OK" << std::endl;
}

// The bound must be inert when no gate is configured, or every caller that
// leaves nMinimumChainWork at zero — every existing test harness among them —
// would start rejecting all traffic.
void test_a_zero_threshold_bounds_nothing()
{
    std::cout << "  test_a_zero_threshold_bounds_nothing..." << std::flush;

    HeadersSyncParams params;
    AlwaysValidChecker checker;
    HeadersSyncState state(/*peer_id=*/1, params, ChainStartHash(),
                           /*chain_start_height=*/54000,
                           /*chain_start_work=*/uint256(),
                           /*minimum_work=*/uint256(), &checker);

    // 0x00000001 is refused above under a real threshold; with no gate to
    // inflate, the work bound has nothing to say and the mantissa guard still
    // does its own job on 0x1e000000 (asserted separately below).
    // vdf=true, DELIBERATELY — do not return to MakeHeader's default. HeadersSyncState draws its
    // commitment offset at random per state and hashes an accepted header when it lands on that
    // slot (ValidateAndStoreHeadersCommitments). A NON-VDF header hashes through RandomX, and this
    // binary never initializes a RandomX VM, so a non-VDF vector threw "RandomX VM not initialized"
    // in 5 of 1,000 runs. With the proof checker injected, header type is incidental to the bound.
    std::vector<CBlockHeader> batch{MakeHeader(0x00000001, ChainStartHash(), /*vdf=*/true)};
    REQUIRE(state.ProcessNextHeaders(batch, false).success);

    std::cout << " OK" << std::endl;
}

// ...and the mantissa guard is NOT threshold-dependent. Saturation makes the
// accounting meaningless whether or not a gate is configured, so this arm keeps
// the two guards from being collapsed into one.
void test_zero_mantissa_is_refused_even_with_no_threshold()
{
    std::cout << "  test_zero_mantissa_is_refused_even_with_no_threshold..." << std::flush;

    HeadersSyncParams params;
    AlwaysValidChecker checker;
    HeadersSyncState state(/*peer_id=*/1, params, ChainStartHash(),
                           /*chain_start_height=*/54000,
                           /*chain_start_work=*/uint256(),
                           /*minimum_work=*/uint256(), &checker);

    // vdf=true, DELIBERATELY — keep it, even though THESE vectors could never flake. They are
    // REFUSED inside ValidateAndProcessSingleHeader (by NBitsUsableForWork, the mantissa guard) before
    // ValidateAndStoreHeadersCommitments reaches the commitment hash, so as non-VDF headers they
    // never threw. They are flipped ONLY to keep this arm single-variable against its partner,
    // test_a_zero_threshold_bounds_nothing, which accepts — and as non-VDF DID throw "RandomX VM
    // not initialized" (this binary never creates a VM). Reverting these alone breaks the pairing.
    std::vector<CBlockHeader> batch{MakeHeader(0x1e000000, ChainStartHash(), /*vdf=*/true)};
    REQUIRE(!state.ProcessNextHeaders(batch, false).success);

    std::cout << " OK" << std::endl;
}

// ============================================================================
// The unchecked-VDF fall-through
// ============================================================================

// ⛔ A VDF HEADER USED TO PASS WITH NO PROOF CHECK AT ALL. The fallback reads
// `else if (!header.IsVDFBlock())`, so with no injected checker a VDF header
// matched neither branch: nothing verified it, and its nBits still fed the work
// accumulator. An absent input silently becoming a permissive verdict is the
// fail-OPEN shape #189 shipped once.
void test_a_vdf_header_without_a_checker_is_refused()
{
    std::cout << "  test_a_vdf_header_without_a_checker_is_refused..." << std::flush;

    REQUIRE(!PresyncAcceptsHeader(0x1d00ffff, /*vdf=*/true, /*inject_checker=*/false));

    // THE DISCRIMINATING HALF. The same VDF header passes once a checker is present — so
    // this pins "refuse the UNCHECKED case", not "refuse VDF".
    // ⚠️ NOT TESTED HERE: the no-checker NON-VDF fallback (the `else if (!header.IsVDFBlock())`
    // PoW branch in ValidateAndProcessSingleHeader). That branch hashes through RandomX and this
    // binary never initializes a RandomX VM, so a non-VDF no-checker vector would throw rather
    // than exercise it.
    REQUIRE(PresyncAcceptsHeader(0x1d00ffff, /*vdf=*/true,  /*inject_checker=*/true));

    std::cout << " OK" << std::endl;
}


void test_the_redownload_site_carries_the_same_bound()
{
    std::cout << "  test_the_redownload_site_carries_the_same_bound..." << std::flush;

    // CONTROL FIRST, because it is what makes the reject attributable. The same
    // two headers that PRESYNC saw, replayed in phase 2, must be accepted — so
    // continuity holds and nothing else in this path is rejecting them.
    REQUIRE(RedownloadAcceptsBatch(HonestChain()));

    // Now the ONLY change is the second header's nBits. It still links to the
    // first, so continuity is identical to the control above and the bound is the
    // only thing that can refuse it.
    std::vector<CBlockHeader> abusive = HonestChain();
    abusive[1].nBits = 0x00000001;
    REQUIRE(!RedownloadAcceptsBatch(abusive));

    std::cout << " OK" << std::endl;
}

int main()
{
    std::cout << "\n=== LP-10 A-2 / F3: headers-sync work bound ===\n" << std::endl;
    test_a_single_header_cannot_reach_the_gate();
    test_an_honest_header_still_passes_the_same_bound();
    test_a_zero_threshold_bounds_nothing();
    test_zero_mantissa_is_refused_even_with_no_threshold();
    test_the_redownload_site_carries_the_same_bound();
    test_a_vdf_header_without_a_checker_is_refused();
    std::cout << "\nheaderssync_work_bound_tests: ALL PASS" << std::endl;
    return 0;
}
