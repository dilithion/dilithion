// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// CBlockIndex::GetAncestor() SKIP-CONDITION REGRESSION
// ====================================================
//
// The skip-follow condition in GetAncestor was:
//
//     (pindexWalk->pskip->nHeight >= height || heightSkip < heightSkipPrev)
//
// The second disjunct fires whenever the skip target for this height sits BELOW
// the skip target for the height beneath it - which is precisely when following
// pskip lands PAST the block being looked for. It licenses the overshoot that
// Bitcoin Core's condition forbids:
//
//     (heightSkip == height ||
//      (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
//                                heightSkipPrev >= height)))
//
// MEASURED before the fix, over all 8,390,656 (from,to) pairs of a 4096-block
// chain, against the real block_index.o: 8,364,034 wrong-height returns (99.68%)
// with a correctly built skip list, and 8,380,908 (99.88%) when the skip list is
// itself built through the broken function. Core's condition: 0 in both. The
// canonical case is chain[8].GetAncestor(7), which returned GENESIS because
// GetSkipHeight(8)=0 < GetSkipHeight(7)=1.
//
// WHY IT SHIPPED HARMLESS, and why that is the point. pskip is INERT in this
// tree: there is no BuildSkip, both constructors set pskip = nullptr and the
// copy-ctor copies a nullptr, so every CBlockIndex the node creates has a null
// skip pointer and GetAncestor degrades to a plain pprev walk. MODE A below is
// that state and it was always correct. The defect is a landmine armed the day
// somebody adds BuildSkip() - and chain.cpp already carries a comment
// anticipating exactly that. Two other comments in the tree describe the skip
// list as live and O(log n), which is what would lead someone to "finish" the
// port and arm it.
//
// So this suite is not defending a live bug. It is defending the CONDITION
// itself, in the state where it is unreachable, so that adding BuildSkip later
// is a safe change rather than a silent consensus break: 22 production call
// sites include checkpoint enforcement, the PoW difficulty anchor, fork-point
// resolution and locator building, and every failure is a WRONG INDEX rather
// than a nullptr, so no caller's null check would catch it.
//
// The three modes are the harness's, kept so the numbers above are reproducible
// in-tree rather than only in a report:
//   MODE A - pskip null everywhere. Production. Was correct, must stay correct.
//   MODE B - skip list built from ground truth by an independent pprev walk.
//            Was 99.68% wrong. Must be 0.
//   MODE C - skip list built by Core's BuildSkip recipe run through THIS
//            function, so errors compound. Was 99.88% wrong. Must be 0, and the
//            skip list it produces must itself be well formed.
//
// The skip-height schedule comes from bitest::GetSkipHeightForTest, a forwarder
// to the file-static GetSkipHeight, so the test builds its lists with the tree's
// own recipe. A copied helper could drift from production and the test would
// then certify a schedule the real walk does not use.

#include <boost/test/unit_test.hpp>

#include <node/block_index.h>

#include <cstdint>
#include <cstdlib>
#include <vector>

namespace {

// A linear chain of N indices: nHeight = i, pprev = &chain[i-1], pskip null.
// The vector is sized once and never resized, so the interior pointers are
// stable for the lifetime of the test.
std::vector<CBlockIndex> MakeLinearChain(int n)
{
    std::vector<CBlockIndex> chain(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        chain[static_cast<size_t>(i)].nHeight = i;
        chain[static_cast<size_t>(i)].pprev = (i == 0) ? nullptr : &chain[static_cast<size_t>(i - 1)];
        chain[static_cast<size_t>(i)].pskip = nullptr;
    }
    return chain;
}

// The true ancestor, found without consulting pskip at all. This is the oracle:
// deriving it from GetAncestor would make the test agree with itself.
CBlockIndex* TrueAncestor(CBlockIndex* from, int height)
{
    CBlockIndex* p = from;
    while (p != nullptr && p->nHeight > height) p = p->pprev;
    return p;
}

struct Mismatch {
    long long pairs = 0;
    long long wrong = 0;
    long long nulls = 0;
    int firstFrom = -1, firstTo = -1, firstGot = -1;
};

// Every (from, to) pair with to <= from. No sampling: the failure rate varies
// per pair, so a sample would certify only itself.
Mismatch EnumerateAllPairs(std::vector<CBlockIndex>& chain)
{
    Mismatch m;
    const int n = static_cast<int>(chain.size());
    for (int from = 0; from < n; ++from) {
        for (int to = 0; to <= from; ++to) {
            ++m.pairs;
            CBlockIndex* got = chain[static_cast<size_t>(from)].GetAncestor(to);
            if (got == nullptr) {
                ++m.nulls; ++m.wrong;
            } else if (got->nHeight != to) {
                ++m.wrong;
            } else {
                continue;
            }
            if (m.firstFrom < 0) {
                m.firstFrom = from; m.firstTo = to;
                m.firstGot = (got == nullptr) ? -1 : got->nHeight;
            }
        }
    }
    return m;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(block_index_getancestor_skip_tests)

// N matches the harness for MODE B and MODE C. The pair count is computed, not
// asserted from memory.
static const int kN = 4096;

// MODE A runs a SMALLER complete census, and the reason is structural rather
// than a concession. With pskip null on every index the ported condition is
// never evaluated at all: `pindexWalk->pskip != nullptr &&` short-circuits false
// at every step, so MODE A exercises the pprev fallback loop, whose behaviour
// does not vary with absolute height. [measured] MODE A at 4096 costs 57s of the
// suite's 59s - the walk is O(from-to), so full enumeration is O(N^3) - while B
// and C, the arms that actually regressed, are under a second each because a
// skip list makes the walk logarithmic. Paying 57s per CI run to re-census a
// path the change cannot reach is the wrong trade.
//
// It is still a COMPLETE census over its chain, not a sample: every (from,to)
// pair with to <= from. Set DILITHION_GETANCESTOR_MODE_A_N=4096 to reproduce the
// harness figure exactly.
static int ModeAChainLength()
{
    if (const char* env = std::getenv("DILITHION_GETANCESTOR_MODE_A_N")) {
        const int n = std::atoi(env);
        if (n > 1 && n <= 65536) return n;
    }
    return 512;
}

// MODE A - production state: pskip null on every index, so GetAncestor is a
// plain pprev walk. This arm was ALREADY passing before the fix; it is here to
// prove the fix did not break the path the node actually takes today.
BOOST_AUTO_TEST_CASE(getancestor_mode_a_no_skip_list_is_exact)
{
    const int n = ModeAChainLength();
    std::vector<CBlockIndex> chain = MakeLinearChain(n);

    long long nonNull = 0;
    for (const CBlockIndex& b : chain) if (b.pskip != nullptr) ++nonNull;
    BOOST_REQUIRE_MESSAGE(nonNull == 0,
        "MODE A must have no skip pointers at all, found " << nonNull);

    const Mismatch m = EnumerateAllPairs(chain);
    BOOST_CHECK_MESSAGE(m.pairs == static_cast<long long>(n) * (n + 1) / 2,
        "MODE A census incomplete: " << m.pairs << " pairs for n=" << n);
    BOOST_CHECK_MESSAGE(m.wrong == 0,
        "MODE A (production, pskip null) returned " << m.wrong << " wrong-height "
        "indices out of " << m.pairs << "; first was ("
        << m.firstFrom << "," << m.firstTo << ")->" << m.firstGot);
    BOOST_CHECK_EQUAL(m.nulls, 0);
}

// MODE B - a CORRECT skip list, built by an independent pprev walk rather than
// by GetAncestor, so the input cannot inherit GetAncestor's own errors. This is
// the arm that was 8,364,034 / 8,390,656 wrong (99.68%).
BOOST_AUTO_TEST_CASE(getancestor_mode_b_correct_skip_list_never_overshoots)
{
    std::vector<CBlockIndex> chain = MakeLinearChain(kN);

    for (int i = 1; i < kN; ++i) {
        const int want = bitest::GetSkipHeightForTest(i);
        chain[static_cast<size_t>(i)].pskip = TrueAncestor(&chain[static_cast<size_t>(i)], want);
    }

    // The fixture itself must be sound before it can indict the function.
    long long badTargets = 0;
    for (int i = 1; i < kN; ++i) {
        const CBlockIndex* sk = chain[static_cast<size_t>(i)].pskip;
        if (sk == nullptr || sk->nHeight != bitest::GetSkipHeightForTest(i)) ++badTargets;
    }
    BOOST_REQUIRE_MESSAGE(badTargets == 0,
        "MODE B fixture is not ground truth: " << badTargets << " skip targets "
        "are at the wrong height, so a pass here would prove nothing");

    const Mismatch m = EnumerateAllPairs(chain);
    BOOST_CHECK_EQUAL(m.pairs, static_cast<long long>(kN) * (kN + 1) / 2);
    BOOST_CHECK_MESSAGE(m.wrong == 0,
        "MODE B (correct skip list) returned " << m.wrong << " wrong-height indices "
        "out of " << m.pairs << "; first was (" << m.firstFrom << "," << m.firstTo
        << ")->" << m.firstGot << ". Before the condition port this was 8364034.");
    BOOST_CHECK_EQUAL(m.nulls, 0);
}

// MODE C - Core's BuildSkip recipe executed with THIS function, in height order,
// so any error in GetAncestor feeds back into the skip list and compounds. This
// arm was 8,380,908 / 8,390,656 wrong (99.88%), and 4,072 of the 4,095 skip
// targets it produced were themselves at the wrong height.
BOOST_AUTO_TEST_CASE(getancestor_mode_c_self_built_skip_list_is_well_formed)
{
    std::vector<CBlockIndex> chain = MakeLinearChain(kN);

    for (int i = 1; i < kN; ++i) {
        const int want = bitest::GetSkipHeightForTest(i);
        chain[static_cast<size_t>(i)].pskip =
            chain[static_cast<size_t>(i - 1)].GetAncestor(want);
    }

    long long badTargets = 0;
    for (int i = 1; i < kN; ++i) {
        const CBlockIndex* sk = chain[static_cast<size_t>(i)].pskip;
        if (sk == nullptr || sk->nHeight != bitest::GetSkipHeightForTest(i)) ++badTargets;
    }
    BOOST_CHECK_MESSAGE(badTargets == 0,
        "MODE C: BuildSkip run through GetAncestor produced " << badTargets
        << " skip targets at the wrong height (was 4072 before the port). A "
        "self-built skip list is how the real BuildSkip would populate the tree.");

    const Mismatch m = EnumerateAllPairs(chain);
    BOOST_CHECK_EQUAL(m.pairs, static_cast<long long>(kN) * (kN + 1) / 2);
    BOOST_CHECK_MESSAGE(m.wrong == 0,
        "MODE C (self-built skip list) returned " << m.wrong << " wrong-height "
        "indices out of " << m.pairs << "; first was (" << m.firstFrom << ","
        << m.firstTo << ")->" << m.firstGot << ". Before the port this was 8380908.");
    BOOST_CHECK_EQUAL(m.nulls, 0);
}

// The canonical case from the report, kept as its own named assertion so a
// failure says WHICH defect came back rather than only a count. With a correct
// skip list, chain[8].GetAncestor(7) returned genesis: GetSkipHeight(8) = 0 is
// below GetSkipHeight(7) = 1, so the old second disjunct fired and the walk
// jumped straight past the target to height 0.
BOOST_AUTO_TEST_CASE(getancestor_canonical_8_to_7_does_not_return_genesis)
{
    std::vector<CBlockIndex> chain = MakeLinearChain(16);
    for (int i = 1; i < 16; ++i) {
        chain[static_cast<size_t>(i)].pskip =
            TrueAncestor(&chain[static_cast<size_t>(i)], bitest::GetSkipHeightForTest(i));
    }

    // The precondition that armed the bug must actually hold, or this case
    // passes for the wrong reason.
    BOOST_REQUIRE_EQUAL(bitest::GetSkipHeightForTest(8), 0);
    BOOST_REQUIRE_EQUAL(bitest::GetSkipHeightForTest(7), 1);

    const CBlockIndex* got = chain[8].GetAncestor(7);
    BOOST_REQUIRE(got != nullptr);
    BOOST_CHECK_MESSAGE(got->nHeight == 7,
        "chain[8].GetAncestor(7) returned height " << got->nHeight
        << " (genesis overshoot is the original defect)");
}

// Edges, so the ported condition is not verified only in the interior.
BOOST_AUTO_TEST_CASE(getancestor_edges_unchanged_by_the_port)
{
    std::vector<CBlockIndex> chain = MakeLinearChain(64);
    for (int i = 1; i < 64; ++i) {
        chain[static_cast<size_t>(i)].pskip =
            TrueAncestor(&chain[static_cast<size_t>(i)], bitest::GetSkipHeightForTest(i));
    }

    BOOST_CHECK(chain[10].GetAncestor(11) == nullptr);   // above this block
    BOOST_CHECK(chain[10].GetAncestor(-1) == nullptr);   // negative
    BOOST_CHECK(chain[10].GetAncestor(10) == &chain[10]); // self, no walk
    BOOST_REQUIRE(chain[63].GetAncestor(0) != nullptr);
    BOOST_CHECK_EQUAL(chain[63].GetAncestor(0)->nHeight, 0);
    BOOST_CHECK(chain[0].GetAncestor(0) == &chain[0]);
}

BOOST_AUTO_TEST_SUITE_END()
