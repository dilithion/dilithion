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
#include <consensus/pow.h>
#include <node/block_index.h>
#include <crypto/randomx_hash.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

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


// Same shape, but reporting whether the manager considers the network SUPPORTED
// at all, and whether the sync entry point actually refuses.
struct Support { bool supported; bool init_accepted; };

Support SupportUnder(const Dilithion::ChainParams& params)
{
    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::g_chainParams = new Dilithion::ChainParams(params);
    CHeadersManager mgr;
    const bool supported = mgr.ProofCheckerSupportsNetwork();
    // The refusal must be at the GATE, not merely reported by an accessor: a
    // flag nobody acts on is what this whole finding is about.
    const bool init_ok = mgr.InitializeDoSProtectedSync(/*peer=*/1, uint256());
    delete Dilithion::g_chainParams;
    Dilithion::g_chainParams = saved;
    return {supported, init_ok};
}

// ============================================================================
// ⛔ ASK THE PRODUCER. DO NOT COPY ITS TABLE.
// ============================================================================
//
// The first version of this suite hardcoded the answer per network — "DilV yes,
// regtest yes, testnet no, mainnet no". Two external seats caught it (grok HIGH,
// gpt6 MEDIUM) and they were right: `grep -c GetNextWorkRequired` in this file
// was ZERO. A suite that COPIES the producer's set cannot detect that set
// CHANGING — which is the very two-predicate drift this PR exists to close,
// reproduced inside the test written to close it. A fifth network, or a change to
// pow.cpp's constant branch in either direction (:1142-1146 at 763c5a06), stayed green unless someone remembered
// to edit the table in lockstep.
//
// So the expected value is DERIVED by calling GetNextWorkRequired itself.

// Every network, from the ENUM rather than a hand-kept list of factory calls.
//
// ⚠️ WHAT THIS ACTUALLY ENFORCES — CORRECTED, because the first version of this
// comment said "adding a fifth Network fails the BUILD" and that is FALSE. Kimi's
// round-2 LOW caught it and the measurement is one grep: there is NO `-Werror`
// anywhere in the Makefile, so `-Wswitch` on the default-less switch below
// produces a WARNING, not an error. Precisely:
//   * `ParamsFor`'s switch has no `default:`, so a new enumerator WARNS under
//     -Wall/-Wextra — visible in build output, not fatal;
//   * `kAllNetworks` is HAND-KEPT, and its static_assert pins only its OWN size
//     (4), not the enum's cardinality — the enum has no count sentinel to bind to;
//   * `ParamsFor` aborts if an unlisted value ever reaches it, which is a
//     backstop for a value already in the roster, not prevention.
// RESIDUAL, stated rather than implied: a fifth Network still needs a human to add
// it here. Nothing in C++17 forces that without a sentinel in the production enum,
// which is out of scope for this PR. Overstating the guarantee was worse than the
// gap, because it invited the next reader to skip the check.
Dilithion::ChainParams ParamsFor(Dilithion::Network n)
{
    switch (n) {
        case Dilithion::MAINNET: return Dilithion::ChainParams::Mainnet();
        case Dilithion::TESTNET: return Dilithion::ChainParams::Testnet();
        case Dilithion::DILV:    return Dilithion::ChainParams::DilV();
        case Dilithion::REGTEST: return Dilithion::ChainParams::Regtest();
    }
    std::cerr << "  FAIL unlisted Network value — add it to ParamsFor" << std::endl;
    std::abort();
}

const Dilithion::Network kAllNetworks[] = {
    Dilithion::MAINNET, Dilithion::TESTNET, Dilithion::DILV, Dilithion::REGTEST,
};
static_assert(sizeof(kAllNetworks) / sizeof(kAllNetworks[0]) == 4,
              "A Network was added or removed. List it above; ParamsFor's switch "
              "will not compile until the new value is handled.");

const char* NameOf(Dilithion::Network n)
{
    switch (n) {
        case Dilithion::MAINNET: return "MAINNET";
        case Dilithion::TESTNET: return "TESTNET";
        case Dilithion::DILV:    return "DILV";
        case Dilithion::REGTEST: return "REGTEST";
    }
    return "?";
}

// A difficulty that is NOT any network's genesisNBits (mainnet 0x1e01fffe;
// testnet/DilV/regtest 0x1d00ffff). It is a plausible real value, so nothing here
// depends on it being unusual.
constexpr uint32_t kSentinelNBits = 0x1b0404cb;

// Does the PRODUCER emit a constant nBits on this network? MEASURED by calling it.
//
// HOW THIS DISCRIMINATES — read out of pow.cpp, not assumed:
//   * the constant branch (`IsDilV() || IsRegtest()` — pow.cpp:1142-1146 as re-verified at 763c5a06; grep the condition, not the line) returns
//     genesisNBits WITHOUT dereferencing pindexLast at all;
//   * every retargeting path needs an ASERT anchor via
//     `pindexLast->GetAncestor(...)`, which is nullptr for a lone index, and the
//     documented fallback is `return pindexLast->header.nBits` — our sentinel.
// A synthetic index carrying kSentinelNBits therefore separates the two exactly.
//
// The height must clear the LARGEST activation threshold in the tree: testnet's
// asertActivationHeight is 999999999 (chainparams.cpp:402, re-verified at 763c5a06). Below it the code
// falls through to the LEGACY retarget, which would compute a third value and
// make this probe meaningless — so the height is deliberately past it.
//
// ⚠️ A retargeting network prints "[ASERT…] CRITICAL: Cannot find anchor block"
// on stderr here. That is the documented fallback being exercised on purpose; it
// is not a failure.
bool ProducerEmitsConstantNBits(const Dilithion::ChainParams& params, const char* name)
{
    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::g_chainParams = new Dilithion::ChainParams(params);

    CBlockIndex idx;
    idx.pprev = nullptr;
    idx.pnext = nullptr;
    idx.pskip = nullptr;
    idx.nHeight = 1500000000;          // clears every activation height in the tree
    idx.header.nBits = kSentinelNBits;
    idx.nBits = kSentinelNBits;

    const uint32_t genesis = Dilithion::g_chainParams->genesisNBits;
    const uint32_t got = GetNextWorkRequired(&idx, /*nBlockTime=*/0);

    delete Dilithion::g_chainParams;
    Dilithion::g_chainParams = saved;

    // ⛔ FAIL LOUDLY RATHER THAN MIS-CLASSIFY. If the producer returns a THIRD
    // value this function cannot tell constant from retargeting, and treating
    // "not genesis" as "retargeting" would be a guess dressed as a measurement.
    if (got != genesis && got != kSentinelNBits) {
        std::cerr << "  FAIL " << name << ": GetNextWorkRequired returned 0x"
                  << std::hex << got << " — neither genesisNBits (0x" << genesis
                  << ") nor the sentinel (0x" << kSentinelNBits << std::dec
                  << "). This probe can no longer classify the producer; fix the "
                     "probe, do not reinterpret its result." << std::endl;
        ++g_failures;
    }
    return got == genesis;
}

// THE ARM THAT REPLACED THE COPIED TABLE. For EVERY network: the checker the
// manager builds must agree with what the PRODUCER actually does, and the gate's
// refusal must be derived from that same bit.
//
// Nothing here names which networks are constant. If pow.cpp:1142-1146 gains or
// loses a network, this arm follows it and the CHECKER is what goes red — which
// is the drift the seats flagged and the drift this PR is about.
void test_selection_and_refusal_match_the_producer_on_every_network()
{
    std::cout << "  test_selection_and_refusal_match_the_producer_on_every_network..." << std::flush;

    int constant_producers = 0, retargeting_producers = 0, refused = 0;

    for (Dilithion::Network n : kAllNetworks) {
        const Dilithion::ChainParams params = ParamsFor(n);
        const std::string name = NameOf(n);
        const bool producer_constant = ProducerEmitsConstantNBits(params, name.c_str());
        producer_constant ? ++constant_producers : ++retargeting_producers;

        // (1) The checker must mirror the producer, not a table.
        Check((name + ": VDF checker selected IFF the producer emits a constant").c_str(),
              SelectsVdfCheckerUnder(params) == producer_constant);

        // (2) The gate's refusal, derived from that same bit. A network that is
        // VDF-from-genesis but whose producer RETARGETS has no correct checker and
        // must be refused; every other network must be accepted.
        const bool expect_supported = !(params.IsVdfFromGenesis() && !producer_constant);
        const Support sup = SupportUnder(params);
        Check((name + ": ProofCheckerSupportsNetwork matches the producer").c_str(),
              sup.supported == expect_supported);
        Check((name + ": the GATE accepts iff supported").c_str(),
              sup.init_accepted == expect_supported);
        if (!expect_supported) ++refused;
    }

    // NON-VACUITY. Without these the loop passes when every network answers the
    // same way — which is what "always pick VDF", "never pick VDF" and "refuse
    // everything" all look like from inside the loop.
    Check("at least one network's producer emits a CONSTANT", constant_producers >= 1);
    Check("at least one network's producer RETARGETS", retargeting_producers >= 1);
    Check("at least one network is REFUSED (VDF-from-genesis yet retargeting)", refused >= 1);
    Check("not every network is refused", refused < 4);

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


// ⛔ TESTNET IS UNSUPPORTED, AND THE GATE REFUSES IT — the half a comment could
// not enforce.
//
// Testnet is VDF-from-genesis (vdfActivationHeight = 0, vdfExclusiveHeight = 0)
// but is NOT in the producer's constant branch `IsDilV() || IsRegtest()`
// (pow.cpp:1142-1146): it retargets via ASERT. So NEITHER checker is correct —
// the VDF checker's nBits-equality rule is violated by testnet's own honest
// headers, and the RandomX checker wants a hash under target from a header never
// mined against one.
//
// The previous draft picked the lesser-wrong checker and wrote the gap into a
// comment. This asserts the gap is MACHINE-ENFORCED: the network reports
// unsupported AND InitializeDoSProtectedSync refuses.
void test_testnet_is_refused_rather_than_given_a_wrong_checker()
{
    std::cout << "  test_testnet_is_refused_rather_than_given_a_wrong_checker..." << std::flush;

    const Support testnet = SupportUnder(Dilithion::ChainParams::Testnet());
    Check("testnet reports UNSUPPORTED", !testnet.supported);
    Check("testnet sync is REFUSED at the gate", !testnet.init_accepted);

    // THE DISCRIMINATING HALF. Without it, "refuse everything" passes the two
    // checks above and would silently disable header sync on every network.
    for (const auto& p : { Dilithion::ChainParams::DilV(),
                           Dilithion::ChainParams::Regtest(),
                           Dilithion::ChainParams::Mainnet() }) {
        const Support ok = SupportUnder(p);
        Check("supported network reports SUPPORTED", ok.supported);
        Check("supported network sync is ACCEPTED", ok.init_accepted);
    }

    std::cout << " done" << std::endl;
}

int main()
{
    // ⚠️ RandomX MUST be initialised, and WITH THE PRODUCTION KEY. This suite
    // constructs a CHeadersManager under MAINNET, whose path reaches
    // GetGenesisHash(), which RECOMPUTES the RandomX genesis hash and compares it
    // to the value pinned in chainparams.
    //
    // Both failure modes were measured here, and the second one is the useful one:
    //   * no init at all           -> throws "RandomX VM not initialized";
    //   * init with an ARBITRARY key -> the recompute mismatches the pin and
    //     GetGenesisHash REFUSES TO RUN ("substituted consensus values"). That
    //     guard is doing exactly its job — a test that invented its own key was
    //     asking the node to validate against consensus values it had changed.
    // So the key is the production one, the same string genesis_test.cpp:96 mines
    // with. Light mode: one genesis hash does not justify full mode's ~2.5 GB.
    const char* rx_key = "Dilithion-RandomX-v1";
    randomx_init_for_hashing(rx_key, strlen(rx_key), 1 /* light mode */);

    std::cout << "proof_checker_selection_tests" << std::endl;

    test_the_two_predicates_really_disagree();
    test_selection_and_refusal_match_the_producer_on_every_network();
    test_testnet_is_refused_rather_than_given_a_wrong_checker();

    if (g_failures != 0) {
        std::cerr << "proof_checker_selection_tests: " << g_failures
                  << " FAILURE(S)" << std::endl;
        return 1;
    }
    std::cout << "proof_checker_selection_tests: ALL PASS" << std::endl;
    return 0;
}
