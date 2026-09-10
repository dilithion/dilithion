// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-10 F5 / D-1 — `full_headers_available` is the SYNC-TERMINATION SIGNAL, and
// our port accepted it and threw it away.
//
// PORT DIVERGENCE, cited line by line against Bitcoin Core v28.0
// (`src/headerssync.cpp`, read 2026-09-10):
//
//   Core :86   PRESYNC + full message  -> request_more = true
//   Core :91   PRESYNC + NON-full      -> "the peer's chain has ended and
//                                          definitely doesn't have enough work,
//                                          so we can stop our sync" — request_more
//                                          stays false and the single exit at
//                                          Core :136 finalises.
//   Core :123  REDOWNLOAD + full       -> request_more = true
//   Core :127  REDOWNLOAD + NON-full   -> "our peer gave us a high-work chain, but
//                                          is now declining to serve us that full
//                                          chain again. Give up." success stays
//                                          TRUE — there is simply nothing more to
//                                          do — and request_more is false.
//
// Ours declared the parameter and commented out its NAME
// (`headerssync.cpp:199`, `bool /* full_headers_available */`), so both aborts
// were absent: a peer answering with SHORT batches was treated exactly like one
// answering with full ones, and we kept asking. That abort is what stops a peer
// holding a sync slot open by drip-feeding — the same budget the whole gate
// exists to protect.
//
// ⚠️ NOT INVENTED HERE, AND THAT IS THE POINT. Two earlier reviews on this
// mission hit the consequence and neither was fixed:
//   REVIEW_grill_substitute_r2.md:143 — the below-threshold rejection "is reached
//     ONLY when headers.empty()", so "a test that feeds a below-threshold chain
//     and then stops observes no rejection ever — it just keeps being asked for
//     more". Described there as a test-design hazard; it is a port defect.
//   REVIEW_port_189.md:29 — the gate "fires only on an empty headers batch".
//
// ⚠️ SCOPE, DELIBERATELY NARROW. This fixes the NON-EMPTY paths, which is where
// Core carries the aborts. The separate divergence — that our empty-batch branch
// drives BOTH state transitions where Core refuses an empty batch outright
// (Core :74) — is F5/D-2 and is NOT touched here, because correcting it requires
// rewriting the transition-driving arms in three other suites. Landing D-1 alone
// leaves those arms untouched and green.
//
// Reachability clause: the gate has ZERO production callers. This is a port
// defect in dormant code, corrected before A-3 wires it.

#include <net/headers_manager.h>
#include <net/headerssync.h>
#include <net/iheader_proof_checker.h>

#include <consensus/chain_work.h>
#include <consensus/params.h>
#include <core/chainparams.h>
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

// Accepts every proof, so the only variable across arms is the termination
// signal. Production always injects a checker.
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
    h.data[0] = 0xA1;
    return h;
}

// VDF headers: linking a chain needs GetHash() on the previous header, and a
// RandomX header's GetHash() throws "RandomX VM not initialized" outside a mining
// context. A checker is injected either way, so the proof path is not under test.
CBlockHeader MakeHeader(const uint256& prev, uint32_t nonce)
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::VDF_VERSION;
    h.nBits    = 0x1d00ffff;
    h.nTime    = 1700000000;
    h.nNonce   = nonce;
    h.hashPrevBlock = prev;
    for (int i = 0; i < 32; ++i) h.vdfProofHash.data[i] = 0x42;
    for (int i = 0; i < 32; ++i) h.vdfOutput.data[i]    = 0x37;
    return h;
}

std::vector<CBlockHeader> LinkedChain(size_t n)
{
    std::vector<CBlockHeader> out;
    uint256 prev = ChainStartHash();
    for (size_t i = 0; i < n; ++i) {
        out.push_back(MakeHeader(prev, static_cast<uint32_t>(i)));
        prev = out.back().GetHash();
    }
    return out;
}

// A threshold far above anything this suite's headers can accumulate, so PRESYNC
// stays BELOW it and the only question is whether we keep asking.
uint256 UnreachableThreshold()
{
    uint256 t;
    for (int i = 0; i < 200000; ++i) t = AddChainWork(t, ComputeChainWork(0x1d00ffff));
    return t;
}

struct Outcome { bool success; bool request_more; HeadersSyncState::State state; };

Outcome PresyncBatch(bool full_headers_available)
{
    HeadersSyncParams params;
    AlwaysValidChecker checker;
    HeadersSyncState state(/*peer_id=*/1, params, ChainStartHash(),
                           /*chain_start_height=*/0,
                           /*chain_start_work=*/uint256(), UnreachableThreshold(),
                           &checker);

    auto r = state.ProcessNextHeaders(LinkedChain(3), full_headers_available);
    return {r.success, r.request_more, state.GetState()};
}


// Promote to REDOWNLOAD through the REAL two-phase flow, then deliver one
// phase-2 batch with the given signal.
//
// ⚠️ THE FIRST VERSION OF THIS HELPER MADE ITS OWN CONTROL ARM FAIL, and the
// reason is worth keeping. It set commitment_period to 1,000,000 to neutralise
// the commitment machinery — so PRESYNC recorded NO commitments, and REDOWNLOAD
// read `m_header_commitments.empty()` as "finished" on its very first batch.
// request_more was then false for BOTH signals and the pair proved nothing.
// A short-circuit that makes both arms agree is indistinguishable from a fix.
//
// So drive it properly: 2,000 headers in PRESYNC records several commitments
// (one per commitment_period, EnterRedownloadPhase preserves them — it clears the
// four redownload fields and m_redownloaded_headers, not the commitment deque),
// then replay only the first 600. Commitments remain, so `finished` is false and
// the ONLY thing deciding request_more is the termination signal under test.
//
// ⚠️ The promotion still rides on an EMPTY-batch-free path — work crosses the
// threshold inside the PRESYNC batch itself — but the separate D-2 divergence
// (Core refuses empty batches at :74; ours transitions on them) is untouched
// here and this helper deliberately does not depend on it.
Outcome RedownloadBatch(bool full_headers_available)
{
    HeadersSyncParams params;  // default commitment_period: commitments ARE recorded
    AlwaysValidChecker checker;

    // Seed AT the threshold so the PRESYNC batch promotes once it is stored.
    uint256 threshold;
    for (int i = 0; i < 1000; ++i) threshold = AddChainWork(threshold, ComputeChainWork(0x1d00ffff));

    HeadersSyncState state(/*peer_id=*/1, params, ChainStartHash(),
                           /*chain_start_height=*/0,
                           /*chain_start_work=*/threshold, threshold, &checker);

    const std::vector<CBlockHeader> chain = LinkedChain(2000);
    state.ProcessNextHeaders(chain, /*full_headers_available=*/true);
    RequireTrue("promoted to REDOWNLOAD",
                state.GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Replay a PREFIX, so commitments are left over and `finished` stays false.
    const std::vector<CBlockHeader> prefix(chain.begin(), chain.begin() + 600);
    auto r = state.ProcessNextHeaders(prefix, full_headers_available);
    return {r.success, r.request_more, state.GetState()};
}

}  // namespace

// ============================================================================
// PRESYNC — Core headerssync.cpp:86 / :91
// ============================================================================

void test_presync_full_batch_keeps_asking()
{
    std::cout << "  test_presync_full_batch_keeps_asking..." << std::flush;

    // THE CONTROL, and it is what makes the arm below mean anything: a FULL
    // message means the peer may have more, so we must keep requesting. Without
    // this, "never request more" would pass the termination arm.
    const Outcome o = PresyncBatch(/*full_headers_available=*/true);
    REQUIRE(o.success);
    REQUIRE(o.request_more);
    REQUIRE(o.state == HeadersSyncState::State::PRESYNC);

    std::cout << " OK" << std::endl;
}

void test_presync_short_batch_ends_the_sync()
{
    std::cout << "  test_presync_short_batch_ends_the_sync..." << std::flush;

    // Core :91 — a NON-full message in PRESYNC means the peer's chain has ended.
    // It is below the threshold and there is no more coming, so it cannot reach
    // the threshold. Asking again is asking a peer to repeat "I have nothing".
    const Outcome o = PresyncBatch(/*full_headers_available=*/false);

    REQUIRE(!o.request_more);
    // Core reaches this through its single exit (:136,
    // `if (!(ret.success && ret.request_more)) Finalize();`), so the peer ends in
    // FINAL either way. Asserting the STATE and not merely the flag, because a
    // flag nobody acts on is the shape this whole finding is about.
    REQUIRE(o.state == HeadersSyncState::State::FINAL);

    std::cout << " OK" << std::endl;
}


// ============================================================================
// REDOWNLOAD — Core headerssync.cpp:123 / :127
// ============================================================================

void test_redownload_full_batch_keeps_asking()
{
    std::cout << "  test_redownload_full_batch_keeps_asking..." << std::flush;

    // The control for the arm below. A full phase-2 message means more of the
    // chain is coming, so we must keep requesting.
    const Outcome o = RedownloadBatch(/*full_headers_available=*/true);
    REQUIRE(o.success);
    REQUIRE(o.request_more);
    REQUIRE(o.state == HeadersSyncState::State::REDOWNLOAD);

    std::cout << " OK" << std::endl;
}

void test_redownload_short_batch_gives_up_but_keeps_its_headers()
{
    std::cout << "  test_redownload_short_batch_gives_up_but_keeps_its_headers..." << std::flush;

    // Core :127 — the peer claimed a high-work chain and is now declining to
    // re-serve it. Give up.
    const Outcome o = RedownloadBatch(/*full_headers_available=*/false);

    REQUIRE(!o.request_more);
    REQUIRE(o.state == HeadersSyncState::State::FINAL);

    // ⛔ AND SUCCESS STAYS TRUE, which is the half that is easy to get wrong.
    // The headers in this batch were validated against their commitments; there
    // is simply nothing more to do. Core: "there's no more processing to be done
    // with these headers, so we can still return success." A failure here would
    // discard good headers and, once A-3 wires the reject reasons, would score a
    // peer for stopping early — an honest-emittable signal.
    REQUIRE(o.success);

    std::cout << " OK" << std::endl;
}


// ============================================================================
// THE CALLER'S HALF — Core net_processing.cpp:2787
// ============================================================================
//
// ⛔ EVERY ARM ABOVE WOULD HAVE PASSED WITH THE FIX UNREACHABLE.
// CHeadersManager::ProcessHeadersWithDoSProtection passed a hardcoded `true` for
// full_headers_available, so the only production caller told the state machine
// that EVERY message was full and neither abort could fire. Restoring the signal
// in HeadersSyncState and stopping there would have been a correct check nothing
// reaches — this mission's own recurring defect, committed while fixing an
// instance of it. The caller now derives it as Core does.
//
// ⚠️ AND THE BEHAVIOURAL ARM FOR IT IS BLOCKED, WHICH IS SAID HERE RATHER THAN
// PAPERED OVER. Driving the manager with a short batch and with a
// MAX_HEADERS_RESULTS batch was MEASURED to give identical outcomes:
//
//     n=3     init=1  before=PRESYNC  ret=0  after=NONE(erased)
//     n=2000  init=1  before=PRESYNC  ret=0  after=NONE(erased)
//
// Not because the signal is broken — because the manager selects its proof
// checker on IsDilV(), so REGTEST gets RandomXHeaderProofChecker, which rejects
// every synthesisable header long before the signal is consulted. That is why the
// existing gate-arming suite drives the manager with an EMPTY vector. An arm
// written against this would have been vacuous, and a weakened one would have
// passed for the wrong reason.
//
// So the caller's invariant is a STRUCTURAL guard instead —
// scripts/check-headers-termination-signal.sh, wired into `make tests-fast`,
// mutation-verified (it exits 1 on the exact literal that shipped). It is
// labelled structural, not counted as behavioural coverage. When the
// checker-selection fix lands (fix/lp10-vdf-checker-selection routes regtest to
// the VDF checker), replace it with the real arm: short batch -> phase FINAL,
// full batch -> phase PRESYNC, via GetHeadersSyncPhase.

void test_the_phase_observable_reports_the_state_machines_own_field()
{
    std::cout << "  test_the_phase_observable_reports_the_state_machines_own_field..." << std::flush;

    uint256 unreachable;
    for (int i = 0; i < 200000; ++i)
        unreachable = AddChainWork(unreachable, ComputeChainWork(0x1d00ffff));

    CHeadersManager mgr(unreachable);
    const NodeId peer = 7;

    // A peer with no session reports nothing — not a defaulted PRESYNC, which
    // would make "session exists" and "session is in phase 1" indistinguishable.
    RequireTrue("no session -> nullopt", !mgr.GetHeadersSyncPhase(peer).has_value());

    RequireTrue("init", mgr.InitializeDoSProtectedSync(peer, mgr.GetMinimumChainWork()));
    RequireTrue("session -> PRESYNC",
                mgr.GetHeadersSyncPhase(peer) == HeadersSyncState::State::PRESYNC);

    // A DIFFERENT peer must still report nothing, so the accessor is keyed on the
    // peer rather than reporting whatever session happens to exist.
    RequireTrue("other peer -> nullopt", !mgr.GetHeadersSyncPhase(8).has_value());

    std::cout << " OK" << std::endl;
}


// ============================================================================
// F5 / D-2 — AN EMPTY BATCH IS REFUSED (Core headerssync.cpp:74)
// ============================================================================
//
// ⛔ THIS ARM IS THE ONE THAT PINS D-2, AND WITHOUT IT THE OTHERS DO NOT.
// The suites that used to drive phase changes with an empty batch were all
// re-derived onto real headers, so every one of them passes whether or not the
// empty-batch transition still exists. Restoring that invented transition would
// have SURVIVED the whole re-derived suite set — measured, not assumed: the
// mutation run was stopped once that became clear, and this arm written before
// it was re-run.
//
// Core refuses the case outright:
//     Assume(!received_headers.empty());
//     if (received_headers.empty()) return ret;
// An empty HEADERS message is the CALLER's business. Ours used to hang BOTH
// state transitions off it — invented, not ported.
void test_an_empty_batch_is_refused_and_changes_nothing()
{
    std::cout << "  test_an_empty_batch_is_refused_and_changes_nothing..." << std::flush;

    HeadersSyncParams params;
    AlwaysValidChecker checker;

    // Seeded AT the threshold, so under the OLD code an empty batch would have
    // promoted to REDOWNLOAD. That is precisely what must no longer happen.
    uint256 threshold;
    for (int i = 0; i < 1000; ++i)
        threshold = AddChainWork(threshold, ComputeChainWork(0x1d00ffff));

    HeadersSyncState state(/*peer_id=*/1, params, ChainStartHash(),
                           /*chain_start_height=*/0,
                           /*chain_start_work=*/threshold, threshold, &checker);

    const auto r = state.ProcessNextHeaders({}, /*full_headers_available=*/true);

    RequireTrue("empty batch reports failure", !r.success);
    RequireTrue("empty batch does not ask for more", !r.request_more);
    RequireTrue("empty batch returns no headers", r.pow_validated_headers.empty());
    // THE LOAD-BEARING ONE: no state transition. Under the old code this same
    // call promoted to REDOWNLOAD.
    RequireTrue("empty batch does NOT change phase",
                state.GetState() == HeadersSyncState::State::PRESYNC);

    // THE DISCRIMINATING HALF. Without it, a state machine that refused
    // EVERYTHING would pass every assertion above. The same seeded state, given a
    // real header, must still promote.
    HeadersSyncState live(/*peer_id=*/2, params, ChainStartHash(),
                          /*chain_start_height=*/0,
                          /*chain_start_work=*/threshold, threshold, &checker);
    live.ProcessNextHeaders(LinkedChain(1), /*full_headers_available=*/true);
    RequireTrue("a REAL batch still promotes",
                live.GetState() == HeadersSyncState::State::REDOWNLOAD);

    std::cout << " OK" << std::endl;
}

int main()
{
    // CHeadersManager reads chainparams during construction, so the manager-level
    // arm cannot run without it. Static, not `new`: the storage outlives every
    // test and a leak here would be noise in any sanitizer run.
    static Dilithion::ChainParams s_regtest = Dilithion::ChainParams::Regtest();
    Dilithion::g_chainParams = &s_regtest;

    std::cout << "\n=== LP-10 F5 / D-1: headers-sync termination signal ===\n" << std::endl;
    test_presync_full_batch_keeps_asking();
    test_presync_short_batch_ends_the_sync();
    test_redownload_full_batch_keeps_asking();
    test_redownload_short_batch_gives_up_but_keeps_its_headers();
    test_an_empty_batch_is_refused_and_changes_nothing();
    test_the_phase_observable_reports_the_state_machines_own_field();
    std::cout << "\nheaderssync_termination_tests: ALL PASS" << std::endl;
    return 0;
}
