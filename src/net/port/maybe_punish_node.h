// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 3 — MaybePunishNodeFor* thin wrappers (deferred from Phase 2 §10
// Q5=C). Mirrors Bitcoin Core net_processing.cpp's dispatch pattern: take
// a typed reject-reason from a validation layer, map it to the scoring-
// policy enum, forward to IPeerScorer::Misbehaving with the canonical
// weight from misbehavior_policy.h::DefaultWeight().
//
// Production-path status (corrected 2026-04-26 per Cursor Phase 3 review
// CONCERN Q5; CORRECTED AGAIN 2026-09-10 by the F4 census, which measured it):
//   * MaybePunishNodeForHeaders — NOT on any production path. The previous
//     version of this line said "WIRED at net.cpp:1574 (HEADERS-count-too-large
//     reject) via the CPeerManager::MisbehaveHeaders forwarder". Both halves
//     were wrong: the raise site is net.cpp:1856, and that forwarder
//     (peers.cpp CPeerManager::MisbehaveHeaders) has never called this wrapper —
//     it reads HeaderRejectWeight() and calls CPeerManager::Misbehaving itself,
//     because it must also run the seed-node guard and banman. The two paths
//     share the WEIGHT TABLE and nothing else, so any policy gate has to exist
//     in both; see the duplicated zero-weight refusal in each.
//   * MaybePunishNodeForBlock — NOT YET WIRED to a production callsite.
//     Test-covered only (test_block_and_tx_reject_reasons_map_exhaustively).
//     Production cutover deferred to Phase 4/5/6 where block-validation
//     paths get rewritten — wiring at existing call sites now would force
//     weight-mismatch drift between the wrapper's DefaultWeight and the
//     existing call-site weights.
//   * MaybePunishNodeForTx — same disposition as MaybePunishNodeForBlock.
//
// ============================================================================
// DELIBERATE DIVERGENCE: three MisbehaviorType enums coexist after Phase 3.
// ============================================================================
//
// 1. `dilithion::net::MisbehaviorType` (ipeer_scorer.h, FROZEN Phase 0).
//    The scoring-policy enum: 15 values. Used by IPeerScorer::Misbehaving
//    and consumed by misbehavior_policy.h::DefaultWeight.
//
// 2. `::MisbehaviorType` (banman.h, EXISTING). The diagnostic-logging
//    enum with uint16_t numeric codes 100–600, baked into production
//    banlist.dat files. Renumbering breaks ban-list compatibility.
//
// 3. `dilithion::net::port::HeaderRejectReason` (this file, NEW Phase 3).
//    HeadersSync-specific reject taxonomy. Granular because Phase 2's
//    enum is intentionally coarse, and HeadersSync diagnostic logs need
//    per-reason discrimination.
//
// The enum-to-enum bridge tables in this header consolidate all three.
// Drift detection: peer_scorer_tests.cpp covers (1)<->(2); a unit test in
// PR3.1 (test_header_reject_reason_maps_exhaustively) covers (3)->(1).
//
// When Phase 6 / future PeerManager rewrite consolidates the dispatch,
// this comment block can come down with the enum-merge PR.
// ============================================================================

#ifndef DILITHION_NET_PORT_MAYBE_PUNISH_NODE_H
#define DILITHION_NET_PORT_MAYBE_PUNISH_NODE_H

#include <net/ipeer_scorer.h>
#include <net/port/misbehavior_policy.h>

#include <optional>
#include <string>

namespace dilithion::net::port {

// ============================================================================
// Header reject reasons
// ============================================================================
//
// HeadersSync-specific taxonomy. Maps to Phase 2's MisbehaviorType via
// MapHeaderRejectToMisbehaviorType(). One source of truth for what each
// header-validation failure costs the peer.
//
// REACHABILITY, MEASURED — stated FIRST because it frames every weight below.
// Grep `HeaderRejectReason::` across src/ excluding src/test/ and this header:
// exactly ONE production raise site exists — net.cpp:1856, MemoryBoundExceeded,
// the HEADERS-message-count check. Every other reason has ZERO. And a proof
// rejection does not score at all: CheckHeaderProof returning false propagates
// as a plain `return false` out of headerssync.cpp:354 / :419 up to
// ProcessNextHeaders, whose caller erases the peer's sync state — there is no
// Misbehaving call anywhere on that path.
//
// So these weights are DORMANT, exactly as the PRESYNC gate they serve is. They
// are corrected here as an ACTIVATION PREREQUISITE — before A-3 wires the raise
// sites — NOT as a live-defect fix. Nothing in this file changes any peer's
// score today, and nothing below should be read as claiming it does.
//
// THE STANDARD every non-zero weight must meet (Will, 2026-07-05): score only on
// a signal an HONEST peer CANNOT emit; throttle or stop-serving otherwise. Each
// reason below carries the argument that it meets that standard, or carries 0.
enum class HeaderRejectReason {
    // --- SCORED: an honest peer cannot emit these ---------------------------

    // weight 100. A proof that fails verification cannot be produced by accident.
    // A checker returning false for OUR OWN reasons must NOT map here — see
    // LocalStateUnavailable.
    InvalidProof,

    // weight 50. nVersion <= 0, or an nBits unusable for work accounting — a
    // zero mantissa, which makes ComputeChainWork saturate to the maximum, or an
    // exponent small enough to put the quotient at the top of the 256-bit word.
    // No honest producer emits either.
    //
    // (An earlier draft of this line cited `chain_work.h NBitsUsableForWork`.
    // That symbol lives on fix/lp10-live-nbits-mantissa and is NOT on this
    // branch, so the citation pointed at nothing. Naming the condition instead
    // of a symbol keeps the comment true on whichever branch it is read.)
    InvalidHeaderFields,

    // weight 20. The headers WITHIN one message do not chain to each other.
    // Upstream-grounded: Core v28.0 net_processing.cpp:2727-2729 scores exactly
    // this — CheckHeadersAreContinuous false -> Misbehaving("non-continuous
    // headers sequence").
    DiscontinuousBatch,

    // weight 20. m_max_commitments is ~648,000 commitments, on the order of 378M
    // blocks of history. Not honest-reachable.
    MemoryBoundExceeded,

    // --- NOT SCORED: an HONEST peer CAN emit these --------------------------

    // weight 0. Indistinguishable from an honest peer on a losing fork, or one
    // with nothing further to give. See the enumeration above HeaderRejectWeight.
    InsufficientChainWork,

    // weight 0. A peer that REORGS between PRESYNC and REDOWNLOAD emits exactly
    // this signal, honestly. See the note above HeaderRejectWeight.
    RedownloadCommitmentMismatch,

    // weight 0 — SPLIT OUT OF THE OLD `NonContinuousChain`, WHICH CONFLATED IT
    // WITH DiscontinuousBatch AND SO SCORED IT 20.
    // The FIRST header of a message does not connect to what THIS session
    // anchored on. An honest reorg plus a locator fallback produces it, and the
    // unconditional continuity check added by the unanchored-first-header fix
    // makes it reachable for the first time — which is why the merged reason
    // could not keep its score. Upstream-grounded, and Core says it in as many
    // words: net_processing.cpp:3130-3134 routes a first header whose prev is
    // unknown to HandleUnconnectingHeaders under the comment "this could be
    // benign" — it sends a getheaders and makes no Misbehaving call.
    UnanchoredFirstHeader,

    // weight 0. Honest peers relay headers whose timestamps run ahead of ours
    // under ordinary CLOCK SKEW — that is why a tolerance exists at all. Such a
    // header is refused on its own merits; refusing it does not require also
    // scoring the peer that relayed it. Upstream-grounded: Core v28.0
    // net_processing.cpp:1992-1994 lists BLOCK_TIME_FUTURE among the results
    // that `break` without punishment.
    FutureTimestamp,

    // --- NOT SCORED: OUR fault, never the peer's ----------------------------

    // weight 0, and NO MisbehaviorType at all — see the std::optional return of
    // MapHeaderRejectToMisbehaviorType. The checker could not reach a verdict for
    // a LOCAL reason: header_proof_checkers.h returns false when
    // Dilithion::g_chainParams is null. Fail closed — accept no header — but
    // never score a peer for state WE are missing. Without a distinct reason that
    // local-fault `false` is indistinguishable from a forged proof, inherits
    // InvalidProof's weight 100, and bans an honest peer for our own bug.
    LocalStateUnavailable,
};

// EVERY reason, once, so that no test has to keep its own list. Two suites
// iterate this — header_proof_checker_tests (table + wrapper) and
// peer_scorer_banman_integration_tests (the production forwarder) — and a
// per-suite roster would let one of them silently stop covering a new reason.
// The pinned size is the forcing function: adding an enumerator fails to compile
// until it is listed here, which fails the suites until it is classified.
inline constexpr HeaderRejectReason kAllHeaderRejectReasons[] = {
    HeaderRejectReason::InvalidProof,
    HeaderRejectReason::InvalidHeaderFields,
    HeaderRejectReason::DiscontinuousBatch,
    HeaderRejectReason::MemoryBoundExceeded,
    HeaderRejectReason::InsufficientChainWork,
    HeaderRejectReason::RedownloadCommitmentMismatch,
    HeaderRejectReason::UnanchoredFirstHeader,
    HeaderRejectReason::FutureTimestamp,
    HeaderRejectReason::LocalStateUnavailable,
};
static_assert(sizeof(kAllHeaderRejectReasons) / sizeof(kAllHeaderRejectReasons[0]) == 9,
              "A HeaderRejectReason was added or removed. List it above, give it a "
              "weight argument on the enumerator, and classify it in "
              "header_proof_checker_tests.cpp's SCORED / NOT-SCORED asserts.");

// Map HeaderRejectReason -> MisbehaviorType (the FROZEN scoring-policy enum).
//
// THE std::optional IS THE POINT, not defensiveness. LocalStateUnavailable is
// not misbehavior, so there is no honest label for it in an enum whose every
// value names something a PEER did wrong; returning some nearby value would put
// "InvalidHeader" in a log line that is describing OUR missing chainparams. The
// frozen enum cannot gain a value (banlist.dat codes are baked into production
// files), so the absence lives in the return type, where the compiler makes
// every caller confront it.
constexpr std::optional<::dilithion::net::MisbehaviorType>
MapHeaderRejectToMisbehaviorType(HeaderRejectReason reason)
{
    using R = HeaderRejectReason;
    using T = ::dilithion::net::MisbehaviorType;
    switch (reason) {
        case R::InvalidProof:                  return T::InvalidPoW;
        case R::InvalidHeaderFields:           return T::InvalidHeader;
        case R::DiscontinuousBatch:            return T::NonContinuousHeaders;
        case R::MemoryBoundExceeded:           return T::OversizedMessage;
        case R::InsufficientChainWork:         return T::InvalidHeader;
        case R::RedownloadCommitmentMismatch:  return T::InvalidHeader;
        case R::UnanchoredFirstHeader:         return T::NonContinuousHeaders;
        case R::FutureTimestamp:               return T::InvalidHeader;
        case R::LocalStateUnavailable:         return std::nullopt;
    }
    // Unreachable. The switch carries NO default, so -Wswitch fails the build if
    // a reason is ever added without a deliberate mapping.
    return std::nullopt;
}

// Special-case weights where DefaultWeight()'s coarse policy doesn't reflect the
// granular reason.
//
// LP-10 A-2 blocker 3 zeroed the first TWO of these, reversing an earlier
// decision (Q6=B); the A-2 / F4 per-reason census then zeroed two more and split
// UnanchoredFirstHeader out of the old NonContinuousChain. All four were NEW
// POLICY WITH NO UPSTREAM COUNTERPART, and the census is what showed it.
//
// Measured by ENUMERATION: Bitcoin Core v28.0 net_processing.cpp has 18
// Misbehaving() CALL SITES; none scores a low-work chain and none scores a
// commitment mismatch.
//
// CORRECTED FROM "21", AND THE CORRECTION IS THE POINT. 21 is what
// `grep -c 'Misbehaving('` returns — but three of those lines are a DECLARATION
// (:555), the DEFINITION (:1939) and a COMMENT (:3087), none of which is a call.
// The first version of this note said "measured by enumeration, not by count"
// while quoting a line count, which is the precise error it claimed to avoid.
// The conclusion is unaffected: all 18 real call sites were read.
//
// WHY, under Will's standing rule (2026-07-05): ban only on a signal an HONEST
// peer CANNOT emit; throttle or stop-serving otherwise.
//
//   InsufficientChainWork — a chain below the threshold is indistinguishable
//     from an honest peer on a losing fork, or one with nothing more to give.
//     Core logs "Ignoring low-work chain (height=%u) from peer=%d" and, on a
//     !success return from ProcessNextHeaders, resets m_headers_sync and erases
//     the peer's presync stats. No scoring, no ban.
//
//   RedownloadCommitmentMismatch — was 100 ("immediate ban") on the reasoning
//     that a peer changing its story is distinguishable. IT IS NOT. A peer that
//     REORGS between PRESYNC and REDOWNLOAD changes its story HONESTLY and emits
//     exactly this signal: we record commitments against its phase-1 chain, then
//     RE-REQUEST headers in phase 2 (headerssync.cpp NextHeadersRequestLocator)
//     and compare against the OLD chain's commitments. The phase-1 window is
//     thousands of headers — minutes, on 30s/45s block chains. Banning here is
//     the honest-indistinguishable-signal misport, except we would have been
//     INVENTING the ban rather than porting one.
//
//   UnanchoredFirstHeader — Core routes it to HandleUnconnectingHeaders with the
//     comment "this could be benign" and sends a getheaders instead of scoring
//     (net_processing.cpp:3130-3134). Our unconditional continuity check made it
//     reachable; the score had to go with it.
//
//   FutureTimestamp — Core lists BLOCK_TIME_FUTURE among the results that break
//     without punishment (net_processing.cpp:1992-1994). Clock skew is honest.
//
// TO BAN HONESTLY ON A COMMITMENT MISMATCH (prerequisite, not a task): record
// the tip the peer ANNOUNCED in phase 1 and compare it in phase 2. A mismatch
// under an UNCHANGED announced tip is a signal an honest peer is far less likely
// to emit — a reorg normally changes the announced tip. That state does not
// exist today, and the argument is probabilistic rather than airtight: a peer
// can reorg and re-announce the same tip. It needs its own analysis before it
// is armed, and this note does not pre-approve it.
//
// A mismatch is a reason to distrust THIS SYNC ATTEMPT, not this PEER: the caller
// resets the sync and stops syncing from that peer for this attempt.
//
// Status: PROPOSED (COORD ruling 2026-09-10, dissent adopted; F4 census
// 2026-09-10). No D- row yet, so this comment cites the MEASUREMENT and the
// doctrine, never a ratification.
constexpr int HeaderRejectWeight(HeaderRejectReason reason)
{
    using R = HeaderRejectReason;
    switch (reason) {
        // Scored. The per-reason argument lives on the enumerator.
        case R::InvalidProof:
        case R::InvalidHeaderFields:
        case R::DiscontinuousBatch:
        case R::MemoryBoundExceeded: {
            const auto type = MapHeaderRejectToMisbehaviorType(reason);
            return type ? ::dilithion::net::port::DefaultWeight(*type) : 0;
        }
        // Not scored: honest-emittable, or our own fault.
        case R::InsufficientChainWork:
        case R::RedownloadCommitmentMismatch:
        case R::UnanchoredFirstHeader:
        case R::FutureTimestamp:
        case R::LocalStateUnavailable:
            return 0;
    }
    // Unreachable. THIS SWITCH DELIBERATELY HAS NO `default:`. The previous
    // version's `default:` fell through to DefaultWeight(), so a newly added
    // reason would have silently inherited a score nobody chose. Without it,
    // -Wswitch fails the build until someone decides.
    return 0;
}

// ============================================================================
// Public wrappers
// ============================================================================
//
// All three return the bool that IPeerScorer::Misbehaving returns: true if
// the peer's score crossed the ban threshold. Callers use that signal to
// decide whether to disconnect immediately.

inline bool MaybePunishNodeForHeaders(
    ::dilithion::net::IPeerScorer& scorer,
    ::dilithion::net::NodeId peer,
    HeaderRejectReason reason,
    const std::string& detail = "")
{
    const int weight = HeaderRejectWeight(reason);

    // A SECOND, INDEPENDENT GATE, deliberately not folded into the weight table.
    // A zero-weight reason must not reach the scorer AT ALL: a zero-weight
    // Misbehaving() call still creates the peer's score entry and still emits a
    // log line that reads as misbehavior, and if DefaultWeight() is ever retuned
    // the table alone would silently re-arm these. Honest-emittable and
    // local-fault reasons stop here.
    //
    // Pinned by test_zero_weight_reasons_never_reach_the_scorer, which counts
    // calls on a mock scorer rather than reading the table back.
    if (weight <= 0) return false;

    return scorer.Misbehaving(peer, weight, detail);
}

// Block-validation reject reasons (PR3.3 wires one site).
enum class BlockRejectReason {
    InvalidProof,
    InvalidMerkleRoot,
    InvalidCoinbase,
    DuplicateTransactions,
    DoubleSpend,
};

constexpr ::dilithion::net::MisbehaviorType
MapBlockRejectToMisbehaviorType(BlockRejectReason reason)
{
    using R = BlockRejectReason;
    using T = ::dilithion::net::MisbehaviorType;
    switch (reason) {
        case R::InvalidProof:           return T::InvalidPoW;
        case R::InvalidMerkleRoot:      return T::InvalidBlock;
        case R::InvalidCoinbase:        return T::InvalidBlock;
        case R::DuplicateTransactions:  return T::InvalidBlock;
        case R::DoubleSpend:            return T::InvalidBlock;
    }
    return T::UnknownMessage;
}

inline bool MaybePunishNodeForBlock(
    ::dilithion::net::IPeerScorer& scorer,
    ::dilithion::net::NodeId peer,
    BlockRejectReason reason,
    const std::string& detail = "")
{
    return scorer.Misbehaving(peer,
        ::dilithion::net::port::DefaultWeight(MapBlockRejectToMisbehaviorType(reason)),
        detail);
}

// Tx-validation reject reasons (PR3.3 wires one site).
enum class TxRejectReason {
    InvalidSignature,
    DuplicateInputs,
    Oversized,
    DoubleSpend,
};

constexpr ::dilithion::net::MisbehaviorType
MapTxRejectToMisbehaviorType(TxRejectReason reason)
{
    using R = TxRejectReason;
    using T = ::dilithion::net::MisbehaviorType;
    switch (reason) {
        case R::InvalidSignature:  return T::InvalidSignature;
        case R::DuplicateInputs:   return T::InvalidBlock;
        case R::Oversized:         return T::OversizedMessage;
        case R::DoubleSpend:       return T::InvalidBlock;
    }
    return T::UnknownMessage;
}

inline bool MaybePunishNodeForTx(
    ::dilithion::net::IPeerScorer& scorer,
    ::dilithion::net::NodeId peer,
    TxRejectReason reason,
    const std::string& detail = "")
{
    return scorer.Misbehaving(peer,
        ::dilithion::net::port::DefaultWeight(MapTxRejectToMisbehaviorType(reason)),
        detail);
}

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_MAYBE_PUNISH_NODE_H
