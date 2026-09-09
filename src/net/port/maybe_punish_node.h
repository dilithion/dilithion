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
// CONCERN Q5):
//   * MaybePunishNodeForHeaders — WIRED at net.cpp:1574 (HEADERS-count-too-
//     large reject) via the CPeerManager::MisbehaveHeaders forwarder.
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

#include <string>

namespace dilithion::net::port {

// ============================================================================
// Header reject reasons
// ============================================================================
//
// HeadersSync-specific taxonomy. Maps to Phase 2's MisbehaviorType via
// MapHeaderRejectToMisbehaviorType(). One source of truth for what each
// header-validation failure costs the peer.
enum class HeaderRejectReason {
    InvalidProof,                  // CheckHeaderProof returned false (PoW or VDF sanity) — weight 100
    InvalidHeaderFields,           // nBits == 0 or nVersion <= 0 — weight 50
    NonContinuousChain,            // hashPrevBlock mismatch — weight 20
    InsufficientChainWork,         // PRESYNC ended below MIN_CHAIN_WORK — weight 0 (honest-emittable)
    RedownloadCommitmentMismatch,  // weight 0 — a REORG emits this; see HeaderRejectWeight below
    MemoryBoundExceeded,           // m_max_commitments cap hit — weight 20
    FutureTimestamp,               // wall-clock guard — weight 50
};

// Map HeaderRejectReason -> MisbehaviorType (scoring-policy enum). Keeps
// the entire Phase 3 reject-reason → policy → weight pipeline in one place.
constexpr ::dilithion::net::MisbehaviorType
MapHeaderRejectToMisbehaviorType(HeaderRejectReason reason)
{
    using R = HeaderRejectReason;
    using T = ::dilithion::net::MisbehaviorType;
    switch (reason) {
        case R::InvalidProof:                  return T::InvalidPoW;
        case R::InvalidHeaderFields:           return T::InvalidHeader;
        case R::NonContinuousChain:            return T::NonContinuousHeaders;
        case R::InsufficientChainWork:         return T::InvalidHeader;
        case R::RedownloadCommitmentMismatch:  return T::InvalidHeader;
        case R::MemoryBoundExceeded:           return T::OversizedMessage;
        case R::FutureTimestamp:               return T::InvalidHeader;
    }
    return T::UnknownMessage;  // unreachable; switch covers all values
}

// Special-case weights where DefaultWeight()'s coarse policy doesn't reflect
// the granular reason.
//
// ⚠️ LP-10 A-2 / blocker 3 — TWO reasons now score ZERO, and this reverses an
// earlier decision (Q6=B). Both were NEW POLICY WITH NO UPSTREAM COUNTERPART.
// Measured by ENUMERATION, not by count: Bitcoin Core v28.0 net_processing.cpp
// has 21 Misbehaving() call sites; NONE is for a low-work chain and NONE is for
// a commitment mismatch. Core logs "Ignoring low-work chain (height=%u) from
// peer=%d" and, on a !success return from ProcessNextHeaders, resets
// m_headers_sync and erases the peer's presync stats. No scoring, no ban.
//
// WHY, under Will's standing rule (2026-07-05): ban only on a signal an HONEST
// peer CANNOT emit; throttle or stop-serving otherwise.
//
//   InsufficientChainWork  — a chain below the threshold is indistinguishable
//     from an honest peer on a losing fork, or one with nothing more to give.
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
// TO BAN HONESTLY HERE (prerequisite, not a task): record the tip the peer
// ANNOUNCED in phase 1 and compare it in phase 2. A mismatch under an UNCHANGED
// announced tip is the signal an honest peer cannot emit — a reorg changes the
// announced tip, deception does not. That state does not exist today.
//
// A mismatch is a reason to distrust THIS SYNC ATTEMPT, not this PEER: the
// caller resets the sync and stops syncing from that peer for this attempt.
//
// Status: PROPOSED (COORD ruling 2026-09-10, dissent adopted). No D- row yet, so
// this comment cites the MEASUREMENT and the doctrine, never a ratification.
constexpr int HeaderRejectWeight(HeaderRejectReason reason)
{
    switch (reason) {
        case HeaderRejectReason::InsufficientChainWork:
        case HeaderRejectReason::RedownloadCommitmentMismatch:
            return 0;  // honest-emittable: stop syncing, do not score
        default:
            return ::dilithion::net::port::DefaultWeight(
                MapHeaderRejectToMisbehaviorType(reason));
    }
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
    return scorer.Misbehaving(peer, HeaderRejectWeight(reason), detail);
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
