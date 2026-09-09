// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 3 — concrete IHeaderProofChecker implementations for the two
// Dilithion chains. Header-only; both classes are small enough that a
// separate translation unit isn't worth the link-edit overhead.
//
// Q4 verification (2026-04-26): both chains share the SAME chain-work
// formula (`2^(256-8*size)/mantissa` driven by nBits). The only thing
// that differs is the cryptographic-proof check itself:
//   * DIL  — RandomX PoW hash <= target  (existing CheckProofOfWork)
//   * DilV — header-level VDF sanity     (full VDF check at ConnectBlock)

#ifndef DILITHION_NET_PORT_HEADER_PROOF_CHECKERS_H
#define DILITHION_NET_PORT_HEADER_PROOF_CHECKERS_H

#include <net/iheader_proof_checker.h>
#include <consensus/chain_work.h>     // Phase 3 shared helper
#include <consensus/pow.h>            // CheckProofOfWork
#include <primitives/block.h>         // CBlockHeader

namespace dilithion::net::port {

// ============================================================================
// RandomXHeaderProofChecker — DIL chain
// ============================================================================
//
// Wraps the existing PoW path. CheckHeaderProof = hash <= target via
// the existing CheckProofOfWork. ChainWorkContribution = ComputeChainWork(nBits).

class RandomXHeaderProofChecker final : public ::dilithion::net::IHeaderProofChecker {
public:
    bool CheckHeaderProof(const CBlockHeader& header) const override
    {
        // Bitcoin's pattern: hash header → compare against target. Existing
        // CheckProofOfWork(hash, nBits) does exactly this.
        return ::CheckProofOfWork(header.GetHash(), header.nBits);
    }

    uint256 ChainWorkContribution(const CBlockHeader& header) const override
    {
        return ::dilithion::consensus::ComputeChainWork(header.nBits);
    }

    bool ChainWorkGreaterThan(const uint256& a, const uint256& b) const override
    {
        // Strict greater-than (the helper provides >=; flip ordering).
        return !::dilithion::consensus::ChainWorkGreaterOrEqual(b, a);
    }
};

// ============================================================================
// VDFHeaderProofChecker — DilV chain
// ============================================================================
//
// VDF blocks have nVersion >= VDF_VERSION (=4) and carry vdfOutput +
// vdfProofHash in the extended header layout. Full VDF proof
// verification needs the coinbase transaction (where the proof bytes
// live) and stays at ConnectBlock / CheckVDFProof — not here.
//
// At header-level we only do cheap sanity: is this actually a VDF
// block, and are the VDF fields populated? A header that fails these
// checks is malformed and the peer should be punished.
class VDFHeaderProofChecker final : public ::dilithion::net::IHeaderProofChecker {
public:
    bool CheckHeaderProof(const CBlockHeader& header) const override
    {
        if (!header.IsVDFBlock()) return false;        // wrong chain type
        if (header.vdfProofHash.IsNull()) return false;
        if (header.vdfOutput.IsNull()) return false;

        // LP-10 A-2 / blocker 4 — nBits SANITY, added because its absence was a
        // complete break of the header-sync work gate on DilV.
        //
        // MEASURED: this function used to examine only the version flag and two
        // non-null fields, all peer-chosen, and never looked at nBits. Compose
        // that with ComputeChainWork saturating to MAX on a zero MANTISSA
        // (chain_work.h:44-47) and ONE fabricated header -- VDF version, two
        // arbitrary non-null VDF fields, nBits = 0x1e000000 -- was worth maximum
        // chain work and satisfied DilV's MEASURED nMinimumChainWork by itself:
        // "sufficient work demonstrated at HEIGHT 1". The same single header with
        // honest nBits did NOT open the gate, so the saturation was the cause.
        //
        // DIL was never exposed to this, and the reason is worth stating because
        // it is not reassuring: RandomXHeaderProofChecker calls CheckProofOfWork,
        // which rejects a zero TARGET (pow.cpp:139-149). The protection was an
        // incidental consequence of that check, not a design decision, and it is
        // one refactor away from being lost. So the guard belongs HERE too, at the
        // chain-specific seam, not only in the caller.
        //
        // Note ChainWorkContribution below feeds the same nBits into
        // ComputeChainWork, so a checker that validates the proof but not the
        // work input is only half a checker.
        if ((header.nBits & 0x00FFFFFFu) == 0) return false;

        // Full VDF verification deferred to CheckVDFProof at ConnectBlock —
        // the proof bytes aren't in the header layout.
        return true;
    }

    uint256 ChainWorkContribution(const CBlockHeader& header) const override
    {
        // Q4: both chains share the formula. VDF blocks set nBits for legacy
        // compatibility (existing chain-selection logic depends on it).
        return ::dilithion::consensus::ComputeChainWork(header.nBits);
    }

    bool ChainWorkGreaterThan(const uint256& a, const uint256& b) const override
    {
        return !::dilithion::consensus::ChainWorkGreaterOrEqual(b, a);
    }
};

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_HEADER_PROOF_CHECKERS_H
