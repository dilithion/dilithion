// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/connect_checks.h>

#include <consensus/validation.h>       // CBlockValidator (deserialize, merkle, subsidy)
#include <consensus/tx_validation.h>    // CTransactionValidator::VerifyScript, IsCanonicalP2PKHScriptSig, TxValidation::*
#include <core/chainparams.h>           // Dilithion::g_chainParams
#include <primitives/transaction.h>
#include <script/script.h>              // CScript::IsPayToPublicKeyHash (malleability gate predicate)
#include <amount.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

// A coin created by an EARLIER transaction in the SAME block. The overlay lets a
// later transaction spend a same-block parent (which is not yet in the on-disk
// UTXO set at pre-ApplyBlock time). Mirrors ApplyBlock's incidental in-block
// chaining (it adds each tx's outputs to the cache as it iterates).
struct OverlayCoin {
    CTxOut   out;        // scriptPubKey + nValue of the created output
    uint32_t nHeight;    // creation height (== this block's height)
    bool     fCoinBase;  // whether the creating tx was the coinbase
};

// Consensus money range. Matches CTransactionValidator::MoneyRange /
// TxValidation::MAX_MONEY (21,000,000 * COIN). Kept local so this validator does
// not depend on any private predicate.
inline bool CC_MoneyRange(CAmount v) {
    return v >= 0 && v <= TxValidation::MAX_MONEY;
}

} // namespace

bool ConnectBlockChecks(const CBlock& block,
                        CUTXOSet& utxoSet,
                        int nHeight,
                        bool fVerifyScripts,
                        std::string& error)
{
    CBlockValidator       blockValidator;
    CTransactionValidator txValidator;

    // --- Deserialize the block's transactions ONCE (block.vtx is raw bytes). ---
    std::vector<CTransactionRef> txs;
    if (!blockValidator.DeserializeBlockTransactions(block, txs, error)) {
        error = "ConnectBlockChecks: failed to deserialize block transactions: " + error;
        return false;
    }
    if (txs.empty()) {
        error = "ConnectBlockChecks: block has no transactions";
        return false;
    }

    // =========================================================================
    // CHECK 1 (keystone) — Merkle root commitment.
    // Recompute the merkle root from the deserialized vtx and require it equals
    // the header's hashMerkleRoot. Without this, an attacker can substitute vtx
    // under a valid (PoW/MIK-passing) header on the connect path. Cheap; run
    // first so a substituted-body block is rejected before any per-tx work.
    // =========================================================================
    {
        uint256 recomputed = blockValidator.BuildMerkleRoot(txs);
        if (!(recomputed == block.hashMerkleRoot)) {
            error = "ConnectBlockChecks: merkle root mismatch "
                    "(block body does not match header commitment)";
            return false;
        }
    }

    const unsigned int coinbaseMaturity = Dilithion::g_chainParams
        ? static_cast<unsigned int>(Dilithion::g_chainParams->coinbaseMaturity)
        : TxValidation::COINBASE_MATURITY;

    // Per-block output overlay (load-bearing: prevents a false-reject chain split
    // on in-block-chained spends). Resolve every input against {overlay U utxoSet},
    // overlay first.
    std::map<COutPoint, OverlayCoin> overlay;
    // In-block spent set: an outpoint may be spent at most once within one block
    // (CHECK 4 — the ApplyBlock stale-read otherwise allows a second spend).
    std::set<COutPoint> spentInBlock;
    // Duplicate-txid guard (keeps the overlay sound and mirrors ApplyBlock's
    // CVE-2012-2459 defence; a duplicate txid would otherwise silently overwrite
    // overlay entries).
    std::set<uint256> seenTxids;

    CAmount totalFees = 0;

    for (size_t txIdx = 0; txIdx < txs.size(); ++txIdx) {
        const CTransactionRef& tx = txs[txIdx];
        const bool isCoinbase = (txIdx == 0);
        const uint256 txid = tx->GetHash();

        if (!seenTxids.insert(txid).second) {
            error = "ConnectBlockChecks: duplicate transaction in block (CVE-2012-2459)";
            return false;
        }

        if (!isCoinbase) {
            // DoS cap on signature-verification work (mirrors CheckTransaction).
            if (tx->vin.size() > TxValidation::MAX_INPUT_COUNT_PER_TX) {
                error = "ConnectBlockChecks: transaction has too many inputs (DoS limit)";
                return false;
            }

            CAmount totalIn = 0;

            for (size_t i = 0; i < tx->vin.size(); ++i) {
                const CTxIn& txin = tx->vin[i];

                // ---- CHECK 4: in-block double-spend ----
                // An outpoint (confirmed OR created earlier in this block) may be
                // spent at most once per block. This also catches duplicate inputs
                // within a single transaction.
                if (!spentInBlock.insert(txin.prevout).second) {
                    error = "ConnectBlockChecks: double-spend of the same outpoint within block";
                    return false;
                }

                // ---- Resolve the spent output: overlay first, then confirmed set ----
                CTxOut   spentOut;
                uint32_t spentHeight   = 0;
                bool     spentCoinbase = false;

                auto ov = overlay.find(txin.prevout);
                if (ov != overlay.end()) {
                    spentOut      = ov->second.out;
                    spentHeight   = ov->second.nHeight;
                    spentCoinbase = ov->second.fCoinBase;
                } else {
                    CUTXOEntry entry;
                    if (!utxoSet.GetUTXO(txin.prevout, entry)) {
                        // Input existence — unresolved => HARD reject. This also
                        // covers the null/incomplete-UTXO-set case for any block
                        // that has non-coinbase inputs (never a silent downgrade).
                        error = "ConnectBlockChecks: input not found "
                                "(spends a non-existent output)";
                        return false;
                    }
                    spentOut      = entry.out;
                    spentHeight   = entry.nHeight;
                    spentCoinbase = entry.fCoinBase;
                }

                // ---- CHECK 6: canonical P2PKH scriptSig (malleability closure) ----
                // A malleated (non-canonical) scriptSig re-encodes the SAME spend to
                // a DIFFERENT txid without invalidating the ML-DSA signature (which
                // commits to no scriptSig bytes) — the classic pre-segwit txid-
                // malleability vector (finding #4). The mempool/relay path already
                // rejects it in CheckTransactionInputs; enforcing the SAME single-
                // source predicate here (IsCanonicalP2PKHScriptSig, exported from
                // tx_validation) closes it on the block-connect path. Every block-
                // acceptance path (normal sync, self-mined, reorg) funnels through
                // ConnectTip -> ConnectBlockChecks, so a malleated scriptSig mined
                // into a block is REJECTED by every node identically — the C-R3
                // connect-path gap the mempool gate could not cover.
                //
                // UNCONDITIONAL (independent of fVerifyScripts): the mempool path
                // enforces it unconditionally, so gating it behind assume-valid here
                // would let the connect surface accept byte-strings the mempool
                // surface rejects — the very mempool/connect split this closure is
                // meant to avoid. It is an O(1) structural check (a length plus two
                // uint16 field compares), so unlike the ~2 ms ML-DSA verify there is
                // no cost reason to skip it; running it BEFORE CHECK 2 also rejects a
                // non-canonical scriptSig before the expensive signature step (DoS
                // ordering). The interpreter's MINIMALDATA + CLEANSTACK flags
                // (defense-in-depth for the general/scriptV2 surface) ride inside
                // CHECK 2's VerifyScript. Keyed on the SPENT output type (P2PKH),
                // resolved above from {overlay U utxoSet}; coinbase never reaches
                // this loop (isCoinbase skip).
                {
                    CScript spk(spentOut.scriptPubKey.begin(),
                                spentOut.scriptPubKey.end());
                    if (spk.IsPayToPublicKeyHash() &&
                        !IsCanonicalP2PKHScriptSig(txin.scriptSig)) {
                        error = "ConnectBlockChecks: non-canonical scriptSig for "
                                "P2PKH input " + std::to_string(i) + " (malleability)";
                        return false;
                    }
                }

                // ---- CHECK 5: coinbase maturity ----
                if (spentCoinbase) {
                    const uint32_t h = static_cast<uint32_t>(nHeight);
                    const uint32_t confs = (h >= spentHeight) ? (h - spentHeight) : 0;
                    if (confs < coinbaseMaturity) {
                        error = "ConnectBlockChecks: spends an immature coinbase output";
                        return false;
                    }
                }

                // ---- CHECK 3 (accumulate inputs) with range/overflow guards ----
                if (!CC_MoneyRange(spentOut.nValue)) {
                    error = "ConnectBlockChecks: spent output value out of range";
                    return false;
                }
                totalIn += static_cast<CAmount>(spentOut.nValue);
                if (!CC_MoneyRange(totalIn)) {
                    error = "ConnectBlockChecks: total input value out of range/overflow";
                    return false;
                }

                // ---- CHECK 2: spend-signature verification (pubkey<->coin bind) ----
                // Verify against the RESOLVED spent scriptPubKey, never against a
                // key the spender supplies. Overlay-resolved parents feed the same
                // interpreter as confirmed ones. Gated by fVerifyScripts so blocks
                // at/below the script-assumevalid height (checkpoint-anchored) can
                // skip the ~2 ms/input ML-DSA cost during IBD.
                if (fVerifyScripts) {
                    std::string sigErr;
                    if (!txValidator.VerifyScript(*tx, i, txin.scriptSig,
                                                  spentOut.scriptPubKey, sigErr)) {
                        error = "ConnectBlockChecks: script/signature verification failed "
                                "for input " + std::to_string(i) + ": " + sigErr;
                        return false;
                    }
                }
            }

            // ---- CHECK 3 (per-tx value conservation: Sigma(in) >= Sigma(out)) ----
            CAmount totalOut = 0;
            for (const auto& txout : tx->vout) {
                if (!CC_MoneyRange(static_cast<CAmount>(txout.nValue))) {
                    error = "ConnectBlockChecks: output value out of range";
                    return false;
                }
                totalOut += static_cast<CAmount>(txout.nValue);
                if (!CC_MoneyRange(totalOut)) {
                    error = "ConnectBlockChecks: total output value out of range/overflow";
                    return false;
                }
            }
            if (totalIn < totalOut) {
                error = "ConnectBlockChecks: transaction inputs less than outputs "
                        "(value creation / mint)";
                return false;
            }

            const CAmount fee = totalIn - totalOut;
            totalFees += fee;
            if (!CC_MoneyRange(totalFees)) {
                error = "ConnectBlockChecks: accumulated fees out of range";
                return false;
            }
        }

        // Add this transaction's outputs to the overlay so later same-block
        // transactions can spend them. Coinbase outputs are included too — a
        // same-block spend of them is rejected by CHECK 5 (0 confirmations).
        for (uint32_t n = 0; n < tx->vout.size(); ++n) {
            OverlayCoin oc;
            oc.out       = tx->vout[n];
            oc.nHeight   = static_cast<uint32_t>(nHeight);
            oc.fCoinBase = isCoinbase;
            overlay[COutPoint(txid, n)] = oc;
        }
    }

    // =========================================================================
    // CHECK 3 (coinbase value) — Sigma(out)(coinbase) <= subsidy + Sigma(fees).
    // Unconditional (independent of fVerifyScripts and of any relay-fee flag);
    // this is the anti-inflation invariant. Genesis (height 0) excepted, matching
    // CBlockValidator::CheckCoinbase's height-0 skip for pre-funded genesis.
    // =========================================================================
    if (nHeight != 0) {
        const CTransactionRef& coinbase = txs[0];

        const uint64_t subsidy =
            CBlockValidator::CalculateBlockSubsidy(static_cast<uint32_t>(nHeight));
        uint64_t maxValue = subsidy;
        if (totalFees > 0) {
            const uint64_t feesU = static_cast<uint64_t>(totalFees);
            if (maxValue + feesU < maxValue) {
                error = "ConnectBlockChecks: coinbase max-value overflow (subsidy + fees)";
                return false;
            }
            maxValue += feesU;
        }

        uint64_t coinbaseOut = 0;
        for (const auto& txout : coinbase->vout) {
            if (coinbaseOut + txout.nValue < coinbaseOut) {
                error = "ConnectBlockChecks: coinbase output value overflow";
                return false;
            }
            coinbaseOut += txout.nValue;
        }

        if (coinbaseOut > maxValue) {
            error = "ConnectBlockChecks: coinbase value exceeds subsidy + fees";
            return false;
        }
    }

    return true;
}

bool ConnectPathMaySkipScriptVerify(int nHeight,
                                    int scriptAssumeValidHeight,
                                    bool fInitialBlockDownload)
{
    // Skip signatures ONLY for a historical block (at/below a POSITIVE
    // assume-valid height) while still in IBD. A block at the tip, a height
    // above the assume-valid height, or a chain configured with
    // scriptAssumeValidHeight <= 0 always verifies. See the header for the
    // full safety rationale (HIGH-1).
    return scriptAssumeValidHeight > 0
        && nHeight <= scriptAssumeValidHeight
        && fInitialBlockDownload;
}

bool ConnectPathVerifyScripts(const Dilithion::ChainParams* params,
                              int nHeight,
                              bool fInitialBlockDownload)
{
    // Read the DEDICATED script-assume-valid height — NOT dfmpAssumeValidHeight.
    // This one line is the HIGH-1 round-2 decoupling: the signature gate and the
    // DFMP/MIK skip now draw from independent knobs. Default 0 (fail-safe, and the
    // value on every network / relaunch) => ConnectPathMaySkipScriptVerify is
    // always false => verify from block 1. A null params likewise verifies.
    const int scriptAssumeValidHeight = params ? params->scriptAssumeValidHeight : 0;
    return !ConnectPathMaySkipScriptVerify(nHeight, scriptAssumeValidHeight,
                                           fInitialBlockDownload);
}

bool ConnectPathMaySkipVDFVerify(int nHeight,
                                 int vdfAssumeValidHeight,
                                 bool fInitialBlockDownload)
{
    // Skip the ~44 ms Wesolowski verify ONLY for a historical block (at/below a
    // POSITIVE assume-valid height) while still in IBD. A block at the tip, a
    // height above the assume-valid height, or a chain configured with
    // vdfAssumeValidHeight <= 0 always verifies. Exact mirror of the ML-DSA
    // script gate — see the header for the full safety rationale.
    return vdfAssumeValidHeight > 0
        && nHeight <= vdfAssumeValidHeight
        && fInitialBlockDownload;
}

bool ConnectPathVerifyVDF(const Dilithion::ChainParams* params,
                          int nHeight,
                          bool fInitialBlockDownload)
{
    // Read the DEDICATED VDF-assume-valid height — NOT scriptAssumeValidHeight
    // and NOT dfmpAssumeValidHeight. Default 0 (the value on every network /
    // relaunch, and the null-params fail-safe) => ConnectPathMaySkipVDFVerify is
    // always false => verify every v4 block's VDF proof from height 1.
    const int vdfAssumeValidHeight = params ? params->vdfAssumeValidHeight : 0;
    return !ConnectPathMaySkipVDFVerify(nHeight, vdfAssumeValidHeight,
                                        fInitialBlockDownload);
}

bool ShouldRunVDFArrivalPreflight(bool isVDFBlock,
                                  bool parentOnActiveChain,
                                  bool alreadyHaveBlockData,
                                  bool fInitialBlockDownload)
{
    // MEDIUM-2 (VDF_WIRING_REREVIEW3): the arrival-time preflight is a
    // defense-in-depth filter, NOT the authoritative verify. Run it only for a
    // FRESH v4 block on the authoritative-height path, outside IBD. The
    // !alreadyHaveBlockData term is the load-bearing fix: a block we already hold
    // must NOT re-run the expensive Wesolowski verify — that is redundant with
    // ConnectTip and, on the honest-valid replay path, an unbannable
    // CPU-exhaustion amplification. Excluding it does NOT weaken forgery
    // rejection: a fresh forged block has no stored data, so it still runs the
    // preflight and its peer is still scored.
    return isVDFBlock
        && parentOnActiveChain
        && !alreadyHaveBlockData
        && !fInitialBlockDownload;
}
