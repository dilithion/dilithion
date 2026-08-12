// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_CONNECT_CHECKS_H
#define DILITHION_CONSENSUS_CONNECT_CHECKS_H

#include <primitives/block.h>
#include <node/utxo_set.h>
#include <string>

/**
 * ConnectBlockChecks — unified connect-path block validator (C-R3 remediation).
 *
 * A single READ-ONLY consensus gate invoked from CChainState::ConnectTip
 * immediately BEFORE CUTXOSet::ApplyBlock mutates the UTXO set. ApplyBlock has
 * exactly one production caller (chain.cpp), and every block-acceptance path
 * (normal sync, async QueueBlock/IBD, reorg via ActivateBestChainStep, and
 * fork-activation) converges on ConnectTip -> ApplyBlock, so one seam covers
 * all of them. Placed LAST among the ConnectTip gates (after the cheap PoW/MIK/
 * DNA/attestation/cooldown checks) so the expensive signature step runs only
 * after the cheap gates have culled bad blocks (DoS ordering).
 *
 * Historically the connect path enforced only input-existence and duplicate-txid
 * (CUTXOSet::ApplyBlock); it verified NO spend signatures, NO value conservation,
 * NO in-block double-spend, NO coinbase maturity, and NO merkle-root commitment —
 * it trusted that a block's transactions had been validated when they transited
 * the mempool, an assumption a self-mined / never-relayed block violates.
 *
 * Enforced here (see connect_checks.cpp for the load-bearing constraints):
 *   1. Merkle root         — BuildMerkleRoot(vtx) == block.hashMerkleRoot.
 *   2. Spend signatures     — real VerifyScript against the SPENT output's
 *                             committed scriptPubKey (pubkey<->coin binding).
 *                             Gated by fVerifyScripts (assumevalid).
 *   3. Value conservation   — Sigma(in) >= Sigma(out) per non-coinbase tx;
 *                             coinbase <= subsidy + fees. Unconditional.
 *   4. In-block double-spend — an outpoint may be spent at most once per block.
 *   5. Coinbase maturity     — no spend of a coinbase output younger than
 *                             COINBASE_MATURITY (per-chain).
 *
 * Load-bearing correctness detail: a per-block output overlay resolves an input
 * that spends a parent transaction EARLIER IN THE SAME BLOCK. Without it a valid
 * in-block-chained block would be falsely rejected (the parent's outputs are not
 * yet in the on-disk UTXO set at pre-ApplyBlock time) — a consensus split.
 *
 * Consensus-only: value conservation is checked directly (Sigma(in) >= Sigma(out),
 * range/overflow guards) and NOT via the relay-policy CheckFee bundle, which
 * would newly reject low/high-fee blocks and split the chain.
 *
 * @param block          The block being connected (block.vtx is raw bytes).
 * @param utxoSet        UTXO set in its pre-ApplyBlock-for-this-block state.
 * @param nHeight        Height at which the block is being connected.
 * @param fVerifyScripts When true, verify ML-DSA spend signatures. Set false only
 *                       for blocks at/below the script-assumevalid height (their
 *                       signatures are anchored by a checkpoint hash commitment).
 *                       Value conservation, merkle, double-spend and maturity are
 *                       enforced REGARDLESS of this flag.
 * @param error          Human-readable rejection reason on failure.
 * @return true if the block passes every enforced check; false (with error set)
 *         otherwise. A false return must abort the connect BEFORE ApplyBlock.
 */
bool ConnectBlockChecks(const CBlock& block,
                        CUTXOSet& utxoSet,
                        int nHeight,
                        bool fVerifyScripts,
                        std::string& error);

#endif // DILITHION_CONSENSUS_CONNECT_CHECKS_H
