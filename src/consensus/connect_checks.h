// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_CONNECT_CHECKS_H
#define DILITHION_CONSENSUS_CONNECT_CHECKS_H

#include <primitives/block.h>
#include <node/utxo_set.h>
#include <string>

namespace Dilithion { class ChainParams; }

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
 *   6. Canonical scriptSig   — every non-coinbase P2PKH input's scriptSig is the
 *                             single canonical layout (IsCanonicalP2PKHScriptSig,
 *                             the SAME single-source predicate the mempool path
 *                             uses). Closes txid malleability on blocks (finding
 *                             #4). UNCONDITIONAL — enforced regardless of
 *                             fVerifyScripts, matching the mempool path so the two
 *                             surfaces never diverge. The interpreter's
 *                             MINIMALDATA+CLEANSTACK flags (general/scriptV2
 *                             defense-in-depth) ride inside check 2's VerifyScript.
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
 *                       Value conservation, merkle, double-spend, maturity and the
 *                       canonical-scriptSig gate are enforced REGARDLESS of this flag.
 * @param error          Human-readable rejection reason on failure.
 * @return true if the block passes every enforced check; false (with error set)
 *         otherwise. A false return must abort the connect BEFORE ApplyBlock.
 */
bool ConnectBlockChecks(const CBlock& block,
                        CUTXOSet& utxoSet,
                        int nHeight,
                        bool fVerifyScripts,
                        std::string& error);

/**
 * ConnectPathMaySkipScriptVerify — assume-valid gate for the ML-DSA signature step.
 *
 * HIGH-1 remediation. The connect path may skip the expensive (~2 ms/input)
 * spend-signature verification ONLY when ALL of the following hold, mirroring
 * Bitcoin Core's assumevalid (which never skips at the tip):
 *
 *   1. scriptAssumeValidHeight > 0  — the chain is CONFIGURED with a positive
 *      script-assume-valid height. A relaunch/reset chain that leaves this at 0
 *      (or negative) verifies EVERY block from height 1 — no dormant window.
 *   2. nHeight <= scriptAssumeValidHeight — the block is at/below that height,
 *      i.e. its signatures are anchored by the shipped checkpoint hash chain.
 *   3. fInitialBlockDownload — the node is still catching up to the network.
 *      A freshly-mined block being connected AT THE TIP (post-IBD) is NEVER
 *      skipped, even if its height is below scriptAssumeValidHeight — closing
 *      the "self-mined low-height tip block skips signatures" theft vector.
 *
 * When it returns false, the caller MUST verify signatures. The default is
 * fail-safe: any caller that cannot determine IBD state passes
 * fInitialBlockDownload=false, which verifies signatures unconditionally.
 *
 * Pure function of its arguments (no globals) so it is directly unit-testable.
 *
 * @param nHeight                  Height at which the block is being connected.
 * @param scriptAssumeValidHeight  Configured script-assume-valid height (<=0 disables skipping).
 * @param fInitialBlockDownload    True iff the node is in initial block download.
 * @return true iff signature verification may be skipped for this block.
 */
bool ConnectPathMaySkipScriptVerify(int nHeight,
                                    int scriptAssumeValidHeight,
                                    bool fInitialBlockDownload);

/**
 * ConnectPathVerifyScripts — the SINGLE decision point for whether ConnectTip
 * verifies ML-DSA spend signatures for a block at nHeight.
 *
 * HIGH-1 round-2 decoupling. Reads the connect-path assume-valid height from
 * `params->scriptAssumeValidHeight` — a dedicated consensus parameter (default 0
 * on every network and every relaunch) that is DELIBERATELY SEPARATE from
 * `params->dfmpAssumeValidHeight` (which gates only the DFMP/MIK/cooldown/DNA
 * skip). Because the signature gate no longer reads the DFMP knob:
 *   - With the default scriptAssumeValidHeight == 0, this returns true for EVERY
 *     block => signatures are verified from height 1 on every network and any
 *     relaunch, closing BOTH the relaunch-IBD theft window AND the
 *     synced-vs-IBD consensus partition the coupled knob created.
 *   - Raising dfmpAssumeValidHeight (which can only ever be raised, never zeroed,
 *     on the live chains) can NEVER silently disable signature verification.
 *
 * Fail-safe: a null `params` yields scriptAssumeValidHeight = 0 => verify.
 *
 * @param params                 Active chain params (may be null => verify).
 * @param nHeight                Height at which the block is being connected.
 * @param fInitialBlockDownload  True iff the node is in initial block download.
 * @return true iff the caller MUST verify ML-DSA spend signatures for this block.
 */
bool ConnectPathVerifyScripts(const Dilithion::ChainParams* params,
                              int nHeight,
                              bool fInitialBlockDownload);

/**
 * ConnectPathMaySkipVDFVerify — assume-valid gate for the Wesolowski VDF-proof
 * verification step (ECOSYSTEM_HUNT_FINDINGS #3 remediation).
 *
 * EXACT structural mirror of ConnectPathMaySkipScriptVerify, applied to the
 * ~44 ms/block CheckVDFProof call the connect path runs for v4+ blocks. The
 * expensive class-group verify may be skipped ONLY when ALL of the following
 * hold (Bitcoin-Core assumevalid semantics — never skips at the tip):
 *
 *   1. vdfAssumeValidHeight > 0  — the chain is CONFIGURED with a positive
 *      VDF-assume-valid height. A relaunch/reset chain that leaves this at 0
 *      (or negative) verifies EVERY v4 block from height 1 — no dormant window.
 *   2. nHeight <= vdfAssumeValidHeight — the block is at/below that height, i.e.
 *      its VDF proof is anchored by the shipped checkpoint hash chain.
 *   3. fInitialBlockDownload — the node is still catching up. A freshly-mined or
 *      reorg block being connected AT THE TIP (post-IBD) is NEVER skipped, even
 *      below vdfAssumeValidHeight — closing the "forged low-height tip/reorg
 *      block skips VDF verification" vector, which is the entire attack.
 *
 * When it returns false, the caller MUST verify the VDF proof. Pure function of
 * its arguments (no globals) so it is directly unit-testable.
 *
 * @param nHeight                Height at which the block is being connected.
 * @param vdfAssumeValidHeight   Configured VDF-assume-valid height (<=0 disables skipping).
 * @param fInitialBlockDownload  True iff the node is in initial block download.
 * @return true iff VDF-proof verification may be skipped for this block.
 */
bool ConnectPathMaySkipVDFVerify(int nHeight,
                                 int vdfAssumeValidHeight,
                                 bool fInitialBlockDownload);

/**
 * ConnectPathVerifyVDF — the SINGLE decision point for whether the connect path
 * runs CheckVDFProof for a v4+ block at nHeight.
 *
 * Reads `params->vdfAssumeValidHeight` — a dedicated consensus parameter
 * (default 0 on every network and every relaunch) DELIBERATELY SEPARATE from
 * `params->scriptAssumeValidHeight` and `params->dfmpAssumeValidHeight`. With
 * the default 0 this returns true for EVERY block => VDF proofs verified from
 * height 1. Raising the DFMP or script knobs can NEVER silently disable VDF
 * verification. Fail-safe: a null `params` yields vdfAssumeValidHeight = 0 =>
 * verify.
 *
 * @param params                 Active chain params (may be null => verify).
 * @param nHeight                Height at which the block is being connected.
 * @param fInitialBlockDownload  True iff the node is in initial block download.
 * @return true iff the caller MUST verify the VDF proof for this block.
 */
bool ConnectPathVerifyVDF(const Dilithion::ChainParams* params,
                          int nHeight,
                          bool fInitialBlockDownload);

/**
 * ConnectPathMaySkipDFMPChecks — assume-valid gate for the DFMP/MIK family of
 * connect-time checks (MIK expiration, seed attestation, consensus cooldown,
 * consecutive-miner, per-MIK window cap, registration rate limit).
 *
 * External round-2 (3/4 reviewers): ConnectTip's `assumeValid` was HEIGHT-ONLY
 * (`dfmpAssumeValidHeight > 0 && nHeight <= dfmpAssumeValidHeight`) with no IBD
 * guard, unlike the script and VDF gates. A SYNCED node connecting a block
 * at/below the DFMP assume-valid height (a low-height fork candidate delivered
 * post-IBD) skipped every DFMP rule. This predicate mirrors the script gate:
 * the skip needs (1) a POSITIVE configured height, (2) nHeight <= that height,
 * and (3) EITHER the node is still in IBD, OR the block is CHECKPOINT-ANCHORED
 * (proven to be an ancestor of a shipped checkpoint hash — the caller resolves
 * that against the block index and passes it in). The anchored arm keeps a
 * synced node that legitimately (re)connects a canonical historical block from
 * running identity-DB / tracker-state-dependent checks that the network never
 * enforced on that block (dfmpAssumeValidHeight exists precisely because those
 * checks fail on canonical incident-range history) — so the guard tightens the
 * unanchored case only and cannot reject canonical history.
 *
 * Pure function of its arguments (no globals) so it is directly unit-testable.
 *
 * @param nHeight                 Height at which the block is being connected.
 * @param dfmpAssumeValidHeight   Configured DFMP assume-valid height (<=0 disables skipping).
 * @param fInitialBlockDownload   True iff the node is in initial block download.
 * @param fCheckpointAnchored     True iff the block is a proven ancestor of a
 *                                shipped checkpoint at height >= nHeight.
 * @return true iff the DFMP-family checks may be skipped for this block.
 */
bool ConnectPathMaySkipDFMPChecks(int nHeight,
                                  int dfmpAssumeValidHeight,
                                  bool fInitialBlockDownload,
                                  bool fCheckpointAnchored);

/**
 * ShouldRunVDFArrivalPreflight — arrival-time (ProcessNewBlock) decision for the
 * defense-in-depth VDF preflight (VDF_WIRING_REREVIEW3 MEDIUM-2 remediation).
 *
 * ProcessNewBlock runs an OPTIONAL arrival-time CheckVDFProof in front of the
 * authoritative ConnectTip verify, so a FORGED v4 block is rejected + its sending
 * peer scored BEFORE the block is stored/relayed. That preflight is the same
 * ~tens-of-ms class-group Wesolowski verify. Round-3 review found it was placed
 * AHEAD of the duplicate/already-have dedup: replaying a KNOWN-VALID v4 block
 * (e.g. the public current tip) forced a full verify on every message with NO
 * peer penalty (a valid proof is never Misbehaving) — an unbounded CPU-exhaustion
 * amplification on the sole block-admission funnel. This predicate hoists the
 * cheap dedup ahead of the expensive verify: an already-known block short-circuits.
 *
 * Runs the preflight ONLY when ALL hold:
 *   1. isVDFBlock            — v4+ block (only these carry a VDF proof to verify).
 *   2. parentOnActiveChain   — the block's parent is on the active chain, so the
 *      height/challenge derivation is authoritative and a failing proof is
 *      honest-impossible (safe to score the peer). An orphan/competing-fork block
 *      whose height we guessed is NEVER preflighted/scored (BUG #246 discipline);
 *      it defers to the authoritative ConnectTip verify.
 *   3. !alreadyHaveBlockData — we do NOT already hold this block's data (in the DB
 *      or a data-bearing index entry). A block we already have was verified at
 *      ConnectTip (or will be when it activates), and a known-forged block is
 *      culled by the Phase-3 IsInvalid() gate — re-running the verify buys nothing
 *      and is the replay-DoS vector. A FRESH forged block has neither DB data nor a
 *      data-bearing index (its data is never written; the reject path only sets
 *      BLOCK_FAILED_VALID on an already-indexed entry), so this term does NOT let
 *      forged blocks skip the preflight — they are still rejected + scored.
 *   4. !fInitialBlockDownload — outside IBD only, so it never doubles the
 *      from-genesis IBD VDF cost nor scores peers while our own sync is behind.
 *
 * Pure function of its arguments (no globals) so it is directly unit-testable and
 * mutation-provable. Authoritative enforcement ALWAYS remains at ConnectTip; this
 * gates only the redundant arrival-time filter in front of it.
 *
 * @param isVDFBlock             block.IsVDFBlock() — the block is v4+.
 * @param parentOnActiveChain    The block's parent is on the active chain.
 * @param alreadyHaveBlockData   We already hold this block's data (DB or index HaveData).
 * @param fInitialBlockDownload  True iff the node is in initial block download.
 * @return true iff the arrival-time VDF preflight should run for this block.
 */
bool ShouldRunVDFArrivalPreflight(bool isVDFBlock,
                                  bool parentOnActiveChain,
                                  bool alreadyHaveBlockData,
                                  bool fInitialBlockDownload);

#endif // DILITHION_CONSENSUS_CONNECT_CHECKS_H
