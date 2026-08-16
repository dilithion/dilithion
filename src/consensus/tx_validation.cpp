// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/tx_validation.h>
#include <consensus/fees.h>
#include <consensus/signature_batch_verifier.h>  // Phase 3.2: Batch sig verification
#include <consensus/sighash_preimage.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <crypto/sha3.h>
#include <core/chainparams.h>
#include <util/time.h>  // P3-C1: For GetTime() in locktime validation
#include <set>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>

// ============================================================================
// Malleability closure (finding #4): the ONE canonical P2PKH scriptSig layout.
// ============================================================================
//
// Exported (declared in tx_validation.h) so BOTH the mempool/relay path
// (CheckTransactionInputs, below) AND the block-connect path (ConnectBlockChecks
// in consensus/connect_checks.cpp) enforce THIS one predicate. A second, drifting
// copy on the connect path would be a latent consensus split; single-sourcing it
// makes the mempool and connect surfaces reject the identical byte-string set.
//
// Pre-scriptV2 the only spend type is P2PKH, and the signature commits to NO
// scriptSig bytes (GetSigningHash replaces every scriptSig with empty) while the
// txid commits to ALL of them. So any scriptSig re-encoding that still verifies
// mutates the txid without invalidating the signature (classic pre-segwit
// malleability). We close it by accepting EXACTLY one byte-string per (sig, pk):
//
//     [sig_len == 3309 (2 LE)] [sig (3309)] [pk_len == 1952 (2 LE)] [pk (1952)]  = 5265 bytes
//
// This is precisely what WalletCrypto::CreateScriptSig already emits and what the
// whole chain already uses (zero wallet/genesis change — the lowest-divergence
// option). It kills all four sub-vectors for P2PKH inputs:
//   B1 legacy<->push-opcode  (only this one format accepted; no push opcodes)
//   B2 PUSHDATA2<->PUSHDATA4  (no push opcodes at all)
//   B3 prepend junk / stack residue (exact length -> no room for extra pushes)
//   B4 format mixing          (no push encodings)
//
// It is STRICTER than IsLegacyScriptSig(), which only checks size + sig_len and
// leaves the inner pk_len field unvalidated: the sequential verify path ignores
// that field (uses the constant) while the batch path (PrepareSignatureData)
// requires pk_len == 1952 — so a bare IsLegacyScriptSig gate would still admit a
// malleated pk_len byte-pair on the sequential path AND split the two paths.
// Nailing pk_len == 1952 here removes both.
//
// NOTE: coinbase inputs are exempt (arbitrary MIK/DFMP data, no signature,
// committed via merkle->header->PoW). This gate lives on the non-coinbase input
// path only (CheckTransactionInputs returns early for coinbase).
bool IsCanonicalP2PKHScriptSig(const std::vector<uint8_t>& s) {
    const size_t SIG = DILITHIUM3_SIG_SIZE;   // 3309
    const size_t PK  = DILITHIUM3_PK_SIZE;    // 1952
    if (s.size() != 2 + SIG + 2 + PK) return false;                 // exactly 5265
    uint16_t sig_len = static_cast<uint16_t>(s[0]) |
                       (static_cast<uint16_t>(s[1]) << 8);
    if (sig_len != SIG) return false;
    uint16_t pk_len = static_cast<uint16_t>(s[2 + SIG]) |
                      (static_cast<uint16_t>(s[2 + SIG + 1]) << 8);
    if (pk_len != PK) return false;
    return true;
}

// ============================================================================
// Basic Structural Validation
// ============================================================================

bool CTransactionValidator::CheckTransactionBasic(const CTransaction& tx, std::string& error) const
{
    // Check transaction is not null
    if (tx.IsNull()) {
        error = "Transaction is null";
        return false;
    }

    // SCRIPT-010 FIX: Transaction version validation (consensus-critical)
    // Version must be positive and within defined range.
    // Currently, only version 1 is defined in the protocol.
    // Version 0 is invalid (reserved for future use or error detection).
    // Maximum version is 255 to prevent overflow issues in signature message.
    if (tx.nVersion == 0) {
        error = "Transaction version cannot be zero";
        return false;
    }
    if (tx.nVersion > 255) {
        error = "Transaction version exceeds maximum (255)";
        return false;
    }

    // Coinbase transactions have special rules
    if (tx.IsCoinBase()) {
        // Coinbase must have exactly one input
        if (tx.vin.size() != 1) {
            error = "Coinbase transaction must have exactly one input";
            return false;
        }

        // Coinbase input must have null prevout
        if (!tx.vin[0].prevout.IsNull()) {
            error = "Coinbase transaction input must have null prevout";
            return false;
        }

        // Coinbase scriptSig size must be between 2 and 20000 bytes
        // Raised for Dilithium MIK + DNA commitment + 3-4 attestation signatures
        // Registration block: MIK(5271) + DNA(33) + 3×attest(9942) ≈ 15246 bytes
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 20000) {
            error = "Coinbase scriptSig size must be between 2 and 20000 bytes";
            return false;
        }
    } else {
        // Regular transaction must have inputs
        if (tx.vin.empty()) {
            error = "Transaction has no inputs";
            return false;
        }

        // Regular transaction inputs must not have null prevout
        for (const auto& txin : tx.vin) {
            if (txin.prevout.IsNull()) {
                error = "Transaction input has null prevout (only coinbase allowed)";
                return false;
            }
        }
    }

    // All transactions must have outputs
    if (tx.vout.empty()) {
        error = "Transaction has no outputs";
        return false;
    }

    // P4-CONS-001 FIX: Maximum output count to prevent DoS via large transactions
    // Without this limit, attackers could create transactions with millions of outputs
    // causing memory exhaustion and slow validation
    static const size_t MAX_OUTPUT_COUNT = 10000;
    if (tx.vout.size() > MAX_OUTPUT_COUNT) {
        error = "Transaction has too many outputs (" + std::to_string(tx.vout.size()) +
                " > max " + std::to_string(MAX_OUTPUT_COUNT) + ")";
        return false;
    }

    // Check output values are positive and within range
    CAmount totalOut = 0;
    for (const auto& txout : tx.vout) {
        // MEDIUM-C004: Zero-value output rejection policy (DESIGN DECISION)
        //
        // This implementation rejects ALL zero-value outputs (nValue == 0).
        //
        // Rationale:
        // - Prevents UTXO set bloat from unspendable zero-value outputs
        // - Simplifies wallet logic (no need to handle zero-value UTXOs)
        // - Unlike Bitcoin, Dilithion does NOT support OP_RETURN for data storage
        //
        // Trade-offs:
        // + Prevents bloat attacks
        // + Simpler UTXO management
        // - Cannot store arbitrary data in blockchain (OP_RETURN)
        // - Less flexible than Bitcoin's approach
        //
        // If future requirements need data storage, consider:
        // - Dedicated data layer (separate from UTXO set)
        // - Witness data field (like SegWit)
        // - Off-chain storage with on-chain hash commitments
        //
        // OP_RETURN outputs are exempt from value checks (used for bridge metadata)
        if (!txout.scriptPubKey.empty() && txout.scriptPubKey[0] == 0x6a) {
            continue;  // OP_RETURN: zero-value data carrier, not stored in UTXO set
        }

        // Current policy: ALL non-OP_RETURN outputs must have nValue > 0
        if (txout.nValue <= 0) {
            error = "Transaction output value must be positive";
            return false;
        }

        // P1-2 FIX: Dust threshold as CONSENSUS rule (not just policy)
        // This prevents UTXO set bloat attacks by creating millions of tiny outputs
        // Threshold: 50000 ions = 0.0005 DIL (enough to cover minimum tx fee)
        static constexpr CAmount CONSENSUS_DUST_THRESHOLD = 50000;
        if (txout.nValue < CONSENSUS_DUST_THRESHOLD) {
            error = "Output value below dust threshold (" + std::to_string(txout.nValue) +
                    " < " + std::to_string(CONSENSUS_DUST_THRESHOLD) + " ions)";
            return false;
        }

        // Output value must be within monetary range
        if (!MoneyRange(txout.nValue)) {
            error = "Transaction output value out of range";
            return false;
        }

        // Check for overflow when adding outputs
        totalOut += txout.nValue;
        if (!MoneyRange(totalOut)) {
            error = "Transaction output total out of range";
            return false;
        }
    }

    // Check transaction size
    size_t txSize = tx.GetSerializedSize();
    if (txSize > TxValidation::MAX_TRANSACTION_SIZE) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Transaction size (%zu bytes) exceeds maximum (%zu bytes)",
                 txSize, TxValidation::MAX_TRANSACTION_SIZE);
        error = buf;
        return false;
    }

    // Check for duplicate inputs (same outpoint spent twice)
    if (!CheckDuplicateInputs(tx)) {
        error = "Transaction contains duplicate inputs";
        return false;
    }

    return true;
}

// ============================================================================
// Input Validation (UTXO Checks)
// ============================================================================

bool CTransactionValidator::CheckTransactionInputs(const CTransaction& tx, CUTXOSet& utxoSet,
                                                     uint32_t currentHeight, CAmount& txFee,
                                                     std::string& error) const
{
    // Coinbase transactions don't have real inputs to check
    if (tx.IsCoinBase()) {
        txFee = 0;
        return true;
    }

    // P3-C1 FIX: Validate locktime (consensus-critical)
    // If any input has sequence != 0xFFFFFFFF, locktime is enforced
    // If locktime < 500,000,000: it's a block height (tx valid at that height)
    // If locktime >= 500,000,000: it's a Unix timestamp (tx valid at that time)
    bool locktime_active = false;
    for (const auto& txin : tx.vin) {
        if (txin.nSequence != 0xFFFFFFFF) {
            locktime_active = true;
            break;
        }
    }

    if (locktime_active && tx.nLockTime != 0) {
        static const uint32_t LOCKTIME_THRESHOLD = 500000000;  // BIP-113 threshold

        if (tx.nLockTime < LOCKTIME_THRESHOLD) {
            // Locktime is a block height
            if (tx.nLockTime > currentHeight) {
                error = "Transaction locktime not satisfied (block height " +
                        std::to_string(tx.nLockTime) + " > current " +
                        std::to_string(currentHeight) + ")";
                return false;
            }
        } else {
            // Locktime is a Unix timestamp
            int64_t now = GetTime();
            if (static_cast<int64_t>(tx.nLockTime) > now) {
                error = "Transaction locktime not satisfied (timestamp " +
                        std::to_string(tx.nLockTime) + " > current " +
                        std::to_string(now) + ")";
                return false;
            }
        }
    }

    // Verify all inputs exist in UTXO set
    for (const auto& txin : tx.vin) {
        if (!utxoSet.HaveUTXO(txin.prevout)) {
            char buf[256];
            snprintf(buf, sizeof(buf), "Input references non-existent UTXO (tx: %s, n: %u)",
                     txin.prevout.hash.GetHex().c_str(), txin.prevout.n);
            error = buf;
            return false;
        }
    }

    // ========================================================================
    // Malleability closure (finding #4): canonical scriptSig gate.
    // ========================================================================
    // For every non-coinbase input spending a P2PKH output, the scriptSig MUST
    // be the single canonical layout (see IsCanonicalP2PKHScriptSig above).
    //
    // Placement is load-bearing: this sits in CheckTransactionInputs, which runs
    //   (a) as step 2 of CheckTransaction — i.e. BEFORE step 3's batch-vs-
    //       sequential verify branch, so BOTH verify paths inherit an identical
    //       already-canonical scriptSig (no consensus split), and
    //   (b) directly on the block-validation path (CBlockValidator::ValidateBlock
    //       and ProcessNewBlock both call CheckTransactionInputs), so a malleated
    //       scriptSig mined into a block is rejected on the same rule.
    // Coinbase never reaches here (early return above).
    //
    // Keyed on the SPENT output type (P2PKH) rather than height, so it stays
    // correct across the scriptV2 boundary: non-P2PKH spends (post-activation)
    // are governed by the interpreter's MINIMALDATA + CLEANSTACK flags instead.
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        CUTXOEntry entry;
        if (!utxoSet.GetUTXO(tx.vin[i].prevout, entry)) {
            // Existence was just verified above; be defensive and let the
            // downstream script/fee steps surface any genuine miss.
            continue;
        }
        CScript spk(entry.out.scriptPubKey.begin(), entry.out.scriptPubKey.end());
        if (spk.IsPayToPublicKeyHash()) {
            if (!IsCanonicalP2PKHScriptSig(tx.vin[i].scriptSig)) {
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "Non-canonical scriptSig for P2PKH input %zu (malleability)", i);
                error = buf;
                return false;
            }
        }
    }

    // BIP-68: Relative locktime enforcement (requires tx version >= 2)
    // Each input's nSequence can encode a relative lock:
    //   Bit 31 (disable): If set, no relative lock enforced for this input
    //   Bit 22 (type):    If set, time-based (units of 512s); otherwise block-based
    //   Bits 0-15 (value): Lock duration (blocks or 512-second intervals)
    if (tx.nVersion >= 2) {
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            uint32_t nSequence = tx.vin[i].nSequence;

            // Bit 31 set = disable relative locktime for this input
            if (nSequence & (1U << 31))
                continue;

            // Look up the UTXO to get its creation height
            CUTXOEntry entry;
            if (!utxoSet.GetUTXO(tx.vin[i].prevout, entry)) {
                continue;  // Will be caught by later validation
            }

            static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1U << 22);
            static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

            uint32_t requiredValue = nSequence & SEQUENCE_LOCKTIME_MASK;

            if (nSequence & SEQUENCE_LOCKTIME_TYPE_FLAG) {
                // Time-based: units of 512 seconds
                // Not yet fully supported (requires MTP tracking per UTXO)
                // For now, block-based relative locks are the primary use case
                // Time-based locks will be added when UTXO creation timestamps are tracked
            } else {
                // Block-based: must have waited N blocks since UTXO was created
                uint32_t heightDiff = currentHeight - entry.nHeight;
                if (heightDiff < requiredValue) {
                    char buf[256];
                    snprintf(buf, sizeof(buf),
                             "BIP-68 relative locktime not satisfied for input %zu "
                             "(need %u blocks, have %u)",
                             i, requiredValue, heightDiff);
                    error = buf;
                    return false;
                }
            }
        }
    }

    // Check coinbase maturity
    if (!CheckCoinbaseMaturity(tx, utxoSet, currentHeight, error)) {
        return false;
    }

    // Calculate total input value
    CAmount totalIn = 0;
    if (!CalculateTotalInputValue(tx, utxoSet, totalIn, error)) {
        return false;
    }

    // Calculate total output value
    CAmount totalOut = 0;
    for (const auto& txout : tx.vout) {
        totalOut += txout.nValue;
    }

    // Calculate fee (inputs - outputs)
    if (totalIn < totalOut) {
        error = "Transaction inputs less than outputs (negative fee)";
        return false;
    }

    txFee = totalIn - totalOut;

    // Verify fee is within reasonable range
    if (!MoneyRange(txFee)) {
        error = "Transaction fee out of range";
        return false;
    }

    // Check for negative fees (should never happen with proper UTXO validation)
    if (txFee < 0) {
        error = "Transaction fee is negative";
        return false;
    }

    // CF-006: Enforce minimum transaction fees (production anti-spam)
    // Only enforce for non-coinbase transactions (coinbase has no inputs)
    if (!tx.IsCoinBase()) {
        std::string fee_error;
        if (!Consensus::CheckFee(tx, txFee, /*check_relay=*/true, &fee_error)) {
            error = "Fee requirement check failed: " + fee_error;
            return false;
        }
    }

    return true;
}

// ============================================================================
// Script Verification (Full Dilithium Signature Verification)
// ============================================================================

bool CTransactionValidator::VerifyScript(const CTransaction& tx,
                                          size_t inputIdx,
                                          const std::vector<uint8_t>& scriptSig,
                                          const std::vector<uint8_t>& scriptPubKey,
                                          std::string& error) const
{
    // ========================================================================
    // Script Interpreter-Based Verification (Phase 6)
    //
    // Replaces the previous hardcoded P2PKH validation with a general-purpose
    // Bitcoin-compatible script interpreter. The interpreter evaluates the same
    // P2PKH opcodes (OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG) via a
    // stack machine, and also supports HTLC, multisig, and other script types
    // when scriptV2 is activated.
    //
    // SIGNATURE MESSAGE (44 bytes):
    //   tx_signing_hash(32) + input_idx(4) + version(4) + chain_id(4)
    //   Hashed with SHA3-256 before Dilithium3 verification.
    //
    // SECURITY: Chain ID prevents cross-chain replay (EIP-155 style).
    //           Input index prevents cross-input replay.
    //           Version field prevents cross-version replay.
    // ========================================================================

    // DoS protection: reject oversized scripts
    if (scriptPubKey.size() > MAX_SCRIPT_SIZE) {
        error = "scriptPubKey exceeds maximum size (DoS protection)";
        return false;
    }
    if (scriptSig.size() > MAX_SCRIPT_SIZE) {
        error = "scriptSig exceeds maximum size (DoS protection)";
        return false;
    }

    // Build CScript for scriptPubKey (already in opcode format)
    CScript pubkey(scriptPubKey.begin(), scriptPubKey.end());

    // Build CScript for scriptSig, converting legacy format if needed
    // Legacy format: [2-byte LE sig_size][sig(3309)][2-byte LE pk_size][pk(1952)] = 5265 bytes
    // New format: [OP_PUSHDATA2][size LE][sig][OP_PUSHDATA2][size LE][pk] = 5267 bytes
    CScript sig;
    if (IsLegacyScriptSig(scriptSig)) {
        // Convert legacy 2-byte-LE-prefix format to Bitcoin-standard push opcodes
        sig.push_back(OP_PUSHDATA2);
        sig.push_back(static_cast<uint8_t>(DILITHIUM3_SIG_SIZE & 0xff));
        sig.push_back(static_cast<uint8_t>((DILITHIUM3_SIG_SIZE >> 8) & 0xff));
        sig.insert(sig.end(),
                   scriptSig.begin() + 2,
                   scriptSig.begin() + 2 + DILITHIUM3_SIG_SIZE);

        sig.push_back(OP_PUSHDATA2);
        sig.push_back(static_cast<uint8_t>(DILITHIUM3_PK_SIZE & 0xff));
        sig.push_back(static_cast<uint8_t>((DILITHIUM3_PK_SIZE >> 8) & 0xff));
        sig.insert(sig.end(),
                   scriptSig.begin() + 2 + DILITHIUM3_SIG_SIZE + 2,
                   scriptSig.end());
    } else {
        // Already in push-opcode format (new transactions)
        sig.assign(scriptSig.begin(), scriptSig.end());
    }

    // Construct signature checker with chain ID for cross-chain replay protection
    uint32_t chain_id = Dilithion::g_chainParams ? Dilithion::g_chainParams->chainID : 1;
    TransactionSignatureChecker checker(tx, static_cast<unsigned int>(inputIdx), chain_id);

    // Verification flags.
    // MINIMALDATA + CLEANSTACK are enabled here as defense-in-depth on the
    // sequential interpreter path (malleability finding #4). For P2PKH the
    // canonical-scriptSig gate in CheckTransactionInputs already rejects every
    // non-canonical form before this runs, so these never fire differently on
    // the P2PKH path (the canonical converted form uses minimal PUSHDATA2 pushes
    // and leaves exactly one stack element) — but they harden the general
    // scriptV2 path and cost nothing on the honest path.
    unsigned int flags = SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
                       | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
                       | SCRIPT_VERIFY_MINIMALDATA
                       | SCRIPT_VERIFY_CLEANSTACK;

    // Evaluate scripts through the interpreter
    return ::VerifyScript(sig, pubkey, flags, checker, error);
}

// ============================================================================
// Complete Transaction Validation
// ============================================================================

bool CTransactionValidator::CheckTransaction(const CTransaction& tx, CUTXOSet& utxoSet,
                                              uint32_t currentHeight, CAmount& txFee,
                                              std::string& error) const
{
    // Step 1: Basic structural validation
    if (!CheckTransactionBasic(tx, error)) {
        return false;
    }

    // Step 2: Input validation against UTXO set
    if (!CheckTransactionInputs(tx, utxoSet, currentHeight, txFee, error)) {
        return false;
    }

    // Step 3: Script verification for all inputs
    if (!tx.IsCoinBase()) {
        // SCRIPT-008 FIX: Rate limiting for signature verification (DoS protection)
        // Dilithium3 verification takes ~2ms per input. Limiting to 10,000 inputs
        // caps verification time at ~20 seconds, preventing computational DoS.
        // Attack scenario: 22,000 inputs × 2ms = 44 seconds = node paralysis
        if (tx.vin.size() > TxValidation::MAX_INPUT_COUNT_PER_TX) {
            error = "Transaction has too many inputs (DoS protection limit exceeded)";
            return false;
        }

        // Script V2 activation check: before activation height, only P2PKH is allowed.
        // The interpreter handles all scripts, but new types are gated by this check.
        if (Dilithion::g_chainParams &&
            static_cast<int>(currentHeight) < Dilithion::g_chainParams->scriptV2ActivationHeight) {
            for (size_t i = 0; i < tx.vout.size(); ++i) {
                CScript spk(tx.vout[i].scriptPubKey.begin(), tx.vout[i].scriptPubKey.end());
                if (!spk.IsPayToPublicKeyHash() && !spk.IsUnspendable()) {
                    error = "Non-P2PKH scripts not activated until height " +
                            std::to_string(Dilithion::g_chainParams->scriptV2ActivationHeight);
                    return false;
                }
            }
        }

        // Phase 3.2: Use batch verification for multi-input transactions
        // Batch verification provides ~3-4x speedup by verifying signatures in parallel.
        // Only used when ALL inputs spend P2PKH UTXOs (legacy format).
        // Non-P2PKH scripts (HTLC, etc.) fall through to sequential interpreter path.
        bool all_p2pkh = true;
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            CUTXOEntry entry;
            if (utxoSet.GetUTXO(tx.vin[i].prevout, entry)) {
                CScript spk(entry.out.scriptPubKey.begin(), entry.out.scriptPubKey.end());
                if (!spk.IsPayToPublicKeyHash() || !IsLegacyScriptSig(tx.vin[i].scriptSig)) {
                    all_p2pkh = false;
                    break;
                }
            }
        }

        bool use_batch = all_p2pkh &&
                         g_signature_verifier != nullptr &&
                         g_signature_verifier->IsRunning() &&
                         tx.vin.size() >= 2;

        if (use_batch) {
            // Batch verification path - verify all signatures in parallel
            if (!BatchVerifyScripts(tx, utxoSet, error)) {
                return false;
            }
        } else {
            // Sequential verification path (single input or no batch verifier)
            for (size_t i = 0; i < tx.vin.size(); ++i) {
                const CTxIn& txin = tx.vin[i];

                CUTXOEntry entry;
                if (!utxoSet.GetUTXO(txin.prevout, entry)) {
                    error = "Failed to retrieve UTXO for script verification";
                    return false;
                }

                if (!VerifyScript(tx, i, txin.scriptSig, entry.out.scriptPubKey, error)) {
                    char buf[256];
                    snprintf(buf, sizeof(buf), "Script verification failed for input %zu: %s", i, error.c_str());
                    error = buf;
                    return false;
                }
            }
        }
    }

    return true;
}

// ============================================================================
// Additional Validation Helpers
// ============================================================================

bool CTransactionValidator::IsStandardTransaction(const CTransaction& tx,
                                                   unsigned int currentHeight) const
{
    // Check transaction version (currently only version 1 is standard)
    if (tx.nVersion != 1) {
        return false;
    }

    // Check transaction size is reasonable (for relay)
    size_t txSize = tx.GetSerializedSize();
    if (txSize > TxValidation::MAX_TRANSACTION_SIZE / 10) {
        return false;  // Transactions over 100KB are not standard
    }

    // Check output values meet dust threshold (0.00001 DIL = 1000 ions)
    // OP_RETURN outputs are exempt (allowed to have zero value for data embedding)
    const CAmount dustThreshold = 1000;
    for (const auto& txout : tx.vout) {
        if (!txout.scriptPubKey.empty() && txout.scriptPubKey[0] == 0x6a) {
            continue;  // OP_RETURN: zero-value allowed
        }
        if (txout.nValue < dustThreshold) {
            return false;
        }
    }

    // Script standardness check
    // Post-scriptV2 activation: also accept HTLC, OP_RETURN, and other recognized types
    bool scriptV2Active = Dilithion::g_chainParams &&
                          (currentHeight >= static_cast<unsigned int>(
                               Dilithion::g_chainParams->scriptV2ActivationHeight));

    for (const auto& txout : tx.vout) {
        CScript spk(txout.scriptPubKey.begin(), txout.scriptPubKey.end());

        if (spk.IsPayToPublicKeyHash()) {
            continue;  // Standard P2PKH (25 bytes)
        }

        if (spk.IsUnspendable()) {
            continue;  // OP_RETURN is always standard
        }

        if (scriptV2Active && spk.IsHTLC()) {
            continue;  // HTLC is standard post-activation
        }

        // Legacy 37-byte SHA3-256 P2PKH (backward compat)
        size_t scriptSize = txout.scriptPubKey.size();
        if (scriptSize == 37 &&
            txout.scriptPubKey[0] == 0x76 &&
            txout.scriptPubKey[1] == 0xa9 &&
            txout.scriptPubKey[2] == 0x20 &&
            txout.scriptPubKey[35] == 0x88 &&
            txout.scriptPubKey[36] == 0xac) {
            continue;
        }

        return false;  // Non-standard script type
    }

    return true;
}

size_t CTransactionValidator::GetTransactionWeight(const CTransaction& tx) const
{
    // For now, weight = serialized size
    // In the future, this could account for witness data differently
    return tx.GetSerializedSize();
}

CAmount CTransactionValidator::GetMinimumFee(const CTransaction& tx) const
{
    // Use existing fee calculation from consensus/fees.h
    size_t txSize = tx.GetSerializedSize();
    return Consensus::CalculateMinFee(txSize);
}

bool CTransactionValidator::CheckDoubleSpend(const CTransaction& tx, CUTXOSet& utxoSet) const
{
    // Check for duplicate inputs within the transaction
    if (!CheckDuplicateInputs(tx)) {
        return false;
    }

    // Check all inputs exist in UTXO set (not already spent)
    for (const auto& txin : tx.vin) {
        if (!utxoSet.HaveUTXO(txin.prevout)) {
            return false;  // UTXO doesn't exist or already spent
        }
    }

    return true;
}

// ============================================================================
// Private Helper Functions
// ============================================================================

bool CTransactionValidator::CheckDuplicateInputs(const CTransaction& tx) const
{
    std::set<COutPoint> uniqueInputs;

    for (const auto& txin : tx.vin) {
        // Try to insert into set
        auto result = uniqueInputs.insert(txin.prevout);

        // If insertion failed, we found a duplicate
        if (!result.second) {
            return false;
        }
    }

    return true;
}

bool CTransactionValidator::CalculateTotalInputValue(const CTransaction& tx, CUTXOSet& utxoSet,
                                                       CAmount& totalIn, std::string& error) const
{
    totalIn = 0;

    for (const auto& txin : tx.vin) {
        CUTXOEntry entry;
        if (!utxoSet.GetUTXO(txin.prevout, entry)) {
            error = "Failed to retrieve UTXO entry";
            return false;
        }

        // Verify value is within range
        if (!MoneyRange(entry.out.nValue)) {
            error = "UTXO value out of range";
            return false;
        }

        // Add to total, checking for overflow
        CAmount newTotal = totalIn + entry.out.nValue;
        if (!MoneyRange(newTotal)) {
            error = "Total input value overflow";
            return false;
        }

        totalIn = newTotal;
    }

    return true;
}

bool CTransactionValidator::CheckCoinbaseMaturity(const CTransaction& tx, CUTXOSet& utxoSet,
                                                   uint32_t currentHeight, std::string& error) const
{
    for (const auto& txin : tx.vin) {
        CUTXOEntry entry;
        if (!utxoSet.GetUTXO(txin.prevout, entry)) {
            error = "Failed to retrieve UTXO for maturity check";
            return false;
        }

        // If this is a coinbase output, check maturity
        if (entry.fCoinBase) {
            uint32_t confirmations = currentHeight - entry.nHeight;

            unsigned int coinbaseMaturity = Dilithion::g_chainParams
                ? static_cast<unsigned int>(Dilithion::g_chainParams->coinbaseMaturity)
                : TxValidation::COINBASE_MATURITY;
            if (confirmations < coinbaseMaturity) {
                char buf[256];
                snprintf(buf, sizeof(buf),
                         "Coinbase output not mature (height: %u, current: %u, confirmations: %u, required: %u)",
                         entry.nHeight, currentHeight, confirmations, coinbaseMaturity);
                error = buf;
                return false;
            }
        }
    }

    return true;
}

// ============================================================================
// Phase 3.2: Batch Signature Verification
// ============================================================================

bool CTransactionValidator::PrepareSignatureData(const CTransaction& tx, size_t inputIdx,
                                                  const std::vector<uint8_t>& scriptSig,
                                                  const std::vector<uint8_t>& scriptPubKey,
                                                  std::vector<uint8_t>& signature,
                                                  std::vector<uint8_t>& message,
                                                  std::vector<uint8_t>& pubkey,
                                                  std::string& error) const
{
    // Dilithium3 sizes
    const size_t DILITHIUM3_SIG_SIZE = 3309;
    const size_t DILITHIUM3_PK_SIZE = 1952;
    const size_t EXPECTED_SCRIPTSIG_SIZE = 2 + DILITHIUM3_SIG_SIZE + 2 + DILITHIUM3_PK_SIZE;

    // Validate scriptPubKey (must be 25-byte P2PKH)
    if (scriptPubKey.size() != 25) {
        error = "scriptPubKey must be 25 bytes (P2PKH)";
        return false;
    }
    if (scriptPubKey[0] != 0x76 || scriptPubKey[1] != 0xa9 || scriptPubKey[2] != 0x14 ||
        scriptPubKey[23] != 0x88 || scriptPubKey[24] != 0xac) {
        error = "Invalid P2PKH script format";
        return false;
    }

    // Validate scriptSig size
    if (scriptSig.size() != EXPECTED_SCRIPTSIG_SIZE) {
        error = "Invalid scriptSig size";
        return false;
    }

    // Extract signature
    size_t pos = 0;
    uint16_t sig_size = scriptSig[pos] | (scriptSig[pos + 1] << 8);
    pos += 2;

    if (sig_size != DILITHIUM3_SIG_SIZE) {
        error = "Invalid signature size";
        return false;
    }

    signature.assign(scriptSig.begin() + pos, scriptSig.begin() + pos + sig_size);
    pos += sig_size;

    // Extract public key
    uint16_t pk_size = scriptSig[pos] | (scriptSig[pos + 1] << 8);
    pos += 2;

    if (pk_size != DILITHIUM3_PK_SIZE) {
        error = "Invalid public key size";
        return false;
    }

    pubkey.assign(scriptSig.begin() + pos, scriptSig.begin() + pos + pk_size);

    // Verify public key hash matches scriptPubKey
    uint8_t hash1[32];
    SHA3_256(pubkey.data(), pubkey.size(), hash1);
    uint8_t computed_hash[32];
    SHA3_256(hash1, 32, computed_hash);

    const uint8_t* expected_hash = scriptPubKey.data() + 3;
    if (memcmp(computed_hash, expected_hash, 20) != 0) {
        error = "Public key hash does not match scriptPubKey";
        return false;
    }

    // Construct signature message (same as VerifyScript) via the single-source
    // builder — byte-identical to the prior open-coded 44-byte form.
    if (Dilithion::g_chainParams == nullptr) {
        error = "Chain parameters not initialized";
        return false;
    }
    uint32_t chain_id = Dilithion::g_chainParams->chainID;

    uint256 tx_hash = tx.GetSigningHash();

    // Hash the signature message
    message.resize(32);
    Consensus::ComputeSighash(tx_hash,
                              static_cast<uint32_t>(inputIdx),
                              static_cast<uint32_t>(tx.nVersion),
                              chain_id,
                              message.data());

    return true;
}

bool CTransactionValidator::BatchVerifyScripts(const CTransaction& tx, CUTXOSet& utxoSet,
                                                std::string& error) const
{
    if (!g_signature_verifier || !g_signature_verifier->IsRunning()) {
        error = "Batch signature verifier not available";
        return false;
    }

    // Begin a new batch. The session is owned for the lifetime of this call
    // (CRITICAL-1 / LP-5): concurrent BatchVerifyScripts callers each get their
    // own session, so their batch state cannot cross-contaminate.
    //
    // The RAII guard (CCheckQueueControl pattern, see checkqueue.h) drains the
    // session via Wait() on EVERY exit path that does not consume the result —
    // both early-return branches below and any future exception. Draining is a
    // latency bound, not a safety requirement: every queued task shared_ptr-
    // owns the session (signature_batch_verifier.h S-005), so an abandoned
    // session is UAF-safe — the guard only avoids spending CPU on signatures
    // we're about to discard and a leaked-task-on-an-abandoned-session waste.
    // The guard's drain uses a throwaway error internally, so a bad signature
    // in an already-queued task can never clobber the real operator-facing
    // `error` we set on the early-return branches.
    std::shared_ptr<CBatchSession> session = g_signature_verifier->BeginBatch();
    CBatchSessionGuard guard(g_signature_verifier, session);

    // Prepare and add all signature verification tasks
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const CTxIn& txin = tx.vin[i];

        // Get UTXO for scriptPubKey
        CUTXOEntry entry;
        if (!utxoSet.GetUTXO(txin.prevout, entry)) {
            error = "Failed to retrieve UTXO for batch verification";
            return false;  // guard drains queued tasks; `error` preserved
        }

        // Prepare signature data
        std::vector<uint8_t> signature, message, pubkey;
        std::string prep_error;
        if (!PrepareSignatureData(tx, i, txin.scriptSig, entry.out.scriptPubKey,
                                  signature, message, pubkey, prep_error)) {
            char buf[256];
            snprintf(buf, sizeof(buf), "Failed to prepare signature data for input %zu: %s",
                     i, prep_error.c_str());
            error = buf;
            return false;  // guard drains queued tasks; `error` preserved
        }

        // Add to this batch's session
        g_signature_verifier->Add(session, signature, message, pubkey, i);
    }

    // Wait for all verifications in this session to complete. WaitResult()
    // consumes the verdict so the guard does NOT drain again on destruction.
    return guard.WaitResult(error);
}
