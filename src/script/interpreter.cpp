// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <script/interpreter.h>
#include <crypto/sha3.h>
#include <consensus/sighash_preimage.h>
#include <cstring>
#include <algorithm>

// Dilithium3 external API
extern "C" {
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

// ============================================================================
// Stack helpers
// ============================================================================

static inline bool CastToBool(const std::vector<uint8_t>& vch) {
    for (size_t i = 0; i < vch.size(); ++i) {
        if (vch[i] != 0) {
            // Negative zero: the last byte can be 0x80 (sign bit only)
            if (i == vch.size() - 1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

// Malleability closure (finding #4, sub-vector B2): SCRIPT_VERIFY_MINIMALDATA.
// A data push of `nSize` bytes must use its shortest possible opcode. Mirrors
// Bitcoin Core's CheckMinimalPush(BIP-62 rule 3/4). Returns true iff `opcode`
// is the minimal encoding for a push of `data[0..nSize)`.
//   * empty push        -> OP_0
//   * 1 byte, 1..16     -> OP_1..OP_16 (a raw push is non-minimal)
//   * 1 byte == 0x81    -> OP_1NEGATE
//   * <= 75 bytes       -> direct push (opcode == nSize)
//   * <= 255 bytes      -> OP_PUSHDATA1
//   * <= 65535 bytes    -> OP_PUSHDATA2
//   * larger            -> OP_PUSHDATA4 (only option)
// `firstByte` is data[0] for a 1-byte push and is ignored for other sizes.
static inline bool CheckMinimalPush(size_t nSize, uint8_t firstByte, uint8_t opcode) {
    if (nSize == 0)                                     return opcode == OP_0;
    if (nSize == 1 && firstByte >= 1 && firstByte <= 16) return false;  // must use OP_1..OP_16
    if (nSize == 1 && firstByte == 0x81)               return false;    // must use OP_1NEGATE
    if (nSize <= 75)                                   return opcode == nSize;
    if (nSize <= 255)                                  return opcode == OP_PUSHDATA1;
    if (nSize <= 65535)                                return opcode == OP_PUSHDATA2;
    return true;  // > 65535 can only be OP_PUSHDATA4
}

// ============================================================================
// TransactionSignatureChecker
// ============================================================================

TransactionSignatureChecker::TransactionSignatureChecker(
    const CTransaction& txTo, unsigned int nIn, uint32_t chainId)
    : m_tx(txTo), m_input_idx(nIn), m_chain_id(chainId)
{
}

bool TransactionSignatureChecker::CheckSig(
    const std::vector<uint8_t>& sig,
    const std::vector<uint8_t>& pubkey) const
{
    // Validate sizes
    if (sig.size() != DILITHIUM3_SIG_SIZE) return false;
    if (pubkey.size() != DILITHIUM3_PK_SIZE) return false;

    // Basic malleability checks (all-zeros, all-ones)
    {
        bool allZeros = true, allOnes = true;
        for (size_t i = 0; i < sig.size() && (allZeros || allOnes); ++i) {
            if (sig[i] != 0x00) allZeros = false;
            if (sig[i] != 0xFF) allOnes = false;
        }
        if (allZeros || allOnes) return false;
    }
    {
        bool allZeros = true, allOnes = true;
        for (size_t i = 0; i < pubkey.size() && (allZeros || allOnes); ++i) {
            if (pubkey[i] != 0x00) allZeros = false;
            if (pubkey[i] != 0xFF) allOnes = false;
        }
        if (allZeros || allOnes) return false;
    }

    // Construct signature message via the single-source builder:
    //   tx_signing_hash(32) + input_idx(4LE) + version(4LE) + chain_id(4LE)
    // (byte-identical to the prior open-coded 44-byte form).
    uint256 tx_hash = m_tx.GetSigningHash();

    // Hash the signature message
    uint8_t sig_hash[32];
    Consensus::ComputeSighash(tx_hash,
                              static_cast<uint32_t>(m_input_idx),
                              static_cast<uint32_t>(m_tx.nVersion),
                              m_chain_id,
                              sig_hash);

    // Verify Dilithium3 signature
    int result = pqcrystals_dilithium3_ref_verify(
        sig.data(), sig.size(),
        sig_hash, 32,
        nullptr, 0,
        pubkey.data()
    );

    return result == 0;
}

bool TransactionSignatureChecker::CheckLockTime(int64_t nLockTime) const {
    // Replicates existing nLockTime validation from tx_validation.cpp
    static const uint32_t LOCKTIME_THRESHOLD = 500000000;

    // nLockTime and tx.nLockTime must be in the same domain (both height or both time)
    if ((m_tx.nLockTime < LOCKTIME_THRESHOLD) != (nLockTime < static_cast<int64_t>(LOCKTIME_THRESHOLD)))
        return false;

    // The lock time must be <= the transaction's lock time
    if (nLockTime > static_cast<int64_t>(m_tx.nLockTime))
        return false;

    // The input's nSequence must not be finalized
    if (m_input_idx >= m_tx.vin.size())
        return false;
    if (m_tx.vin[m_input_idx].nSequence == CTxIn::SEQUENCE_FINAL)
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckSequence(int64_t nSequence) const {
    // BIP-68: relative lock-time
    // If the disable flag is set, the sequence is not enforced
    if (nSequence & (1LL << 31))
        return true;

    // Transaction version must be >= 2 for sequence enforcement (BIP-68)
    if (m_tx.nVersion < 2)
        return false;

    if (m_input_idx >= m_tx.vin.size())
        return false;

    // The input's sequence number must also have the disable flag unset
    uint32_t txSequence = m_tx.vin[m_input_idx].nSequence;
    if (txSequence & (1U << 31))
        return false;

    // Mask for type flag (bit 22) and value (bits 0-15)
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1U << 22);
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    // Both must be in the same domain (time-based or block-based)
    if ((txSequence & SEQUENCE_LOCKTIME_TYPE_FLAG) !=
        (static_cast<uint32_t>(nSequence) & SEQUENCE_LOCKTIME_TYPE_FLAG))
        return false;

    // The sequence value must be >= the required value
    if ((txSequence & SEQUENCE_LOCKTIME_MASK) <
        (static_cast<uint32_t>(nSequence) & SEQUENCE_LOCKTIME_MASK))
        return false;

    return true;
}

// ============================================================================
// EvalScript - Stack machine
// ============================================================================

bool EvalScript(std::vector<std::vector<uint8_t>>& stack,
                const CScript& script,
                unsigned int flags,
                const SignatureChecker& checker,
                std::string& error)
{
    if (script.size() > MAX_SCRIPT_SIZE) {
        error = "Script size exceeds maximum";
        return false;
    }

    // Execution state for IF/ELSE/ENDIF
    std::vector<bool> vfExec;  // Stack of execution states

    int nOpCount = 0;
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();

    try {
        while (pc < pend) {
            bool fExec = vfExec.empty() || vfExec.back();

            uint8_t opcode = *pc++;

            // ================================================================
            // Data push opcodes (0x01-0x4b): push next N bytes
            // ================================================================
            if (opcode > 0 && opcode < OP_PUSHDATA1) {
                size_t nSize = opcode;
                if (pc + nSize > pend) {
                    error = "Push data extends past end of script";
                    return false;
                }
                if (nSize > MAX_SCRIPT_ELEMENT_SIZE) {
                    error = "Push data size exceeds maximum element size";
                    return false;
                }
                if ((flags & SCRIPT_VERIFY_MINIMALDATA) &&
                    !CheckMinimalPush(nSize, (nSize >= 1 ? *pc : uint8_t(0)), opcode)) {
                    error = "Non-minimal data push (MINIMALDATA)";
                    return false;
                }
                if (fExec) {
                    std::vector<uint8_t> data(pc, pc + nSize);
                    stack.push_back(std::move(data));
                }
                pc += nSize;
                continue;
            }

            // ================================================================
            // OP_PUSHDATA1/2/4
            // ================================================================
            if (opcode == OP_PUSHDATA1 || opcode == OP_PUSHDATA2 || opcode == OP_PUSHDATA4) {
                size_t nSize = 0;
                if (opcode == OP_PUSHDATA1) {
                    if (pc + 1 > pend) { error = "OP_PUSHDATA1 past end"; return false; }
                    nSize = *pc++;
                } else if (opcode == OP_PUSHDATA2) {
                    if (pc + 2 > pend) { error = "OP_PUSHDATA2 past end"; return false; }
                    nSize = pc[0] | (static_cast<size_t>(pc[1]) << 8);
                    pc += 2;
                } else {
                    if (pc + 4 > pend) { error = "OP_PUSHDATA4 past end"; return false; }
                    nSize = pc[0] | (static_cast<size_t>(pc[1]) << 8) |
                            (static_cast<size_t>(pc[2]) << 16) | (static_cast<size_t>(pc[3]) << 24);
                    pc += 4;
                }
                if (pc + nSize > pend) {
                    error = "Push data extends past end of script";
                    return false;
                }
                if (nSize > MAX_SCRIPT_ELEMENT_SIZE) {
                    error = "Push data size exceeds maximum element size";
                    return false;
                }
                if ((flags & SCRIPT_VERIFY_MINIMALDATA) &&
                    !CheckMinimalPush(nSize, (nSize >= 1 ? *pc : uint8_t(0)), opcode)) {
                    error = "Non-minimal data push (MINIMALDATA)";
                    return false;
                }
                if (fExec) {
                    std::vector<uint8_t> data(pc, pc + nSize);
                    stack.push_back(std::move(data));
                }
                pc += nSize;
                continue;
            }

            // Count non-push opcodes toward the limit
            if (opcode > OP_16) {
                ++nOpCount;
                if (nOpCount > MAX_OPS_PER_SCRIPT) {
                    error = "Opcode count exceeds maximum";
                    return false;
                }
            }

            // ================================================================
            // Handle each opcode
            // ================================================================
            switch (opcode) {

            // ── Push value opcodes ──────────────────────────────────────────

            case OP_0: {
                if (fExec)
                    stack.push_back(std::vector<uint8_t>());
                break;
            }

            case OP_1NEGATE: {
                if (fExec) {
                    CScriptNum num(-1);
                    stack.push_back(num.getvch());
                }
                break;
            }

            case OP_1: case OP_2: case OP_3: case OP_4: case OP_5:
            case OP_6: case OP_7: case OP_8: case OP_9: case OP_10:
            case OP_11: case OP_12: case OP_13: case OP_14: case OP_15:
            case OP_16: {
                if (fExec) {
                    CScriptNum num(static_cast<int64_t>(opcode - (OP_1 - 1)));
                    stack.push_back(num.getvch());
                }
                break;
            }

            // ── Flow control ────────────────────────────────────────────────

            case OP_NOP:
                break;

            case OP_IF:
            case OP_NOTIF: {
                bool fValue = false;
                if (fExec) {
                    if (stack.empty()) {
                        error = "OP_IF/OP_NOTIF requires stack element";
                        return false;
                    }
                    fValue = CastToBool(stack.back());
                    if (opcode == OP_NOTIF)
                        fValue = !fValue;
                    stack.pop_back();
                }
                vfExec.push_back(fExec ? fValue : false);
                break;
            }

            case OP_ELSE: {
                if (vfExec.empty()) {
                    error = "OP_ELSE without OP_IF";
                    return false;
                }
                // Only flip if the parent is executing
                // Find if the second-to-last (parent) is true
                bool parentExec = (vfExec.size() < 2) || vfExec[vfExec.size() - 2];
                if (parentExec) {
                    vfExec.back() = !vfExec.back();
                }
                break;
            }

            case OP_ENDIF: {
                if (vfExec.empty()) {
                    error = "OP_ENDIF without OP_IF";
                    return false;
                }
                vfExec.pop_back();
                break;
            }

            case OP_VERIFY: {
                if (!fExec) break;
                if (stack.empty()) {
                    error = "OP_VERIFY requires stack element";
                    return false;
                }
                if (!CastToBool(stack.back())) {
                    error = "OP_VERIFY failed";
                    return false;
                }
                stack.pop_back();
                break;
            }

            case OP_RETURN: {
                if (fExec) {
                    error = "OP_RETURN encountered";
                    return false;
                }
                break;
            }

            // ── Stack operations ────────────────────────────────────────────

            case OP_DUP: {
                if (!fExec) break;
                if (stack.empty()) {
                    error = "OP_DUP requires stack element";
                    return false;
                }
                stack.push_back(stack.back());
                break;
            }

            case OP_DROP: {
                if (!fExec) break;
                if (stack.empty()) {
                    error = "OP_DROP requires stack element";
                    return false;
                }
                stack.pop_back();
                break;
            }

            case OP_SWAP: {
                if (!fExec) break;
                if (stack.size() < 2) {
                    error = "OP_SWAP requires two stack elements";
                    return false;
                }
                std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
                break;
            }

            case OP_SIZE: {
                if (!fExec) break;
                if (stack.empty()) {
                    error = "OP_SIZE requires stack element";
                    return false;
                }
                CScriptNum num(static_cast<int64_t>(stack.back().size()));
                stack.push_back(num.getvch());
                break;
            }

            // ── Comparison ──────────────────────────────────────────────────

            case OP_EQUAL:
            case OP_EQUALVERIFY: {
                if (!fExec) break;
                if (stack.size() < 2) {
                    error = "OP_EQUAL requires two stack elements";
                    return false;
                }
                bool equal = (stack[stack.size() - 1] == stack[stack.size() - 2]);
                stack.pop_back();
                stack.pop_back();
                stack.push_back(equal ? std::vector<uint8_t>{1} : std::vector<uint8_t>{});
                if (opcode == OP_EQUALVERIFY) {
                    if (!equal) {
                        error = "OP_EQUALVERIFY failed";
                        return false;
                    }
                    stack.pop_back();
                }
                break;
            }

            // ── Crypto ──────────────────────────────────────────────────────

            case OP_SHA3_256: {
                if (!fExec) break;
                if (stack.empty()) {
                    error = "OP_SHA3_256 requires stack element";
                    return false;
                }
                std::vector<uint8_t>& top = stack.back();
                uint8_t hash[32];
                SHA3_256(top.data(), top.size(), hash);
                top.assign(hash, hash + 32);
                break;
            }

            case OP_HASH160: {
                // Double SHA3-256, first 20 bytes
                // Matches WalletCrypto::HashPubKey():
                //   hash1 = SHA3_256(data)
                //   hash2 = SHA3_256(hash1)
                //   return hash2[0:20]
                if (!fExec) break;
                if (stack.empty()) {
                    error = "OP_HASH160 requires stack element";
                    return false;
                }
                std::vector<uint8_t>& top = stack.back();
                uint8_t hash1[32], hash2[32];
                SHA3_256(top.data(), top.size(), hash1);
                SHA3_256(hash1, 32, hash2);
                top.assign(hash2, hash2 + 20);
                break;
            }

            case OP_CHECKSIG: {
                if (!fExec) break;
                if (stack.size() < 2) {
                    error = "OP_CHECKSIG requires two stack elements";
                    return false;
                }
                // Stack: ... <sig> <pubkey>
                std::vector<uint8_t> pubkey = std::move(stack.back());
                stack.pop_back();
                std::vector<uint8_t> sig = std::move(stack.back());
                stack.pop_back();

                bool ok = checker.CheckSig(sig, pubkey);
                stack.push_back(ok ? std::vector<uint8_t>{1} : std::vector<uint8_t>{});
                break;
            }

            // ── Locktime ────────────────────────────────────────────────────

            case OP_CHECKLOCKTIMEVERIFY: {
                if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                    // If CLTV flag is not set, treat as OP_NOP (soft-fork compatible)
                    break;
                }
                if (!fExec) break;
                if (stack.empty()) {
                    error = "OP_CHECKLOCKTIMEVERIFY requires stack element";
                    return false;
                }

                // BIP-65: nLockTime is interpreted as a 5-byte script number
                CScriptNum nLockTime(stack.back(), 5);

                if (nLockTime.getint() < 0) {
                    error = "OP_CHECKLOCKTIMEVERIFY: negative locktime";
                    return false;
                }

                if (!checker.CheckLockTime(nLockTime.getint())) {
                    error = "OP_CHECKLOCKTIMEVERIFY: locktime not satisfied";
                    return false;
                }

                // BIP-65: do NOT pop the stack (element remains for potential OP_DROP)
                break;
            }

            case OP_CHECKSEQUENCEVERIFY: {
                if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                    // If CSV flag is not set, treat as OP_NOP (soft-fork compatible)
                    break;
                }
                if (!fExec) break;
                if (stack.empty()) {
                    error = "OP_CHECKSEQUENCEVERIFY requires stack element";
                    return false;
                }

                // BIP-112: nSequence is interpreted as a 5-byte script number
                CScriptNum nSequence(stack.back(), 5);

                if (nSequence.getint() < 0) {
                    error = "OP_CHECKSEQUENCEVERIFY: negative sequence";
                    return false;
                }

                if (!checker.CheckSequence(nSequence.getint())) {
                    error = "OP_CHECKSEQUENCEVERIFY: sequence not satisfied";
                    return false;
                }

                // BIP-112: do NOT pop the stack
                break;
            }

            // ── Reserved NOPs ───────────────────────────────────────────────

            case OP_NOP1:
            case OP_NOP4: case OP_NOP5: case OP_NOP6: case OP_NOP7:
            case OP_NOP8: case OP_NOP9: case OP_NOP10:
                // Soft-fork-safe NOPs: do nothing
                break;

            case OP_CHECKMULTISIG: {
                // Not yet implemented — fail cleanly
                if (!fExec) break;
                error = "OP_CHECKMULTISIG not yet implemented";
                return false;
            }

            default: {
                // Unknown opcode
                if (fExec) {
                    error = "Unknown opcode: 0x" +
                            std::string(1, "0123456789abcdef"[(opcode >> 4) & 0xf]) +
                            std::string(1, "0123456789abcdef"[opcode & 0xf]);
                    return false;
                }
                break;
            }

            } // switch

            // Stack size check
            if (stack.size() > MAX_STACK_SIZE) {
                error = "Stack size exceeds maximum";
                return false;
            }
        } // while

        if (!vfExec.empty()) {
            error = "Unmatched OP_IF/OP_ENDIF";
            return false;
        }

    } catch (const std::exception& e) {
        error = std::string("Script exception: ") + e.what();
        return false;
    }

    return true;
}

// ============================================================================
// VerifyScript - Two-phase verification (Bitcoin Core model)
// ============================================================================

bool VerifyScript(const CScript& scriptSig,
                  const CScript& scriptPubKey,
                  unsigned int flags,
                  const SignatureChecker& checker,
                  std::string& error)
{
    // Phase 1: Evaluate scriptSig to build the stack
    std::vector<std::vector<uint8_t>> stack;
    if (!EvalScript(stack, scriptSig, flags, checker, error)) {
        return false;
    }

    // Phase 2: Evaluate scriptPubKey using the stack from scriptSig
    if (!EvalScript(stack, scriptPubKey, flags, checker, error)) {
        return false;
    }

    // Final check: stack must have exactly one true element
    if (stack.empty()) {
        error = "Script evaluated to empty stack";
        return false;
    }

    if (!CastToBool(stack.back())) {
        error = "Script evaluated to false";
        return false;
    }

    // Malleability closure (finding #4, sub-vector B3): SCRIPT_VERIFY_CLEANSTACK.
    // The scriptSig may prepend arbitrary extra pushes that land BELOW sig/pk;
    // OP_CHECKSIG still leaves 1 on top so verification would pass while the
    // extra bytes mutate the txid. Require the final stack to hold EXACTLY one
    // element so no residue survives. Bitcoin BIP-62 rule 6.
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) && stack.size() != 1) {
        error = "Stack not clean after evaluation (CLEANSTACK)";
        return false;
    }

    return true;
}
