// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_SCRIPT_INTERPRETER_H
#define DILITHION_SCRIPT_INTERPRETER_H

#include <script/script.h>
#include <primitives/transaction.h>
#include <cstdint>
#include <vector>
#include <string>

// ============================================================================
// Script Verification Flags
// ============================================================================

enum ScriptVerifyFlags : unsigned int {
    SCRIPT_VERIFY_NONE                  = 0,
    SCRIPT_VERIFY_P2SH                  = (1U << 0),  // Future
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY   = (1U << 1),  // BIP-65
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY   = (1U << 2),  // BIP-112
    SCRIPT_VERIFY_NULLDUMMY             = (1U << 3),  // Require empty dummy for CHECKMULTISIG
    // Malleability closure (finding #4), general-script / scriptV2 surface:
    SCRIPT_VERIFY_MINIMALDATA           = (1U << 4),  // Every push must use its shortest opcode (kills B2)
    SCRIPT_VERIFY_CLEANSTACK            = (1U << 5),  // Final stack must hold exactly one element (kills B3)
};

// ============================================================================
// Signature Checker (abstract base)
// ============================================================================

class SignatureChecker {
public:
    virtual bool CheckSig(const std::vector<uint8_t>& sig,
                          const std::vector<uint8_t>& pubkey) const = 0;

    virtual bool CheckLockTime(int64_t nLockTime) const = 0;

    virtual bool CheckSequence(int64_t nSequence) const = 0;

    virtual ~SignatureChecker() = default;
};

// ============================================================================
// Transaction Signature Checker
// ============================================================================

class TransactionSignatureChecker : public SignatureChecker {
public:
    TransactionSignatureChecker(const CTransaction& txTo, unsigned int nIn, uint32_t chainId);

    bool CheckSig(const std::vector<uint8_t>& sig,
                  const std::vector<uint8_t>& pubkey) const override;

    bool CheckLockTime(int64_t nLockTime) const override;

    bool CheckSequence(int64_t nSequence) const override;

private:
    const CTransaction& m_tx;
    unsigned int m_input_idx;
    uint32_t m_chain_id;
};

// ============================================================================
// Script Evaluation
// ============================================================================

/**
 * Evaluate a script on the given stack.
 *
 * @param stack       Data stack (modified in place)
 * @param script      Script to evaluate
 * @param flags       Verification flags
 * @param checker     Signature checker for OP_CHECKSIG / OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY
 * @param error       Error message on failure
 * @return true if script executed successfully
 */
bool EvalScript(std::vector<std::vector<uint8_t>>& stack,
                const CScript& script,
                unsigned int flags,
                const SignatureChecker& checker,
                std::string& error);

/**
 * Verify a pair of scripts (scriptSig + scriptPubKey).
 *
 * Bitcoin Core two-phase model:
 * 1. Evaluate scriptSig -> resulting stack
 * 2. Copy stack, evaluate scriptPubKey with this stack
 * 3. Final stack must have exactly one true (non-empty, non-zero) element
 *
 * @param scriptSig      Unlocking script
 * @param scriptPubKey   Locking script
 * @param flags          Verification flags
 * @param checker        Signature checker
 * @param error          Error message on failure
 * @return true if scripts verify successfully
 */
bool VerifyScript(const CScript& scriptSig,
                  const CScript& scriptPubKey,
                  unsigned int flags,
                  const SignatureChecker& checker,
                  std::string& error);

#endif // DILITHION_SCRIPT_INTERPRETER_H
