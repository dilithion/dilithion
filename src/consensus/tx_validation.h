// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_TX_VALIDATION_H
#define DILITHION_CONSENSUS_TX_VALIDATION_H

#include <primitives/transaction.h>
#include <node/utxo_set.h>
#include <amount.h>
#include <string>
#include <set>

/**
 * Transaction validation constants
 */
namespace TxValidation {
    /** Maximum transaction size (1 MB) */
    static const size_t MAX_TRANSACTION_SIZE = 1000000;

    /** Maximum total money supply (21 million coins) */
    static const CAmount MAX_MONEY = 21000000LL * COIN;

    /** Minimum transaction fee (0.00001 DIL = 1000 ions) */
    static const CAmount MIN_TX_FEE = 1000;

    /** Coinbase maturity requirement (must wait 100 blocks) */
    static const uint32_t COINBASE_MATURITY = 100;

    /** Maximum number of signature operations per transaction */
    static const size_t MAX_TX_SIGOPS = 20000;

    /**
     * Maximum number of inputs per transaction (DoS protection)
     *
     * SCRIPT-008 FIX: Rate limiting for signature verification
     * Dilithium3 signature verification takes ~2ms per input.
     * Limiting to 10,000 inputs caps verification time at ~20 seconds.
     * This prevents computational DoS attacks via high-input-count transactions.
     */
    static const size_t MAX_INPUT_COUNT_PER_TX = 10000;

    /**
     * Maximum transaction size the wallet is allowed to construct (bytes).
     *
     * Mempool admission rejects txs > 1,000,000 bytes (node/mempool.cpp). With
     * Dilithium3 scriptSigs at ~5,308 bytes per input, a send that pulls in
     * thousands of tiny UTXOs easily exceeds that cap. Capping selection here
     * produces a clean "consolidate first" error instead of signing a 50+ MB
     * transaction that will be rejected downstream.
     *
     * 1 KB margin left for serialization overhead / future output variants.
     */
    static const size_t MAX_WALLET_TX_SIZE = 999000;
}

/**
 * IsCanonicalP2PKHScriptSig — the SINGLE canonical P2PKH scriptSig layout
 * (transaction-malleability closure, finding #4).
 *
 * Pre-scriptV2 the only spend type is P2PKH, and the ML-DSA signature commits to
 * NO scriptSig bytes (GetSigningHash blanks every scriptSig) while the txid commits
 * to ALL of them. Any scriptSig re-encoding that still verifies therefore mutates
 * the txid without invalidating the signature (classic pre-segwit malleability).
 * Exactly one byte-string is accepted per (sig, pk):
 *
 *   [sig_len == 3309 (2 LE)] [sig (3309)] [pk_len == 1952 (2 LE)] [pk (1952)] = 5265 bytes
 *
 * This is byte-for-byte what WalletCrypto::CreateScriptSig already emits, so no
 * honest spend is rejected. Exported (single-source) so both the mempool/relay
 * path (CTransactionValidator::CheckTransactionInputs) and the block-connect path
 * (ConnectBlockChecks) enforce the identical predicate — no drift, no consensus
 * split between the two surfaces. Coinbase inputs are exempt (both call sites skip
 * them).
 *
 * @param scriptSig The unlocking script bytes of a non-coinbase P2PKH input.
 * @return true iff scriptSig is the single canonical layout above.
 */
bool IsCanonicalP2PKHScriptSig(const std::vector<uint8_t>& scriptSig);

/**
 * CTransactionValidator
 *
 * Comprehensive transaction validation system for Dilithion cryptocurrency.
 * Validates individual transactions against consensus rules, UTXO set, and
 * cryptographic requirements.
 *
 * Thread Safety: Not thread-safe. Caller must ensure thread safety when
 * accessing shared UTXO set.
 */
class CTransactionValidator
{
public:
    CTransactionValidator() = default;
    ~CTransactionValidator() = default;

    /**
     * CheckTransactionBasic
     *
     * Performs basic structural validation of a transaction without
     * accessing the UTXO set. This is the first validation step.
     *
     * Checks:
     * - Non-empty inputs and outputs
     * - Positive output values
     * - No value overflow
     * - Reasonable transaction size
     * - No duplicate inputs
     * - Coinbase-specific rules
     *
     * @param tx The transaction to validate
     * @param error Reference to store error message if validation fails
     * @return true if valid, false otherwise
     */
    bool CheckTransactionBasic(const CTransaction& tx, std::string& error) const;

    /**
     * CheckTransactionInputs
     *
     * Validates transaction inputs against the UTXO set.
     * Verifies all inputs exist, are spendable, and calculates the fee.
     *
     * Checks:
     * - All inputs exist in UTXO set
     * - Coinbase maturity (100 blocks)
     * - Input values are valid
     * - Fee calculation (inputs - outputs)
     * - Non-negative fee
     *
     * @param tx The transaction to validate
     * @param utxoSet UTXO set to check inputs against
     * @param currentHeight Current blockchain height
     * @param txFee Output parameter to store calculated fee
     * @param error Reference to store error message if validation fails
     * @return true if valid, false otherwise
     */
    bool CheckTransactionInputs(const CTransaction& tx, CUTXOSet& utxoSet,
                                 uint32_t currentHeight, CAmount& txFee,
                                 std::string& error) const;

    /**
     * VerifyScript
     *
     * Validates transaction scripts with full Dilithium signature verification.
     *
     * Performs complete cryptographic validation:
     * - Parse signature and public key from scriptSig
     * - Extract public key hash from scriptPubKey
     * - Verify public key hashes to expected value
     * - Verify Dilithium3 signature over transaction
     *
     * @param tx The transaction being validated (for signature message)
     * @param inputIdx Index of the input being verified
     * @param scriptSig The signature script (unlocking script)
     * @param scriptPubKey The public key script (locking script)
     * @param error Reference to store error message if validation fails
     * @return true if valid, false otherwise
     */
    bool VerifyScript(const CTransaction& tx,
                      size_t inputIdx,
                      const std::vector<uint8_t>& scriptSig,
                      const std::vector<uint8_t>& scriptPubKey,
                      std::string& error) const;

    /**
     * CheckTransaction
     *
     * Complete transaction validation - combines all validation steps.
     * This is the main entry point for transaction validation.
     *
     * Performs:
     * 1. Basic structural validation
     * 2. Input validation against UTXO set
     * 3. Script verification for all inputs
     * 4. Fee calculation
     *
     * @param tx The transaction to validate
     * @param utxoSet UTXO set to check inputs against
     * @param currentHeight Current blockchain height
     * @param txFee Output parameter to store calculated fee
     * @param error Reference to store error message if validation fails
     * @return true if valid, false otherwise
     */
    bool CheckTransaction(const CTransaction& tx, CUTXOSet& utxoSet,
                          uint32_t currentHeight, CAmount& txFee,
                          std::string& error) const;

    /**
     * IsStandardTransaction
     *
     * Check if transaction follows standard rules for relay and mempool.
     * Standard transactions are more restrictive than consensus rules.
     *
     * Checks:
     * - Transaction version is supported
     * - Output values meet dust threshold
     * - Scripts are standard types
     * - Transaction size is reasonable
     *
     * @param tx            The transaction to check
     * @param currentHeight Current chain height (used to check scriptV2ActivationHeight).
     *                      Defaults to 0, which is conservative: only chains where
     *                      scriptV2ActivationHeight == 0 (DilV, testnet) will accept HTLCs.
     * @return true if transaction is standard
     */
    bool IsStandardTransaction(const CTransaction& tx,
                               unsigned int currentHeight = 0) const;

    /**
     * GetTransactionWeight
     *
     * Calculate transaction weight for fee calculation.
     * Currently uses serialized size, but can be extended for witness data.
     *
     * @param tx The transaction
     * @return Transaction weight in weight units
     */
    size_t GetTransactionWeight(const CTransaction& tx) const;

    /**
     * GetMinimumFee
     *
     * Calculate minimum required fee for a transaction based on size.
     *
     * @param tx The transaction
     * @return Minimum fee in ions
     */
    CAmount GetMinimumFee(const CTransaction& tx) const;

    /**
     * CheckDoubleSpend
     *
     * Verify transaction does not double-spend any outputs.
     * Checks both within the transaction itself and against the UTXO set.
     *
     * @param tx The transaction to check
     * @param utxoSet UTXO set to check against
     * @return true if no double-spend detected
     */
    bool CheckDoubleSpend(const CTransaction& tx, CUTXOSet& utxoSet) const;

private:
    /**
     * MoneyRange
     *
     * Check if an amount is within valid monetary range.
     *
     * @param nValue Amount to check
     * @return true if valid
     */
    bool MoneyRange(CAmount nValue) const {
        return (nValue >= 0 && nValue <= TxValidation::MAX_MONEY);
    }

    /**
     * CheckDuplicateInputs
     *
     * Verify transaction does not spend the same output twice.
     *
     * @param tx The transaction to check
     * @return true if no duplicates found
     */
    bool CheckDuplicateInputs(const CTransaction& tx) const;

    /**
     * CalculateTotalInputValue
     *
     * Calculate the total value of all transaction inputs.
     *
     * @param tx The transaction
     * @param utxoSet UTXO set to lookup input values
     * @param totalIn Output parameter for total input value
     * @param error Reference to store error message if lookup fails
     * @return true if successful
     */
    bool CalculateTotalInputValue(const CTransaction& tx, CUTXOSet& utxoSet,
                                   CAmount& totalIn, std::string& error) const;

    /**
     * CheckCoinbaseMaturity
     *
     * Verify coinbase inputs have sufficient confirmations.
     *
     * @param tx The transaction
     * @param utxoSet UTXO set to check coinbase status
     * @param currentHeight Current blockchain height
     * @param error Reference to store error message if immature
     * @return true if all coinbase inputs are mature
     */
    bool CheckCoinbaseMaturity(const CTransaction& tx, CUTXOSet& utxoSet,
                               uint32_t currentHeight, std::string& error) const;

    /**
     * BatchVerifyScripts
     *
     * Phase 3.2 Performance Optimization: Batch signature verification.
     * Verifies all input signatures in parallel using a thread pool.
     * Provides ~3-4x speedup for multi-input transactions.
     *
     * @param tx The transaction to verify
     * @param utxoSet UTXO set to lookup scriptPubKeys
     * @param error Reference to store error message if verification fails
     * @return true if all signatures are valid
     */
    bool BatchVerifyScripts(const CTransaction& tx, CUTXOSet& utxoSet,
                            std::string& error) const;

    /**
     * PrepareSignatureData
     *
     * Extract signature verification data from a transaction input.
     * Parses scriptSig and constructs the message to be verified.
     *
     * @param tx The transaction
     * @param inputIdx Index of the input
     * @param scriptSig The signature script
     * @param scriptPubKey The public key script
     * @param signature Output: extracted signature bytes
     * @param message Output: constructed message hash
     * @param pubkey Output: extracted public key bytes
     * @param error Reference to store error message if parsing fails
     * @return true if data extracted successfully
     */
    bool PrepareSignatureData(const CTransaction& tx, size_t inputIdx,
                              const std::vector<uint8_t>& scriptSig,
                              const std::vector<uint8_t>& scriptPubKey,
                              std::vector<uint8_t>& signature,
                              std::vector<uint8_t>& message,
                              std::vector<uint8_t>& pubkey,
                              std::string& error) const;
};

#endif // DILITHION_CONSENSUS_TX_VALIDATION_H
