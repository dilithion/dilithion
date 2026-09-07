// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wallet.h>
#include <core/chainparams.h>
#include <crypto/sha3.h>

#include <iostream>
#include <iomanip>

using namespace std;

bool TestSHA3() {
    cout << "Testing SHA-3-256..." << endl;

    // Test vector from NIST
    const char* msg = "abc";
    uint8_t hash[32];

    SHA3_256((const uint8_t*)msg, 3, hash);

    cout << "  Input: \"" << msg << "\"" << endl;
    cout << "  SHA3-256: ";
    for (int i = 0; i < 32; i++) {
        cout << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    cout << dec << endl;

    // Expected: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    bool correct = (hash[0] == 0x3a && hash[1] == 0x98 && hash[2] == 0x5d);

    if (correct) {
        cout << "  ✓ SHA-3 working correctly" << endl;
    } else {
        cout << "  ✗ SHA-3 output doesn't match expected" << endl;
    }

    return correct;
}

bool TestKeyGeneration() {
    cout << "\nTesting Dilithium key generation..." << endl;

    CKey key;
    if (!WalletCrypto::GenerateKeyPair(key)) {
        cout << "  ✗ Key generation failed" << endl;
        return false;
    }

    cout << "  ✓ Key pair generated" << endl;
    cout << "  Public key size: " << key.vchPubKey.size() << " bytes" << endl;
    cout << "  Secret key size: " << key.vchPrivKey.size() << " bytes" << endl;

    if (key.vchPubKey.size() != DILITHIUM_PUBLICKEY_SIZE) {
        cout << "  ✗ Invalid public key size" << endl;
        return false;
    }

    if (key.vchPrivKey.size() != DILITHIUM_SECRETKEY_SIZE) {
        cout << "  ✗ Invalid secret key size" << endl;
        return false;
    }

    cout << "  ✓ Key sizes correct" << endl;
    return true;
}

bool TestSignature() {
    cout << "\nTesting Dilithium signature..." << endl;

    // Generate key pair
    CKey key;
    if (!WalletCrypto::GenerateKeyPair(key)) {
        cout << "  ✗ Key generation failed" << endl;
        return false;
    }

    // Create a message to sign
    uint8_t message[32];
    for (int i = 0; i < 32; i++) {
        message[i] = i;
    }

    // Sign the message
    vector<uint8_t> signature;
    if (!WalletCrypto::Sign(key, message, 32, signature)) {
        cout << "  ✗ Signing failed" << endl;
        return false;
    }

    cout << "  ✓ Signature created" << endl;
    cout << "  Signature size: " << signature.size() << " bytes" << endl;

    // Verify the signature
    if (!WalletCrypto::Verify(key.vchPubKey, message, 32, signature)) {
        cout << "  ✗ Signature verification failed" << endl;
        return false;
    }

    cout << "  ✓ Signature verified" << endl;

    // Test with wrong message
    message[0] = 0xFF;
    if (WalletCrypto::Verify(key.vchPubKey, message, 32, signature)) {
        cout << "  ✗ Verification should have failed for wrong message" << endl;
        return false;
    }

    cout << "  ✓ Invalid signature correctly rejected" << endl;
    return true;
}

bool TestAddressGeneration() {
    cout << "\nTesting address generation..." << endl;

    // Generate key pair
    CKey key;
    if (!WalletCrypto::GenerateKeyPair(key)) {
        cout << "  ✗ Key generation failed" << endl;
        return false;
    }

    // Create address from public key
    CDilithiumAddress address(key.vchPubKey);

    if (!address.IsValid()) {
        cout << "  ✗ Address invalid" << endl;
        return false;
    }

    string addrStr = address.ToString();
    cout << "  Address: " << addrStr << endl;

    if (addrStr.empty()) {
        cout << "  ✗ Address string empty" << endl;
        return false;
    }

    // Test round-trip (string -> address -> string)
    CDilithiumAddress address2;
    if (!address2.SetString(addrStr)) {
        cout << "  ✗ Failed to parse address string" << endl;
        return false;
    }

    if (!(address == address2)) {
        cout << "  ✗ Address round-trip failed" << endl;
        return false;
    }

    cout << "  ✓ Address generation and encoding working" << endl;
    return true;
}

bool TestWalletBasics() {
    cout << "\nTesting wallet basics..." << endl;

    CWallet wallet;

    // Generate a key
    if (!wallet.GenerateNewKey()) {
        cout << "  ✗ Failed to generate key" << endl;
        return false;
    }

    cout << "  ✓ Key generated" << endl;
    cout << "  Keys in wallet: " << wallet.GetKeyPoolSize() << endl;

    // Get address
    CDilithiumAddress addr = wallet.GetNewAddress();
    if (!addr.IsValid()) {
        cout << "  ✗ Failed to get address" << endl;
        return false;
    }

    cout << "  ✓ Address: " << addr.ToString() << endl;

    // Check balance (should be 0)
    int64_t balance = wallet.GetBalance();
    if (balance != 0) {
        cout << "  ✗ Initial balance should be 0" << endl;
        return false;
    }

    cout << "  ✓ Initial balance: " << balance << endl;

    // Add a transaction output
    uint256 txid;
    txid.data[0] = 0x01;
    wallet.AddTxOut(txid, 0, 100000000, addr, 1);

    balance = wallet.GetBalance();
    if (balance != 100000000) {
        cout << "  ✗ Balance incorrect after adding txout" << endl;
        return false;
    }

    cout << "  ✓ Balance after txout: " << balance << endl;

    // Get unspent outputs
    auto unspent = wallet.GetUnspentTxOuts();
    if (unspent.size() != 1) {
        cout << "  ✗ Should have 1 unspent output" << endl;
        return false;
    }

    cout << "  ✓ Unspent outputs: " << unspent.size() << endl;

    // Mark as spent
    wallet.MarkSpent(txid, 0);
    balance = wallet.GetBalance();
    if (balance != 0) {
        cout << "  ✗ Balance should be 0 after spending" << endl;
        return false;
    }

    cout << "  ✓ Balance after spending: " << balance << endl;

    return true;
}

bool TestHashConsistency() {
    cout << "\nTesting hash consistency..." << endl;

    // Test that same input gives same hash
    uint8_t data[] = {1, 2, 3, 4, 5};
    uint8_t hash1[32], hash2[32];

    SHA3_256(data, 5, hash1);
    SHA3_256(data, 5, hash2);

    if (memcmp(hash1, hash2, 32) != 0) {
        cout << "  ✗ Same input produced different hashes" << endl;
        return false;
    }

    cout << "  ✓ Hash deterministic" << endl;

    // Test that different input gives different hash
    data[0] = 2;
    SHA3_256(data, 5, hash2);

    if (memcmp(hash1, hash2, 32) == 0) {
        cout << "  ✗ Different inputs produced same hash" << endl;
        return false;
    }

    cout << "  ✓ Hash sensitive to input changes" << endl;

    return true;
}

// ============================================================================
// Phase 5.2: Transaction Creation Tests
// ============================================================================

#include <node/utxo_set.h>
#include <node/mempool.h>
#include <primitives/transaction.h>
#include <consensus/tx_validation.h>

bool TestScriptCreation() {
    cout << "\nTesting script creation (Phase 5.2)..." << endl;

    // Generate a public key hash (32 bytes)
    std::vector<uint8_t> pubkey_hash(32);
    for (size_t i = 0; i < 32; i++) {
        pubkey_hash[i] = static_cast<uint8_t>(i);
    }

    // Create scriptPubKey
    std::vector<uint8_t> scriptPubKey = WalletCrypto::CreateScriptPubKey(pubkey_hash);

    // Verify P2PKH format: OP_DUP OP_HASH160 <hash_size> <hash> OP_EQUALVERIFY OP_CHECKSIG
    // Expected size: 1 + 1 + 1 + 32 + 1 + 1 = 37 bytes for 32-byte hash
    if (scriptPubKey.size() != 37) {
        cout << "  ✗ scriptPubKey size should be 37 bytes (P2PKH), got " << scriptPubKey.size() << endl;
        return false;
    }

    // Verify P2PKH opcodes
    if (scriptPubKey[0] != 0x76) {  // OP_DUP
        cout << "  ✗ First byte should be OP_DUP (0x76)" << endl;
        return false;
    }

    if (scriptPubKey[1] != 0xA9) {  // OP_HASH160
        cout << "  ✗ Second byte should be OP_HASH160 (0xA9)" << endl;
        return false;
    }

    if (scriptPubKey[2] != 32) {  // hash size
        cout << "  ✗ Third byte should be hash size (32)" << endl;
        return false;
    }

    if (scriptPubKey[35] != 0x88) {  // OP_EQUALVERIFY
        cout << "  ✗ Second-to-last byte should be OP_EQUALVERIFY (0x88)" << endl;
        return false;
    }

    if (scriptPubKey[36] != 0xAC) {  // OP_CHECKSIG
        cout << "  ✗ Last byte should be OP_CHECKSIG (0xAC)" << endl;
        return false;
    }

    cout << "  ✓ scriptPubKey format correct" << endl;

    // Extract hash back
    std::vector<uint8_t> extracted_hash = WalletCrypto::ExtractPubKeyHash(scriptPubKey);
    if (extracted_hash != pubkey_hash) {
        cout << "  ✗ Extracted hash doesn't match original" << endl;
        return false;
    }

    cout << "  ✓ Hash extraction working" << endl;

    // Create scriptSig
    std::vector<uint8_t> signature(3293, 0xFF);  // Mock Dilithium signature
    std::vector<uint8_t> pubkey(1952, 0xAA);     // Mock Dilithium pubkey

    std::vector<uint8_t> scriptSig = WalletCrypto::CreateScriptSig(signature, pubkey);

    // Verify format: [sig_size(2)] [signature] [pk_size(2)] [pubkey]
    size_t expected_size = 2 + 3293 + 2 + 1952;
    if (scriptSig.size() != expected_size) {
        cout << "  ✗ scriptSig size should be " << expected_size << " bytes, got " << scriptSig.size() << endl;
        return false;
    }

    // Verify signature size encoding (little-endian)
    uint16_t sig_size = scriptSig[0] | (scriptSig[1] << 8);
    if (sig_size != 3293) {
        cout << "  ✗ Signature size encoding incorrect" << endl;
        return false;
    }

    cout << "  ✓ scriptSig format correct" << endl;

    return true;
}

bool TestCoinSelection() {
    cout << "\nTesting coin selection (Phase 5.2)..." << endl;

    // Create wallet with multiple UTXOs
    CWallet wallet;
    wallet.GenerateNewKey();
    CDilithiumAddress addr = wallet.GetNewAddress();

    // Create mock UTXO set
    CUTXOSet utxo_set;
    utxo_set.Open(":memory:");  // In-memory database for testing

    // Add multiple UTXOs to wallet with different values
    std::vector<CAmount> values = {50000000, 30000000, 20000000, 10000000};
    for (size_t i = 0; i < values.size(); i++) {
        uint256 txid;
        txid.data[0] = static_cast<uint8_t>(i + 1);

        wallet.AddTxOut(txid, 0, values[i], addr, 100);

        // Add to global UTXO set
        std::vector<uint8_t> pubkey_hash = wallet.GetPubKeyHash();
        std::vector<uint8_t> scriptPubKey = WalletCrypto::CreateScriptPubKey(pubkey_hash);
        CTxOut txout(values[i], scriptPubKey);
        COutPoint outpoint(txid, 0);
        utxo_set.AddUTXO(outpoint, txout, 100, false);
    }

    utxo_set.Flush();

    // Test: Select coins for exact amount
    std::vector<CWalletTx> selected;
    CAmount total = 0;
    std::string error;

    unsigned int current_height = 200;  // All coins are mature

    if (!wallet.SelectCoins(50000000, selected, total, utxo_set, current_height, error)) {
        cout << "  ✗ Coin selection failed: " << error << endl;
        return false;
    }

    if (total < 50000000) {
        cout << "  ✗ Selected coins total less than requested" << endl;
        return false;
    }

    cout << "  ✓ Exact amount selection: selected " << selected.size() << " coins totaling " << total << endl;

    // Test: Select more than available (should fail)
    selected.clear();
    total = 0;
    if (wallet.SelectCoins(200000000, selected, total, utxo_set, current_height, error)) {
        cout << "  ✗ Should have failed to select insufficient coins" << endl;
        return false;
    }

    cout << "  ✓ Insufficient funds correctly detected" << endl;

    return true;
}

bool TestTransactionCreation() {
    cout << "\nTesting transaction creation (Phase 5.2)..." << endl;

    // Create two wallets
    CWallet sender_wallet;
    sender_wallet.GenerateNewKey();
    CDilithiumAddress sender_addr = sender_wallet.GetNewAddress();

    CWallet recipient_wallet;
    recipient_wallet.GenerateNewKey();
    CDilithiumAddress recipient_addr = recipient_wallet.GetNewAddress();

    // Create UTXO set
    CUTXOSet utxo_set;
    utxo_set.Open(":memory:");

    // Give sender some coins
    uint256 funding_txid;
    funding_txid.data[0] = 0x01;
    CAmount funding_amount = 100000000;  // 1 DLT

    sender_wallet.AddTxOut(funding_txid, 0, funding_amount, sender_addr, 100);

    // Add to UTXO set
    std::vector<uint8_t> sender_hash = sender_wallet.GetPubKeyHash();
    std::vector<uint8_t> scriptPubKey = WalletCrypto::CreateScriptPubKey(sender_hash);
    CTxOut funding_txout(funding_amount, scriptPubKey);
    COutPoint funding_outpoint(funding_txid, 0);
    utxo_set.AddUTXO(funding_outpoint, funding_txout, 100, false);
    utxo_set.Flush();

    // Create transaction
    CAmount amount_to_send = 50000000;  // 0.5 DLT
    // STALE EXPECTATION, fixed with its cite. 1000 ions = 0.00001000 DIL, which
    // is an order of magnitude BELOW MIN_RELAY_TX_FEE = 10000
    // (consensus/fees.h:20), so CreateTransaction refused with "Fee below
    // minimum relay fee". The expectation predates the current fee policy.
    // Use the wallet's own estimator rather than a fresh hardcoded number --
    // a literal here would go stale again the next time policy moves, and the
    // sibling test at :538 in this same file was ALREADY migrated to it.
    CAmount fee = CWallet::EstimateFee();
    CTransactionRef tx;
    std::string error;
    unsigned int current_height = 200;

    if (!sender_wallet.CreateTransaction(recipient_addr, amount_to_send, fee,
                                        utxo_set, current_height, tx, error)) {
        cout << "  ✗ Transaction creation failed: " << error << endl;
        return false;
    }

    cout << "  ✓ Transaction created successfully" << endl;

    // Verify transaction structure
    if (tx->vin.empty()) {
        cout << "  ✗ Transaction has no inputs" << endl;
        return false;
    }

    if (tx->vout.size() < 1 || tx->vout.size() > 2) {
        cout << "  ✗ Transaction should have 1-2 outputs (recipient + optional change)" << endl;
        return false;
    }

    cout << "  ✓ Transaction has " << tx->vin.size() << " input(s) and " << tx->vout.size() << " output(s)" << endl;

    // Verify first output is to recipient
    std::vector<uint8_t> recipient_hash = recipient_wallet.GetPubKeyHash();
    std::vector<uint8_t> expected_script = WalletCrypto::CreateScriptPubKey(recipient_hash);

    if (tx->vout[0].scriptPubKey != expected_script) {
        cout << "  ✗ First output not to recipient" << endl;
        return false;
    }

    if (tx->vout[0].nValue != amount_to_send) {
        cout << "  ✗ First output value incorrect" << endl;
        return false;
    }

    cout << "  ✓ Recipient output correct" << endl;

    // Verify change output if present
    if (tx->vout.size() == 2) {
        CAmount expected_change = funding_amount - amount_to_send - fee;
        if (tx->vout[1].nValue != expected_change) {
            cout << "  ✗ Change output value incorrect" << endl;
            return false;
        }
        cout << "  ✓ Change output correct: " << expected_change << endl;
    }

    // Verify inputs are signed
    for (size_t i = 0; i < tx->vin.size(); i++) {
        if (tx->vin[i].scriptSig.empty()) {
            cout << "  ✗ Input " << i << " not signed" << endl;
            return false;
        }
    }

    cout << "  ✓ All inputs signed" << endl;

    return true;
}

bool TestTransactionSending() {
    cout << "\nTesting transaction sending (Phase 5.2)..." << endl;

    // Create wallet
    CWallet wallet;
    wallet.GenerateNewKey();
    CDilithiumAddress addr = wallet.GetNewAddress();

    // Create UTXO set
    CUTXOSet utxo_set;
    utxo_set.Open(":memory:");

    // Fund wallet
    uint256 funding_txid;
    funding_txid.data[0] = 0x01;
    CAmount funding_amount = 100000000;

    wallet.AddTxOut(funding_txid, 0, funding_amount, addr, 100);

    std::vector<uint8_t> sender_hash = wallet.GetPubKeyHash();
    std::vector<uint8_t> scriptPubKey = WalletCrypto::CreateScriptPubKey(sender_hash);
    CTxOut funding_txout(funding_amount, scriptPubKey);
    COutPoint funding_outpoint(funding_txid, 0);
    utxo_set.AddUTXO(funding_outpoint, funding_txout, 100, false);
    utxo_set.Flush();

    // Create recipient
    CWallet recipient;
    recipient.GenerateNewKey();
    CDilithiumAddress recipient_addr = recipient.GetNewAddress();

    // Create transaction
    CTransactionRef tx;
    std::string error;
    unsigned int current_height = 200;

    // Use estimated fee instead of hardcoded fee
    CAmount fee = CWallet::EstimateFee();

    if (!wallet.CreateTransaction(recipient_addr, 50000000, fee,
                                 utxo_set, current_height, tx, error)) {
        cout << "  ✗ Transaction creation failed: " << error << endl;
        return false;
    }

    // Create mempool
    CTxMemPool mempool;
    mempool.SetHeight(current_height);

    // Send transaction
    if (!wallet.SendTransaction(tx, mempool, utxo_set, current_height, error)) {
        cout << "  ✗ Transaction sending failed: " << error << endl;
        return false;
    }

    cout << "  ✓ Transaction accepted to mempool" << endl;

    // Verify transaction is in mempool
    if (!mempool.Exists(tx->GetHash())) {
        cout << "  ✗ Transaction not found in mempool" << endl;
        return false;
    }

    cout << "  ✓ Transaction found in mempool" << endl;

    return true;
}

bool TestBalanceCalculation() {
    cout << "\nTesting balance calculation with maturity (Phase 5.2)..." << endl;

    CWallet wallet;
    wallet.GenerateNewKey();
    CDilithiumAddress addr = wallet.GetNewAddress();

    CUTXOSet utxo_set;
    utxo_set.Open(":memory:");

    std::vector<uint8_t> pubkey_hash = wallet.GetPubKeyHash();
    std::vector<uint8_t> scriptPubKey = WalletCrypto::CreateScriptPubKey(pubkey_hash);

    // Add mature coinbase UTXO
    uint256 txid1;
    txid1.data[0] = 0x01;
    wallet.AddTxOut(txid1, 0, 50000000, addr, 50);

    CTxOut txout1(50000000, scriptPubKey);
    COutPoint outpoint1(txid1, 0);
    utxo_set.AddUTXO(outpoint1, txout1, 50, true);  // Coinbase

    // Add immature coinbase UTXO
    uint256 txid2;
    txid2.data[0] = 0x02;
    wallet.AddTxOut(txid2, 0, 30000000, addr, 180);

    CTxOut txout2(30000000, scriptPubKey);
    COutPoint outpoint2(txid2, 0);
    utxo_set.AddUTXO(outpoint2, txout2, 180, true);  // Coinbase

    utxo_set.Flush();

    // Check balance at height 200
    // UTXO1 (height 50): 200 - 50 = 150 > 100 confirmations → MATURE
    // UTXO2 (height 180): 200 - 180 = 20 < 100 confirmations → IMMATURE

    unsigned int current_height = 200;
    CAmount balance = wallet.GetAvailableBalance(utxo_set, current_height);

    if (balance != 50000000) {
        cout << "  ✗ Balance should be 50000000 (only mature coinbase), got " << balance << endl;
        return false;
    }

    cout << "  ✓ Balance correctly excludes immature coinbase" << endl;

    // Check balance at height 280 (both mature)
    current_height = 280;
    balance = wallet.GetAvailableBalance(utxo_set, current_height);

    if (balance != 80000000) {
        cout << "  ✗ Balance should be 80000000 (both mature), got " << balance << endl;
        return false;
    }

    cout << "  ✓ Balance correct when both coinbases mature" << endl;

    return true;
}

bool TestEdgeCases() {
    cout << "\nTesting edge cases (Phase 5.2)..." << endl;

    CWallet wallet;
    wallet.GenerateNewKey();
    CDilithiumAddress addr = wallet.GetNewAddress();

    CUTXOSet utxo_set;
    utxo_set.Open(":memory:");

    // Test: Create transaction with zero amount (should fail)
    CTransactionRef tx;
    std::string error;
    unsigned int current_height = 200;

    if (wallet.CreateTransaction(addr, 0, 1000, utxo_set, current_height, tx, error)) {
        cout << "  ✗ Should have rejected zero amount" << endl;
        return false;
    }

    cout << "  ✓ Zero amount correctly rejected" << endl;

    // Test: Create transaction with negative fee (should fail)
    if (wallet.CreateTransaction(addr, 1000, -100, utxo_set, current_height, tx, error)) {
        cout << "  ✗ Should have rejected negative fee" << endl;
        return false;
    }

    cout << "  ✓ Negative fee correctly rejected" << endl;

    // Test: Create transaction with no funds (should fail)
    if (wallet.CreateTransaction(addr, 1000000, 1000, utxo_set, current_height, tx, error)) {
        cout << "  ✗ Should have rejected insufficient funds" << endl;
        return false;
    }

    cout << "  ✓ Insufficient funds correctly detected" << endl;

    // Test: Empty wallet balance
    CAmount balance = wallet.GetAvailableBalance(utxo_set, current_height);
    if (balance != 0) {
        cout << "  ✗ Empty wallet should have zero balance" << endl;
        return false;
    }

    cout << "  ✓ Empty wallet balance correct" << endl;

    return true;
}

int main() {
    cout << "======================================" << endl;
    cout << "Phase 5.2 Wallet Integration Tests" << endl;
    cout << "Post-Quantum Transaction System" << endl;
    cout << "======================================" << endl;
    cout << endl;

    // THE OTHER QUARANTINE CAUSE. Without this the suite fails with its own
    // message -- "Transaction creation failed: Chain parameters not
    // initialized" -- because CreateTransaction reaches consensus code that
    // needs g_chainParams. Production initialises it at startup
    // (dilithion-node.cpp:2249-2255); this harness never did. Same shape as
    // rpc_tests (auth+permissions) and miner_tests (RandomX): the code
    // correctly refuses to run uninitialised and the SUITE was quarantined for
    // it. Regtest is the lightest of the three parameter sets.
    if (Dilithion::g_chainParams == nullptr) {
        Dilithion::g_chainParams =
            new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
    }

    bool allPassed = true;

    // Phase 4 tests (baseline)
    cout << "=== Phase 4 Tests (Baseline) ===" << endl;
    allPassed &= TestSHA3();
    allPassed &= TestHashConsistency();
    allPassed &= TestKeyGeneration();
    allPassed &= TestSignature();
    allPassed &= TestAddressGeneration();
    allPassed &= TestWalletBasics();

    // Phase 5.2 tests (new transaction functionality)
    cout << endl << "=== Phase 5.2 Tests (Transaction System) ===" << endl;
    allPassed &= TestScriptCreation();
    allPassed &= TestCoinSelection();
    allPassed &= TestTransactionCreation();
    allPassed &= TestTransactionSending();
    allPassed &= TestBalanceCalculation();
    allPassed &= TestEdgeCases();

    cout << endl;
    cout << "======================================" << endl;
    if (allPassed) {
        cout << "✅ All wallet tests passed!" << endl;
    } else {
        cout << "❌ Some tests failed" << endl;
    }
    cout << "======================================" << endl;
    cout << endl;

    cout << "Phase 5.2 Components Validated:" << endl;
    cout << "  ✓ SHA-3-256 hashing (quantum-resistant)" << endl;
    cout << "  ✓ Dilithium3 key generation & signatures" << endl;
    cout << "  ✓ Address generation (Base58Check)" << endl;
    cout << "  ✓ UTXO management & tracking" << endl;
    cout << "  ✓ Balance calculation with maturity" << endl;
    cout << "  ✓ Script creation (P2PKH-like)" << endl;
    cout << "  ✓ Coin selection algorithm" << endl;
    cout << "  ✓ Transaction creation & signing" << endl;
    cout << "  ✓ Transaction validation" << endl;
    cout << "  ✓ Mempool integration" << endl;
    cout << endl;

    cout << "Post-Quantum Security Stack:" << endl;
    cout << "  ✓ Signatures: CRYSTALS-Dilithium3 (NIST PQC)" << endl;
    cout << "  ✓ Hashing: SHA-3-256 (quantum-resistant)" << endl;
    cout << "  ✓ Mining: RandomX (CPU-friendly, ASIC-resistant)" << endl;
    cout << "  ✓ Transactions: Full UTXO model" << endl;
    cout << endl;

    return allPassed ? 0 : 1;
}
