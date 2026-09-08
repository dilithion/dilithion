// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Phase 5 Integration Tests
 *
 * Tests the full integration of all components:
 * - Phase 1: Blockchain storage, mempool, fees
 * - Phase 2: P2P networking (basic)
 * - Phase 3: Mining controller
 * - Phase 4: Wallet, RPC server
 */

#include <node/blockchain_storage.h>
#include <node/mempool.h>
#include <node/block_index.h>
#include <consensus/fees.h>
#include <consensus/pow.h>
#include <net/peers.h>
#include <net/net.h>
#include <net/connman.h>
#include <miner/controller.h>
#include <wallet/wallet.h>
#include <rpc/server.h>
#include <rpc/auth.h>
#include <util/time.h>
#include <crypto/randomx_hash.h>

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>
#include <filesystem>

// Needed by UniqueTempPath below. This file previously had no platform include
// block at all, so the process-id call has to bring its own.
#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

using namespace std;

// MEM-MED-001 FIX: Replace system() with std::filesystem for safe directory operations
// Helper: Remove test directory
void CleanupTestDir(const string& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    // Ignore errors - directory may not exist
}

// Helper: Create test directory
void CreateTestDir(const string& path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
}

// Per-invocation temp paths. This is the THIRD consecutive review round in
// which a principle landed in rpc_tests.cpp and not in its twin here, so it is
// being applied to both files at once rather than a third time to one. A fixed
// /tmp path is a greenness gate held by anyone who can write /tmp:
// InitializePermissions -> LoadFromFile succeeds if the file merely EXISTS and
// returns without installing the credentials.
static std::string UniqueTempPath(const std::string& stem) {
#ifdef _WIN32
    const long pid = static_cast<long>(GetCurrentProcessId());
#else
    const long pid = static_cast<long>(getpid());
#endif
    const std::string p =
        (std::filesystem::temp_directory_path()
         / (stem + "_" + std::to_string(pid) + ".json")).string();
    std::error_code ec;
    std::filesystem::remove(p, ec);
    return p;
}

bool TestBlockchainAndMempool() {
    cout << "Testing blockchain storage and mempool integration..." << endl;

    string testdir = "/tmp/dilithion-integration-test-1";
    CleanupTestDir(testdir);
    CreateTestDir(testdir + "/blocks");

    // Open blockchain database
    CBlockchainDB blockchain;
    if (!blockchain.Open(testdir + "/blocks")) {
        cout << "  ✗ Failed to open blockchain database" << endl;
        return false;
    }
    cout << "  ✓ Blockchain database opened" << endl;

    // Create mempool
    CTxMemPool mempool;
    cout << "  ✓ Mempool created" << endl;

    // Create and store a block
    CBlock block;
    block.nVersion = 1;
    block.nTime = static_cast<uint32_t>(time(nullptr));
    block.nBits = 0x1d00ffff;
    block.nNonce = 12345;

    uint256 hash = block.GetHash();
    if (!blockchain.WriteBlock(hash, block)) {
        cout << "  ✗ Failed to write block" << endl;
        return false;
    }
    cout << "  ✓ Block written to database" << endl;

    // Read block back
    CBlock readBlock;
    if (!blockchain.ReadBlock(hash, readBlock)) {
        cout << "  ✗ Failed to read block" << endl;
        return false;
    }

    if (readBlock.nVersion != block.nVersion ||
        readBlock.nTime != block.nTime ||
        readBlock.nBits != block.nBits ||
        readBlock.nNonce != block.nNonce) {
        cout << "  ✗ Block data mismatch" << endl;
        return false;
    }
    cout << "  ✓ Block read correctly" << endl;

    blockchain.Close();
    CleanupTestDir(testdir);
    return true;
}

bool TestMiningIntegration() {
    cout << "\nTesting mining controller integration..." << endl;

    // Create mining controller with 2 threads
    CMiningController miner(2);
    cout << "  ✓ Mining controller created (2 threads)" << endl;

    // Create block template
    CBlock block;
    block.nVersion = 1;
    block.nTime = static_cast<uint32_t>(time(nullptr));
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;

    // Very easy target (high value = easy to find block below this)
    uint256 hashTarget;
    hashTarget.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    CBlockTemplate blockTemplate(block, hashTarget, 0);

    // Track if block found
    bool blockFound = false;
    miner.SetBlockFoundCallback([&](const CBlock& foundBlock) {
        blockFound = true;
        uint256 hash = foundBlock.GetHash();
        cout << "  ✓ Block found! Hash: " << hash.GetHex().substr(0, 16) << "..." << endl;
    });

    // Start mining
    if (!miner.StartMining(blockTemplate)) {
        cout << "  ✗ Failed to start mining" << endl;
        return false;
    }
    cout << "  ✓ Mining started" << endl;

    // Mine for a bit
    this_thread::sleep_for(chrono::seconds(2));

    // Check stats
    auto stats = miner.GetStats();
    if (stats.nHashesComputed == 0) {
        cout << "  ✗ No hashes computed" << endl;
        miner.StopMining();
        return false;
    }
    cout << "  ✓ Hashes computed: " << stats.nHashesComputed << endl;
    cout << "  ✓ Hash rate: " << miner.GetHashRate() << " H/s" << endl;

    // Stop mining
    miner.StopMining();
    cout << "  ✓ Mining stopped" << endl;

    return true;
}

bool TestWalletIntegration() {
    cout << "\nTesting wallet integration..." << endl;

    CWallet wallet;
    cout << "  ✓ Wallet created" << endl;

    // Generate keys
    for (int i = 0; i < 3; ++i) {
        if (!wallet.GenerateNewKey()) {
            cout << "  ✗ Failed to generate key " << i << endl;
            return false;
        }
    }
    cout << "  ✓ Generated 3 key pairs" << endl;

    // Get addresses
    auto addresses = wallet.GetAddresses();
    if (addresses.size() != 3) {
        cout << "  ✗ Expected 3 addresses, got " << addresses.size() << endl;
        return false;
    }
    cout << "  ✓ Retrieved 3 addresses:" << endl;
    for (const auto& addr : addresses) {
        cout << "    " << addr.ToString() << endl;
    }

    // Check initial balance
    if (wallet.GetBalance() != 0) {
        cout << "  ✗ Expected balance 0, got " << wallet.GetBalance() << endl;
        return false;
    }
    cout << "  ✓ Initial balance: 0" << endl;

    // Add a fake UTXO
    uint256 txid;
    wallet.AddTxOut(txid, 0, 1000000, addresses[0], 0);  // 1M ions

    if (wallet.GetBalance() != 1000000) {
        cout << "  ✗ Expected balance 1000000, got " << wallet.GetBalance() << endl;
        return false;
    }
    cout << "  ✓ Balance after UTXO: " << wallet.GetBalance() << endl;

    return true;
}

bool TestRPCIntegration() {
    cout << "\nTesting RPC server integration..." << endl;

    // Create components
    CWallet wallet;
    wallet.GenerateNewKey();

    CMiningController miner(2);

    // Create RPC server
    CRPCServer server(18546);  // Use higher port to avoid conflicts
    server.RegisterWallet(&wallet);
    server.RegisterMiner(&miner);

    // CVE-2026-RPC-AUTH: Start() refuses unless auth AND permissions are
    // initialised (server.cpp:468-478). Production does both
    // (dilithion-node.cpp:7656). This test did neither, so Start() always
    // failed -- and then blamed "port conflict or system limitation" and
    // returned TRUE, so the suite reported "✓ RPC server start/stop" and exited
    // 0 while the RPC server had never started once. The server prints the real
    // reason on the line immediately above; the test overwrote it with a guess.
    if (!RPCAuth::InitializeAuth("testuser", "testpassword123")) {
        cout << "  ✗ RPCAuth::InitializeAuth failed" << endl;
        return false;
    }
    const std::string perms_path = UniqueTempPath("dil_integration_rpc_perms");
    if (!server.InitializePermissions(perms_path, "testuser", "testpassword123")) {
        cout << "  ✗ InitializePermissions failed (" << perms_path << ")" << endl;
        return false;
    }

    if (!server.Start()) {
        cout << "  ✗ Failed to start RPC server" << endl;
        cout << "    auth configured : " << (RPCAuth::IsAuthConfigured() ? "yes" : "NO") << endl;
        cout << "    Start() printed the actual cause above. Not skipping: an RPC" << endl;
        cout << "    server that will not start is a failure of this test." << endl;
        return false;
    }
    cout << "  ✓ RPC server started on port 18546" << endl;

    // Give server time to start
    this_thread::sleep_for(chrono::milliseconds(100));

    if (!server.IsRunning()) {
        cout << "  ✗ Server not running" << endl;
        return false;
    }
    cout << "  ✓ Server is running" << endl;

    // Stop server
    server.Stop();

    if (server.IsRunning()) {
        cout << "  ✗ Server still running after stop" << endl;
        return false;
    }
    cout << "  ✓ Server stopped cleanly" << endl;

    return true;
}

bool TestRPCAuthenticationIntegration() {
    cout << "\nTesting RPC authentication integration..." << endl;

    // Test 1: Initialize authentication
    if (!RPCAuth::InitializeAuth("testuser", "testpassword123")) {
        cout << "  ✗ Failed to initialize authentication" << endl;
        return false;
    }
    cout << "  ✓ Authentication initialized" << endl;

    // Test 2: Check authentication is configured
    if (!RPCAuth::IsAuthConfigured()) {
        cout << "  ✗ Authentication not configured after initialization" << endl;
        return false;
    }
    cout << "  ✓ Authentication is configured" << endl;

    // Test 3: Valid credentials
    if (!RPCAuth::AuthenticateRequest("testuser", "testpassword123")) {
        cout << "  ✗ Valid credentials rejected" << endl;
        return false;
    }
    cout << "  ✓ Valid credentials accepted" << endl;

    // Test 4: Invalid username
    if (RPCAuth::AuthenticateRequest("wronguser", "testpassword123")) {
        cout << "  ✗ Invalid username accepted" << endl;
        return false;
    }
    cout << "  ✓ Invalid username rejected" << endl;

    // Test 5: Invalid password
    if (RPCAuth::AuthenticateRequest("testuser", "wrongpassword")) {
        cout << "  ✗ Invalid password accepted" << endl;
        return false;
    }
    cout << "  ✓ Invalid password rejected" << endl;

    // Test 6: Parse HTTP Basic Auth header
    string username, password;
    if (!RPCAuth::ParseAuthHeader("Basic dXNlcjpwYXNz", username, password)) {
        cout << "  ✗ Failed to parse valid auth header" << endl;
        return false;
    }
    if (username != "user" || password != "pass") {
        cout << "  ✗ Parsed credentials incorrect" << endl;
        return false;
    }
    cout << "  ✓ HTTP Basic Auth header parsed correctly" << endl;

    // Test 7: Reject invalid auth header
    if (RPCAuth::ParseAuthHeader("Invalid header", username, password)) {
        cout << "  ✗ Invalid auth header accepted" << endl;
        return false;
    }
    cout << "  ✓ Invalid auth header rejected" << endl;

    return true;
}

bool TestTimestampValidationIntegration() {
    cout << "\nTesting timestamp validation integration..." << endl;

    // Test 1: Future timestamp validation
    CBlockHeader block;
    int64_t now = GetTime();

    // Valid: 1 hour in future
    block.nTime = now + 3600;
    if (!CheckBlockTimestamp(block, nullptr)) {
        cout << "  ✗ Valid future timestamp rejected" << endl;
        return false;
    }
    cout << "  ✓ Valid future timestamp (1h) accepted" << endl;

    // Invalid: 3 hours in future
    block.nTime = now + 3 * 3600;
    if (CheckBlockTimestamp(block, nullptr)) {
        cout << "  ✗ Invalid future timestamp accepted" << endl;
        return false;
    }
    cout << "  ✓ Invalid future timestamp (3h) rejected" << endl;

    // Test 2: Median-time-past validation
    // Create a simple chain
    vector<CBlockIndex> chain(5);
    int64_t baseTime = now - 5000;
    for (size_t i = 0; i < chain.size(); i++) {
        chain[i].nTime = baseTime + i * 600;
        chain[i].nHeight = i;
        if (i > 0) {
            chain[i].pprev = &chain[i - 1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    // Calculate median-time-past
    int64_t median = GetMedianTimePast(&chain[4]);
    cout << "  ✓ Median-time-past calculated: " << median << endl;

    // Block time equal to MTP should be rejected
    block.nTime = median;
    if (CheckBlockTimestamp(block, &chain[4])) {
        cout << "  ✗ Block time equal to MTP accepted" << endl;
        return false;
    }
    cout << "  ✓ Block time equal to MTP rejected" << endl;

    // Block time greater than MTP should be accepted
    block.nTime = median + 1;
    if (!CheckBlockTimestamp(block, &chain[4])) {
        cout << "  ✗ Block time greater than MTP rejected" << endl;
        return false;
    }
    cout << "  ✓ Block time greater than MTP accepted" << endl;

    return true;
}

bool TestFullNodeStack() {
    cout << "\nTesting full node stack integration..." << endl;

    string testdir = "/tmp/dilithion-integration-test-full";
    CleanupTestDir(testdir);
    CreateTestDir(testdir + "/blocks");

    try {
        // Phase 1: Blockchain and mempool
        CBlockchainDB blockchain;
        if (!blockchain.Open(testdir + "/blocks")) {
            cout << "  ✗ Failed to open blockchain" << endl;
            return false;
        }
        cout << "  ✓ Blockchain initialized" << endl;

        CTxMemPool mempool;
        cout << "  ✓ Mempool initialized" << endl;

        // Phase 2: P2P components (using CConnman instead of deprecated CConnectionManager)
        CPeerManager peer_manager;
        CNetMessageProcessor message_processor(peer_manager);
        CConnman connman;
        CConnmanOptions options;
        options.fListen = false;  // Don't listen in tests
        options.nMaxOutbound = 8;
        options.nMaxInbound = 117;
        options.nMaxTotal = 125;
        // Identical shape to the RPC skip this commit exists to remove, and it
        // sits 39 lines above it in the same function: it printed a cross,
        // continued, and TestFullNodeStack still returned true -- so
        // "✓ Full node stack initialization" printed with P2P never started.
        // The failure branch also abandoned a partially-started CConnman
        // without calling Stop().
        if (!connman.Start(peer_manager, message_processor, options)) {
            cout << "  ✗ Failed to start CConnman" << endl;
            connman.Stop();  // do not abandon a partially-started connman
            return false;
        }
        cout << "  ✓ P2P components initialized (CConnman)" << endl;
        connman.Stop();  // Clean shutdown

        // Phase 3: Mining
        CMiningController miner(2);
        cout << "  ✓ Mining controller initialized" << endl;

        // Phase 4: Wallet
        CWallet wallet;
        wallet.GenerateNewKey();
        CDilithiumAddress addr = wallet.GetNewAddress();
        cout << "  ✓ Wallet initialized (address: " << addr.ToString() << ")" << endl;

        // Phase 4: RPC server
        CRPCServer rpc_server(18547);  // Use higher port to avoid conflicts
        rpc_server.RegisterWallet(&wallet);
        rpc_server.RegisterMiner(&miner);

        // Second site, and it failed for a DIFFERENT reason than the first:
        // by the time the full-stack phase runs, InitializeAuth has been called
        // by TestRPCAuthenticationIntegration, so this one got past the auth
        // check and tripped the permissions check instead
        // ("Start() called before InitializePermissions()"). Both were reported
        // as "not critical", so neither ever surfaced.
        const std::string stack_perms = UniqueTempPath("dil_integration_stack_perms");
        if (!RPCAuth::IsAuthConfigured() &&
            !RPCAuth::InitializeAuth("testuser", "testpassword123")) {
            cout << "  ✗ RPCAuth::InitializeAuth failed" << endl;
            return false;
        }
        if (!rpc_server.InitializePermissions(stack_perms, "testuser", "testpassword123")) {
            cout << "  ✗ InitializePermissions failed (" << stack_perms << ")" << endl;
            return false;
        }
        if (!rpc_server.Start()) {
            cout << "  ✗ RPC server failed to start in the full-stack phase" << endl;
            cout << "    auth configured : " << (RPCAuth::IsAuthConfigured() ? "yes" : "NO") << endl;
            return false;
        }
        cout << "  ✓ RPC server started" << endl;

        // Let everything run for a moment
        this_thread::sleep_for(chrono::milliseconds(500));

        // Clean shutdown
        cout << "  Initiating shutdown..." << endl;
        rpc_server.Stop();
        blockchain.Close();
        cout << "  ✓ Clean shutdown completed" << endl;

        CleanupTestDir(testdir);
        return true;

    } catch (const exception& e) {
        cout << "  ✗ Exception: " << e.what() << endl;
        CleanupTestDir(testdir);
        return false;
    }
}

int main() {
    cout << "======================================" << endl;
    cout << "Comprehensive Integration Tests" << endl;
    cout << "Testing Full Node Integration" << endl;
    cout << "======================================" << endl;
    cout << endl;

    // Initialize RandomX VM for proof-of-work hashing
    const char* key = "dilithion_integration_test";
    randomx_init_for_hashing(key, strlen(key), 1);  // light_mode=1 for tests
    cout << "✓ RandomX VM initialized" << endl;
    cout << endl;

    bool allPassed = true;

    // Core component tests
    allPassed &= TestBlockchainAndMempool();
    allPassed &= TestMiningIntegration();
    allPassed &= TestWalletIntegration();
    allPassed &= TestRPCIntegration();

    // New security feature tests (TASK-001 & TASK-002)
    allPassed &= TestRPCAuthenticationIntegration();
    allPassed &= TestTimestampValidationIntegration();

    // Full stack test
    allPassed &= TestFullNodeStack();

    cout << endl;
    cout << "======================================" << endl;
    if (allPassed) {
        cout << "✅ All integration tests passed!" << endl;
    } else {
        cout << "❌ Some tests failed" << endl;
    }
    cout << "======================================" << endl;
    cout << endl;

    // These 15 ticks used to print UNCONDITIONALLY, including on a failing run
    // -- "✓ RPC server start/stop" and "✓ Security features operational" were
    // exactly what a human reading test-suite-logs/integration_tests.log saw
    // while the RPC server had never started. The exit code was always right;
    // the part people READ was not, which is how the skip survived so long.
    //
    // Caught by red-team on this very commit: the sibling fix in rpc_tests.cpp
    // was applied and this one was missed -- a fix aimed at a SITE leaving its
    // twin untouched, in the same commit as its own thesis.
    if (allPassed) {
        cout << "Components Validated:" << endl;
        cout << "  ✓ Blockchain + Mempool working together" << endl;
        cout << "  ✓ Mining controller functional" << endl;
        cout << "  ✓ Wallet operations working" << endl;
        cout << "  ✓ RPC server start/stop" << endl;
        cout << "  ✓ RPC Authentication (TASK-001)" << endl;
        cout << "  ✓ Block Timestamp Validation (TASK-002)" << endl;
        cout << "  ✓ Full node stack initialization" << endl;
        cout << endl;

        cout << "Security Features Validated:" << endl;
        cout << "  ✓ HTTP Basic Auth working" << endl;
        cout << "  ✓ Password hashing (SHA-3-256)" << endl;
        cout << "  ✓ Credential validation" << endl;
        cout << "  ✓ Future timestamp rejection" << endl;
        cout << "  ✓ Median-time-past validation" << endl;
        cout << endl;

        cout << "Production Readiness:" << endl;
        cout << "  ✓ All core components integrated" << endl;
        cout << "  ✓ Security features operational" << endl;
        cout << "  ✓ Ready for end-to-end testing" << endl;
    } else {
        cout << "NOTHING above is validated -- the run failed. There is no" << endl;
        cout << "component list for a failing run; do not read one." << endl;
    }
    cout << endl;

    return allPassed ? 0 : 1;
}
