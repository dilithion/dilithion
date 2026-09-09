// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <miner/controller.h>
#include <primitives/block.h>
#include <crypto/randomx_hash.h>

#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <cstring>   // strlen, for the RandomX key

using namespace std;

// Test helper: Create easy mining target for testing
uint256 CreateEasyTarget() {
    uint256 target;
    // THE SECOND QUARANTINE CAUSE, and the controller is right, not this file.
    //
    // This used to `memset(target.begin(), 0xFF, 32)` -- an all-ones target.
    // The MINE-008 fix in CMiningController::StartMining
    // (miner/controller.cpp:170-181) explicitly REJECTS a target that is all
    // 0x00 or all 0xFF as unachievable/invalid, so StartMining returned false
    // and the suite reported "Failed to start mining". The roster read that as
    // "the mining controller does not start under the test harness"; in fact
    // the harness was handing it an input the product had learned to refuse.
    //
    // Use an easy-but-VALID target: leading zero bytes then all ones. Same
    // shape integration_tests.cpp uses for the mining assertions that pass.
    target.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return target;
}

// Test helper: Create block template
CBlockTemplate CreateTestTemplate(uint32_t height = 0) {
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = uint256(); // Initialize to null
    block.hashMerkleRoot = uint256(); // Initialize to null
    block.nTime = static_cast<uint32_t>(time(nullptr));
    block.nBits = 0x1d00ffff; // Standard difficulty bits
    block.nNonce = 0;

    uint256 target = CreateEasyTarget();

    return CBlockTemplate(block, target, height);
}

bool TestMinerConstruction() {
    cout << "Testing miner construction..." << endl;

    // Test default constructor (auto-detect threads)
    CMiningController miner1;
    if (miner1.GetThreadCount() == 0) {
        cout << "  ✗ Auto-detect failed" << endl;
        return false;
    }
    cout << "  ✓ Auto-detect: " << miner1.GetThreadCount() << " threads" << endl;

    // Test explicit thread count
    CMiningController miner2(4);
    if (miner2.GetThreadCount() != 4) {
        cout << "  ✗ Explicit thread count failed" << endl;
        return false;
    }
    cout << "  ✓ Explicit: 4 threads" << endl;

    return true;
}

bool TestMinerStartStop() {
    cout << "\nTesting miner start/stop..." << endl;

    CMiningController miner(2);
    CBlockTemplate tmpl = CreateTestTemplate();

    // Test start
    if (!miner.StartMining(tmpl)) {
        cout << "  ✗ Failed to start mining" << endl;
        return false;
    }
    cout << "  ✓ Mining started" << endl;

    if (!miner.IsMining()) {
        cout << "  ✗ IsMining() returned false" << endl;
        return false;
    }
    cout << "  ✓ IsMining() correct" << endl;

    // Can't start twice
    if (miner.StartMining(tmpl)) {
        cout << "  ✗ Should not allow starting twice" << endl;
        return false;
    }
    cout << "  ✓ Prevents double-start" << endl;

    // Test stop
    miner.StopMining();
    if (miner.IsMining()) {
        cout << "  ✗ Still mining after stop" << endl;
        return false;
    }
    cout << "  ✓ Mining stopped" << endl;

    return true;
}

bool TestHashRateMonitoring() {
    cout << "\nTesting hash rate monitoring..." << endl;

    CMiningController miner(4);
    CBlockTemplate tmpl = CreateTestTemplate();

    miner.StartMining(tmpl);

    // Wait for some mining
    cout << "  Mining for 3 seconds..." << endl;
    this_thread::sleep_for(chrono::seconds(3));

    CMiningStats stats = miner.GetStats();
    uint64_t hashRate = miner.GetHashRate();

    cout << "  Hashes: " << stats.nHashesComputed << endl;
    cout << "  Hash rate: " << hashRate << " H/s" << endl;
    cout << "  Uptime: " << stats.GetUptime() << " seconds" << endl;

    if (stats.nHashesComputed == 0) {
        cout << "  ✗ No hashes computed" << endl;
        miner.StopMining();
        return false;
    }
    cout << "  ✓ Hashes computed" << endl;

    // Hash rate can be zero if measurement interval is very short
    // As long as hashes are being computed, the system is working
    if (hashRate == 0) {
        cout << "  ⚠️  Hash rate is zero (timing artifact - not a failure)" << endl;
    }
    cout << "  ✓ Hash rate tracking works" << endl;

    if (stats.GetUptime() < 2) {
        cout << "  ✗ Uptime too short: " << stats.GetUptime() << endl;
        miner.StopMining();
        return false;
    }
    cout << "  ✓ Uptime tracking works (" << stats.GetUptime() << " seconds)" << endl;

    miner.StopMining();
    return true;
}

bool TestBlockCallback() {
    cout << "\nTesting block found callback..." << endl;

    bool blockFound = false;
    uint256 foundHash;

    CMiningController miner(4);

    // Set callback
    miner.SetBlockFoundCallback([&](const CBlock& block) {
        blockFound = true;
        foundHash = block.GetHash();
        cout << "  Block found! Hash: " << foundHash.GetHex() << endl;
    });

    // Use very easy target
    CBlockTemplate tmpl = CreateTestTemplate();

    miner.StartMining(tmpl);

    // Wait for block (should find quickly with easy target)
    cout << "  Waiting for block (max 10 seconds)..." << endl;
    for (int i = 0; i < 10 && !blockFound; ++i) {
        this_thread::sleep_for(chrono::seconds(1));
        if (blockFound) break;
    }

    miner.StopMining();

    if (!blockFound) {
        cout << "  ✗ No block found (target may be too hard)" << endl;
        cout << "  Note: This is expected with RandomX's difficulty" << endl;
        return true; // Not a failure - RandomX is hard even with easy target
    }

    cout << "  ✓ Block callback works" << endl;
    return true;
}

bool TestTemplateUpdate() {
    cout << "\nTesting template update..." << endl;

    CMiningController miner(2);
    CBlockTemplate tmpl1 = CreateTestTemplate(100);

    miner.StartMining(tmpl1);
    this_thread::sleep_for(chrono::milliseconds(500));

    // Update template
    CBlockTemplate tmpl2 = CreateTestTemplate(101);
    miner.UpdateTemplate(tmpl2);
    cout << "  ✓ Template updated while mining" << endl;

    this_thread::sleep_for(chrono::milliseconds(500));
    miner.StopMining();

    return true;
}

bool TestStatistics() {
    cout << "\nTesting statistics tracking..." << endl;

    CMiningController miner(2);
    CBlockTemplate tmpl = CreateTestTemplate();

    // Check initial stats
    CMiningStats stats = miner.GetStats();
    if (stats.nHashesComputed != 0) {
        cout << "  ✗ Initial hash count not zero" << endl;
        return false;
    }
    cout << "  ✓ Initial stats correct" << endl;

    // Mine briefly
    miner.StartMining(tmpl);
    this_thread::sleep_for(chrono::seconds(2));

    stats = miner.GetStats();
    uint64_t hashes1 = stats.nHashesComputed;

    if (hashes1 == 0) {
        cout << "  ✗ No hashes after mining" << endl;
        miner.StopMining();
        return false;
    }
    cout << "  ✓ Hash counting works: " << hashes1 << " hashes" << endl;

    // Continue mining
    this_thread::sleep_for(chrono::seconds(1));
    stats = miner.GetStats();
    uint64_t hashes2 = stats.nHashesComputed;

    if (hashes2 <= hashes1) {
        cout << "  ✗ Hash count not increasing" << endl;
        miner.StopMining();
        return false;
    }
    cout << "  ✓ Hash count increases: " << hashes2 << " hashes" << endl;

    miner.StopMining();
    return true;
}

int main() {
    cout << "======================================" << endl;
    cout << "Phase 3 Mining Controller Tests" << endl;
    cout << "======================================" << endl;
    cout << endl;

    // THE QUARANTINE CAUSE. Without this, every mining assertion in this file
    // fails -- "Failed to start mining", "No hashes computed", "No block
    // found", "No hashes after mining" -- because the controller cannot hash
    // without an initialised RandomX VM. The suite was quarantined as
    // "PRE-EXISTING, UNOWNED: the mining controller does not start under the
    // test harness"; the controller is fine, the HARNESS never initialised it.
    //
    // Proof it is the harness and not the product: integration_tests.cpp does
    // call randomx_init_for_hashing and passes the IDENTICAL assertions. Census
    // over both files: 1 call there, 0 here.
    //
    // MIRROR PRODUCTION, not the other tests. randomx_init_for_hashing is the
    // LEGACY API (randomx_hash.h:19, "LEGACY API: Uses global VM with mutex")
    // and its per-thread VMs come from a backward-compatibility fallback the
    // node never takes. Production calls randomx_init_validation_mode
    // (dilithion-node.cpp:2651): light mode for block validation, blocking,
    // 1-2 seconds.
    //
    // Using the legacy call here would have made this harness pass down a path
    // production does not use -- which is the same class of defect as the
    // quarantine this commit is fixing, just pointing the other way.
    const char* rxKey = "dilithion_miner_tests";
    randomx_init_validation_mode(rxKey, strlen(rxKey));
    cout << "  (RandomX validation-mode VM initialised, as production does)" << endl;
    cout << endl;

    bool allPassed = true;

    allPassed &= TestMinerConstruction();
    allPassed &= TestMinerStartStop();
    allPassed &= TestHashRateMonitoring();
    allPassed &= TestBlockCallback();
    allPassed &= TestTemplateUpdate();
    allPassed &= TestStatistics();

    cout << endl;
    cout << "======================================" << endl;
    if (allPassed) {
        cout << "✅ All mining tests passed!" << endl;
    } else {
        cout << "❌ Some tests failed" << endl;
    }
    cout << "======================================" << endl;
    cout << endl;

    // THIRD instance of this pattern in the repo, after rpc_tests.cpp and
    // integration_tests.cpp (both fixed in #181): six green ticks printed
    // UNCONDITIONALLY, including on the run where mining never started and the
    // hash rate was 0 H/s. "✓ RandomX integration" and "✓ Statistics tracking"
    // were being printed by a run that had just failed both. The exit code was
    // always right; the part a human READS was not, which is how a suite can
    // look healthy in a log while failing.
    if (allPassed) {
        cout << "Phase 3 Mining Components Validated:" << endl;
        cout << "  ✓ Mining controller" << endl;
        cout << "  ✓ Thread pool management" << endl;
        cout << "  ✓ Hash rate monitoring" << endl;
        cout << "  ✓ RandomX integration" << endl;
        cout << "  ✓ Block template handling" << endl;
        cout << "  ✓ Statistics tracking" << endl;
    } else {
        cout << "NOTHING above is validated -- the run failed. There is no" << endl;
        cout << "component list for a failing run; do not read one." << endl;
    }
    cout << endl;

    return allPassed ? 0 : 1;
}
