// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/pow.h>
#include <consensus/params.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <util/time.h>
#include <iostream>
#include <cassert>
#include <vector>

/**
 * Test: GetMedianTimePast() with various chain lengths
 */
void TestMedianTimePast() {
    std::cout << "Testing median-time-past calculation..." << std::endl;

    // Create a chain of 15 blocks with incrementing timestamps
    std::vector<CBlockIndex> chain(15);
    for (size_t i = 0; i < chain.size(); i++) {
        chain[i].nTime = 1000 + i * 600; // 10 minute increments
        chain[i].nHeight = i;
        if (i > 0) {
            chain[i].pprev = &chain[i - 1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    // Test median with full 11 blocks
    int64_t median = GetMedianTimePast(&chain[14]); // Block 14, uses blocks 14-4
    // Blocks 14-4 have times: 1000+14*600 to 1000+4*600
    // = 9400, 8800, 8200, 7600, 7000, 6400, 5800, 5200, 4600, 4000, 3400
    // Sorted: 3400, 4000, 4600, 5200, 5800, [6400], 7000, 7600, 8200, 8800, 9400
    assert(median == 6400);
    std::cout << "  ✓ Median-time-past with 11 blocks correct (median: " << median << ")" << std::endl;

    // Test median with fewer than 11 blocks
    median = GetMedianTimePast(&chain[5]); // Block 5, uses blocks 5-0 (6 blocks)
    // Blocks 5-0 have times: 4000, 3400, 2800, 2200, 1600, 1000
    // Sorted: 1000, 1600, 2200, [2800], 3400, 4000
    assert(median == 2800);
    std::cout << "  ✓ Median-time-past with 6 blocks correct (median: " << median << ")" << std::endl;

    // Test median with single block (genesis)
    median = GetMedianTimePast(&chain[0]);
    assert(median == 1000);
    std::cout << "  ✓ Median-time-past with 1 block (genesis) correct" << std::endl;
}

/**
 * Test: CheckBlockTimestamp() - Future timestamp validation
 */
void TestFutureTimestamp() {
    std::cout << "\nTesting future timestamp validation..." << std::endl;

    CBlockHeader block;
    int64_t now = GetTime();

    // Test 1: Block 1 hour in future (should accept)
    block.nTime = now + 1 * 60 * 60;
    assert(CheckBlockTimestamp(block, nullptr) == true);
    std::cout << "  ✓ Block 1 hour in future accepted" << std::endl;

    // Test 2: Block exactly 2 hours in future (should accept)
    block.nTime = now + 2 * 60 * 60;
    assert(CheckBlockTimestamp(block, nullptr) == true);
    std::cout << "  ✓ Block 2 hours in future accepted" << std::endl;

    // Test 3: Block 3 hours in future (should reject)
    block.nTime = now + 3 * 60 * 60;
    assert(CheckBlockTimestamp(block, nullptr) == false);
    std::cout << "  ✓ Block 3 hours in future rejected" << std::endl;

    // Test 4: Block 1 day in future (should reject)
    block.nTime = now + 24 * 60 * 60;
    assert(CheckBlockTimestamp(block, nullptr) == false);
    std::cout << "  ✓ Block 1 day in future rejected" << std::endl;
}

/**
 * Test: CheckBlockTimestamp() - Median-time-past validation
 */
void TestMedianTimePastValidation() {
    std::cout << "\nTesting median-time-past validation..." << std::endl;

    // Create a chain of 15 blocks
    std::vector<CBlockIndex> chain(15);
    int64_t baseTime = GetTime() - 10000; // Start 10000 seconds ago
    for (size_t i = 0; i < chain.size(); i++) {
        chain[i].nTime = baseTime + i * 600; // 10 minute increments
        chain[i].nHeight = i;
        if (i > 0) {
            chain[i].pprev = &chain[i - 1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    CBlockHeader block;
    CBlockIndex* pindexPrev = &chain[14];
    int64_t median = GetMedianTimePast(pindexPrev);

    // Test 1: Block time equal to median-time-past (should reject)
    block.nTime = median;
    assert(CheckBlockTimestamp(block, pindexPrev) == false);
    std::cout << "  ✓ Block time equal to median-time-past rejected" << std::endl;

    // Test 2: Block time less than median-time-past (should reject)
    block.nTime = median - 100;
    assert(CheckBlockTimestamp(block, pindexPrev) == false);
    std::cout << "  ✓ Block time less than median-time-past rejected" << std::endl;

    // Test 3: Block time greater than median-time-past (should accept)
    block.nTime = median + 1;
    assert(CheckBlockTimestamp(block, pindexPrev) == true);
    std::cout << "  ✓ Block time greater than median-time-past accepted" << std::endl;

    // Test 4: Block time much greater than median-time-past (should accept if not too far in future)
    block.nTime = median + 3600; // 1 hour ahead
    assert(CheckBlockTimestamp(block, pindexPrev) == true);
    std::cout << "  ✓ Block time 1 hour after median-time-past accepted" << std::endl;
}

/**
 * Test: CheckBlockTimestamp() - Genesis block (no previous block)
 */
void TestGenesisBlockTimestamp() {
    std::cout << "\nTesting genesis block timestamp validation..." << std::endl;

    CBlockHeader genesis;
    int64_t now = GetTime();

    // Test 1: Genesis block with current time (should accept)
    genesis.nTime = now;
    assert(CheckBlockTimestamp(genesis, nullptr) == true);
    std::cout << "  ✓ Genesis block with current time accepted" << std::endl;

    // Test 2: Genesis block with past time (should accept - no MTP check)
    genesis.nTime = now - 86400; // 1 day ago
    assert(CheckBlockTimestamp(genesis, nullptr) == true);
    std::cout << "  ✓ Genesis block with past time accepted (no MTP validation)" << std::endl;

    // Test 3: Genesis block 3 hours in future (should reject)
    genesis.nTime = now + 3 * 60 * 60;
    assert(CheckBlockTimestamp(genesis, nullptr) == false);
    std::cout << "  ✓ Genesis block 3 hours in future rejected" << std::endl;
}

/**
 * Test: Edge cases
 */
void TestEdgeCases() {
    std::cout << "\nTesting edge cases..." << std::endl;

    // Create minimal chain
    std::vector<CBlockIndex> chain(3);
    int64_t baseTime = GetTime() - 1800; // 30 minutes ago
    for (size_t i = 0; i < chain.size(); i++) {
        chain[i].nTime = baseTime + i * 600;
        chain[i].nHeight = i;
        if (i > 0) {
            chain[i].pprev = &chain[i - 1];
        } else {
            chain[i].pprev = nullptr;
        }
    }

    CBlockHeader block;

    // Test 1: Block exactly at boundary (2 hours + 1 second should reject)
    int64_t now = GetTime();
    block.nTime = now + 2 * 60 * 60 + 1;
    assert(CheckBlockTimestamp(block, &chain[2]) == false);
    std::cout << "  ✓ Block at boundary (2h + 1s) rejected" << std::endl;

    // Test 2: Block with timestamp 0 (should reject - before MTP)
    block.nTime = 0;
    assert(CheckBlockTimestamp(block, &chain[2]) == false);
    std::cout << "  ✓ Block with timestamp 0 rejected" << std::endl;

    // Test 3: Block with maximum uint32_t timestamp (should reject - too far in future)
    block.nTime = 0xFFFFFFFF;
    assert(CheckBlockTimestamp(block, &chain[2]) == false);
    std::cout << "  ✓ Block with maximum timestamp rejected" << std::endl;
}

/**
 * Test: Realistic chain scenario
 */
void TestRealisticChain() {
    std::cout << "\nTesting realistic chain scenario..." << std::endl;

    // Simulate a realistic chain with some timestamp variance
    std::vector<CBlockIndex> chain;
    int64_t baseTime = GetTime() - 7200; // Start 2 hours ago
    int64_t timestamps[] = {0, 610, 580, 615, 605, 590, 620, 595, 610, 600, 615, 605, 620};

    for (size_t i = 0; i < 13; i++) {
        CBlockIndex block;
        if (i == 0) {
            block.nTime = baseTime;
            block.pprev = nullptr;
        } else {
            block.nTime = chain[i - 1].nTime + timestamps[i];
            block.pprev = &chain[i - 1];
        }
        block.nHeight = i;
        chain.push_back(block);
    }

    CBlockHeader newBlock;
    CBlockIndex* tip = &chain.back();
    int64_t median = GetMedianTimePast(tip);

    // Test 1: New block with reasonable timestamp
    newBlock.nTime = tip->nTime + 600; // 10 minutes after tip
    assert(CheckBlockTimestamp(newBlock, tip) == true);
    std::cout << "  ✓ Realistic new block accepted (10 min after tip)" << std::endl;

    // Test 2: Miner tries to use old timestamp (attack)
    newBlock.nTime = median - 100;
    assert(CheckBlockTimestamp(newBlock, tip) == false);
    std::cout << "  ✓ Attack with old timestamp rejected" << std::endl;

    // Test 3: Miner tries future timestamp (attack)
    newBlock.nTime = GetTime() + 3 * 60 * 60;
    assert(CheckBlockTimestamp(newBlock, tip) == false);
    std::cout << "  ✓ Attack with future timestamp rejected" << std::endl;
}

/**
 * Test: Post-fork timestamp validation (600s limit at timestampValidationHeight)
 *
 * Verifies that after the timestamp validation fork, blocks with timestamps
 * >10 minutes in the future are rejected, while the pre-fork 2-hour limit
 * still applies for blocks below the activation height.
 */
void TestPostForkTimestamp() {
    std::cout << "\nTesting post-fork timestamp validation (600s limit)..." << std::endl;

    // Set up g_chainParams with a known activation height
    // K3: MUST start from a fully-populated ChainParams. `ChainParams` is an
    // aggregate whose POD members (minBlockTimestampGap, minBlockTimestampGapHeight,
    // ...) have NO default member initialisers, so a bare `ChainParams testParams;`
    // on the stack leaves them INDETERMINATE. That made this test read garbage into
    // CheckBlockTimestamp()'s Rule-3 minimum-gap comparison and fail roughly 1 run
    // in 3 with a nonsense required gap (observed: 1410859008s ≈ 44 years).
    // Mainnet() sets every field explicitly; override only what this test varies.
    Dilithion::ChainParams testParams = Dilithion::ChainParams::Mainnet();
    testParams.timestampValidationHeight = 24500;
    testParams.minBlockTimestampGap = 0;        // Rule 3 not under test here
    testParams.minBlockTimestampGapHeight = 0;
    Dilithion::ChainParams* prevParams = Dilithion::g_chainParams;
    Dilithion::g_chainParams = &testParams;

    // Create a minimal parent block
    CBlockIndex parent;
    parent.nHeight = 24499;  // Parent of the first post-fork block
    parent.nTime = GetTime() - 240;
    parent.pprev = nullptr;

    CBlockHeader block;
    int64_t now = GetTime();
    int postForkHeight = 24500;  // First block to use 600s limit
    int preForkHeight = 24499;   // Last block to use 7200s limit

    // Test 1: Post-fork block 11 minutes in future (should REJECT — over 600s)
    block.nTime = now + 660;
    assert(CheckBlockTimestamp(block, &parent, postForkHeight) == false);
    std::cout << "  ✓ Post-fork: block +660s (11 min) in future rejected" << std::endl;

    // Test 2: Post-fork block 9 minutes in future (should ACCEPT — under 600s)
    block.nTime = now + 540;
    assert(CheckBlockTimestamp(block, &parent, postForkHeight) == true);
    std::cout << "  ✓ Post-fork: block +540s (9 min) in future accepted" << std::endl;

    // Test 3: Post-fork block 1 hour in future (should REJECT)
    block.nTime = now + 3600;
    assert(CheckBlockTimestamp(block, &parent, postForkHeight) == false);
    std::cout << "  ✓ Post-fork: block +3600s (1 hour) in future rejected" << std::endl;

    // Test 4: Pre-fork block 1 hour in future (should ACCEPT — under 7200s)
    block.nTime = now + 3600;
    assert(CheckBlockTimestamp(block, &parent, preForkHeight) == true);
    std::cout << "  ✓ Pre-fork: block +3600s (1 hour) in future accepted" << std::endl;

    // Test 5: Pre-fork block 3 hours in future (should REJECT — over 7200s)
    block.nTime = now + 3 * 60 * 60;
    assert(CheckBlockTimestamp(block, &parent, preForkHeight) == false);
    std::cout << "  ✓ Pre-fork: block +10800s (3 hours) in future rejected" << std::endl;

    // Test 6: Default blockHeight (-1) uses pre-fork 7200s limit (backward compat)
    block.nTime = now + 3600;
    assert(CheckBlockTimestamp(block, &parent) == true);
    std::cout << "  ✓ Default (no height): block +3600s accepted (pre-fork 7200s limit)" << std::endl;

    // Restore previous g_chainParams
    Dilithion::g_chainParams = prevParams;
}

/**
 * Test: CheckBlockTimestamp() Rule 3 — minimum inter-block timestamp gap
 *
 * K3: this consensus rule (pow.cpp:1421-1440) had NO test coverage at all.
 * Its inputs, minBlockTimestampGap / minBlockTimestampGapHeight, are POD
 * members of ChainParams with no default member initialisers, so the gap
 * was only ever exercised here by accident, via uninitialised stack memory.
 * Pin the real behaviour: gap enforced at/above the activation height,
 * not enforced below it, and disabled entirely when the gap is 0.
 */
void TestMinBlockTimestampGap() {
    std::cout << "\nTesting minimum inter-block timestamp gap (Rule 3)..." << std::endl;

    Dilithion::ChainParams testParams = Dilithion::ChainParams::Mainnet();
    testParams.timestampValidationHeight = 0;   // keep the 600s future limit out of the way
    testParams.minBlockTimestampGap = 45;
    testParams.minBlockTimestampGapHeight = 1000;
    Dilithion::ChainParams* prevParams = Dilithion::g_chainParams;
    Dilithion::g_chainParams = &testParams;

    int64_t now = GetTime();

    CBlockIndex parent;
    parent.nHeight = 999;
    parent.nTime = static_cast<uint32_t>(now - 100);
    parent.pprev = nullptr;

    CBlockHeader block;

    // At activation height: gap of exactly 45s is accepted (boundary, >=).
    block.nTime = parent.nTime + 45;
    assert(CheckBlockTimestamp(block, &parent, 1000) == true);
    std::cout << "  ✓ Post-activation: gap of exactly 45s accepted" << std::endl;

    // At activation height: gap of 44s is rejected.
    block.nTime = parent.nTime + 44;
    assert(CheckBlockTimestamp(block, &parent, 1000) == false);
    std::cout << "  ✓ Post-activation: gap of 44s rejected" << std::endl;

    // Below activation height: the same 44s gap is accepted.
    block.nTime = parent.nTime + 44;
    assert(CheckBlockTimestamp(block, &parent, 999) == true);
    std::cout << "  ✓ Pre-activation: gap of 44s accepted (rule not yet active)" << std::endl;

    // Gap of 0 disables the rule entirely (DIL mainnet / regtest configuration).
    testParams.minBlockTimestampGap = 0;
    block.nTime = parent.nTime + 1;
    assert(CheckBlockTimestamp(block, &parent, 1000) == true);
    std::cout << "  ✓ minBlockTimestampGap=0 disables the rule" << std::endl;

    Dilithion::g_chainParams = prevParams;
}

/**
 * Test: MTP bump-forward logic used in BuildMiningTemplate()
 *
 * When creating a block template, if the current time is at or below
 * the Median-Time-Past, the timestamp must be bumped to MTP + 1.
 * This prevents mining blocks that consensus would reject.
 *
 * This test exercises the same logic as dilithion-node.cpp and
 * dilv-node.cpp in BuildMiningTemplate(), without needing a full
 * node context.
 */
void TestMTPBumpForward() {
    std::cout << "\nTesting MTP bump-forward (template builder logic)..." << std::endl;

    // Create a chain of 15 blocks
    std::vector<CBlockIndex> chain(15);
    int64_t baseTime = 1700000000; // Fixed base for determinism
    for (size_t i = 0; i < chain.size(); i++) {
        chain[i].nTime = baseTime + i * 600;
        chain[i].nHeight = i;
        chain[i].pprev = (i > 0) ? &chain[i - 1] : nullptr;
    }

    CBlockIndex* pindexPrev = &chain[14];
    int64_t mtp = GetMedianTimePast(pindexPrev);

    // Scenario 1: Current time is well ahead of MTP — no bump needed
    {
        uint32_t blockTime = static_cast<uint32_t>(mtp + 3600);
        // Apply same logic as BuildMiningTemplate
        if (static_cast<int64_t>(blockTime) <= mtp) {
            blockTime = static_cast<uint32_t>(mtp + 1);
        }
        assert(blockTime == static_cast<uint32_t>(mtp + 3600));
        std::cout << "  ✓ Normal case: time ahead of MTP, no bump" << std::endl;
    }

    // Scenario 2: Current time equals MTP — must bump to MTP + 1
    {
        uint32_t blockTime = static_cast<uint32_t>(mtp);
        if (static_cast<int64_t>(blockTime) <= mtp) {
            blockTime = static_cast<uint32_t>(mtp + 1);
        }
        assert(blockTime == static_cast<uint32_t>(mtp + 1));
        std::cout << "  ✓ Edge case: time == MTP, bumped to MTP + 1" << std::endl;
    }

    // Scenario 3: Current time is below MTP (clock skew) — must bump
    {
        uint32_t blockTime = static_cast<uint32_t>(mtp - 100);
        if (static_cast<int64_t>(blockTime) <= mtp) {
            blockTime = static_cast<uint32_t>(mtp + 1);
        }
        assert(blockTime == static_cast<uint32_t>(mtp + 1));
        std::cout << "  ✓ Clock skew: time < MTP, bumped to MTP + 1" << std::endl;
    }

    // Scenario 4: Current time is MTP + 1 — exactly valid, no bump
    {
        uint32_t blockTime = static_cast<uint32_t>(mtp + 1);
        if (static_cast<int64_t>(blockTime) <= mtp) {
            blockTime = static_cast<uint32_t>(mtp + 1);
        }
        assert(blockTime == static_cast<uint32_t>(mtp + 1));
        std::cout << "  ✓ Boundary: time == MTP + 1, no bump needed" << std::endl;
    }

    // Scenario 5: Bumped timestamp should pass consensus validation
    {
        CBlockHeader block;
        block.nTime = static_cast<uint32_t>(mtp + 1);
        assert(CheckBlockTimestamp(block, pindexPrev) == true);
        std::cout << "  ✓ Bumped timestamp passes CheckBlockTimestamp()" << std::endl;
    }

    // Scenario 6: Un-bumped MTP timestamp would fail consensus
    {
        CBlockHeader block;
        block.nTime = static_cast<uint32_t>(mtp);
        assert(CheckBlockTimestamp(block, pindexPrev) == false);
        std::cout << "  ✓ Un-bumped MTP timestamp correctly rejected by consensus" << std::endl;
    }

    // Scenario 7: Genesis block (pindexPrev == nullptr) — no MTP check
    {
        uint32_t blockTime = 1000; // Arbitrary old time
        CBlockIndex* nullPrev = nullptr;
        // BuildMiningTemplate guard: if (pindexPrev) { ... }
        if (nullPrev) {
            int64_t nMedianTimePast = GetMedianTimePast(nullPrev);
            if (static_cast<int64_t>(blockTime) <= nMedianTimePast) {
                blockTime = static_cast<uint32_t>(nMedianTimePast + 1);
            }
        }
        assert(blockTime == 1000); // Unchanged
        std::cout << "  ✓ Genesis: no pindexPrev, timestamp unchanged" << std::endl;
    }
}

int main() {
    std::cout << "======================================" << std::endl;
    std::cout << "Block Timestamp Validation Tests" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    try {
        TestMedianTimePast();
        TestFutureTimestamp();
        TestMedianTimePastValidation();
        TestGenesisBlockTimestamp();
        TestEdgeCases();
        TestRealisticChain();
        TestPostForkTimestamp();
        TestMinBlockTimestampGap();
        TestMTPBumpForward();

        std::cout << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "All timestamp validation tests passed!" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << std::endl;

        std::cout << "Components Validated:" << std::endl;
        std::cout << "  - Median-time-past calculation" << std::endl;
        std::cout << "  - Future timestamp rejection (> 2 hours pre-fork)" << std::endl;
        std::cout << "  - Future timestamp rejection (> 600s post-fork)" << std::endl;
        std::cout << "  - Median-time-past comparison" << std::endl;
        std::cout << "  - Genesis block handling" << std::endl;
        std::cout << "  - Edge cases" << std::endl;
        std::cout << "  - Realistic chain scenarios" << std::endl;
        std::cout << "  - Post-fork 600s limit enforcement" << std::endl;
        std::cout << std::endl;

        std::cout << "Consensus Rules Enforced:" << std::endl;
        std::cout << "  - Block time must not be > 2 hours in future (pre-fork)" << std::endl;
        std::cout << "  - Block time must not be > 600s in future (post-fork)" << std::endl;
        std::cout << "  - Block time must be > median-time-past" << std::endl;
        std::cout << "  - Prevents timestamp manipulation attacks" << std::endl;
        std::cout << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    }
}
