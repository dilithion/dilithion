// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * RandomX Mode Verification Test
 *
 * Test 1/2 verify that LIGHT mode and FULL mode produce identical hashes.
 * This is CRITICAL for consensus - if they produce different hashes, the
 * network will fork between nodes using different modes.
 *
 * Test 3/4 cover the large-page allocation path:
 *
 *   Test 3 is the load-bearing safety assertion. randomx_alloc_dataset() returns
 *   nullptr when large pages are unavailable and randomx_init_for_hashing() turns
 *   that into a fatal throw, so requesting the flag without a working fallback would
 *   stop every miner lacking the OS privilege from starting at all. This test asserts
 *   that init with large pages REQUESTED still succeeds on a machine that cannot
 *   grant them - which is the machine most developers and most CI runners are on.
 *
 *   Test 4 is the Family-A guard: large pages are an allocation strategy, so the hash
 *   of a given input must not depend on whether they were used. If this ever fails,
 *   the change is consensus-affecting and must be reclassified.
 *
 * Set DILITHION_TEST_REQUIRE_LARGE_PAGES=1 to additionally REQUIRE that large pages
 * actually engaged. Without that, a host with no hugetlb pool would report success
 * for a build in which the large-page request had been deleted entirely - the test
 * would pass while covering nothing. Run it that way on a configured mining host.
 */

#include <crypto/randomx_hash.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>

void print_hash(const char* label, const uint8_t* hash) {
    std::cout << label << ": ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "======================================" << std::endl;
    std::cout << "RandomX Mode Verification Test" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    const char* key = "Dilithion-RandomX-v1";
    const char* input = "test block header data";

    uint8_t hash_light[32];
    uint8_t hash_full[32];
    uint8_t hash_full_lp[32];

    // Test 1: Hash with LIGHT mode
    std::cout << "Test 1: Hashing with LIGHT mode..." << std::endl;
    randomx_init_for_hashing(key, strlen(key), 1);  // light_mode=1
    randomx_hash_fast(input, strlen(input), hash_light);
    print_hash("LIGHT mode hash", hash_light);
    std::cout << std::endl;

    // Test 2: Hash with FULL mode, large pages NOT requested (the default).
    std::cout << "Test 2: Hashing with FULL mode (standard pages)..." << std::endl;
    randomx_set_large_pages_allowed(0);
    randomx_init_for_hashing(key, strlen(key), 0);  // light_mode=0 (FULL mode)
    randomx_hash_fast(input, strlen(input), hash_full);
    print_hash("FULL mode hash", hash_full);
    if (randomx_large_pages_active() != 0) {
        std::cout << "✗ FAILURE: large pages reported active after allowed=0." << std::endl;
        std::cout << "  The opt-in gate is not holding - a relay node would pin ~2GB" << std::endl;
        std::cout << "  of non-swappable memory it never asked for." << std::endl;
        return 1;
    }
    std::cout << "  (gate holds: large pages not active when not requested)" << std::endl;
    std::cout << std::endl;

    // Test 3: FULL mode with large pages REQUESTED. Must not brick startup.
    std::cout << "Test 3: FULL mode with large pages requested..." << std::endl;
    randomx_cleanup();  // force a real re-init; init short-circuits on unchanged key+mode
    randomx_set_large_pages_allowed(1);
    try {
        randomx_init_for_hashing(key, strlen(key), 0);
    } catch (const std::exception& e) {
        std::cout << "✗ FAILURE: init threw with large pages requested: " << e.what() << std::endl;
        std::cout << "  The fallback to standard pages is broken. Shipping this would stop" << std::endl;
        std::cout << "  every miner without the large-page privilege from starting." << std::endl;
        return 1;
    }
    randomx_hash_fast(input, strlen(input), hash_full_lp);
    print_hash("FULL mode hash (large pages requested)", hash_full_lp);

    const bool lp_active = randomx_large_pages_active() != 0;
    std::cout << "  Large pages actually engaged: " << (lp_active ? "YES" : "NO (fell back)")
              << std::endl;
    std::cout << "✓ init succeeded with large pages requested (fallback intact)" << std::endl;
    std::cout << std::endl;

    // Test 4: Family-A guard. Allocation strategy must not change the hash.
    std::cout << "Test 4: Hash identity across page backing..." << std::endl;
    if (memcmp(hash_full, hash_full_lp, 32) != 0) {
        std::cout << "✗ FAILURE: FULL mode hash DIFFERS with and without large pages!"
                  << std::endl;
        std::cout << "  Large pages are supposed to be an allocation strategy only." << std::endl;
        std::cout << "  This makes the change CONSENSUS-AFFECTING - reclassify to Family A" << std::endl;
        std::cout << "  and do not ship it." << std::endl;
        return 1;
    }
    std::cout << "✓ identical - allocation strategy does not affect hash output" << std::endl;
    std::cout << std::endl;

    const char* require_lp = std::getenv("DILITHION_TEST_REQUIRE_LARGE_PAGES");
    if (require_lp != nullptr && strcmp(require_lp, "1") == 0 && !lp_active) {
        std::cout << "✗ FAILURE: DILITHION_TEST_REQUIRE_LARGE_PAGES=1 but large pages did"
                  << " not engage." << std::endl;
        std::cout << "  Either the host is not configured (Linux: vm.nr_hugepages needs" << std::endl;
        std::cout << "  >= 1040 pages for the dataset; Windows: Lock pages in memory)," << std::endl;
        std::cout << "  or the large-page request has been removed from the code." << std::endl;
        return 1;
    }

    // Compare LIGHT vs FULL
    std::cout << "======================================" << std::endl;
    if (memcmp(hash_light, hash_full, 32) == 0) {
        std::cout << "✓ SUCCESS: LIGHT and FULL modes produce IDENTICAL hashes" << std::endl;
        std::cout << "  This is correct behavior - consensus will work across nodes" << std::endl;
        std::cout << std::endl;

        std::cout << "Implications:" << std::endl;
        std::cout << "  - 2GB nodes can use LIGHT mode (~256MB RAM, slower hashing)" << std::endl;
        std::cout << "  - 4GB+ nodes can use FULL mode (~2GB RAM, faster hashing)" << std::endl;
        std::cout << "  - All nodes will agree on block validity" << std::endl;
        std::cout << "  - External miners can use either mode" << std::endl;
        if (!lp_active) {
            std::cout << std::endl;
            std::cout << "NOTE: large pages did not engage on this host, so the enabled path" << std::endl;
            std::cout << "  was not exercised. Re-run with DILITHION_TEST_REQUIRE_LARGE_PAGES=1" << std::endl;
            std::cout << "  on a configured mining host to cover it." << std::endl;
        }

        return 0;
    } else {
        std::cout << "✗ FAILURE: LIGHT and FULL modes produce DIFFERENT hashes!" << std::endl;
        std::cout << "  This breaks consensus - nodes will reject each other's blocks" << std::endl;
        std::cout << std::endl;

        std::cout << "Required action:" << std::endl;
        std::cout << "  - ALL nodes must use the same mode" << std::endl;
        std::cout << "  - Either all LIGHT (2GB compatible) or all FULL (4GB+ required)" << std::endl;
        std::cout << "  - Cannot mix modes on the network" << std::endl;

        return 1;
    }
}
