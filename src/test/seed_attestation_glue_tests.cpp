// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Fix 3 (extreview PR#121): the seed-attestation glue tests previously lived ONLY
// in the standalone seed_attestation_key_tests.cpp (its own main()), wired only
// into the Makefile `tests` target. CI runs ONLY the Boost test_dilithion binary,
// so those load-bearing decision/gate assertions never gated CI. This file folds
// the security-critical cases into the Boost suite so CI actually enforces them:
//   - ResolveSeedIdentity REGISTER / SKIP / FATAL / DEGRADED dispositions
//   - the Fix 1 datacenter-over-attestation gate (ban chain + empty datacenter
//     list -> DEGRADED_NO_DATACENTER_LIST; DIL/non-ban never demoted)
//   - the consensus-equivalence assertion the FATAL_MISMATCH design rests on
//   - the distinct degraded getmikattestation error strings (Fix 1/Fix 2)
//
// The standalone binary is kept too (it carries the at-rest key-format tests).

#include <boost/test/unit_test.hpp>

#include <attestation/seed_attestation.h>
#include <attestation/seed_pubkeys_mainnet.h>
#include <dfmp/dfmp.h>
#include <rpc/server.h>

#include <stdexcept>
#include <string>
#include <vector>

using namespace Attestation;

namespace {

// Build a 4-seed mainnet-shaped configuration with REAL Dilithium3 keys per slot
// so the byte-compare mirrors production.
struct SeedFixture {
    std::vector<std::string> seedIPs{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"};
    std::vector<CSeedAttestationKey> keys{4};
    std::vector<std::vector<uint8_t>> seedPubkeys;
    SeedFixture() {
        for (int i = 0; i < 4; i++) {
            BOOST_REQUIRE(keys[i].Generate());
            seedPubkeys.push_back(keys[i].GetPubKey());
        }
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(seed_attestation_glue_tests)

// --- Core dispositions: REGISTER / FATAL_MISMATCH / SKIP / testnet -----------
BOOST_AUTO_TEST_CASE(resolve_core_dispositions)
{
    SeedFixture f;

    // REGISTER: resolved slot + matching key + ASN ok + inert datacenter inputs.
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, f.seedPubkeys, "10.0.0.3", f.keys[2].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/false, /*datacenterListLoaded=*/true);
        BOOST_CHECK(r.decision == SeedIdentityDecision::REGISTER);
        BOOST_CHECK_EQUAL(r.seedId, 2);
        BOOST_CHECK(!r.usedTestnetDefault);
    }

    // FATAL_MISMATCH: resolved slot, WRONG key.
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, f.seedPubkeys, "10.0.0.1", f.keys[3].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/false, /*datacenterListLoaded=*/true);
        BOOST_CHECK(r.decision == SeedIdentityDecision::FATAL_MISMATCH);
        BOOST_CHECK_EQUAL(r.seedId, 0);
    }

    // SKIP_NOT_A_SEED: externalip matches no slot (even with a usable key).
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, f.seedPubkeys, "203.0.113.7", f.keys[0].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/false, /*datacenterListLoaded=*/true);
        BOOST_CHECK(r.decision == SeedIdentityDecision::SKIP_NOT_A_SEED);
        BOOST_CHECK_EQUAL(r.seedId, -1);
    }

    // Testnet (empty pubkey set): lenient default-0 register.
    {
        std::vector<std::vector<uint8_t>> emptyPubkeys;
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, emptyPubkeys, "203.0.113.7", f.keys[0].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/false, /*datacenterListLoaded=*/true);
        BOOST_CHECK(r.decision == SeedIdentityDecision::REGISTER);
        BOOST_CHECK_EQUAL(r.seedId, 0);
        BOOST_CHECK(r.usedTestnetDefault);
    }
}

// --- DEGRADED_NO_ASN: valid identity, ASN DB down ----------------------------
BOOST_AUTO_TEST_CASE(resolve_degraded_no_asn)
{
    SeedFixture f;
    SeedIdentityResult r = ResolveSeedIdentity(
        f.seedIPs, f.seedPubkeys, "10.0.0.3", f.keys[2].GetPubKey(),
        /*asnLoaded=*/false, /*datacenterBanChain=*/true, /*datacenterListLoaded=*/true);
    BOOST_CHECK(r.decision == SeedIdentityDecision::DEGRADED_NO_ASN);
    BOOST_CHECK(r.decision != SeedIdentityDecision::REGISTER);
    BOOST_CHECK(r.decision != SeedIdentityDecision::FATAL_MISMATCH);
    BOOST_CHECK_EQUAL(r.seedId, 2);
}

// --- Fix 1: datacenter-over-attestation gate ---------------------------------
// Mutation self-check: disabling the gate (registerOrDegrade always REGISTER on
// the ban+no-list case) makes case (a) FAIL.
BOOST_AUTO_TEST_CASE(resolve_datacenter_gate)
{
    SeedFixture f;

    // (a) ban chain + datacenter list NOT loaded + valid id + ASN loaded
    //     -> DEGRADED_NO_DATACENTER_LIST (NOT register, NOT fatal).
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, f.seedPubkeys, "10.0.0.3", f.keys[2].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/true, /*datacenterListLoaded=*/false);
        BOOST_CHECK(r.decision == SeedIdentityDecision::DEGRADED_NO_DATACENTER_LIST);
        BOOST_CHECK(r.decision != SeedIdentityDecision::REGISTER);
        BOOST_CHECK(r.decision != SeedIdentityDecision::FATAL_MISMATCH);
        BOOST_CHECK_EQUAL(r.seedId, 2);
    }

    // (b) ban chain + datacenter list LOADED -> REGISTER (provisioned DilV seed
    //     not demoted).
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, f.seedPubkeys, "10.0.0.3", f.keys[2].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/true, /*datacenterListLoaded=*/true);
        BOOST_CHECK(r.decision == SeedIdentityDecision::REGISTER);
        BOOST_CHECK_EQUAL(r.seedId, 2);
    }

    // (c) NON-ban chain (DIL) + datacenter list NOT loaded -> REGISTER. DIL is
    //     never demoted by a missing datacenter list.
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, f.seedPubkeys, "10.0.0.3", f.keys[2].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/false, /*datacenterListLoaded=*/false);
        BOOST_CHECK(r.decision == SeedIdentityDecision::REGISTER);
        BOOST_CHECK_EQUAL(r.seedId, 2);
    }

    // (d) FATAL_MISMATCH on ban chain + empty list is STILL fatal (trust > datacenter).
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, f.seedPubkeys, "10.0.0.1", f.keys[3].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/true, /*datacenterListLoaded=*/false);
        BOOST_CHECK(r.decision == SeedIdentityDecision::FATAL_MISMATCH);
    }

    // Fold order: ASN-down reported before datacenter-list.
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, f.seedPubkeys, "10.0.0.3", f.keys[2].GetPubKey(),
            /*asnLoaded=*/false, /*datacenterBanChain=*/true, /*datacenterListLoaded=*/false);
        BOOST_CHECK(r.decision == SeedIdentityDecision::DEGRADED_NO_ASN);
    }

    // A non-seed stays SKIP even on a ban chain with empty list.
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            f.seedIPs, f.seedPubkeys, "203.0.113.7", f.keys[0].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/true, /*datacenterListLoaded=*/false);
        BOOST_CHECK(r.decision == SeedIdentityDecision::SKIP_NOT_A_SEED);
    }
}

// --- Fix 3: consensus-equivalence of the baked-in mainnet seed pubkeys --------
BOOST_AUTO_TEST_CASE(mainnet_seed_pubkey_consensus_equivalence)
{
    std::vector<std::vector<uint8_t>> pubs = GetMainnetSeedPubkeys();
    BOOST_REQUIRE_EQUAL(pubs.size(), (size_t)NUM_SEEDS);
    for (size_t i = 0; i < pubs.size(); i++) {
        BOOST_CHECK_EQUAL(pubs[i].size(), (size_t)DFMP::MIK_PUBKEY_SIZE);
        // The exact comparison the node's FATAL_MISMATCH gate performs
        // (loadedPubkey != seedPubkeys[seedId]); pin the accessor's stability.
        BOOST_CHECK(GetMainnetSeedPubkeys()[i] == pubs[i]);
    }
    // Pairwise-distinct: a duplicate would collapse the 3-of-4 Byzantine model.
    for (size_t i = 0; i < pubs.size(); i++)
        for (size_t j = i + 1; j < pubs.size(); j++)
            BOOST_CHECK(pubs[i] != pubs[j]);
}

// --- Fix 1/Fix 2: distinct degraded getmikattestation error strings ----------
BOOST_AUTO_TEST_CASE(degraded_getmikattestation_error_strings)
{
    // Plain (un-registered) server -> generic non-seed error.
    {
        CRPCServer rpc;
        std::string err;
        try { rpc.InvokeRPCForTest("getmikattestation", "{}"); err = "<no throw>"; }
        catch (const std::exception& e) { err = e.what(); }
        BOOST_CHECK(err.find("only available on seed nodes") != std::string::npos);
        BOOST_CHECK(err.find("ASN database not loaded") == std::string::npos);
    }

    // NO_ASN degraded -> distinct ASN-DB string + seed_id surfaced (Fix 2).
    {
        CRPCServer rpc;
        rpc.RegisterSeedAttestationDegraded(/*seedId=*/2,
            CRPCServer::SeedDegradedReason::NO_ASN);
        std::string err;
        try { rpc.InvokeRPCForTest("getmikattestation", "{}"); err = "<no throw>"; }
        catch (const std::exception& e) { err = e.what(); }
        BOOST_CHECK(err.find("ASN database not loaded") != std::string::npos);
        BOOST_CHECK(err.find("only available on seed nodes") == std::string::npos);
        BOOST_CHECK(err.find("seed_id=2") != std::string::npos);
    }

    // NO_DATACENTER_LIST degraded -> distinct datacenter string (NOT the ASN one).
    {
        CRPCServer rpc;
        rpc.RegisterSeedAttestationDegraded(/*seedId=*/1,
            CRPCServer::SeedDegradedReason::NO_DATACENTER_LIST);
        std::string err;
        try { rpc.InvokeRPCForTest("getmikattestation", "{}"); err = "<no throw>"; }
        catch (const std::exception& e) { err = e.what(); }
        BOOST_CHECK(err.find("datacenter ASN list not loaded") != std::string::npos);
        BOOST_CHECK(err.find("ASN database not loaded") == std::string::npos);
        BOOST_CHECK(err.find("seed_id=1") != std::string::npos);
    }
}

BOOST_AUTO_TEST_SUITE_END()
