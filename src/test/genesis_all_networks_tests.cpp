// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// ============================================================================
// GENESIS VALIDITY REGRESSION SUITE — EVERY NETWORK
// ============================================================================
//
// WHY THIS EXISTS
// ---------------
// On 2026-08-08 both `dilithion-node --testnet` and `dilithion-node --regtest`
// were found to be completely unbootable: they died at
// "[1/6] Loading genesis block..." with "Genesis block verification failed".
//
// Root cause: commit d6e67172 (2026-03-25) converted TESTNET to VDF-only from
// genesis (vdfActivationHeight = vdfExclusiveHeight = 0) and taught
// Genesis::IsGenesisBlock()/GetGenesisHash() to dispatch on that, but left
// dilithion-node.cpp hard-coding Genesis::CreateGenesisBlock() (the legacy,
// v1 constructor). The node therefore built a genesis its own verifier
// rejected. REGTEST, which derives from Testnet(), inherited the breakage.
// It went unnoticed for four and a half months because NOTHING pinned
// "each network's genesis actually validates".
//
// That is the gap this suite closes. It asserts, for EVERY network the
// binaries can select, that:
//   (1) the genesis the node would construct at boot passes the exact gate
//       the node boots on — Genesis::IsGenesisBlock();
//   (2) the genesis has the block version its VDF configuration implies;
//   (3) on chains with a PINNED genesis hash (mainnet, DilV — frozen consensus
//       values with live chains on them) the constructed genesis hashes to
//       exactly that pin;
//   (4) IsGenesisBlock() genuinely DISCRIMINATES — the other constructor's
//       block is rejected. Without (4) the suite would stay green even if
//       IsGenesisBlock() degenerated to `return true`.
//
// GetGenesisHash() caches via std::call_once for the process lifetime, so it
// can only be exercised for one network per process. Pass the network name as
// argv[1] to select which; the harness below runs the binary once per network.
// With no argument it defaults to mainnet.
//
// Run: ./genesis_all_networks_tests [mainnet|testnet|dilv|regtest]

#include <core/chainparams.h>
#include <node/genesis.h>
#include <primitives/block.h>
#include <crypto/randomx_hash.h>
#include <uint256.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using Dilithion::ChainParams;

namespace {

struct NetworkCase {
    const char* name;
    ChainParams (*factory)();
    bool expectVdfGenesis;    // genesis is a VDF (v4) block
    bool expectPinnedHash;    // chainparams pins genesisHash (frozen consensus)
    // GOLDEN genesis hash, asserted for EVERY network including the ones whose
    // chainparams genesisHash is "" (computed at startup).
    //
    // Why a golden value is needed even where chainparams has no pin: for
    // testnet and regtest, IsGenesisBlock() compares the block's nTime/nBits
    // against the very chainparams fields that produced them, so a parameter
    // edit moves both sides and is INVISIBLE to every structural check. That
    // exact mutation (testnet genesisTime 1774656000 -> ...001) survived the
    // first version of this suite. It is not a harmless edit: it changes the
    // testnet genesis hash, which orphans every existing testnet datadir and
    // splits the node from the testnet seeds on the `invalid_genesis` check.
    //
    // A DELIBERATE testnet/regtest reset is expected to update this constant in
    // the same commit that changes the parameters — that conscious update is
    // the whole point. An accidental drift fails here.
    const char* goldenHash;
};

// EXHAUSTIVE over Dilithion::Network. If a new network is added to the enum
// without a row here, the guard in main() fails loudly rather than silently
// leaving the new network's genesis untested — which is precisely how testnet
// and regtest rotted.
const std::vector<NetworkCase>& AllNetworks()
{
    static const std::vector<NetworkCase> cases = {
        // mainnet: legacy RandomX chain, genesis pinned (LIVE CHAIN — frozen).
        {"mainnet", &ChainParams::Mainnet, /*vdf=*/false, /*pinned=*/true,
         "0000009eaa5e7781ba6d14525c3f75c35444045b21ddafbbea61090db99b0bc3"},
        // testnet: VDF-only from genesis since d6e67172; chainparams leaves the
        // pin empty (computed at startup), so the golden value below is the ONLY
        // thing standing between testnet and a silent genesis change.
        {"testnet", &ChainParams::Testnet, /*vdf=*/true,  /*pinned=*/false,
         "45cff8020830b10d06e9b6123aaa187a334600e49335e4605f3807e30dd0a972"},
        // dilv: VDF chain, genesis pinned (LIVE CHAIN — frozen).
        {"dilv",    &ChainParams::DilV,    /*vdf=*/true,  /*pinned=*/true,
         "ed06d89a233d9cfa4518f9a6012d8bccb2264afed098c6035b9949710d31c48e"},
        // regtest: derives from testnet, VDF-from-genesis; chainparams pin empty.
        // Both binaries must agree on this value — verified 2026-08-08 that
        // dilithion-node --regtest and dilv-node --regtest print it identically.
        {"regtest", &ChainParams::Regtest, /*vdf=*/true,  /*pinned=*/false,
         "cae9f96b1d2037faee02e83aed59b83e0e9b1d94ea0bb14aefcebeeb5cf5d84d"},
    };
    return cases;
}

void InstallParams(const NetworkCase& c)
{
    delete Dilithion::g_chainParams;
    Dilithion::g_chainParams = new ChainParams(c.factory());
}

int g_failures = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "    FAIL: " << (msg) << "  [" #cond "]" << std::endl; \
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

// ---------------------------------------------------------------------------
// (1)(2)(3) The boot gate, the version, and the frozen pin.
// ---------------------------------------------------------------------------
void test_genesis_validates(const NetworkCase& c)
{
    std::cout << "  [" << c.name << "] genesis constructs and validates..." << std::endl;
    InstallParams(c);

    // The VDF predicate must agree with what this network is declared to be.
    CHECK(Dilithion::g_chainParams->IsVdfFromGenesis() == c.expectVdfGenesis,
          std::string(c.name) + ": IsVdfFromGenesis() disagrees with declared VDF config");

    // This is the exact pair of calls the node makes at "[1/6] Loading genesis
    // block...". If this fails, that network's binary does not start.
    CBlock genesis = Genesis::CreateGenesisBlockForChain();
    CHECK(Genesis::IsGenesisBlock(genesis),
          std::string(c.name) + ": node-boot genesis FAILS Genesis::IsGenesisBlock()");

    // (2) Version implied by the VDF configuration.
    const int32_t expectedVersion =
        c.expectVdfGenesis ? CBlockHeader::VDF_VERSION : Genesis::VERSION;
    CHECK(genesis.nVersion == expectedVersion,
          std::string(c.name) + ": genesis nVersion is not the version its VDF config implies");

    // Structural invariants shared by every genesis.
    CHECK(genesis.hashPrevBlock.IsNull(), std::string(c.name) + ": genesis hashPrevBlock not null");
    CHECK(genesis.nTime == Dilithion::g_chainParams->genesisTime,
          std::string(c.name) + ": genesis nTime != chainparams genesisTime");
    CHECK(genesis.nBits == Dilithion::g_chainParams->genesisNBits,
          std::string(c.name) + ": genesis nBits != chainparams genesisNBits");
    CHECK(!genesis.vtx.empty(), std::string(c.name) + ": genesis has no coinbase");

    // (3a) GOLDEN hash — asserted for every network, pinned or not. This is the
    // only check that catches a genesis PARAMETER drift on testnet/regtest,
    // where every structural check above compares the block against the same
    // chainparams fields that built it.
    const uint256 computed = genesis.GetHash();
    const uint256 golden = uint256S(c.goldenHash);
    if (!(computed == golden)) {
        std::cerr << "    FAIL: " << c.name << ": genesis hash CHANGED — computed "
                  << computed.GetHex() << " != golden " << golden.GetHex()
                  << "\n           A genesis parameter moved. If this was a deliberate "
                     "reset of this network, update the golden value in this file in the "
                     "SAME commit. If not, revert the parameter change."
                  << std::endl;
        ++g_failures;
    }

    // (3b) Frozen-consensus pin. Mainnet and DilV have live chains on these
    // values; a mismatch here means a parameter was edited under a live chain.
    const bool hasPin = !Dilithion::g_chainParams->genesisHash.empty();
    CHECK(hasPin == c.expectPinnedHash,
          std::string(c.name) + ": genesisHash pin presence changed unexpectedly");
    if (hasPin) {
        const uint256 pinned = uint256S(Dilithion::g_chainParams->genesisHash);
        if (!(computed == pinned)) {
            std::cerr << "    FAIL: " << c.name << ": computed genesis "
                      << computed.GetHex() << " != pinned " << pinned.GetHex()
                      << std::endl;
            ++g_failures;
        }
    }
}

// ---------------------------------------------------------------------------
// (4) Discrimination: prove IsGenesisBlock() is not vacuously true.
//
// For each network, hand IsGenesisBlock() the genesis built by the WRONG
// constructor and require rejection. This is the mutation the original bug
// walked into: dilithion-node handed testnet/regtest a legacy genesis. If this
// assertion ever goes green-for-the-wrong-reason (IsGenesisBlock degrading to
// `return true`), test (1) becomes worthless — so pin it explicitly.
// ---------------------------------------------------------------------------
void test_wrong_constructor_is_rejected(const NetworkCase& c)
{
    std::cout << "  [" << c.name << "] wrong-constructor genesis is rejected..." << std::endl;
    InstallParams(c);

    CBlock wrong = c.expectVdfGenesis ? Genesis::CreateGenesisBlock()
                                      : Genesis::CreateDilVGenesisBlock();
    CHECK(!Genesis::IsGenesisBlock(wrong),
          std::string(c.name) + ": IsGenesisBlock() ACCEPTED the wrong-constructor genesis "
                                "(the check does not discriminate — suite is vacuous)");
}

// ---------------------------------------------------------------------------
// Cross-consumer agreement: every consumer of "the genesis" must agree.
//
// GetGenesisHash() keys the block DB, the headers manager's mapHeaders entry,
// the P2P version message and the per-peer genesis/ban check. If it disagrees
// with the block the node actually stores, the node strands itself on a private
// chain and gets banned for `invalid_genesis`. Exercised for ONE network per
// process because of the call_once cache.
// ---------------------------------------------------------------------------
void test_get_genesis_hash_agrees(const NetworkCase& c)
{
    std::cout << "  [" << c.name << "] GetGenesisHash() agrees with the stored block..."
              << std::endl;
    InstallParams(c);

    CBlock genesis = Genesis::CreateGenesisBlockForChain();
    const uint256 blockHash = genesis.GetHash();
    const uint256 accessor = Genesis::GetGenesisHash();

    if (!(accessor == blockHash)) {
        std::cerr << "    FAIL: " << c.name << ": GetGenesisHash() " << accessor.GetHex()
                  << " != stored genesis block hash " << blockHash.GetHex() << std::endl;
        ++g_failures;
    }
}

} // namespace

int main(int argc, char** argv)
{
    std::cout << "\n=== Genesis validity — all networks ===\n" << std::endl;

    // Mainnet genesis hashes with RandomX; initialise LIGHT validation mode so
    // GetHash() on a legacy block returns the real value rather than garbage.
    const char* rx_key = "Dilithion-RandomX-v1";
    randomx_init_validation_mode(rx_key, strlen(rx_key));

    const std::vector<NetworkCase>& cases = AllNetworks();

    // Exhaustiveness guard: REGTEST is the last enumerator in Dilithion::Network,
    // so the enum has (REGTEST + 1) members. If a network is added, this trips
    // until a row is added above.
    const size_t enumSize = static_cast<size_t>(Dilithion::REGTEST) + 1;
    if (cases.size() != enumSize) {
        std::cerr << "FAIL: Dilithion::Network has " << enumSize
                  << " members but only " << cases.size()
                  << " are covered here. Add the missing network's row." << std::endl;
        ++g_failures;
    }

    for (const NetworkCase& c : cases) {
        test_genesis_validates(c);
        test_wrong_constructor_is_rejected(c);
    }

    // One network's GetGenesisHash() per process (call_once cache).
    const std::string want = (argc > 1) ? argv[1] : "mainnet";
    bool matched = false;
    for (const NetworkCase& c : cases) {
        if (want == c.name) {
            test_get_genesis_hash_agrees(c);
            matched = true;
            break;
        }
    }
    if (!matched) {
        std::cerr << "FAIL: unknown network argument '" << want << "'" << std::endl;
        ++g_failures;
    }

    delete Dilithion::g_chainParams;
    Dilithion::g_chainParams = nullptr;

    if (g_failures != 0) {
        std::cerr << "\n=== FAILED: " << g_failures << " check(s) ===\n" << std::endl;
        return 1;
    }
    std::cout << "\n=== All networks OK (GetGenesisHash arm: " << want << ") ===\n" << std::endl;
    return 0;
}
