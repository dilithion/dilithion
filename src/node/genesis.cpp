// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/genesis.h>
#include <primitives/transaction.h>
#include <crypto/randomx_hash.h>
#include <crypto/sha3.h>
#include <consensus/pow.h>
#include <core/chainparams.h>
#include <vdf/coinbase_vdf.h>
#include <util/base58.h>
#include <util/logging.h>

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>

namespace Genesis {

CBlock CreateGenesisBlock() {
    // Ensure chain parameters are initialized
    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized. Call InitChainParams() first.");
    }

    CBlock genesis;

    // Set header fields from chain parameters
    genesis.nVersion = VERSION;
    genesis.hashPrevBlock = uint256();  // All zeros (no previous block)
    genesis.nTime = Dilithion::g_chainParams->genesisTime;
    genesis.nBits = Dilithion::g_chainParams->genesisNBits;
    genesis.nNonce = Dilithion::g_chainParams->genesisNonce;

    // =========================================================================
    // BUG #4 FIX: Create proper coinbase transaction
    // =========================================================================
    // Following Bitcoin Core's pattern, genesis coinbase is a real transaction
    // that can be deserialized and validated like any other coinbase.
    //
    // Structure:
    // - 1 input with null prevout (standard for coinbase)
    // - scriptSig contains block height (0) + genesis message
    // - 1 output with 5 billion satoshi subsidy to unspendable address
    // - Transaction is serialized and stored in block.vtx
    // - Merkle root = hash of this single transaction

    CTransaction coinbaseTx;
    coinbaseTx.nVersion = 1;

    // Input: Null prevout (standard for coinbase)
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();  // Marks this as coinbase
    coinbaseTx.vin[0].nSequence = 0xFFFFFFFF;

    // scriptSig: Height (0) + genesis message
    // Following BIP34 pattern for height encoding
    std::vector<uint8_t> scriptSigData;
    scriptSigData.push_back(0);  // Height 0 for genesis
    const std::string& genesisMsg = Dilithion::g_chainParams->genesisCoinbaseMsg;
    scriptSigData.insert(scriptSigData.end(), genesisMsg.begin(), genesisMsg.end());
    coinbaseTx.vin[0].scriptSig = scriptSigData;

    // Output: 5 billion ions (matching miner subsidy)
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].nValue = 5000000000ULL;  // 50 DLT (5 billion ions)

    // scriptPubKey: OP_RETURN (unspendable)
    // Genesis coins are traditionally unspendable
    coinbaseTx.vout[0].scriptPubKey.push_back(0x6a);  // OP_RETURN opcode

    coinbaseTx.nLockTime = 0;

    // Serialize the transaction
    std::vector<uint8_t> serializedTx = coinbaseTx.Serialize();

    // BUG #7 FIX: Store transaction with count prefix
    // DeserializeBlockTransactions expects: [count][tx1][tx2]...
    // Genesis has 1 transaction, so prefix with count=1
    genesis.vtx.clear();
    genesis.vtx.push_back(1);  // Transaction count = 1
    genesis.vtx.insert(genesis.vtx.end(), serializedTx.begin(), serializedTx.end());

    // Calculate merkle root from transaction hash
    // Genesis block has only 1 transaction, so merkle root = transaction hash
    genesis.hashMerkleRoot = coinbaseTx.GetHash();

    return genesis;
}

CBlock CreateDilVGenesisBlock() {
    // Ensure chain parameters are initialized
    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized. Call InitChainParams() first.");
    }

    CBlock genesis;

    // DilV genesis is a VDF block (version 4)
    genesis.nVersion = CBlockHeader::VDF_VERSION;
    genesis.hashPrevBlock = uint256();  // All zeros (no previous block)
    genesis.nTime = Dilithion::g_chainParams->genesisTime;
    genesis.nBits = Dilithion::g_chainParams->genesisNBits;
    genesis.nNonce = 0;  // nNonce is vestigial for VDF blocks

    // =========================================================================
    // Pre-computed VDF proof for genesis block
    // =========================================================================
    // Challenge = SHA3-256(zeros_32 || height_0_le32 || address_20_zeros) = 56-byte preimage
    // Computed with 500,000 iterations of chiavdf squaring
    //
    // These values are computed once by the dilv-genesis-vdf tool and hardcoded here.
    // Challenge: 37d87925f453b19faae61935631462157c0168e14f0f819ec032e4b8b5eb2322
    // =========================================================================

    // VDF output (32 bytes) — result of 500,000 squarings
    static const uint8_t vdfOutputBytes[32] = {
        0xde, 0xab, 0x28, 0xaf, 0x3c, 0x2b, 0x26, 0xf8, 0x61, 0x5b, 0xff, 0xf1, 0x54, 0x78, 0x94, 0x3b,
        0x77, 0x23, 0xc5, 0x88, 0x86, 0x4c, 0xc4, 0xcc, 0xdf, 0xce, 0x71, 0x62, 0xd1, 0x1d, 0xc1, 0x86
    };
    std::memcpy(genesis.vdfOutput.data, vdfOutputBytes, 32);

    // VDF proof hash (32 bytes) — SHA3-256(proof_bytes)
    static const uint8_t vdfProofHashBytes[32] = {
        0x44, 0xc4, 0x9e, 0x17, 0x02, 0xb3, 0x04, 0xea, 0x8a, 0x49, 0x92, 0x1c, 0x1e, 0x4a, 0x56, 0xcb,
        0x6a, 0x16, 0x67, 0x88, 0xd2, 0xb3, 0x04, 0xf5, 0x9a, 0x88, 0x4f, 0xf8, 0x4a, 0x56, 0xb1, 0x91
    };
    std::memcpy(genesis.vdfProofHash.data, vdfProofHashBytes, 32);

    // =========================================================================
    // Coinbase transaction: 100 DilV to unspendable address
    // =========================================================================
    CTransaction coinbaseTx;
    coinbaseTx.nVersion = 1;

    // Input: Null prevout (standard for coinbase)
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vin[0].nSequence = 0xFFFFFFFF;

    // scriptSig: Height (0) + genesis message + VDF proof
    std::vector<uint8_t> scriptSigData;
    scriptSigData.push_back(0);  // Height 0 for genesis
    const std::string& genesisMsg = Dilithion::g_chainParams->genesisCoinbaseMsg;
    scriptSigData.insert(scriptSigData.end(), genesisMsg.begin(), genesisMsg.end());
    coinbaseTx.vin[0].scriptSig = scriptSigData;

    // Embed the pre-computed VDF proof into the coinbase scriptSig
    // 200-byte Wesolowski proof from dilv-genesis-vdf tool
    static const uint8_t genesisVdfProofBytes[200] = {
        0x01, 0x00, 0x0d, 0xa0, 0xff, 0x96, 0xa4, 0x30, 0xec, 0x38, 0x55, 0x9a, 0xed, 0xa6, 0xf2, 0xaa,
        0xd9, 0xcd, 0x68, 0x62, 0x9e, 0x32, 0x20, 0x43, 0x9b, 0xe2, 0xad, 0x4e, 0x20, 0x40, 0x80, 0x93,
        0xe1, 0x17, 0x97, 0xfd, 0xfc, 0x38, 0xee, 0x49, 0x96, 0xc6, 0x15, 0x99, 0xee, 0xc7, 0x34, 0x49,
        0xc4, 0x00, 0xf4, 0x43, 0x19, 0xc7, 0x4b, 0xb3, 0x25, 0xd9, 0xea, 0xf9, 0x69, 0x47, 0x4a, 0x5a,
        0x85, 0x02, 0xe7, 0x3c, 0xf6, 0xa2, 0x59, 0x70, 0xc8, 0xe4, 0x55, 0x7d, 0x56, 0xaa, 0xb4, 0x27,
        0xac, 0x43, 0x35, 0x6a, 0x8d, 0x35, 0x8f, 0xc0, 0x64, 0x01, 0xc7, 0xed, 0xef, 0x95, 0x0d, 0xae,
        0x7a, 0x0c, 0x01, 0x00, 0x00, 0x00, 0xcc, 0x5a, 0x1e, 0x6c, 0x91, 0xf3, 0x0d, 0xe5, 0x87, 0x03,
        0x09, 0x5b, 0x8b, 0x48, 0x68, 0xca, 0xe2, 0xc8, 0x21, 0xa1, 0x3e, 0x29, 0xb9, 0x57, 0x0a, 0x84,
        0x2d, 0x3a, 0xf5, 0x66, 0x90, 0x6e, 0x49, 0xc3, 0xc3, 0x7b, 0x26, 0x4c, 0x6f, 0x92, 0x0f, 0x22,
        0xaf, 0x85, 0xdc, 0xe8, 0x9c, 0xaa, 0xb2, 0x65, 0x16, 0x42, 0x6c, 0x9e, 0xc3, 0x1d, 0x2c, 0x90,
        0x2e, 0xd7, 0x0f, 0xb8, 0x5d, 0x42, 0x25, 0x0b, 0x5e, 0x85, 0xb3, 0x6a, 0x9b, 0x1a, 0xcd, 0x59,
        0xad, 0x17, 0x33, 0x91, 0x44, 0x49, 0x04, 0x98, 0x21, 0x41, 0xb1, 0x6e, 0x5e, 0x6e, 0x8f, 0x2a,
        0xa1, 0xff, 0xd5, 0xa5, 0x31, 0x3a, 0x01, 0x00
    };
    std::vector<uint8_t> genesisVdfProof(genesisVdfProofBytes, genesisVdfProofBytes + 200);
    CoinbaseVDF::EmbedProof(coinbaseTx.vin[0], genesisVdfProof);

    // Output 0: OP_RETURN (unspendable, genesis tradition)
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].nValue = 0;  // No value for OP_RETURN
    coinbaseTx.vout[0].scriptPubKey.push_back(0x6a);  // OP_RETURN opcode

    // Pre-funded outputs: balance restoration from chain reset
    // Each address gets a P2PKH output with their preserved balance
    for (const auto& [address, amount] : Dilithion::g_chainParams->preFundAddresses) {
        std::vector<uint8_t> addrData;
        if (!DecodeBase58Check(address, addrData) || addrData.size() != 21) {
            continue;  // Skip invalid addresses
        }
        // Extract 20-byte pubkey hash (skip version byte)
        std::vector<uint8_t> pubKeyHash(addrData.begin() + 1, addrData.end());

        CTxOut out;
        out.nValue = amount;
        // P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
        out.scriptPubKey.push_back(0x76);  // OP_DUP
        out.scriptPubKey.push_back(0xa9);  // OP_HASH160
        out.scriptPubKey.push_back(0x14);  // Push 20 bytes
        out.scriptPubKey.insert(out.scriptPubKey.end(), pubKeyHash.begin(), pubKeyHash.end());
        out.scriptPubKey.push_back(0x88);  // OP_EQUALVERIFY
        out.scriptPubKey.push_back(0xac);  // OP_CHECKSIG
        coinbaseTx.vout.push_back(out);
    }

    coinbaseTx.nLockTime = 0;

    // Serialize the transaction
    std::vector<uint8_t> serializedTx = coinbaseTx.Serialize();

    // Store transaction with count prefix
    genesis.vtx.clear();
    genesis.vtx.push_back(1);  // Transaction count = 1
    genesis.vtx.insert(genesis.vtx.end(), serializedTx.begin(), serializedTx.end());

    // Merkle root = hash of the single transaction
    genesis.hashMerkleRoot = coinbaseTx.GetHash();

    return genesis;
}

uint256 GetGenesisHash() {
    static uint256 hash;
    static std::once_flag genesisHashOnce;

    // ── SINGLE-SOURCE GENESIS HASH + INTEGRITY GUARD (2026-06-28) ─────────────
    // call_once: the previous `static bool initialized` lazy-init was an unguarded
    // data race — C++ magic-statics protect only the FIRST default construction of
    // `hash`, NOT the later assignment inside the `if`, so two threads racing the
    // first call could both enter the block (or read `hash` before the other's
    // write was visible). call_once serializes it.
    //
    // Integrity: this accessor is the SINGLE canonical source of the genesis hash
    // consumed across the node — the startup DB key (dilithion-node/dilv-node), the
    // headers manager, the P2P version message AND the per-peer genesis/ban check
    // (net.cpp:2248/:582). The RandomX (legacy) / SHA3 (VDF) recompute was observed
    // once, on an 8GB+ miner, to transiently produce a WRONG value; persisting OR
    // advertising it strands the node on a private 1-block chain and gets its IP
    // banned (`invalid_genesis`). chainparams pins the canonical hash for mainnet +
    // DilV and the pin cannot be attacker-influenced, so when a pin exists we TRUST
    // IT: if the recompute disagrees, log loudly (fault stays visible) and use the
    // pinned value — no consumer ever sees a miscomputed genesis. Testnet leaves the
    // pin empty (computed at startup) → unguarded, as before.
    std::call_once(genesisHashOnce, []() {
        // Refuse to populate the cache before chainparams are selected: caching an
        // UNVALIDATED (un-pinned) hash for the process lifetime would silently
        // defeat the integrity check below. CreateGenesisBlock() already throws on
        // null params, but enforce the invariant locally so it is self-documenting
        // and survives a future refactor of that helper. Throwing leaves the
        // once_flag un-armed, so a correctly-ordered later call performs the
        // validated compute rather than poisoning the cache. (No such early caller
        // exists today — g_chainParams is set at startup before any genesis work.)
        if (!Dilithion::g_chainParams) {
            throw std::runtime_error("GetGenesisHash() called before chainparams initialized");
        }

        // Use VDF genesis for any chain with VDF active from genesis (DilV, or testnet in VDF-only mode)
        bool useVdfGenesis = Dilithion::g_chainParams &&
            (Dilithion::g_chainParams->IsDilV() ||
             (Dilithion::g_chainParams->vdfActivationHeight == 0 &&
              Dilithion::g_chainParams->vdfExclusiveHeight == 0));
        CBlock genesis = useVdfGenesis ?
            CreateDilVGenesisBlock() : CreateGenesisBlock();
        uint256 computed = genesis.GetHash();

        if (Dilithion::g_chainParams && !Dilithion::g_chainParams->genesisHash.empty()) {
            const uint256 pinned = uint256S(Dilithion::g_chainParams->genesisHash);
            if (!(computed == pinned)) {
                LogPrintf(ALL, ERROR,
                    "[GENESIS] recomputed genesis hash %s does not match the value pinned in "
                    "chainparams %s — using the pinned value (transient compute fault; see ops "
                    "board randomx-genesis-init-corruption)",
                    computed.GetHex().c_str(), pinned.GetHex().c_str());
                computed = pinned;
            }
        }
        hash = computed;
    });

    return hash;
}

bool IsGenesisBlock(const CBlock& block) {
    // Ensure chain parameters are initialized
    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized");
    }

    // Use VDF genesis for any chain with VDF active from genesis
    bool useVdfGenesis = Dilithion::g_chainParams->IsDilV() ||
        (Dilithion::g_chainParams->vdfActivationHeight == 0 &&
         Dilithion::g_chainParams->vdfExclusiveHeight == 0);

    if (useVdfGenesis) {
        if (block.nVersion != CBlockHeader::VDF_VERSION) return false;
    } else {
        if (block.nVersion != VERSION) return false;
    }

    if (!block.hashPrevBlock.IsNull()) return false;
    if (block.nTime != Dilithion::g_chainParams->genesisTime) return false;
    if (block.nBits != Dilithion::g_chainParams->genesisNBits) return false;

    // Check merkle root matches expected
    CBlock genesis = useVdfGenesis ?
        CreateDilVGenesisBlock() : CreateGenesisBlock();
    if (!(block.hashMerkleRoot == genesis.hashMerkleRoot)) return false;

    return true;
}

// Global state for multi-threaded mining
static std::atomic<bool> g_found{false};
static std::atomic<uint64_t> g_totalHashes{0};
static std::mutex g_resultMutex;
static uint32_t g_winningNonce = 0;
static uint256 g_winningHash;

// Serialize block header to 80 bytes (for thread-safe hashing).
// Exposed (non-static, declared in genesis.h) so the WF-1 byte-equality test can
// drive the REAL production emitter instead of a hand-copied mirror.
void SerializeBlockHeader(const CBlock& block, uint32_t nonce, std::vector<uint8_t>& data) {
    data.clear();
    data.reserve(80);

    // version (4) + prevBlock (32) + merkleRoot (32) + time (4) + bits (4) + nonce (4) = 80
    // WF-1: explicit little-endian for the four 32-bit scalars, byte-identical to
    // CBlockHeader::SerializeHeader() (the canonical serializer) for a legacy
    // (v1) block. This helper is the offline genesis-mining hasher; it must emit
    // the same 80 bytes the validator's GetHash() path consumes.
    AppendLE32(data, static_cast<uint32_t>(block.nVersion));
    data.insert(data.end(), block.hashPrevBlock.begin(), block.hashPrevBlock.end());
    data.insert(data.end(), block.hashMerkleRoot.begin(), block.hashMerkleRoot.end());
    AppendLE32(data, block.nTime);
    AppendLE32(data, block.nBits);
    AppendLE32(data, nonce);
}

void MineWorker(int threadId, int numThreads, const CBlock& templateBlock, const uint256& target) {
    // Each thread searches a different part of the nonce space
    uint32_t start = (uint32_t)(((uint64_t)0xFFFFFFFF * threadId) / numThreads);
    uint32_t end = (uint32_t)(((uint64_t)0xFFFFFFFF * (threadId + 1)) / numThreads);

    // Create per-thread RandomX VM for true parallel mining
    void* vm = randomx_create_thread_vm();
    if (!vm) {
        std::cerr << "[Thread " << threadId << "] Failed to create VM" << std::endl;
        return;
    }

    std::vector<uint8_t> headerData;
    uint64_t localHashes = 0;

    for (uint32_t nonce = start; nonce < end && !g_found.load(); ++nonce) {
        // Serialize header with current nonce
        SerializeBlockHeader(templateBlock, nonce, headerData);

        // Hash with thread-local VM (no mutex, fully parallel)
        uint256 hash;
        randomx_hash_thread(vm, headerData.data(), headerData.size(), hash.data);
        localHashes++;

        if (HashLessThan(hash, target)) {
            // Found a valid nonce!
            std::lock_guard<std::mutex> lock(g_resultMutex);
            if (!g_found.load()) {  // Double-check under lock
                g_found.store(true);
                g_winningNonce = nonce;
                g_winningHash = hash;
            }
            break;
        }

        // Update global counter periodically
        if (localHashes % 1000 == 0) {
            g_totalHashes.fetch_add(1000);
        }
    }

    // Add remaining hashes to global counter
    g_totalHashes.fetch_add(localHashes % 1000);

    // Cleanup thread-local VM
    randomx_destroy_thread_vm(vm);
}

bool MineGenesisBlock(CBlock& block, const uint256& target, int numThreads) {
    std::cout << "Mining genesis block..." << std::endl;
    std::cout << "Target: " << target.GetHex() << std::endl;
    std::cout << "Using " << numThreads << " threads..." << std::endl;

    // Reset global state
    g_found.store(false);
    g_totalHashes.store(0);
    g_winningNonce = 0;
    g_winningHash = uint256();

    // Launch worker threads
    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(MineWorker, i, numThreads, std::cref(block), std::cref(target));
    }

    // Progress reporting in main thread
    while (!g_found.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "\rHashes: " << g_totalHashes.load() << std::flush;
    }

    // Wait for all threads to finish
    for (auto& t : threads) {
        t.join();
    }

    if (g_found.load()) {
        block.nNonce = g_winningNonce;
        block.InvalidateCache();

        std::cout << "\n\nGenesis block found!" << std::endl;
        std::cout << "Nonce: " << g_winningNonce << std::endl;
        std::cout << "Hash: " << g_winningHash.GetHex() << std::endl;
        std::cout << "Hashes tried: " << g_totalHashes.load() << std::endl;

        // Verify the found nonce passes consensus validation
        std::cout << "Verifying with consensus rules..." << std::endl;
        if (!CheckProofOfWork(g_winningHash, block.nBits)) {
            std::cout << "ERROR: Found nonce does NOT pass CheckProofOfWork!" << std::endl;
            return false;
        }
        std::cout << "Verification passed! Genesis block is valid." << std::endl;

        return true;
    }

    std::cout << "\nFailed to find valid nonce" << std::endl;
    return false;
}

// Backward compatible overload
bool MineGenesisBlock(CBlock& block, const uint256& target) {
    return MineGenesisBlock(block, target, 1);
}

} // namespace Genesis
