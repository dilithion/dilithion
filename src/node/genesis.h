// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_GENESIS_H
#define DILITHION_NODE_GENESIS_H

#include <primitives/block.h>
#include <uint256.h>
#include <core/chainparams.h>

/**
 * Genesis Block Parameters
 *
 * The genesis block is the first block in the Dilithion blockchain.
 * It is hardcoded and must be identical across all nodes.
 *
 * Parameters are network-specific (mainnet vs testnet) and defined in ChainParams.
 */
namespace Genesis {

// Genesis block version for RandomX chains (mainnet/testnet)
const int32_t VERSION = 1;

// DilV genesis uses VDF_VERSION (4) — defined in block.h

/**
 * Create the genesis block
 *
 * This function creates the genesis block using parameters from g_chainParams.
 * The genesis block has:
 * - No previous block (hashPrevBlock = 0)
 * - Merkle root from coinbase transaction
 * - Timestamp from ChainParams
 * - Difficulty target from ChainParams
 * - Nonce from ChainParams (0 if not yet mined)
 *
 * @return The genesis block for the current network
 */
CBlock CreateGenesisBlock();

/**
 * Get the genesis block hash
 *
 * This is the hash of the genesis block after it has been mined.
 * It must match across all nodes.
 *
 * @return The genesis block hash
 */
uint256 GetGenesisHash();

/**
 * Verify a block is the genesis block
 *
 * @param block Block to verify
 * @return true if the block is the genesis block
 */
bool IsGenesisBlock(const CBlock& block);

/**
 * Create the DilV genesis block (VDF chain)
 *
 * Unlike the RandomX genesis, the DilV genesis is a VDF block (version 4)
 * with a pre-computed VDF proof. The proof is hardcoded after being computed
 * once using the genesis VDF computation tool.
 *
 * The genesis block has:
 * - Version 4 (VDF_VERSION)
 * - Pre-computed vdfOutput and vdfProofHash in the header
 * - VDF proof embedded in coinbase scriptSig
 * - 100 DilV (10,000,000,000 ions) block reward
 * - No MIK (genesis is exempt from MIK requirement)
 *
 * @return The DilV genesis block
 */
CBlock CreateDilVGenesisBlock();

/**
 * Mine the genesis block
 *
 * This function mines the genesis block by finding a valid nonce.
 * It should only be called once during initial setup.
 *
 * WARNING: This can take a long time depending on the difficulty target.
 *
 * @param block Genesis block to mine
 * @param target Target hash value (derived from nBits)
 * @param numThreads Number of threads to use for mining (default: 1)
 * @return true if a valid nonce was found
 */
bool MineGenesisBlock(CBlock& block, const uint256& target, int numThreads);
bool MineGenesisBlock(CBlock& block, const uint256& target);  // Single-threaded overload

/**
 * Serialize a legacy (80-byte) block header for the offline genesis-mining
 * hasher, with an externally-supplied nonce.
 *
 * WF-1: emits the four 32-bit scalars in explicit little-endian, byte-identical
 * to CBlockHeader::SerializeHeader() for a legacy (v1) block. Exposed (rather
 * than file-static) so the WF-1 differential test can drive this real emitter.
 *
 * @param block  Block whose header fields are serialized
 * @param nonce  Nonce to write (overrides block.nNonce in the output)
 * @param data   Output buffer (cleared, then filled with 80 bytes)
 */
void SerializeBlockHeader(const CBlock& block, uint32_t nonce, std::vector<uint8_t>& data);

} // namespace Genesis

#endif // DILITHION_NODE_GENESIS_H
