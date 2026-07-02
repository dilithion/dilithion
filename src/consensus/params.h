// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_PARAMS_H
#define DILITHION_CONSENSUS_PARAMS_H

#include <amount.h>
#include <cstdint>

/**
 * Consensus Parameters
 *
 * This file contains all consensus-critical constants for the Dilithion blockchain.
 * These parameters define the economic model, security limits, and network behavior.
 *
 * CRITICAL: Changing these values creates incompatible consensus rules.
 * All nodes must use identical values for network consensus.
 */

namespace Consensus {

//==============================================================================
// Block Reward Parameters
//==============================================================================

/** Initial block subsidy in ions (50 DIL) */
static const CAmount INITIAL_BLOCK_SUBSIDY = 50 * COIN;

/** Number of blocks between subsidy halvings (~1.6 years at 4-min blocks) */
static const uint32_t SUBSIDY_HALVING_INTERVAL = 210000;

/** Stop halving after this many halvings (64 halvings = ~102 years) */
static const int SUBSIDY_HALVING_BITS = 64;

/** Minimum coinbase maturity (blocks before coinbase can be spent) */
static const unsigned int COINBASE_MATURITY = 100;

//==============================================================================
// Mining Development Contribution (2% of block subsidy)
//==============================================================================

/** Mining tax percentage (2% of block subsidy, NOT fees) */
static const uint64_t MINING_TAX_PERCENT = 2;

/** Dev Fund share of tax (50% of 2% = 1% of subsidy) */
static const uint64_t DEV_FUND_SHARE = 50;

/** Developer Reward share of tax (50% of 2% = 1% of subsidy) */
static const uint64_t DEV_REWARD_SHARE = 50;

/** Dev Fund pubkey hash (20 bytes) - Address: DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq */
static const uint8_t DEV_FUND_PUBKEY_HASH[20] = {
    0x96, 0x85, 0x9a, 0x6f, 0x0b, 0xf2, 0x80, 0xb9, 0x5e, 0x36,
    0xbb, 0xe6, 0xaf, 0x01, 0x02, 0x5f, 0x9e, 0xd4, 0x5f, 0xce
};

/** Developer Reward pubkey hash (20 bytes) - Address: DRne9ygVbQJFKma1pyEMPpyRbjmVKNcbWe */
static const uint8_t DEV_REWARD_PUBKEY_HASH[20] = {
    0xe2, 0x7c, 0x4c, 0x3f, 0xd6, 0x4a, 0x06, 0xc9, 0x6a, 0x11,
    0x85, 0xa3, 0xcc, 0xc2, 0x0c, 0xc6, 0x96, 0x93, 0xa1, 0xd5
};

//==============================================================================
// Network Protocol Limits
//==============================================================================

/** Maximum inventory items per message (prevents DoS) */
static const unsigned int MAX_INV_SIZE = 50000;

/** Maximum Base58 string length (prevents memory exhaustion) */
static const size_t MAX_BASE58_LENGTH = 1024;

/** Maximum RPC request size in bytes (1 MB limit) */
static const size_t MAX_REQUEST_SIZE = 1024 * 1024;

/**
 * Maximum block size in bytes (4 MB).
 *
 * Sized for post-quantum signatures (ML-DSA), which are far larger than ECDSA.
 * This is the SINGLE SOURCE OF TRUTH for the block `vtx` serialized-blob byte
 * size: every block-size-limit site (storage write, P2P receive, mining
 * templates, the dead CheckBlock validator) must reference this constant —
 * no local hard-coded literals.
 */
static const size_t MAX_BLOCK_SIZE = 4 * 1024 * 1024;

/**
 * Safety margin (16 KB) subtracted from MAX_BLOCK_SIZE when building mining
 * templates. Size estimates during transaction selection have small jitter;
 * budgeting against MAX_BLOCK_SIZE - BLOCK_SIZE_SAFETY_MARGIN guarantees the
 * finished template can never produce a block the storage/consensus layer
 * rejects as oversize.
 */
static const size_t BLOCK_SIZE_SAFETY_MARGIN = 16 * 1024;

/**
 * Upper-bound byte overhead of a coinbase transaction EXCLUDING its scriptSig.
 *
 * BUG-003 Bug B: mining-template builders that finalize the coinbase scriptSig
 * before knowing the final vout can seed their size budget with
 *   coinbaseScriptSig.size() + COINBASE_NON_SCRIPTSIG_OVERHEAD
 * instead of a flat (and badly-undersized) 200-byte estimate.
 *
 * Covers, generously: 4-byte version + 4-byte locktime + vin count varint +
 * 32-byte prevout hash + 4-byte prevout index + 4-byte nSequence +
 * scriptSig-length varint + vout count varint + up to 3 outputs, each an
 * 8-byte nValue + a script-length varint + a ~25-byte P2PKH script. 256 bytes
 * comfortably exceeds that (~150 bytes actual) and also absorbs the block
 * tx-count varint prefix.
 */
static const size_t COINBASE_NON_SCRIPTSIG_OVERHEAD = 256;

//==============================================================================
// Port Range Validation
//==============================================================================

/** Minimum valid port number */
static const int MIN_PORT = 1;

/** Maximum valid port number */
static const int MAX_PORT = 65535;

/** Default P2P port for mainnet */
static const uint16_t DEFAULT_P2P_PORT = 8444;

/** Default RPC port for mainnet */
static const uint16_t DEFAULT_RPC_PORT = 8445;

/** Default P2P port for testnet */
static const uint16_t DEFAULT_TESTNET_P2P_PORT = 18444;

/** Default RPC port for testnet */
static const uint16_t DEFAULT_TESTNET_RPC_PORT = 18445;

//==============================================================================
// Mining Parameters
//==============================================================================

/** Minimum mining threads */
static const int MIN_MINING_THREADS = 1;

/** Maximum mining threads (reasonable upper bound) */
static const int MAX_MINING_THREADS = 256;

/** Target block time in seconds (4 minutes) */
static const int64_t TARGET_BLOCK_TIME = 240;

/** Difficulty adjustment interval in blocks (pre-fork, runtime value from chainparams) */
static const int DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;
/** Post-fork difficulty adjustment interval (360 blocks = ~1 day at 4-min target) */
static const int DIFFICULTY_ADJUSTMENT_INTERVAL_V2 = 360;

//==============================================================================
// Chain Security Parameters
//==============================================================================

/**
 * Maximum allowed chain reorganization depth — the ROLLING reorg cap
 * (Bitcoin-practical-limit lineage). SINGLE SOURCE OF TRUTH: every reorg-bound
 * check references this constant; there must be no literal copies elsewhere.
 *
 * Value = 60 (ION decision F-02, 2026-07-01: tightened from the inherited 100).
 * On a constant-VDF-work chain nChainWork ~= block-count, so this hard depth
 * cap + attested-identity scarcity are the deep-reorg defense (not PoW
 * cumulative-work cost). See ION_DECISION_REGISTER F-02.
 */
static const int MAX_REORG_DEPTH = 60;

/** Maximum number of block headers to process in one message */
static const unsigned int MAX_HEADERS_RESULTS = 2000;

/** Maximum number of blocks to keep in flight per peer (increased from 16 for better IBD throughput) */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 32;

//==============================================================================
// P2P Network Parameters
//==============================================================================

/** Maximum number of outbound connections */
static const int MAX_OUTBOUND_CONNECTIONS = 8;

/** Maximum number of inbound connections */
static const int MAX_INBOUND_CONNECTIONS = 117;

/** Maximum total connections (8 outbound + 117 inbound = 125 total, similar to Bitcoin) */
static const int MAX_CONNECTIONS = MAX_OUTBOUND_CONNECTIONS + MAX_INBOUND_CONNECTIONS;

/** Peer connection timeout in seconds */
static const int PEER_CONNECT_TIMEOUT = 60;

/** Peer handshake timeout in seconds */
static const int PEER_HANDSHAKE_TIMEOUT = 60;

//==============================================================================
// Mempool Parameters
//==============================================================================

/** Maximum number of transactions in mempool */
static const size_t MAX_MEMPOOL_SIZE = 300000000;  // 300 MB

/** Minimum transaction fee per kilobyte (in ions) */
static const CAmount MIN_TX_FEE_PER_KB = 1000;  // 0.00001 DIL per KB

/** Maximum transaction size in bytes */
static const size_t MAX_TX_SIZE = 100000;  // 100 KB

//==============================================================================
// Script and Transaction Limits
//==============================================================================

/** Maximum number of signature operations per transaction */
static const unsigned int MAX_TX_SIGOPS = 20000;

/** Maximum script size in bytes (raised from 10KB for Dilithium post-quantum signatures) */
static const size_t MAX_SCRIPT_SIZE = 20000;

/** Maximum number of transaction inputs */
static const size_t MAX_TX_INPUTS = 100000;

/** Maximum number of transaction outputs */
static const size_t MAX_TX_OUTPUTS = 100000;

//==============================================================================
// Cryptographic Constants
//==============================================================================

/** Dilithium3 public key size in bytes */
static const size_t DILITHIUM3_PUBKEY_SIZE = 1952;

/** Dilithium3 signature size in bytes */
static const size_t DILITHIUM3_SIGNATURE_SIZE = 3309;

/** Dilithium3 private key size in bytes */
static const size_t DILITHIUM3_PRIVKEY_SIZE = 4000;

/** SHA3-256 hash output size in bytes */
static const size_t SHA3_256_SIZE = 32;

//==============================================================================
// Time Constants
//==============================================================================

/** Maximum future block timestamp (2 hours) — used pre-fork */
static const int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;

/** Reduced future block timestamp limit post-fork (10 minutes) */
static const int64_t MAX_FUTURE_BLOCK_TIME_V2 = 10 * 60;

/** Maximum block timestamp drift (median time of past 11 blocks) */
static const int MEDIAN_TIME_SPAN = 11;

//==============================================================================
// Compile-time safety invariants
//==============================================================================

/**
 * F-08 safety invariant: a reorg must never be able to un-mature (and thus
 * un-spend) a matured coinbase. The rolling reorg cap must therefore be no
 * deeper than coinbase maturity, i.e. MAX_REORG_DEPTH <= COINBASE_MATURITY.
 *
 * SCOPE (do NOT over-read this): the static_assert below guards only the
 * COMPILE-TIME constant (DIL: COINBASE_MATURITY = 100). The check that actually
 * enforces maturity at runtime reads the PER-CHAIN value
 * g_chainParams->coinbaseMaturity (e.g. DilV = 6, utxo_set.cpp), which this
 * assert does NOT cover. On a chain whose runtime maturity is below
 * MAX_REORG_DEPTH (DilV: 6 < 60), a reorg in the (maturity, cap] window can
 * still un-spend a matured coinbase — a separate live-chain finding, not caught
 * here. This assert protects DIL's compile-time invariant only.
 * (See ION_DECISION_REGISTER F-08 / K-08 + the DilV maturity item.)
 */
static_assert(MAX_REORG_DEPTH <= COINBASE_MATURITY,
              "F-08 violated: MAX_REORG_DEPTH must be <= COINBASE_MATURITY — "
              "a reorg deeper than coinbase maturity can un-spend a matured coinbase");

} // namespace Consensus

#endif // DILITHION_CONSENSUS_PARAMS_H
