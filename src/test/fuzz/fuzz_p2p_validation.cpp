// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Fuzz target: structural validation of P2P block and headers messages
 *
 * Exercises the checks a node applies to peer-supplied block data before any
 * chain-state or proof-of-work work is done:
 * - block header field parsing from raw bytes
 * - CBlockValidator::DeserializeBlockTransactions on attacker-controlled vtx bytes
 * - duplicate-transaction, double-spend, merkle-root and coinbase checks
 * - HEADERS / INV / ADDR count limits
 *
 * libFuzzer allows exactly one LLVMFuzzerTestOneInput per binary, so the scenarios
 * are selected by the first input byte.
 *
 * Priority: HIGH (DoS protection and network security)
 */

#include "fuzz.h"
#include "util.h"
#include "../../net/protocol.h"
#include "../../net/serialize.h"
#include "../../primitives/block.h"
#include "../../primitives/transaction.h"
#include "../../consensus/validation.h"
#include "../../consensus/params.h"
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

static void ConsumeHash(FuzzedDataProvider& fdp, uint256& out)
{
    std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(32);
    bytes.resize(32, 0);
    std::memcpy(out.data, bytes.data(), 32);
}

static void ConsumeHeader(FuzzedDataProvider& fdp, CBlockHeader& header)
{
    header.nVersion = fdp.ConsumeIntegral<int32_t>();
    ConsumeHash(fdp, header.hashPrevBlock);
    ConsumeHash(fdp, header.hashMerkleRoot);
    header.nTime = fdp.ConsumeIntegral<uint32_t>();
    header.nBits = fdp.ConsumeIntegral<uint32_t>();
    header.nNonce = fdp.ConsumeIntegral<uint32_t>();
}

// A block message from a peer: header fields plus raw serialized transaction bytes.
static void p2p_block_validation(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try {
        CBlock block;
        ConsumeHeader(fdp, block);
        block.vtx = fdp.ConsumeRemainingBytes<uint8_t>();
        if (block.vtx.size() > Consensus::MAX_BLOCK_SIZE) {
            return;  // oversized block messages are rejected before parsing
        }

        CBlockValidator validator;
        std::vector<CTransactionRef> txs;
        std::string error;
        if (!validator.DeserializeBlockTransactions(block, txs, error)) {
            return;
        }

        error.clear();
        (void)validator.CheckNoDuplicateTransactions(txs, error);
        error.clear();
        (void)validator.CheckNoDoubleSpends(txs, error);
        error.clear();
        (void)validator.VerifyMerkleRoot(block, txs, error);
        if (!txs.empty() && txs[0]) {
            error.clear();
            (void)validator.CheckCoinbase(*txs[0], block.nTime % 4000000u, 0, error);
        }
    } catch (const std::exception&) {
        // Expected for malformed data
    }
}

// A headers message: a count followed by that many 80-byte header field sets.
static void p2p_headers_validation(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try {
        uint64_t header_count = fdp.ConsumeIntegral<uint64_t>();
        if (header_count > Consensus::MAX_HEADERS_RESULTS) {
            return;  // rejected by the count limit
        }
        std::vector<CBlockHeader> headers;
        for (uint64_t i = 0; i < header_count && fdp.remaining_bytes() > 0; i++) {
            CBlockHeader header;
            ConsumeHeader(fdp, header);
            headers.push_back(header);
        }
        // Cheap, hash-free sanity pass over the parsed headers.
        for (size_t i = 1; i < headers.size(); i++) {
            (void)(headers[i].hashPrevBlock == headers[i - 1].hashPrevBlock);
            (void)headers[i].IsVDFBlock();
        }
    } catch (const std::exception&) {
        // Expected for malformed data
    }
}

// INV / ADDR count limits.
static void p2p_inv_addr_limits(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    uint64_t inv_count = fdp.ConsumeIntegral<uint64_t>();
    uint64_t addr_count = fdp.ConsumeIntegral<uint64_t>();
    volatile bool inv_rejected = inv_count > Consensus::MAX_INV_SIZE;
    volatile bool addr_rejected = addr_count > Consensus::MAX_INV_SIZE;
    (void)inv_rejected;
    (void)addr_rejected;
}

FUZZ_TARGET(p2p_validation)
{
    if (size == 0) {
        return;
    }
    switch (data[0] % 3) {
        case 0: p2p_block_validation(data + 1, size - 1); break;
        case 1: p2p_headers_validation(data + 1, size - 1); break;
        default: p2p_inv_addr_limits(data + 1, size - 1); break;
    }
}
