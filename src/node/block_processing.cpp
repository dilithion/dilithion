// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_processing.h>
#include <node/blockchain_storage.h>
#include <node/peer_mik_tracker.h>
#include <consensus/vdf_validation.h>
#include <node/block_index.h>
#include <node/block_validation_queue.h>
#include <node/fork_manager.h>
#include <net/port/sync_coordinator.h>  // Phase 6 PR6.5a: routes via ISyncCoordinator
#include <node/utxo_set.h>
#include <consensus/chain.h>
#include <consensus/pow.h>
#include <consensus/validation.h>
#include <consensus/tx_validation.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <net/peers.h>
#include <net/banman.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>
#include <net/orphan_manager.h>
#include <net/headers_manager.h>
#include <net/async_broadcaster.h>
#include <net/net.h>
#include <net/protocol.h>
#include <net/connman.h>
#include <api/metrics.h>
#include <miner/controller.h>
#include <wallet/wallet.h>

#include <util/logging.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <mutex>
#include <unordered_map>

// NodeState struct (defined in globals.cpp, duplicated here for extern declaration)
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};
    std::atomic<bool> mining_enabled{false};
    CMiningController* miner{nullptr};
    CWallet* wallet{nullptr};
};

// External globals (used throughout codebase, thread-safe via internal mutexes)
extern CChainState g_chainstate;
extern NodeState g_node_state;

// ---------------------------------------------------------------------------
// Per-peer fork block tracking (P2P policy, NOT consensus)
// ---------------------------------------------------------------------------
// Tracks how many competing-chain blocks each peer relays. If a peer relays
// too many fork blocks (>10 in a 5-minute window), it receives a misbehavior
// penalty.  This deters private fork mining and broadcasting.
static struct PeerForkTracker {
    std::mutex mutex;
    std::map<int, int> counts;  // peer_id -> fork block count
    std::chrono::steady_clock::time_point lastDecay;

    static constexpr int THRESHOLD = 10;           // Fork blocks before penalty
    static constexpr int DECAY_INTERVAL_SEC = 300;  // Decay every 5 minutes

    void RecordForkBlock(int peerId, NodeContext& ctx) {
        bool shouldPenalize = false;
        {
            std::lock_guard<std::mutex> lock(mutex);

            // Periodic decay: halve all counters every 5 minutes
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastDecay).count() >= DECAY_INTERVAL_SEC) {
                for (auto& [id, count] : counts) {
                    count /= 2;
                }
                lastDecay = now;
            }

            counts[peerId]++;
            if (counts[peerId] >= THRESHOLD) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[ForkTracker] Peer " << peerId
                              << " relayed " << counts[peerId]
                              << " fork blocks — applying misbehavior penalty" << std::endl;
                counts[peerId] = 0;  // Reset after penalty
                shouldPenalize = true;
            }
        }
        // Call Misbehaving outside the mutex to avoid lock-order risks
        if (shouldPenalize && ctx.peer_manager) {
            ctx.peer_manager->Misbehaving(peerId, 0, MisbehaviorType::EXCESSIVE_FORK_BLOCKS);
        }
    }
} s_forkTracker;

// ---------------------------------------------------------------------------
// Hardcoded Sybil ban list: DilV March 30, 2026 attack (97 MIKs)
// One operator created 97 identities and mined 698 blocks (12.4% of supply)
// in a single 13-hour window. All confirmed via forensic analysis:
// - Identical 1:1 address-to-block ratio (new address every block)
// - All active only in blocks 1543-2631 (March 30 09:22-23:14 UTC)
// - 70.2% consecutive blocks (gap=1)
// ---------------------------------------------------------------------------
static const char* HARDCODED_BANNED_MIKS[] = {
    "07a15b1fda57bde1528053af9179259b7ffdf618",
    "1382eb69cc2ba25be09df59386afbdcfdca33c39",
    "143658c6e84262883b976d50d80e17271c8c797b",
    "15753ce782c421fbcaa35e6ef25e7a9efd8b6798",
    "16cdcd49af1fbaca4ef74c04e6ce8ba6ab2631a7",
    "211e948c67cb7c921b3d83401f0654bd852b97a4",
    "22d9929ad567ceaa04c05252f1141e6facc66d41",
    "2f70042cd51b05dbb53fd8e216a1a6625adbb1a3",
    "32462815e1f2b6d465fddf86432920a9f24d4fc8",
    "392ffb18cdfd0d656d38e2ad6c01d0483c316a5b",
    "3a3123d8cd40e54da9961ad46fca3295ad2b0612",
    "3b88a1416e3da53e10b2ec084f07dea96b3caec4",
    "3fcac01ad86e7783d4acca31a7ce5eae02d5a737",
    "40342ee387029399d2766e56e74e31e49548126c",
    "43f011daa32194cd863bfe8eb544d1b1b6a9c778",
    "4588be4d68cd77e67c83e315b60c8e3dbd4bc207",
    "4937fabc53031b0063b1810eff87a24ccf63e07e",
    "4bbc43dc118d7bc27c7fb62051afc3359315427a",
    "4d1b9e435e972fce96f518ccda84835106f267fd",
    "56aed37350a69f174b052257d4afb163cc569dd9",
    "589cabca22ba9d9d5fdd76a492dd891d23291e37",
    "5aacfdad89569709ea67db85f7450923bcfed875",
    "5b1830676b592574d3b091c75a75a2ee5a8b8972",
    "5cbfadccd8620dfa686137537038eabf880acf8c",
    "6121bb3600623c0dd86daff64238207db8c5201e",
    "6332541d823aceecf45f82cd7b1d011dd8e392bf",
    "666028abb676a4a5574ab358db106a62e504ee6f",
    "6833f81601a7ef3807b1dcbba4edfb2b469e9fa7",
    "68c6629cc458ca8642c611da8825bd11b608868a",
    "6a80a261591c3fe9150c51c2da31b529637160f7",
    "6f91ff9260d3b1e0633287066dc92b75a32f7d64",
    "6fbb2212684cd11b481eef39c2a2a91f287b73c6",
    "71530bf0bf3cd11d9e7ee4d840e58a2297691433",
    "72df1a7ed049ae851f5c9537a913a47d939b44dc",
    "7899dd8a1e57f1c4afb16e38eaa7213c0dc64a83",
    "7d892d4ab74e5575188b6badab9676cc64aae320",
    "81b009b01c73862f941282b717402cf6377e6c63",
    "83dd12cb97a30fd1e5085f77b830d0fb4f2a1dfe",
    "855b2ab535f4deb72e49a4087e60925ba808dc21",
    "85d52d5e6f0f58c145066df9ecc5b25e919c833f",
    "8a8c5c4ed3df83f2942597fa4a2c04898354673f",
    "8bb67d74f95193168c900ce225e90952ea50798c",
    "8eedb27daf1585410962ca02f8a2faaef0790119",
    "915b2fa8c55f97554085482329ec41daf2b24257",
    "958ef4879b8ed61003d565046e23c945e177a84d",
    "96a7af8b36f55002aff8ed4bb8a64f00505d4e20",
    "96e65340959b6577bb84f9680721597772f3b00a",
    "9a9fc953323c8a594d19298bdfa5ae259dd797c5",
    "9d9eecf0ab8307a39744d775629fcfc20363619c",
    "9f92f3696abb60d4ea3c2acd3987118684be2b34",
    "a04247f80fc02613c6b93e5658225b842338e494",
    "a0d0b05c224846e5482efbe4d6f9857cb95fcb1b",
    "a3219c068d1890ff23eb1ec230bf5de460dd54ce",
    "a5f43e95e988136e2a6b88167641e8affefecd64",
    "a7aeef53c0e3e7851def7c50c3e75df8c4981017",
    "a8d752238f8576c1148ed5a61a54607864606ce2",
    "ab690eba0a2f56faf59c0c130913ae946e4ba1fa",
    "abb98db15179ded901648bc20eb6d9741b59c971",
    "b7d30cfed74c1555bf1160e2256b6cf87c973b9d",
    "b85248a1e6d1dc1e49a882ba3e7cd5d61d383e08",
    "b8e544ac2ce9098eead7a1e37f473b9a09e51b6b",
    "b9516a2e4bbbadb57a24d1ad2f8c4645c7418041",
    "b999bd9444ecbe0eedd5e35c219ceab77298599c",
    "be7c3f02caf635d3d2db5251ec35bbe23bceb3b6",
    "bf4f0a11b757afa8f125a7a9d3d75598f3ba2bad",
    "c116dc13321f14e6ca367c029951738956d9e987",
    "c3015b97997c86127920254f98509926f267962e",
    "c4282edfa14bfe3d3f43321661d58abc259a3304",
    "c81581bb2cbc322ae27f869e180d9cc295af7b39",
    "c9027dad7595025517ea3b00a3cfef6cf0ed1426",
    "ce6d413f3ff0e4b145de437bf460d0804a737adb",
    "d01dce74783e6b1903361bedccfad754daa30066",
    "d13a3777266c814ee9310dfe4fce5f161dfc824c",
    "d2db717b17a914abca3aaf66ef064aa0f2b3ef2b",
    "d468861db4492b691e510091c877e9a1c9ad55b4",
    "dcfc5f9d4b35c19193a8cbb6b7d20e1d26327249",
    "dd2b01eeefb3f09b7dba699f432fe5212098e263",
    "dd46ccfa2a237bbac42f24c679a075a481cf98b8",
    "de3d7cadf1ee96b3a0eb22b4dc2f90e03a37d15a",
    "e3768997759f6a3b9e3dd639791f9b04c0681cc4",
    "e3c478423c5e0b0cc16f2dd0dfff13b31da00246",
    "e7be40b85ba4061a810205f7fb850be95c524b0f",
    "ea687388c2f0a2de07c39b3043db0fa4d43f6e39",
    "eb2ae41318016d4969d087fbc93c6ffd804e1d3a",
    "eca8acae259c44446c86c5d57b105e9fa9ac0be4",
    "edce6b7f9d8748a37ede0cc83c2aec520f1dd273",
    "edf05cea505d408a2f075c640ef1aec882e19beb",
    "ee17ce2a0d2c7a13455f5b660ea46cc0fed060ba",
    "ee499856ab7cc466469f3f10211126499044f7be",
    "ee5a8dfc72208003ec208267c82927c79afa6f5a",
    "eeb5e8fe894a5be3faffde1ae7d67b5492aade6d",
    "f085ee4769ea03400fd17bc305ea679c90808e63",
    "f77241bbbe1ed12d58d3c597c3d19447133e6126",
    "f9dc7ed21d764c9e0e75f1a03fe42a645752b784",
    "fc57d1ba6e08b2743b96bf5e5c0ab10fbcb11061",
    "fd12ef5effe930387c89aff09f2e24c9180f8935",
    "fe4fa16cf2229555b64a7068b58db7e877927bfb",
    nullptr  // sentinel
};

// ---------------------------------------------------------------------------
// Banned MIK identities (node policy, NOT consensus)
// ---------------------------------------------------------------------------
// Blocks from banned MIKs are rejected locally and not relayed.
// Managed via RPC: banmik / unbanmik / listbannedmiks
static struct BannedMIKSet {
    std::mutex mutex;
    std::set<std::string> banned;  // MIK hex strings (40 chars)

    BannedMIKSet() {
        // Load hardcoded Sybil bans at startup
        for (int i = 0; HARDCODED_BANNED_MIKS[i] != nullptr; i++) {
            banned.insert(HARDCODED_BANNED_MIKS[i]);
        }
    }

    bool IsBanned(const std::string& mikHex) {
        std::lock_guard<std::mutex> lock(mutex);
        return banned.count(mikHex) > 0;
    }

    void Add(const std::string& mikHex) {
        std::lock_guard<std::mutex> lock(mutex);
        banned.insert(mikHex);
    }

    void Remove(const std::string& mikHex) {
        std::lock_guard<std::mutex> lock(mutex);
        banned.erase(mikHex);
    }

    std::vector<std::string> List() {
        std::lock_guard<std::mutex> lock(mutex);
        return std::vector<std::string>(banned.begin(), banned.end());
    }
} g_bannedMIKs;

// Public accessors for RPC
void BanMIK(const std::string& mikHex) { g_bannedMIKs.Add(mikHex); }
void UnbanMIK(const std::string& mikHex) { g_bannedMIKs.Remove(mikHex); }
std::vector<std::string> ListBannedMIKs() { return g_bannedMIKs.List(); }
bool IsMIKBanned(const std::string& mikHex) { return g_bannedMIKs.IsBanned(mikHex); }

// Chain tip update callback (set by main node at startup)
static ChainTipUpdateCallback g_chain_tip_callback = nullptr;

void SetChainTipUpdateCallback(ChainTipUpdateCallback callback) {
    g_chain_tip_callback = callback;
}

/**
 * @brief Resolve orphan children whose parent now has a CBlockIndex.
 *
 * When a block is added to mapBlockIndex (via fork staging or normal activation),
 * any orphan blocks waiting for it as their parent can now be processed.
 * This function extracts each orphan child from the pool and recursively calls
 * ProcessNewBlock, which cascades to grandchildren automatically.
 *
 * Called from:
 *   - Fork staging path (out-of-order arrivals during fork recovery)
 *   - Fork switch success path (intermediate blocks connected during reorg)
 *   - Normal path (existing Phase 7 orphan resolution)
 */
static void ResolveOrphanChildren(
    const uint256& parentHash,
    NodeContext& ctx,
    CBlockchainDB& db)
{
    if (!ctx.orphan_manager) return;

    std::vector<uint256> children = ctx.orphan_manager->GetOrphanChildren(parentHash);
    if (children.empty()) return;

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[ForkOrphan] Resolving " << children.size()
                  << " orphan children of " << parentHash.GetHex().substr(0, 16)
                  << "..." << std::endl;

    for (const uint256& orphanHash : children) {
        CBlock orphanBlock;
        if (ctx.orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
            // Erase from orphan pool BEFORE processing to avoid re-entry
            ctx.orphan_manager->EraseOrphanBlock(orphanHash);
            uint256 orphanBlockHash = orphanBlock.GetHash();
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ForkOrphan] Processing orphan child "
                          << orphanBlockHash.GetHex().substr(0, 16) << "..." << std::endl;
            ProcessNewBlock(ctx, db, -1, orphanBlock, &orphanBlockHash);
        }
    }
}

const char* BlockProcessResultToString(BlockProcessResult result) {
    switch (result) {
        case BlockProcessResult::ACCEPTED: return "ACCEPTED";
        case BlockProcessResult::ACCEPTED_ASYNC: return "ACCEPTED_ASYNC";
        case BlockProcessResult::ALREADY_HAVE: return "ALREADY_HAVE";
        case BlockProcessResult::INVALID_POW: return "INVALID_POW";
        case BlockProcessResult::ORPHAN: return "ORPHAN";
        case BlockProcessResult::DB_ERROR: return "DB_ERROR";
        case BlockProcessResult::CHAINSTATE_ERROR: return "CHAINSTATE_ERROR";
        case BlockProcessResult::VALIDATION_ERROR: return "VALIDATION_ERROR";
        default: return "UNKNOWN";
    }
}

BlockProcessResult ProcessNewBlock(
    NodeContext& ctx,
    CBlockchainDB& db,
    int peer_id,
    const CBlock& block,
    const uint256* precomputed_hash)
{
    if (g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[ProcessNewBlock] ENTRY peer=" << peer_id << std::endl;
        std::cout.flush();
    }
    auto handler_start = std::chrono::steady_clock::now();

    // =========================================================================
    // PHASE 1: HASH COMPUTATION/LOOKUP
    // BUG #152 FIX: ALWAYS use canonical (RandomX) hash for block identity
    // =========================================================================
    int currentChainHeight = g_chainstate.GetHeight();
    int checkpointHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;

    // Skip PoW validation (target check) for blocks below checkpoint
    bool skipPoWCheck = (checkpointHeight > 0 && currentChainHeight < checkpointHeight);

    uint256 blockHash;

    // Use precomputed hash if provided (e.g., from compact block reconstruction)
    if (precomputed_hash && !precomputed_hash->IsNull()) {
        blockHash = *precomputed_hash;
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[ProcessNewBlock] Using precomputed hash: " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;
    } else if (ctx.headers_manager) {
        // ALWAYS look up hash from headers first (both above and below checkpoint)
        int expectedHeight = -1;

        // 1a. Try chainstate for parent
        CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
        if (pParent) {
            expectedHeight = pParent->nHeight + 1;
        } else {
            // 1b. Try headers manager for parent height
            expectedHeight = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
            if (expectedHeight >= 0) {
                expectedHeight += 1;  // Our height is parent + 1
            }
        }

        // 2. Look up our hash from headers manager
        if (expectedHeight > 0) {
            blockHash = ctx.headers_manager->GetRandomXHashAtHeight(expectedHeight);
            if (!blockHash.IsNull() && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[ProcessNewBlock] Hash from headers (height " << expectedHeight << "): "
                          << blockHash.GetHex().substr(0, 16) << "..." << std::endl;
            }
        }
    }

    // Fallback: compute hash if not found in headers
    if (blockHash.IsNull()) {
        if (g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[ProcessNewBlock] Computing block hash (RandomX)..." << std::endl;
            std::cout.flush();
        }
        auto hash_start = std::chrono::steady_clock::now();
        blockHash = block.GetHash();
        auto hash_end = std::chrono::steady_clock::now();
        auto hash_ms = std::chrono::duration_cast<std::chrono::milliseconds>(hash_end - hash_start).count();
        if (g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[ProcessNewBlock] Hash computed in " << hash_ms << "ms: " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;
            std::cout.flush();
        }
    }

    // =========================================================================
    // MIK BAN CHECK (node policy, NOT consensus)
    // Reject blocks from banned MIK identities before any expensive processing.
    // Also extract MIK hex for Sybil relay tracking (Phase 1).
    //
    // BUG #284 FIX: Skip ban check during IBD when below checkpoint height.
    // The Sybil ban list includes MIKs that mined blocks 1543-2631, which are
    // part of the checkpointed chain. Rejecting them during IBD prevents sync.
    // =========================================================================
    std::string blockMikHex;  // Persisted for Sybil relay tracking
    {
        std::array<uint8_t, 20> blockMik{};
        if (ExtractCoinbaseMIKIdentity(block, blockMik)) {
            // Convert to hex for lookup
            blockMikHex.reserve(40);
            for (int i = 0; i < 20; i++) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", blockMik[i]);
                blockMikHex += hex;
            }
            // Only enforce ban for new blocks at chain tip (post-IBD).
            // During IBD, skip ban check — these blocks were already accepted by
            // the network. The ban list includes DilV Sybil MIKs that may overlap
            // with legitimate DIL miners (shared ban list, separate chains).
            // Bans are node policy (NOT consensus) per line 206.
            bool is_ibd = g_node_context.sync_coordinator &&
                          !g_node_context.sync_coordinator->IsSynced();
            if (!skipPoWCheck && !is_ibd && g_bannedMIKs.IsBanned(blockMikHex)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[ProcessNewBlock] REJECTED: banned MIK " << blockMikHex.substr(0, 12) << "..." << std::endl;
                if (peer_id >= 0 && ctx.block_fetcher) {
                    ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                }
                return BlockProcessResult::VALIDATION_ERROR;
            }
        }
    }

    // RAII guard: ensures block tracker is cleaned on ALL exit paths.
    // 16 of 28 return paths were missing tracker cleanup, causing "all peers at capacity"
    // stalls during IBD. Uses hash-only cleanup (safe, authoritative).
    // Paths with existing explicit cleanup set released=true to avoid double stats.
    struct BlockTrackerGuard {
        NodeContext& ctx;
        int peer_id;
        uint256 hash;
        bool released = false;
        ~BlockTrackerGuard() {
            if (!released && peer_id >= 0 && ctx.block_fetcher) {
                ctx.block_fetcher->MarkBlockReceived(peer_id, hash);
            }
        }
    };
    BlockTrackerGuard tracker_guard{ctx, peer_id, blockHash};

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[ProcessNewBlock] Processing block: " << blockHash.GetHex().substr(0, 16) << "..."
                  << " (chainHeight=" << currentChainHeight << ", checkpoint=" << checkpointHeight
                  << ", skipPoWCheck=" << (skipPoWCheck ? "yes" : "no") << ")" << std::endl;

    // =========================================================================
    // PHASE 1.5: FORK BLOCK PRE-VALIDATION (Validate-Before-Disconnect)
    // If a fork is being validated, pre-validate blocks before normal processing.
    // Blocks still go through normal processing to create CBlockIndex entries,
    // but we skip ActivateBestChain until all fork blocks are ready.
    // =========================================================================
    bool isForkBlock = false;
    bool forkPreValidated = false;  // Track if fork block actually passed pre-validation
    int blockHeight = -1;  // Will be calculated if needed
    {
        ForkManager& forkMgr = ForkManager::GetInstance();

        if (forkMgr.HasActiveFork()) {
            // Calculate block height
            blockHeight = currentChainHeight + 1;
            CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
            if (pParent) {
                blockHeight = pParent->nHeight + 1;
            } else if (ctx.headers_manager) {
                int parentHeight = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
                if (parentHeight >= 0) {
                    blockHeight = parentHeight + 1;
                }
            }

            auto fork = forkMgr.GetActiveFork();
            if (fork) {
                int32_t forkPoint = fork->GetForkPointHeight();
                int32_t forkTip = fork->GetExpectedTipHeight();

                // Check if this block belongs to the fork using hash verification
                // IsExpectedBlock checks both height range AND hash match (if expected hashes available)
                bool inForkRange = (blockHeight > forkPoint && blockHeight <= forkTip);
                if (fork->IsExpectedBlock(blockHash, blockHeight)) {
                    isForkBlock = true;

                    if (g_verbose.load(std::memory_order_relaxed)) {
                        if (fork->HasExpectedHashes()) {
                            std::cout << "[ProcessNewBlock] Block VERIFIED as fork member (height "
                                      << blockHeight << ", hash matches expected)" << std::endl;
                        } else {
                            std::cout << "[ProcessNewBlock] Block in fork range (height "
                                      << blockHeight << " in " << (forkPoint + 1) << "-" << forkTip
                                      << ", no hash verification available)" << std::endl;
                        }
                    }

                    // Add block to fork tracking
                    forkMgr.AddBlockToFork(block, blockHash, blockHeight);

                    // Pre-validate this fork block (PoW + MIK) BEFORE normal processing
                    // MIK validation uses fork identity cache + main DB
                    ForkBlock* forkBlock = fork->GetBlockAtHeight(blockHeight);
                    if (forkBlock && forkBlock->status == ForkBlockStatus::PENDING) {
                        if (!forkMgr.PreValidateBlock(*forkBlock, db)) {
                            std::cerr << "[ProcessNewBlock] Fork block FAILED pre-validation: "
                                      << forkBlock->invalidReason << std::endl;

                            // Cancel the fork - invalid block detected!
                            int cancelForkPoint = fork->GetForkPointHeight();
                            forkMgr.CancelFork("Block failed pre-validation: " + forkBlock->invalidReason);
                            forkMgr.ClearInFlightState(ctx, cancelForkPoint);
                            g_node_context.fork_detected.store(false);
                            g_metrics.ClearForkDetected();

                            // Invalidate the header
                            if (ctx.headers_manager) {
                                ctx.headers_manager->InvalidateHeader(blockHash);
                            }

                            // FORK FIX: Do NOT ban peer on fork pre-validation failure
                            // Fork blocks may appear invalid due to our incorrect chain state.
                            // Banning prevents the peer from helping us recover.
                            // Just cancel the fork and let the node try again.
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[ProcessNewBlock] Fork cancelled, NOT banning peer (fork recovery mode)" << std::endl;

                            return BlockProcessResult::INVALID_POW;
                        }
                        forkPreValidated = true;  // Track successful pre-validation
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[ProcessNewBlock] Fork block pre-validated successfully (PoW + MIK)" << std::endl;
                    }
                } else if (inForkRange) {
                    // BUG #256 FIX: Block is in fork height range but hash doesn't match expected
                    // This could be:
                    // 1. A block from a DIFFERENT chain (e.g., valid chain from NYC)
                    // 2. Peer sent wrong block
                    // Log for debugging and try to validate it through normal path
                    uint256 expectedHash = fork->GetExpectedHashAtHeight(blockHeight);
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[ProcessNewBlock] Block in fork range but HASH MISMATCH at height " << blockHeight
                                  << "\n  Expected: " << expectedHash.GetHex().substr(0, 16) << "..."
                                  << "\n  Got:      " << blockHash.GetHex().substr(0, 16) << "..."
                                  << "\n  prevBlock: " << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;

                    // BUG #261 FIX: Track hash mismatches. If we keep getting blocks
                    // at expected heights but with wrong hashes, the fork candidate's
                    // expected hash set is stale. Refresh the hash if possible.
                    int mismatchCount = fork->RecordHashMismatch();

                    // Refresh stale expected hash from headers manager
                    if (ctx.headers_manager) {
                        uint256 currentExpected = ctx.headers_manager->GetRandomXHashAtHeight(blockHeight);
                        if (!currentExpected.IsNull()) {
                            fork->UpdateExpectedHash(blockHeight, currentExpected);
                        }
                    }

                    if (fork->HasExcessiveHashMismatches()) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[ProcessNewBlock] Fork has " << mismatchCount
                                      << " hash mismatches - expected hashes are STALE, cancelling fork" << std::endl;
                        int cancelForkPoint = fork->GetForkPointHeight();
                        forkMgr.CancelFork("Excessive hash mismatches (" + std::to_string(mismatchCount) + ") - stale expected hashes");
                        forkMgr.ClearInFlightState(ctx, cancelForkPoint);
                        g_node_context.fork_detected.store(false);
                        g_metrics.ClearForkDetected();
                    }
                    // Let block go through normal orphan handling regardless
                }
            }
        }
    }
    // Note: Fork blocks continue through normal processing below to create CBlockIndex.
    // We will skip ActivateBestChain in Phase 7 if isForkBlock is true.

    // =========================================================================
    // PHASE 2: PROOF-OF-WORK VALIDATION (with DFMP enforcement)
    // =========================================================================
    // FORK FIX: Skip DFMP check for fork blocks that passed pre-validation
    // Fork blocks are MIK-validated during PreValidateBlock using the fork
    // identity cache. Only skip DFMP if pre-validation actually succeeded.
    // If pre-validation wasn't run (race condition), fall through to DFMP check.
    if (!skipPoWCheck && !forkPreValidated) {
        // Get block height for DFMP calculation
        // BUG FIX: Use headers_manager for correct height when blocks arrive out of order
        int blockHeight = currentChainHeight + 1;  // Default: next block
        std::string heightSource = "default";
        CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
        if (pParent) {
            blockHeight = pParent->nHeight + 1;
            heightSource = "pParent";
        } else if (ctx.headers_manager) {
            // Parent not in chain yet - get height from headers manager
            int parentHeight = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
            if (parentHeight >= 0) {
                blockHeight = parentHeight + 1;
                heightSource = "headers_manager";
            }
        }

        // Debug: Show height derivation
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[ProcessNewBlock] DFMP height=" << blockHeight
                      << " (source=" << heightSource << ", chainHeight=" << currentChainHeight << ")" << std::endl;

        // BUG #246c/248 FIX: Skip DFMP validation when parent not connected
        // MIK validation requires registration blocks to be processed first.
        // If parent isn't in chainstate, we can't trust that the identity database
        // has all necessary MIK registrations. Defer MIK validation until the
        // parent connects and this block is reprocessed.
        // Basic PoW check still runs; full MIK validation happens on reconnect.
        //
        // CRITICAL: The old condition was:
        //   isOrphanBlock = (!pParent && blockHeight > currentChainHeight + 1)
        // This failed for blocks exactly 1 ahead (e.g., block 1001 when chain at 1000).
        // Those blocks would run MIK validation before their parent connected,
        // causing signature failure if the height was derived wrong or identity
        // wasn't registered yet.
        //
        // BUG #250 FIX: Only run DFMP when parent is on ACTIVE chain.
        // The identity DB only contains identities from the active chain (connect-only writes).
        // If parent exists but is on a competing chain, identity lookups will fail incorrectly.
        // Treat such blocks like orphans: basic PoW only, defer MIK until parent is on active chain.
        //
        // BLOCK_VALID_CHAIN is set in ConnectTip and cleared in DisconnectTip,
        // so it reliably indicates "block is part of current active chain."
        bool parentOnActiveChain = (pParent != nullptr) && (pParent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN);
        bool shouldSkipDFMP = !parentOnActiveChain;

        // =========================================================================
        // CRITICAL FIX: Validate nBits matches expected difficulty
        // =========================================================================
        // Without this check, miners can use ANY difficulty (including genesis difficulty)
        // forever, bypassing the difficulty adjustment algorithm entirely.
        // This was causing blocks to be accepted with easy difficulty after block 2016.
        //
        // Only validate when parent is on active chain (we need full chain history
        // to calculate expected difficulty). For orphan blocks, nBits validation
        // is deferred until the parent connects (same as DFMP validation).
        if (parentOnActiveChain) {
            uint32_t expectedNBits = GetNextWorkRequired(pParent, static_cast<int64_t>(block.nTime));
            if (block.nBits != expectedNBits) {
                std::cerr << "[ProcessNewBlock] ERROR: Block has wrong difficulty" << std::endl;
                std::cerr << "  Block nBits:    0x" << std::hex << block.nBits << std::endl;
                std::cerr << "  Expected nBits: 0x" << expectedNBits << std::dec << std::endl;
                std::cerr << "  Parent height:  " << pParent->nHeight << std::endl;
                g_metrics.RecordInvalidBlock();
                return BlockProcessResult::INVALID_POW;
            }
        }

        if (shouldSkipDFMP) {
            // Parent missing OR parent on competing chain - do basic PoW check only (no MIK/DFMP)
            // VDF blocks skip hash-under-target check (proof validated in CheckVDFProof)
            if (!block.IsVDFBlock() && !CheckProofOfWork(blockHash, block.nBits)) {
                std::cerr << "[ProcessNewBlock] ERROR: Block has invalid basic PoW (parent not on active chain)" << std::endl;
                return BlockProcessResult::INVALID_POW;
            }
            if (g_verbose.load(std::memory_order_relaxed)) {
                if (pParent == nullptr) {
                    std::cout << "[ProcessNewBlock] Orphan block at height " << blockHeight
                              << " (chainHeight=" << currentChainHeight << ") - deferring MIK validation until parent connects" << std::endl;
                } else {
                    std::cout << "[ProcessNewBlock] Block at height " << blockHeight
                              << " has parent on competing chain - deferring MIK validation" << std::endl;
                }
            }
            // Skip DFMP check - will run when block is reprocessed after parent is on active chain
        }

        // Get DFMP activation height
        int dfmpActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpActivationHeight : 0;

        // Use DFMP-aware PoW check (applies identity-based difficulty multipliers)
        // Skip when parent is not on active chain - MIK validation deferred
        if (!shouldSkipDFMP && !CheckProofOfWorkDFMP(block, blockHash, block.nBits, blockHeight, dfmpActivationHeight)) {
            std::cerr << "[ProcessNewBlock] ERROR: Block has invalid PoW (DFMP check failed)" << std::endl;
            std::cerr << "  Hash must be less than DFMP-adjusted target" << std::endl;
            g_metrics.RecordInvalidBlock();

            // Invalidate header to prevent re-requesting this block
            if (ctx.headers_manager) {
                ctx.headers_manager->InvalidateHeader(blockHash);
            }

            // BUG #250 FIX: Only reset headers if parent IS on active chain.
            // If parent is on active chain and MIK fails, block is truly invalid.
            // If parent is NOT on active chain, identity DB may not have the identity
            // (since we only write on connect) - don't invalidate headers for chain mismatch.
            if (parentOnActiveChain) {
                g_node_context.headers_chain_invalid.store(true);
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[ProcessNewBlock] Headers chain invalid (parent on active chain, MIK failed) - will resync from different peer" << std::endl;

                // BUG #255 FIX: Mark block as permanently failed (authoritative validation)
                // Parent is on active chain, so chain state is correct. DFMP failure is definitive.
                CBlockIndex* pindex = g_chainstate.GetBlockIndex(blockHash);
                if (pindex) {
                    pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
                    // Perf fix 2026-07-12: this flips validity status on an
                    // already-indexed entry outside AddBlockIndex, so the
                    // GetChainTips() cache needs an explicit nudge.
                    g_chainstate.InvalidateChainTipsCache();
                    std::cerr << "[ProcessNewBlock] Block marked BLOCK_FAILED_VALID - will not retry" << std::endl;
                    // Persist to disk
                    if (ctx.blockchain_db) {
                        ctx.blockchain_db->WriteBlockIndex(blockHash, *pindex);
                    }
                }
            } else {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[ProcessNewBlock] MIK validation failed but parent not on active chain at height " << blockHeight
                              << " (chainHeight=" << currentChainHeight << ") - NOT resetting headers (chain mismatch expected)" << std::endl;
            }

            // BUG #246 FIX: NO misbehavior for MIK failures.
            // MIK failures are almost always chain mismatch (peer on different fork),
            // not malicious behavior. Banning peers for being on a different chain
            // causes network partitioning and prevents fork resolution.
            // The block is already rejected - that's sufficient protection.
            // if (ctx.peer_manager && peer_id >= 0) {
            //     ctx.peer_manager->Misbehaving(peer_id, 20, MisbehaviorType::INVALID_BLOCK_POW);
            // }

            // BUG #246b FIX: Mark block as received even when validation fails.
            // Without this, failed blocks stay in-flight forever, causing
            // "all peers at capacity" stalls. We still reject the block, but
            // we clear it from tracking so new blocks can be requested.
            tracker_guard.released = true;
            if (ctx.block_fetcher) {
                ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                ctx.block_fetcher->OnBlockReceived(peer_id, blockHeight, blockHash);
            }

            return BlockProcessResult::INVALID_POW;
        }
    } else if (forkPreValidated) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[ProcessNewBlock] Fork block - skipping DFMP check (MIK validated in PreValidateBlock)" << std::endl;
    }

    // =========================================================================
    // PHASE 2.25: TIMESTAMP VALIDATION (consensus fork at timestampValidationHeight)
    // Validates block timestamp against future-time limit and median-time-past.
    // Pre-fork (< timestampValidationHeight): skipped (historical blocks not affected).
    // Post-fork (>= timestampValidationHeight): rejects blocks with timestamp > now + 600s or <= MTP.
    // Block at timestampValidationHeight (24500 mainnet) is the first to use the 600s limit.
    // Orphan blocks (no parent) skip validation — re-validated when parent connects.
    //
    // v4.0.22 (2026-04-25 incident): also skip if block is at or below
    // dfmpAssumeValidHeight. The historical chain in the incident range
    // contains blocks whose timestamps are inconsistent with current MTP
    // computation (likely due to clock skew or bug in the originating
    // miners). They were accepted by the network at the time. Above
    // dfmpAssumeValidHeight, strict validation applies.
    // =========================================================================
    {
        int tsValHeight = (Dilithion::g_chainParams)
            ? Dilithion::g_chainParams->timestampValidationHeight : 999999999;
        int tsAssumeValidHeight = (Dilithion::g_chainParams)
            ? Dilithion::g_chainParams->dfmpAssumeValidHeight : 0;

        CBlockIndex* pParentTS = g_chainstate.GetBlockIndex(block.hashPrevBlock);
        int tsBlockHeight = (pParentTS != nullptr) ? pParentTS->nHeight + 1 : currentChainHeight + 1;

        if (pParentTS != nullptr && tsBlockHeight >= tsValHeight
                                  && tsBlockHeight > tsAssumeValidHeight) {
            if (!CheckBlockTimestamp(block, pParentTS, tsBlockHeight)) {
                std::cerr << "[ProcessNewBlock] REJECTED: Block at height " << tsBlockHeight
                          << " failed timestamp validation" << std::endl;
                g_metrics.RecordInvalidBlock();
                // Penalize the peer — 20 points per offense (ban after 5).
                // Clock skew is usually misconfiguration, not malice, so we
                // give them a chance to fix it before banning.
                if (peer_id >= 0 && ctx.peer_manager) {
                    ctx.peer_manager->Misbehaving(peer_id, 0,
                        MisbehaviorType::FUTURE_BLOCK_TIMESTAMP);
                }
                return BlockProcessResult::VALIDATION_ERROR;
            }
        }
    }

    // =========================================================================
    // PHASE 2.5: COINBASE TAX VALIDATION (MAINNET ONLY)
    // Validates that coinbase includes required Dev Fund & Dev Reward outputs
    // =========================================================================
    bool isTestnet = Dilithion::g_chainParams && Dilithion::g_chainParams->IsTestnet();
    // BUG FIX: Skip coinbase validation for fork pre-validated blocks.
    // Fork blocks use our local UTXO set which reflects a different chain,
    // so fee calculation is wrong. Full coinbase validation runs in ConnectTip
    // when the fork chain is actually activated and the UTXO set is correct.
    if (!isTestnet && !skipPoWCheck && !forkPreValidated) {
        // Get block height
        int blockHeight = currentChainHeight + 1;
        CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
        if (pParent) {
            blockHeight = pParent->nHeight + 1;
        }

        // Deserialize transactions to get coinbase
        CBlockValidator validator;
        std::vector<CTransactionRef> transactions;
        std::string validationError;

        if (!validator.DeserializeBlockTransactions(block, transactions, validationError)) {
            std::cerr << "[ProcessNewBlock] ERROR: Failed to deserialize transactions for coinbase check: "
                      << validationError << std::endl;
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        if (transactions.empty()) {
            std::cerr << "[ProcessNewBlock] ERROR: Block has no transactions" << std::endl;
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        // BUG #260 FIX: Calculate transaction fees before validating coinbase
        // Previously passed fees=0, which rejected blocks with any transaction fees
        // BUG #276 FIX: When fee calculation fails (e.g., UTXO set corruption after crash,
        // or inputs not yet in UTXO set for blocks received out-of-order), skip the
        // coinbase value check here. Full validation happens in ConnectTip where the
        // UTXO set is guaranteed correct. This prevents rejecting valid blocks from peers.
        uint64_t totalFees = 0;
        CUTXOSet* utxoSet = g_utxo_set.load();
        bool feeCalcReliable = true;

        if (utxoSet && transactions.size() > 1) {
            // Calculate fees from non-coinbase transactions
            CTransactionValidator txValidator;
            for (size_t i = 1; i < transactions.size(); i++) {
                CAmount txFee = 0;
                std::string txError;
                if (txValidator.CheckTransactionInputs(*transactions[i], *utxoSet, blockHeight, txFee, txError)) {
                    if (txFee > 0) {
                        totalFees += static_cast<uint64_t>(txFee);
                    }
                } else {
                    // BUG #276: If any tx fee calc fails, we can't trust totalFees
                    feeCalcReliable = false;
                    std::cerr << "[ProcessNewBlock] Fee calc failed for tx " << i
                              << " at height " << blockHeight << ": " << txError << std::endl;
                }
            }
        } else if (!utxoSet && transactions.size() > 1) {
            // No UTXO set available — can't calculate fees
            feeCalcReliable = false;
        }

        // CheckCoinbase validates:
        // - Coinbase value doesn't exceed subsidy + fees
        // - Required Dev Fund and Dev Reward outputs are present with correct amounts
        // BUG #276: Only check coinbase value if fee calculation was reliable.
        // If fees couldn't be determined, defer full validation to ConnectTip.
        // Still check coinbase structure (format, MIK, dev tax) regardless.
        if (feeCalcReliable) {
            if (!validator.CheckCoinbase(*transactions[0], static_cast<uint32_t>(blockHeight), totalFees, validationError)) {
                std::cerr << "[ProcessNewBlock] ERROR: Coinbase validation failed: " << validationError << std::endl;
                SendRejectMessage(peer_id, "block", "Invalid coinbase: " + validationError);
                if (ctx.peer_manager) {
                    ctx.peer_manager->Misbehaving(peer_id, 100, MisbehaviorType::INVALID_COINBASE);  // Ban peer for invalid coinbase
                }
                g_metrics.RecordInvalidBlock();
                return BlockProcessResult::VALIDATION_ERROR;
            }
        } else {
            // BUG #276: Fee calc unreliable — still validate coinbase structure
            // Pass totalFees=UINT64_MAX/2 to skip value check but still validate format/tax
            std::string structError;
            uint64_t maxFees = std::numeric_limits<uint64_t>::max() / 2;
            if (!validator.CheckCoinbase(*transactions[0], static_cast<uint32_t>(blockHeight), maxFees, structError)) {
                // Only reject if it's a structural error (not value-based)
                if (structError.find("exceeds subsidy") == std::string::npos) {
                    std::cerr << "[ProcessNewBlock] ERROR: Coinbase structure invalid: " << structError << std::endl;
                    SendRejectMessage(peer_id, "block", "Invalid coinbase: " + structError);
                    if (ctx.peer_manager) {
                        ctx.peer_manager->Misbehaving(peer_id, 100, MisbehaviorType::INVALID_COINBASE);
                    }
                    g_metrics.RecordInvalidBlock();
                    return BlockProcessResult::VALIDATION_ERROR;
                }
            }
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Fee calc unreliable at height " << blockHeight
                          << " (txs=" << transactions.size() << ", utxo=" << (utxoSet ? "yes" : "no")
                          << ") — deferring coinbase value check to ConnectTip" << std::endl;
        }
    }

    // =========================================================================
    // PHASE 3: DUPLICATE/EXISTING BLOCK CHECKS
    // BUG #114, #150 fixes
    // =========================================================================
    CBlockIndex* pindex = g_chainstate.GetBlockIndex(blockHash);
    if (pindex && pindex->HaveData()) {
        // If this block was previously marked invalid by authoritative validation,
        // never retry activation. Retrying here can starve fresh block processing.
        if (pindex->IsInvalid()) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Block is permanently invalid, skipping activation"
                          << " height=" << pindex->nHeight
                          << " hash=" << blockHash.GetHex().substr(0, 16) << std::endl;
            tracker_guard.released = true;
            if (ctx.block_fetcher) {
                ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                ctx.block_fetcher->OnBlockReceived(peer_id, pindex->nHeight, blockHash);
            }
            return BlockProcessResult::VALIDATION_ERROR;
        }

        // Check if block is actually on main chain (BLOCK_VALID_CHAIN flag)
        if (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Block already in chain and connected, skipping"
                          << " height=" << pindex->nHeight << " hash=" << blockHash.GetHex().substr(0, 16)
                          << std::endl;
            // BUG #167 FIX: Use per-block tracking
            tracker_guard.released = true;
            if (ctx.block_fetcher) {
                ctx.block_fetcher->OnBlockReceived(peer_id, pindex->nHeight, blockHash);
            }
            return BlockProcessResult::ALREADY_HAVE;
        }

        // BUG #150 FIX: Block has data but is NOT connected - try to activate it
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[ProcessNewBlock] Block in chainstate but not connected, trying to activate"
                      << " height=" << pindex->nHeight << " hash=" << blockHash.GetHex().substr(0, 16)
                      << std::endl;

        // BUG #243 FIX: Ensure block data is saved to database before activation
        // HaveData() flag may be stale if block was deleted during fork recovery
        if (!db.BlockExists(blockHash)) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Block not in database - saving before activation" << std::endl;
            if (!db.WriteBlock(blockHash, block)) {
                std::cerr << "[ProcessNewBlock] ERROR: Failed to save block to database" << std::endl;
                return BlockProcessResult::DB_ERROR;
            }
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Block saved to database" << std::endl;
        }

        bool reorgOccurred = false;
        if (g_chainstate.ActivateBestChain(pindex, block, reorgOccurred)) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Successfully activated previously stuck block at height "
                          << pindex->nHeight << std::endl;
            tracker_guard.released = true;
            if (ctx.block_fetcher) {
                ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                ctx.block_fetcher->OnBlockReceived(peer_id, pindex->nHeight, blockHash);
            }
            // Sybil defense Phase 1: record which peer relayed this MIK's block
            if (ctx.peer_mik_tracker && peer_id >= 0 && !blockMikHex.empty()) {
                ctx.peer_mik_tracker->RecordMIKRelay(peer_id, blockMikHex);
            }
            return BlockProcessResult::ACCEPTED;
        } else {
            std::cerr << "[ProcessNewBlock] Failed to activate stuck block at height " << pindex->nHeight << std::endl;
            tracker_guard.released = true;
            if (ctx.block_fetcher) {
                ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                ctx.block_fetcher->OnBlockReceived(peer_id, pindex->nHeight, blockHash);
            }
            return BlockProcessResult::VALIDATION_ERROR;
        }
    }

    // Check if we already have this block in database
    bool blockInDb = db.BlockExists(blockHash);
    if (blockInDb) {
        // BUG #86 FIX: Mark block as received even when skipping
        tracker_guard.released = true;
        if (ctx.block_fetcher) {
            ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
        }

        // BUG #88 FIX: If block is in DB but NOT in chainstate, try to connect it
        if (!g_chainstate.HasBlockIndex(blockHash)) {
            CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
            if (pParent != nullptr) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BUG88-FIX] Block in DB but not chainstate, parent now available - connecting" << std::endl;
                // Don't return - fall through to create block index and connect
            } else {
                // BUG #149 FIX: Check if parent is on a competing fork
                int parent_height = -1;
                if (ctx.headers_manager) {
                    parent_height = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
                }

                // Rate-limited parent block request tracking (shared between fork paths)
                struct Uint256Hasher {
                    size_t operator()(const uint256& h) const {
                        return *reinterpret_cast<const size_t*>(h.data);
                    }
                };
                static std::unordered_map<uint256, std::chrono::steady_clock::time_point, Uint256Hasher> s_requested_parents;
                static std::mutex s_requested_mutex;

                // Request parent if missing from chainstate, regardless of whether
                // it's in the headers chain or not. Handles both:
                //   - parent_height <= 0: parent on a completely unknown fork
                //   - parent_height > 0 but not in chainstate: VDF divergence (#279)
                CBlockIndex* pParentCheck = g_chainstate.GetBlockIndex(block.hashPrevBlock);
                if (!pParentCheck && ctx.connman && ctx.message_processor) {
                    std::lock_guard<std::mutex> lock(s_requested_mutex);
                    auto now = std::chrono::steady_clock::now();
                    auto it = s_requested_parents.find(block.hashPrevBlock);

                    if (it == s_requested_parents.end() ||
                        std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() > 30) {
                        s_requested_parents[block.hashPrevBlock] = now;

                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[ProcessNewBlock] Parent " << block.hashPrevBlock.GetHex().substr(0, 16)
                                      << "... (height " << parent_height << ") NOT in chainstate"
                                      << " — requesting by hash from peer " << peer_id << std::endl;

                        std::vector<NetProtocol::CInv> getdata_inv;
                        getdata_inv.emplace_back(NetProtocol::MSG_BLOCK_INV, block.hashPrevBlock);
                        CNetMessage getdata_msg = ctx.message_processor->CreateGetDataMessage(getdata_inv);
                        ctx.connman->PushMessage(peer_id, getdata_msg);
                    }
                }

                // Diagnostic: why can't we find the parent?
                if (g_verbose.load(std::memory_order_relaxed)) {
                    std::cout << "[ProcessNewBlock] Block in DB but parent still missing"
                              << " prevBlock=" << block.hashPrevBlock.GetHex().substr(0, 16) << "..."
                              << " parentHeight=" << parent_height
                              << " chainTip=" << currentChainHeight << std::endl;
                    // Check what hash we actually have at the expected parent height
                    if (ctx.headers_manager && parent_height > 0) {
                        uint256 expected_parent = ctx.headers_manager->GetRandomXHashAtHeight(parent_height);
                        if (!expected_parent.IsNull() && expected_parent != block.hashPrevBlock) {
                            std::cout << "[ProcessNewBlock] FORK: prevBlock doesn't match header chain at height " << parent_height
                                      << " header=" << expected_parent.GetHex().substr(0, 16) << "..."
                                      << " block.prev=" << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                        }
                    }
                }
                // Notify IBD coordinator of orphan block for Layer 2 fork detection
                if (g_node_context.sync_coordinator) {
                    g_node_context.sync_coordinator->OnOrphanBlockReceived();
                }
                // ROOT CAUSE FIX: Mark height completed to prevent re-request loop.
                // Without this, MarkBlockReceived (line 559) clears the tracker entry,
                // and the next IBD tick re-requests the same orphan block every second.
                // MarkCompleted prevents GetNextBlocksToRequest from returning this
                // height. If a reorg makes the parent connectable, ClearAboveHeight
                // resets completed heights during fork recovery.
                if (g_node_context.block_tracker && parent_height > 0) {
                    g_node_context.block_tracker->MarkCompleted(parent_height + 1);
                }
                return BlockProcessResult::ORPHAN;
            }
        } else {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Block already in chainstate, skipping" << std::endl;
            return BlockProcessResult::ALREADY_HAVE;
        }
    }

    // =========================================================================
    // PHASE 4: DATABASE PERSISTENCE
    // =========================================================================
    if (!blockInDb && !db.WriteBlock(blockHash, block)) {
        std::cerr << "[ProcessNewBlock] ERROR: Failed to save block to database" << std::endl;
        return BlockProcessResult::DB_ERROR;
    }
    if (!blockInDb && g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[ProcessNewBlock] Block saved to database" << std::endl;
    }

    // =========================================================================
    // PHASE 5: BLOCK INDEX CREATION / ORPHAN HANDLING
    // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
    // =========================================================================
    auto pblockIndex = std::make_unique<CBlockIndex>(block);
    pblockIndex->phashBlock = blockHash;
    // v4.3.3 F14 (Layer-3 round 2 LOW-2): canonical block-receipt
    // flag-setter. Combines the F1 BLOCK_HAVE_DATA OR-merge with the F7
    // BLOCK_VALID_TRANSACTIONS validity-raise into ONE op. Mirrors
    // upstream Bitcoin Core's ReceivedBlockTransactions invariant
    // (validation.cpp:3774,3778). DO NOT split this back into open-coded
    // F1+F7 — the helper is the canonical contract.
    pblockIndex->MarkBlockReceived();



    // Link to parent block
    pblockIndex->pprev = g_chainstate.GetBlockIndex(block.hashPrevBlock);
    if (pblockIndex->pprev == nullptr) {
        // BUG #12 FIX (Phase 4.3): Orphan block handling
        if (g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[ProcessNewBlock] Parent block not found: " << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
            std::cout << "[ProcessNewBlock] Storing block as orphan and requesting parent" << std::endl;
        }

        // CRITICAL-3 FIX: Validate orphan block before storing
        CBlockValidator validator;
        std::vector<CTransactionRef> transactions;
        std::string validationError;

        // Deserialize and verify merkle root
        if (!validator.DeserializeBlockTransactions(block, transactions, validationError)) {
            std::cerr << "[Orphan] ERROR: Failed to deserialize orphan block transactions" << std::endl;
            std::cerr << "  Error: " << validationError << std::endl;
            SendRejectMessage(peer_id, "block", "Failed to deserialize block transactions");
            if (ctx.peer_manager) {
                ctx.peer_manager->Misbehaving(peer_id, 100, MisbehaviorType::PARSE_FAILURE);
            }
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        if (!validator.VerifyMerkleRoot(block, transactions, validationError)) {
            std::cerr << "[Orphan] ERROR: Orphan block has invalid merkle root" << std::endl;
            std::cerr << "  Error: " << validationError << std::endl;
            SendRejectMessage(peer_id, "block", "Invalid merkle root");
            if (ctx.peer_manager) {
                ctx.peer_manager->Misbehaving(peer_id, 100, MisbehaviorType::INVALID_MERKLE_ROOT);
            }
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        // Check for duplicate transactions
        if (!validator.CheckNoDuplicateTransactions(transactions, validationError)) {
            std::cerr << "[Orphan] ERROR: Orphan block contains duplicate transactions" << std::endl;
            SendRejectMessage(peer_id, "block", "Block contains duplicate transactions", REJECT_DUPLICATE);
            if (ctx.peer_manager) {
                ctx.peer_manager->Misbehaving(peer_id, 100, MisbehaviorType::DUPLICATE_TRANSACTIONS);
            }
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        // Check for double-spends within block
        if (!validator.CheckNoDoubleSpends(transactions, validationError)) {
            std::cerr << "[Orphan] ERROR: Orphan block contains double-spend" << std::endl;
            SendRejectMessage(peer_id, "block", "Block contains double-spend");
            if (ctx.peer_manager) {
                ctx.peer_manager->Misbehaving(peer_id, 100, MisbehaviorType::DOUBLE_SPEND_IN_BLOCK);
            }
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        // Add block to orphan manager (now validated)
        if (ctx.orphan_manager->AddOrphanBlock(peer_id, block)) {
            // BUG #262 FIX: Do NOT free CBlockTracker entry for orphan blocks.
            // Keep them tracked as "in-flight" to prevent re-request loops.
            // When parent arrives and orphan resolves via recursive ProcessNewBlock,
            // MarkBlockReceived is called in the acceptance path, clearing the tracker.
            tracker_guard.released = true;  // Prevent RAII guard from clearing

            // IBD OPTIMIZATION: Check if parent is already in-flight
            bool parent_in_flight = false;
            int parent_height = -1;
            if (ctx.headers_manager && ctx.block_tracker) {
                parent_height = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
                if (parent_height > 0) {
                    parent_in_flight = ctx.block_tracker->IsTracked(parent_height);
                }
            }

            if (parent_in_flight) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[ProcessNewBlock] Orphan block stored - parent height " << parent_height
                              << " already in-flight" << std::endl;
            } else if (parent_height <= 0) {
                // BUG #149 FIX: Parent is not in our header chain (competing fork)
                // Instead of requesting one block at a time (inefficient for deep forks),
                // request HEADERS to find common ancestor efficiently
                //
                // BUG #186 FIX: Only request headers if we're not already syncing.
                // During fork sync, every compact block triggers this code, but FAST PATH
                // is already requesting headers efficiently. Avoid redundant requests.
                //
                // BUG FIX: During IBD below checkpoints, orphan blocks with unknown
                // parents are EXPECTED (tip blocks arriving via compact relay while
                // we're catching up). Don't trigger fork detection below checkpoints.
                bool below_checkpoint = (currentChainHeight < checkpointHeight && blockHeight > checkpointHeight);
                if (below_checkpoint) {
                    // Normal IBD - parent unknown because we haven't synced past checkpoints yet
                } else if (ctx.headers_manager && !ctx.headers_manager->IsHeaderSyncInProgress()) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[ProcessNewBlock] Competing fork detected (parent "
                                  << block.hashPrevBlock.GetHex().substr(0, 16) << " unknown) - requesting headers" << std::endl;

                    // Track per-peer fork block relay for misbehavior scoring
                    if (peer_id >= 0) {
                        s_forkTracker.RecordForkBlock(peer_id, ctx);
                    }

                    // Use pure locator from our tip to find common ancestor
                    ctx.headers_manager->RequestHeaders(peer_id, uint256());  // null = use our tip's locator

                    // BUG #261 FIX: Only signal fork if node is synced
                    // During startup, blocks can arrive with "unknown" parents due to timing.
                    // This is normal startup behavior, not a real fork.
                    bool is_synced = g_node_context.sync_coordinator &&
                                     g_node_context.sync_coordinator->IsSynced();
                    if (is_synced) {
                        g_node_context.fork_detected.store(true);
                        g_metrics.SetForkDetected(true, 0, 0);
                    }
                } else {
                    // Header sync already in progress - skip redundant request
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[ProcessNewBlock] Fork header sync already in progress - skipping redundant request" << std::endl;
                }
            } else {
                // BUG #279 FIX: Parent hash is known in headers but NOT in chainstate.
                // This happens after VDF distribution tiebreak: the header chain references
                // a replacement block at the same height that we don't have. The IBD
                // coordinator tracks by height and already has a different block at that
                // height, so it will never request this specific hash. Fetch it directly.
                bool parent_in_chainstate = (g_chainstate.GetBlockIndex(block.hashPrevBlock) != nullptr);
                if (!parent_in_chainstate && peer_id >= 0 && ctx.block_fetcher && ctx.connman) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[ProcessNewBlock] Parent " << block.hashPrevBlock.GetHex().substr(0, 16)
                                  << "... (height " << parent_height << ") not in chainstate — requesting by hash from peer "
                                  << peer_id << std::endl;
                    if (ctx.block_fetcher->RequestBlockFromPeer(peer_id, parent_height, block.hashPrevBlock)) {
                        CNetMessage parent_msg = ctx.message_processor->CreateGetDataMessage(
                            {{NetProtocol::MSG_BLOCK_INV, block.hashPrevBlock}});
                        ctx.connman->PushMessage(peer_id, parent_msg);
                    }
                } else {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[ProcessNewBlock] Orphan block stored - IBD coordinator will handle block request" << std::endl;
                }
            }
        } else {
            std::cerr << "[Orphan] ERROR: Failed to add block to orphan pool" << std::endl;
        }

        // BUG #262 FIX: Do NOT clear orphan blocks from the tracker.
        // Previously (BUG #148), we called MarkBlockReceived here which cleared
        // the block from CBlockTracker. This caused a re-request loop:
        //   1. Blocks arrive out of order → stored as orphans → cleared from tracker
        //   2. GetNextBlocksToRequest sees untracked heights → re-requests them
        //   3. FetchBlocks "succeeds" (sends GETDATA) → stall counter never increments
        //   4. Peer may not re-send (already sent) → permanent stall
        // Fix: Keep orphan blocks tracked as "in-flight". They won't be re-requested.
        // When parent arrives and orphan resolves via recursive ProcessNewBlock,
        // MarkBlockReceived is called in the acceptance path, clearing the tracker.
        tracker_guard.released = true;  // Prevent RAII guard from clearing tracker

        // Also mark height as completed to survive the 15s in-flight timeout.
        // Without this, RetryTimeoutsAndStalls clears the entry after 15s and
        // the block gets re-requested, entering a 1/second loop via the blockInDb
        // path which unconditionally calls MarkBlockReceived.
        if (g_node_context.block_tracker && ctx.headers_manager) {
            int orphan_parent_h = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
            if (orphan_parent_h > 0) {
                g_node_context.block_tracker->MarkCompleted(orphan_parent_h + 1);
            }
        }

        // Notify IBD coordinator of orphan block for Layer 2 fork detection
        if (g_node_context.sync_coordinator) {
            g_node_context.sync_coordinator->OnOrphanBlockReceived();
        }

        return BlockProcessResult::ORPHAN;
    }

    // Calculate height and chain work
    pblockIndex->nHeight = pblockIndex->pprev->nHeight + 1;
    pblockIndex->BuildChainWork();

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[ProcessNewBlock] Block index created (height " << pblockIndex->nHeight << ")" << std::endl;

    // Save block index to database
    if (!db.WriteBlockIndex(blockHash, *pblockIndex)) {
        std::cerr << "[ProcessNewBlock] ERROR: Failed to save block index" << std::endl;
        return BlockProcessResult::DB_ERROR;
    }

    // Add to chain state memory map (transfer ownership with std::move)
    if (!g_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
        std::cerr << "[ProcessNewBlock] ERROR: Failed to add block to chain state" << std::endl;
        return BlockProcessResult::CHAINSTATE_ERROR;
    }

    // HIGH-C001 FIX: After move, retrieve pointer from chain state
    CBlockIndex* pblockIndexPtr = g_chainstate.GetBlockIndex(blockHash);
    if (pblockIndexPtr == nullptr) {
        std::cerr << "[ProcessNewBlock] CRITICAL ERROR: Block index not found after adding!" << std::endl;
        return BlockProcessResult::CHAINSTATE_ERROR;
    }

    // =========================================================================
    // PHASE 6: VALIDATION ROUTING (ASYNC VS SYNC)
    // =========================================================================
    bool useAsyncValidation = false;
    if (ctx.validation_queue && ctx.validation_queue->IsRunning()) {
        int header_height = ctx.headers_manager ?
            ctx.headers_manager->GetBestHeight() : currentChainHeight;
        int blocks_behind = header_height - currentChainHeight;

        // Use async validation if we're more than 10 blocks behind (active IBD)
        // FORK BLOCK FIX: Never use async validation for fork blocks
        // Fork blocks must go through Phase 7 for proper staging/activation
        useAsyncValidation = (blocks_behind > 10) && !isForkBlock;
    }

    if (useAsyncValidation) {
        // Queue for async validation - returns immediately
        int expected_height = pblockIndexPtr->nHeight;
        if (ctx.validation_queue->QueueBlock(peer_id, block, expected_height, blockHash, pblockIndexPtr)) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Block queued for async validation (height " << expected_height
                          << ", queue depth: " << ctx.validation_queue->GetQueueDepth() << ")" << std::endl;
            // IBD HANG FIX: Mark block as received IMMEDIATELY
            tracker_guard.released = true;
            ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
            ctx.block_fetcher->OnBlockReceived(peer_id, expected_height, blockHash);
            if (g_verbose.load(std::memory_order_relaxed)) {
                auto handler_end = std::chrono::steady_clock::now();
                auto handler_ms = std::chrono::duration_cast<std::chrono::milliseconds>(handler_end - handler_start).count();
                std::cout << "[ProcessNewBlock] EXIT (async) total=" << handler_ms << "ms" << std::endl;
            }
            return BlockProcessResult::ACCEPTED_ASYNC;
        } else {
            std::cerr << "[ProcessNewBlock] WARNING: Failed to queue block for async validation, falling back to sync" << std::endl;
            // Fall through to synchronous validation
        }
    }

    // =========================================================================
    // PHASE 7: SYNCHRONOUS BLOCK ACTIVATION + MINING UPDATE + RELAY
    // =========================================================================

    // FORK BLOCK HANDLING: Skip normal ActivateBestChain for fork blocks
    // Fork blocks are staged and only activated via TriggerChainSwitch when all are ready
    if (isForkBlock) {
        ForkManager& forkMgr = ForkManager::GetInstance();
        auto fork = forkMgr.GetActiveFork();

        if (fork) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Fork block stored with index, checking if ready to switch..." << std::endl;

            // ROBUST FIX: Switch when fork has more work, not when ALL blocks received
            // This prevents the race condition where fast blocks cause the fork to never complete
            bool allReceivedPrevalidated = fork->AllReceivedBlocksPrevalidated();
            int32_t highestPrevalidated = fork->GetHighestPrevalidatedHeight();

            // Get chainwork comparison - switch if fork has more work than current chain
            bool forkHasMoreWork = false;
            if (highestPrevalidated > 0) {
                // Get the block index for our highest prevalidated fork block
                ForkBlock* highestBlock = fork->GetBlockAtHeight(highestPrevalidated);
                if (highestBlock) {
                    CBlockIndex* forkIndex = g_chainstate.GetBlockIndex(highestBlock->hash);
                    CBlockIndex* currentTip = g_chainstate.GetTip();

                    if (forkIndex && currentTip) {
                        forkHasMoreWork = (currentTip->nChainWork < forkIndex->nChainWork);
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[ProcessNewBlock] Chainwork comparison: fork="
                                      << forkIndex->nChainWork.GetHex().substr(0, 16) << " current="
                                      << currentTip->nChainWork.GetHex().substr(0, 16)
                                      << " forkHasMore=" << (forkHasMoreWork ? "yes" : "no") << std::endl;
                    }
                }
            }

            // Switch if: all received blocks are prevalidated AND fork has more chainwork
            if (allReceivedPrevalidated && forkHasMoreWork) {
                if (g_verbose.load(std::memory_order_relaxed)) {
                    std::cout << "[ProcessNewBlock] Fork has more work and all received blocks prevalidated!" << std::endl;
                    std::cout << "[ProcessNewBlock] Triggering early chain switch (height " << highestPrevalidated << ")..." << std::endl;
                }

                // Trigger chain switch - this uses ActivateBestChain with the fork tip
                if (forkMgr.TriggerChainSwitch(ctx, db)) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[ProcessNewBlock] Fork chain switch SUCCESSFUL!" << std::endl;
                    g_node_context.fork_detected.store(false);
                    g_metrics.ClearForkDetected();

                    // FORK ORPHAN FIX: Sweep all blocks in the activated fork range.
                    // TriggerChainSwitch may have activated to a tip different from
                    // blockHash (it uses highestPrevalidatedHeight). Walk from new tip
                    // down to fork point so intermediate blocks' orphan children get resolved.
                    // The local `fork` shared_ptr is still valid after TriggerChainSwitch
                    // clears m_activeFork — the shared_ptr reference keeps it alive.
                    if (ctx.orphan_manager && fork) {
                        int32_t forkPoint = fork->GetForkPointHeight();
                        CBlockIndex* pSweep = g_chainstate.GetTip();
                        while (pSweep && pSweep->nHeight > forkPoint) {
                            ResolveOrphanChildren(pSweep->GetBlockHash(), ctx, db);
                            pSweep = pSweep->pprev;
                        }
                    }

                    // Mark block as received
                    tracker_guard.released = true;
                    if (ctx.block_fetcher) {
                        ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                        ctx.block_fetcher->OnBlockReceived(peer_id, pblockIndexPtr->nHeight, blockHash);
                    }

                    // Sybil defense Phase 1: record which peer relayed this MIK's block
                    if (ctx.peer_mik_tracker && peer_id >= 0 && !blockMikHex.empty()) {
                        ctx.peer_mik_tracker->RecordMIKRelay(peer_id, blockMikHex);
                    }

                    if (g_verbose.load(std::memory_order_relaxed)) {
                        auto handler_end = std::chrono::steady_clock::now();
                        auto handler_ms = std::chrono::duration_cast<std::chrono::milliseconds>(handler_end - handler_start).count();
                        std::cout << "[ProcessNewBlock] EXIT (fork switch) total=" << handler_ms << "ms" << std::endl;
                    }
                    return BlockProcessResult::ACCEPTED;
                } else {
                    std::cerr << "[ProcessNewBlock] Fork chain switch FAILED!" << std::endl;
                    // Fork manager already cleared state
                    return BlockProcessResult::VALIDATION_ERROR;
                }
            } else {
                // Not ready to switch yet
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[ProcessNewBlock] Fork block staged, waiting for more work..."
                              << " (stats: " << fork->GetStats() << ")"
                              << " allPrevalidated=" << (allReceivedPrevalidated ? "yes" : "no")
                              << " forkHasMoreWork=" << (forkHasMoreWork ? "yes" : "no") << std::endl;

                // FORK ORPHAN FIX: Resolve orphan children of this newly-indexed fork block.
                // Without this, out-of-order arrivals during fork recovery leave orphans
                // permanently stuck — no CBlockIndex, no chainwork, no switch.
                // Each resolved child cascades through ProcessNewBlock → fork staging →
                // its own ResolveOrphanChildren, building the full fork chain.
                ResolveOrphanChildren(blockHash, ctx, db);

                // Mark block as received
                tracker_guard.released = true;
                if (ctx.block_fetcher) {
                    ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                    ctx.block_fetcher->OnBlockReceived(peer_id, pblockIndexPtr->nHeight, blockHash);
                }

                if (g_verbose.load(std::memory_order_relaxed)) {
                    auto handler_end = std::chrono::steady_clock::now();
                    auto handler_ms = std::chrono::duration_cast<std::chrono::milliseconds>(handler_end - handler_start).count();
                    std::cout << "[ProcessNewBlock] EXIT (fork staging) total=" << handler_ms << "ms" << std::endl;
                }
                return BlockProcessResult::ACCEPTED_ASYNC;
            }
        }
    }

    // Normal block processing (non-fork blocks)
    if (g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[ProcessNewBlock] Calling ActivateBestChain synchronously..." << std::endl;
        std::cout.flush();
    }
    auto activate_start = std::chrono::steady_clock::now();
    int heightBeforeActivate = g_chainstate.GetHeight();
    bool reorgOccurred = false;
    if (g_chainstate.ActivateBestChain(pblockIndexPtr, block, reorgOccurred)) {
        if (g_verbose.load(std::memory_order_relaxed)) {
            auto activate_end = std::chrono::steady_clock::now();
            auto activate_ms = std::chrono::duration_cast<std::chrono::milliseconds>(activate_end - activate_start).count();
            std::cout << "[ProcessNewBlock] ActivateBestChain succeeded in " << activate_ms << "ms" << std::endl;
        }

        // A1 FIX: Notify IBD coordinator that a block connected successfully
        // Resets orphan streak counter (Layer 2 fork detection) and updates block-flow timestamp
        if (g_node_context.sync_coordinator) {
            g_node_context.sync_coordinator->OnBlockConnected();
        }

        if (reorgOccurred) {
            int heightAfterActivate = g_chainstate.GetHeight();
            bool isVdfTipSwap = (heightAfterActivate == heightBeforeActivate);

            if (isVdfTipSwap) {
                // VDF tip replacement (same height, lower VDF output won) — routine on VDF chains.
                // Only log at verbose level to avoid flooding the console.
                if (g_verbose.load(std::memory_order_relaxed)) {
                    std::cout << "[ProcessNewBlock] VDF tip replacement at height "
                              << heightAfterActivate << " -> "
                              << g_chainstate.GetTip()->GetBlockHash().GetHex().substr(0, 16)
                              << std::endl;
                }
            } else {
                std::cout << "[ProcessNewBlock] CHAIN REORGANIZATION occurred!" << std::endl;
                std::cout << "  New tip: " << g_chainstate.GetTip()->GetBlockHash().GetHex().substr(0, 16)
                          << " (height " << heightAfterActivate << ")" << std::endl;
            }
            g_metrics.RecordReorg();

            g_node_state.new_block_found = true;

            // BUG #32 FIX: Notify callback to update mining template when reorg occurs
            if (g_chain_tip_callback) {
                g_chain_tip_callback(db, g_chainstate.GetHeight(), true /* is_reorg */);
            }

            // VDF DISTRIBUTION RELAY FIX: Relay the block that just became tip via reorg.
            // Without this, VDF distribution winners are never propagated to peers.
            // Only relay when the arriving block IS the new tip (not deep reorgs
            // where the tip may be different from the submitted block).
            if (g_chainstate.GetTip() == pblockIndexPtr) {
                if (ctx.peer_manager && ctx.async_broadcaster) {
                    auto connected_peers = ctx.peer_manager->GetConnectedPeers();
                    std::vector<int> relay_peer_ids;
                    for (const auto& peer : connected_peers) {
                        if (peer && peer->IsHandshakeComplete() && peer->id != peer_id) {
                            relay_peer_ids.push_back(peer->id);
                        }
                    }
                    // Phase 4: Sort relay peers by trust score (highest first)
                    if (!relay_peer_ids.empty() && g_node_context.GetPeerTrustScore) {
                        int chainHeight = g_chainstate.GetHeight();
                        bool trustActive = Dilithion::g_chainParams &&
                            chainHeight >= Dilithion::g_chainParams->trustWeightedNetworkHeight;
                        if (trustActive) {
                            std::sort(relay_peer_ids.begin(), relay_peer_ids.end(),
                                [](int a, int b) {
                                    double ta = g_node_context.GetPeerTrustScore(a);
                                    double tb = g_node_context.GetPeerTrustScore(b);
                                    // Unknown (-1) treated as neutral (50.0)
                                    if (ta < 0) ta = 50.0;
                                    if (tb < 0) tb = 50.0;
                                    return ta > tb;  // Higher trust first
                                });
                        }
                    }

                    if (!relay_peer_ids.empty()) {
                        if (ctx.async_broadcaster->BroadcastBlock(blockHash, block, relay_peer_ids)) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[ProcessNewBlock] Relaying distribution-winning block to "
                                          << relay_peer_ids.size() << " peer(s)" << std::endl;
                        }
                    }
                }
            }
        } else {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ProcessNewBlock] Block activated successfully" << std::endl;
            g_metrics.blocks_accepted_total++;

            // Clear stale fork detection when active chain advances normally
            if (g_node_context.fork_detected.load()) {
                g_node_context.fork_detected.store(false);
                g_metrics.ClearForkDetected();
            }

            // Phase 2.2: Mark this block as received if it was a pending parent request
            if (ctx.orphan_manager) {
                ctx.orphan_manager->MarkParentReceived(blockHash);
            }

            // Check if this became the new tip
            if (g_chainstate.GetTip() == pblockIndexPtr) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[ProcessNewBlock] Updated best block to height " << pblockIndexPtr->nHeight << std::endl;
                g_node_state.new_block_found = true;

                // BUG #32 FIX: Notify callback to update mining template
                if (g_chain_tip_callback) {
                    g_chain_tip_callback(db, pblockIndexPtr->nHeight, false /* is_reorg */);
                }

                // BUG #43 FIX: Relay received blocks to other peers (Bitcoin Core standard)
                if (ctx.peer_manager && ctx.async_broadcaster) {
                    auto connected_peers = ctx.peer_manager->GetConnectedPeers();
                    std::vector<int> relay_peer_ids;

                    for (const auto& peer : connected_peers) {
                        if (peer && peer->IsHandshakeComplete() && peer->id != peer_id) {
                            relay_peer_ids.push_back(peer->id);
                        }
                    }

                    // Phase 4: Sort relay peers by trust score (highest first)
                    if (!relay_peer_ids.empty() && g_node_context.GetPeerTrustScore) {
                        int chainHeight = g_chainstate.GetHeight();
                        bool trustActive = Dilithion::g_chainParams &&
                            chainHeight >= Dilithion::g_chainParams->trustWeightedNetworkHeight;
                        if (trustActive) {
                            std::sort(relay_peer_ids.begin(), relay_peer_ids.end(),
                                [](int a, int b) {
                                    double ta = g_node_context.GetPeerTrustScore(a);
                                    double tb = g_node_context.GetPeerTrustScore(b);
                                    // Unknown (-1) treated as neutral (50.0)
                                    if (ta < 0) ta = 50.0;
                                    if (tb < 0) tb = 50.0;
                                    return ta > tb;  // Higher trust first
                                });
                        }
                    }

                    if (!relay_peer_ids.empty()) {
                        if (ctx.async_broadcaster->BroadcastBlock(blockHash, block, relay_peer_ids)) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[ProcessNewBlock] Relaying block to " << relay_peer_ids.size()
                                          << " peer(s) (excluding sender peer " << peer_id << ")" << std::endl;
                        } else {
                            std::cerr << "[ProcessNewBlock] ERROR: Failed to queue block relay" << std::endl;
                        }
                    }
                }
            } else {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[ProcessNewBlock] Block is valid but not on best chain" << std::endl;
            }
        }

        // Process orphan children after successful block activation.
        // Unified via ResolveOrphanChildren helper (same logic used in fork path).
        ResolveOrphanChildren(blockHash, ctx, db);

        // Notify BlockFetcher
        tracker_guard.released = true;
        if (ctx.block_fetcher) {
            ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
            ctx.block_fetcher->OnBlockReceived(peer_id, pblockIndexPtr->nHeight, blockHash);
        }

        // Sybil defense Phase 1: record which peer relayed this MIK's block
        if (ctx.peer_mik_tracker && peer_id >= 0 && !blockMikHex.empty()) {
            ctx.peer_mik_tracker->RecordMIKRelay(peer_id, blockMikHex);
        }

        return BlockProcessResult::ACCEPTED;
    } else {
        std::cerr << "[ProcessNewBlock] ERROR: Failed to activate block in chain" << std::endl;
        return BlockProcessResult::VALIDATION_ERROR;
    }
}
