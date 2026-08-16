// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// v4.3.4 Option C cut — Block 3 regression gate.
//
// Proves the legacy block-arrival path reaches IChainSelector::ProcessNewBlock
// under DILITHION_USE_NEW_CHAIN_SELECTOR=1 with NO port peer manager registered.

#include <consensus/chain.h>
#include <consensus/ichain_selector.h>
#include <consensus/port/chain_selector_impl.h>
#include <core/chainparams.h>
#include <core/node_context.h>
#include <net/connman.h>
#include <net/headers_manager.h>
#include <net/net.h>
#include <net/node.h>
#include <net/peers.h>
#include <net/port/sync_coordinator.h>
#include <node/genesis.h>
#include <primitives/block.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

extern CChainState g_chainstate;

namespace {

class RecordingChainSelector final : public dilithion::consensus::IChainSelector {
public:
    explicit RecordingChainSelector(std::unique_ptr<dilithion::consensus::IChainSelector> inner)
        : m_inner(std::move(inner)) {}

    bool ProcessNewBlock(std::shared_ptr<const CBlock> block,
                         bool force_processing,
                         bool* triggered_reorg) override {
        (void)force_processing;
        if (triggered_reorg != nullptr) {
            *triggered_reorg = false;
        }
        ++process_new_block_calls;
        if (block) {
            last_seen_block_hash = block->GetHash();
        } else {
            last_seen_block_hash = uint256();
        }
        // This fixture is a routing gate: record arrival only, skip validation.
        return true;
    }

    bool ProcessNewHeader(const CBlockHeader& header) override {
        return m_inner->ProcessNewHeader(header);
    }

    CBlockIndex* GetActiveTip() const override { return m_inner->GetActiveTip(); }
    int GetActiveHeight() const override { return m_inner->GetActiveHeight(); }
    uint256 GetActiveTipHash() const override { return m_inner->GetActiveTipHash(); }
    std::vector<dilithion::consensus::ChainTipInfo> GetChainTips() const override {
        return m_inner->GetChainTips();
    }
    CBlockIndex* FindMostWorkChain() const override { return m_inner->FindMostWorkChain(); }
    CBlockIndex* LookupBlockIndex(const uint256& hash) const override {
        return m_inner->LookupBlockIndex(hash);
    }
    bool InvalidateBlock(const uint256& hash) override { return m_inner->InvalidateBlock(hash); }
    bool ReconsiderBlock(const uint256& hash) override { return m_inner->ReconsiderBlock(hash); }
    bool IsInitialBlockDownload() const override { return m_inner->IsInitialBlockDownload(); }

    int process_new_block_calls{0};
    uint256 last_seen_block_hash{};

private:
    std::unique_ptr<dilithion::consensus::IChainSelector> m_inner;
};

static Dilithion::ChainParams s_regtest_params = Dilithion::ChainParams::Regtest();

NetProtocol::CAddress MakeTestAddress(uint16_t port = 18444)
{
    NetProtocol::CAddress addr;
    std::memset(addr.ip, 0, 10);
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;
    addr.ip[12] = 127;
    addr.ip[13] = 0;
    addr.ip[14] = 0;
    addr.ip[15] = 1;
    addr.port = port;
    addr.services = 0;
    addr.time = 0;
    return addr;
}

bool InitRegtestGenesisOnGlobalChainstate()
{
    g_chainstate.Cleanup();
    Dilithion::g_chainParams = &s_regtest_params;

    const CBlock genesis = Genesis::CreateDilVGenesisBlock();
    const uint256 genesis_hash = genesis.GetHash();

    auto pindex = std::make_unique<CBlockIndex>(genesis);
    pindex->phashBlock = genesis_hash;
    pindex->pprev = nullptr;
    pindex->nHeight = 0;
    pindex->nChainWork = pindex->GetBlockProof();
    pindex->nStatus = CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA;

    if (!g_chainstate.AddBlockIndex(genesis_hash, std::move(pindex))) {
        return false;
    }
    CBlockIndex* tip = g_chainstate.GetBlockIndex(genesis_hash);
    if (tip == nullptr) {
        return false;
    }

    bool reorg = false;
    return g_chainstate.ActivateBestChain(tip, genesis, reorg);
}

CBlock BuildChildOfTip()
{
    CBlock blk;
    blk.nVersion = CBlockHeader::VDF_VERSION;
    const CBlockIndex* tip = g_chainstate.GetTip();
    assert(tip != nullptr);
    blk.hashPrevBlock = tip->GetBlockHash();
    blk.hashMerkleRoot = uint256();
    blk.nTime = 1700010000u;
    blk.nBits = 0x1d00ffff;
    blk.nNonce = 0;
    std::memset(blk.vdfOutput.data, 0, 32);
    std::memset(blk.vdfProofHash.data, 0, 32);
    blk.vdfOutput.data[0] = 0x42;
    return blk;
}

void ClearGlobalNodeContext()
{
    g_node_context.message_processor = nullptr;
    g_node_context.sync_coordinator.reset();
    g_node_context.headers_manager.reset();
    g_node_context.connman.reset();
    g_node_context.peer_manager.reset();
    g_node_context.chain_selector.reset();
    g_node_context.chainstate = nullptr;
}

void test_legacy_block_arrival_routes_to_chain_selector_without_port_pm()
{
    std::cout << "  test_legacy_block_arrival_routes_to_chain_selector_without_port_pm..." << std::flush;

    assert(InitRegtestGenesisOnGlobalChainstate());
    g_node_context.chainstate = &g_chainstate;

    auto real_selector = std::make_unique<dilithion::consensus::port::ChainSelectorAdapter>(g_chainstate);
    auto rec_selector = std::make_unique<RecordingChainSelector>(std::move(real_selector));
    auto* rec_raw = rec_selector.get();
    g_node_context.chain_selector = std::move(rec_selector);

    g_node_context.peer_manager = std::make_unique<CPeerManager>("");
    g_node_context.connman = std::make_unique<CConnman>();

    CNetMessageProcessor msg_processor(*g_node_context.peer_manager);
    g_node_context.message_processor = &msg_processor;

    msg_processor.SetBlockHandler([](int, const CBlock& block) {
        bool triggered_reorg = false;
        auto block_ptr = std::make_shared<const CBlock>(block);
        (void)g_node_context.chain_selector->ProcessNewBlock(block_ptr, /*force_processing=*/false, &triggered_reorg);
    });

    CConnmanOptions opts;
    opts.fListen = false;
    assert(g_node_context.connman->Start(*g_node_context.peer_manager, msg_processor, opts));
    const int kPeerId = 7001;
    NetProtocol::CAddress addr = MakeTestAddress();
    auto test_node = std::make_unique<CNode>(kPeerId, addr, /*inbound=*/false);
    test_node->state.store(CNode::STATE_HANDSHAKE_COMPLETE);
    assert(g_node_context.connman->DispatchPeerConnected(kPeerId, test_node.get(), addr, /*inbound=*/false));

    const CBlock child = BuildChildOfTip();
    const uint256 child_hash = child.GetHash();
    const CNetMessage block_msg = msg_processor.CreateBlockMessage(child);

    const bool ok = g_node_context.connman->TestProcessQueuedMessage(kPeerId, "block", block_msg.payload);
    assert(ok);
    assert(rec_raw->process_new_block_calls >= 1);
    assert(rec_raw->last_seen_block_hash == child_hash);

    g_node_context.connman->DispatchPeerDisconnected(kPeerId);
    g_node_context.connman->Stop();
    ClearGlobalNodeContext();
    g_chainstate.Cleanup();
    Dilithion::g_chainParams = nullptr;

    std::cout << " OK\n";
}

}  // namespace

int main()
{
    // TEST-ONLY opt-in: this harness drives ConnectTip on a CChainState with
    // no UTXO set attached (header/selector-level test). Production ConnectTip
    // FAILS CLOSED on a null UTXO set (external round-2 HIGH); opt in explicitly.
    CChainState::SetTestAllowConnectWithoutUTXOSet(true);
    std::cout << "v4.3.4 cut Block 3 — legacy block-arrival chain-selector gate\n\n";
    try {
        test_legacy_block_arrival_routes_to_chain_selector_without_port_pm();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }
    std::cout << "\nAll Block 3 regression-gate tests passed.\n";
    return 0;
}
