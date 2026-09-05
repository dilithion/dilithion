// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <core/node_context.h>
#include <net/peers.h>
#include <net/connman.h>  // Phase 2: For CConnman destructor
#include <net/headers_manager.h>
#include <net/orphan_manager.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>  // IBD Redesign: Single source of truth
#include <net/blockencodings.h>  // BIP 152: For PartiallyDownloadedBlock destructor
#include <node/block_validation_queue.h>  // Phase 2: Async block validation
#include <digital_dna/dna_registry_db.h>  // Digital DNA: LevelDB-backed registry
#include <digital_dna/verification_manager.h>  // Phase 2: DNA Verification & Attestation
#include <consensus/ichain_selector.h>             // Phase 5: frozen interface
#include <consensus/port/chain_selector_impl.h>    // Phase 5: ChainSelectorAdapter
#include <node/fork_manager.h>                     // Phase 11 A1: ForkManager wiring
#include <net/port/sync_coordinator.h>             // Phase 6 PR6.5a: ISyncCoordinator complete type for unique_ptr destructor
#include <util/logging.h>

#include <cstdlib>  // std::getenv
#include <cstring>  // std::strcmp

// Global node context instance
NodeContext g_node_context;

// Destructor defined here (not in header) because unique_ptr<DNARegistryDB>
// requires the complete type for default_delete.
NodeContext::~NodeContext() = default;

// DNA collector stored in a separate global to avoid memory stomp from NodeContext fields.
// Something in the NodeContext layout overwrites byte 4 of the shared_ptr's internal pointer
// when stored as a member. Isolating it here eliminates that corruption.
static std::shared_ptr<digital_dna::DigitalDNACollector> g_dna_collector;
static std::mutex g_cs_dna_collector;

std::shared_ptr<digital_dna::DigitalDNACollector> NodeContext::GetDNACollector() const {
    std::lock_guard<std::mutex> lock(g_cs_dna_collector);
    return g_dna_collector;
}

void NodeContext::SetDNACollector(std::shared_ptr<digital_dna::DigitalDNACollector> new_collector) {
    std::lock_guard<std::mutex> lock(g_cs_dna_collector);
    g_dna_collector = std::move(new_collector);
}

bool NodeContext::Init(const std::string& datadir, CChainState* chainstate_ptr) {
    if (IsInitialized()) {
        LogPrintf(ALL, WARN, "NodeContext already initialized");
        return false;
    }

    if (!chainstate_ptr) {
        LogPrintf(ALL, ERROR, "NodeContext::Init: chainstate_ptr is null");
        return false;
    }

    chainstate = chainstate_ptr;

    // Phase 5: instantiate chain selector adapter over the chainstate.
    // The adapter is a thin wrapper; lifetime is tied to NodeContext
    // and MUST be reset before chainstate is freed (handled in Shutdown/Reset).
    //
    // v4.1 IBD silent-drop construction gate (RETAINED in v4.3 as operator
    // opt-in). The underlying AddBlockIndex flag-merge bug is fixed by
    // Phase 11 ABI (commit 3a0c2ea above), but we keep this gate to preserve
    // operator control per Phase 5 PR5.4 partition-risk lesson and the v4.3
    // emergency deploy review. Setting DILITHION_USE_NEW_CHAIN_SELECTOR=1
    // is the operator's explicit opt-in to engage the new chain-selection
    // logic AND the Phase 11 A1 fork-staging adapter.
    //
    // The 6 ProcessNewHeader call sites in headers_manager.cpp and the 2
    // use_port_pm gates in dilithion-node.cpp / dilv-node.cpp already
    // null-check chain_selector. NodeContext::WireForkStaging() (called by
    // node startup once blockchain_db is set) is null-safe — it's a no-op
    // when chain_selector is nullptr (env-var unset).
    //
    // Activation: wrapper /root/run-dilv-seed.sh exports
    // DILITHION_USE_NEW_CHAIN_SELECTOR=1 to enable the port chain selector.
    // The companion --usenewpeerman flag was retired in v4.3.4 (Block 8 of
    // Option C cut) — the chain-selector env-var is now an independent toggle.
    // Without the env-var, chain_selector stays null and the legacy
    // chain.cpp validation path runs (fail-loud).
    try {
        const char* selector_env = std::getenv("DILITHION_USE_NEW_CHAIN_SELECTOR");
        const bool use_new_selector = (selector_env != nullptr) && (std::strcmp(selector_env, "1") == 0);
        if (use_new_selector) {
            chain_selector = std::make_unique<::dilithion::consensus::port::ChainSelectorAdapter>(*chainstate);
            LogPrintf(ALL, INFO, "v4.3: chain selector adapter wired (env-var=1, opt-in; A1 fork-staging deferred until WireForkStaging)");
        } else {
            chain_selector = nullptr;
            LogPrintf(ALL, INFO,
                "v4.3: chain selector adapter SUPPRESSED (default; set "
                "DILITHION_USE_NEW_CHAIN_SELECTOR=1 to engage new path)");
        }
    } catch (const std::exception& e) {
        LogPrintf(ALL, ERROR, "Failed to instantiate chain selector adapter: %s", e.what());
        return false;
    }

    // Initialize peer manager
    try {
        peer_manager = std::make_unique<CPeerManager>(datadir);
        LogPrintf(NET, INFO, "Initialized peer manager");
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "Failed to initialize peer manager: %s", e.what());
        return false;
    }

    // Initialize IBD managers
    try {
        headers_manager = std::make_unique<CHeadersManager>();
        orphan_manager = std::make_unique<COrphanManager>();
        block_fetcher = std::make_unique<CBlockFetcher>(peer_manager.get());
        block_tracker = std::make_unique<CBlockTracker>();  // IBD Redesign: Single source of truth
        LogPrintf(IBD, INFO, "Initialized IBD managers (headers, orphan, block_fetcher, block_tracker)");

        // BUG #125: Start async header validation thread
        if (headers_manager && !headers_manager->StartValidationThread()) {
            LogPrintf(IBD, WARN, "Failed to start header validation thread");
            // Non-fatal - will fall back to sync validation
        }
    } catch (const std::exception& e) {
        LogPrintf(IBD, ERROR, "Failed to initialize IBD managers: %s", e.what());
        return false;
    }

    // Initialize Digital DNA registry (LevelDB-backed)
    try {
        dna_registry = std::make_unique<digital_dna::DNARegistryDB>();
        std::string dna_path = datadir + "/dna_registry";
        if (dna_registry->Open(dna_path)) {
            LogPrintf(ALL, INFO, "DNA registry opened (%zu identities) at %s",
                      dna_registry->count(), dna_path.c_str());
            // DNA registration is ADVISORY-ONLY (flag-and-store, never reject) per the
            // 2026-06-12 DNA review. Score-based similarity rejection false-positives
            // honest co-located miners (same datacenter / VPS SKU), AND dropping rejected
            // identities blinds the clustering tripwire DNA is meant to feed. The
            // Phase-2A rejection code path (DNARegistryDB::register_identity ->
            // SYBIL_REJECTED when is_same_identity()) is RETAINED but DISABLED here; it is
            // to be re-armed only via a deliberate Will/Zach decision.
            dna_registry->SetEnforceDNADedup(false);
        } else {
            LogPrintf(ALL, WARN, "Failed to open DNA registry at %s", dna_path.c_str());
            dna_registry.reset();  // Non-fatal, DNA is advisory
        }
    } catch (const std::exception& e) {
        LogPrintf(ALL, ERROR, "Failed to initialize Digital DNA registry: %s", e.what());
        dna_registry.reset();  // Non-fatal
    }

    // Initialize trust score manager
    try {
        trust_manager = std::make_unique<digital_dna::TrustScoreManager>();
        std::string trust_path = datadir + "/dna_trust";
        if (trust_manager->load(trust_path)) {
            LogPrintf(ALL, INFO, "Trust scores loaded (%zu identities) from %s",
                      trust_manager->count(), trust_path.c_str());
        } else {
            LogPrintf(ALL, INFO, "No existing trust scores at %s (fresh start)",
                      trust_path.c_str());
        }
    } catch (const std::exception& e) {
        LogPrintf(ALL, ERROR, "Failed to initialize trust score manager: %s", e.what());
        trust_manager.reset();  // Non-fatal
    }

    // Initialize DNA verification manager (Phase 2: peer verification & attestation)
    if (dna_registry && trust_manager) {
        try {
            verification_manager = std::make_unique<digital_dna::verification::VerificationManager>(
                dna_registry.get(), trust_manager.get());
            LogPrintf(ALL, INFO, "DNA verification manager initialized");
        } catch (const std::exception& e) {
            LogPrintf(ALL, ERROR, "Failed to initialize verification manager: %s", e.what());
            verification_manager.reset();  // Non-fatal
        }
    }

    // Initialize state flags
    running = false;
    new_block_found = false;
    mining_enabled = false;

    LogPrintf(ALL, INFO, "NodeContext initialized successfully");
    return true;
}

bool NodeContext::WireForkStaging() {
    // Phase 11 A1: rebuild the chain selector adapter with the ForkManager
    // singleton + blockchain_db wired in, enabling fork-staging dispatch
    // on ProcessNewBlock. Idempotent — calling twice with the same db is
    // safe (we just reconstruct the adapter, which is a thin wrapper).
    //
    // v4.3 conflict-resolution: respect the v4.1 IBD silent-drop construction
    // gate retained at NodeContext::Init. If chain_selector was suppressed
    // there (env-var unset → chain_selector == nullptr), the operator did NOT
    // opt in to the new path; do NOT silently construct a staging-enabled
    // adapter here. Stay null. The 6 ProcessNewHeader / 2 use_port_pm null
    // checks downstream rely on this.
    if (!chain_selector) {
        LogPrintf(ALL, INFO,
                  "WireForkStaging: chain_selector was suppressed at Init "
                  "(DILITHION_USE_NEW_CHAIN_SELECTOR != 1); fork-staging stays disabled");
        return true;  // Not an error — operator opted out via env-var.
    }
    if (!chainstate || !blockchain_db) {
        LogPrintf(ALL, WARN,
                  "WireForkStaging: prerequisites not ready (chainstate=%s, blockchain_db=%s); "
                  "fork-staging stays in Phase-5 mode",
                  chainstate ? "ok" : "null",
                  blockchain_db ? "ok" : "null");
        return false;
    }

    try {
        // Reset BEFORE constructing the new adapter — both reference the same
        // CChainState&, but the unique_ptr swap is atomic enough for our
        // single-threaded startup invocation. NodeContext::WireForkStaging is
        // called from the main thread before any block-receive thread starts,
        // so no concurrent chain_selector access is possible during the swap.
        chain_selector.reset();
        chain_selector = std::make_unique<::dilithion::consensus::port::ChainSelectorAdapter>(
            *chainstate,
            &ForkManager::GetInstance(),
            blockchain_db);
        LogPrintf(ALL, INFO, "Phase 11 A1: chain selector adapter re-wired with fork-staging dispatch");
        return true;
    } catch (const std::exception& e) {
        LogPrintf(ALL, ERROR, "WireForkStaging failed: %s", e.what());
        return false;
    }
}

void NodeContext::Shutdown() {
    LogPrintf(ALL, INFO, "Shutting down NodeContext...");

    // Stop services first
    running = false;

    // Shutdown components in reverse order of initialization
    if (async_broadcaster) {
        // Async broadcaster cleanup handled by its destructor
        async_broadcaster = nullptr;
    }


    // Phase 2: Stop CConnman
    if (connman) {
        connman->Stop();
        connman.reset();
    }

    if (message_processor) {
        message_processor = nullptr;
    }

    // Phase 2: Stop validation queue before IBD managers
    if (validation_queue) {
        validation_queue->Stop();
        validation_queue.reset();
    }

    // Reset IBD managers (unique_ptr will handle cleanup)
    block_tracker.reset();  // IBD Redesign
    block_fetcher.reset();
    orphan_manager.reset();

    // BUG #125: Stop validation thread before destroying headers_manager
    if (headers_manager) {
        headers_manager->StopValidationThread();
    }
    headers_manager.reset();

    // Reset peer manager (unique_ptr will handle cleanup)
    peer_manager.reset();

    // Phase 2: Reset verification manager before trust/registry
    verification_manager.reset();

    // Digital DNA: Reset trust manager (caller saves before Shutdown)
    trust_manager.reset();
    if (dna_registry) {
        dna_registry->Close();
        dna_registry.reset();
    }
    SetDNACollector(nullptr);

    // Phase 5: reset chain selector BEFORE clearing chainstate (adapter
    // holds a non-owning reference into chainstate).
    chain_selector.reset();

    // Clear pointers
    chainstate = nullptr;
    rpc_server = nullptr;
    miner = nullptr;
    wallet = nullptr;
    p2p_socket = nullptr;
    http_server = nullptr;

    LogPrintf(ALL, INFO, "NodeContext shutdown complete");
}

void NodeContext::Reset() {
    // Phase 5: reset selector BEFORE clearing chainstate.
    chain_selector.reset();
    chainstate = nullptr;
    peer_manager.reset();
    connman.reset();  // Phase 2: Reset CConnman
    message_processor = nullptr;
    headers_manager.reset();
    orphan_manager.reset();
    block_fetcher.reset();
    block_tracker.reset();  // IBD Redesign
    validation_queue.reset();  // Phase 2: Reset validation queue
    dna_registry.reset();  // Digital DNA
    trust_manager.reset();
    verification_manager.reset();  // Phase 2
    SetDNACollector(nullptr);
    async_broadcaster = nullptr;
    rpc_server = nullptr;
    miner = nullptr;
    wallet = nullptr;
    p2p_socket = nullptr;
    http_server = nullptr;
    running = false;
    new_block_found = false;
    mining_enabled = false;
}

