// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_MINER_VDF_MINER_H
#define DILITHION_MINER_VDF_MINER_H

#include <miner/controller.h>  // CBlockTemplate
#include <vdf/vdf.h>
#include <vdf/cooldown_tracker.h>
#include <consensus/vdf_validation.h>
#include <primitives/block.h>
#include <uint256.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <mutex>
#include <functional>
#include <condition_variable>
#include <array>
#include <utility>

/**
 * VDF Mining Controller
 *
 * Replaces RandomX nonce-grinding with single-threaded VDF computation.
 * Each round:
 *   1. Wait for new block (epoch change)
 *   2. Check cooldown — skip if miner recently won
 *   3. Compute VDF challenge from prevHash + height + minerAddress
 *   4. Run vdf::compute() (~200s on reference hardware)
 *   5. Build VDF block (version 4) with proof in coinbase
 *   6. Submit via callback
 *
 * Key differences from CMiningController:
 *   - Single thread (VDF is inherently sequential)
 *   - Deterministic duration (no nonce brute-force)
 *   - Epoch-aware: aborts computation if a new block arrives
 */
class CVDFMiner {
public:
    using Address = std::array<uint8_t, 20>;
    // ⚠️ THESE THREE CALLBACKS RUN ON THE MINER THREAD, AND THEY MUST NOT BLOCK
    // (round-8 F53). MiningLoop is a registered epoch participant: it publishes an
    // epoch at its loop top, and every one of these is invoked with that epoch
    // live. A callback that waits on a condition variable, sleeps, or performs
    // blocking I/O therefore freezes DrainGraveyard's minimum for its whole
    // duration -- the same defect the eight waits in MiningLoop itself carried
    // (F46), arriving through an injected std::function instead.
    //
    // ⚠️ AND NO CHECKER SEES IT. scripts/check_participant_waits.sh follows ONE HOP
    // from a checkpointing function; an injected callable is not a call it can
    // resolve, so these escape it by construction. The contract is written here
    // because the machine cannot hold it -- which is exactly the situation where a
    // comment IS the mechanism and has to say so.
    //
    // If a callback must block, it takes an EpochOfflineScope around the blocking
    // part itself -- it must NOT be wrapped at the injection site, because the
    // scope has to bracket the wait and nothing else.
    using BlockFoundCallback = std::function<void(const CBlock&)>;
    using TemplateProvider = std::function<std::optional<CBlockTemplate>()>;

    CVDFMiner();
    ~CVDFMiner();

    // Non-copyable
    CVDFMiner(const CVDFMiner&) = delete;
    CVDFMiner& operator=(const CVDFMiner&) = delete;

    /**
     * Start VDF mining.
     * Launches a single background thread that loops:
     *   get template → compute VDF → submit block.
     */
    void Start();

    /**
     * Stop VDF mining and wait for thread to join.
     */
    void Stop();

    /**
     * Signal that a new block has arrived.
     * VDF Distribution: If the new block is at the SAME height we're computing for,
     * don't abort — our output may be lower and win the distribution.
     * If at a different height, abort and restart on the new epoch.
     *
     * @param newTipHeight Height of the new chain tip (-1 = always abort)
     */
    void OnNewBlock(int newTipHeight = -1);

    /**
     * Check if VDF miner is running.
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Set callback invoked when a valid VDF block is produced.
     * Same safety requirements as CMiningController::SetBlockFoundCallback.
     */
    void SetBlockFoundCallback(BlockFoundCallback cb);

    /**
     * Set the function that provides fresh block templates.
     * Called at the start of each VDF round to get the current chain tip data.
     * The template should include coinbase with miner's payout address.
     */
    void SetTemplateProvider(TemplateProvider provider);

    /**
     * Set the miner's payout address (20-byte pubkey hash).
     */
    void SetMinerAddress(const Address& addr);

    /**
     * Set the miner's MIK identity (20-byte MIK hash).
     * Used for cooldown tracking instead of payout address to prevent
     * address rotation bypass.
     */
    void SetMIKIdentity(const Address& mikId);

    /**
     * Set the VDF iteration count (from chainparams).
     */
    void SetIterations(uint64_t iterations);

    /**
     * Set the cooldown tracker (optional).
     * If set, the miner will skip rounds when in cooldown.
     */
    void SetCooldownTracker(CCooldownTracker* tracker);

    /**
     * Set minimum block time from chainparams.
     * Miners wait this many seconds after a height change before starting next VDF.
     */
    void SetMinBlockTime(int seconds);

    /**
     * VDF Distribution: Set provider for current tip's VDF output.
     * Used for pre-submission comparison — miner checks if its output is
     * lower than the current tip before submitting (optimization to avoid
     * unnecessary block construction + relay).
     */
    using TipOutputProvider = std::function<std::pair<int, uint256>()>;
    void SetTipOutputProvider(TipOutputProvider provider);

    /**
     * Get the number of VDF blocks found.
     */
    uint64_t GetBlocksFound() const { return m_blocksFound.load(); }

    /**
     * Get the height currently being computed for (0 if idle).
     */
    uint32_t GetCurrentHeight() const { return m_currentHeight.load(); }

    /**
     * Finalize a VDF block: embed proof in coinbase, set header fields,
     * recompute merkle root.
     *
     * Takes a block from BuildMiningTemplate (version 1, no VDF fields)
     * and transforms it into a valid VDF block (version 4).
     *
     * @param block       Block from template (version will be set to 4)
     * @param result      VDF computation result (output + proof)
     * @param minerAddr   Miner's 20-byte payout address
     * @param height      Block height (for coinbase scriptSig)
     * @return true if finalization succeeded
     */
    bool FinalizeVDFBlock(CBlock& block, const vdf::VDFResult& result,
                          const Address& minerAddr, uint32_t height);

private:
    /**
     * Main mining loop (runs in m_thread).
     */
    void MiningLoop();

    // Thread and state
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_abort{false};  // Abort current VDF computation

    // Epoch tracking
    std::atomic<uint32_t> m_currentHeight{0};
    std::mutex m_epochMutex;
    std::condition_variable m_epochCV;
    bool m_epochChanged{false};

    // Configuration
    Address m_minerAddress{};
    Address m_mikIdentity{};   // MIK identity for cooldown (0 = use m_minerAddress)
    uint64_t m_iterations{200'000'000};
    CCooldownTracker* m_cooldownTracker{nullptr};

    // Minimum block time enforcement
    int m_minBlockTimeSec{0};                              // 0 = disabled
    std::chrono::steady_clock::time_point m_lastHeightChangeTime{};
    bool m_firstRound{true};  // Skip wait on first round after start

    // Callbacks
    BlockFoundCallback m_blockFoundCallback;
    TemplateProvider m_templateProvider;
    TipOutputProvider m_tipOutputProvider;
    std::mutex m_callbackMutex;

    // Stats
    std::atomic<uint64_t> m_blocksFound{0};
};

#endif // DILITHION_MINER_VDF_MINER_H
