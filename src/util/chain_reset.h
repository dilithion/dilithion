// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_CHAIN_RESET_H
#define DILITHION_UTIL_CHAIN_RESET_H

/**
 * Chain state reset helper.
 *
 * Wipes chain-derived data (blocks, chainstate, headers, dna_registry, wal, mempool)
 * while preserving wallet and identity material (wallet.dat, peers.dat,
 * mik_registration.dat, banlist, configs, logs).
 *
 * Used by:
 *   - `--reset-chain` CLI flag (user-invoked)
 *   - Auto-rebuild marker handler (BUG #277, post-UTXO-corruption recovery)
 */

#include <string>
#include <vector>

namespace Dilithion {

struct ChainResetReport {
    std::vector<std::string> removed;    // Paths actually removed
    std::vector<std::string> preserved;  // Files explicitly kept (that existed)
    std::vector<std::string> errors;     // Paths we failed to remove
};

/**
 * Perform the reset. Does NOT prompt — callers handle confirmation.
 * Returns a report listing what was touched. No exceptions thrown.
 */
ChainResetReport ResetChainState(const std::string& datadir);

/**
 * Interactive confirmation prompt. Prints the plan, reads from stdin,
 * returns true iff the user typed "RESET" (uppercase). If `yesFlag` is
 * true, skips the prompt and returns true.
 */
bool ConfirmChainReset(const std::string& datadir, bool yesFlag);

/**
 * v4.0.19: Write the auto_rebuild marker file. Used by:
 *   - IBDCoordinator on persistent UTXO/UndoBlock failure (BUG #277, v4.0.19)
 *   - Startup integrity check on missing undo data (Fix B, v4.0.19)
 *   - forcerebuild RPC on operator demand (Fix C, v4.0.19)
 *
 * The marker is a single text file at <datadir>/auto_rebuild containing the
 * reason. Existence triggers the startup wipe path on next launch.
 *
 * @param datadir Data directory (creates marker as <datadir>/auto_rebuild)
 * @param reason Human-readable reason — written to the file as a single line
 * @return true on success, false if the write failed (logs to stderr on failure)
 */
bool WriteAutoRebuildMarker(const std::string& datadir, const std::string& reason);

} // namespace Dilithion

#endif // DILITHION_UTIL_CHAIN_RESET_H
