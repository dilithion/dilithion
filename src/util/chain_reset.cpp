// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <util/chain_reset.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>

namespace Dilithion {

namespace {

// Chain-derived directories that get wiped on reset.
// dfmp_identity/ MUST be wiped alongside chain data: it tracks which MIKs
// have registered on-chain, and a non-empty identity DB with an empty chain
// would cause BuildMiningTemplate to emit a Reference coinbase (type 0x02)
// before the registration block exists on the rebuilt chain, breaking
// consensus. dna_trust/ is also chain-adjacent (trust scores derived from
// on-chain behavior) so it goes too.
const char* const kRemoveDirs[] = {
    "blocks",
    "chainstate",
    "headers",
    "dna_registry",
    "dfmp_identity",
    "dna_trust",
    "wal",
};

// Chain-derived individual files that get wiped on reset.
// dfmp_heat.dat and dfmp_payout_heat.dat are derived from block history;
// stale heat against a reset chain would penalize miners incorrectly.
const char* const kRemoveFiles[] = {
    "mempool.dat",
    "auto_rebuild",
    "fee_estimates.dat",
    "dfmp_heat.dat",
    "dfmp_payout_heat.dat",
};

// User-owned state that must survive a reset. Used for the "preserved" report
// and defensive logging — anything NOT in kRemoveDirs/kRemoveFiles is already
// safe (we only delete what's explicitly listed). Common user backup spots
// are called out here so the reset output reassures the user they weren't
// touched.
const char* const kPreserveFiles[] = {
    "wallet.dat",
    "wallet.dat.bak",
    "mik_registration.dat",
    "peers.dat",
    "banlist.json",
    "dilithion.conf",
    "dilv.conf",
    "backups",
    "backup",
};

} // namespace

ChainResetReport ResetChainState(const std::string& datadir) {
    ChainResetReport report;
    std::filesystem::path base(datadir);

    for (const char* name : kRemoveDirs) {
        std::filesystem::path p = base / name;
        std::error_code ec;
        if (std::filesystem::exists(p, ec)) {
            std::filesystem::remove_all(p, ec);
            if (ec) {
                report.errors.push_back(p.string() + " (" + ec.message() + ")");
            } else {
                report.removed.push_back(p.string());
            }
        }
    }

    for (const char* name : kRemoveFiles) {
        std::filesystem::path p = base / name;
        std::error_code ec;
        if (std::filesystem::exists(p, ec)) {
            std::filesystem::remove(p, ec);
            if (ec) {
                report.errors.push_back(p.string() + " (" + ec.message() + ")");
            } else {
                report.removed.push_back(p.string());
            }
        }
    }

    for (const char* name : kPreserveFiles) {
        std::filesystem::path p = base / name;
        std::error_code ec;
        if (std::filesystem::exists(p, ec)) {
            report.preserved.push_back(p.string());
        }
    }

    return report;
}

bool WriteAutoRebuildMarker(const std::string& datadir, const std::string& reason) {
    if (datadir.empty()) {
        std::cerr << "[Recovery] WriteAutoRebuildMarker: empty datadir, refusing to write marker"
                  << std::endl;
        return false;
    }
    std::filesystem::path markerPath = std::filesystem::path(datadir) / "auto_rebuild";
    std::ofstream marker(markerPath);
    if (!marker.is_open()) {
        std::cerr << "[Recovery] WriteAutoRebuildMarker: failed to open " << markerPath.string()
                  << " for write" << std::endl;
        return false;
    }
    // Single-line reason. The startup handler reads this and logs it; some operators
    // also tail the file directly. Keep newline-terminated for log readability.
    marker << reason << std::endl;
    marker.close();
    if (marker.fail()) {
        std::cerr << "[Recovery] WriteAutoRebuildMarker: write to " << markerPath.string()
                  << " failed (stream error)" << std::endl;
        return false;
    }
    std::cerr << "[Recovery] Wrote auto_rebuild marker to " << markerPath.string()
              << " (reason: " << reason << ")" << std::endl;
    return true;
}

bool ConfirmChainReset(const std::string& datadir, bool yesFlag) {
    std::cout << "\n=== --reset-chain ===" << std::endl;
    std::cout << "Data directory: " << datadir << std::endl;
    std::cout << "\nWill REMOVE (chain-derived state, can be re-synced):" << std::endl;
    for (const char* n : kRemoveDirs) std::cout << "  - " << n << "/" << std::endl;
    for (const char* n : kRemoveFiles) std::cout << "  - " << n << std::endl;

    std::cout << "\nWill PRESERVE (if present):" << std::endl;
    for (const char* n : kPreserveFiles) std::cout << "  + " << n << std::endl;
    std::cout << "  + (any other file you put here — logs, backups, notes, etc.)" << std::endl;

    if (yesFlag) {
        std::cout << "\n--yes flag set, proceeding without prompt." << std::endl;
        return true;
    }

    std::cout << "\nType RESET (uppercase) to proceed, anything else to abort: " << std::flush;
    std::string answer;
    if (!std::getline(std::cin, answer)) {
        std::cout << "Aborted." << std::endl;
        return false;
    }
    if (answer != "RESET") {
        std::cout << "Aborted." << std::endl;
        return false;
    }
    return true;
}

} // namespace Dilithion
