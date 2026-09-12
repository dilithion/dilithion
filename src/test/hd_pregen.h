// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// hd_pregen.h — the BUG #115 pre-generation base, defined ONCE for the HD test
// suites.
//
// WHY THIS FILE EXISTS. The fix for the stale HD expectations introduced a
// `kHDPregen` constant in wallet_hd_tests.cpp and another in
// rpc_hd_wallet_tests.cpp, plus a runtime-derived form in
// hd_wallet_standalone_tests.cpp — three definitions of one product fact
// (a8 review, LOW-1). Three copies of a rule is exactly what produced the
// defect being fixed: CRestAPI, http_path_gate and a test model each carried
// their own copy of the REST prefix, and the "parity sweep" ended up comparing
// two copies to each other instead of to the product.
//
// THE FACT. GenerateHDWallet pre-generates HD_GAP_LIMIT addresses at wallet
// creation (wallet.cpp:5286-5291, BUG #115) and sets nHDExternalChainIndex past
// them (wallet.cpp:5316). HD_GAP_LIMIT is 20 (wallet.h:469) and is PRIVATE, so
// the tests cannot read it directly.
//
// WHY A LITERAL AND NOT A RUNTIME LOOKUP. A test that derives the base from the
// wallet at runtime passes no matter what the wallet does — including if the
// pre-generation were removed entirely. Pinning the number means a change to
// HD_GAP_LIMIT breaks these suites LOUDLY, at one place, which is what should
// happen when a product policy moves. That is not a hypothetical: these
// expectations DID fail when BUG #115 landed, and the suites were excluded from
// CI rather than updated, costing ~1054 commits of zero enforced coverage on
// user-facing key derivation.
//
// So: if this constant and CWallet::HD_GAP_LIMIT ever disagree, the HD suites
// fail. Read that as the alarm working, not as a broken test — check which side
// changed and why before touching either.

#ifndef DILITHION_TEST_HD_PREGEN_H
#define DILITHION_TEST_HD_PREGEN_H

#include <cstdint>
#include <string>

namespace hdtest {

/// Mirrors the private CWallet::HD_GAP_LIMIT (wallet.h:469).
static const uint32_t kHDPregen = 20;

/// The BIP44 EXTERNAL-chain path for an index, so path expectations move with
/// the base instead of being frozen strings.
///
/// INTERNAL-chain paths are deliberately absent: wallet.cpp:5284 leaves
/// nHDInternalChainIndex at 0, so change addresses still start at 0 and none of
/// those expectations shifted.
inline std::string ExternalPath(uint32_t index)
{
    return "m/44'/573'/0'/0'/" + std::to_string(index) + "'";
}

} // namespace hdtest

#endif // DILITHION_TEST_HD_PREGEN_H
