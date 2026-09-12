// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// epoch_nest_probe — A PAIRED CONTROL WHOSE PASS IS A PROCESS ABORT.
//
// EpochOfflineScope refuses to nest: quiescing while already offline fires a
// ConsensusInvariant, because t_epoch_offline is a bool and an inner destructor
// would silently re-enter a thread whose outer scope still believes it is parked.
//
// ⚠️ A SUITE CANNOT ASSERT THAT. Catching a ConsensusInvariant and continuing is
// exactly what the invariant exists to prevent, so the refusal can only be observed
// from OUTSIDE the process — by a parent that watches this one die. That is what
// scripts/red_arms_pr198_r1_folds.sh does with it, as the positive control for the
// inverted F13 mutation arm: the mutant shows the nest is ACCEPTED without the
// refusal, and this shows it is REJECTED with it. Either half alone proves nothing.
//
// EXIT CODES
//   abort (non-zero, with "t_epoch_offline" on stderr)  the refusal works — PASS
//   0                                                   the nest was ACCEPTED — FAIL
//
// It is EXEMPT from the suite roster for the same reason batch_verifier_race_control
// is: rostering a binary whose correct behaviour is to die would file a working
// control as a defect.

#include <consensus/chain.h>
#include <core/chainparams.h>

#include <iostream>

int main()
{
    Dilithion::ChainParams* saved = Dilithion::g_chainParams;
    Dilithion::ChainParams params = Dilithion::ChainParams::Regtest();
    Dilithion::g_chainParams = &params;

    CChainState cs;

    // A registered participant: an unregistered thread's scope is inert by design
    // (EpochQuiesce fails closed), which would make this probe vacuous.
    cs.EpochCheckpoint("nest-probe");

    std::cout << "probe: opening the outer offline scope" << std::endl;
    EpochOfflineScope outer(&cs);

    std::cout << "probe: opening an ILLEGAL inner offline scope — this must abort"
              << std::endl;
    EpochOfflineScope inner(&cs);

    // Reaching this line means the refusal is gone.
    std::cout << "probe: FAILED — the illegal nest was accepted" << std::endl;
    Dilithion::g_chainParams = saved;
    return 0;
}
