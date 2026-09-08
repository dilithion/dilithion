# P2P-14/15 — `cs_headers` <-> `cs_main` lock-order inversion: CONSTRUCTED

**This branch is the record.** Any loose copy of these results in a scratch or temp directory is
not authoritative and should be treated as stale.

## Result

Measured against `origin/main` **`f47b9b24`**, 2026-09-07 12:57 UTC, WSL Ubuntu-24.04,
`make TSAN=1 -j8`, run under `setarch $(uname -m) -R`, binary carrying **33 dynamic TSan symbols**
(`nm -D`; note `nm -C` reports 0 on a correctly instrumented binary here — the symbols are dynamic).

| arm | exit | TSan inversion reports | forward edge reached | tip callback fired |
|---|---|---|---|---|
| `registered`   | **124 — TIMED OUT, the process HUNG** | **2** | 200/200 | 200 |
| `unregistered` | 0 — clean, 200 rounds | 0 | 200/200 | 0 |

The two arms differ by **one line**: the `RegisterTipUpdateCallback` copied verbatim in shape from
`src/node/dilithion-node.cpp:3551` (and `dilv-node.cpp:3371`). Adding it turns a clean 200-round
run into a hang.

`EXIT=124` is a real deadlock, not merely an observed inversion.

## TSan's own words

```
WARNING: ThreadSanitizer: lock-order-inversion (potential deadlock)
  Cycle in lock order graph: M0 => M1 => M0        # M0 = cs_headers, M1 = cs_main

  Mutex M1 acquired here while holding mutex M0 in main thread:
    CChainState::HasBlockIndex(uint256 const&) const
    dilithion::consensus::port::ChainSelectorAdapter::ProcessNewHeader(CBlockHeader const&)
    CHeadersManager::ProcessHeaders(int, std::vector<CBlockHeader> const&)

  Mutex M0 acquired here while holding mutex M1 in thread T2:
    CHeadersManager::OnBlockActivated(CBlockHeader const&, uint256 const&)
    std::_Function_handler<void (CBlockIndex const*), main::{lambda(CBlockIndex const*)#1}>

SUMMARY: ThreadSanitizer: lock-order-inversion (potential deadlock)
         in CChainState::HasBlockIndex(uint256 const&) const
```

Full output: [`tsan_registered.err`](tsan_registered.err) · [`tsan_unregistered.err`](tsan_unregistered.err).

## Why a purpose-built harness

**Zero tests in `src/test` register any of the three `chain.h` callbacks** (`:271`, `:278`, `:279`).
The reverse edge exists only because the node binaries register that lambda in `main()`, so it is
unreachable from the entire existing suite by construction — **a TSan run over the existing suites
reports clean, and that clean is false.**

## How to run

```bash
make TSAN=1 -j8 p2p14_lock_inversion_tsan_tests
scripts/run_p2p14_lock_inversion_tsan.sh
```

`scripts/build-with-sanitizers.sh tsan` does **not** work — `make` is commented out at `:102-106`;
it prints "TSAN build configuration ready" and exits 0 having built nothing.

## Status of this file as a test

It is a **RED baseline**: it is *expected to hang* until the lock order is fixed, and to go green
after. The both-arms control is therefore the regression test for the fix, not a one-off demo.

Once #165 arms the TSan leg in CI, a hang here surfaces through the `[TIMEOUT]` arm of
`scripts/run_test_suites.sh` — which only classifies hangs correctly as of #180 (exit 143 from
`timeout --preserve-status` previously fell through to `[FAIL]`, so a suite that HUNG was reported
as a suite whose tests BROKE).

## Two guards that must not be removed

1. **Reachability guard** — the harness exits **3** rather than report a zero it has not earned, if
   thread A never reached `ProcessNewHeader`. An earlier run reported `0 inversions` in both arms
   purely because the forward edge was never driven; that zero said nothing about the cycle.
2. **Own-headers count** — it counts *thread A's own* headers landing in the chainstate. Thread B's
   setup pre-adds a tip chain, so a bare `mapBlockIndex > 1` check would pass whether or not the
   forward edge ever ran.

## Two configuration facts that silently defeat this harness

- **Regtest ships no checkpoints**, so `FAST PATH 1` (`headers_manager.cpp:317`,
  `expectedHeight <= highestCheckpoint`) is never taken: every header falls to the slow PoW path
  and is dropped **while `ProcessHeaders` still returns `true`**. Hence the single high checkpoint
  installed by the harness. (Register row: regtest cannot exercise the production header fast path,
  so a green regtest header test proves nothing about it.)
- **Mainnet params abort** the harness with `RandomX VM not initialized`.

## Scope

`cs_headers <-> cs_main` is CONSTRUCTED. The separate `cs_headers -> g_validation_mutex` edge
(via `header.GetHash()` -> `randomx_hash_fast`) is **not** constructed and remains labelled
inspection-plus-argument.
