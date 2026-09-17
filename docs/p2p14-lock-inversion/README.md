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

## Second edge: `cs_headers` -> `g_validation_mutex` — CONSTRUCTED as a STALL

**Not a deadlock, and this is not claimed as one.** `crypto/randomx_hash.cpp` holds no net symbol
and no callback registry, so `g_validation_mutex -> cs_headers` cannot exist — the edge is one-way.
TSan reports only *cycles*, so it is the wrong instrument here; the load-bearing claim is latency,
and latency is what is measured.

`p2p14_headers_randomx_stall_tsan_tests`, n=200 headers, same tree and toolchain:

| arm | `ProcessHeaders` wall | max stall of a thread that only wants `cs_headers` | cache |
|---|---|---|---|
| `unwarmed` (mirrors `ProcessHeaders:331`) | 3305 ms | **3,305,860 µs — 3.31 s** | 0 -> 200 |
| `prewarmed` (mirrors `QueueHeadersForValidation:2789`) | 6 ms | 6,227 µs | 200 before |

**531x.** The probe thread does nothing but call `GetHeaderCount()` (`headers_manager.cpp:1496`),
which only takes `cs_headers` and returns a map size — it contributes no work of its own. So the
headers lock is held continuously for 3.3 seconds while RandomX hashes are computed under it, on
the message-handling path.

The only difference between the arms is **where `GetHash()` is called** — which is exactly the
difference between the two production paths:

    QueueHeadersForValidation:2789   parallel pre-warm OUTSIDE the lock  -> cache HIT
    ProcessHeaders:331               no pre-warm                          -> cache MISS
    ProcessHeadersWithDoSProtection:649  no pre-warm                      -> cache MISS

and `QueueHeadersForValidation:2536` falls back to `ProcessHeaders` when the validation thread is
not running — i.e. onto the unwarmed path.

Evidence: [`stall_n200.txt`](stall_n200.txt). Run: `N=200 scripts/run_p2p14_headers_stall.sh`.

**Honest bounds on that number.** It is RandomX *light* mode; validation mode differs. It is 200
headers, chosen so the figure is measured rather than extrapolated — production batches run to
`MAX_HEADERS_RESULTS = 2000`, and this harness takes the batch size as `argv[2]` so anyone can
measure that directly instead of multiplying. The reachability guard (`fHashCached` flipping
0 -> 200 inside `ProcessHeaders`) is what makes the timing meaningful rather than a machine-speed
anecdote.

## Scope

Both edges are now constructed: `cs_headers <-> cs_main` as a **deadlock** (the registered arm
hangs), and `cs_headers -> g_validation_mutex` as a **multi-second stall** (one-way, no cycle).
