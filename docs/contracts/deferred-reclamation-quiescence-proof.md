# Deferred reclamation of CBlockIndex — the quiescence proof

**Branch:** `fix/blockindex-deferred-reclamation`, cut from `0f6837d0` (#129's head).
**Base as of 2026-09-10: #129 IS MERGED** — main `4ccf3797` carries leaf-only
eviction, so the dependency below is no longer "depends on #129" but "depends on
main ≥ `4ccf3797`". The argument is unchanged; only its base moved.
**Mandatory reader:** LP10 (A-5 owner).

> ## ⚠️ THE SENTENCE THIS DOCUMENT USED TO OPEN WITH WAS FALSE
>
> It said: *"the checkpoint goes before the wait, so the pin per thread is one unit
> of work — an RPC server parked in `accept()` for hours pins exactly nothing."*
> **A 3/3 external panel falsified it, and the bench then measured it.** Publishing
> epoch E before blocking does not release anything: the slot **stays at E for the
> whole park**, and every entry unlinked afterwards is retained. Measured, at the
> 10,400/s ingress ceiling with one participant parked: **47.60 MB in 15 seconds
> and still growing — 0 entries freed in the entire run.** An hour of park is
> ~37M entries, ~11 GB. Attacker-influenceable, and the note called it safe.
>
> **THE CORRECT RULE IS A QUIESCENT-STATE PROTOCOL — offline/online, as in RCU.**
> A thread about to block calls `EpochQuiesce()`, which publishes the retired
> value: it leaves the minimum calculation entirely, exactly as an exited thread
> does. On wake it re-enters with `EpochCheckpoint()` **before it resolves
> anything**. `EpochOfflineScope` pairs the two so no wake path — including an
> exception or an early `break` — can perform half of it. Same bench, same
> configuration, with the park inside the scope: **6.41 MB peak, 146,486 entries
> freed during the run.** Unbounded became bounded.
>
> The old sentence survives in one narrower form, and it is still the reason the
> checkpoint sits where it does: **at the top of a loop, before the wait, a thread
> provably holds nothing** — that is what makes it safe to publish there at all.
> What it does not do is bound the pin for a thread that then stops looping.
>
> **The exception that remains**: a thread that blocks *while holding* a resolved
> pointer. It must not go offline (offline means "I hold nothing"), and it must not
> stay online either — it must drop the pointer first. The census found none.

> **LEAF-ONLY EVICTION IS WHAT MAKES AN ENTRY SAFE TO FREE AT ALL. Deferred
> reclamation only makes the TIMING safe.** A grace period protects a pointer held by
> a THREAD; it does nothing for a pointer stored in the GRAPH. That is the whole
> reason this is based on #129 rather than on `main`, and it is the first thing to
> read here.

---

## ⚠️ BASE: THIS IS CUT FROM #129, NOT FROM `main`, AND THAT IS NOT A PREFERENCE

The instruction was to cut from `0ecd033e` (main). I did not, and the reason is a
hard dependency rather than convenience — **deferred reclamation ALONE cannot fix the
class on `main`.**

`main`'s evictor (`EvictLowestWorkLeafNotPinned`) has no leaf or in-degree concept at
all — measured: zero occurrences of `in_degree` in `chain.cpp` on `0ecd033e`. It selects
the lowest-work entry not on the active chain and frees it, **which can be an INTERIOR
fork node whose higher-work child still names it as `pprev`**. That is precisely the UAF
#129 exists to fix.

A graveyard does not help there, and it is worth being exact about why:

> **A grace period protects pointers held by THREADS. It does nothing for a pointer
> stored in the GRAPH.**

If interior node `X` is evicted while child `C` has `C->pprev == X`, deferring the free
extends `X`'s validity — and then the drain frees it and `C->pprev` dangles anyway. No
quiescence point exists, because `C->pprev` is not transient: it persists for as long as
`C` does. **Only the leaf-only rule makes the freed entry safe to free at all.**

The two mechanisms are complementary and neither is sufficient alone:

| hazard | fixed by |
|---|---|
| pointer held by a thread across a `cs_main` release | **deferred reclamation** (this branch) |
| pointer stored in the index graph (`pprev` of a surviving child) | **leaf-only eviction** (#129) |

My own design note already depended on this without naming it: the three OUTLIVES-CALL
sites were cleared *because* `pnext` is null on anything evictable and a `pprev` written
into a new child makes the parent non-leaf — **both are #129 properties**. Building on
`main` would have produced a branch whose drain-time assertions could not be enabled and
whose safety argument had a hole in exactly the place it claims to close.

If the decision is that these must ship independently, the honest sequencing is #129
first; this branch is then additive. Cutting from `main` and asserting less is the option
I would argue against.

---

## The threads that can hold a `CBlockIndex*`

> ⚠️ **THE FIRST VERSION OF THIS TABLE WAS WRONG IN THREE PLACES, AND THE WIRING
> BUILT ON IT INHERITED ALL THREE.** It is replaced below by a call-graph census of
> every `std::thread` in production `src/` (36 threads; each entry function followed
> 2-3 levels deep, every row cited to `file:line`).

What the first table got wrong:

1. **"P2P message handler - spawn site: node main loop".** It is
   `CConnman::ThreadMessageHandler` (`net/connman.cpp:196`), a thread of its own.
   The node main loop is a *separate* participant, and it had no checkpoint at all.
2. **"RPC server - `m_serverThread` - resolves `rpc/server.cpp` (6)".** The accept
   thread resolves nothing; it accepts a socket and enqueues it. **Every RPC method
   runs on the worker pool** (`CRPCServer::WorkerThread`, `rpc/server.cpp:613`),
   which is where all 23 resolve sites are. The checkpoint went on the wrong thread.
3. **"Hash worker pool - excluded, never resolves".** The exclusion is correct -
   `FullValidateHeader` (`headers_manager.cpp:2614`) is checkpoint-height / VDF /
   PoW-hash only - but the pool's entry function *is* `ValidationWorkerThread`, the
   same function the table listed separately as the wired participant "Header
   validation". One row said excluded and the other said wired, about the same
   threads. It is wired: a checkpoint in a thread that holds nothing is always a
   true statement and costs nothing.

And it **omitted four threads that demonstrably resolve**: the HTTP worker pool, the
WebSocket server thread, the cached-stats updater, and both miner threads.

| thread | spawn | conditional | resolves - cited | checkpoint name |
|---|---|---|---|---|
| `CConnman::ThreadMessageHandler` | `connman.cpp:192` | no | yes - control msgs inline, `dilithion-node.cpp:4409` (`GetBlockIndex`), `:4415` (`GetTip`) | `p2p-msg-handler` |
| `CConnman::HeadersWorkerThread` | `connman.cpp:220` | no | **no longer** - see the note below | `p2p-headers-worker` (belt and braces) |
| `CConnman::BlocksWorkerThread` xN | `connman.cpp:234` | no | yes - `dilithion-node.cpp:6408`, `:6437`, `:6446` | `p2p-blocks-worker` |
| `CHeadersManager::ValidationWorkerThread` xHW | `headers_manager.cpp:3503` | no | **no** - hash-only | `headers-validation` (belt and braces) |
| `CHeadersManager::HeaderProcessorThread` | `headers_manager.cpp:3509` | no | **no longer** - see the note below | `headers-processor` (belt and braces) |
| `CBlockValidationQueue::ValidationWorker` | `block_validation_queue.cpp:86` | falls back to sync on failure | yes - `:626`, `:767`, `:849`, `:901` | `validation-worker` |
| `CTxIndex::SyncLoop` | `tx_index.cpp:560` | **yes** - `config.txindex_enabled` | yes - `:713`, `:620`, `:229`, `:240` | `txindex-sync` |
| `CCoinStatsIndex::SyncLoop` | `coinstatsindex.cpp:658` | **yes** - `config.coinstatsindex_enabled` | yes - `:741`, `:679`, `:487` | `coinstatsindex-sync` |
| `CRPCServer::ServerThread` (accept) | `rpc/server.cpp:608` | no | **no** - accept + enqueue only | `rpc-accept` (belt and braces) |
| **`CRPCServer::WorkerThread` xpool** | `rpc/server.cpp:613` | no | **yes - 23 sites**: `:3509`, `:3654`, `:7018`, `:8409` ... | `rpc-worker` |
| **`CHttpServer::WorkerThread` xN** | `http_server.cpp:139` | no | **yes** - `/metrics` `dilithion-node.cpp:3982`; REST `rest_api.cpp:362`, `:369` | `http-worker` |
| **`CWebSocketServer::ServerThread`** | `websocket.cpp:102` | **yes** - `rpcwebsocketport > 0` | **yes** - `server.cpp:7759` `ExecuteRPC` reaches the whole handler table | `websocket-server` |
| **`CCachedChainStats::UpdateThread`** | `cached_stats.cpp:32` | no - **every node, once a second** | **yes** - `dilithion-node.cpp:3935` then a 20-deep `pprev` walk `:3943-3949` | `cached-stats` |
| **`CMiningController::MiningWorker` xN** | `controller.cpp:274` | **yes** - mining on | **yes**, via `m_blockFoundCallback` -> `dilithion-node.cpp:6410`, `:6439` | `mining-worker` |
| **`CVDFMiner::MiningLoop`** | `vdf_miner.cpp:29` | **yes** - mining on, post-IBD | **yes**, via three injected callbacks -> `dilithion-node.cpp:6746`, `:6753`, `:6616` | `vdf-miner` |
| **node main loop** | `dilithion-node.cpp:8106` / `dilv-node.cpp:7868` | no | **yes, nearly every iteration** - `:8112`, `:8407`, `:8547`, `:8706-8736` | `node-main-loop` |

> ⚠️ **EVERY CITATION IN THE TABLE ABOVE WAS STALE, AND TWO ROWS WERE WRONG IN
> SUBSTANCE** (round-7 F44, re-derived 2026-09-10 on `11f0c525`). COORD reported two
> drifted line numbers; grepping the *shape* rather than fixing the reported lines
> found that **all eleven** citations had moved — the spawn citations pointed into
> `Stop()`, the resolve citations into unrelated code. A table of eleven `file:line`
> claims is eleven things with no decay function, and it decayed as a block.
>
> **The two substantive corrections:** `headers_manager.cpp` now contains **zero live
> resolves** — #194 removed the released-pointer sites from it entirely, so
> `HeadersWorkerThread` and `HeaderProcessorThread` no longer obtain a `CBlockIndex*`
> at all. Verified with #194's own comment stripper (`strip-cxx-comments.awk`), not by
> eye: every remaining `GetTip()`/`GetBlockIndex(` token in that file is inside a
> comment. Both threads keep their checkpoints as belt and braces, and the table now
> says *why* they have one rather than implying a resolve that no longer happens.
>
> **A table like this should be generated, not maintained.** It is left hand-written
> for now because the generator is a larger change than this round, but that is the
> real fix and it is recorded here as the reason this keeps happening.


**Deliberately NOT participants** - each checked, not assumed: `ThreadSocketHandler`
(bytes and framing; zero `CBlockIndex` tokens in `connman.cpp`), `ThreadOpenConnections`
(`CreateVersionMessage` uses `GetHeight()`, an `int`, `net.cpp:2238`),
`CRPCServer::CleanupThread`, `CHttpServer::CleanupThread` / `AcceptThread`,
`CTxMemPool::ExpirationThreadFunc`, `CAsyncBroadcaster::WorkerThread`,
`CSignatureBatchVerifier::WorkerThread`, `CResourceMonitor::MonitorThread`,
`ChainstateIntegrityMonitor::WorkerLoop` (`SnapshotIntegrityWindow` returns heights and
hashes **by value** - that thread was designed not to hold pointers),
`CRegistrationManager::WorkerMain_` (tip height is passed in as an `int`), the DigitalDNA
collector, the P2P maintenance lambda, the RandomX init threads, and the detached
shutdown triggers.

**⚠️ THE MINER AND CACHED-STATS ROWS ARE THE INSTRUCTIVE ONES.** `vdf_miner.cpp`
contains **no `CBlockIndex` token at all**, and neither does `cached_stats.cpp`; every
resolve arrives through an **injected callback** defined in the node binary. A grep of
the thread's own file says "clean" and is wrong. Only a call-graph census finds these -
which is why the list below is not the primary mechanism.

**The index sync loops were flagged as "long-running loops over historical blocks -
exactly the long-hold shape". Measured, they are not.** Both resolve and dereference
within two to three lines (`tx_index.cpp:229-232`, `:240-243`) and retain nothing across
an iteration; `tx_index.cpp:564-567` documents the same discipline for `m_mutex`. Short
windows at a high repetition rate, not long holds.

**The validation worker is covered twice over, and the second cover is stronger.** A
queued block and its parent are reported by `GetPendingBlockHashes` and pinned by
eviction clause (d), so eviction cannot free them while they are queued - **the queue
path is protected by PINNING, not by grace.** That answers LP10's drain rule ("refuse to
free while an entry enqueued before the epoch is in flight"): the pin makes the situation
unreachable rather than merely survivable.

## ⚠️ A LIST IS THE WRONG PRIMARY MECHANISM, SO IT IS NOT THE ONLY ONE

Everything above is a hand-maintained census, and its failure mode is obvious once
stated: **the thread that leaks is added by someone who never reads this file.** A count
checked against a table catches a *wired* thread that failed to reach its checkpoint. It
cannot catch the thread nobody wrote down - the person who forgets the checkpoint is the
same person who forgets the table row.

So there is a second, list-free mechanism. `CChainState::GetBlockIndex()` and `GetTip()`
are the only two ways a raw `CBlockIndex*` leaves `cs_main` - `mapBlockIndex` is private
and every mention of it outside `chain.cpp` is in a comment (verified tree-wide). Both
record the calling thread the first time it obtains a pointer while not yet being an
epoch participant. The record is **cleared when that thread checkpoints**, so resolving
during startup before the first checkpoint - which every thread does - is not an
accusation. What survives to the startup census is exactly the set of threads that hold
pointers and have made no promise: observed, not tabulated.

Cost for a participant: one thread-local load and a predicted branch per resolve. The
registry mutex is touched once in a thread's lifetime.

## The scheme: epoch counter, not a timer

Each of threads 1–2 and 4–8 holds a **thread-local epoch**, bumped at the call boundary
named above. The evictor records the current global epoch when it moves an entry to the
graveyard. **An entry is freed only when every registered thread's epoch has advanced
past the entry's recorded epoch** — at that point no thread can still hold a pointer
resolved before the unlink, because each has re-entered its boundary at least once.

This is preferred over a wall-clock grace deliberately: a timer's bound is an assumption
about worst-case call duration, and a call that runs long under load (a slow LevelDB
write, a paused VM, a debugger) silently violates it. **An epoch bound is a proof; a
timer bound is a hope with a number attached.** If a timer is ever used instead, the
worst-case call duration it must exceed has to be stated *and measured* — the
`ProcessBlock` path alone contains a LevelDB write, which is milliseconds and not
bounded above by anything in this repo.

## Drain-time invariants (asserted, not argued)

Every entry, at the moment it is actually freed:

1. **`pnext == nullptr`.** `pnext` is set only for active-chain members, and active-chain
   ancestors are pinned by eviction clause (a), so an entry with `pnext` set is never
   evictable. A walk from a graveyard entry therefore terminates immediately.
2. **`pskip == nullptr`.** `pskip` is inert repo-wide — only ever assigned `nullptr` or
   copied; no `BuildSkip` exists. If `BuildSkip` is ever implemented this assertion will
   catch it, which is the point.
3. **No live map entry names it as `pprev`.** Guaranteed by #129's leaf-only rule (an
   entry with a surviving child has in-degree ≥ 1 and is not a leaf), and asserted here
   rather than inherited — the assertion is what makes the dependency on #129 visible if
   someone ever weakens it.

`pprev` of a graveyard entry points INTO the live map and stays valid; that is
memory-safe but must never be read as reachability. Nothing may walk *from* the map
*into* the graveyard — which is what "unlinked" buys.

## ⚠️ TWO BLOCKERS AN EXTERNAL REVIEWER FOUND THAT EVERY TEST HERE MISSED

Both were found by a single external seat on the raw diff, and both are the same
shape: **the suite exercised the mechanism by calling it itself, so nothing noticed
that production never did.**

**1. NOTHING IN PRODUCTION CALLED `DrainGraveyard()`.** Every checkpoint was wired,
the census gate refused to start a node with a missing participant, the graveyard
filled correctly on every eviction — and no code path ever freed any of it. A node
would have run perfectly and grown without bound. The tests all passed because each
one calls `DrainGraveyard()` directly; the wiring test for the checkpoints had no
counterpart for the drain.

It is now called from the node main loop, once a second, in both binaries — a brief
`cs_main` acquisition off every hot path. And because "nobody drains" is exactly the
kind of absence that is invisible in a passing test, the evictor now carries a
**tripwire**: when the graveyard passes 1024 entries (then 2048, 4096 …) it logs
`GRAVEYARD NOT DRAINING`, which also catches the other cause of the same symptom —
a registered thread that has stopped checkpointing and is pinning every entry.

**2. AN EMPTY REGISTRY FREED THE WHOLE GRAVEYARD, AND THE COMMENT CLAIMED THE
OPPOSITE.** `safe_epoch` started at the global epoch and was only ever *lowered* by
a registered slot. With no registered threads, nothing lowered it, the
`safe_epoch == 0` guard never fired (the global epoch starts at 1), and every entry
was freed immediately. Reachable interleaving: a thread resolves a pointer before
any thread has checkpointed → an eviction unlinks it → a drain runs → the entry is
freed → the thread dereferences. That is precisely the use-after-free this document
exists to remove, reintroduced by the mechanism meant to prevent it.

The suite missed it because its first act was to checkpoint the main thread, so the
registry was never empty by the time anything was measured. The rule is now explicit
— **no participants means no promises, so nothing may be freed** — and the arm that
tests it runs FIRST in the file, because the registry is process-global and one
checkpoint anywhere populates it for the life of the process. The arm was
RED-checked: with the guard removed it fails, and the tree is green again after
restoration.

**The lesson worth keeping**: a test that calls the mechanism itself proves the
mechanism works, not that anything invokes it. Both blockers were absences, and an
absence is invisible to a suite that supplies the missing thing itself.

## MEASURED — the arithmetic is gone

> Regenerate this whole table with **`scripts/graveyard_occupancy_sweep.sh`**, which
> runs every configuration in one command and fails closed on a stale binary. It was
> written because five numbers gathered from five hand-typed invocations drift: one
> gets re-measured after a change and the other four keep their old values, with
> nothing in the document saying which is which. That had already happened here —
> see the variance note below.

Both open numbers are now observations. `graveyard_occupancy_bench` (500,000-entry
index, evictions throttled to a sustained **10,400/s** — the ingress ceiling, not
the evictor's own, which measures 1.29 M/s and would consume the whole evictable set
in 19 ms and report its size as a "peak"):

| configuration | peak graveyard | vs the arithmetic |
|---|---|---|
| **A — as wired**: 1 Hz drain, 1 Hz slowest checkpoint | **21,041 entries = 6.42 MB** | predicted 3.17 MB → **2.03x** |
| B — 10 s drain, 10 s slowest checkpoint | 113,844 entries = 34.74 MB | predicted 31.72 MB → 1.10x |
| C — 1 Hz drain, **10 s** slowest checkpoint | 105,666 entries = 32.25 MB | → 1.02x |

⚠️ **AND THEY VARY RUN TO RUN BY ~2x, WHICH A SINGLE QUOTED FIGURE HID.** The
wired setting measured **6.42, 6.39 and 3.53 MB** on three consecutive runs of the
same command, and **6.43 / 6.40 / 3.61 MB** when the sweep repeated it later.

**The spread is about one drain cycle of accumulation, so it scales with the cycle**:
config B (a 10 s drain period) swung **34.79 → 63.46 MB** between sweeps, which is
~10 s × 10,400/s × 305 B ≈ 32 MB — exactly one cycle. B and C are single runs and
must not be quoted as point values either. Peak occupancy is sampled after each eviction, so it depends on where
the run ends relative to the 1 Hz drain cycle — a run that stops just before a drain
reports roughly twice one that stops just after. The honest statement for the wired
setting is **3.5–6.4 MB**, and the number to quote is the **upper** end.

This only became visible when `scripts/graveyard_occupancy_sweep.sh` ran the whole
table in one command and config A came back at 3.53 MB against the 6.42 MB this
document had carried since it was measured once. **A figure measured once is a
sample, and this document had been treating it as a constant.**

⚠️ **THESE ARE OBSERVATIONS AT THESE SETTINGS, NOT A BOUND.** 6.42 MB is what a
1 Hz drain and a 1 Hz slowest checkpoint produced on this machine at this ingress
rate; it is not a ceiling. The ceiling is set by the slowest participant's interval,
and a participant that parks without going offline has no interval at all — see the
round-1 panel section below, where the same bench measures 47.60 MB and still
climbing.

**C is the row that matters.** A drain ten times faster than B's bought 2.5 MB:
**the slowest CHECKPOINT dominates, not the drain cadence.** The number to defend is
therefore the slowest participant's interval, and the wired shape's honest figure is
~6.4 MB, not the ~3.3 MB this document used to carry — the arithmetic counted one
interval where the peak spans two (one checkpoint lag plus one drain period).

**Drain cost, held under `cs_main`**: max 6.1 ms / mean 2.4 ms at the 1 Hz setting;
max 18.0 ms at the 10 s setting, where each call frees ten times as much.

### ⚠️ The measurement found two defects that reading had not

**1. A THREAD THAT EXITS PINNED THE GRAVEYARD FOR THE PROCESS LIFETIME.** Epoch
slots are leaked on purpose so a drain can read them after their owner exits — but a
dead thread's slot kept its last published epoch, the drain takes the MINIMUM across
slots, and nothing ever raised it again. The first bench run ended with 24,936
entries still in the graveyard and a final drain, with every thread quiescent,
freeing **zero**.

This is not exotic: the miner threads exit when mining stops, the index sync loops
exit when they finish, the RPC and websocket threads exit on `Stop()`. Any one of
them froze reclamation permanently — the same silent unbounded growth as a thread
that never checkpoints, reached from the opposite direction. A thread that has exited
holds no `CBlockIndex*`, so its slot is now retired to the maximum epoch and can
never lower the minimum.

**Two things about that fix are worth keeping**, because both were wrong first:
a `thread_local` with a TRIVIAL constructor gets no dynamic initialisation and
therefore **no destructor registration at all** — the retirement code existed and
never ran; and once it did run, reading the sibling `thread_local` slot pointer
returned NULL, because TLS teardown had already cleared it. The slot pointer now
lives inside the retirer object, whose own storage is valid during its destructor.
Both were found by the regression arm going red, not by reading the diff.

**2. THE DRAIN'S INVARIANT WALK WAS O(map) PER FREED ENTRY.** "No live entry names
this as `pprev`" was checked by scanning the whole of `mapBlockIndex` for every entry
freed — measured 46.9 ms to free 64 entries at n=50,000 (0.73 ms each), i.e. ~7 ms
each at the 500,000 cap, so one drain of a 10,000-entry graveyard would have held
`cs_main` for over a minute. Same class as CON-27, introduced by an assertion rather
than by the algorithm. The maintained in-degree map answers it in O(log n) and now
carries it in production; the exhaustive scan — which validates `m_inDegree` itself
rather than trusting it — is behind a runtime switch the suites turn on. It was first
guarded with `#ifndef NDEBUG`, and that was a **false claim about this repo**: NDEBUG
is defined nowhere in the Makefile (line 1421 says so, and the test objects add
`-UNDEBUG` to keep it that way), so the "debug-only" scan would have run in every
shipped node. Drain cost after the fix: 0.1 ms.

## THE ASan VERDICT — in, and both trap arms trapped

Run `34424068632`, job `102705495467`, head `4ae2798c`, step *"Deferred-reclamation
ASan arms (2 of 3 MUST trap)"*, clang with `-fsanitize=address`. Verbatim:

```
sanitizer: PRESENT
--- arm=deferred (exit 0) ---
        dereference completed, value intact
  PASS  deferred: clean, as required
--- arm=immediate (exit 1) ---
    ==12388==ERROR: AddressSanitizer: heap-use-after-free on address 0x512000000a10
    SUMMARY: AddressSanitizer: heap-use-after-free src/test/blockindex_uaf_asan_arm.cpp:194 in main
  PASS  immediate: AddressSanitizer reported heap-use-after-free
--- arm=drained (exit 1) ---
        drained 1 entry while still holding the pointer
    ==12396==ERROR: AddressSanitizer: heap-use-after-free on address 0x512000000a10
  PASS  drained: AddressSanitizer reported heap-use-after-free
===== ASan arms: PASS (0 failed) =====
```

So: **the defect reproduces** (`immediate` — deferral off, the evictor freeing in
place), **the fix is clean** (`deferred` — a pointer resolved before an eviction on
another thread, still readable), and **the harness demonstrably reaches the free**
(`drained` — the holder checkpoints while still holding, so the drain frees under it,
and it traps at the same address). Without that third arm the clean one would prove
nothing.

## ⚠️ EXTERNAL PANEL, ROUND 1 (head 42a287cd) — FOUR CONFIRMED DEFECTS

Three named seats, 3 of 3 responding, aggregate **NO-GO**; no seat asked for a
redesign. Full page: `dilithion-strategy/missions/pr129-eviction-uaf/REVIEW_external_pr198_r1_42a287cd.md`.
Every fold below carries a RED-first arm (`scripts/red_arms_pr198_r1_folds.sh`).

**F1 — a thread that resolves and NEVER checkpoints was not pinning; it was being
freed under.** The drain's minimum runs over the slot registry, and a slot existed
only after a first checkpoint — so an unregistered resolver was simply absent from
the calculation, and the drain went on freeing the entry it held. The startup gate
refuses such a node, but the *periodic* census only LOGS while the drain keeps
freeing, and the node-loop comment called that state "safe". **It was the
use-after-free direction, in the mechanism that exists to remove use-after-frees.**
Fixed: the resolve itself creates the slot at **0**, which is below every stamp, so
the drain refuses everything while such a thread lives — a loud leak instead. And
registration is now **counted per thread**: a `std::set<std::string>` meant one
`rpc-worker` reaching its checkpoint satisfied the census for the entire pool.

**F2 — a parked participant pinned forever.** The headline defect, above.

**F3 — the drain was O(graveyard) per call in the pinned regime.** Every 1 Hz call
walked and rebuilt the whole vector under `cs_main` even when nothing could be
freed, so the lock hold grew linearly with time-since-pin (CON-27's class; the
6.1 ms figure was measured in the *draining* regime, where it does not appear).
Stamps are strictly increasing and the vector is insertion-ordered, so the front
entry answers "anything freeable?" in O(1) and a binary search finds the cutoff.
Measured in the pinned regime at G≈156,000: **max 1.0 ms / mean 0.5 ms with the
full walk, 0.0 ms with the fast path.** Honest magnitude: the walk costs ~3.2 ns
per entry, so at fifteen seconds of pin it is small — its danger is that it grows
with G, and G grows at the ingress rate. The memory ceiling bites first.

**F4 — the free-time leaf check was a tautology.** `LeafIndexOnErase` erased the
victim's in-degree row at **unlink**, so at free time `it == end()` always held and
`ConsensusInvariant(it == end || second == 0)` could not fail for any input. The row
is now kept until the free, asserted zero there, and erased. The mutant that
restores the old erase **aborts on that assertion at the first drain** — which is
the proof the check is no longer vacuous.

### Obligations the panel asked to be stated, not fixed

* **No handoff across a thread's exit.** `~EpochSlotRetirer` retires the slot the
  instant the thread ends, so a pointer *queued, captured or stored* by that thread
  before exiting would be outside the proof. The 62-site census found no site that
  hands a resolved `CBlockIndex*` to another thread or stores one beyond its call —
  every escape is a stack pointer used within the call. The queue path is the one
  that comes closest, and it is covered from the other side: `queued_block.pindex`
  is re-resolved by hash and its entry is pinned by eviction clause (d) while it is
  in flight. **If a future change queues a raw index pointer, this proof breaks and
  the drain-time invariants will not catch it.**
* **Shutdown.** Nothing frees the graveyard at teardown. `CChainState`'s destruction
  releases it with everything else; no code path clears the slots or drains at
  `Stop()`. That is deliberate — a drain during teardown would need every thread to
  still be checkpointing — and it means the graveyard's contents are freed by
  process exit, not by reclamation. Stated so nobody adds a "tidy" drain into a
  shutdown path where the participants are already gone.
* **One `CChainState` per process.** `m_globalEpoch` is a member; the slot registry
  and the thread-locals are process-wide. That is sound only while exactly one
  chainstate exists and is never re-created. `g_chainstate` (`src/core/globals.cpp`)
  is the only production instance. **Tests construct their own `CChainState`, which
  is why the registry must never be keyed to one** — and why a second *production*
  chainstate would require keying the registry by chainstate.

## ⚠️ A CLAIM OF MINE THE ROUND-2 PANEL RETRACTED

I wrote, in the round-1 fold and in the PR body, that the two defects **compose** —
that after F1 a stale unregistered-resolver record would also stop the drain, so the
withdrawal bug "would have stopped reclamation outright rather than printing a wrong
number". **That is false, and the seats were right to call it.**

`DrainGraveyard` refuses on `safe_epoch == 0`, and `safe_epoch` is the minimum over
**live slot values**. `UnregisteredResolverThreads()` is read only *inside* that
branch, to format the message. An **exited** thread's slot is `EPOCH_SLOT_RETIRED`,
which is the maximum — it cannot lower the minimum, so a stale accusation left behind
by an exited thread never gated the free rule at all. It failed the **startup gate**
and the **periodic census**, and nothing else.

**So the fifth fix is load-bearing for the CENSUS, not for reclamation.** Still worth
having — a census that cries wolf is a census nobody reads, and the gate refuses to
start a node over it — but one grade less serious than I said, and I said it in a
message that shaped how someone else read the branch. The composition I described
would require the accusation to be held by a **live** thread, which is precisely the
case the record is not needed for: that thread's slot is already 0.

## THE POINTER-ESCAPE CENSUS — every way a raw `CBlockIndex*` leaves `cs_main`

The seats could not verify the claim that `GetBlockIndex` and `GetTip` are the only
escapes, because the pack did not carry `GetTip`. It is instrumented
(`chain.cpp:3838-3841`, verified in this tree — COORD cited 3767-3770 from an earlier head). The full census, grep-level:

| route | status |
|---|---|
| `CChainState::GetBlockIndex(hash)` | **instrumented** — `NoteIndexPointerResolved(current_epoch)` before the return |
| `CChainState::GetTip()` | **instrumented** — same call, guarded on a non-null tip |
| `CChainState::FindMostWorkChainImpl()` (`chain.h:1650`, body `chain.cpp:4448`) | **private**, and it has exactly ONE caller: `ActivateBestChain` at `chain.cpp:1994`, inside the function-scoped `lock_guard(cs_main)` taken at `chain.cpp:1820`. The returned pointer is used and discarded within that scope, which covers the whole function. No escape — verified by grep, not asserted. |
| `CChainState::FindFork(a, b)` (static) | returns one of **its own arguments** — a pointer the caller already had. Creates no new escape. |
| `mapBlockIndex` iteration | **private**; every mention outside `chain.cpp` is in a comment (verified tree-wide). No caller can iterate it. |
| callbacks (`RegisterBlockConnectCallback`, tip-update) | pass **values** — `const CBlock&`, `int`, `uint256`. This was deliberately changed from a `const CBlockIndex*` under P2P-14/15 and the header says not to change it back. |
| `AddBlockIndex(hash, unique_ptr)` | takes ownership; the caller's raw pointer is one it already held before the call. |
| `phashBlock` / `GetBlockHash()` | returns a `uint256` **by value**. The `phashBlock` member is a value member of the index entry, not a pointer into the map. |
| `SetTip` / `SetTipForTest` | take a pointer **in**; they do not hand one out. |

So the two instrumented accessors are the complete set of *new* escapes, and the
detector at those two points sees every thread that acquires one. **What it does not
see** is a pointer passed from one thread to another after the fact — see the
no-handoff obligation above.

## ⚠️ ROUND 4: THE CHECK I ADDED WAS A REMOTE DENIAL OF SERVICE

The one-thread-one-name check from round 3 was **remotely reachable**, and the panel
found it 3/3 (one BLOCKER, one HIGH):

* the three `wait-*` RPC handlers opened scopes hard-named `"rpc-worker"`;
* the WebSocket server thread dispatches the **entire RPC table**
  (`websocket.cpp`'s `SetMessageCallback` → `ExecuteRPC`) while registered as
  `"websocket-server"`;
* the mismatch fired `ConsensusInvariant(false)`.

**A websocket client calling `waitfornewblock` aborted the node.** The check written
to catch a wiring mistake became a remote kill switch, in a delta whose entire purpose
is to make the node safer.

**The root cause is not the check's strictness — a handler cannot know its thread.** A
name is chosen per *site*; a slot belongs to a *thread*. So:

* **names belong to threads**: a thread registers once, at its own loop-top
  checkpoint;
* **scopes take no name at all** and act on whatever the calling thread is registered
  as;
* a scope opened on a thread with **no registered name refuses, fail-closed** — it
  stays online and keeps pinning, and the scope becomes inert. Publishing a promise
  for an undeclared thread would *unpin a holder*, which is the use-after-free
  direction arriving through a different door;
* the one-thread-one-name check now applies **only to named checkpoints**, where a
  thread really is asserting its own identity.

Same class, also fixed: `CWebSocketServer::SocketWrite` is reachable from
`SendToClient` / `Broadcast` on threads other than the websocket server thread, and
the HTTP REST branch reaches the same handlers.

### What else round 4 found

* **F17 — the pause path pinned online indefinitely.** A paused validation thread
  spins 10 ms at a time with its epoch frozen; a fork recovery can hold the pause open
  for as long as it likes. Now offline across the sleep. **The panel named one site;
  there are two** (`ValidationWorkerThread` and `HeaderProcessorThread`, identical
  bodies) — found by grepping the shape rather than fixing the reported line.
* **F18 — "bounded by the socket timeouts" was asserted, not checked.** There is no
  `setsockopt` anywhere in `http_server.cpp`: HTTP client sockets get **no
  `SO_SNDTIMEO`** (the RPC server sets 10 s on its own). A blackholed HTTP client pins
  its worker **online for TCP's retransmit lifetime**. The claim is corrected at the
  site; the two real fixes (one write funnel, plus send timeouts on accepted sockets)
  change that server's network behaviour and are filed rather than smuggled in here.
* **F19 — the nesting refusal is narrower than it claimed.** It rejects an offline
  *state*, not a live outer *scope*: `offline → OnlineWindow → offline` and
  `offline → instrumented resolve → offline` both pass, because each clears the flag.
  The first is the legal nest; the second is a genuine gap, recorded as such.
* **F23 — the websocket READ side was wired nowhere.** `HandleClient` blocks in
  `SocketRead` for the whole life of a connection, and a client that simply never
  sends pinned that thread online indefinitely. Now offline, symmetric with the write.

### ⚠️ A ROUND-4 FIX SUBSUMED A ROUND-3 FIX, and the mutant is how it showed

Round 3 made a resolve-after-quiesce restore the withdrawn accusation. The
fail-closed rule makes that **unreachable**: quiesce requires a registered name, a
name comes only from `EpochCheckpoint(name)`, that call clears the accusation, and a
thread with a slot is never re-recorded. So no thread can reach a quiesce still
accused.

**The round-3 mutation arm then survived on the fixed tree** — correctly, because
there was nothing left to break. A surviving mutant is ambiguous (unreachable *or*
untested); this one was unreachable. The arm now asserts the unreachability, the
mutant is retired with its reason, and the withdrawal call stays as a **guard** whose
three preconditions are written down, because any one of them could be broken by a
later change.

## ⚠️ THE PER-SITE CONTRACT *IS* THE MECHANISM — SO HERE IS EVERY SITE

The round-3 panel was asked directly whether the no-pointer-across-a-boundary rule
can be made structural rather than contractual. **All three seats: it cannot, in
C++17.** There is no borrow checker; a raw pointer copied to the stack, obtained via
`.get()`, or handed to another thread is invisible to any scope type.

What they proposed instead — and COORD ruled it **out of this PR's scope**, to its
own contract and PR — is that the two instrumented accessors return a **move-only
handle** whose constructor and destructor drive the hold counter, with every boundary
asserting `holds == 0` **in production**. Cost: one thread-local add per resolve and
~62 call sites touched. Escape from the handle (`.get()`, a copy of the raw pointer)
stays contractual even then, so it narrows the hole rather than closing it.

**Until that lands, this PR's mechanism is the contract stated at each site.** A
contract nobody can point at is not a mechanism, so every site is listed here with
its enclosing function and what the contract asserts there. **Fourteen sites**, not
the nine an earlier count claimed:

| # | site | enclosing function | what is claimed while offline |
|---|---|---|---|
| 1 | `connman.cpp:908` | `CConnman::ThreadMessageHandler` | the batch is routed; nothing resolved is retained across the bottom wait |
| 2 | `connman.cpp:990` | `CConnman::HeadersWorkerThread` | between messages this thread holds nothing; `ProcessQueuedMessage` has returned |
| 3 | `connman.cpp:1051` | `CConnman::BlocksWorkerThread` | as above, per block message |
| 4 | `headers_manager.cpp:3419` | `CHeadersManager::ValidationWorkerThread` | the pool never resolves at all (`FullValidateHeader` is hash-only); the scope is belt-and-braces |
| 5 | `block_validation_queue.cpp:422` | `CBlockValidationQueue::ValidationWorker` | the previous `ProcessBlock` is complete; the queued entry is pinned by clause (d), not by this thread |
| 6 | `http_server.cpp:286` | `CHttpServer::WorkerThread` | the previous request is finished. ⚠️ **Write side NOT covered** — see the coverage note below |
| 7 | `websocket.cpp:170` | `CWebSocketServer::ServerThread` | no client is being served; `HandleClient` has returned |
| 8 | `websocket.cpp:454` | `CWebSocketServer::SocketWrite` | the response is a built buffer; no index pointer is live in any caller frame |
| 9 | `server.cpp:810` | `CRPCServer::ServerThread` (accept) | this thread never resolves at all |
| 10 | `server.cpp:838` | `CRPCServer::ServerThread` (SSL handshake) | as above; the handshake moves bytes |
| 11 | `server.cpp:920` | `CRPCServer::WorkerThread` | the previous request is complete |
| 12 | `server.cpp:1045` | `CRPCServer::HandleClient` → `socket_write` lambda | the response is a built `std::string`; the census of handlers says no pointer is live |
| 13 | `server.cpp:10191/:10240/:10288` | `RPC_WaitForNewBlock` / `WaitForBlock` / `WaitForBlockHeight` | the park holds only `{uint256, int}` copies; the predicate goes **online** to resolve |
| 14 | `server.cpp:10193/:10242/:10290` | the same three predicates (`EpochOnlineWindow`) | the inverse: briefly online **because** it resolves |

**Row 13 and 14 are one mechanism.** The wait is offline; its predicate is online.
The braces matter and were wrong once: a function-scoped park kept the thread offline
through the `get_tip()` *after* the wait, making every ordinary return a
resolve-while-offline and a false alarm on the observer added to catch real ones.

**⚠️ THE HOLE THE CONTRACT DOES NOT COVER, stated plainly and not softened: a thread
that RESOLVES A POINTER AND THEN PARKS.** `EpochQuiesce` publishes "I hold nothing"
and unpins; if the caller is holding, that is a lie and the entry can be freed under
it. The hold tracking catches it **only when a test declares the hold**; the
resolve-while-offline counter catches the *other* order (park, then resolve) and
nothing else. **The detector is not protection against resolve-then-park** — it is
detection of a different mistake, and any reading of it as protection is wrong.

### Coverage, stated rather than implied

* **The write side is covered for RPC and WebSocket, not HTTP.** Both of those funnel
  every response through one helper (`socket_write`, `CWebSocketServer::SocketWrite`),
  so one scope covers each. `http_server.cpp` has no funnel — `SendResponse` plus a
  dozen raw `send()` calls through `HandleRequest` — so an HTTP response to a slow
  client is written **online**, pinning for the send. Bounded by that socket's
  timeouts, not by anything here. Wiring it means routing every write through one
  helper first: a refactor of that file, not this PR.
* **Nesting is refused, not counted.** `EpochOfflineScope` inside `EpochOfflineScope`
  fires a `ConsensusInvariant` — `t_epoch_offline` is a bool, so an inner destructor
  would silently re-enter a thread whose outer scope still believes it is parked (and
  `HandleClient`'s scope can lexically enclose `socket_write`'s). A counter would make
  the nest "work" and hide the design error. `EpochOnlineWindow` inside an offline
  scope is the one legal nest and goes through `EpochCheckpoint`.
* **One thread, one name — and SCOPES CARRY NO NAME AT ALL.** A *named checkpoint*
  whose name differs from the one this thread already registered under aborts. That
  check is safe only because scopes no longer name anything: when they did, a handler
  running on a differently-named thread hit it, and `waitfornewblock` over a websocket
  **aborted the node**. Names are established once per thread at its own loop-top
  checkpoint; a scope acts on whatever the calling thread already is, and refuses
  fail-closed if that thread is unregistered.

## ⚠️ CLOSED — EVERY `thread_local` DESTRUCTOR ON THIS TOOLCHAIN RAN ON FREED MEMORY

**This was the last open item on the branch. It is closed by mechanism, with probes,
and it turned out to be worse than the phantom that led to it.**

### What was observed

`deferred_reclamation_tests` failed roughly **3 runs in 50** (measured repeatedly:
2/30, 3/40, 5/40, 3/50, 2/50, 3/50 across six successive attempted fixes). Every
failure had the same signature: `EpochRegistrationComplete` accusing **one** thread
that had already exited and been joined, and never withdrawing it — so the census
failed permanently for the rest of the process. A trace showed the withdrawal firing
with `recorded == true` and the stored `id` **default-constructed**.

### The mechanism

On the toolchain this project ships on — MSYS2 `g++ 15.2`, `libwinpthread`,
`libstdc++`, the node binary's own DLL set — **`thread_local` is emutls**:

1. Each `thread_local` gets a `malloc(size + 8)` block per thread, the object at
   `base + 8`, and emutls registers **one pthread key** whose destructor frees **all**
   of that thread's blocks.
2. libstdc++'s `__cxa_thread_atexit` has **no `__cxa_thread_atexit_impl`** to call on
   this CRT (measured: absent from every `libmsvcrt*.a` and `libucrt*.a`), so it uses
   the Win32 fallback — a per-thread list of `elt {dtor, obj, next, dll}`, 32 bytes,
   one `new elt` per registration, held in a **second** pthread key.
3. winpthreads runs key destructors in **key-index order**, and emutls' key is created
   first, because the first TLS access necessarily precedes the first destructor
   registration.

**So every C++ `thread_local` destructor in this process runs after its own storage
has been `free()`d.** Measured directly with `--wrap=free`: **300/300 and 600/600**,
every run. Not a race — a certainty.

Reading a freed block usually returns the old bytes, which is exactly why six fixes
and 260 suite runs never pinned it down. It returns something else only when the block
is **re-issued** inside the microsecond window between the free and the destructor —
and the thing that re-issues it is **a thread STARTING**, whose first
`__cxa_thread_atexit` allocates a 32-byte `elt` in the same size class. Plain heap
churn on long-lived threads never did it (**0 in 4000**); a starting thread did, at
**~2% per exit**.

That also explains why every earlier probe read zero: *"300 accused threads,
sequentially and in batches of 20"* has nothing **starting** at the instant one exits.
**The rate is a function of concurrent thread start-up, not of the arms.**

### ⚠️ The retirer was carrying the same defect with a much worse payload

The phantom was the visible half. `~EpochSlotRetirer` read `slot` from the same freed
block:

| what `slot` read | rate per exit | consequence |
|---|---|---|
| the correct pointer | ~95–98% | fine |
| **NULL** | ~1–2% | the slot is **never retired** → it caps `DrainGraveyard`'s minimum for the process lifetime. The unbounded leak the retirer exists to prevent, now probabilistic. |
| **a re-issued pointer** | ~1–3% | `slot->store(~0)` writes **eight 0xFF bytes through a wild pointer into a live foreign heap block**. |

**Reachable on any Windows node that mines, with no wiring bug at all.**
`StopMining()` exits every worker on each template update and `StartMining()` restarts
them immediately — precisely the starting-thread pressure above. `CTxIndex::SyncLoop`
returns when it catches up; RPC, HTTP and websocket workers exit at `Stop()`.

The **pre-gate phantom** — a node refusing to start — is *not* reachable today: the
only threads that exit before the gate are the `std::async` hash workers and the
RandomX init threads, and neither resolves a `CBlockIndex*`. It is latent, and it
becomes live the moment an unwired resolver thread is added — which is the exact class
the detector exists to catch.

Linux/glibc has `__cxa_thread_atexit_impl` and is unaffected. **This is the Windows
binary.**

### Why none of the six earlier fixes could have worked

| attempt | what it changed | why it could not close |
|---|---|---|
| polls after `join()` | when the count was read | the block is freed before the destructor either way |
| deltas instead of absolute counts | what the arms asserted | same |
| id-keyed erase → authoritative count | **what** was read from the freed block | narrowed it; the block is still freed |
| `Touch()` to force construction | when the object was constructed | construction was never the problem |
| the 8-entry cap accounting | a diagnostic list | never load-bearing |
| TLS-destructor reliability probes | 300/300, 600/600 clean | correct, and irrelevant: the destructors DO run |

Every one of them changed **what** is read from the freed block, not **that** it is
freed. Six attempts from the same angle is a review modality at its yield limit; the
close came from a decorrelated read with the toolchain's memory model in front of it,
not from a seventh attempt.

### The fix

The exit hook must not touch emutls storage **at all**. Per-thread state now lives in
a heap `EpochThreadRecord` owned by **our own `pthread_key_create`**, whose destructor
is **handed the record as its argument** — pthread key values live in the pthread TLS
array, not in emutls. It works for the unwired ninth thread too, which is the point:
an explicit "withdraw at thread exit" call would require the very wiring whose absence
is being detected.

The two hooks were also **merged into one**. Their being separate was itself a trap: a
thread's accusation was withdrawn by one destructor and its slot retired by another, so
the record count could reach zero while a slot still sat at 0 pinning the whole
graveyard. One hook, one order, one place to read.

Kept from the earlier work because it is right on its own terms: **the count is
authoritative and the id list is diagnostics.** A teardown path must not depend on a
lookup key surviving.

Also fixed, found by the same read: the **re-record branch never incremented `live`**
while every withdrawal path decrements it — so a thread that quiesced and then resolved
anyway **ate another thread's accusation**. An under-count, the opposite direction to
the phantom and the more dangerous one, because a cancelled accusation is a real
leaking thread the census stops reporting.

### The evidence

| check | before | after |
|---|---|---|
| `deferred_reclamation_tests`, 50 runs | ~47/50 | **50/50** |
| the TLS-teardown arm (2000 accused + 2000 participant exits under 8000 short-lived thread starts) | **the process died — every run, both halves independently** | **PASS, 3/3** |
| `scripts/check_thread_local_guard.sh` | — | **PASS**, 6 declarations, 0 unguarded; positive control fires |

The arm is in the suite permanently. It is deliberately the **last** arm, because it is
the only one that can leave the process dirty.

### The guard, because a comment has no decay function

Every `thread_local` in `src/` (tests excluded) must now be **trivially destructible**
and must carry a `static_assert` saying so **within six lines of its declaration** —
tight on purpose, so moving a declaration cannot leave its proof behind.
`scripts/check_thread_local_guard.sh` enforces it, fails closed if it finds **zero**
declarations (a broken instrument must not read as a pass), and has **no allowlist**: a
`thread_local` that cannot satisfy the assert is one that must not exist.

**It found a third production instance on its first run.** `src/net/connman.cpp` held a
`static thread_local std::random_device`, which is **not** trivially destructible on
this toolchain (measured; `std::mt19937_64` is) — so `~random_device()` was running
`_M_fini()` on freed storage at every connman thread exit. Now a leaked pointer, one
per thread, bounded by the thread count.

### What remains unsettled, and does not gate this

* Why plain `malloc`/`free` churn on long-lived threads never re-issued the block while
  a starting thread did (0/4000 vs ~4%). LFH per-thread affinity is the hypothesis; not
  measured, and it does not change the fix.
* Pthread key indices and the `elt` layout are read from the libgcc / libstdc++ /
  winpthreads sources rather than printed. The fact they predict — storage freed before
  the destructor — is measured at 100%.
* The `--wrap=free` tripwire is deliberately **not** ported into the build. It belongs
  in a probe, not in a shipping link line.


## WIRING CENSUS — checkpoints, offline scopes, and declared counts

Three separate things are wired per thread, and conflating them is what produced two
of this branch's defects:

1. **REGISTRATION** — the first *named* checkpoint. It must happen at thread ENTRY for
   any thread whose next act is to block, because the offline scope's checkpoint lives
   in its **destructor** and fires only when the wait RETURNS. Wiring registration
   through the scope alone meant an idle node's `rpc-accept`, `http-worker` and
   `websocket-server` never registered, and the startup gate **refused to start an
   idle node**. Caught by the node control, not by reading.
2. **THE PIN BOUND** — a loop-top checkpoint, which is where the thread provably holds
   nothing.
3. **THE OFFLINE WINDOW** — `EpochOfflineScope` around each blocking wait, so a parked
   thread pins nothing at all. Without it a loop-top checkpoint bounds the pin only
   for a thread that keeps looping.

| name | registration | loop-top checkpoint | offline scope around | declared count |
|---|---|---|---|---|
| `p2p-msg-handler` | loop top | `ThreadMessageHandler` top | `condMsgProc.wait_for` (bottom, 100 ms) | 1 |
| `p2p-headers-worker` | loop top | `HeadersWorkerThread` top | `m_headers_cv.wait` | 1 |
| `p2p-blocks-worker` | loop top | `BlocksWorkerThread` top | `m_blocks_cv.wait` | **`NUM_BLOCK_WORKERS`** |
| `headers-validation` | loop top | `ValidationWorkerThread` top | `m_validation_cv.wait` | **pool size** |
| `headers-processor` | loop top | `HeaderProcessorThread` top | `m_raw_queue_cv.wait` **(round-7 F45)** | 1 |
| `validation-worker` | loop top | before `m_queue_cv.wait` | `m_queue_cv.wait` | 1 |
| `txindex-sync` | loop top | `SyncLoop` top | — | 1 (conditional) |
| `coinstatsindex-sync` | loop top | `SyncLoop` top | — | 1 (conditional) |

> ⚠️ **THE `headers-processor` ROW CARRIED A `—` FOR THREE ROUNDS, AND A DASH IS NOT A
> DECISION** (round-7 F45). It meant "this thread has no offline scope", and the row
> disclosed that honestly — but disclosure is not closure, and nothing turned the
> disclosure back into a task. Meanwhile `HeaderProcessorThread` is the thread a
> HEALTHY, IDLE node sits in essentially all the time: its `m_raw_queue_cv.wait` ran
> ONLINE, so an idle node froze `DrainGraveyard`'s minimum at that thread's last
> loop-top epoch and nothing unlinked during the idle period could be freed. Same
> shape as the parked RPC participant the round-1 panel found (47.60 MB and climbing
> over 15 s), through a different door.
>
> Note what made it invisible: the thread **holds nothing** at that wait. **Pointer-free
> is not pin-free** — a thread pins by its PUBLISHED EPOCH. The pause path a dozen
> lines above was already offline; the wait that matters more was not.
>
> **A `—` in this table is now a finding, not a footnote.** Any row that has one must
> say why the thread cannot park with an epoch published, or get a scope.
| `rpc-accept` | **thread entry** | — | `accept()` | 1 |
| `rpc-worker` | loop top | before `m_queueCV.wait` | `m_queueCV.wait` | **`m_threadPoolSize`** |
| `http-worker` | **thread entry** | — | blocking `Dequeue` | **pool size** |
| `websocket-server` | **thread entry** | — | `accept()` | 1 (conditional) |
| `cached-stats` | loop top | `UpdateThread` top | — | 1 |
| `mining-worker` | hash-loop top | hash-loop top | — | **`m_nThreads`** (conditional) |
| `vdf-miner` | loop top | `MiningLoop` top | — | 1 (conditional) |
| `node-main-loop` | before the gate | loop top, before the 1 s sleep | — | 1 |

**Declared counts are per THREAD.** They were per *name* — a `std::set<std::string>` —
so one `rpc-worker` reaching its checkpoint satisfied the census for the entire pool,
and fifteen of sixteen could have been wired wrong. On a live relay-only node the
census went from **11 participants to 28** when the pools began declaring their real
sizes: the same node, counted honestly.

**Threads with no offline scope are the ones that sleep rather than block** (the sync
loops, cached-stats, the miners, the node main loop). Their pin is bounded by the sleep,
which is 1 s or less and is the wired cadence the occupancy table measures. A thread
that ever converts such a sleep into an indefinite wait must take a scope with it.

`mining-worker` checkpoints inside the hash loop: an acquire load plus a release store
against a loop body that computes a RandomX hash (~100 us light / ~1 ms full). Not
measurable.

### The RPC handler that blocks on a slow client — the exception, checked in the wild

COORD's question: the accept-thread checkpoint covers `accept()`, but a **handler**
thread that resolves a pointer, then blocks on a slow client write **while still holding
it**, is the exception this design names. Two independent answers, both measured:

1. **The handlers drop the pointer before any socket write.** The architecture forces
   it: every RPC method returns a fully-built `std::string`, and **every socket write
   happens in a caller frame**. `rpc/server.cpp` contains no `send()` inside any method
   body — the only write primitive is the `socket_write` lambda at `:987`, a local of
   `HandleClient`, invoked at `:2211` after `ExecuteRPC` (`:2145`) has returned. Worked
   example: `RPC_GetTransaction` resolves at `:3509`, last dereferences at `:3691`, then
   returns a string; the frame holding `pTip` is gone before a byte moves. Same shape for
   the REST branch (`rest_api.cpp:362` resolve, `:411` last deref, `server.cpp:1600`
   write), `/metrics` (`dilithion-node.cpp:3982` resolve, `:3984` last deref,
   `http_server.cpp:670`/`:682` write) and WebSocket (`server.cpp:7759` then `:7763`).
   The long-poll RPCs (`waitfornewblock`, `waitforblock`, `waitforblockheight`) are the
   sharpest case and are written correctly: the pointer lives only inside a `get_tip`
   lambda (`:10107`, `:10140`, `:10171`) that immediately converts to `{uint256, int}`,
   so a worker parked up to 300 s in `wait_until` holds **no** index pointer.
2. **And the checkpoint is at that boundary anyway.** `rpc-worker` sits at the worker
   loop top, so the pin bound is one whole request *including* the response write. That
   write is bounded: `SO_SNDTIMEO` and `SO_RCVTIMEO` are set to **10 s** per connection
   (`rpc/server.cpp:934-950`, the RPC-017 slowloris hardening). A slow client extends one
   thread's pin by seconds per `send()` call, not indefinitely.

So the answer is "both": the pointer is dead before the write **and** the boundary is
checkpointed. Answer 1 is the one that would silently stop being true if a handler ever
streamed a response while walking the chain — and answer 2 is what would keep the bound
finite if it did.

### The blocking-thread question, settled

**A thread that registers and then blocks for a long time pins nothing, because
the checkpoint goes BEFORE the block, not after the work.**

This is the whole reason for that placement. At the point just before
`cv.wait()` or `accept()`, the thread has finished its previous unit and started
no new one — it provably holds no `CBlockIndex*`. Publishing the epoch there means:

* an **idle** node's workers sleep for minutes on an empty queue having already
  published — they pin nothing while asleep;
* an **RPC server** sitting hours in `accept()` pins nothing;
* a sync loop waiting on I/O between passes pins nothing.

Checkpointing *after* the work instead would be exactly backwards: it would make a
thread hold the graveyard for precisely the period it is doing nothing, which is
when it is most obviously safe.

**So the bound per thread is ONE UNIT OF WORK, never the duration of a wait.**
The worst case is the longest single unit: a `ProcessBlock` containing a LevelDB
write, or one index walk pass. Those are the numbers to measure — not idle time,
which contributes nothing.

**The exception that would break this**: a thread that blocks on I/O *while
holding* a resolved pointer. None of the eight does today (the census found no
site retaining a pointer across an iteration boundary), and if one is ever added
it must checkpoint before blocking or drop the pointer first. That is the rule to
apply when the ninth thread arrives.

### A non-participant is a silent leak, so the node refuses to start

A thread that never checkpoints reads epoch 0 and pins the **entire graveyard for the
process lifetime**. That is the safe direction — nothing is freed on the account of a
thread that made no promise — but it is an unbounded leak in which the node behaves
perfectly and memory grows. The worst shape a defect can take, so it is asserted at
startup rather than trusted.

**Where it runs.** Both node binaries, immediately after the last thread spawn and
before entering the main loop: the main thread declares and checkpoints itself, then
`AwaitEpochRegistration(15000, why)` polls until every declared participant has
checkpointed. On failure the node **throws and exits non-zero** with the diagnostic —
it does not start. A 15 s deadline is generous because every checkpoint sits *before*
its thread's wait, so a thread reaches its first one as soon as it is scheduled; it does
not need work to arrive. A participant still missing after 15 s never checkpoints.

**Two failures, one gate:**

* a **declared** thread that never checkpointed — reported **by name**, so the log says
  `[coinstatsindex-sync]`, not "12 of 13";
* any thread that has **obtained a `CBlockIndex*`** while never having checkpointed —
  observed at the resolve, needing no list, which is the arm that catches a thread
  nobody declared.

**Declarations are made by the code that spawns the thread**, not by a static list:
`DeclareEpochParticipant("txindex-sync")` sits next to `std::thread(&CTxIndex::SyncLoop…)`.
That is deliberate — a static list cannot know whether the txindex thread was started on
*this* run, and a count that includes a thread the config never spawns would fail a
healthy node. Conditional subsystems (txindex, coinstatsindex, websocket, mining)
declare only when they actually start.

**Threads that start later are re-checked, not ignored.** The miners spawn when mining
begins, long after the startup gate. The main loop re-runs the census every ~300
iterations and logs `⚠️  GRAVEYARD PINNED: <name>` if a participant is missing. Refusing
to run is not on the table once the node is live: the consequence of the leak is that
the graveyard stops draining, which is safe and unbounded, and the operator watching
memory grow needs that line in the log to know why.
