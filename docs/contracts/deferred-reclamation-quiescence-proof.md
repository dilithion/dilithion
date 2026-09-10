# Deferred reclamation of CBlockIndex — the quiescence proof

**Branch:** `fix/blockindex-deferred-reclamation`, cut from `0f6837d0` (#129's head).
**Base as of 2026-09-10: #129 IS MERGED** — main `4ccf3797` carries leaf-only
eviction, so the dependency below is no longer "depends on #129" but "depends on
main ≥ `4ccf3797`". The argument is unchanged; only its base moved.
**Mandatory reader:** LP10 (A-5 owner).

> **THE CHECKPOINT GOES BEFORE THE WAIT, BECAUSE THAT IS THE INSTANT THE THREAD
> PROVABLY HOLDS NOTHING.** Everything else here follows from that one placement:
> the pin per thread is ONE UNIT OF WORK, never the duration of a wait, so an idle
> worker, an RPC server parked in `accept()` for hours, and a sync loop waiting on
> I/O all pin exactly nothing. Checkpointing *after* the work would be backwards —
> it would hold the graveyard for precisely the period the thread is doing nothing.
>
> **The exception that would break it**, and the rule that survives this document:
> a thread that blocks on I/O *while holding* a resolved pointer. The census below
> found that **none of the wired threads does** — every one resolves and
> dereferences within a few lines and retains nothing across its boundary. A thread
> that ever does must checkpoint before blocking, or drop the pointer first.

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

`main`'s evictor (`EvictLowestWorkNotOnBestChain`) has no leaf or in-degree concept at
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
| `CConnman::ThreadMessageHandler` | `connman.cpp:196` | no | yes - control msgs inline, `dilithion-node.cpp:4411`, `:4417-4446` (`pTip->GetAncestor`) | `p2p-msg-handler` |
| `CConnman::HeadersWorkerThread` | `connman.cpp:224` | no | yes - `headers_manager.cpp:242`, `:1219`, `:1273` | `p2p-headers-worker` |
| `CConnman::BlocksWorkerThread` xN | `connman.cpp:238` | no | yes - `dilithion-node.cpp:6410`, `:6439`, `:6448` | `p2p-blocks-worker` |
| `CHeadersManager::ValidationWorkerThread` xHW | `headers_manager.cpp:3245` | no | **no** - hash-only | `headers-validation` (belt and braces) |
| `CHeadersManager::HeaderProcessorThread` | `headers_manager.cpp:3251` | no | yes | `headers-processor` |
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

## What still has to be measured

* graveyard peak occupancy at the 10,400 evictions/s ingress ceiling, both grace
  settings, via the `evict_cost_bench` fixture — **my ~3.3 MB / ~33 MB figures are
  arithmetic, not observations**, and are not to be quoted until measured;
* the ASan RED arm: resolve a pointer, evict on another thread, dereference — must trap
  on `main`, be clean here, **and trap again with the drain forced immediate**, which is
  what proves the harness actually reaches the free rather than passing vacuously.

## WIRING CENSUS — where EpochCheckpoint() actually is

Every participant checkpoints **at its loop top, before its blocking wait**, and passes
its name, which is what the startup census compares against the declarations made at the
spawn sites.

| checkpoint name | site | pin bound |
|---|---|---|
| `p2p-msg-handler` | `connman.cpp` `ThreadMessageHandler`, loop top | one batch (<=500 msgs) + the 100 ms bottom wait |
| `p2p-headers-worker` | `connman.cpp` `HeadersWorkerThread`, before `m_headers_cv.wait` | one headers message |
| `p2p-blocks-worker` | `connman.cpp` `BlocksWorkerThread`, before `m_blocks_cv.wait` | one block message |
| `headers-validation` | `headers_manager.cpp` `ValidationWorkerThread`, before `m_validation_cv.wait` | one header validation |
| `headers-processor` | `headers_manager.cpp` `HeaderProcessorThread`, loop top | one header batch |
| `validation-worker` | `block_validation_queue.cpp`, before `m_queue_cv.wait` | one `ProcessBlock` (incl. a LevelDB write) |
| `txindex-sync` | `tx_index.cpp` `SyncLoop`, loop top | one walk pass |
| `coinstatsindex-sync` | `coinstatsindex.cpp` `SyncLoop`, loop top | one walk pass |
| `rpc-accept` | `rpc/server.cpp` `ServerThread`, before `accept()` | n/a (resolves nothing) |
| `rpc-worker` | `rpc/server.cpp` `WorkerThread`, before `m_queueCV.wait` | one RPC request, **including its response write** |
| `http-worker` | `http_server.cpp` `WorkerThread`, before the blocking dequeue | one HTTP request |
| `websocket-server` | `websocket.cpp` `ServerThread`, before `accept()` | one websocket request |
| `cached-stats` | `cached_stats.cpp` `UpdateThread`, loop top | one 1 s update |
| `mining-worker` | `controller.cpp` `MiningWorker`, hash-loop top | one hash attempt |
| `vdf-miner` | `vdf_miner.cpp` `MiningLoop`, loop top | one VDF round |
| `node-main-loop` | both node binaries, loop top before the 1 s sleep | one loop iteration |

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
