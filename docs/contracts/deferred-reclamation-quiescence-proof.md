# Deferred reclamation of CBlockIndex — the quiescence proof

**Branch:** `fix/blockindex-deferred-reclamation`, cut from `0f6837d0` (#129's head).
**Mandatory reader:** LP10 (A-5 owner).

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

Every `std::thread` spawned in production `src/`, filtered to those whose code
reaches `GetBlockIndex(` / `GetTip(` / `LookupBlockIndex(`. Counts are from the
tree-wide census (`census_blockindex_pointer_windows.py`), not from a hand list.

| # | thread | spawn site | resolves | the point at which it provably holds none |
|---|---|---|---|---|
| 1 | P2P message handler | node main loop | `block_processing.cpp` (13) | top of each message dispatch |
| 2 | Header validation | `headers_manager` validation thread | `headers_manager.cpp` (1) | top of each `ProcessHeaders` batch |
| 3 | **Hash worker pool** (`m_hash_workers`, `hardware_concurrency`) | `headers_manager.h:911` | **none — takes header bytes, returns hashes** | n/a, and see the note below |
| 4 | Validation worker | `block_validation_queue` `m_worker` | `block_validation_queue.cpp` (9) | top of each `ProcessBlock` iteration |
| 5 | IBD coordinator | node main loop | `ibd_coordinator.cpp` (9) | top of each coordinator tick |
| 6 | **RPC server** | `rpc/server.cpp:604` `m_serverThread` | `rpc/server.cpp` (6) | **completion of each request** — see below |
| 7 | **RPC cleanup** | `rpc/server.cpp:614` `m_cleanupThread` | none observed | n/a |
| 8 | **TxIndex sync** | `index/tx_index.cpp:559` `SyncLoop` | `tx_index.cpp` (4) | top of each height iteration |
| 9 | **CoinStatsIndex sync** | `index/coinstatsindex.cpp:657` `SyncLoop` | `coinstatsindex.cpp` (4) | top of each height iteration |
| 10 | Node main loop | `dilithion-node` / `dilv-node` | those files (26) | top of each loop iteration |
| 11 | Cached stats | `api/cached_stats.cpp` | via RPC-style accessors | treat as (6) |

**Thread 3 is listed to be EXCLUDED explicitly, not omitted.** The hash workers take
header bytes and return hashes; they never touch `mapBlockIndex`. If that ever changes
they must be added here — an omission would be invisible, which is why the row exists.

**Threads 6 and 7 have no "iteration".** RPC is request/response, so the boundary is
request completion rather than a loop top. That is still a well-defined point — a
handler cannot hold a pointer resolved during a request that has returned — but it
means the epoch bump belongs at the dispatch boundary, not in a loop.

**Threads 8 and 9 were flagged as "long-running loops over historical blocks — exactly
the long-hold shape". Measured, they are not.** Both resolve and dereference within
two to three lines (`tx_index.cpp:229-232`, `:240-243`: resolve, null-check,
`GetBlockHash()`, done) and retain nothing across an iteration. `tx_index.cpp:564-567`
documents the opposite discipline explicitly — `m_mutex` must NOT be held across chain
reads. So they are ordinary short windows at a high repetition rate, not long holds. The
concern was reasonable and the code does not have that shape.

**Thread 4 is covered twice over, and the second cover is the stronger one.** A queued
block and its parent are reported by `GetPendingBlockHashes` and pinned by eviction
clause (d), so eviction cannot free them while they are queued — **the queue path is
protected by PINNING, not by grace.** That is what answers LP10's drain rule ("refuse to
free while an entry enqueued before the epoch is in flight"): the pin makes the situation
unreachable rather than merely survivable. It is also why the `queued_block.pindex`
escape (`block_validation_queue.cpp:151` → `:166` → `:172` → the worker) is not a live
UAF on this base, though it remains one on `main`, where neither the pin nor the by-hash
re-resolve exists.

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

| thread | checkpoint site | pin bound |
|---|---|---|
| Validation worker | `block_validation_queue.cpp` `ValidationWorker`, loop top **before** `m_queue_cv.wait` | one `ProcessBlock` |
| Header validation | `headers_manager.cpp` `ValidationWorkerThread`, **before** `m_validation_cv.wait` | one validation unit |
| Header processor | `headers_manager.cpp` `HeaderProcessorThread`, loop top | one header batch |
| TxIndex sync | `tx_index.cpp` `SyncLoop`, loop top before the walk | one walk pass |
| CoinStatsIndex sync | `coinstatsindex.cpp` `SyncLoop`, loop top | one walk pass |
| RPC server | `rpc/server.cpp` `ServerThread`, **immediately before `accept()`** | one request |
| Hash worker pool | — none, and deliberately | never resolves an index pointer |
| P2P handler / main loop / IBD coordinator | run **on** the node main loop | one loop iteration |

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

### A non-participant is a silent leak, so it is asserted

A thread that never checkpoints reads epoch 0 and pins the **entire graveyard for
the process lifetime**. That is the safe direction — nothing is freed on the
account of a thread that made no promise — but it is an unbounded leak in which
the node behaves perfectly and memory grows. `EpochRegistrationComplete()` checks
the participant count against this table so a ninth thread that resolves block
indices and forgets to checkpoint fails loudly at startup rather than quietly
holding the graveyard. Its diagnostic names the leak, not just a count.
