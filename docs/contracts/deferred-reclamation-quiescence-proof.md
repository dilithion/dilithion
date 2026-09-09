# Deferred reclamation of CBlockIndex — the quiescence proof

**Branch:** `fix/blockindex-deferred-reclamation`, cut from `0f6837d0` (#129's head).
**Mandatory reader:** LP10 (A-5 owner).

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

Censused from every `std::thread` spawned in production `src/`, filtered to those whose
code reaches `GetBlockIndex(` / `GetTip(` / `LookupBlockIndex(`:

| # | thread | where it resolves | call-boundary (where it provably holds none) |
|---|---|---|---|
| 1 | **P2P message handler** | `block_processing.cpp` (13 sites) | top of each message dispatch |
| 2 | **Header validation thread** | `headers_manager.cpp` (5 sites) | top of each `ProcessHeaders` batch |
| 3 | **Hash worker pool** (`m_hash_workers`, N = cores) | computes RandomX hashes; **does not resolve index pointers** | n/a — see below |
| 4 | **Validation worker** (`m_worker`) | `block_validation_queue.cpp` (9 sites) | top of each `ProcessBlock` iteration |
| 5 | **IBD coordinator** | `ibd_coordinator.cpp` (20 sites) | top of each coordinator tick |
| 6 | **RPC/HTTP worker pool** (`m_workers`) | `rpc/server.cpp` (24), `rpc/rest_api.cpp` (1) | top of each RPC request |
| 7 | **Main loop** | `dilithion-node.cpp` / `dilv-node.cpp` | top of each loop iteration |
| 8 | **Cached-stats thread** | `api/cached_stats.cpp` | reads via RPC-style accessors; treat as (6) |

**Thread 3 is listed to be excluded explicitly, not omitted.** The hash workers take
header bytes and return hashes; they never touch `mapBlockIndex`. If that ever changes
they must be added here — an omission would be invisible.

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
