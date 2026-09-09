# Contract — close the block-index resolve→deref race at the four remaining sites

**Status:** OPEN. Opened 2026-09-09 as the named sibling of PR #129, at the moment
#129's fold was pushed, so that the deferral is a tracked deliverable with an owner
rather than a register row nobody carries.

**Why this exists as its own PR.** #129 closes this race at two sites with
`CChainState::MainLockGuard` and leaves it open at four more. Those four were not
folded into #129 because four widenings of `cs_main` — the lock that block
processing, `ActivateBestChain` and the RPC tip cache all contend on — need their
own deadlock argument, their own TSan evidence and their own red-first test. That
is not work that belongs inside a review fold, and #129's panel had already
returned one NO-GO on a smaller diff.

## The defect

`GetBlockIndex()` takes `cs_main`, looks up the hash, **releases `cs_main`**, and
returns a raw `CBlockIndex*`. A caller that then dereferences that pointer is
racing `EvictLowestWorkLeafNotPinned`, which frees unpinned leaf entries under
`cs_main` on another thread. The critical section is exactly
*[resolve `pprev`, insert the child]*: once the child is in the map naming `pprev`,
the parent has in-degree ≥ 1, is no longer a leaf, and is ineligible for eviction.
Before that instant it is naked.

## The four sites

| site | shape |
|---|---|
| `src/node/block_processing.cpp:1094 → :1274 → :1281 → :1287` | resolve `pprev`; deref `pprev->nHeight`; **LevelDB `WriteBlockIndex` inside the window**; `AddBlockIndex`. This file contains **zero** occurrences of `cs_main` or `MainLockGuard`. Widest window of the six — a disk write, so milliseconds rather than instructions. |
| `src/node/dilithion-node.cpp:6413 → :6432` | same shape |
| `src/node/dilithion-node.cpp:6622 → :6650` | same shape |
| `src/node/dilv-node.cpp:6431 → :6459` | same shape |

| `src/node/block_validation_queue.cpp` — `QueueBlock` | `GetBlockIndex(block.hashPrevBlock)` then `pParent->nStatus`, across a `cs_main` release. Found by the #129 non-author reader **in that PR's own file**. |

All five are **pre-existing** — they predate #129 and are not introduced by it.

## ⚠️ THE LIST ABOVE IS A FLOOR, NOT A CENSUS — and enumerating it is deliverable 0

#129 first said "four more sites". The reader then found a fifth *in the file #129
was editing*. That is the `a-fix-aimed-at-a-site-leaves-siblings` defect committed
while citing the lesson, and it means a hand-listed set must not be trusted as
complete a third time.

There are **~61 `GetBlockIndex(` call sites** across `block_processing.cpp` (13),
`block_validation_queue.cpp` (10), `dilithion-node.cpp` (14), `dilv-node.cpp` (12),
`ibd_coordinator.cpp` (9), `headers_manager.cpp` (1) and `orphan_manager.cpp` (1),
and they have never been swept for this shape.

**Deliverable 0, before any fix:** a mechanical, grep-driven enumeration of every
`GetBlockIndex(` call whose result is dereferenced or stored after the call
returns — script-generated with its output committed, not another hand count. The
fix list is then whatever that census produces. A site is cleared only by a written
reason it cannot race, never by absence from a list somebody typed.

## Reachability, stated correctly

An earlier framing said lowering the cap *creates* the exposure. It does not.
**Eviction is attacker-triggerable by header spam at any cap size**; the cap sets
the *price of the trigger* — roughly 2.1 GB of attacker-supplied headers at
5,000,000 versus ~210 MB at 500,000. The race is live at either value.

That is why the DilV cap reduction was pulled out of #129 and rides here: the cap
may only move together with the fix that makes moving it safe. Shipping a 10×
cheaper trigger for a live, unfixed UAF class — in the change whose header comment
advertises the class as closed — was the combination worth refusing.

## Deliverables

1. **`MainLockGuard` across [resolve, insert] at all four sites**, or, per site, a
   written reason it cannot race that does not depend on timing.
2. **A deadlock argument, and it is the contract.** `cs_main` vs `m_queue_mutex`
   (documented order is `cs_main → m_queue_mutex`; eviction holds `cs_main` and
   calls `GetPendingBlockHashes`, which takes `m_queue_mutex`), `cs_main` vs
   `ActivateBestChain` re-entry, and `cs_main` vs `cs_headers` — the last one is
   forward-only as of #183 and must be **re-verified**, not inherited, because
   #129 already found that paragraph stale once.
3. **A RED-first test at the `block_processing` site** that frees the parent inside
   the window and fails without the guard. Red before the fix exists, green after.
4. **A real queue-path regression harness**, inherited from #129's item 6: a live
   `CBlockValidationQueue` over an opened `CBlockchainDB`, driven through the public
   `Start`/`QueueBlock`/`WaitForBlock` surface, with a **deliberately wrong cached
   `pindex`** passed to `QueueBlock` so that any code reading it yields an
   observably wrong answer. This is the guard-removal → RED property that #129's
   Test 7 could not supply. Same infrastructure as (3).
5. **TSan across the new edges with a positive control** — an arm that proves the
   harness can still report an inversion, so a clean result is not "the harness
   never wired it up".
6. **The DilV cap reduction 5,000,000 → 500,000**, landing only once 1–5 hold, with
   its grounds re-argued on their own merits (attack headroom; eviction-scan cost
   per over-cap insert; the honest-path saturation horizon — DilV's 45 s blocks
   reach a 500K cap in ~8.7 months against DIL's ~3.8 years at the identical
   number, so "matching DIL" is not a justification). No memory-ceiling claim: the
   cap is advisory, so it is a target and the pinned set is the real floor.
7. **Measure the post-saturation cost** the panel asked for: per over-cap insert is
   O(n log n) with allocations under `cs_main`, and a full drain is O(n² log n).
   Measure at 500K before relying on the reduction, and record the honest-height
   ceiling as a register row needing a disk-backed index or pruning.

## Not in scope

- `GetLocator`/`ProcessHeaders` take-and-release (reader M-1) — same released-pointer
  class, but it is LP10's A-5 charter, which retires runtime eviction entirely.
- `m_stats_mutex`/`m_queue_mutex` ordering at `block_validation_queue.cpp:225-226`
  vs `:266`/`:295` (reader M-2), and `node_context` `Reset()`-without-`Stop()`. Both
  pre-existing and outside this diff; filed as rows.

## Review bar

Touches `src/` and is not test-only, so **D-DIL-2026-09-08-4 applies**: an external
cross-family seat on the raw diff at PR open, plus one independent non-author read.
Consensus-adjacent and concurrency-touching, so TSan is mandatory rather than
advisory.

## NOT IN SCOPE HERE: the eviction COST fix — it landed in #129

For a while the plan was for #129 to ship the leaf-only UAF fix and hand the
performance problem to this PR. It did not work out that way, and the record
matters so nobody re-opens it:

* #129's leaf-only evictor was **measured at 2.31x main's cost** per over-cap
  insert at a 500,000-entry index (485.4 ms vs 210.6 ms of `cs_main` hold,
  43 MB vs 20 MB transient) — on the has-evictable-leaves path an attacker
  reaches by spamming headers to the cap. That made it merge-blocking: a
  hardening PR that closes a UAF by making a remote CPU-DoS cheaper is a bad
  trade.
* It was fixed **in #129** with an evictable-leaf side index (O(log n) victim
  selection), landing at **0.008 ms and 0 KB transient**. CON-27 carries the
  numbers and the method.
* The reasoning for putting it there rather than here: the algorithm's cost fix
  belongs with the algorithm and its review. Making a UAF fix depend on THIS
  PR's bundle — four foreign-file guards, their deadlock argument, the
  ~61-call census and the cap reduction — is the wrong dependency direction.

**So this contract's scope is unchanged.** Do not add "incremental in-degree" or
"evictable-leaf side index" as a deliverable here; both are already shipped in
#129. What remains here is exactly what is listed above.
