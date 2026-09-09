# Where to fix the released-CBlockIndex\* class: consumers, producer, or the free itself

**Author:** 2f. **Mandatory reader:** LP10 (A-5 owner — the released-pointer class is
its charter). **Status:** recommendation, not a decision.

**Recommendation up front: OPTION 2 — deferred reclamation at the producer.** Reasons
and the case against it are below; the fallback if its quiescence proof cannot be made
cleanly is Option 3, and Option 1 should not be built at all.

---

## The situation, measured

* **52** `GetBlockIndex(` call sites across the five node/net files; **41 UNGUARDED** —
  resolve a `CBlockIndex*`, then dereference/walk/store it after `cs_main` is released.
  (`scripts/census_blockindex_pointer_windows.py`, committed; GUARDED arm
  positive-controlled against #129's branch, self-check on every cited line.)
* **Exactly one runtime free path.** `mapBlockIndex.erase` inside the evictor. The only
  other mutations are teardown `clear()` and first-time insert. There is no pruning,
  reorg-cleanup or reindex path that frees an index entry at runtime.
* `sizeof(CBlockIndex)` = **320 bytes** (measured, not estimated).
* Header ingress is rate-limited: **5000 headers / 60 s window** per peer
  (`chainparams.h:187,196` defaults).
* `pskip` is **inert** — only ever assigned `nullptr` or copied; no `BuildSkip` exists.
* `pnext` is **live** (24 production uses), set on connect and cleared on disconnect.

**41 consumers, 1 producer.** That asymmetry is the whole argument.

---

## Option 1 — guard the 41 consumers

Wrap each resolve→use window in a `cs_main` holder, with a per-site deadlock argument
and TSan across them.

* **#129 as merged:** unaffected.
* **The 41:** all fixed, one at a time.
* **A-5:** unaffected; eviction stays.
* **Memory under 500K spam:** unchanged.

**Why not.** This is a fix aimed at consumers when the defect has one producer, and the
repo has already paid for that mistake three times in this PR alone — a guard applied at
one site and not its sibling, twice, and a "four sites" list that was really five. The
census exists *because* hand-scoped consumer fixes kept missing members of their own
population.

Three further costs, in order of how much they should worry us:

1. **It does not close the class, it enumerates it.** Every future `GetBlockIndex`
   caller is a new landmine, and the guard is invisible to a reviewer who does not
   already know the rule. The census would have to be re-run forever as a CI gate — and
   a lexical scanner as a merge gate will produce false positives that get switched off.
2. **41 `cs_main` widenings on the hottest paths.** `cs_main` is what block processing,
   `ActivateBestChain` and the RPC tip cache contend on. #129 already had to refuse a
   single wide guard across `CheckProofOfWorkDFMP` for exactly this reason. Forty-one of
   them, written under review pressure, is a contention regression waiting to be found
   by a deploy.
3. **41 deadlock arguments.** The `cs_main → cs_headers` order was established by
   #183 and #129 both had to reason about it. Each new hold is a new chance to invert it.

---

## Option 2 — deferred reclamation at the producer *(RECOMMENDED)*

Eviction **unlinks** immediately — out of `mapBlockIndex`, the leaf index and the
candidate set — so a by-hash re-resolve returns null exactly as today. The
`CBlockIndex` *memory* moves to a graveyard and is freed only at a point where no raw
pointer to it can be live.

* **#129 as merged:** stays, unchanged and still correct. The advisory cap, the leaf
  index and the O(log n) selection are all orthogonal to *when the memory is released*.
  This is additive.
* **The 41:** all 41 windows become safe **without touching any of the 41 files**. A
  pointer resolved under `cs_main` and used after release now points at memory that is
  still valid for the duration of the call. They stop being landmines.
* **A-5:** compatible. If A-5 later deletes runtime eviction, the graveyard becomes dead
  code and is removed; nothing built here has to be unbuilt first.
* **Memory under 500K spam:** bounded by *evictions per grace period*, not by total
  evictions. Ingress is capped at 5000 headers/60 s/peer, so at 125 peers the ceiling is
  ~10,400 evictions/s. With a 1 s grace that is ~10,400 × 320 B ≈ **3.3 MB**; at 10 s,
  ~33 MB — against a 500K-entry index that is already ~160 MB. **Measure it, do not
  trust this arithmetic**: the same `evict_cost_bench` fixture can report peak graveyard
  occupancy directly.

### The quiescence proof, which is where the risk actually lives

The drain point must be one where no raw `CBlockIndex*` obtained before it can still be
held. **Proposed: the top of each message-handler / validation-worker iteration**, with
the claim that no site retains a pointer across an iteration boundary.

That claim is exactly what the census can be extended to check mechanically — flag any
site that stores a resolved pointer into a member, a static, or a container rather than
a local. **That extension is a prerequisite, not a nicety**: an epoch scheme whose
quiescence claim rests on a human reading 41 sites has the same weakness as Option 1,
just concentrated. It should be a gate, and it is small — the tool already binds the
variable and finds its first use.

### Graveyard pointer hygiene, stated explicitly

* A graveyard entry's **`pprev` points INTO the live map**. That is memory-safe (the
  parent is alive) but must never be treated as reachability: nothing may walk *from*
  the map *into* the graveyard, which is what "unlinked" buys.
* A graveyard entry's **`pnext` is null by construction** — `pnext` is set only for
  active-chain members, and active-chain ancestors are pinned by eviction clause (a), so
  an entry with `pnext` set is never evictable. **A walk from a graveyard entry
  terminates at once.** (Assert it at unlink time rather than relying on the argument.)
* **`pskip` is inert**, so it cannot resurrect a graveyard entry. If `BuildSkip` is ever
  implemented, this note must be revisited — add that to the A-5 charter.

---

## Option 3 — delete runtime eviction (A-5), bound header-spam differently

No free at runtime ⇒ no dangling pointer ⇒ the class disappears, with no graveyard and
no quiescence proof. Header-only, off-active-chain entries get their own cap enforced at
**header acceptance**: refuse the header, never free an index entry.

* **#129 as merged:** substantially undone. The leaf index, the advisory-cap semantics
  and the eviction cost work all become dead code. That is not an argument against it —
  but it should be said plainly rather than discovered at review.
* **The 41:** all safe, permanently and by construction. The strongest outcome of the three.
* **A-5:** this *is* A-5, brought forward.
* **Memory under 500K spam:** bounded by the new header-only cap, which is a smaller and
  more honest bound than today's.

**The objection, and it is the one that decides between 2 and 3.** #129 established —
after measurement and a panel round — that *"refusing to extend the chain is strictly
worse than exceeding a soft memory target"*, and made the cap advisory for that reason.
Option 3 reintroduces refusal. The mitigation is real (it refuses only header-only
off-active-chain entries, so honest height never trips it), but the failure mode is
that **an attacker who fills the header-only budget can block the headers of a
legitimate deep reorg** — a censorship vector, not merely a memory one. Establishing
that this is acceptable needs the same care #129 spent establishing the opposite.

**A-5's premise also needs re-checking before this is chosen.** A-5 rests on "eviction
is reachable only by low-work header spam". #129 added candidate and pending-block pins
since that was written, which changes what is evictable; and the regtest reproduction
showed the honest path reaching the cap at ordinary heights. The premise is probably
still true on production caps, but it is not the same premise it was.

---

## Recommendation

**Option 2**, for three reasons:

1. **It fixes the class at its one producer and leaves #129 intact.** Options 1 and 3
   both spend the work already done — 1 by adding 41 new obligations beside it, 3 by
   deleting it.
2. **It is compatible with Option 3 rather than competing with it.** If A-5 later
   removes eviction, the graveyard is deleted and nothing is stranded. Choosing 2 now
   does not foreclose 3; choosing 3 now forecloses the advisory-cap decision #129 just
   made on evidence.
3. **Its risk is one proof, and the proof is mechanisable.** Option 1's risk is 41
   human judgements that must all be right and stay right. I would rather defend one
   invariant that a script re-checks than 41 that a reviewer re-reads.

**The load-bearing claim is now MEASURED, not assumed.** I wrote the paragraph above
saying the drain point was what I was least sure of and that the tool should be extended
before the decision rather than after — so I extended it rather than filing the caveat.

`census_blockindex_pointer_windows.py` now also classifies **OUTLIVES-CALL**: a resolved
pointer stored into a member (`m_*`), a global (`g_*`), a struct field, or a container —
i.e. somewhere it can be read on a LATER iteration, which a per-iteration grace period
would NOT cover. Result over the same 52 sites:

    OUTLIVES-CALL   3
    UNGUARDED      38
    UNKNOWN         0
    GUARDED         0
    NO-WINDOW      11

**All three were inspected by hand, and all three are index-graph linkage, not escapes:**

| site | the store | verdict |
|---|---|---|
| `block_validation_queue.cpp:444` | `pOrphanIndex->pprev = pOrphanParent;` | writes the parent into a NEW entry's `pprev` |
| `dilithion-node.cpp:3008` | `pblockIndexPtr->pprev->pnext = pblockIndexPtr;` | active-chain `pnext` linkage |
| `dilv-node.cpp:2874` | same as above | active-chain `pnext` linkage |

> ## ⚠️ RETRACTED — THE SENTENCE BELOW IS FALSE
>
> It read: *"Zero sites store a resolved `CBlockIndex*` into a member, a global, or a
> container."* That was the headline claim this recommendation leaned on, and LP10's
> read (BLOCKER 1) refuted it.
>
> **The counter-example is one the scanner cannot see by construction.**
> `block_validation_queue.cpp:151` resolves `existing`; `:166` stores it into a **local
> struct**; `:172` copies that local into `m_queue`; `:349` reads it back in
> `ProcessBlock` on the worker thread, arbitrarily later, bounded only by queue depth.
> My tool binds the resolved variable and inspects its first *use* — the escape is six
> lines away through a struct copy, and the variable's name is gone by then. A
> first-use scanner cannot answer a lifetime question, and I presented its silence as
> a finding.
>
> **Until the tool classifies local→container escapes and is re-run tree-wide, treat
> the escape analysis in this note as UNMEASURED.** The count below (3 OUTLIVES-CALL)
> is a floor, not a census — the same error I flagged in #129's "four more sites", made
> by me, one document later.
>
> **What survives the retraction**, and it is why the conclusion still holds: on #129's
> base the queue path is covered by **pinning**, not by grace. A queued block and its
> parent are reported by `GetPendingBlockHashes` and pinned by eviction clause (d), so
> eviction cannot free them while they are queued, and `ProcessBlock` no longer reads
> the cached pointer at all — it re-resolves by hash. That is precisely why this work
> is based on #129 and not on `main`, where neither protection exists.

The original sentence, kept visible rather than deleted:

~~**Zero sites store a resolved `CBlockIndex*` into a member, a global, or a container.**~~
Every retained pointer is stored *inside the block-index graph*, which the graveyard
design already reasons about explicitly: `pnext` is null on anything evictable, and a
`pprev` written into a new child makes the parent non-leaf and therefore non-evictable
under #129's leaf-only rule.

So the per-iteration grace point is sound on the evidence available, and Option 2's
principal risk is smaller than I priced it two paragraphs ago. **What remains unproven is
the negative:** the scanner is lexical, so it cannot see a pointer that escapes through a
helper function or an alias. That is the residual, it is the right thing for LP10 to
attack, and it is one question rather than 41.

Option 1 should not be built under any of these outcomes.
