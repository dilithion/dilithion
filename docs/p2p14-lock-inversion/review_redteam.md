# P2P-14/15 red-team — branch `fix/p2p14-15-cs-headers-lock-order` @ `9f594a99`

Fresh-context adversarial pass. Read-only; no builds, no git writes. **I had no Bash tool, so I could
not run `git diff origin/main...HEAD`** — every judgement below is from reading the post-fix tree
(`C:/tmp/a8-p2p15`) plus the branch's own evidence files. Where a verdict depends on knowing the
PRE-fix text, I say so explicitly rather than guessing.

Family A routing applied (lenses 1,2,3,4 + 6, 8).

---

# Findings

## BLOCKER
None.

## HIGH

### H-1 — "the ratified order in net.h where cs_headers sits ABOVE both" is FALSE at source
`connman.cpp:1734` and `docs/p2p14-lock-inversion/scope_analysis.txt:24-26` both cite net.h as the
authority that ratifies `cs_headers` ABOVE `cs_vNodes`/`cs_peers`.

`net.h:338-353` — the file's only lock-order block — reads:

```
//     cs_vNodes  →  cs_peers  →  {cs_getdata_rate, cs_headers_rate, cs_served_blocks}
```

`cs_headers` **does not appear in it** (`cs_headers_rate` is a different mutex). `connman.h:321-324`
ratifies only `cs_vNodes → cs_peers/cs_nodes`; `peers.h:211` only `cs_vNodes → cs_peers → cs_nodes`;
`block_tracker.h:480` only says `{cs_vNodes, cs_peers, cs_headers} → block_tracker.m_mutex`, which
constrains none of the three against each other. Nowhere in `src/net` is the claimed ordering ratified.

Why it is load-bearing, not a nit: the direction is what decides whether the six surviving sites at
`headers_manager.cpp:351/498/530/674/2917/2987` (all calling `Misbehaving`/`PushMessage` **while
holding cs_headers**, i.e. `cs_headers → cs_peers` and `cs_headers → cs_vNodes`) are "conforming" or
"violations". `scope_analysis.txt:24` declares them conforming by appeal to a rule that does not
exist. This branch is in fact **choosing** that direction (a defensible choice — it moves one site
instead of six) and writing the choice into the tree as if it were inherited governance. That is the
fabricated-ratification class.

Concrete consequence, not hypothetical: the invariant the whole `DisconnectNodes` rewrite rests on is
**not written in the place the codebase designates for lock order**. `net.h:340` is unchanged by this
branch. A future maintainer who re-adds a dispatch under `cs_vNodes` (or reads net.h as authoritative
and "restores" the old shape) reintroduces `cs_vNodes → cs_peers → cs_headers` vs the live
`cs_headers → cs_vNodes` at `headers_manager.cpp:498`, and nothing catches it —
`scripts/check-tip-notify-drain.sh` guards only the `cs_main` half.

Fix: state the full order in `net.h` (`cs_headers → cs_vNodes → cs_peers → {rate-limit}`), label it as
ratified BY this change with the date/PR, and either extend the guard script to assert "no outbound
peer/headers dispatch inside a `cs_vNodes` scope in connman.cpp" or say plainly that half is unguarded.

Classification: asserted as **inherited**; actually **reasoned/new**.

### H-2 — exception between phases 1 and 2 of `DisconnectNodes` leaves dangling `node_refs`
`connman.cpp:1759-1794`. Phase 1 moves the `unique_ptr<CNode>`s out of `m_nodes` into local
`detached`. Phase 2 loops dispatch → `RemoveNode` → `CloseSocket`. `detached` unwinds at `:1794`.

If **any** phase-2 call throws — `DispatchPeerDisconnected` (`connman.cpp:65-70`) →
`CPeerManager::OnPeerDisconnected` → headers-manager / DNA-collector / `std::bad_alloc`; none of it is
`noexcept` — the loop is abandoned and `detached`'s destructor runs, destroying **every remaining
CNode without ever calling `RemoveNode`**. `CPeerManager::node_refs` (`peers.cpp:1821-1843`) keeps raw
`CNode*` entries pointing at freed memory, and `GetNode()` (`peers.cpp:1845-1853`) will hand those
pointers out to `Misbehaving` (`peers.cpp:589-593`, `it->second->MarkDisconnect()`), to
`PeriodicMaintenance` (`peers.cpp:1124`), to `GetConnectionCount` (`peers.cpp:376`). That is BUG #148
("no node_ref may outlive its CNode") and BUG #153 violated on the throw path — a use-after-free, not
a leak.

Failure sequence:
1. ThreadSocketHandler → `DisconnectNodes()`; three nodes marked, all three detached at `:1768`.
2. Node #1: `DispatchPeerDisconnected` throws (any exception from the peers/headers/DNA chain).
3. Stack unwinds past `:1793`; `detached` destructor frees CNodes #2 and #3.
4. `node_refs` still holds `id2→freed`, `id3→freed`; peers map still holds their `CPeer`s.
5. Next `PeriodicMaintenance` tick calls `GetNode(id2)->fManual` → UAF.

Pre-fix this could not happen in the same way: the CNode stayed **owned by `m_nodes`** until after
`RemoveNode`, so an escaping exception left the node alive and re-reapable, not freed. The rewrite is
what makes the throw path destructive. Cheap fix: wrap the phase-2 body in `try/catch(...)` per node,
or drive phase 2 from a scope-guard that guarantees `RemoveNode(node->id)` for every element of
`detached`.

Note the comment at `:1757-1758` — "Destroying them here rather than inside the lock is **strictly**
safer than before: the CNode now provably outlives RemoveNode" — is true only on the non-throwing
path. "Strictly safer" is **reasoned, and overstated**; on the throw path it is strictly less safe.

### H-3 — deferred firing removes the cross-thread serialisation of tip callbacks (new concurrency contract, undocumented)
`chain.cpp:2581-2619`. Pre-fix, `NotifyTipUpdate` invoked callbacks **under `cs_main`**, so tip
callbacks were mutually exclusive and strictly ordered network-wide. Post-fix, `DrainTipNotifications`
swaps the queue under the lock and then fires **with no lock held**, so two threads can be inside the
callback list simultaneously, and a later tip's callback can COMPLETE BEFORE an earlier tip's.

Failure sequence (two block-processing threads — `block_validation_queue.cpp:402` worker plus
`block_processing.cpp:945/1468`, plus `chain_selector_impl.cpp:213`, all call `ActivateBestChain`):
1. T1 activates height 100, queues N100 (`chain.cpp:2551`), guard releases at `:1328`.
2. T1's drain takes cs_main, swaps out `[N100]`, releases, and begins firing.
3. T2 acquires cs_main, activates height 101, queues N101, releases.
4. T2's drain swaps out `[N101]` and fires it — **concurrently with T1 still inside N100**.
5. `CHeadersManager::OnBlockActivated` (`headers_manager.cpp:958-1043`) therefore runs re-entrantly
   from two threads, and `UpdateBestHeader(hash)` at `:981`/`:1036` can be reached with the height-100
   hash *after* the height-101 hash.

Whether that regresses `hashBestHeader` depends on `UpdateBestHeader`'s comparison (I did not open it
— see coverage gaps), but the *contract change* is real and is documented nowhere: the header block at
`chain.h:964-996` and the comment at `chain.cpp:2601-2605` claim only "per-activation order is
preserved", which is true and beside the point — the property that was silently dropped is
**cross-activation** ordering and mutual exclusion. Any registered consumer that was implicitly
serialised by cs_main (the two node binaries' lambdas at `dilithion-node.cpp:3555` /
`dilv-node.cpp:3375`, and every future one) must now be re-entrant and monotonic on its own.
`chain.cpp:2604-2605` is **reasoned and narrower than it reads**.

Secondary, same site: a thread that has finished its own activation can block in
`DrainTipNotifications` on `cs_main` (`:2593`) behind another thread's *entire* activation, and can
then be made to run that other thread's callbacks. Latency and attribution both move; neither is noted.

## MEDIUM

### M-1 — the accessor GREEN arm has no discriminating power; its stated conclusion is unsupported
`src/test/p2p14_lock_inversion_tsan_tests.cpp:181-255` +
`docs/p2p14-lock-inversion/tsan_accessor_safe_GREEN.err`.

The unsafe arm reads `p->nStatus` outside the lock (`:215`) while the writer mutates `nStatus`
(`:233`) — TSan reports the race, correctly RED. The safe arm reads **`nHeight`** via
`GetBlockHeightByHash` (`:221`), and the writer sets `dup->nHeight = 0` on every iteration (`:232`) —
i.e. **nothing ever writes a different value to the field the safe arm reads**. A deliberately
*unsafe* read of `nHeight` (pointer escaped, unlocked deref) would have been green in this fixture
too. The GREEN is fully explained by the field choice, independent of the mechanism.

The file states the confound honestly at `:173-180` ("differ in field as well as in mechanism… NOT a
same-field A/B") and then draws exactly the conclusion the confound forbids: "That makes this a
demonstration that POINTER ESCAPE races and VALUE RETURN does not" (`:176-178`). It demonstrates no
such thing. This is **reasoned, presented as measured**. Either add a value accessor for `nStatus` and
re-run the A/B on the same field, or downgrade the claim to "the unsafe pattern is RED here; the safe
arm is not a control for it."

(The fix at `chain.cpp:198-210` is nonetheless correct on inspection — read+deref+copy inside one lock
scope. The defect is in the evidence, not the code.)

### M-2 — `GetBlockHeightByHash` closes one of at least three instances of the pattern it names, and leaves a comment that is now false
`chain.h:643-664` states the doctrine "return the value, never the pointer… the read and the
dereference happen inside one lock scope." It is applied at exactly one call site
(`headers_manager.cpp:1017-1020`). In the same file, unchanged:

- `headers_manager.cpp:1104` — `CBlockIndex* pTip = g_chainstate.GetTip();` then, holding only
  `cs_headers`, `GetLocatorImpl` walks `pTip->GetAncestor(height)` (`:1158`) — a `pprev`/`pskip` walk
  on an escaped pointer, outside `cs_main`, against the eviction path
  (`EvictLowestWorkNotOnBestChain`, `chain.cpp:221`, erases and destroys `CBlockIndex`es). The file's
  own comment at `:48` already admits pskip is "mutated outside cs_main".
- `headers_manager.cpp:219-220` — same prefetch pattern into the same walker.

And the rationale comment at `headers_manager.cpp:1102-1103` now reads:
`(OnBlockActivated holds cs_main and wants cs_headers; …)` — **false as of this branch**; the whole
point of the change is that OnBlockActivated no longer holds cs_main. This is the identical stale-
rationale shape the branch itself excavates at `headers_manager.cpp:1005-1006`, left behind 100 lines
below the one it fixed. Same class, same file, not folded.

### M-3 — new window: node removed from `m_nodes` while still present in `peers`/`node_refs`
`connman.cpp:1765-1774` erases from `m_nodes` **first**; `RemoveNode` (which erases `peers` +
`node_refs` under `scoped_lock(cs_peers, cs_nodes)`, `peers.cpp:1834-1837`) runs later, at `:1789`.
Pre-fix the order was the reverse (node stayed in `m_nodes` until after RemoveNode). During the new
window every `m_nodes`-derived view disagrees with every `node_refs`-derived view:

- `CConnman::GetNodeCount()` / the accept-path caps (`connman.cpp:447-450`, `:488-491`, `:1262`) count
  the node as **already gone**, so an extra inbound connection can be admitted while the peer still
  occupies a `peers`-map slot and its socket is still open (`CloseSocket` is at `:1792`).
- `CConnman::GetNode(id)` (`:597-605`) returns nullptr while `CPeerManager::GetNode(id)`
  (`peers.cpp:1845`) still returns a live pointer — the two "is this peer alive" oracles disagree for
  the duration of dispatch + RemoveNode + CloseSocket, which now includes taking `cs_peers` **and**
  `cs_headers` and can be slow under contention.

I checked the specific escalation I most expected — `EvictPeersIfNeeded`'s fallback at
`peers.cpp:1080-1092`, which double-dispatches when "no live CNode" — and it is **safe**: it consults
`CPeerManager::GetNode` (node_refs), not `m_nodes`, so during the window it still sees the node and
takes the `MarkDisconnect` branch. No double-dispatch. Recording it as checked-and-clear rather than
assumed.

Verdict: bounded and probably tolerable, but it is a genuine new disagreement window that the
comment block at `:1728-1758` does not mention while asserting the change is "strictly safer".

### M-4 — `DrainTipNotifications` is called from a destructor and can `std::terminate`
`chain.h:997-1003` — `~TipNotifyDrain() { m_chainstate.DrainTipNotifications(); }`. Destructors are
implicitly `noexcept`. `DrainTipNotifications` catches exceptions from the callbacks
(`chain.cpp:2608-2616`, correctly), but **not** from `std::lock_guard`'s `lock()` at `:2593` (can
throw `system_error`) nor from `toFire`/`callbacks` vector allocation at `:2586-2598`
(`callbacks = m_tipCallbacks` is a copy — an allocation — on every drain). Any of those throwing from
inside the destructor aborts the node. Low probability; worth one `try/catch(...)` around the body
since this is now on every activation path.

Note also that `callbacks = m_tipCallbacks` (`:2598`) is a **new heap allocation on the block-
activation hot path**, once per activation. The brief asked what the fix makes worse; this is the one
I found. Small, but it is under `cs_main` and it is per-block.

## LOW

### L-1 — the canary threshold cannot fire for the leak it describes
`chain.cpp:2554-2578`. The stated failure mode is "someone adds a fifth call site in a scope with no
TipNotifyDrain", and the canary watches `m_pendingTipNotifications.size() > 64`. But every existing
site is inside `ActivateBestChain`, whose drain **swaps the entire vector** (`:2597`) — including
notifications queued by the hypothetical undrained fifth site. So an undrained site leaks nothing as
long as *any* activation subsequently runs; the queue is emptied by the next block. The canary
therefore only fires if the undrained site queues >64 notifications between two activations, which is
the narrow tail of the case it claims to cover. The real guard is
`scripts/check-tip-notify-drain.sh:36-45` (NotifyTipUpdate confined to chain.cpp), which is sound.
The canary is weaker than its 25-line comment claims — **reasoned, reads as designed-for**.

### L-2 — Case 1 (genesis) still returns without notifying
`chain.cpp:692-709` sets `pindexTip` and returns `true` at `:708` with no `NotifyTipUpdate`. Pre-
existing, unchanged by this branch, and the drain does not paper over it (nothing was queued). Noted
only because the branch's comments repeatedly enumerate "all four call sites" as if that set were
complete w.r.t. tip changes — it is complete w.r.t. `NotifyTipUpdate`, not w.r.t. tip mutation.
`SetTip` (`chain.cpp:2493-2517`) likewise notifies nothing.

### L-3 — stale cross-reference in `net.h:342-344`
"the eviction/disconnect callers hold cs_vNodes and/or cs_peers **across the dispatch**
(AcceptConnection → EvictPeersIfNeeded → DispatchPeerDisconnected → OnPeerDisconnected)" — no longer
true of the disconnect path after this branch, and `connman.cpp:1301-1308` says the accept path
deliberately does not call EvictPeersIfNeeded under cs_vNodes either. Doc drift adjacent to the
invariant the branch depends on; should have been folded with H-1.

---

# Priority questions, answered directly

**1. The RAII drain — is reverse-order destruction sound given cs_main is recursive? YES, verified,
with one caveat.** Both facts the header claims (`chain.h:980-990`) hold at this tree:

- `cs_main` is declared at `chain.h:136` inside the `private:` block that runs `107→166`. I checked
  every access-specifier line in the class (`107,166,193,238,252,316,821,834,958,998,1003`): no
  `public:`/`protected:` section contains it, there is **no `friend` declaration anywhere in
  chain.h**, and no accessor returns the mutex (grepped `recursive_mutex&`). So no external frame can
  hold it. **Verified, not taken on trust.**
- No re-entry into `ActivateBestChain` with cs_main held: the only definition is `chain.cpp:386`,
  spanning `386→1328` (next symbol `ConnectTip` at `:1330`), and it is called from exactly nine
  non-test sites (`block_processing.cpp:945,1468`; `block_validation_queue.cpp:402`;
  `fork_manager.cpp:722`; `chain_selector_impl.cpp:213`; `dilithion-node.cpp:2766,6435,6647`;
  `dilv-node.cpp:2623,6446`) — **none of them can be holding cs_main, because they cannot name it**.
  There is no recursive call from within `CChainState`.
- All four `NotifyTipUpdate` sites (`chain.cpp:684,749,803,1324`) are inside `386..1328` — the
  comment at `chain.cpp:2556` is **correct**, I checked the function bounds rather than trusting it.
- `drain` at `:393` precedes the guard at `:397`; C++ destroys in reverse declaration order, so the
  guard's `unlock()` genuinely precedes the drain. Not a no-op.

Caveat: the guarantee is enforced by `private:` + call-graph, and the guard script
(`check-tip-notify-drain.sh:61-70`) checks the declaration order but **not** the two facts the header
says would invalidate it. A `friend` or a public `GetMutex()` added later silently re-arms the
deadlock with the guard still green. Worth one grep in the script.

**2. Two-phase DisconnectNodes — orderings preserved?** On the **non-throwing** path, yes, and the
detach is a better construction than "collect ids": #262 (dispatch at `:1785` before RemoveNode at
`:1789`), #153 (RemoveNode before destruction at `:1794`), #148 (no node_ref outlives its CNode) all
hold, and the CNode provably outlives RemoveNode because `detached` owns it. On the **throwing** path
all three break — H-2. The window (M-3) exists but the one escalation I could construct through it
(eviction double-dispatch) is closed by `node_refs` being consulted rather than `m_nodes`.
I could **not** compare against the pre-fix text (no git access), so "preserved relative to before" is
inference from the BUG numbers and the surviving comments, not a diff read.

**3. Claims asserted as measured that are reasoned or false at source:** H-1 (false — net.h does not
say it), M-1 (reasoned, presented as demonstrated), M-2 (`headers_manager.cpp:1102-1103` now false),
H-2/`connman.cpp:1757` ("strictly safer" — false on the throw path), H-3/`chain.cpp:2604` (true but
answers a narrower question than the reader will take it for), L-1, L-3. Also a provenance mismatch:
`docs/p2p14-lock-inversion/README.md:8` records the RED baseline as measured against origin/main
**`f47b9b24`**, while `scope_analysis.txt:2` gives the branch base as **`9e12e649`** — the RED and
GREEN are not on the same base. The test file is honest about this at `:283-287` ("NOT a re-run of
the recorded baseline"); the README's headline table is not.

**On evidence attributability (the "green because it stopped executing" question):** for the
lock-order arms the green IS attributable. `tsan_FIXED_both_arms.err:5-6` records, in the registered
arm, `EDGE-B callback fired=200` (incremented at `p2p14_lock_inversion_tsan_tests.cpp:290`
immediately **before** `OnBlockActivated`, so the reverse edge into cs_headers provably ran 200 times)
AND `forward-edge landed=200/200` (the cs_headers→cs_main direction still constructed), with the
reachability guard returning 3 rather than 0 if either is absent. Green with both edges live is the
right shape. The accessor arms are the ones that do not carry their claim — M-1.

---

# What I did NOT reach (coverage gaps — do not read this review as covering these)

- `git diff origin/main...HEAD` itself — no Bash tool. Everything above is post-fix-tree reading; I
  cannot state what the pre-fix `DisconnectNodes`/`NotifyTipUpdate` text was.
- `CHeadersManager::UpdateBestHeader` — the monotonicity question that decides whether H-3's
  out-of-order delivery actually regresses `hashBestHeader`. Unopened.
- `CPeerManager::OnPeerDisconnected` body and `CHeadersManager::OnPeerDisconnected` — I traced the
  call chain but did not read what they do with no locks held now.
- The commit messages. I reviewed code comments and `docs/p2p14-lock-inversion/*` only; commit-message
  claim classification is unperformed.
- `scripts/check-tip-notify-drain.sh` read only via grep context (`:36-90`), not line-by-line; the
  Makefile:623/626 wiring is **unverified** — I never opened the Makefile.
- `scripts/run_p2p14_lock_inversion_tsan.sh` — unopened; I did not verify the runner actually fails
  the build on a red arm (my memory has repeat offenders here: `|| true`, unconditional "✅",
  `timeout` exit-code misclassification).
- `tsan_registered.err` / `tsan_unregistered.err` beyond the excerpt quoted in the README.
- Whether any block-connect/disconnect callback fired under cs_main (`ConnectTip`/`DisconnectTip`)
  reaches cs_headers — i.e. whether the `cs_main → cs_headers` edge survives via a *second* callback
  family. I enumerated the registrations in `dilv-node.cpp` (txindex, fee estimator, coinstats,
  wallet, DFMP, session counters, VDF cooldown, DNA) and none obviously touches the headers manager,
  but I did not read their bodies and I did not enumerate `dilithion-node.cpp`'s set at all. **This is
  the most important gap: if one of them reaches cs_headers, the cycle is not closed.**
- The `cs_headers → g_validation_mutex` edge (README:91 says it is out of scope and unconstructed —
  I did not independently check that scoping decision).
- Lens 9 (Sybil/mining-concentration): not applicable to this diff; no DFMP/DNA surface touched.

---

# Verdict

Scoped to what I actually examined: **the core mechanism is sound.** The RAII drain is not a no-op —
I verified both load-bearing facts (private `cs_main`, no re-entrant caller) myself rather than
accepting the header's assertion, and the lock-order evidence is attributable rather than
green-by-absence.

**Yes, load-bearing items remain unresolved**, two of them:

1. **H-2** — the exception path through the new two-phase `DisconnectNodes` frees CNodes while
   `node_refs` still points at them, breaking BUG #148/#153. A three-line `try/catch` or scope-guard
   closes it; shipping without it means the branch's own headline ordering guarantees are conditional
   on nothing throwing.
2. **H-1** — the lock order this entire change rests on is cited as ratified in `net.h` and is not
   there. Until it is written down, the fix is one plausible refactor away from being undone, and the
   guard script covers only the `cs_main` half.

H-3 is load-bearing as a *documentation* gap (the concurrency contract for every tip-callback consumer
changed silently); whether it is also a live defect depends on `UpdateBestHeader`, which I did not read.

M-1 does not block the code but does mean the §0.3-POST accessor work is **not** evidenced by the
artifact that claims to evidence it.
