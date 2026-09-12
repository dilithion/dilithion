# P2P-14/15 convergence check — worktree `C:/tmp/a8-p2p15`, head `d63df3a6`

Fresh context, read-only, **no Bash tool** (no `git diff`, no `git show`). Everything below is from
reading the post-fix tree plus `.git/worktrees/a8-p2p15/logs/HEAD` (readable as a text file, which is
how I recovered the commit sequence). Where a verdict depends on knowing which commit a hunk landed
in, I say so and mark it as inference.

---

## 1. Per-item verdicts (the five numbered brief items + the commit-claim question)

| # | Item | Verdict |
|---|------|---------|
| 1a | `EvictPeersIfNeeded()` outside the `cs_vNodes` scope in `AcceptConnection` | **VERIFIED CLEAN** — `connman.cpp:475-483` closes the counting scope; the call is at `:487` with the lock released. |
| 1b | Any OTHER path in `AcceptConnection`/callees acquiring `cs_headers` under `cs_vNodes` | **VERIFIED CLEAN** — call graph followed across files; see §3. |
| 1c | Any OTHER path acquiring `cs_peers` under `cs_vNodes` | **PRESENT, and permitted by the ratified order** — `connman.cpp:587 → :590 DispatchPeerConnected → peers.cpp:1767 RegisterNode → :1790 scoped_lock(cs_peers, cs_nodes)`. `cs_vNodes → cs_peers → cs_nodes` conforms to `net.h:341`. Not a defect. |
| 2 | `DisconnectNodes` phase 2 — does every path reach `RemoveNode` before destruction; does the catch swallow something that should abort | **VERIFIED CLEAN on phase 2**, with two LOW residuals (F-2, F-3 below). Phase 1 is **DEFECT (LOW)** — see F-2. |
| 3 | Can anything escape `~TipNotifyDrain` | **VERIFIED CLEAN** — `chain.h:1023-1036` wraps the entire body in `try { … } catch (...) {}`; the handler body is empty (no allocation, no logging call), so nothing can throw out of the destructor. |
| 4 | Does `net.h`'s newly-ratified order match live code | **DEFECT — BLOCKER.** A live site contradicts it: `peers.cpp:963 → :1089 → :1708 → headers_manager.cpp:1470` acquires `cs_headers` **while holding `cs_peers`**, against `net.h:341` which places `cs_headers` ABOVE `cs_peers`. Details in F-1. |
| 5 | `TipNotifyDrain` still declared before the `cs_main` guard | **VERIFIED CLEAN** — `chain.cpp:393` (`TipNotifyDrain drain(*this);`) precedes `chain.cpp:397` (`lock_guard<recursive_mutex> lock(cs_main)`). All four `NotifyTipUpdate` sites (`chain.cpp:684/749/803/1324`) remain inside `ActivateBestChain`. |
| 6 | `d63df3a6` "no code behaviour change" | **DEFECT (MEDIUM, provenance) — inference, not measured.** See F-4. |

---

## 2. Findings

### F-1 — BLOCKER — the ratified order is contradicted by live code: `cs_peers → cs_headers` survives, and the reverse edge is live at six sites

The fold hoisted `cs_vNodes` out of the eviction path but left the **inner** pair of the very chain
the fix's own comment prints. `net.h:338-354` now ratifies:

```
cs_headers → cs_vNodes → cs_peers → cs_nodes → {rate-limit} → block_tracker.m_mutex
```

**Live forward edge, `cs_peers` → `cs_headers`** (verified line by line, all four hops read):

```
peers.cpp:962-963   CPeerManager::EvictPeersIfNeeded()
                    std::lock_guard<std::recursive_mutex> lock(cs_peers);   // FUNCTION SCOPE — held throughout
peers.cpp:1080-1089 CNode* node = GetNode(peer_to_evict);
                    if (node) { … } else {                                   // no live CNode: fallback
peers.cpp:1089          g_node_context.connman->DispatchPeerDisconnected(peer_to_evict);
connman.cpp:65-69   CConnman::DispatchPeerDisconnected → m_peer_manager->OnPeerDisconnected(node_id)
peers.cpp:1708      g_node_context.headers_manager->OnPeerDisconnected(peer_id);
headers_manager.cpp:1468-1470   std::lock_guard<std::mutex> lock(cs_headers);   // ACQUIRED under cs_peers
```

**Live reverse edge, `cs_headers` → `cs_peers`** (the six sites the change itself declares
"conforming"):

```
headers_manager.cpp:210-222  ProcessHeaders … std::lock_guard<std::mutex> lock(cs_headers);  // function scope
headers_manager.cpp:530      peer_manager->Misbehaving(peer, 20, INVALID_BLOCK_HEADER);
peers.cpp:527-528            CPeerManager::Misbehaving → GetPeer(peer_id)
peers.cpp:282-283            std::lock_guard<std::recursive_mutex> lock(cs_peers);            // ACQUIRED under cs_headers
```
(same shape at `headers_manager.cpp:351/498/674/2917/2987`, per `scope_analysis.txt:43-48`, and I read
`:530` and its enclosing lock at `:222` directly.)

`cs_headers` is a plain `std::mutex`; `cs_peers` is recursive, which buys nothing across threads.
Two threads, opposite order:

1. T1 (message handler) — `ProcessHeaders` holds `cs_headers`, hits a checkpoint/validation failure at
   `headers_manager.cpp:530`, blocks on `cs_peers`.
2. T2 (socket handler via `PeriodicMaintenance`, `peers.cpp:1104`, or the accept path,
   `connman.cpp:487`) — `EvictPeersIfNeeded` holds `cs_peers`, takes the no-live-CNode fallback at
   `peers.cpp:1083`, blocks on `cs_headers`.

**Deadlock. Same class, same two mutexes, same fallback branch the port review named** — the fold
removed only the outermost lock from that chain. Reachability is the same triple the port review
established (`peers.size() >= MAX_TOTAL_CONNECTIONS` + a `peers` entry with no `node_refs` mapping),
and it is now reachable from *both* `EvictPeersIfNeeded` call sites, not just the accept one.

Three places in the tree assert or imply this is closed, and they are mutually inconsistent:

- `net.h:366-369` — "the disconnect dispatch is **NO LONGER** made while holding `cs_vNodes`/`cs_peers`".
  Unqualified subject, two dispatch sites; true of `CConnman::DisconnectNodes`, **false** of
  `peers.cpp:1089`.
- `peers.cpp:1720-1727` — in the same change, states the opposite as a live fact and relies on it:
  "this runs under the eviction/disconnect locks (`cs_vNodes` and/or `cs_peers` — e.g.
  **EvictPeersIfNeeded holds `cs_peers` across `DispatchPeerDisconnected`**)".
- `net.cpp:1170-1176` — the F-009 invariant is *derived from* "the eviction/disconnect path takes
  `cs_peers` and then, via `OnPeerDisconnected` → …". That reasoning is still correct and still
  depends on `cs_peers` being held through `OnPeerDisconnected`.
- `scope_analysis.txt:33-35` — the validation block records `1708: [held: -]` and states
  "expected: `:1708` NOTHING held". That is the per-file lexical view of `peers.cpp`'s own body; the
  caller at `:963` holds `cs_peers` function-scope. **The file's own header warning (`:5-29`) about
  per-file lexical analysis applies to its own validation block, one level up.**

By the brief's own criterion — "if any live site contradicts it, the documentation is now itself a
fabricated ratification and that is a BLOCKER" — this is a BLOCKER. It is also a live deadlock, not
only a doc defect.

Not introduced by this branch (pre-existing), but it is squarely inside the completeness claim the
branch now makes in `net.h` and in `connman.cpp:1757-1769`.

**Fix shape** (the branch's own ratified rule, applied one level in): in `EvictPeersIfNeeded`, decide
under `cs_peers` and act after releasing — hoist the `peers.cpp:1083-1092` fallback (`Dispatch…` +
`RemovePeer`) out of the function-scope lock, or narrow that lock to the candidate-selection loop.
Alternatively convert the fallback to mark-and-let-the-reaper-handle-it like its sibling branch at
`:1082`. Whichever is chosen, `net.h:366-369` must be re-scoped to name *both* dispatch sites, and
`scope_analysis.txt:33-35` must stop asserting "`:1708` NOTHING held".

### F-2 — LOW — phase 1 of `DisconnectNodes` is not exception-contained, and the H-2 unwind path survives there

`connman.cpp:1803` — `detached.push_back(std::move(*it));` inside the `cs_vNodes` scope. `push_back`
can throw `bad_alloc` on reallocation. At that point `detached` already owns previously-detached
CNodes that have been erased from `m_nodes` (`:1804`), so the unwind destroys them **without ever
calling `RemoveNode`** — precisely the `node_refs`-dangles-on-throw failure the phase-2 try/catch was
added to close (`:1814-1832`). The containment was applied to phase 2 only. (`unique_ptr`'s move ctor
is `noexcept`, so the *element being moved* is not lost — the exposure is the already-detached ones.)

Probability is negligible; the cheap complete close is `detached.reserve(m_nodes.size());` before the
loop (allocates before anything is detached) or a `try/catch` around phase 1 that re-inserts.

### F-3 — LOW — the `RemoveNode` catch knowingly proceeds to free a node whose `node_ref` was not erased

`connman.cpp:1859-1862` catches everything from `RemoveNode` and logs "node_refs **may still hold this
id**" — then the loop continues and `detached` unwinds at `:1870`, destroying that CNode. That is the
identical UAF shape H-2 named, narrowed from "all remaining nodes" to "this one node". The comment is
honest about it, which is why this is LOW and not higher. One-line complete close: in that catch, do
`(void)node.release();` — deliberately leak the CNode rather than free one that `node_refs` may still
point at. A leak is strictly preferable to a dangling raw pointer handed to `Misbehaving` /
`PeriodicMaintenance` / `GetConnectionCount`.

Answering the brief's sub-question directly: **no**, the catches do not swallow anything that should
abort *except* this one — `DispatchPeerDisconnected` throwing genuinely should be contained (that is
the whole point), and `CloseSocket` throwing is inert. `RemoveNode` throwing is the single case where
"continue teardown" is the unsafe branch.

### F-4 — MEDIUM (provenance) — `d63df3a6`'s "no code behaviour change" is very likely false; the chain.h hunk is a behaviour change

**This is inference — I could not run `git show`.** Evidence:
- The reflog (`.git/worktrees/a8-p2p15/logs/HEAD:12-13`) shows exactly two commits after the reviewed
  head `9f594a99`: `6383a516` "close the SECOND forward edge" and `d63df3a6` "fold the three remaining
  review findings — no code behaviour change".
- The reviewed tree had `~TipNotifyDrain() { m_chainstate.DrainTipNotifications(); }` with **no**
  try/catch (red-team M-4 quotes it verbatim at `chain.h:997-1003`).
- The post-fix `chain.h:1023-1036` has the try/catch and its comment ends "**(Red-team M-4.)**" — i.e.
  it is one of "the three remaining review findings", which is `d63df3a6`'s stated subject, and the
  brief confirms `d63df3a6` touches `chain.h`.

Adding a `catch (...)` around a destructor body is a behaviour change by definition: the pre-fold code
called `std::terminate` on a `bad_alloc`/`system_error` from the drain; the post-fold code swallows it
and continues. It is an *inline function in a header on the block-activation path*, so the emitted
code changes in every TU. Labelling it "no code behaviour change" means a later bisect or audit that
triages by commit subject will skip the one commit that changed abort semantics on the consensus hot
path. Fix: amend/annotate the subject, or record it in the branch docs. One command settles it:
`git show --stat d63df3a6 -- src/consensus/chain.h`.

### F-5 — LOW — stale line references in the new comments

`connman.cpp:458-459` and `scope_analysis.txt:20-21` cite `headers_manager.cpp:1450` for
`OnPeerDisconnected`/`lock_guard(cs_headers)`; the actual lines are `1468`/`1470`. Same class of drift
the fold set exists to remove, in the fold's own text.

### Not folded, still open from the prior reviews (recorded, not re-litigated)

- Port-review **M5 / L15** — `headers_manager.cpp:987` still defaults `height = 1` and
  `:1017-1020` still stores silently on lookup failure. No loud log added.
- Port-review **H2 / red-team M-2** — the raw-`CBlockIndex*` class at `headers_manager.cpp:219-220`,
  `:490`, `:1124-1125`, `:1158`. **Deliberately and explicitly scoped out**, in writing, at
  `headers_manager.cpp:1115-1123` (names the residual, cites the LP10 census). That is the correct
  disposition of a scoped-out finding and I am not counting it against the fold.
- Red-team **H-3 / port-review M3** — the cross-activation ordering / re-entrancy contract on tip
  subscribers is still undocumented at `chain.h:297`. `chain.cpp:2604-2605` still says only
  "per-activation order is preserved".

---

## 3. What I checked to clear item 1b (so it is not a silent assumption)

Followed across files, not per-file: `AcceptConnection` (`connman.cpp:438-601`) holds `cs_vNodes` in
exactly three scopes — `:476-483` (counting only, no calls out), `:517-541` (per-IP cap, no calls
out), and `:587-596`. The third calls `DispatchPeerConnected` (`connman.cpp:58-63`) →
`CPeerManager::RegisterNode` (`peers.cpp:1767`), which reaches `banman.IsBanned`, `IsSeedNode`, and
`scoped_lock(cs_peers, cs_nodes)` at `:1790`. **No path from `RegisterNode` reaches `cs_headers`**
(`peers.cpp` has exactly two `headers_manager` references, `:12` include and `:1708`, and `:1708` is
in `OnPeerDisconnected`, not the register path). `EvictPeersIfNeeded` at `:487` and `IsBanned` at
`:507` are outside every `cs_vNodes` scope. `ConnectNode`'s sibling dispatch (`connman.cpp:425`,
under the `:371` scope) is the same `RegisterNode` path — also clean. I also checked
`CPeerManager::Misbehaving` (`peers.cpp:527-625`) end-to-end: it reaches `cs_peers`, `cs_nodes`,
`banman`, `addrman`, and `m_scorer`, and **never** `cs_headers` — so the `cs_vNodes → cs_peers`
sites at `connman.cpp:875/878/1433/1717/1720` cannot extend into `cs_headers`. Likewise
`CleanupPeerRateLimitState` (`net.cpp:181-201`) takes only the three rate-limit mutexes, which sit
last in the ratified order.

The single cross-file escape to `cs_headers` from the net layer is `peers.cpp:1708`, reachable from
two callers: `connman.cpp:1841` (no locks held — **correct after the fold**) and `peers.cpp:1089`
(`cs_peers` held — **F-1**).

---

## 4. Verdict

**NOT CLEAN. One BLOCKER remains: F-1.**

Items 1a, 1b, 2 (phase 2), 3 and 5 are verified clean at source — the second forward edge is genuinely
out of the `cs_vNodes` scope, the phase-2 teardown reaches `RemoveNode` for every node on every path
including the throwing one, nothing can escape `~TipNotifyDrain`, and the declaration-order mechanism
at `chain.cpp:393/397` is intact. The folds did not break the mechanism.

But item 4 fails: `net.h:341`'s freshly-ratified `cs_headers → … → cs_peers` is contradicted by a live
site, `peers.cpp:963/1089 → :1708 → headers_manager.cpp:1470`, against a live reverse edge at six
`headers_manager.cpp` sites. That is both a fabricated ratification by the brief's stated criterion
and a real AB-BA deadlock between two non-recursive-in-practice mutexes. Two other files in the same
change (`peers.cpp:1720-1727`, `net.cpp:1170-1176`) state the contradicting fact outright. The fold
hoisted `cs_vNodes` out of the chain and left the `cs_peers` leg of the same printed chain in place.

Minimum to converge: either close `peers.cpp:1083-1092` under the same "decide under the lock, act
after release" rule, or amend `net.h:338-369` + `scope_analysis.txt:33-35` to record `cs_peers →
cs_headers` at `peers.cpp:1089` as a known live inversion with an owner — so the next reader does not
inherit "the cycle is closed" as fact. F-2/F-3/F-5 are cheap and can ride along; F-4 is a one-command
check.

### What I did NOT examine (do not read this pass as covering it)

- `git diff` / `git show` of any commit — no Bash. F-4 is inference from the reflog + an in-file
  citation, not a measurement.
- `scripts/check-tip-notify-drain.sh`, `scripts/run_p2p14_lock_inversion_tsan.sh`, the Makefile
  wiring, and the CI leg — **unopened this pass.** The prior red-team also flagged these as a gap
  (`|| true` / unconditional-green class). Still uncovered by anyone.
- The `.err` evidence files (`tsan_FIXED_both_arms.err` etc.) — not re-read; I relied on the prior
  reviews' reading of them.
- `p2p14_lock_inversion_tsan_tests.cpp` beyond `:150-330`. The M-1 fold in that window **is** properly
  done: `:173-206` now states the confound and rests the safe half on construction, explicitly
  labelled "an argument, not a measurement". I did not read the lock-order arms (`:330-450`) or
  re-verify the reachability guard.
- `CHeadersManager::UpdateBestHeader` — the monotonicity question behind red-team H-3. Still unopened
  by any seat.
- `chain.cpp` block-connect/disconnect callback families (port-review L5/L6, `chain.cpp:1932-1949`,
  `:2139-2153`) — out of the fold's scope, not re-checked.
- Whether any `ConnectTip`/`DisconnectTip` callback registered in `dilithion-node.cpp` /
  `dilv-node.cpp` reaches `cs_headers` — the prior red-team named this as its most important gap; it
  is still a gap.
