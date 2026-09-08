# P2P-14/15 final-head upstream-equivalence review (seat 2)

- Worktree: `C:/tmp/a8-p2p15`, head `48d25748`
- Modality: audit modality 2 — upstream equivalence (Bitcoin Core reference)
- Predecessor ledger (earlier head): `docs/p2p14-lock-inversion/review_port.md` — FOLDED, extended not re-derived
- Status: IN PROGRESS (rows appended as settled)

## Upstream reference identified

Bitcoin Core, asserted from knowledge (no Core checkout in this tree, no network in this seat —
same confidence discipline as the predecessor seat; I name structure/rationale, not file:line):
- `src/net.cpp` — `CConnman::DisconnectNodes()`, `CConnman::CreateNodeFromAcceptedSocket()`
  (older trees: `AcceptConnection`), `CConnman::AttemptToEvictConnection()`,
  `src/node/eviction.cpp` `SelectNodeToEvict()`.
- `src/net.h` / `src/validation.h` — lock-order documentation + `GUARDED_BY` /
  `EXCLUSIVE_LOCKS_REQUIRED` / `LOCKS_EXCLUDED` (`src/sync.h`), compiled under
  `-Wthread-safety`; plus the runtime `DEBUG_LOCKORDER` lock-order graph in `sync.cpp`.
- `src/validationinterface.{h,cpp}` + `src/scheduler.{h,cpp}` — the deferral mechanism
  Dilithion has no port of (predecessor verified: 0 references).
- `src/sync.h` `REVERSE_LOCK` — Core's sanctioned "release inside a scope" primitive.

## Divergence ledger

Verdict key: EQUIVALENT / JUSTIFIED-DIVERGENCE / UNFORCED-DIVERGENCE / DEFECT.
Rows N1..N9 are NEW at this head; predecessor rows L1-L17 are folded, not re-derived.

| # | Port site | Upstream concept | Verdict | Note |
|---|-----------|------------------|---------|------|
| N1 | `connman.cpp:473-496` — inbound/total counted in a scoped `cs_vNodes` block, lock released, `EvictPeersIfNeeded()` called after | Core `CreateNodeFromAcceptedSocket`: `{LOCK(m_nodes_mutex); count inbound;}` then `if (nInbound >= nMaxInbound) if (!AttemptToEvictConnection())` **outside** the lock | **EQUIVALENT** | This is Core's shape almost line-for-line, including the accepted count-staleness. The fix moved the port *onto* the upstream idiom rather than inventing one. |
| N2 | `peers.cpp:1085-1087` — primary eviction branch marks `node->MarkDisconnect()` and lets `DisconnectNodes` reap | Core `AttemptToEvictConnection` sets `fDisconnect = true` on the selected node and returns; the reaper does teardown. Core's evictor **never** dispatches subscriber callbacks itself | **EQUIVALENT** | Mark-and-reap is exactly Core's discipline, and it is the branch that runs in production. |
| N3 | `peers.cpp:1088-1123` — fallback branch: orphaned `peers`-map entry with no `node_refs` mapping ⇒ direct `DispatchPeerDisconnected` + `RemovePeer` | Core has **no analogue**: `Peer`/`CNodeState` are slaved to `m_nodes` by `InitializeNode`/`FinalizeNode`, so a peer entry cannot outlive its `CNode`. Core has one registry with a strictly-derived side map | **UNFORCED-DIVERGENCE (architectural, pre-existing)** | This branch is the *sole* reason a `cs_peers → cs_headers` edge exists at all. The lock fix patches the edge; the two-registry drift that creates the orphan is the root. Naming it because every pass so far has fought symptoms of it. |
| N4 | `connman.cpp:1794-1889` — two-phase detach-then-dispatch, `detached` owns the `unique_ptr`s, per-node try/catch, `release()`-and-leak on `RemoveNode` throw | Core `DisconnectNodes()`: part 1 under the nodes mutex (erase from `m_nodes`, release grant, close socket, move to `m_nodes_disconnected`); part 2 outside deletes only nodes with **refcount 0** and idle send buffers | **JUSTIFIED-DIVERGENCE** | Same two-phase silhouette, different guarantee. Core's split is a LIFETIME mechanism (deferred refcounted delete, survivors roll to the next pass); this is a LOCK-ORDER mechanism with unconditional delete at scope exit. Predecessor already established the four external facts that make it safe here. |
| N5 | `connman.cpp:1846-1885` — exception containment per node, with a deliberate CNode leak if `RemoveNode` throws | Core needs no equivalent: ownership is not transferred to a local, and the refcount check is what gates deletion | **JUSTIFIED-DIVERGENCE** | Correct compensation for the ownership transfer N4 introduces, and the comment now says so honestly (an earlier "strictly safer than before" claim was retracted). Given no `CNode` refcount exists, leak-over-free is the right call. |
| N6 | `peers.cpp:968` `std::unique_lock<std::recursive_mutex>` + `peers.cpp:1118` explicit `lock.unlock()` before the fallback dispatch | Core: compute under the lock, close the scope, act after. `AttemptToEvictConnection` builds candidates under `m_nodes_mutex`, releases, runs `SelectNodeToEvict` outside, then re-takes the lock to mark. Core's only sanctioned mid-scope release is `REVERSE_LOCK` (`sync.h`), used rarely | **UNFORCED-DIVERGENCE** (style) — but see F-2 for the load-bearing part | The unlock is *terminal* (the branch returns 6 lines later), so it is a scope end written by hand. A scope narrowing does the same job and is strictly better: it cannot be left half-owned, it is visible in the brace structure, and future statements added after it cannot silently run unlocked. The unlock is NOT what makes this correct or incorrect — the recursive mutex is (F-2). |
| N7 | `net.h:338-354` — written global order `cs_headers → cs_vNodes → cs_peers → cs_nodes → {rate-limit} → block_tracker` | Core documents order in `net.h`/`validation.h`, backs it with `GUARDED_BY`/`EXCLUSIVE_LOCKS_REQUIRED` under `-Wthread-safety`, AND with the runtime `DEBUG_LOCKORDER` lock graph in `sync.cpp` that aborts on a detected inversion | **JUSTIFIED-DIVERGENCE on the ORDER; gap on ENFORCEMENT** | The order itself is the one Core-style reasoning picks — see §Q3. The honesty of the comment ("a CHOICE justified by cost, not a rule recovered from somewhere else"; "cs_main has NO position … do not write it in to make the diagram tidy") is better upstream practice than most ported comments. The enforcement gap is real and is F-4. |
| N8 | `connman.cpp:598` — `PushMessage(int nodeid,…)` resolves the id under `cs_vNodes`; `peers.cpp:283` — `Misbehaving(int)` → `GetPeer` takes `cs_peers` | Core: `PushMessage(CNode* pnode, …)` takes an already-resolved, **ref-counted** handle and locks only `pnode->cs_vSend`; `Misbehaving(Peer&, …)` takes a resolved `Peer&`. Neither touches the node-registry mutex | **UNFORCED-DIVERGENCE (architectural, pre-existing, ROOT CAUSE)** | This is why a `cs_headers → cs_vNodes/cs_peers` edge exists at all. In Core the two locks are barely ordered against each other because the edge does not exist: the protocol layer holds a handle, not an id. Every fix in this branch is downstream of that choice. Not fixable in this diff; it is the thing to name so the fourth pass is not another lock-level. |
| N9 | `connman.cpp:447-466` — the comment calls the accept path "the SECOND live forward edge … the one that survived the DisconnectNodes fix" | — | **DEFECT (evidence/documentation)** | `CConnman::AcceptConnection` has **no production caller** — stated by the tree itself 860 lines later at `connman.cpp:1327` ("it has NO production caller — every real inbound is accepted here in SocketHandler"). Grep confirms: definition, header decl, two comments, one test. The live accept path (`connman.cpp:1290-1351`) already refused to call `EvictPeersIfNeeded` under `cs_vNodes`. So that edge was **not live**. The fix is right and worth keeping; the claim attached to it is one notch stronger than the file's own evidence, which is Shape 1 again, inverted. |
| N10 | `connman.cpp:1850/1854/1873/1884` — four `std::cerr` writes on the phase-2 path | Core routes everything through `LogPrintf`/`LogPrint(BCLog::NET, …)` — categorised, throttled, redirectable | **UNFORCED-DIVERGENCE** | `DisconnectNodes()` runs on every `ThreadSocketHandler` iteration (`connman.cpp:698`). A repeating throw becomes unbounded, uncategorised, unthrottled stderr from a hot loop, invisible to the node's own log plumbing. The rest of the same function uses `LogPrintf(NET, …)`. |
| N11 | `connman.cpp:1877-1878` — `node.release(); continue;` **skips `CloseSocket()`** | Core: the socket is closed in part 1, under the nodes mutex, before the node is ever queued for deletion — so no path can leak the fd | **DEFECT (narrow, on the throw path only)** | Leaking the `CNode` is the right call vs. a UAF, but leaking the **fd with it** is not required by that reasoning. `CNode::CloseSocket()` only closes the descriptor; calling it before `release()` is safe for anything still holding the `node_ref` (a later `PushMessage` fails on an invalid fd instead of writing to a live socket) and prevents a permanently half-open connection plus a consumed slot. One-line fix: `node->CloseSocket();` before `(void)node.release();`. |
| N12 | `peers.cpp:1751-1753` — "this runs under the eviction/disconnect locks (cs_vNodes and/or cs_peers — e.g. EvictPeersIfNeeded holds cs_peers across DispatchPeerDisconnected)" | — | **accidental doc drift** | Both halves are now false: `DisconnectNodes` phase 2 holds nothing, and `EvictPeersIfNeeded` released `cs_peers` at `:1118`. `net.h:366-369` was updated for exactly this and `peers.cpp:1751` was not — and this is the comment a future reader uses to decide what `OnPeerDisconnected` may lock. It also directly contradicts `CENSUS…md:67-70` ("both are now lock-free at the call") in the same change. Over-stating the held set is the conservative direction, hence LOW, not MEDIUM. |
| N13 | `connman.cpp:1805` — `detached.reserve(m_nodes.size())` **inside** the `cs_vNodes` scope, unconditionally, ~20 Hz | Core's `DisconnectNodes` has historically taken a same-size copy of the node container under the same lock each pass (`std::vector<CNode*> vNodesCopy = vNodes;` in older trees). I cannot pin current Core's exact allocation behaviour from memory | **EQUIVALENT-ish / INFO** | So: a new allocation-under-lock on a hot path, but **not worse than upstream practice**, and required by the throw-safety argument at `:1799-1804`. Cheap improvement if wanted: reserve lazily on first candidate, or reuse a member vector. Not a finding I would block on. |
| N14 | `docs/p2p14-lock-inversion/` — TSan both-arms control constructs `cs_headers ↔ cs_main` only (README §Scope) | Core's `DEBUG_LOCKORDER` tracks **every** mutex pair at runtime, not one constructed pair | **UNFORCED-DIVERGENCE (evidence coverage)** | The four changes at this head are all in the `cs_vNodes`/`cs_peers` ↔ `cs_headers` plane. That plane has **no runtime control** — its completeness rests entirely on the static census. Static reading is the exact modality that failed three consecutive times on this same problem (README/CENSUS §intro). See F-3. |

---

## Q2 — the explicit `unlock()` pattern

**Verdict: unforced as a matter of style; the load-bearing issue is not the `unique_lock`, it is the recursive mutex underneath it.**

`peers.cpp:1118`'s `lock.unlock()` is *terminal* — the branch does `Dispatch → RemovePeer → return true` and never re-locks. So it expresses a scope end by hand. Core's equivalent construct (`AttemptToEvictConnection`) closes the scope instead; Core's only sanctioned mid-scope release is `REVERSE_LOCK` in `sync.h`, used sparingly and *paired*. A scope narrowing here is available and strictly better on three counts: it cannot leave the lock half-owned on a later-added path, it is visible in the brace structure to a reader and to any structural tool, and a statement added after it cannot silently run unlocked while looking locked.

But narrowing the scope would **not** fix the actual hazard, and that is the point worth carrying: `cs_peers` is a `std::recursive_mutex`. `unique_lock::unlock()` calls `mutex.unlock()` **once**, decrementing the recursion count by one. If any caller of `EvictPeersIfNeeded` already holds `cs_peers` in an outer frame, the count goes 2 → 1, **this thread still holds the mutex**, the dispatch runs under `cs_peers` after all, and the cycle is intact — while the comment at `:963-967` asserts the opposite. A `lock_guard` in a narrowed scope has exactly the same property. The only real protection is a statement about the caller set. See F-2.

## Q3 — the written lock order

**(a) Is the order itself right on the merits? Yes — and for better reasons than the ones written down.**

`net.h:350-354` justifies `cs_headers` ABOVE by site count (six sites vs one). That is a cost argument, and the comment is admirably honest that it is one. Two stronger arguments exist and are not made:

1. **Lock-granularity hierarchy.** Core's discipline is coarse, long-held, high-level state locks outermost; short leaf container locks innermost. `cs_vNodes` and `cs_peers` guard registries — lookup-and-return. `cs_headers` is held across an entire header-batch validation (`headers_manager.cpp:222` through the `:351/:498/:530/:674` sites). A long logic lock belongs above a container lock. `cs_headers` ABOVE is the granularity-correct choice independent of how many sites happen to exist.
2. **Cost asymmetry on the fix side.** Ordering `cs_headers` BELOW would require `ProcessHeaders` to drop `cs_headers` mid-batch before each `Misbehaving`/`PushMessage` and re-acquire — destroying the atomicity of the header-state update and creating a re-validation problem at every release point. Ordering it ABOVE requires only that the disconnect/eviction dispatch be lock-free *at the call*, where the decision is already made and nothing needs re-checking. The cheap side is the side that was fixed. This is the argument that makes the choice principled rather than arithmetic; I would add it to `net.h`.

I also endorse `net.h:356-360` (refusing to give `cs_main` a position it does not have). "A documented order the code violates is worse than an acknowledged gap" is upstream-grade reasoning and is the opposite of the failure mode `connman.cpp:1733`/`scope_analysis.txt` produced last round.

**(b) Is the comment-plus-shell-script gap worth naming? Yes — but the useful follow-up is NOT the annotations.**

Core carries two independent mechanisms and they catch different things:
- `GUARDED_BY` / `EXCLUSIVE_LOCKS_REQUIRED` / `LOCKS_EXCLUDED` under `-Wthread-safety` catch **"this member was touched without its lock"** and **"this function was called without the lock it declares"**. They are largely intra-procedural and do **not** track lock *order* through an indirect call.
- `DEBUG_LOCKORDER` (`sync.cpp`, `push_lock`/`pop_lock`) maintains a runtime lock-order graph across **all** mutexes and aborts on a detected inversion, through any call depth or indirection.

Every miss on this problem — pass 1's per-file scope analysis, pass 2's, and the accept path — was an *indirect call out of a lock scope*. Annotations would have caught none of them. `DEBUG_LOCKORDER`, or the TSan `lock-order-inversion` detector the branch already used successfully for the `cs_main` edge, catches exactly that class. **So the highest-yield follow-up is a runtime lock-order tracker (or extending the existing TSan harness to drive the connection-lock plane), not thread-safety annotations.** Annotations are still worth having for a different, real gap (the `cs_main`-guarded members in `chain.h` are prose-guarded), but they are the second recommendation, not the first.

## Q4 — what the fix makes worse relative to upstream practice

- **N11** — the `RemoveNode`-throws path leaks the fd along with the `CNode`; Core closes the socket in part 1, so no Core path can. One-line fix.
- **N10** — four raw `std::cerr` writes on a ~20 Hz loop where the rest of the function uses the project's categorised logger; Core has no unthrottled stderr on the disconnect path.
- **N13** — a new allocation under `cs_vNodes` every iteration; *not* worse than upstream (Core copies the node container under the same lock), and forced by the throw-safety argument. INFO.
- **Windows/guarantees:** `AcceptConnection`'s count-then-release widens a TOCTOU window on the connection caps, but that is precisely Core's shape (`CreateNodeFromAcceptedSocket` counts under `m_nodes_mutex`, releases, then evicts), and the function has no production caller. No lost guarantee.
- **`DisconnectNodes` phase-1/phase-2 window** (node absent from `m_nodes`, still present in `peers`/`node_refs`) was established and cleared by the predecessor seat; nothing at this head changes it. Exception containment only *narrows* the failure set.
- **Upstream detail I could not verify:** whether Core invokes `m_msgproc->FinalizeNode()` inside or outside `m_nodes_mutex`. I am not asserting it. Inference only, shown as inference: `FinalizeNode` takes `cs_main`, and calling it under `m_nodes_mutex` would order `cs_main` beneath a net-layer lock, against Core's general `cs_main`-outermost discipline — so Core almost certainly dispatches outside. If someone wants the "Core does it this way" claim in a commit message, it needs a checkout first.

## Severity-tiered findings (NEW at this head)

**MEDIUM**

- **F-1 (N9) — the accept-path fix is attached to a claim the tree itself refutes.** `connman.cpp:447-449` calls it "the SECOND live forward edge"; `connman.cpp:1327`, same file, says `AcceptConnection` "has NO production caller". Grep confirms zero call sites outside the definition, the header, two comments and one test. Keep the fix (it is correct and it is Core's shape); correct the claim, or wire the function up. Leaving it as-is reproduces the failure this branch was created to stop: an evidence artifact stronger than its evidence.
- **F-2 (N6) — the manual `unlock()` rests on an unstated premise about the caller set, under a recursive mutex.** `cs_peers` is `std::recursive_mutex`; one `unlock()` on a nested acquisition leaves the mutex held and the dispatch still inside `cs_peers`. The premise holds today — the only callers are `connman.cpp:487` (holds nothing, and is dead) and `peers.cpp:1135` `PeriodicMaintenance`, which calls it *before* its own `lock_guard` at `:1143`, reached from the p2p maintenance thread (`dilithion-node.cpp:6893`, `dilv-node.cpp:6717`) holding nothing. Nothing states it, and nothing checks it. The asymmetry is the finding: **the sibling construct in this same branch (`TipNotifyDrain`) writes this exact premise out at `chain.h:979-992` with the caller set enumerated and a shell-script guard.** Same hazard class, same branch, one documented and one not. Fix: enumerate the caller set at `peers.cpp:963` as `chain.h` does. (A secondary unstated premise: after the unlock, a concurrent second evictor could select the same orphan and double-dispatch; single-evictor-thread today.)
- **F-3 (N14) — the modality that settled `cs_main` was not applied to the plane these four changes live in.** The TSan both-arms control is scoped to `cs_headers ↔ cs_main` (README §Scope). The `cs_vNodes`/`cs_peers` ↔ `cs_headers` edges rest on the static census alone — the modality that produced three wrong "closed" verdicts on this problem. The census is a genuinely good artifact (the privacy argument at §1 is what converts a sample into a census, and it is sound), but its own §7 boundary lists two live gaps: registrant bodies for the connect/disconnect callback families were enumerated by name, not read; signal handlers not examined. Cheapest closure: extend the existing harness with an arm that drives `ProcessHeaders` (forward) against `PeriodicMaintenance`-driven eviction of an orphaned peer (reverse) and let TSan's `lock-order-inversion` detector answer.

**LOW**

- **F-4 (N7)** — no compile-time or runtime lock-order enforcement. Recommend a `DEBUG_LOCKORDER`-style runtime tracker (or extending the TSan harness) **first**, `GUARDED_BY` annotations second — see Q3(b) for why that priority and not the reverse. Also worth adding the two merits arguments to `net.h:350-354` so the order reads as principled rather than arithmetic.
- **F-5 (N11)** — `connman.cpp:1877`: add `node->CloseSocket();` before `(void)node.release();` so the throw path leaks memory but not the descriptor or the connection slot.
- **F-6 (N10)** — replace the four `std::cerr` writes in `DisconnectNodes` with `LogPrintf(NET, ERROR, …)`, matching the rest of the function; it is a 20 Hz loop.
- **F-7 (N12)** — `peers.cpp:1751-1753` still says the disconnect dispatch runs under `cs_vNodes`/`cs_peers`. Both halves are now false and it contradicts `CENSUS_cs_headers_edges.md:67-70`. `net.h:366-369` was updated for exactly this; this one was missed.
- **F-8** — `headers_manager.cpp:1115-1123` carries an explicit "RESIDUAL, NOT FIXED HERE (red-team H-2 / port-review L9)" annotation on the `:1124` `GetTip()` pre-fetch. The **same pattern at `:216-220`** (the `ProcessHeaders` pre-fetch, whose live window is the entire header batch — much longer) carries only the old "DEADLOCK FIX" comment and no residual marker. Annotate both or neither; a reader who greps for the residual marker will conclude `:219` is audited-safe.
- **F-9 (INFO, N13)** — `detached.reserve(m_nodes.size())` allocates under `cs_vNodes` every socket-handler iteration. Not worse than upstream, forced by the throw-safety argument, cheap to avoid if anyone cares.

**Predecessor findings still open at this head (recorded, NOT re-derived — see `review_port.md`)**

- **L6 / M1 is UNCHANGED and still wrong.** `chain.cpp:2140-2144` still states "cs_main is NOT held during these callbacks"; on the reorg path `ActivateBestChain` holds the recursive `cs_main` in an outer frame. Verified present at this head. This is the same recursive-mutex reasoning failure as F-2, in the same branch, for the third time. It should ship with this change.
- **L9 / H2** — accepted as a documented residual at `:1115-1123` (see F-8 for the annotation asymmetry). Not re-litigated.

## Invariants checked and confirmed still holding at this head

1. **`DisconnectNodes` BUG #262 ordering** — `DispatchPeerDisconnected(node_id)` precedes `RemoveNode(node_id)` on every path, including when the dispatch throws (`connman.cpp:1846-1864`).
2. **BUG #153/#148** — `RemoveNode` precedes `CNode` destruction on every path; on the `RemoveNode`-throws path the node is leaked rather than freed, so `node_refs` can never point at freed memory. The exception containment strictly narrows the failure set relative to an uncontained throw.
3. **`reserve` before any detach** — the only throwing operation in phase 1 happens while `detached` is still empty (`connman.cpp:1799-1805`); no path can free a node without `RemoveNode` via a phase-1 unwind.
4. **Phase 2 holds no connman lock** — `cs_vNodes` scope closes at `:1816`; the dispatch loop begins at `:1840`. Forward edge broken at the primary reaper.
5. **`AcceptConnection` count-then-act** — `cs_vNodes` scope `:475-483` closes before `EvictPeersIfNeeded()` at `:487`. Matches Core's `CreateNodeFromAcceptedSocket` shape.
6. **`EvictPeersIfNeeded` primary branch is mark-and-reap** (`peers.cpp:1085-1087`), i.e. Core's `AttemptToEvictConnection` discipline; the direct-dispatch fallback is only the orphan case.
7. **No dangling use after `lock.unlock()`** — `GetPeer` returns `std::shared_ptr<CPeer>` (`peers.h:295`), `peer` is not dereferenced after `:1118`, and only the `int peer_to_evict` is used. Node ids are monotonic (`m_next_node_id`), so no id-reuse race across the unlock window.
8. **The recursion premise for F-2 is TRUE today** — both callers of `EvictPeersIfNeeded` verified to hold no `cs_peers` at the call (`connman.cpp:487`; `peers.cpp:1135`, before its own guard at `:1143`, from a maintenance thread holding nothing).
9. **`AcceptConnection` is not on any production path** — grep over `src/` returns definition, declaration, two comments, one test; corroborated by the tree's own statement at `connman.cpp:1327`. So no live regression can come from its lock-scope change.
10. **The live accept path never calls eviction under `cs_vNodes`** — `connman.cpp:1331-1338` refuses deliberately and says why. The two accept paths now agree (predecessor's L16 is resolved).
11. **`DispatchPeerDisconnected` takes no lock of its own** (`connman.cpp:65-70`) — it is a straight forward to `CPeerManager::OnPeerDisconnected`, so the lock context at the call site is the whole story.
12. **The six forward `cs_headers`-above sites are real** — `headers_manager.cpp:222` guard with `Misbehaving` at `:351/:530/:674` and `PushMessage` at `:498` inside it; `:867`'s `PushMessage` is outside its guard at `:869`. The `net.h` order is describing live code, not aspiration.
13. **`net.h:338-360` is internally honest** — it flags its own ratification as a choice, refuses to place `cs_main`, and corrects the stale "dispatch under cs_vNodes/cs_peers" claim at `:366-369`.
14. **The TSan control is a real deadlock, not an observed inversion** — README records `EXIT=124` (hang) on the registered arm vs clean 200 rounds unregistered, differing by one line, with a reachability guard that exits 3 rather than report an unearned zero.

## NOT-REACHED

Stated because a review that overstates its scope is the failure this whole file exists to correct.

1. **No Bitcoin Core source was read.** None in this tree; no network in this seat. Every Core claim above is from knowledge, structure-level, no file:line. Specifically **unverified**: whether Core calls `m_msgproc->FinalizeNode()` inside or outside `m_nodes_mutex` (flagged inline as inference); current Core's exact allocation behaviour in `DisconnectNodes`; whether `REVERSE_LOCK` is still spelled that way; whether TSan's deadlock detector is on by default in the toolchain used for the harness.
2. **No diff.** No Bash in this seat, per the brief. Every "made worse / made better" judgement is against Core practice and against the in-tree comments, **not** against a measured before-state. Where a finding could be pre-existing rather than introduced (e.g. the evict-then-still-reject sequencing in `AcceptConnection:485-501`, where eviction can drop a peer and the total-cap check then rejects the new connection anyway) I have not tried to attribute it.
3. **Nothing was built or run.** No TSan harness run, no compile, no test.
4. **`SocketHandler()` was read only at `:1280-1351`** (the live accept path). The rest of it, and `InactivityCheck()`, were not audited for lock scopes.
5. **`cs_nodes`** (the fourth lock in the `net.h` order) was not examined at all — only `cs_headers`/`cs_vNodes`/`cs_peers`/`cs_main`.
6. **Census boundary inherited, not closed:** registrant bodies for `m_blockConnectCallbacks` / `m_blockDisconnectCallbacks` were enumerated by name and not read (CENSUS §7); signal handlers not examined; `g_validation_mutex` out of scope by contract.
7. **The claimed forward sites at `headers_manager.cpp:2917/2987`** were not confirmed (grep paginated at 60 results); `:351/:498/:530/:674` were.
8. **Predecessor rows L1-L5, L7, L10-L17** were not re-derived — folded per the brief. I re-verified only L6 (still open) and L9 (now an annotated residual).
9. **The `dilv-node.cpp` twin** was checked only for the `PeriodicMaintenance` call site; it was not audited in parallel with `dilithion-node.cpp`.

## Verdict

**The four lock-scope changes are equivalence-safe. All four move the port toward upstream practice, and two of them land on Core's shape almost exactly** (`AcceptConnection` = `CreateNodeFromAcceptedSocket`'s count-release-evict; the primary eviction branch = `AttemptToEvictConnection`'s mark-and-reap). The `DisconnectNodes` two-phase split is a justified divergence with an honest, self-corrected rationale. The written lock order is the order Core-style reasoning would choose, and `net.h` is unusually honest about the limits of its own claim.

**Nothing LOAD-BEARING is unresolved in the code.** No accidental divergence in the four changed regions introduces a deadlock, a UAF, a lost bug-fix ordering, or a resource bound Core holds and this does not. F-2's premise is true today and F-1's fix is correct even though its justification is not.

**Two things are load-bearing in the EVIDENCE, and both are the same recurring shape:**

- **F-1** — the accept-path comment asserts a "live forward edge" that `connman.cpp:1327` refutes 860 lines away in the same file. A branch whose entire lesson is "three passes each claimed completion and were wrong" must not ship a fourth over-claim, however small.
- **F-3** — the `cs_vNodes`/`cs_peers` ↔ `cs_headers` plane, which is where all four of these changes live, has no runtime control. It rests on the static census — the modality with a 0-for-3 record on this specific problem. The `cs_main` edge got a constructed both-arms TSan control and that is what finally settled it.

**Recommendation: merge-able after F-1, F-2 and F-7 (all comment/premise text, no code) and the one-line F-5.** F-3 should be an owned follow-up issue rather than a merge blocker — extending the harness is a bigger change than the fix it would corroborate, and the static census here is genuinely stronger than the tools that failed before it. Predecessor's **L6/M1 (`chain.cpp:2140`, the false "cs_main is NOT held")** should ride along: it is the third instance of recursive-mutex mis-reasoning in this branch's blast radius and it is a two-line comment fix.


