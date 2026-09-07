# P2P-14/15 — upstream-equivalence review (audit modality 2)

**Tree:** `C:/tmp/a8-p2p15`, branch `fix/p2p14-15-cs-headers-lock-order`, head `9f594a99`, base `origin/main 9e12e649`.
**Scope:** does this port correctly adopt Bitcoin Core's idiom for deferring subscriber callbacks out of a lock?
**Method:** source read of the port (no Bash available in this seat, so no `git diff`; before-state reconstructed from the branch's own in-tree documentation at `chain.h:270-306`, `chain.cpp:2538-2552`, `connman.cpp:1729-1758`, `headers_manager.cpp:1002-1016`, `docs/p2p14-lock-inversion/`). Where the before-state matters I say which side of that reconstruction a claim rests on.

**Upstream reference:** Bitcoin Core `src/validationinterface.{h,cpp}` (`CValidationInterface`, `CMainSignals`, `SingleThreadedSchedulerClient`, `SyncWithValidationInterfaceQueue`), `src/scheduler.{h,cpp}` (`CScheduler` service thread), `src/net.cpp` (`CConnman::DisconnectNodes`), `src/node/blockstorage.*` (`BlockManager::m_block_index` lifetime), `src/sync.h` (`GUARDED_BY` / `EXCLUSIVE_LOCKS_REQUIRED` / `LOCKS_EXCLUDED` clang thread-safety annotations).

**Confidence discipline on upstream claims.** I am asserting Core *structure and rationale* from knowledge, not from a checkout — there is no Bitcoin Core source in this tree and I have no network fetch in this seat. I state exact file/line for Core nowhere; where a Core detail is version-dependent (member names `cs_vNodes` vs `m_nodes_mutex`, the exact `BlockConnected` arity after the `ChainstateRole` addition) I say so rather than pinning it.

---

## 0. Answer to Q5 first (the highest-value-if-true finding): NEGATIVE

There is **no** partial port of `CValidationInterface` / `CMainSignals` in this tree, and nothing was bypassed.

- `grep -r 'ValidationInterface|MainSignals|CValidationInterface' src/` → **0 files**.
- `grep -ri 'CScheduler|SingleThreadedSchedulerClient'` → 0; the only `scheduler` hits are prose (`connman.h:398` "connection-attempt scheduler") and log strings. **There is no scheduler thread in Dilithion.**

So the bespoke mechanism is not a duplicate of existing infrastructure. It is the *first* deferral mechanism in the tree. That reframes the review: the question is not "why didn't you use the port" but "is a one-off RAII drain an acceptable substitute for the mechanism Core built, and does building it one-off leave the other two callback families stranded?" (It does — row L5 below.)

---

## 1. Divergence ledger

Verdict key: **EQUIVALENT** / **JUSTIFIED-DIVERGENCE** / **UNFORCED-DIVERGENCE** / **DEFECT**.

| # | Port site | Upstream concept | Verdict | Note |
|---|---|---|---|---|
| L1 | `src/consensus/chain.h:297` — `TipUpdateCallback = std::function<void(const CBlockHeader&, const uint256&)>` | `CValidationInterface::UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload)` — Core **does** hand a raw `CBlockIndex*` to a callback that runs later | **JUSTIFIED-DIVERGENCE** | See §2. The brief's premise is inverted: Core passes the pointer. It is safe there because Core never erases `m_block_index` entries at runtime. Dilithion *does* (`chain.cpp:221 EvictLowestWorkNotOnBestChain`), so the port must snapshot. Right answer, different reasoning — a **compensating** divergence, not an adoption. |
| L2 | `chain.cpp:2538-2552` — `NotifyTipUpdate` dereferences under `cs_main`, pushes `{header, hash}` to `m_pendingTipNotifications` | `CMainSignals::UpdatedBlockTip` → `m_schedulerClient.AddToProcessQueue(...)` | **EQUIVALENT** | Same shape: capture under the lock, dispatch later. Pointer never escapes the lock scope. |
| L3 | `chain.h:997-1005` + `chain.cpp:393` — `TipNotifyDrain` declared before the `cs_main` guard; fires at scope exit | `SingleThreadedSchedulerClient` on the `CScheduler` service thread + `SyncWithValidationInterfaceQueue()` barrier | **JUSTIFIED-DIVERGENCE**, with three named losses | See §3. Sound for the *lock-order* purpose; drops global serialization, drops the barrier primitive, and makes "delivered before `ActivateBestChain` returns" non-guaranteed under concurrency. |
| L4 | `chain.cpp:2586-2599` — drain copies **both** `m_pendingTipNotifications` and `m_tipCallbacks` under `cs_main` before firing | Core guards `m_internals->m_validationInterfaces` for the same reason | **EQUIVALENT** | Correct, and explicitly better than its own sibling at L6. |
| L5 | `chain.cpp:1932-1949` — `m_blockConnectCallbacks` still invoked **with `cs_main` held** (txindex, coinstatsindex, wallet, ZMQ consumers, registered `dilithion-node.cpp:3322/3414`) | Core routes `BlockConnected` through the *same* queue as `UpdatedBlockTip`; no subscriber runs under `cs_main` | **UNFORCED-DIVERGENCE** | The branch built a deferral mechanism and applied it to 1 of 3 callback families. `cs_main → cs_wallet / cs_txindex / ZMQ` edges remain, structurally identical to the one just closed. Not a regression; an incomplete adoption that leaves the next inversion pre-built. |
| L6 | `chain.cpp:2139-2153` — `m_blockDisconnectCallbacks` iterated with the comment "cs_main is **NOT** held during these callbacks" | Core: queue, so genuinely not held | **DEFECT (pre-existing, and now actively misleading)** | `DisconnectTip` is called from `ActivateBestChain`, which holds the **recursive** `cs_main` in an outer frame. The inner scope ending at `chain.cpp:2104` does **not** release the mutex on the reorg path. The comment states the opposite. It is also the exact trap `chain.h:979-992` was written to warn about — the branch documented the hazard and left a live instance of it two hundred lines away. Secondary: this loop iterates `m_blockDisconnectCallbacks` **unlocked** when the mutex genuinely is free, the data race L4 fixed for tip callbacks. |
| L7 | `connman.cpp:1759-1794` — phase 1 detaches `unique_ptr`s under `cs_vNodes`; phase 2 dispatch → `RemoveNode` → `CloseSocket` outside; `detached` destructs at function end | Core `CConnman::DisconnectNodes()`: part 1 under the nodes mutex (erase from `m_nodes`, release grant, close socket, move to `m_nodes_disconnected`); part 2 outside, deleting only nodes whose **refcount is zero** and whose buffers are idle | **JUSTIFIED-DIVERGENCE — but the property Core's split exists for is NOT reproduced** | See §4. Core's split is a *lifetime* mechanism (refcounted deferred delete). This split is a *lock-order* mechanism with unconditional delete at scope exit. It happens to be safe here (verified: the two threads that could hold a `CNode*` don't — §4), but it is not Core's guarantee and nothing enforces the property it relies on. |
| L8 | `connman.cpp:447` (`cs_vNodes` held) → `:457 EvictPeersIfNeeded()` → `peers.cpp:963` (`cs_peers`) → `:1089 DispatchPeerDisconnected` → `peers.cpp:1708` → `headers_manager.cpp:1450` (`cs_headers`) | Core's "no cross-subsystem call under the nodes mutex" discipline | **DEFECT — the cycle this branch exists to break survives on a second path** | See §5. This is the load-bearing finding. |
| L9 | `headers_manager.cpp:219` + `:490` + `:1104-1105` + `:1158` — raw `CBlockIndex*` from `g_chainstate.GetTip()` carried across the whole `cs_headers` scope and `GetAncestor()`-walked with `cs_main` not held | Core: `CBlockIndex*` deref outside `cs_main` is a thread-safety-annotation violation (`GUARDED_BY(cs_main)`); Core's index entries also aren't freed at runtime | **DEFECT — same class as the one the branch fixed, left live in the same file** | See §6. `chain.h:642-664` states the doctrine ("return the value, never the pointer"), the branch applies it at `headers_manager.cpp:1018`, and `:1104`/`:219` are the same pattern with a *much* longer window. |
| L10 | `scripts/check-tip-notify-drain.sh` check 1 — "NotifyTipUpdate is called ONLY from chain.cpp" | Core needs no such guard (queue is global, drain is unconditional) | **UNFORCED-DIVERGENCE** | The script's stated invariant is "every `NotifyTipUpdate` must be drained"; check 1 proves only *file* locality. A fifth call site inside `DisconnectToHeight` (`chain.cpp:2158`), `InvalidateBlockImpl` (`:3525`) or `ReconsiderBlockImpl` (`:3552`) — all in `chain.cpp`, none under `ActivateBestChain`'s drain — passes all four checks and leaks. The runtime canary (`chain.cpp:2571-2578`) is a `std::cerr` line; nothing asserts it. |
| L11 | `connman.cpp:1733-1734` — "against the ratified order in net.h where cs_headers sits ABOVE both" | — | **DEFECT (documentation)** | `net.h:338-353` ratifies exactly one order: `cs_vNodes → cs_peers → {cs_getdata_rate, cs_headers_rate, cs_served_blocks}`. **`cs_headers` does not appear in it** (`cs_headers_rate` is a different mutex). The comment, and `docs/p2p14-lock-inversion/scope_analysis.txt:24-25` which repeats it, cite a ratification that is not in the cited file. Separately, `net.h:343-344` still documents "the eviction/disconnect callers hold cs_vNodes and/or cs_peers **across the dispatch**" — now false for `DisconnectNodes`, still true for the L8 path. |
| L12 | `headers_manager.cpp:1100-1103` — "(OnBlockActivated holds cs_main and wants cs_headers)" | — | accidental doc drift | Stale as of this branch; `OnBlockActivated` no longer holds `cs_main`. Harmless in itself, but it is the comment that justifies the `GetTip()` pre-fetch at `:1104` — i.e. the stale rationale is load-bearing for L9. |
| L13 | `chain.h:297` drops `pindexFork` and `fInitialDownload` | `UpdatedBlockTip` carries both | pre-existing divergence, INFO | Consumers cannot distinguish extension from reorg, or IBD from steady state. Not introduced here (old signature was a bare `CBlockIndex*`), but the snapshot struct (`chain.h:301-304`) is the natural place to add them and the header explicitly invites it ("Add a field to the snapshot instead"). |
| L14 | `chain.h:1000` — `~TipNotifyDrain()` is implicitly `noexcept` and calls `DrainTipNotifications`, which allocates (`callbacks = m_tipCallbacks`, `toFire.swap`) and locks outside any `try` | Core's queue drain runs on the scheduler thread; same terminate-on-throw exposure | LOW | Callback exceptions *are* caught (`chain.cpp:2608-2616`). A `bad_alloc` from the vector copy, or a `system_error` from the lock, terminates. Also: this destructor now runs during stack unwinding if `ActivateBestChain` throws. |
| L15 | `headers_manager.cpp:986-1021` — on lookup failure `height` stays at its default of **1** (`:987`) and the header is stored + height-indexed at height 1 | Core's `UpdatedBlockTip` subscribers re-enter `LookupBlockIndex` under `cs_main`, and the index entry cannot have vanished | MEDIUM — newly reachable | The port made the lookup non-atomic with the tip update. `GetBlockHeightByHash` (correctly) returns `false` on absence, but the caller's fallback is silent and wrong (height 1), not fail-loud. Window is small (same thread, microseconds) and requires the parent to be absent from `mapHeaders` *and* the block to have left `mapBlockIndex`; under the old code the same fallback existed but was unreachable because `cs_main` was held. |
| L16 | `connman.cpp:457` calls `EvictPeersIfNeeded()` under `cs_vNodes`, while `connman.cpp:1302-1310` explicitly refuses to for exactly that reason | — | UNFORCED-DIVERGENCE | Two inbound-accept paths, opposite decisions on the same hazard, with the safe one carrying the comment explaining why. This is the mechanism behind L8. |
| L17 | No `GUARDED_BY` / `EXCLUSIVE_LOCKS_REQUIRED` / `LOCKS_EXCLUDED` anywhere; "caller must hold cs_main" is prose (`chain.cpp:2539`, `headers_manager.cpp:1113`) | Core compiles with clang thread-safety analysis and annotates every `cs_main`-guarded member | UNFORCED-DIVERGENCE (project-wide, out of scope for this branch) | Relevant because L3's entire safety argument ("no caller holds `cs_main`; `ActivateBestChain` never nests") is exactly the class of claim those annotations make machine-checked. Here it is a paragraph and a shell script. |

---

## 2. Q2 — the `CBlockIndex*` question, corrected

The brief states Core "deliberately does NOT hand subscribers a `CBlockIndex*` for callbacks that may run later." **That is not right, and the correction matters.**

Core's `CValidationInterface::UpdatedBlockTip` takes `const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload`, and `BlockConnected` takes a `std::shared_ptr<const CBlock>` **plus** a `const CBlockIndex*` (modern versions prepend a `ChainstateRole`; I am not asserting the current exact arity). These run on the scheduler thread, long after `cs_main` was released. Core hands out the pointer *because it can*.

Why it can: **Core never destroys `CBlockIndex` objects during normal operation.** They live in `BlockManager::m_block_index` for the process lifetime; there is no runtime eviction. Core's deferred-pointer safety is a *lifetime* invariant, not a locking one — the pointer is stable, only the *fields* need `cs_main`, and that is what the `GUARDED_BY(cs_main)` annotations encode. What Core takes care to pass by value is block *data* (`shared_ptr<const CBlock>`), not the index node.

Dilithion breaks that invariant: `CChainState::EvictLowestWorkNotOnBestChain` (`chain.cpp:221`) erases from `mapBlockIndex` at runtime, and the headers thread drives it. So:

- The port's value-snapshot is **correct and necessary** — but as a *compensation for a Dilithion-specific divergence Core does not have*, not as adoption of a Core idiom. `chain.h:284-289` gets the reasoning exactly right; it just isn't Core's reasoning.
- The consequence the branch only half-follows: if `CBlockIndex*` is unsafe to hold across a lock release **in general** in this codebase, then the callback was one instance of a class, not the class. `GetTip()` and `GetBlockIndex()` still hand out raw pointers to every caller (`chain.h:640` documents this: "acquires cs_main, releases it, and hands back a raw pointer. Every caller that dereferences that pointer without separately holding cs_main is racing the eviction path"). The branch added `GetBlockHeightByHash` and used it at **one** call site. L9 is the live remainder in the same file.

---

## 3. Q1 — is the RAII drain a sound simplification of queue-and-scheduler?

**Sound for the purpose it was built for.** The lock-order argument holds, and the argument is genuinely non-trivial because `cs_main` is a `std::recursive_mutex` (`chain.h:136`) — "the guard ended" does not imply "the mutex is free". `chain.h:979-992` identifies exactly the two facts that make it free, and both check out:

- `cs_main` is **private** (`chain.h:136`, inside the private section) — verified; no accessor or friend exposes it, so no external frame can hold it.
- No `CChainState` method calls `ActivateBestChain` — verified across all 100+ `ActivateBestChain` hits: production callers are `block_processing.cpp:945/:1468`, `block_validation_queue.cpp:402`, `fork_manager.cpp:722`, `dilv-node.cpp:2623/:6446`, `dilithion-node.cpp:2766/:6435/:6647`, plus `chain_selector_impl.cpp:213` (which has **no production caller** — `ChainSelectorAdapter::ProcessNewBlock` is referenced only from `src/test/`).
- Re-entrancy through the drain: `OnBlockActivated` → `chain_selector->ProcessNewHeader` (`headers_manager.cpp:1040`) reaches `cs_main` (`HasBlockIndex`/`EvictLowestWorkNotOnBestChain`/`AddBlockIndex`) but **not** `ActivateBestChain` (`chain_selector_impl.cpp:235-311`). No recursion, and the resulting `cs_headers → cs_main` direction matches the header-processing path rather than opposing it. Correct.
- Coverage: `ActivateBestChain` spans `chain.cpp:386-1329` (`ConnectTip` begins at `:1330`), so all four `NotifyTipUpdate` sites (`:684, :749, :803, :1324`) are inside the one drain's scope. Correct.
- The drain adds no new lock edges: it runs on the *same thread* with the *same caller-frame locks* as the old inline invocation, minus `cs_main`. The edge set is a strict subset. That is a clean argument and it is right.

**What it drops relative to Core's queue** — three things, none currently biting, none documented as an assumption on consumers:

1. **Global serialization / total order.** Core's `SingleThreadedSchedulerClient` guarantees every subscriber sees every event **once, in order, on one thread**. Here, two threads can be in `DrainTipNotifications` concurrently (nothing serializes them; the swap at `chain.cpp:2597` is the only synchronized part). Thread A can queue tip X, be preempted, and deliver X *after* thread B delivered the later tip Y. Delivery is not lost (whoever swaps takes the whole queue), but ordering and single-threadedness are not guaranteed. **Currently benign, by accident of the consumer:** `UpdateBestHeader` (`headers_manager.cpp:2106-2141`) compares cumulative work and is monotone, `mapHeaders[hash] = ...` is idempotent, and `ProcessNewHeader` is idempotent by construction. So an out-of-order or duplicated tip cannot demote state today. Nothing states this as a requirement on future subscribers, and Core's contract is the opposite of it — a subscriber ported from Core may legitimately assume serialized ordered delivery.
2. **No barrier.** There is no `SyncWithValidationInterfaceQueue()` equivalent. In the single-threaded case the RAII drain gives something *stronger* than Core (delivery completes before `ActivateBestChain` returns) — but that is exactly the property queue-stealing breaks: if another thread swapped the queue out first, A's `ActivateBestChain` can return with A's notification still undelivered. So "delivered on return" is true almost always and not guaranteed ever, which is the worst combination for anything that comes to depend on it. Nothing depends on it today.
3. **Cross-call-boundary survival.** Core's queue is a process-wide object; a notification queued anywhere is drained. Here the queue is drained at exactly one function's exit, and the invariant that every producer sits inside that function is enforced by a shell script whose check 1 is weaker than the invariant (L10).

The one place the RAII form is *better* than Core's: it cannot deliver after shutdown began, and it needs no thread. Given that Dilithion has no `CScheduler`, building one for this fix would have been a much larger and riskier change. **The choice is defensible; the undocumented consumer contract is the gap.**

---

## 4. Q3 — two-phase `DisconnectNodes` vs Core's split

Core's `DisconnectNodes()` splits for a **lifetime** reason: the message-handler thread holds counted references (`CNode::AddRef`/`Release`) to nodes it is processing, so the reaper may not delete a node just because it was removed from the node list. Part 1 removes it from the live list and closes the socket under the nodes mutex; part 2 walks `m_nodes_disconnected` and deletes only entries with refcount zero (and idle buffers). Nodes that are still referenced simply survive to the next pass. (Member names differ across Core versions — `cs_vNodes`/`vNodesDisconnected` in older trees, `m_nodes_mutex`/`m_nodes_disconnected` in newer. I'm asserting the structure, not the spelling.)

This port splits for a **lock-order** reason, and does not implement the lifetime mechanism: `detached` unwinds unconditionally at `connman.cpp:1794`, deleting every `CNode` in the same pass. There is no refcount on `CNode`.

**Is it safe here?** Yes, verified — but for reasons outside the function:

- `DisconnectNodes` runs on `ThreadSocketHandler` (`connman.cpp:669`), the same thread as `SocketHandler()`, so the two cannot interleave.
- `ThreadMessageHandler` copies **`int node_id`**, not `CNode*`, out of `m_nodes` (`connman.cpp:703-706, 730`) and re-resolves by id later. No pointer is held across the lock release.
- `CPeerManager::node_refs` does hold raw `CNode*`, but phase 2 calls `RemoveNode(node_id)` (which erases `node_refs` under `cs_nodes`) for **every** node before **any** node is destroyed. BUG #153 and #148 hold, as claimed.
- `~CNode` (`node.cpp:28-30`) only closes the socket — it touches no `CConnman` state — so moving destruction outside `cs_vNodes` introduces no race.

**What is genuinely new, and what isn't:**

- **New, benign:** between phase 1 and phase 2 the node is absent from `m_nodes` but still present in `peers`/`node_refs`. This *reverses* the old observable order (old: dispatch → RemoveNode → CloseSocket → erase from `m_nodes`, per `peers.cpp:1076-1078`). Anything inside the dispatch chain that consults `CConnman::GetNode`/`GetNodeCount` now sees the node already gone. I traced the chain (`DispatchPeerDisconnected` → `OnPeerDisconnected`, `peers.cpp:1665-1731`): it consults `peers` (untouched until `RemoveNode`) and `node_refs` (untouched), never `m_nodes`. BUG #262 is preserved.
- **Not the double-dispatch it looks like:** the eviction fallback at `peers.cpp:1083-1092` fires only when `GetNode()` returns null, and `CPeerManager::GetNode` reads `node_refs`, which phase 1 does not touch. So an eviction landing inside the window still takes the `MarkDisconnect` branch. No double dispatch. (If `GetNode` had read `m_nodes`, the split would have opened exactly the double-dispatch window `peers.cpp:1079` warns about — worth recording as the near-miss it is.)
- **Not new:** a thread that obtained a raw `CNode*` from `node_refs` and dereferences it after `RemoveNode` is a UAF in both versions. That is precisely what Core's refcount prevents and this port does not. Pre-existing; unchanged; unenforced.

**Verdict:** the split preserves the three bug-fix orderings it claims to, and is strictly safer than before on node lifetime. It does **not** preserve the property Core's split exists for, and the safety argument depends on four facts in three other files, none of which is asserted anywhere.

---

## 5. HIGH — the cycle survives on a second path (`connman.cpp:457`)

The branch's own evidence file says: *"AFTER THE FIX: no outbound dispatch under cs_vNodes in connman.cpp — (empty = the forward edge is broken at the primary reaper)"* (`docs/p2p14-lock-inversion/scope_analysis.txt:14-15`).

The tool answers "does `connman.cpp` **textually** dispatch under `cs_vNodes`". The question is "can `cs_headers` be acquired under `cs_vNodes`". Those differ by one indirection, and the indirection is live:

```
CConnman::AcceptConnection
  connman.cpp:447   std::lock_guard<std::mutex> lock(cs_vNodes);        // cs_vNodes HELD
  connman.cpp:457   m_peer_manager->EvictPeersIfNeeded()
CPeerManager::EvictPeersIfNeeded
  peers.cpp:963     std::lock_guard<std::recursive_mutex> lock(cs_peers); // function-scope
  peers.cpp:1080    CNode* node = GetNode(peer_to_evict);
  peers.cpp:1083    else {                                                // no live CNode
  peers.cpp:1089        connman->DispatchPeerDisconnected(peer_to_evict);
CPeerManager::OnPeerDisconnected
  peers.cpp:1708    g_node_context.headers_manager->OnPeerDisconnected(peer_id);
CHeadersManager::OnPeerDisconnected
  headers_manager.cpp:1450  std::lock_guard<std::mutex> lock(cs_headers);  // cs_headers ACQUIRED
```

Forward edge **`cs_vNodes → cs_headers`**, still present.

Reverse edge, unchanged and explicitly enumerated by the branch as "conforming" (`scope_analysis.txt:19`):

```
CHeadersManager::ProcessHeaders
  headers_manager.cpp:222   std::lock_guard<std::mutex> lock(cs_headers);
  headers_manager.cpp:498   connman->PushMessage(peer, getheaders);
CConnman::PushMessage(int, ...)
  connman.cpp:618           CNode* pnode = GetNode(nodeid);
  connman.cpp:598           std::lock_guard<std::mutex> lock(cs_vNodes);   // cs_vNodes ACQUIRED
```

`cs_vNodes` is a plain `std::mutex` (`connman.cpp:1763`, `:598`) and `cs_headers` is a plain `std::mutex` (`headers_manager.cpp:1450`). Two threads, opposite order, non-recursive: **deadlock**, same class as the one this branch fixed.

- **Reachability** is narrow but real: inbound at `nMaxInbound` (`connman.cpp:455`) **and** `peers.size() >= MAX_TOTAL_CONNECTIONS` (`peers.cpp:966`) **and** the evicted peer having a `peers` entry with no `node_refs` mapping (the `else` at `peers.cpp:1083`). The first two are the sustained-inbound-pressure state an attacker chooses. The third is the documented orphan case the fallback exists for — dead code would not have a fallback.
- **Not introduced by this branch.** What makes it load-bearing is that the branch *claims* the forward edge is broken, and the evidence artifact that backs the claim has a blind spot precisely shaped like this path. `net.h:343-344` names this exact call chain — `AcceptConnection → EvictPeersIfNeeded → DispatchPeerDisconnected → OnPeerDisconnected` — in prose, in the file the branch cites as the ratified order.
- **The tree already knows.** `connman.cpp:1302-1310` refuses to call `EvictPeersIfNeeded` from the *other* accept path for this reason. Two accept paths, opposite decisions (L16).
- **Fix shape** matching the ratified rule the branch itself adopted: hoist the `EvictPeersIfNeeded()` call at `connman.cpp:457` out of the `cs_vNodes` scope (decide under the lock, act after release), or convert the `peers.cpp:1083-1092` fallback to mark-and-let-the-reaper-handle-it like its sibling branch.

---

## 6. HIGH — the pointer doctrine is applied at one site and violated at three in the same file

`chain.h:642-664` establishes the rule and gives the reason (`GetBlockIndex` "acquires cs_main, releases it, and hands back a raw pointer… racing the eviction path — the shape LP10 measured under TSan at 6353bc33"). The branch adds `GetBlockHeightByHash` and applies it at `headers_manager.cpp:1018`. Live violations of the identical shape remain:

- `headers_manager.cpp:1104-1105` — `CBlockIndex* pTip = g_chainstate.GetTip(); int chainstateHeight = (pTip && pTip->nHeight > 0) ? pTip->nHeight : 0;` — `nHeight` dereferenced with `cs_main` released.
- `headers_manager.cpp:219-220` — same pattern, `pTipPreFetched`, captured **before** `cs_headers` is taken at `:222`…
- `headers_manager.cpp:490` — …and passed into `GetLocatorImpl` far down the `ProcessHeaders` body, where
- `headers_manager.cpp:1158` — `CBlockIndex* pBlock = pTip->GetAncestor(height);` walks the `pprev` chain, dereferencing index nodes, with `cs_main` not held.

The window at `:219 → :490` spans the entire header-batch processing loop — orders of magnitude longer than the callback window the branch closed — and `ProcessHeaders` is the *same thread that drives eviction*. The mitigating fact is the one `chain.h:288-289` already states: eviction spares the active chain, so the tip survives *until a reorg makes it non-active*. That is the identical residual risk the branch judged unacceptable for the callback.

Also note the justification comment at `headers_manager.cpp:1100-1103` for the pre-fetch is now factually stale (L12): it cites `OnBlockActivated` holding `cs_main`, which this branch removed.

---

## 7. Invariants I checked and confirmed still hold

1. **Snapshot is taken under the lock.** `chain.cpp:2551-2552` dereferences `pindex` inside `NotifyTipUpdate`, which runs under `ActivateBestChain`'s guard. The pointer does not escape.
2. **Callback vector is copied under the lock before iteration.** `chain.cpp:2593-2598`. No race with `RegisterTipUpdateCallback` (`chain.cpp:2533-2536`).
3. **Reverse-order destruction is real and covers every return path.** `drain` at `chain.cpp:393` precedes the guard at `:397`; `ActivateBestChain` has many returns and all are covered without a goto.
4. **The mutex is genuinely free when the drain fires.** Both premises verified independently (§3): `cs_main` private, `ActivateBestChain` never nested. Under a recursive mutex this is the whole argument, and it is correct.
5. **All producers are inside the one drain's scope.** `ActivateBestChain` = `chain.cpp:386-1329`; sites `:684, :749, :803, :1324` all inside.
6. **No new lock edges from the deferral.** Same thread, same caller-frame locks, minus `cs_main`. Strict subset.
7. **No re-entrancy through the consumer.** `OnBlockActivated → ProcessNewHeader` reaches `cs_main` but never `ActivateBestChain`; `ChainSelectorAdapter::ProcessNewBlock` has no production caller.
8. **`cs_headers → cs_main` after the fix is consistent with the pre-existing header path** — one direction only; the cycle at *this* site is genuinely gone.
9. **Delivery is not lost under queue-stealing.** `swap` takes the entire queue; whoever swaps fires everything.
10. **Notification ordering within one activation is preserved** — append-only under `cs_main`, drained in order (`chain.cpp:2606`).
11. **The three `DisconnectNodes` bug-fix orderings (#262, #153, #148) are preserved**, and node lifetime is strictly extended relative to the base (§4).
12. **No `CNode*` is held across a lock release by `ThreadMessageHandler`** — `PendingMessage` carries `int node_id` (`connman.cpp:703-706`).
13. **Exceptions from callbacks cannot escape the drain** (`chain.cpp:2608-2616`), matching the base behaviour.
14. **`ProcessNewHeader` orphan/invalid-parent DoS guards are intact** (`chain_selector_impl.cpp:276-290`) — the new call path does not bypass them.

---

## 8. Severity-tiered findings

**HIGH**
- **H1 (L8, §5)** — `cs_vNodes → cs_peers → cs_headers` survives via `connman.cpp:447/457 → peers.cpp:963/1089 → peers.cpp:1708 → headers_manager.cpp:1450`, against the reverse edge at `headers_manager.cpp:222/498 → connman.cpp:598`. Both mutexes non-recursive. The branch's completeness claim (`scope_analysis.txt:14-15`) rests on a tool that only sees direct dispatch calls in `connman.cpp`. Fix: hoist `EvictPeersIfNeeded()` out of the `cs_vNodes` scope at `connman.cpp:457`, matching the deliberate refusal already documented at `connman.cpp:1302-1310`.
- **H2 (L9, §6)** — raw `CBlockIndex*` deref outside `cs_main` at `headers_manager.cpp:219-220`, `:490`, `:1104-1105`, `:1158` (`GetAncestor` walk), same class as the fixed site, longer window, driven by the eviction thread. The branch wrote the doctrine (`chain.h:642-664`) and applied it once.

**MEDIUM**
- **M1 (L6)** — `chain.cpp:2140-2144` asserts `cs_main` is not held during disconnect callbacks; on the reorg path `ActivateBestChain` holds the recursive `cs_main` in an outer frame, so it is. The same loop iterates the callback vector unlocked. Both are the exact traps `chain.h:979-992` and `chain.cpp:2589-2592` were written to prevent.
- **M2 (L5)** — block-connect callbacks (`chain.cpp:1941-1949`) still fire under `cs_main` into wallet / txindex / coinstatsindex / ZMQ. The new mechanism was built and not applied to them; `cs_main → subsystem-lock` edges remain pre-built for the next inversion.
- **M3 (L3, §3)** — the drain silently imposes an undocumented contract on subscribers: *must be safe when invoked concurrently from multiple threads, and must tolerate out-of-order and cross-thread delivery*. Today's sole subscriber satisfies it by accident (work-monotone `UpdateBestHeader`, idempotent map writes). Core's contract is the opposite, so a subscriber ported from Core would be wrong here. Should be stated at `chain.h:297`.
- **M4 (L10)** — `check-tip-notify-drain.sh` check 1 proves file locality, not drain coverage. A `NotifyTipUpdate` added to `DisconnectToHeight`/`InvalidateBlockImpl`/`ReconsiderBlockImpl` (all in `chain.cpp`, none under the drain) passes all four checks and leaks silently — the precise failure the script says it exists to catch. Tighten to "inside `ActivateBestChain`'s line range", or assert the canary in a test.
- **M5 (L15)** — `OnBlockActivated`'s chainstate height lookup is no longer atomic with the tip update; on failure the header is stored and height-indexed at height **1** (`headers_manager.cpp:987`) with no log. Make the fallback loud, or skip the store.

**LOW / INFO**
- **L-1 (L11)** — `connman.cpp:1733-1734` and `scope_analysis.txt:24-25` cite a `net.h` ratification of `cs_headers`'s position that `net.h:338-353` does not contain (it ratifies `cs_vNodes → cs_peers → {rate-limit mutexes}` only; `cs_headers_rate` ≠ `cs_headers`). Either add `cs_headers` to `net.h`'s order or stop citing it. Also update `net.h:343-344`, now false for `DisconnectNodes`.
- **L-2 (L12)** — stale comment at `headers_manager.cpp:1100-1103`.
- **L-3 (L14)** — `~TipNotifyDrain` is `noexcept` over allocating, locking code; `bad_alloc` terminates.
- **L-4 (L13)** — no `pindexFork` / `fInitialDownload` equivalent; consumers cannot distinguish reorg from extension.
- **L-5 (L16)** — two inbound-accept paths make opposite calls on the same hazard.
- **L-6 (L17)** — no clang thread-safety annotations; L3's safety argument is prose + a shell script where Core has a compiler.
- **INFO** — `ChainSelectorAdapter::ProcessNewBlock` (`chain_selector_impl.cpp:93-218`) has no production caller. Fine, but it means `chain_selector_impl.cpp:213` in the "every `ActivateBestChain` caller" audit (`chain.h:984-985`) is a test-only site; the audit is correct but its scope should say so.

---

## 9. Verdict

**The tip-callback deferral is equivalence-safe and correctly reasoned.** The RAII drain is a legitimate simplification of Core's queue-and-scheduler given that Dilithion has no scheduler thread; the recursive-mutex hazard is identified and both premises that neutralise it are true; the value-snapshot is the right call, and is in fact *more* necessary here than in Core because Dilithion evicts block-index entries at runtime, which Core does not. The `DisconnectNodes` split preserves the three orderings it claims and improves node lifetime. Nothing in the ported region is an accidental divergence from Core's *intent*.

**But two load-bearing items are unresolved, and both are of the form "the fix is right and incomplete, while the artifact says it is complete":**

1. **H1 — the `cs_vNodes ↔ cs_headers` cycle is still closable** through `AcceptConnection → EvictPeersIfNeeded → DispatchPeerDisconnected → OnPeerDisconnected`, and the branch's evidence tool cannot see it. A branch whose thesis is "the forward edge is broken" must either break this one too or state explicitly that it does not.
2. **H2 — the raw-`CBlockIndex*`-across-a-lock-release class is left live** at three sites in the file the branch edited, including a `GetAncestor()` walk, after the branch established the doctrine that this is unsafe.

Neither is a regression introduced by the diff. Both are within the blast radius of the claims the diff makes. **Do not merge on the current completeness claim.** Either fix H1 and H2, or amend `docs/p2p14-lock-inversion/scope_analysis.txt` and the `connman.cpp:1729-1758` comment to scope the claim to the primary reaper and record H1/H2 as known-residual with owners — so the next reader does not inherit "the forward edge is broken" as fact.

M1 (the false "cs_main is NOT held" comment) should go in the same change regardless: a comment that states the opposite of the truth about a recursive mutex is how this class of bug is reintroduced.
