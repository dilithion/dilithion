# Red-team review — p2p14/15 lock-order fix, worktree `C:/tmp/a8-p2p15`

Fresh-context adversarial pass, Family-A concurrency, HEAVY tier. Read-only. No Bash — every
claim below comes from reading the tree with Read/Glob/Grep.

**⚠️ PROVENANCE CAVEAT: the worktree was edited by another actor DURING this review.**
Between my first read of `peers.cpp` and my last, line numbers in that file shifted by ~+16 and
the `connman.cpp` rationale block was rewritten. All `path:line` citations below were
**re-anchored by grep at the end of the pass** and are current as of my final read. Anything I
quote as "still says X" was verified after the shift, not before.

---

# Findings

## HIGH-1 — `CConnman::AcceptConnection` is dead code; the "SECOND live forward edge" was never live — VERIFIED, FOLDED

Reported mid-pass, independently re-verified by the coordinator, and corrected in-tree during
this review. Retained only as a record. Evidence: whole-tree grep for `AcceptConnection` returns
the definition (`connman.cpp:453`), its own log strings, two comments (`connman.cpp:1341/:1346`),
the declaration (`connman.h:130`) and one stale doc line (`peers.cpp:1783`) — **no call site
anywhere, including tests**. The codebase already said so at `connman.cpp:1342` ("it has NO
production caller — every real inbound is accepted here in SocketHandler"). Only production
caller of `EvictPeersIfNeeded` is `peers.cpp:1151` (PeriodicMaintenance); `connman.cpp:502` is
inside the dead function. No further action.

## HIGH-2 — NEW, and not in any prior review: `m_next_node_id++` is a non-atomic RMW performed OUTSIDE `cs_vNodes` on the LIVE accept path, while the outbound path does it INSIDE

`connman.h:325` declares `int m_next_node_id = 1;` — a plain `int` in the `private:` block that
`cs_vNodes` guards. Three increment sites, and they do not agree:

| site | function | lock state |
|---|---|---|
| `connman.cpp:413` | `CConnman::ConnectNode` (outbound) | **INSIDE** `cs_vNodes` — the comment at `:412` says "still holding lock" |
| `connman.cpp:1294` | `CConnman::SocketHandler` inbound accept — **the live production accept path** | **OUTSIDE** — the comment at `:1293` says "Create CNode first (before locking)"; the `cs_vNodes` guard is not taken until `:1306` |
| `connman.cpp:559` | `AcceptConnection` (dead, HIGH-1) | OUTSIDE |

**Concrete failure sequence.** T1 = `threadSocketHandler` (`connman.cpp:1294`, inbound accept).
T2 = the connection-opener / RPC `addnode` thread inside `ConnectNode` (`connman.cpp:413`). Both
execute `m_next_node_id++` — a load-modify-store on a non-atomic `int` — concurrently, and only
T2 holds `cs_vNodes`. That is a data race (UB) on its face; on any real interleaving where both
read the same value it also mints **two live CNodes with the same `node_id`**.

**Why a duplicate id is not cosmetic.** `CPeerManager::RegisterNode` does
`node_refs[node_id] = node` and `peers[node_id] = …` under `scoped_lock(cs_peers, cs_nodes)`
(`peers.cpp:1836/:1843`, keyed on the id). Two CNodes sharing one id means:
- the second registration silently overwrites the first's `node_refs` entry — `GetNode()` for
  that id now returns the wrong CNode, which is then handed to `Misbehaving` /
  `PeriodicMaintenance` / `MarkDisconnect`;
- when either node disconnects, `RemoveNode(id)` erases the single shared entry, so the survivor
  is unreachable via `GetNode` for the rest of its life and its per-peer rate-limit/dedup maps
  are never cleaned. That is exactly the unbounded-map memory-exhaustion DoS that
  `peers.cpp:1764` says is prevented — and the sentence it rests on,
  *"Node IDs are monotonic (never reused, connman `m_next_node_id`)"*, is **precisely the premise
  this race breaks**.

**Standing.** Pre-existing, not introduced by this branch. Reported HIGH anyway because (a) it is
a live data race on the exact object this branch just ratified a lock discipline for
(`net.h:338-378` enumerates the order and says nothing about members mutated outside it), (b) the
branch's own reasoning at `peers.cpp:1764` depends on the invariant it breaks, and (c) three
prior review passes over these two files did not name it. TSan on a concurrent accept+connect
workload would flag it directly — the existing harness does not drive that pair.

**Fix shape:** `std::atomic<int> m_next_node_id{1};` with `fetch_add`, or move `:1294` inside the
`:1306` scope. One line either way.

## MEDIUM-1 — the census's §1 premise is TRUE; its inference is NOT entailed, and the census then relies on the inference to skip the work that actually closes the case

`CENSUS_cs_headers_edges.md:17-28` claims `cs_vNodes` (`connman.h:324`), `cs_peers`
(`peers.h:214`) and `cs_main` (`chain.h:136`) are private with zero `friend`s, therefore "only
`connman.cpp` can hold `cs_vNodes`, only `peers.cpp` can hold `cs_peers`, and only `chain.cpp`
can hold `cs_main`", therefore "no other file can create an inverted edge".

**I attacked the premise and it holds.** Verified this pass: no `friend` declaration in any of
the three headers; no public accessor returning a lock, a `unique_lock`, or a locked view; no
`protected:` exposure; the one nested class (`CChainState::TipNotifyDrain`, `chain.h:1020-1041`)
is itself declared after `private:` at `:981` and takes no lock; and a whole-tree grep for
`cs_main` outside `src/consensus/chain.*` returns **31 hits, every one a comment**. The premise
is sound and I could not break it.

**The inference is still false.** Privacy bounds where a lock can be *acquired*. It does not
bound where it is *held* — and an inverted edge is created by what runs while the lock is held,
not by who acquired it. All three locks are held across calls into other translation units:

- `cs_main` held across `m_blockConnectCallbacks[i](...)` at `chain.cpp:1943` (its own comment at
  `:1933` says so: "cs_main IS held during these callbacks"), across
  `m_blockDisconnectCallbacks[i](...)` at `chain.cpp:2147`, across the `onConfirmedCorruption`
  callback (`chain.h:607-613`, "runs synchronously inside cs_main"), and across the
  `ConnectTipOverride` / `DisconnectTipOverride` / `ReadBlockOverride` hooks (`chain.h:239-246`).
- `cs_vNodes` held across `DispatchPeerConnected` → `CPeerManager::RegisterNode`
  (`connman.cpp:605` and `:1375`).
- `cs_peers` held across `g_node_context.GetPeerTrustScore(pid)` (`peers.cpp:1046`) — a
  `std::function` whose body lives in `dilithion-node.cpp:7616` / `dilv-node.cpp:7447`.

So §1 cannot carry the conclusion. What actually closes the `cs_main` leg is the enumeration of
the callback registrant bodies — which the census explicitly *declines* to do (`:97-99`, "I
enumerated the registrants, I did not read every registrant's body") while still writing
"complete … by the privacy argument in §1" at `:84-86`. **Those two sentences cannot both be
true.** I did that enumeration by hand (see NO-FINDINGS-1) and the conclusion survives — but it
survives on the enumeration, not on §1.

Severity MEDIUM: the verdict is right, the stated method does not establish it, and the method
is what the next change gets audited against.

## MEDIUM-2 — §3's exclusion is a depth-1 grep presented as "by construction"

`CENSUS_cs_headers_edges.md:38-48` greps five callee implementations (`node.cpp`, `addrman.cpp`,
`banman.cpp`, `block_tracker.cpp`, `connection_quality.cpp`) for `headers_manager` /
`CHeadersManager`, gets 0, and concludes "**Zero references means no path through them reaches
`cs_headers`, by construction**".

Invalid as stated: zero *direct* references excludes a depth-1 edge only. `node.cpp` → X →
`headers_manager` is not excluded by grepping `node.cpp`. A transitive-closure argument, or a
whole-program one, is what "by construction" would require.

I probed the three highest-risk instances the argument cannot see and found **no live
violation**:
- `peers.cpp:1046` `GetPeerTrustScore` under `cs_peers` → `dilithion-node.cpp:7616-7636`: takes
  `g_mik_peer_mutex` and the trust manager's own locks. **Clean.**
- `peers.cpp:1042` `sync_coordinator->IsInitialBlockDownload()` under `cs_peers` →
  `CIbdCoordinator::IsInitialBlockDownload` (`ibd_coordinator.cpp:442-444`) → `!IsSynced()` →
  atomic load. **Clean** — and notable, because `ibd_coordinator.cpp` carries 81
  `headers_manager` references and sits one virtual dispatch below `cs_peers`.
- `peers.cpp:1038` `g_chainstate.GetHeight()` under `cs_peers` → `chain.cpp:2519-2523`, a
  lock-free `m_cachedHeight.load()`. **Clean — it does NOT take `cs_main`**, which is load-bearing:
  if it did, `cs_peers → cs_main` would exist directly under the eviction lock.

## MEDIUM-3 — the stale-premise twin at `net.cpp:1170-1176` was NOT corrected when its `peers.cpp` sibling was, and it is a defence-in-depth-erosion trap

The confirmation review named three places asserting the (now false) fact that the disconnect
dispatch runs under `cs_peers`. During this pass the `peers.cpp` one was fixed — it now reads,
correctly, at `peers.cpp:1769-1778`: "⚠️ CORRECTED BY P2P-14/15 … BOTH halves are now false".

**`net.cpp:1170-1176` still carries the uncorrected version:**

    // dilv-dedup-livelock-fix (F-009 BLOCKER-1): Misbehaving() takes cs_peers (via GetPeer),
    // and the eviction/disconnect path takes cs_peers and then, via OnPeerDisconnected →
    // CleanupPeerRateLimitState, the rate-limit mutexes. Calling Misbehaving WHILE holding
    // cs_getdata_rate inverts that order → a reachable {cs_getdata_rate, cs_peers} AB-BA
    // deadlock (GETDATA-storm peer + inbound-at-limit eviction). INVARIANT: never call
    // Misbehaving (or anything that acquires cs_peers) while holding a rate-limit mutex

"the eviction/disconnect path takes `cs_peers` and then … the rate-limit mutexes" is now false on
both callers: `DisconnectNodes` dispatches with `cs_vNodes` released (`connman.cpp` phase 2) and
`EvictPeersIfNeeded` releases `cs_peers` at `peers.cpp:1134` before dispatching.

**Why this is more than a doc nit (lens 6).** The F-009 *invariant* is still correct and the hoist
at `net.cpp:1165`/`:1177` (decide under `cs_getdata_rate`, penalize after release) is still
wanted. But its written justification is now a scenario that no longer occurs. A future reader
who checks the cited AB-BA and finds it gone has a documented licence to conclude "this hoist is
redundant now" and move `Misbehaving` back inside the rate-limit scope — re-creating a real
inversion, because `cs_headers → … → cs_peers` still reaches that mutex family by other routes.
This is the "removed a guard because the cited reason expired" shape. Fix: mirror the
`peers.cpp:1769-1778` correction into `net.cpp:1170`, and restate the invariant as
order-based ("rate-limit mutexes are LAST; nothing above them may be acquired beneath them")
rather than scenario-based.

## LOW-1 — `EvictPeersIfNeeded`'s post-unlock window can silently drop the bookkeeping the dispatch exists to perform

`peers.cpp:1134-1138`:

    lock.unlock();
    if (g_node_context.connman) { g_node_context.connman->DispatchPeerDisconnected(peer_to_evict); }
    RemovePeer(peer_to_evict);  // re-acquires cs_peers itself

The staleness note at `:1129-1133` covers `RemovePeer` ("in which case it is a no-op") and the
recursive-mutex premise, but not the dispatch itself. `OnPeerDisconnected` does two `peers`-map
lookups under freshly-acquired `cs_peers` — `peers.cpp:1703` (`MarkAddressTried` on a
non-handshake-complete peer) and `peers.cpp:1726` (DNA `on_peer_disconnected`). With `cs_peers`
released between decision and dispatch, a concurrent erase makes both silent no-ops.

Sequence: T1 PeriodicMaintenance → `EvictPeersIfNeeded` selects peer 42 (no live CNode), unlocks
at `:1134`. T2 takes `cs_peers` and erases 42. T1 dispatches; `peers.find(42)` misses twice; the
failed-connection attempt is never recorded in AddrMan and the DNA collector never sees the
disconnect. Before the change this whole sequence was atomic under `cs_peers` on this path.

LOW: bookkeeping loss on a rare fallback branch, no corruption, narrow window. Flagged because
the change's own staleness note is narrower than the staleness it introduced.

## LOW-2 — `total_count` is read before eviction and consumed after it (answers the brief's cap question)

`connman.cpp:492` reads `total_count = m_nodes.size()` under `cs_vNodes`; `:512` compares it to
`nMaxTotal` *after* `EvictPeersIfNeeded` may have run at `:502`. **Direct answer to attack item 3:
no, the hoist cannot admit a connection past a hard cap.** The staleness is fail-closed (it can
reject a connection whose slot eviction just freed, never admit one), and the check→insert gap
(`:512` vs the insert scope at `:602`) was already non-atomic before the change — the insert has
always been a separate `cs_vNodes` acquisition. The hoist widens an already-advisory window; it
does not create a bypass. And the function is unreachable anyway (HIGH-1). The **live** accept
path at `connman.cpp:1306-1366` reads its counts and inserts inside **one** `cs_vNodes` scope, so
it is strictly tighter than the dead one. Informational.

---

# Explicit no-findings (silence is not a pass)

## NO-FINDINGS-1 — attack item 2, the registrant bodies: **I read them. None reaches the headers manager. `cs_main → cs_headers` does not return by that route.**

This is the gap the census names at `:97-99` and every prior seat left open. Closed by hand.
`m_blockConnectCallbacks` / `m_blockDisconnectCallbacks` fire under `cs_main` at
`chain.cpp:1943` and `chain.cpp:2147`. Full registrant set, both binaries, bodies read:

| registrant | body reaches | verdict |
|---|---|---|
| `dilithion-node.cpp:3322/:3331` · `dilv:3193/:3202` | `g_tx_index->WriteBlock/EraseBlock` | `tx_index.cpp` has **0** `headers_manager` refs — clean |
| `dilithion-node.cpp:3414` · `dilv:3243` | `ibd_coordinator->IsSynced()` (atomic), `CBlockValidator`, `g_fee_estimator->processBlock` | clean |
| `dilithion-node.cpp:3480/:3489` · `dilv:3302/:3311` | `g_coin_stats_index->WriteBlock/EraseBlock` | clean |
| `dilithion-node.cpp:5277/:5280`, `:5855/:5858` · `dilv:5309/:5312`, `:5922/:5925` | `wallet.blockConnected/blockDisconnected` | grep of **all of `src/wallet/`** for `headers_manager\|connman\|peer_manager\|cs_headers` returns **0 matches across 0 files** — clean |
| `dilithion-node.cpp:6035/:6097` · `dilv:6083/:6152` | DFMP identity DB, heat trackers, `mik_pubkey_cache` | clean |
| `dilithion-node.cpp:6119/:6129` · `dilv:6174/:6184` | `rpc_server->Increment/DecrementAcceptedSession` → `server.h:636/:639`, atomic counter | clean |
| `dilithion-node.cpp:6149/:6159` · `dilv:6204/:6215` | `cooldown_tracker->OnBlockConnected/Disconnected` | clean |
| `dilithion-node.cpp:6179` · `dilv:6237` | `g_pendingMinerWinsMutex`, `g_chainstate.GetTip/GetBlockIndex` (re-entrant `cs_main`) | clean |
| `dilithion-node.cpp:6214` · `dilv:6273` | DNA collector, trust manager, verification manager, `CBlockValidator` | clean |
| `dilithion-node.cpp:7288` · `dilv:7110` | `CRPCServer::NotifyBlockTipChanged()` → `server.cpp:10033-10039`, a bare `cv.notify_all()` | clean — this was the most dangerous-looking one, since `rpc/server.cpp` carries 10 `headers_manager` refs; the callback touches none of them |

I also located every `headers_manager` reference in both node binaries and confirmed none falls
inside a connect/disconnect registrant body. The two that look like they might:
`dilithion-node.cpp:6323-6332` / `dilv-node.cpp:6386-6395` are inside
`resource_monitor.SetCleanupCallback` (a `CResourceMonitor` thread, no chainstate lock), and
`dilithion-node.cpp:8273` / `dilv-node.cpp:7981` are in the IBD progress-monitor loop. The only
registrant that reaches the headers manager at all is the **tip** callback
(`dilithion-node.cpp:3555-3557`, `dilv-node.cpp:3375-3377`) — which is the one the fix moved
outside `cs_main`.

## NO-FINDINGS-2 — attack item 4, the `unique_lock`: correct on every path

`peers.cpp:968` `std::unique_lock<std::recursive_mutex> lock(cs_peers)`; single `unlock()` at
`:1134`. Checked exhaustively:
- Every early return (`:971` not-at-limit, `:1029` no candidates, `:1143` no peer) leaves the
  lock **owned**, and `~unique_lock` releases it. No path returns with the mutex held or
  double-unlocks (`owns_lock()` is false after `:1134`, so the destructor is a no-op).
- Nothing after `:1134` touches `cs_peers`-guarded state directly: the only values used are
  `peer_to_evict` (an `int`, copied at `:1062`) and `g_node_context.connman`. The
  `std::shared_ptr<CPeer> peer` from `:1063` and the `CNode* node` from `:1085` are **not** used
  after the unlock. `RemovePeer` re-acquires for itself.
- **The recursive-mutex trap is closed and correctly documented.** `cs_peers` is
  `std::recursive_mutex`, so `unlock()` would be a *no-op for deadlock purposes* if any caller
  held an outer `cs_peers`. I verified both callers independently: `PeriodicMaintenance`
  (`peers.cpp:1146-1151`) calls it **before** its own `lock_guard` opens at `:1159`, and the
  other caller is the dead `connman.cpp:502`. The in-tree comment at `peers.cpp:1129-1133` states
  this premise and its failure mode explicitly, mirroring `chain.h:1002-1015`. This is the one
  place in the change where the reasoning is genuinely airtight.

## NO-FINDINGS-3 — the `TipNotifyDrain` mechanism itself

`chain.cpp:393` `TipNotifyDrain drain(*this);` precedes `chain.cpp:397`
`lock_guard<recursive_mutex> lock(cs_main)`, so reverse-destruction order fires the drain after
release. `NotifyTipUpdate` (`chain.cpp:2538-2579`) dereferences `pindex` under the lock and
snapshots `{header, hash}` by value — no pointer escapes. `DrainTipNotifications`
(`chain.cpp:2581-2619`) re-acquires briefly to swap the queue **and copy `m_tipCallbacks`**
(correct — `RegisterTipUpdateCallback` mutates that vector under `cs_main`, so iterating it
unlocked would be the very race class at issue), then fires with the lock released, per-callback
try/catch. `~TipNotifyDrain` (`chain.h:1023-1036`) wraps the whole body in `catch (...)` with an
empty, allocation-free handler — nothing can escape a destructor. The undrained-queue canary at
`chain.cpp:2571-2578` is a real guard against a future fifth `NotifyTipUpdate` call site.
`GetBlockHeightByHash` (`chain.cpp:198-210`) does find + dereference + copy inside one lock scope
and returns `bool` + out-param — the pointer genuinely cannot escape. **No findings.**

## NO-FINDINGS-4 — no NEW cycle was opened by moving work out of the locks

I checked the direction the census does not cover, in case the hoists created a
`cs_vNodes/cs_peers → cs_main` leg to pair with the `cs_main → cs_*` callback legs:
`grep g_chainstate` over `connman.cpp` returns **no matches at all**; over `peers.cpp` it returns
exactly two (`:16` the include, `:1038` `GetHeight()`, which is lock-free). So neither net-layer
lock is ever held above `cs_main`. No new cycle.

## NO-FINDINGS-5 — attack item 3 extended (coordinator's question): what ELSE the branch touches is NOT dead

`AcceptConnection` is the only dead surface in the change. Verified live by call-site grep:
`CConnman::DisconnectNodes` ← `connman.cpp:713` (SocketHandler); `CPeerManager::PeriodicMaintenance`
← `dilithion-node.cpp:6893`, `dilv-node.cpp:6717`; `CHeadersManager::OnBlockActivated` ←
the tip callbacks in both binaries (+ the TSan test); `CChainState::GetBlockHeightByHash` ←
`headers_manager.cpp:1018` inside `OnBlockActivated`'s parent-missing branch. `ActivateBestChain`
(the `TipNotifyDrain` host) is reached from `block_processing.cpp`, `block_validation_queue.cpp`,
`fork_manager.cpp`, `chain_selector_impl.cpp` per `chain.h:1006-1008`. **Four of the five changed
surfaces are live; one is not.**

---

# NOT-REACHED — examined by nobody this pass, do not read as clean

1. `scripts/check-tip-notify-drain.sh`, `scripts/run_p2p14_lock_inversion_tsan.sh`, the Makefile
   wiring and the CI leg — **unopened by me and, per the confirmation review's own not-examined
   list, by every prior seat.** The `|| true` / unconditional-green class has bitten this repo
   before. This is the largest single hole left in the evidence chain.
2. `docs/p2p14-lock-inversion/tsan_*.err` (5 files) — not read. I relied on prior seats' reading.
   I did NOT verify that the both-arms control actually goes red on the unfixed arm.
3. `src/test/p2p14_lock_inversion_tsan_tests.cpp` — I read only the header comment block
   (`:1-60`) and the `GetBlockHeightByHash` region referenced at `:165-247`. The lock-order arms,
   the reachability guard, and whether the harness drives the *production* call graph or a
   fixture were not examined. Given HIGH-1 (the accept arm is unreachable in production), the
   question "which arm does the harness actually construct" is now materially more important.
4. `g_validation_mutex` — out of contract scope, not analysed, same as the census.
5. `CHeadersManager::UpdateBestHeader` monotonicity (red-team H-3). Still unopened by any seat.
6. The forward direction `cs_headers → cs_vNodes/cs_peers`: I confirmed the six `Misbehaving` /
   `PushMessage` sites exist by grep and by reading `headers_manager.cpp:1018`, but I did not
   re-walk all six. Prior reviews did.
7. `headers_manager.cpp` outside `:940-1160` and `:200-230` — 178 `cs_headers`-adjacent
   references in that file; I read two regions. In particular `ProcessHeaders`'s full body and the
   `chain_selector->ProcessNewHeader` call made **under `cs_headers`** at `headers_manager.cpp:1041`
   → `chain_selector_impl.cpp:235-279` — I read the first 45 lines of that callee (it takes
   `cs_main` via `HasBlockIndex`/`GetBlockIndex`/`EvictLowestWorkNotOnBestChain`, i.e. a
   `cs_headers → cs_main` edge, direction-consistent) but not to its end.
8. `CNode` lifetime across the new `DisconnectNodes` phase-2 window — I read the function and the
   BUG #262/#153/#148 ordering holds on every path including the throwing one, but I did **not**
   audit every other consumer of a `CNode*` for the new "alive but no longer in `m_nodes`"
   window. `net.h:362-363` already warns the pointer is not lifetime-safe outside `cs_vNodes`.
9. `dilv-node.cpp` registrants at `:3302/:3311`, `:5309/:5312`, `:5922/:5925`, `:6083`, `:6152`,
   `:6174/:6184`, `:6204/:6215` — verified as **textual mirrors** of the dilithion twins I read
   line-by-line (I read `dilv:3193-3257`, `:6237-6304`, `:7110-7113` in full and they are
   character-for-character parallel). Eight bodies are mirror-inference, not direct reads.
10. Signal handlers — not examined, same as the census.
11. `git show` / `git diff` of any commit — no Bash. I cannot attribute any line to a commit;
    everything above is a statement about the tree as it stands.
12. Whether the mid-run edits to `peers.cpp` / `connman.cpp` introduced anything new — my final
    re-anchor re-read the changed regions of both files, but not the whole files a second time.

---

# Verdict

**Does anything LOAD-BEARING remain? Yes — one item, and it is not the branch's own mechanism.**

The P2P-14/15 mechanism itself is **sound**. I attacked all four named surfaces and could not
break any of them: the `TipNotifyDrain` declaration-order trick is correct and its premise
(private `cs_main`, no `CChainState` self-call into `ActivateBestChain`) is verified, not
asserted; the value-passing callback removes the escaping pointer completely;
`GetBlockHeightByHash` is a genuine fix, not a paper one; the `unique_lock` in
`EvictPeersIfNeeded` is correct on every path *and* its recursive-mutex trap is closed at both
callers; the `DisconnectNodes` two-phase detach preserves all three encoded bug-ordering
constraints including on the throwing path; and no new cycle was opened in the reverse direction.
**Most importantly, I closed the census's own named gap — every block-connect and
block-disconnect registrant body in both binaries — and `cs_main → cs_headers` does not return.**

What remains load-bearing is **HIGH-2**: a live, pre-existing data race on `m_next_node_id`
(`connman.cpp:1294` outside `cs_vNodes` vs `connman.cpp:413` inside it) that can mint duplicate
node ids and that **invalidates the stated premise of an unrelated leak fix**
(`peers.cpp:1764`, "node IDs are monotonic, never reused"). It is a one-line fix and it sits in
the same file and the same lock discipline this branch just ratified. Merging without it is a
defensible scope call; merging without *recording* it is not.

MEDIUM-1/2/3 are all reasoning-quality defects rather than runtime ones. They matter more than
usual here only because this change's deliverable is partly a *document* — `net.h:338-378` and the
census — that future changes will be audited against. A census whose headline says "complete by
construction" while its own boundary section says the decisive enumeration was not performed will
be cited as settled by the next reader. It should say what it actually establishes.

Everything else I found is LOW, and after HIGH-2 and the MEDIUM-3 comment correction, **nothing
load-bearing remains in the change itself**.
