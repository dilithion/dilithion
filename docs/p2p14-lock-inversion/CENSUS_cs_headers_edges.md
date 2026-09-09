# P2P-14/15 — call-graph census: every edge into `cs_headers`

**Why this exists.** Three consecutive passes each closed one lock level of the same chain and
declared the cycle closed. Each was wrong, and each was caught by a *different* lens:

    pass 1  my per-file scope analysis   -> missed the accept path    (connman.cpp)
    pass 2  port-reviewer                -> caught pass 1; I fixed it and declared closed
    pass 3  confirmation read            -> caught pass 2, found the eviction path (peers.cpp)

That is the convergence rule firing: findings recurring across rounds mean the **modality** is wrong,
not that one more site-fix will land. The fix was aimed at sites. This is aimed at the chain.

**Method: exclusion + enumeration + a privacy argument — not sampling.**

---

## 1. The locks are PRIVATE. This bounds the problem to three files.

| lock | declared | nearest access specifier | `friend` decls in header |
|---|---|---|---|
| `cs_vNodes` | `connman.h:324` | `private:` at `:221` | **0** |
| `cs_peers` | `peers.h:214` | `private:` at `:207` | **0** |
| `cs_main` | `chain.h:136` | `private:` at `:107` | **0** |

**Therefore only `connman.cpp`, `peers.cpp` and `chain.cpp` can ACQUIRE these locks** — the set of
*holding frames* is bounded to three files.

**⚠️ CORRECTED (final red-team MEDIUM-1): that bounds ACQUISITION, not REACH, and an earlier version
of this section drew the stronger conclusion it does not support.** Privacy says where a lock is
taken; an inverted edge is created by whatever RUNS while it is held — and all three locks are held
across calls into other translation units (`cs_main` across the connect/disconnect callbacks and the
test hooks; `cs_vNodes` across `DispatchPeerConnected` → `RegisterNode`; `cs_peers` across the
`GetPeerTrustScore` `std::function` whose body lives in a node binary). So §1 alone cannot carry
"no other file can create an inverted edge".

**What §1 actually buys** is still substantial and is the reason to state it: the search for holding
frames is confined to three files, so §3's exclusion and §4's enumeration only have to cover the
outbound calls made *from those three files*, rather than the whole tree. **Completeness comes from
§3 + §4 + §5a, not from §1.** The earlier text asserted "complete … by the privacy argument in §1"
while §7 admitted the decisive enumeration had not been done — two statements that could not both be
true, and the kind of contradiction that gets a document cited as settled.

## 2. `cs_headers` is acquired in exactly ONE file

`src/net/headers_manager.cpp` — 46 `CHeadersManager` methods take it. Every route to `cs_headers`
therefore passes through a call to one of those methods. **The reverse-edge surface is the set of
such calls made from the three lock-holding files.**

## 3. Exclusion: subsystems reachable under those locks that CANNOT reach `cs_headers`

`grep -c 'headers_manager\|CHeadersManager'` over each callee subsystem's implementation:

    node.cpp                0    -> CloseSocket, MarkDisconnect, Ban, IsConnected, PopProcessMsg …
    addrman.cpp             0    -> RecordAttempt …
    banman.cpp              0    -> IsBanned …
    block_tracker.cpp       0    -> GetPeerInFlightCount …
    connection_quality.cpp  0    -> RemovePeer …

**Zero references means no path through them reaches `cs_headers`, by construction.** Every call made
under `cs_vNodes`/`cs_peers` into these objects is excluded wholesale, which removes the large
majority of the outbound-call surface without inspecting it line by line.

## 4. Enumeration: the complete surface is 13 references, of which TWO are live calls

| file | refs | breakdown |
|---|---|---|
| `peers.cpp` | 6 | 1 `#include`, 3 comments (mine), **1 live call: `:1739 OnPeerDisconnected`** |
| `connman.cpp` | 4 | **4 comments (mine) — zero live calls** |
| `net.cpp` | 3 | 1 `#include`, **1 live call: `:1805 GetBestHeight`** |

### The two live calls, resolved

**`net.cpp:1805` — `GetBestHeight()`.** Inside `CNetMessageProcessor::ProcessHeadersMessage`, at the
top of the function, **`[held: -]`**. A message-handler entry point, not under a net lock. **CLEAN.**
*(This call had never been examined by any pass, including mine. It is the reason to run a census
rather than chase the chain you already know about.)*

**`peers.cpp:1739` — `OnPeerDisconnected()`.** Inside `CPeerManager::OnPeerDisconnected`. Two callers:

    connman.cpp  DisconnectNodes -> DispatchPeerDisconnected   locks: NONE (phase 2, post-detach)
    peers.cpp    EvictPeersIfNeeded fallback                   locks: NONE (after lock.unlock())

Both were forward edges before this branch; both are now lock-free at the call. **CLEAN.**

## 5. The `cs_main` direction

`cs_main` is private to `CChainState`, so only `chain.cpp` can hold it, and `chain.cpp` contains **no
call to any `CHeadersManager` method**. The only route was the **inverted** one — the tip callback,
a `std::function` registered by the node binaries and fired from inside `ActivateBestChain`. That is
what `TipNotifyDrain` moves outside the lock. No other callback family in `chain.h`
(`m_blockConnectCallbacks`, `m_blockDisconnectCallbacks`) has a registrant that reaches
`headers_manager`.

## 5a. The registrant enumeration — DONE, and it is what closes the `cs_main` leg

This was an open gap in every prior pass, including the first version of this census. **The final
red-team read every connect/disconnect registrant body in BOTH binaries** and confirmed none reaches
the headers manager: tx_index, fee estimator, coinstats, wallet (a whole-tree grep of `src/wallet/`
for `headers_manager|connman|peer_manager|cs_headers` returns **0 matches**), DFMP, session counters,
VDF cooldown, miner-win, DNA, and the one that looked most dangerous —
`CRPCServer::NotifyBlockTipChanged()`, which is a bare `cv.notify_all()`.

**The only registrant that reaches the headers manager is the tip callback — the one this branch
moved out of the lock.** So `cs_main → cs_headers` does not return by another route, and that
verdict rests on the enumeration, not on §1's privacy argument.

## 6. Result

**Every edge into `cs_headers` from a lock-holding frame is now lock-free at the call.** The set is
complete for `{cs_vNodes, cs_peers, cs_main}` by: §1 bounding holding frames to three files, §3
excluding five callee subsystems with zero references, §4 enumerating the 13 remaining references
down to two live calls, and **§5a reading every callback registrant body** — the last of which is
what actually closes the `cs_main` leg.

## 6b. ⚠️ CORRECTION — one entry point in this census is DEAD CODE

Final-head red-team, verified independently: **`CConnman::AcceptConnection` has ZERO callers** in the
whole tree — no production call site, no test. Only the declaration (`connman.h:130`), its own log
strings, two comments, and a deprecated doc reference (`peers.cpp:1768`). The tree already said so at
`connman.cpp:1327`: *"it has NO production caller — every real inbound is accepted here in
SocketHandler"*.

**What that changes:** the branch's earlier rationale called `connman.cpp:447` "the SECOND live
forward edge". The cycle it described was real; the **entry point was not live**. The genuinely live
route into `EvictPeersIfNeeded` is `peers.cpp:1135` (PeriodicMaintenance), and the inversion on that
route is closed inside `EvictPeersIfNeeded` itself, where `cs_peers` is now released before the
fallback dispatch.

**What it does not change:** this census's §4 count. `connman.cpp` was already recorded as *"4
comments — zero live calls"*, which is consistent. The dead entry point never contributed an edge.

**Why it is recorded rather than quietly dropped:** an "unreachable today" verdict is exactly the
kind of thing that silently becomes reachable. The `AcceptConnection` fix is kept as defence in
depth, and this note exists so nobody cites it as the fix that closed the cycle.

## 7. BOUNDARY — what this census does NOT cover

Stated because a census that overstates its scope is exactly the failure it exists to correct.

- **`g_validation_mutex`** — out of scope by contract (hold-duration row, own owner). Not analysed here.
- **The forward direction** (`cs_headers` → `cs_vNodes`/`cs_peers`, the six `Misbehaving`/`PushMessage`
  sites) is *conforming* under the ratified order, not absent. The order says `cs_headers` is above;
  these sites are what establish that. They are edges, and they are the reason an inverted edge
  deadlocks.
- ~~Registrant bodies not read~~ — **CLOSED, see §5a.** Read in full by the final red-team, both
  binaries. This was a gap in three consecutive passes.
- **§3's exclusion is depth-1.** Zero direct references excludes a *direct* path only. The final
  red-team probed the three riskiest indirect escapes (`GetPeerTrustScore`,
  `sync_coordinator->IsInitialBlockDownload()`, `g_chainstate.GetHeight()`) and found none live —
  the last of those load-bearing, since if it took `cs_main` then `cs_peers → cs_main` would exist
  directly under the eviction lock. Deeper indirect paths remain unproven.
- **Signal handlers** — not examined.
- **The node binaries** call `CHeadersManager` methods in many places; none can hold `cs_vNodes`,
  `cs_peers` or `cs_main` (§1), so they cannot create an inverted edge, but they are not individually
  audited for other locks of their own.
- This is a **static** argument. It is corroborated by, not a substitute for, the TSan both-arms
  control in this directory.
