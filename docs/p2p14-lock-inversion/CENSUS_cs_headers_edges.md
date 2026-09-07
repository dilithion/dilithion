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

**Therefore only `connman.cpp` can hold `cs_vNodes`, only `peers.cpp` can hold `cs_peers`, and only
`chain.cpp` can hold `cs_main`.** No other translation unit can hold any of the three, so no other
file can create an inverted edge. This is the fact that turns a sample into a census, and it is the
same argument that made the `TipNotifyDrain` sound.

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
`headers_manager` — **but see the boundary below: I enumerated the registrants, I did not read every
registrant's body.**

## 6. Result

**Every edge into `cs_headers` from a lock-holding frame is now lock-free at the call**, and the set
is complete for `{cs_vNodes, cs_peers, cs_main}` by the privacy argument in §1 plus the enumeration
in §4.

## 7. BOUNDARY — what this census does NOT cover

Stated because a census that overstates its scope is exactly the failure it exists to correct.

- **`g_validation_mutex`** — out of scope by contract (hold-duration row, own owner). Not analysed here.
- **The forward direction** (`cs_headers` → `cs_vNodes`/`cs_peers`, the six `Misbehaving`/`PushMessage`
  sites) is *conforming* under the ratified order, not absent. The order says `cs_headers` is above;
  these sites are what establish that. They are edges, and they are the reason an inverted edge
  deadlocks.
- **Registrant bodies for the block connect/disconnect callback families** were enumerated by name,
  not read. If one reaches `headers_manager`, `cs_main → cs_headers` returns by that route. Named as
  a gap by the first red-team pass; still a gap.
- **Signal handlers** — not examined.
- **The node binaries** call `CHeadersManager` methods in many places; none can hold `cs_vNodes`,
  `cs_peers` or `cs_main` (§1), so they cannot create an inverted edge, but they are not individually
  audited for other locks of their own.
- This is a **static** argument. It is corroborated by, not a substitute for, the TSan both-arms
  control in this directory.
