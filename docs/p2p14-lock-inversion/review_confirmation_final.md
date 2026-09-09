# CONFIRMATION READ #2 — fix/p2p14-15-cs-headers-lock-order @ 0f4ab449
Seat: fresh-context confirmation (first seat WITH bash). Worktree C:/tmp/a8-p2p15. Read-only wrt source.
Started: (see git log below). Findings appended incrementally as settled.

---
## Verified head
`git log --oneline -1` in C:/tmp/a8-p2p15 => `0f4ab449 fix(p2p14/15): the TSan harness runner could not FAIL — unconditional green`.
Diffstat vs origin/main: 28 files, +3261/-93. Working tree clean except untracked `build-tsan/`.

---

## ITEM 1 — `m_next_node_id` now `std::atomic<int>` — **VERIFIED CLEAN**

Command: `grep -rn "m_next_node_id" --include=*.cpp --include=*.h . | grep -v ^./docs/`

Complete tree-wide reference set (7 hits, 3 live):
- `src/net/connman.h:346` — `std::atomic<int> m_next_node_id{1};` (declaration)
- `src/net/connman.cpp:413` — `int node_id = m_next_node_id++;`
- `src/net/connman.cpp:559` — `int node_id = m_next_node_id++;`
- `src/net/connman.cpp:1294` — `int node_id = m_next_node_id++;`
- `src/net/connman.h:341`, `src/net/net.cpp:296`, `src/net/peers.cpp:1764` — comments only.

All three live sites are bare `operator++` on the atomic, which is `fetch_add(1)` — a single atomic
RMW, correct regardless of lock state. There is **no** read-only use, no `= n` assignment, no use to
size/reserve anything, and no arithmetic on it anywhere in the tree. Nothing depended on the old
non-atomic semantics; the value is consumed immediately into a local `int node_id`.
`#include <atomic>` is present at `src/net/connman.h:14` (pre-existing, not added by this branch —
so no missing-include risk in TUs that include connman.h).

Note: `connman.cpp:559` is inside `AcceptConnection`, which census §6b establishes is dead code. The
fix covers it anyway; harmless.

### Build/link — VERIFIED
`C:/msys64/usr/bin/bash -lc "cd /c/tmp/a8-p2p15 && make -j8"` → `MAKE_EXIT=0`, "Build complete!"
(dilithion-node 9.1M, dilv-node 9.1M, genesis_gen, check-wallet-balance).
Then forced a fresh compile of the changed TU: `rm -f build/obj/net/connman.o && make build/obj/net/connman.o` → EXIT=0.
`src/net/connman.h` mtime 07:13; every node object is 07:18 — i.e. all 21 TUs that
`#include <net/connman.h>` were already compiled against the atomic declaration, and make reports
them up to date. No TU treated `m_next_node_id` as a plain int.

---

## ITEM 3 — F-009 invariant restated ORDER-BASED — **TRUE AT SOURCE**

The three rate-limit mutexes are `static` at file scope in `src/net/net.cpp` (`:63`, `:72`, `:85`),
so **no other translation unit can hold one** — the search space is net.cpp alone.
Enumerated every acquisition (10 sites) and read each critical section end to end:

| site | scope contents | acquires cs_peers? |
|---|---|---|
| `net.cpp:183/187/191` (`CleanupPeerRateLimitState`) | three sequential `erase()` blocks, no calls | NO |
| `net.cpp:240/243` (via `CleanupTimestampMap`) | map pruning only | NO |
| `net.cpp:259` (periodic sweep) | map pruning + atomic-unit capping | NO |
| `net.cpp:1151` (GETDATA rate) | sets `getdata_rate_breached` local, `Misbehaving` is AFTER the closing brace at `:1187` | NO |
| `net.cpp:1274` (dup detect) | counts duplicates | NO |
| `net.cpp:1308` (resend budget) | strike decay + token bucket, decisions into locals | NO |
| `net.cpp:1448` / `:1478` (serve / record) | set ops only; `on_getdata` and `Misbehaving` are outside | NO |
| `net.cpp:1821` (HEADERS rate) | timestamps only; `MisbehaveHeaders` is after the block | NO |

**Zero live sites take `cs_peers` (or call `Misbehaving`/`MisbehaveHeaders`/`GetPeer`) while holding a
rate-limit mutex.** The order-based statement at `net.cpp:1171-1186` is correct.

Also re-verified the two premises the restatement asserts as *no longer* true:
- `CConnman::DisconnectNodes` (`connman.cpp:1772`) — phase 1 detaches under `cs_vNodes` (`:1812-1831`),
  phase 2 dispatches with `cs_vNodes` **released** (`:1863`). Confirmed.
- `CPeerManager::EvictPeersIfNeeded` (`peers.cpp:962`) — `lock.unlock()` at `:1134` precedes
  `DispatchPeerDisconnected` at `:1136`. Confirmed.

### **LOW-1 — the sibling comment at `net.cpp:1287-1294` was NOT folded and still states the removed scenario**
`src/net/net.cpp:1290-1292`:
> `// Misbehaving→GetPeer takes cs_peers, and the disconnect path takes`
> `// cs_peers then (via OnPeerDisconnected→CleanupPeerRateLimitState) cs_served_blocks;`

This is verbatim the construction that the fold at `:1174-1179` declares **no longer occurs**. The
port-review MEDIUM-3 fold corrected the `cs_getdata_rate` copy of the invariant and left the
`cs_served_blocks` copy 100 lines below untouched. Its own stated rationale applies exactly:
"a reader who checks the cited AB-BA, finds it gone, and concludes the invariant is obsolete would
have a documented licence to move Misbehaving back inside" — that licence now exists at
`cs_served_blocks` instead of `cs_getdata_rate`. Comment-only; no behavioural defect.

---

## ITEM 2 — census §1 / §5a — **REVISED CLAIM IS TRUE; §5a INDEPENDENTLY RE-DERIVED**

**§1's revised claim** ("bounds ACQUISITION, not REACH; completeness comes from §3+§4+§5a") is correct.
Verified the underlying privacy facts at source: `cs_vNodes` `connman.h:324` under `private:`,
`cs_peers` `peers.h:214` under `private:`, `cs_main` `chain.h:136` under `private:`; `check-tip-notify-drain.sh`
step 5 additionally machine-enforces zero `friend` and no by-reference mutex accessor in those three
headers (I mutation-tested that check — see ITEM 4b).

**§5a re-derived independently, not spot-checked.** I brace-matched EVERY
`g_chainstate.Register{BlockConnect,BlockDisconnect,TipUpdate}Callback` lambda body in both binaries
(39 registrants: 19 in `dilithion-node.cpp`, 20 in `dilv-node.cpp`), stripped comments, and scanned
each body for `headers_manager|CHeadersManager|cs_headers|connman|peer_manager|Misbehaving|PushMessage|GetPeer`.

**Result: exactly TWO bodies hit — `dilithion-node.cpp:3555` and `dilv-node.cpp:3375`, both the
TipUpdate callback.** All 37 connect/disconnect registrants: zero hits. §5a's headline is correct.
(Script: `C:/tmp/redteam/_extract.py`.)

Three registrants resolved past depth-1, as asked:
1. `dilithion-node.cpp:7288` → `CRPCServer::NotifyBlockTipChanged()`. Body at `src/rpc/server.cpp:10033-10039`
   is `g_wait_cluster_cv.notify_all();` and nothing else. Census §5a's description is exact.
2. `dilithion-node.cpp:6179` (miner-win). Takes only `g_pendingMinerWinsMutex`; calls
   `g_chainstate.GetTip()/GetBlockIndex()/GetAncestor()` (cs_main, recursive, same thread) and iostream. No net reach.
3. `dilithion-node.cpp:6214` (DNA, 85 lines — the largest registrant). Reaches
   `collector->on_block_received`, `trust_manager->on_heartbeat_success/on_block_relayed`,
   `dna_registry->is_registered/get_identity_by_mik`, `verification_manager->OnNewRegistration`
   (read: `src/digital_dna/verification_manager.cpp:77`, takes only its own `mutex_`).
   Closed at **subsystem** level, not depth-1: `grep -c "headers_manager|CHeadersManager|cs_headers"`
   over all of `src/digital_dna/*.{cpp,h}` returns **zero across every file** — unreachable by construction at any depth.

Corroborating global bound: only 32 files in `src/` reference `headers_manager|CHeadersManager` at
all, and no registrant body reaches any of them except via the two TipUpdate lambdas.

### INFO-1 — line-number drift in three load-bearing comments
- `peers.cpp:1128-1129` names the two callers of `EvictPeersIfNeeded` as `peers.cpp:1135` and
  `connman.cpp:487`. Actual call sites: **`peers.cpp:1151`** (PeriodicMaintenance) and
  **`connman.cpp:502`** (AcceptConnection). Following `peers.cpp:1135` lands *inside this very comment block*.
- `scripts/run_p2p14_lock_inversion_tsan.sh:13` cites `dilithion-node.cpp:3551` for the tip
  registration; actual is **`:3555`**.
The premise itself is sound — `PeriodicMaintenance` begins at `peers.cpp:1146` and calls
`EvictPeersIfNeeded()` at `:1151` holding no `cs_peers` (its first `cs_peers` acquisition is the
`lock_guard` further down, AFTER the call), and its only callers are
`dilithion-node.cpp:6893` / `dilv-node.cpp:6717`, which cannot hold `cs_peers` (private, §1).

---

## ITEM 4 — the runner's three exit paths — ALL THREE VERIFIED BY RUNNING THE REAL SCRIPT

The previous verification drove an *extracted* exit block with fabricated inputs. I did not repeat
that. **The limitation it worked around still applies** — `/tmp/p2p14_${arm}.err` is truncated by
`>` on every run (script line 47), so editing it to inject a report is impossible — **but it is now
irrelevant**, because the script can be driven end to end with a substitute binary. That exercises
the real preflight, the real `timeout`/`setarch` invocation, the real `grep -c`, and the real exit
block, in one piece.

Method: sandbox `~/p2p14_runnertest` under WSL (Ubuntu 24.04, g++ 13.3, libtsan present), containing
only `scripts/run_p2p14_lock_inversion_tsan.sh` copied verbatim from the branch, plus a substitute
`./p2p14_lock_inversion_tsan_tests` **genuinely compiled with `-fsanitize=thread`**, so the
instrumentation preflight (`TSAN_SYMS_DYNAMIC=4  LIBTSAN_LINKED=1`) passes on its own merits rather
than being bypassed.

| case | substitute binary | observed | script exit | verdict |
|---|---|---|---|---|
| **A** both arms clean | returns 0, no stderr | `registered EXIT=0` / `unregistered EXIT=0`, `INVERSION_REPORTS=0` | **0** | OK — `RESULT: PASS` |
| **B** hung arm | registered arm loops on `sleep(60)` | `EXIT=124`, `VERDICT: HUNG` printed | **1** | OK — `FAIL: arm 'registered' exited 124` |
| **C** real inversion | registered arm takes A then B, then B then A, on two `std::mutex` | `EXIT=66`, `INVERSION_REPORTS=2` | **1** | OK — both legs fired |
| **C2** inversion with rc=0 | prints the TSan inversion banner to stderr, returns 0 | `EXIT=0`, `INVERSION_REPORTS=1` | **1** | OK — isolates the grep leg |

C2 matters: it proves the `grep -c` leg fails independently of the exit-code leg. C proves the real
TSan deadlock detector's wording (`ThreadSanitizer: lock-order-inversion (potential deadlock)`)
actually matches the script's pattern — produced, not assumed.
Case A also exercises the "grep -c returns 1 on no match" hazard the script's own comment calls out:
`inv` came out as `0`, not a two-line string, and the `-gt` test did not error.

### Can the check be fooled? YES, in one way, and it is worth stating.

### MEDIUM-1 — the instrumentation preflight proves the RUNTIME is linked, not that the code under test is INSTRUMENTED
`scripts/run_p2p14_lock_inversion_tsan.sh:29-35` passes if `nm -D | grep -c tsan` **or**
`ldd | grep -c libtsan` is non-zero. A build where `-fsanitize=thread` reached the link line but not
the compile of `chain.cpp`/`headers_manager.cpp` (a per-TU `CXXFLAGS` override; a stale non-TSan
object left in `build-tsan/obj/`; an `ifdef TSAN` that fires for `LDFLAGS` only) links `libtsan`,
reports `LIBTSAN_LINKED=1`, runs clean, and yields `RESULT: PASS` with the cycle unobserved.
Demonstrated: my **case A** binary is a three-line `printf` with no locks at all, and it produced a
full green `RESULT: PASS - both arms clean, zero inversions`. The preflight cannot distinguish that
from the real harness.
The script's own header states the concern exactly ("a TSan build that silently lost its
instrumentation runs clean and looks identical to a pass") and then implements a weaker check than
the one it describes. A positive control closes it: the harness should contain one deliberate
inversion the run is REQUIRED to report, so zero reports is itself a failure.

### MEDIUM-2 — nothing invokes the runner; the HEAD commit's fix has no consumer
The HEAD commit exists to make this script able to fail. Tree-wide search for anything that calls it
returns only the script itself and its own header comment.

- Not in `Makefile` — only the manual link target at `Makefile:921`.
- Not in `scripts/run_test_suites.sh`. `bash scripts/run_test_suites.sh --list all` does **not** list
  `p2p14_lock_inversion_tsan_tests`, so it is in neither `TEST_SUITES_FAST` nor `TEST_SUITES_FULL`.
- Not in any `.github/workflows/*.yml`. The existing `sanitizer-tsan` job (`.github/workflows/ci.yml:310`)
  builds `test_dilithion` only, and runs it as `./test_dilithion ... || true` (`ci.yml:378`) — the
  swallow pattern, so that job cannot go red either.

The branch applied the opposite standard to its sibling guard, in its own words (`Makefile:624-628`):
*"check-tip-notify-drain is a PREREQUISITE, not a suggestion ... a guard with zero callers is not a
guard - it is a file."* The TSan runner did not get that treatment. There is a defensible reason
(Linux + TSan only, ~4 minutes for the two arms, needs `setarch -R`), but then it should be stated
as a **manual gate**, not left to read as a regression test. As it stands the artifacts describe a
regression test that no pipeline runs.

### 4b — `make check-tip-notify-drain` PASSES, and 9 of 12 mutations are killed
`bash scripts/check-tip-notify-drain.sh` -> `PASS`, exit 0. It is wired at `Makefile:487-488` and is
a prerequisite of both `tests-fast` and `tests-full`.

**Mutation testing was done on an ISOLATED COPY of `src/` + `scripts/`** (in the session scratchpad,
`.../scratchpad/drainmut`), never in the shared worktree — `git -C C:/tmp/a8-p2p15 status --porcelain`
showed only the pre-existing untracked `build-tsan/` throughout and no tracked file was ever
modified. Baseline in the copy: PASS/0. After restore: PASS/0.

| # | mutation | expected | result |
|---|---|---|---|
| M1 | move `TipNotifyDrain drain(*this)` to AFTER the `cs_main` guard | FAIL | KILLED — exit 1, names both line numbers |
| M2 | delete the drain | FAIL | KILLED — exit 1 ("found 0") |
| M4 | add `NotifyTipUpdate()` in `src/net/net.cpp` | FAIL | KILLED — exit 1, prints the offending line |
| M5 | revert `TipUpdateCallback` to `CBlockIndex*` | FAIL | KILLED — exit 1 |
| M6 | `friend class Evil;` at line start in `connman.h` | FAIL | KILLED — exit 1 |
| M7 | `std::mutex& GetCsVNodes();` in `connman.h` | FAIL | KILLED — exit 1 |
| M9 | `TipNotifyDrain drain{*this};` (brace init) | n/a | FAILS ("found 0") — fail-SAFE, but a benign reformat reds the build |
| M10 | `TipNotifyDrain  drain(*this);` (two spaces) | n/a | FAILS ("found 0") — same |
| **M3** | **add `TipNotifyDrain drain2(*this);` beside the real one** | FAIL | **SURVIVED — exit 0** |
| **M8** | **add `TipNotifyDrain d2(*this);` INSIDE a `cs_main` scope (`chain.cpp:2018`)** | FAIL | **SURVIVED — exit 0** |
| M11 | `public: friend class Evil;` (not at line start) | FAIL | SURVIVED — exit 0 |
| M12 | `std::mutex* GetCsVNodesPtr();` (pointer, not reference) | FAIL | SURVIVED — exit 0 |

### MEDIUM-3 — check #2 is NAME-coupled, not TYPE-coupled, and M8 is exactly the failure it exists to catch
`scripts/check-tip-notify-drain.sh:52` does `drains=$(grep -c "TipNotifyDrain drain(" "$CHAIN_CPP")`.
That counts only instantiations whose variable is literally named `drain` and constructed with `(`.
A second `TipNotifyDrain` named anything else is invisible to it.
**M8 placed a second drain (`d2`) directly inside a `cs_main` `lock_guard` scope at `chain.cpp:2018`
— so the drain fires WITH cs_main HELD, which is precisely the deadlock this branch removes — and the
guard printed `PASS: ... exactly one TipNotifyDrain, declared before the cs_main guard`.**
The guard's stated claim ("exactly ONE TipNotifyDrain instantiation ... >1 means a second drain point
exists and this guard's reasoning no longer holds") is not the property it enforces.
`grep -cE 'TipNotifyDrain[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[({]'` would close M3, M8, M9
and M10 in one change. The current head is correct — this is a hole in the future-regression guard,
not a defect in the fix.

### LOW-2 — check #5's premise checks are pattern-fragile
`friend` is matched only as `^\s*friend` (M11 escapes as `public: friend class Evil;`), and a mutex
exposed by **pointer** (`std::mutex* GetCsVNodesPtr();`, M12) escapes the by-reference regex. Same
class as MEDIUM-3, smaller reach.

---

## ITEM 5 — did any fold break something already verified? — NO. All three still hold at `0f4ab449`.

**(a) `TipNotifyDrain` declared before the `cs_main` guard.** `src/consensus/chain.cpp:393`
`TipNotifyDrain drain(*this);` vs `:397` `std::lock_guard<std::recursive_mutex> lock(cs_main);` —
drain first, so it destructs last. Nothing else acquires `cs_main` between `:386` (function open) and
`:397`. Read `DrainTipNotifications` (`chain.cpp:2597`): it re-takes `cs_main` only to
`swap()` the queue out **and to copy `m_tipCallbacks`**, then fires with the lock released — so
iterating the callback vector unlocked is not a race either. `NotifyTipUpdate` (`chain.cpp:2554`)
only snapshots `pindex->header` + `GetBlockHash()` under the lock; the `CBlockIndex*` never escapes.
All four `NotifyTipUpdate` call sites (`chain.cpp:684`, `:749`, `:803`, `:1324`) are inside
`ActivateBestChain`, whose body spans `:386`-`:1329` (`ConnectTip` opens at `:1330`) — verified, not
taken from the comment.

**(b) `DisconnectNodes` preserving BUG #262 / #153 / #148 on the throwing path.** `src/net/connman.cpp:1772`.
Phase 1 (`:1812`-`:1831`) reserves before detaching, so the only throw point is before ownership
moves. Phase 2 runs with `cs_vNodes` released: `DispatchPeerDisconnected` in try/catch
(`:1861`-`:1877`, both `const std::exception&` and `...`), then `RemoveNode` in try/catch
(`:1881`-`:1910`) whose catch closes the socket and **deliberately leaks** the `CNode`
(`node.release()`) rather than freeing one `node_refs` may still point at, then `CloseSocket` in
try/catch. `continue` after the leak means the object is never touched again. #262 (dispatch before
RemoveNode), #153 (RemoveNode before destruction — `detached` unwinds only at function end) and #148
(no `node_ref` outliving its `CNode`) hold on the normal path and on every throwing path.

**(c) the `unique_lock` unlock correct on every path.** `CPeerManager::EvictPeersIfNeeded`
(`src/net/peers.cpp:962`) has exactly four returns: `:972` `return false`, `:1030` `return false`,
`:1140` `return true`, `:1143` `return false`. `lock.unlock()` occurs once, at `:1134`, on the
`node == nullptr` fallback only; that path then does `DispatchPeerDisconnected` (`:1136`),
`RemovePeer` (`:1138`, which re-acquires `cs_peers` itself) and returns at `:1140`. No path unlocks
twice and no path touches `lock` after unlocking; `unique_lock`'s destructor is `owns_lock()`-guarded,
so the `:1140` return is correct whether it arrives locked (live-CNode branch) or unlocked (fallback).
The recursive-mutex premise the unlock rests on is sound: the only two callers of
`EvictPeersIfNeeded` are `peers.cpp:1151` (inside `PeriodicMaintenance`, which begins at `:1146` and
takes no `cs_peers` before the call) and `connman.cpp:502` (inside the dead `AcceptConnection`), and
`PeriodicMaintenance`'s only callers are `dilithion-node.cpp:6893` / `dilv-node.cpp:6717`, which
cannot hold `cs_peers` because it is private.

**No regression found in any of the three.**

### Two additional edges I resolved rather than assume (both CLEAN)
- `peers.cpp:988` and `:1085` call `GetNode(...)` **while holding `cs_peers`**, which would invert
  against `cs_vNodes → cs_peers` if it were `CConnman::GetNode`. It is not: it resolves to
  `CPeerManager::GetNode` (`peers.h:349`), which takes only `cs_nodes` — below `cs_peers` in the
  ratified order. Conforming.
- `peers.cpp:1037` calls `g_chainstate.GetHeight()` under `cs_peers`. Census §7 asserts this is not a
  `cs_peers → cs_main` edge; independently confirmed — `CChainState::GetHeight()` is
  `m_cachedHeight.load(std::memory_order_acquire)`, no lock at all. Same for the neighbours:
  `sync_coordinator->IsInitialBlockDownload()` → `CIbdCoordinator::IsSynced()` →
  `m_synced.load(acquire)`; and the `GetPeerTrustScore` functor (`dilithion-node.cpp:7616`) takes only
  `g_mik_peer_mutex` and `trust_manager`, and all of `src/digital_dna/` has zero `cs_headers` /
  `headers_manager` references.
- `net.cpp:1814` `GetBestHeight()` — census §4 says `[held: -]`. Confirmed: `ProcessHeadersMessage`
  opens at `:1806` and there is no `lock_guard`/`unique_lock`/`.lock()` between `:1806` and `:1814`.

### LOW-3 — `chain.h`'s ActivateBestChain-caller enumeration is presented as complete and is not
`src/consensus/chain.h:1006-1008` states: *"Every ActivateBestChain caller measured [held: -]:
block_processing.cpp:945/:1468, block_validation_queue.cpp:402, fork_manager.cpp:722,
chain_selector_impl.cpp:213."* The actual production caller set is **nine**, not five — it also
includes `dilithion-node.cpp:2766`, `:6435`, `:6647` and `dilv-node.cpp:2623`, `:6446` (plus eight
test call sites). The **conclusion still holds**, because `cs_main` is private to `CChainState` so a
node-binary or test caller cannot hold it — but that is the privacy argument, not the enumeration,
and the sentence claims the enumeration. This is the same overstatement class the final red-team
already corrected once in CENSUS §1; it recurs here in a different file. The second premise in the
same comment ("No CChainState method calls ActivateBestChain, so it never nests") **is** correct:
`grep -rn "ActivateBestChain("` returns no call site inside `src/consensus/chain.cpp`.

### INFO-1 (consolidated) — line-number drift in load-bearing citations
Folds inserted lines above these references and the citations were not re-derived. The *facts* are
correct in every case; the *pointers* land in the wrong place, and several of them land inside the
comment block that cites them.

| citation | says | actual |
|---|---|---|
| `peers.cpp:1128` | callers of `EvictPeersIfNeeded` at `peers.cpp:1135` | `peers.cpp:1151` |
| `peers.cpp:1129` | `connman.cpp:487` | `connman.cpp:502` |
| `peers.cpp:1100` / `connman.cpp:473` | `peers.cpp:1708 headers_manager->OnPeerDisconnected` | `peers.cpp:1755` |
| `connman.cpp:472` | `peers.cpp:1089 DispatchPeerDisconnected` | `peers.cpp:1136` |
| CENSUS §4 | `peers.cpp:1739 OnPeerDisconnected` | `peers.cpp:1755` |
| CENSUS §4 | `net.cpp:1805 GetBestHeight` | `net.cpp:1814` |
| runner script `:13` | `dilithion-node.cpp:3551` tip registration | `:3555` |

CENSUS §4's *counts* are right, re-derived: `peers.cpp` 6 refs (1 include, 3 comments, 1 live call
spanning a guard+call), `net.cpp` 3 refs (1 include, 1 live call spanning guard+call), `connman.cpp`
4 refs all comments.

---

## NOT-REACHED LIST
One line each. These were not examined; none of them is being counted as clean.

- **The real TSan harness was never run at this head.** `make TSAN=1 p2p14_lock_inversion_tsan_tests`
  under WSL FAILED at link — `depends/dilithium/ref/*.o` in the shared worktree are MSYS2/mingw
  objects (`dangerous relocation: R_AMD64_IMAGEBASE`, `undefined reference to __stack_chk_guard`).
  Rebuilding depends for Linux would have overwritten the Windows objects other sessions rely on.
  So the two-arm result at `0f4ab449` rests on the committed
  `docs/p2p14-lock-inversion/tsan_FIXED_both_arms.err`, which I did not reproduce.
- `src/test/p2p14_lock_inversion_tsan_tests.cpp` (476 lines) — not reviewed at all. Whether the
  harness actually constructs the cycle it claims is unverified by me; MEDIUM-1 above is precisely
  about not being able to tell a real harness from an inert one by its exit status.
- `g_validation_mutex` — out of scope by contract, and out of scope here too.
- The forward direction `cs_headers → cs_vNodes/cs_peers` (the six `Misbehaving`/`PushMessage` sites
  at `headers_manager.cpp:351/498/530/674/2917/2987`) — not re-verified; conforming by the ratified order.
- `block_tracker.m_mutex` and `cs_nodes` orderings beyond the two sites named in ITEM 5 — not audited.
- Signal handlers — not examined (census §7 says the same).
- CENSUS §3's depth-1 exclusion of `node.cpp` / `addrman.cpp` / `banman.cpp` / `block_tracker.cpp` /
  `connection_quality.cpp` — I re-ran the zero-reference grep, but did NOT chase indirect paths
  through them beyond depth 1.
- The other 34 registrant bodies were closed by the automated brace-matched symbol scan, not read
  line by line; only the three named in ITEM 2 were resolved past depth-1.
- `src/consensus/chain.cpp`'s other 133 changed lines (Case 2 / 2.5 / 3 activation logic,
  `GetBlockHeightByHash`) — read only where they touch the drain; not reviewed for chain-selection
  correctness.
- `src/net/headers_manager.cpp` (+48 lines) — the consumer side, `OnBlockActivated` / the
  `GetBlockHeightByHash` cutover — not reviewed.
- `docs/p2p14-lock-inversion/review_confirmation.md`, `review_redteam.md`, `review_port.md` (the three
  non-final artifacts) — not read; I read the two `*_final.md` and the census as instructed.
- Whether the `sanitizer-tsan` CI job's `|| true` (`ci.yml:378`) is pre-existing or touched by this
  branch — I read it from the branch, not from `origin/main`.
- The wallet-tree `grep` that CENSUS §5a cites (0 matches in `src/wallet/`) — I did not re-run it;
  I closed the wallet registrants via the brace-matched body scan instead.

---

## DOES ANYTHING LOAD-BEARING REMAIN?

**On the FIX itself: no.** Every fold I was asked to check holds at `0f4ab449`, and the three
previously-verified properties (drain declaration order, `DisconnectNodes` exception containment,
`unique_lock` unlock) are intact — a late fold did not break an early guarantee. The
`m_next_node_id` atomic conversion is complete and compiles and links. The order-based F-009
restatement is true at source, verified by enumerating all ten rate-limit critical sections rather
than by trusting the claim. CENSUS §1's revised, narrower claim is honest, and §5a's registrant
verdict re-derives correctly from an independent census of all 39 registrants. **No HIGH or BLOCKER.**

**On the ENFORCEMENT layer: three MEDIUMs, and they are the honest answer to "is this converged".**
None changes the runtime behaviour of the branch; all three weaken the machinery that is supposed to
keep it fixed, and two of them were demonstrated by mutation rather than argued:

- **MEDIUM-3** — `check-tip-notify-drain.sh:52` is name-coupled: a second `TipNotifyDrain` placed
  **inside a `cs_main` scope** (M8) restores the deadlock and the guard prints PASS. One-line fix.
- **MEDIUM-1** — the TSan runner's instrumentation preflight cannot distinguish the real harness from
  an uninstrumented binary; a lock-free three-line stub earns a full green `RESULT: PASS`.
- **MEDIUM-2** — nothing invokes the runner. The HEAD commit makes it *able* to fail, and no
  pipeline, Makefile target or test-suite list calls it, so nothing consumes that.

MEDIUM-3 is the one I would not ship without: it is one line, it is in the guard the branch itself
calls "the single most fragile line in the fix", and M8 is a working demonstration that the guard
passes on a tree with the deadlock reintroduced. MEDIUM-1 and MEDIUM-2 are about the TSan runner's
standing being overstated in the artifacts; they can be closed by a positive control plus one honest
sentence saying the runner is a manual gate.

Everything else — LOW-1 (unfolded sibling comment at `net.cpp:1287-1294`), LOW-2 (pattern-fragile
premise checks), LOW-3 (overstated caller enumeration in `chain.h`), INFO-1 (line-number drift) — is
documentation accuracy, and this branch's own history is the argument for fixing rather than
tolerating that class: three consecutive passes were misled by a stale comment and by a census that
overstated its scope.

---

## SIDE EFFECTS ON THE SHARED CHECKOUT (disclosure)
- No tracked file was modified at any point. `git status --porcelain` in `C:/tmp/a8-p2p15` reads
  `?? build-tsan/` at start and at end — identical to the state I found.
- I ran `make -j8` (relinked `genesis_gen` + `check-wallet-balance`, which were stale) and
  `rm -f build/obj/net/connman.o && make build/obj/net/connman.o`. Both rebuilt cleanly.
- **My failed `make TSAN=1` attempt wrote Linux ELF objects into the untracked `build-tsan/obj/`,
  which already existed with 19 MB of objects from a prior session.** That directory may now hold a
  mixture. Anyone resuming the TSan build should `rm -rf build-tsan` first. Nothing tracked is affected.
- All mutation testing ran in an isolated copy under the session scratchpad, never in the worktree.
