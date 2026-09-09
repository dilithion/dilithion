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

## DELIVERABLE 0 — THE CENSUS (done; regenerate, do not re-type)

Produced by `scripts/census_blockindex_pointer_windows.py`, committed with this
contract. Re-run it after any change to the five node/net files:

    python3 scripts/census_blockindex_pointer_windows.py [repo-root]

**Why a script.** #129 published "four more sites" as a census; a reviewer found a
fifth *in the file #129 was editing*. A hand-listed set is not to be trusted a
third time — the fix list is whatever this produces.

**How it classifies.** For each `GetBlockIndex(` call: bind the result variable,
find the enclosing function, scan forward for the first USE (`var->`, `*var`,
escape into a call or a store), and ask whether a `cs_main` holder is in scope at
BOTH the resolve and that use.

**It is a lexical scanner, not a compiler**, so it is biased to ESCALATE: it never
clears a site on its own authority. `UNKNOWN` means "could not follow" and is a
human decision, not a pass. Undercounting is the failure that matters — a site
wrongly cleared is a use-after-free nobody looks at again.

**Verification of the tool itself:**
* *GUARDED arm positive-controlled* — run against the `#129` branch (which has 6
  `MainLockGuard` uses) it reports **5 GUARDED**, exactly `QueueBlock`'s two and
  `ProcessBlock`'s three. So "0 GUARDED on main" is a finding, not a broken detector.
* *Wrong-root refusal* — pointed at a directory with no `src/`, it exits 2 rather
  than reporting zero findings.
* *Built-in self-check* — every reported `path:line` is re-read and must contain
  `GetBlockIndex(`; if not it exits 3. RED-armed: reintroducing the original
  newline-eating `strip_comments` gives **rc=3 and 33 bad locations**; the fixed
  version gives rc=0 and "all 52 verified". That bug was real and shipped in the
  first draft — block comments were replaced with `''` instead of their own
  newlines, shifting every line number after the first `/* */`. It was caught by
  hand-checking ONE row against the source.

### Result on this branch (main + this contract)

> **⚠️ THIS TABLE REPLACES AN EARLIER ONE THAT WAS SCOPED WRONG.** The first census
> hardcoded five files and reported **52** sites as if that were the population; the
> tree-wide figure is **74 classified across 11 files** (81 raw `GetBlockIndex(` hits).
> `rpc/server.cpp`, `index/tx_index.cpp`, `index/coinstatsindex.cpp`,
> `chain_selector_impl.cpp`, `chain_verifier.cpp` and `fork_manager.cpp` were all
> outside the list — the same "hand-listed set read as a census" defect this tool was
> built to prevent, committed by the tool. The file set is now DISCOVERED, so a new
> file cannot be missed by anyone forgetting to edit a list. (LP10 BLOCKER 2.)
>
> It also now detects **indirect escapes**: a pointer assigned into a LOCAL aggregate
> that is later pushed into a member/container. `block_validation_queue.cpp:151` —
> resolve, `queued_block.pindex = pindex ? pindex : existing;`, `m_queue.push(...)`,
> read back on the worker thread — is the case LP10 named, and the first version of
> the extension MISSED IT because the store is a ternary and the pattern required the
> variable to be the whole right-hand side. Fixed and verified against that exact
> site. (LP10 BLOCKER 1.)

| # | class | file:line | function | var | first use | cs_main in scope |
|---|---|---|---|---|---|---|
| 1 | **OUTLIVES-CALL** | `src/node/block_validation_queue.cpp:151` | `bool CBlockValidationQueue::QueueBlock(int peer_id, const CBlock& bloc` | `existing` | deref@152 | no |
| 2 | **OUTLIVES-CALL** | `src/node/block_validation_queue.cpp:444` | `bool CBlockValidationQueue::ProcessBlock(const QueuedBlock& queued_blo` | `pOrphanParent` | deref@453 | no |
| 3 | **OUTLIVES-CALL** | `src/node/dilithion-node.cpp:3008` | `int main(int argc, char* argv[]) {` | `pblockIndexPtr` | deref@3010 | no |
| 4 | **OUTLIVES-CALL** | `src/node/dilv-node.cpp:2874` | `int main(int argc, char* argv[]) {` | `pblockIndexPtr` | deref@2876 | no |
| 5 | **UNGUARDED** | `src/consensus/chain_verifier.cpp:159` | `bool CChainVerifier::CheckGenesisExists(std::string& error)` | `pGenesisIndex` | deref@165 | no |
| 6 | **UNGUARDED** | `src/consensus/chain_verifier.cpp:204` | `bool CChainVerifier::CheckParentExists(const uint256& hash, std::strin` | `pIndex` | deref@211 | no |
| 7 | **UNGUARDED** | `src/consensus/port/chain_selector_impl.cpp:106` | `bool ChainSelectorAdapter::ProcessNewBlock(std::shared_ptr<const CBloc` | `pindex` | deref@133 | no |
| 8 | **UNGUARDED** | `src/consensus/port/chain_selector_impl.cpp:175` | `bool ChainSelectorAdapter::ProcessNewBlock(std::shared_ptr<const CBloc` | `forkIndex` | deref@188 | no |
| 9 | **UNGUARDED** | `src/consensus/port/chain_selector_impl.cpp:275` | `bool ChainSelectorAdapter::ProcessNewHeader(const CBlockHeader& header` | `pprev` | deref@288 | no |
| 10 | **UNGUARDED** | `src/index/coinstatsindex.cpp:311` | `bool CCoinStatsIndex::Init(const std::string& datadir,` | `pi` | deref@312 | no |
| 11 | **UNGUARDED** | `src/index/coinstatsindex.cpp:319` | `bool CCoinStatsIndex::Init(const std::string& datadir,` | `pi` | deref@321 | no |
| 12 | **UNGUARDED** | `src/index/coinstatsindex.cpp:487` | `bool CCoinStatsIndex::WriteBlock(const CBlock& block, int height, cons` | `pi` | deref@488 | no |
| 13 | **UNGUARDED** | `src/index/coinstatsindex.cpp:679` | `bool CCoinStatsIndex::WalkBlockRange(int start, int end) {` | `pi` | deref@680 | no |
| 14 | **UNGUARDED** | `src/index/tx_index.cpp:229` | `bool CTxIndex::Init(const std::string& datadir, CBlockchainDB* chain_d` | `pi` | deref@230 | no |
| 15 | **UNGUARDED** | `src/index/tx_index.cpp:240` | `bool CTxIndex::Init(const std::string& datadir, CBlockchainDB* chain_d` | `pi` | deref@242 | no |
| 16 | **UNGUARDED** | `src/index/tx_index.cpp:620` | `bool CTxIndex::WalkBlockRange(int start, int end) {` | `pi` | deref@621 | no |
| 17 | **UNGUARDED** | `src/node/block_processing.cpp:350` | `BlockProcessResult ProcessNewBlock(` | `pParent` | escape@351 | no |
| 18 | **UNGUARDED** | `src/node/block_processing.cpp:462` | `BlockProcessResult ProcessNewBlock(` | `pParent` | escape@463 | no |
| 19 | **UNGUARDED** | `src/node/block_processing.cpp:586` | `BlockProcessResult ProcessNewBlock(` | `pParent` | escape@587 | no |
| 20 | **UNGUARDED** | `src/node/block_processing.cpp:696` | `BlockProcessResult ProcessNewBlock(` | `pindex` | escape@697 | no |
| 21 | **UNGUARDED** | `src/node/block_processing.cpp:762` | `BlockProcessResult ProcessNewBlock(` | `pParentTS` | deref@763 | no |
| 22 | **UNGUARDED** | `src/node/block_processing.cpp:795` | `BlockProcessResult ProcessNewBlock(` | `pParent` | escape@796 | no |
| 23 | **UNGUARDED** | `src/node/block_processing.cpp:894` | `BlockProcessResult ProcessNewBlock(` | `pindex` | deref@895 | no |
| 24 | **UNGUARDED** | `src/node/block_processing.cpp:1094` | `BlockProcessResult ProcessNewBlock(` | `pprev` | deref@1274 | no |
| 25 | **UNGUARDED** | `src/node/block_processing.cpp:1293` | `BlockProcessResult ProcessNewBlock(` | `pblockIndexPtr` | deref@1316 | no |
| 26 | **UNGUARDED** | `src/node/block_processing.cpp:1362` | `BlockProcessResult ProcessNewBlock(` | `forkIndex` | deref@1366 | no |
| 27 | **UNGUARDED** | `src/node/block_validation_queue.cpp:89` | `bool CBlockValidationQueue::QueueBlock(int peer_id, const CBlock& bloc` | `pParent` | deref@90 | no |
| 28 | **UNGUARDED** | `src/node/block_validation_queue.cpp:362` | `bool CBlockValidationQueue::ProcessBlock(const QueuedBlock& queued_blo` | `pprev` | deref@370 | no |
| 29 | **UNGUARDED** | `src/node/block_validation_queue.cpp:496` | `bool CBlockValidationQueue::ProcessBlock(const QueuedBlock& queued_blo` | `pOrphanIndexRaw` | deref*@506 | no |
| 30 | **UNGUARDED** | `src/node/dilithion-node.cpp:2758` | `int main(int argc, char* argv[]) {` | `pgenesisIndexPtr` | escape@2766 | no |
| 31 | **UNGUARDED** | `src/node/dilithion-node.cpp:2852` | `int main(int argc, char* argv[]) {` | `pgenesisIndexPtr` | escape@2858 | no |
| 32 | **UNGUARDED** | `src/node/dilithion-node.cpp:2909` | `int main(int argc, char* argv[]) {` | `pprev` | deref@2914 | no |
| 33 | **UNGUARDED** | `src/node/dilithion-node.cpp:3016` | `int main(int argc, char* argv[]) {` | `pindexTip` | escape@3023 | no |
| 34 | **UNGUARDED** | `src/node/dilithion-node.cpp:6398` | `int main(int argc, char* argv[]) {` | `pprev` | deref@6407 | no |
| 35 | **UNGUARDED** | `src/node/dilithion-node.cpp:6427` | `int main(int argc, char* argv[]) {` | `pblockIndexPtr` | escape@6435 | no |
| 36 | **UNGUARDED** | `src/node/dilithion-node.cpp:6625` | `int main(int argc, char* argv[]) {` | `pprev` | deref@6630 | no |
| 37 | **UNGUARDED** | `src/node/dilithion-node.cpp:6643` | `int main(int argc, char* argv[]) {` | `pblockIndexPtr` | escape@6647 | no |
| 38 | **UNGUARDED** | `src/node/dilithion-node.cpp:8722` | `int main(int argc, char* argv[]) {` | `pidx` | deref@8723 | no |
| 39 | **UNGUARDED** | `src/node/dilv-node.cpp:2615` | `int main(int argc, char* argv[]) {` | `pgenesisIndexPtr` | escape@2623 | no |
| 40 | **UNGUARDED** | `src/node/dilv-node.cpp:2709` | `int main(int argc, char* argv[]) {` | `pgenesisIndexPtr` | escape@2715 | no |
| 41 | **UNGUARDED** | `src/node/dilv-node.cpp:2775` | `int main(int argc, char* argv[]) {` | `pprev` | deref@2780 | no |
| 42 | **UNGUARDED** | `src/node/dilv-node.cpp:2882` | `int main(int argc, char* argv[]) {` | `pindexTip` | escape@2889 | no |
| 43 | **UNGUARDED** | `src/node/dilv-node.cpp:6424` | `int main(int argc, char* argv[]) {` | `pprev` | deref@6429 | no |
| 44 | **UNGUARDED** | `src/node/dilv-node.cpp:6442` | `int main(int argc, char* argv[]) {` | `pblockIndexPtr` | escape@6446 | no |
| 45 | **UNGUARDED** | `src/node/dilv-node.cpp:8358` | `int main(int argc, char* argv[]) {` | `pidx` | deref@8359 | no |
| 46 | **UNGUARDED** | `src/node/fork_manager.cpp:709` | `bool ForkManager::TriggerChainSwitch(NodeContext& ctx, CBlockchainDB& ` | `pindexNew` | escape@722 | no |
| 47 | **UNGUARDED** | `src/node/ibd_coordinator.cpp:934` | `void CIbdCoordinator::DownloadBlocks(int header_height, int chain_heig` | `forkIndex` | deref@937 | no |
| 48 | **UNGUARDED** | `src/node/ibd_coordinator.cpp:1561` | `bool CIbdCoordinator::FetchBlocks() {` | `pindex` | escape@1562 | no |
| 49 | **UNGUARDED** | `src/node/ibd_coordinator.cpp:1619` | `bool CIbdCoordinator::FetchBlocks() {` | `pParent` | deref@1620 | no |
| 50 | **UNGUARDED** | `src/node/ibd_coordinator.cpp:1640` | `bool CIbdCoordinator::FetchBlocks() {` | `pParent` | deref@1641 | no |
| 51 | **UNGUARDED** | `src/node/ibd_coordinator.cpp:1828` | `bool CIbdCoordinator::FetchBlocks() {` | `pindex` | deref@1829 | no |
| 52 | **UNGUARDED** | `src/node/ibd_coordinator.cpp:1851` | `bool CIbdCoordinator::FetchBlocks() {` | `pParent` | deref@1852 | no |
| 53 | **UNGUARDED** | `src/node/ibd_coordinator.cpp:2010` | `bool CIbdCoordinator::FetchBlocks() {` | `pindex` | deref@2011 | no |
| 54 | **UNGUARDED** | `src/node/ibd_coordinator.cpp:2050` | `bool CIbdCoordinator::FetchBlocks() {` | `pParent` | deref@2051 | no |
| 55 | **UNGUARDED** | `src/rpc/server.cpp:3622` | `std::string CRPCServer::RPC_GetTransaction(const std::string& params) ` | `pIdx` | deref@3631 | no |
| 56 | **UNGUARDED** | `src/rpc/server.cpp:3813` | `std::string CRPCServer::RPC_ListTransactions(const std::string& params` | `pindex` | deref@3814 | no |
| 57 | **UNGUARDED** | `src/rpc/server.cpp:7008` | `std::string CRPCServer::RPC_GetRawTransaction(const std::string& param` | `pIdx` | deref@7017 | no |
| 58 | **UNGUARDED** | `src/rpc/server.cpp:7895` | `std::string CRPCServer::RPC_RepairBlocks(const std::string& params) {` | `pindex` | escape@7896 | no |
| 59 | **UNGUARDED** | `src/rpc/server.cpp:8011` | `std::string CRPCServer::RPC_ScanBlockDB(const std::string& params) {` | `pindex` | escape@8012 | no |
| 60 | **UNGUARDED** | `src/rpc/server.cpp:8402` | `std::string CRPCServer::RPC_InvalidateBlock(const std::string& params)` | `pindex` | deref@8407 | no |
| 61 | **UNKNOWN** | `src/consensus/chain.cpp:186` | `CBlockIndex* CChainState::GetBlockIndex(const uint256& hash) {` | `-` | — | no |
| 62 | **UNKNOWN** | `src/consensus/chain.h:663` | `<file scope>` | `-` | — | no |
| 63 | **NO-WINDOW** | `src/consensus/port/chain_selector_impl.cpp:71` | `CBlockIndex* ChainSelectorAdapter::LookupBlockIndex(const uint256& has` | `-` | — | no |
| 64 | **NO-WINDOW** | `src/net/orphan_manager.cpp:434` | `uint256 COrphanManager::SelectOrphanForEviction()` | `-` | — | no |
| 65 | **NO-WINDOW** | `src/node/block_processing.cpp:981` | `BlockProcessResult ProcessNewBlock(` | `pParent` | — | no |
| 66 | **NO-WINDOW** | `src/node/block_processing.cpp:1006` | `BlockProcessResult ProcessNewBlock(` | `pParentCheck` | — | no |
| 67 | **NO-WINDOW** | `src/node/block_processing.cpp:1222` | `BlockProcessResult ProcessNewBlock(` | `parent_in_chainstate` | — | no |
| 68 | **NO-WINDOW** | `src/node/block_validation_queue.cpp:351` | `bool CBlockValidationQueue::ProcessBlock(const QueuedBlock& queued_blo` | `pindex` | — | no |
| 69 | **NO-WINDOW** | `src/node/block_validation_queue.cpp:383` | `bool CBlockValidationQueue::ProcessBlock(const QueuedBlock& queued_blo` | `pindex` | — | no |
| 70 | **NO-WINDOW** | `src/node/block_validation_queue.cpp:391` | `bool CBlockValidationQueue::ProcessBlock(const QueuedBlock& queued_blo` | `pindex` | — | no |
| 71 | **NO-WINDOW** | `src/node/block_validation_queue.cpp:456` | `bool CBlockValidationQueue::ProcessBlock(const QueuedBlock& queued_blo` | `-` | — | no |
| 72 | **NO-WINDOW** | `src/node/dilithion-node.cpp:6186` | `int main(int argc, char* argv[]) {` | `ourIdx` | — | no |
| 73 | **NO-WINDOW** | `src/node/dilv-node.cpp:6244` | `int main(int argc, char* argv[]) {` | `ourIdx` | — | no |
| 74 | **NO-WINDOW** | `src/node/ibd_coordinator.cpp:806` | `void CIbdCoordinator::DownloadBlocks(int header_height, int chain_heig` | `pParent` | — | no |

TOTAL call sites: 74
  OUTLIVES-CALL 4
  UNGUARDED  56
  UNKNOWN    2
  HELD-UNDER-CS_MAIN 0
  GUARDED    0
  NO-WINDOW  12

UNGUARDED and UNKNOWN both require a human decision. UNKNOWN is NOT a
clearance -- it is the scanner saying it could not follow the pointer.

OUTLIVES-CALL is the one that decides deferred reclamation: a pointer
stored into a member/global/field/container can be read on a LATER
iteration, so a per-iteration grace period would NOT cover it.

self-check: all 74 reported locations verified to contain GetBlockIndex(

**56 UNGUARDED + 4 OUTLIVES-CALL + 2 UNKNOWN = 62 sites needing a decision**
hand-named sites above — which remain accurate but were never the whole set. The
four guards this contract was written around are a subset; the deadlock argument
must cover the population, not the sample.

**0 GUARDED on this branch is expected**: the `MainLockGuard` sites live on #129's
branch and are not merged. Re-run after #129 lands and the count should move.
