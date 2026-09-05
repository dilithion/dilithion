# close-session — Dilithion project overlay

Loaded by the generic close-session skill when present. Holds Dilithion's concrete repo paths, the disposition-tag hard-check, and OPERATIONS_BOARD/SESSIONS reconciliation specifics. Absent in non-Dilithion repos → generic inventory only.

---

## Concrete repo paths (the canonical clone-root SET)

The six canonical clone roots (always include these, even if "I didn't touch them" — verify-before-assert):
- `c:/Users/will/dilithion`
- `c:/Users/will/agent-comms`  *(was `c:/Users/will/dilithion-private` — that path NO LONGER EXISTS; the hub moved 2026-08-21, corrected 2026-08-31 when a close-session run fetched it and found nothing there)*
- `c:/Users/will/dilithion-strategy`
- `C:/Users/will/.claude/projects/c--Users-will-dilithion/memory`
- `C:/Users/will/ion-strategy`
- `C:/Users/will/core-test`

> **Why this list must be EXHAUSTIVE — 2026-09-04.** A close ceremony can only fail on a repo it
> was told about. Stores were missing from this list, and every close passed its §7.2 "no unpushed
> commits" hard check *by not having them in scope* — **clean by luck, not by ceremony.** Measured
> when one was finally checked: months of local-only work that looked durable because its contents
> were loaded every session.
>
> **The shape to hunt for is a persistent store that is NOT a worktree of the working repo** — a
> separate clone, an agent-memory directory, a scratch corpus, a local notes tree. §1.1's
> "include anything in `git worktree list`" fallback is **structurally blind to every one of them**,
> so it cannot be the safety net. A separate clone never appears in that output at all.
>
> When you add a persistent store to this project, add it to this list **in the same change**.
> Measured detail belongs in the strategy repo's mission notes, not here.
>
> *(Kept deliberately free of remote names, repo purposes and file names: this repo is **public**.
> Verify a destination's visibility before adding any identifying detail to a tracked file — this
> file reads like private operator tooling and is not.)*

Plus any FURTHER repo (a worktree under `c:/tmp/`, a separate `agent-comms` clone, anything else) if it is in the worktree-list output but not in the canonical six — INCLUDE it. **Note the asymmetry this cannot fix:** that rule only reaches things the worktree list can see, which is why the six above must be maintained by hand.

Generic-skill placeholder mapping for this project:
- `<working-repo>` → `c:/Users/will/dilithion`
- `<agent-comms-hub>` → `c:/Users/will/agent-comms`  *(corrected 2026-08-31; the old `dilithion-private` path does not exist)*
- `<strategy/state-repo>` → `c:/Users/will/dilithion-strategy`
- `<memory-store>` → `C:/Users/will/.claude/projects/c--Users-will-dilithion/memory`

### Memory-store commit + push (Steps 6.2 and 7.2)

The memory store is a **working repo** for ordering purposes — push it in Step 6.2, before the strategy repo, and include it in the Step 7.2 `git log @{u}..HEAD` sweep.

```
cd C:/Users/will/.claude/projects/c--Users-will-dilithion/memory
git add -A -- . ':!project_ion_launch_liquidity.md'
git commit -m "memory: <session slug> — <what was learned>"
git push origin HEAD
git log @{u}..HEAD   # must be empty
```

Two standing exclusions, both deliberate:
- **`project_ion_launch_liquidity.md`** — `MEMORY.md` marks it *"LOCAL only, never quote the figure"*. The remote is private so backing it up is probably intended, but reversing an explicit confidentiality annotation is Will's call. Leave it untracked until he says otherwise.
- Empty scratch files (e.g. a zero-byte `close-readiness`) — cruft, not memory.

Use an explicit pathspec with exclusions, never a bare `git add -A`, per the standing rule about sweeping agent-memory directories (`feedback_git_add_scope_agent_memory.md`). If the store is clean, say so in the Step 8 report rather than skipping it silently — "nothing to commit" is a result, an unexamined repo is not.

### Strategy-repo pull (Step 1.3)

```
cd c:/Users/will/dilithion-strategy && git pull --ff-only
```

### Session ledger + board paths (Steps 1.4, 5.3, 6.3)

- Session ledger: `c:/Users/will/dilithion-strategy/00-context/SESSIONS.md` (grep `<this-session's-slug>` for paths declared at start)
- `00-context/OPERATIONS_BOARD.md`
- `00-context/SESSIONS.md`
- `00-context/CURRENT_STATE.md`

Strategy repo commit + push (Step 6.3):

```
cd c:/Users/will/dilithion-strategy
git add 00-context/OPERATIONS_BOARD.md 00-context/SESSIONS.md
# also CURRENT_STATE.md if updated, and any missions/<active>/ files
git commit -m "session: <slug> <closed|parked> — <one-line outcome>"   # word matches the §5.3 disposition
git push origin main
git log @{u}..HEAD   # must be empty
```

`migrate-to-strategy` target (Step 3 categorization): `dilithion-strategy/missions/...`

---

## Principles + autonomy-contract references

This skill enforces principles **#1 (single source of truth)**, **#8 (no silent skips)**,
and **#37 (show your work)** from `dilithion-strategy/00-context/yoda_principles.md`.

Mission audit trail — per [yoda_autonomy_contract.md §8](../../../../dilithion-strategy/00-context/yoda_autonomy_contract.md), every mission produces a fixed set of artifacts (`contract.md`, `decisions.md`, `cost.md`, `reviews/`, `amendments.md` if scope changed, `MISSION_CLOSE.md` on close). A close-pass that skips the §8 set silently violates principle #8 (no silent skips) and #34 (mission scope amendment audit trail).

Other numbered-principle citations used by the generic skill map to this same ledger:
- principle #7 (surface to Will, never silently halt under autonomy)
- principle #34 (mission scope amendment audit trail)
- principle #35 (session-boundary note)

---

## Disposition-tag hard-check (Step 7.1)

- [ ] **Disposition-tag hard-check** (fires on every CLOSE-disposition `/close-session` run. **N/A on a PARK** — a parked session writes no `MISSION_CLOSE.md` and closes no mission, so skip this entire check; the mission dir legitimately has no `MISSION_CLOSE.md` while parked. See Canonical parsing rules in the mission contract that introduced this rule):
  - If a mission dir exists under `dilithion-strategy/missions/<active>/<slug>/` AND `MISSION_CLOSE.md` exists in it: MUST execute
    ```
    bash c:/Users/will/dilithion-strategy/scripts/disposition_check.sh \
      dilithion-strategy/missions/<active>/<slug>/MISSION_CLOSE.md \
      dilithion-strategy/00-context/OPERATIONS_BOARD.md
    ```
    Exit `0` = pass. Exit `1` (parse violation: untagged item / missing heading / empty rationale / invalid slug) or exit `2` (orphan QUEUED: slug not at OPERATIONS_BOARD HEAD) = ❌ fail closed, surface the script's diagnostic + offending lines, do NOT push.
  - If mission dir exists but `MISSION_CLOSE.md` is missing: ❌ fail closed with "MISSION_CLOSE.md missing for active mission".
  - If no mission dir exists under `missions/<active>/`: no-op silent skip (session-close runs without mission state).
  - **Prose-only inspection ("I read the file and it looks tagged") does NOT satisfy this check.** The script must actually run and its exit code must be observed. This is the specific failure mode `feedback_session_discipline_collapse.md` names.

---

## OPERATIONS_BOARD / SESSIONS reconciliation specifics

- Mission directory archive move on close (done-branch, Step 8): `git mv dilithion-strategy/missions/<active>/<slug>/ dilithion-strategy/missions/_closed/<slug>_<date>/`
- OPERATIONS_BOARD sections to reconcile against (Step 4): In-flight missions / Time-bound follow-ups / Production hot-list / Loss-risk inbox / Stale-state / Open PR decisions / CI tail / Backlog / Memory files / Recent closures.
- SESSIONS.md tables: "Active sessions" → "Recently closed sessions" (CLOSE) or "Parked sessions" (PARK). Parked table schema: `| slug | worktree | branch | mission | parked-at | resume-when | notes |`.
