# close-session — Dilithion project overlay

Loaded by the generic close-session skill when present. Holds Dilithion's concrete repo paths, the disposition-tag hard-check, and OPERATIONS_BOARD/SESSIONS reconciliation specifics. Absent in non-Dilithion repos → generic inventory only.

---

## Concrete repo paths (the canonical clone-root triplet)

The three canonical clone roots (always include these, even if "I didn't touch them" — verify-before-assert):
- `c:/Users/will/dilithion`
- `c:/Users/will/dilithion-private`
- `c:/Users/will/dilithion-strategy`

Plus a fourth repo (worktree under `c:/tmp/`, a separate `agent-comms` clone, anything else) if it is in the worktree-list output but not in the canonical three — INCLUDE it.

Generic-skill placeholder mapping for this project:
- `<working-repo>` → `c:/Users/will/dilithion`
- `<agent-comms-hub>` → `c:/Users/will/dilithion-private`
- `<strategy/state-repo>` → `c:/Users/will/dilithion-strategy`

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
