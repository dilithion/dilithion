# red-team-validator — Dilithion project overlay

Loaded by the generic red-team-validator agent when present (`docs/agent-overlays/red-team-validator.overlay.md`). Holds Dilithion-specific adversarial lenses (7–9) and the Matrix-1 change-class routing table. Absent in non-Dilithion repos → generic lenses only.

## Dilithion concretes for the generic lenses (restored grep targets)

The generic lenses 1–6 were de-Dilithion-ized; these are the concrete Dilithion targets that make them bite harder in this repo. Apply them in addition to the generic wording:

- **Lens 3 (interface evolution) — build coverage:** the real build target is `make dilithion-node`; confirm the changed interface still compiles the node binary, not just the tests.
- **Lens 5 (storage-of-record) — canonical stores:** Dilithion's authoritative stores are `CCoinsView` (UTXO), `BlockManager` (block index), and `LevelDB` (on-disk). Hunt new read paths that consult an in-memory map/cache/index instead of one of these.

## Additional dangerous-surface lenses (Dilithion-specific)

7. **Disclosure-attacker-view** → fires only when the embargo flag is set (Family G security-release within ~2-week coordinated-disclosure window per `memory/feedback_security_release_disclosure_pattern.md`). Hunt: does the diff itself, read by an attacker, reveal which input pattern triggers the bug? Is the unpatched surface still exploitable on miners/nodes that haven't upgraded yet — for how long? Does the commit message / PR title leak the exploit signature (e.g., "fix RPC auth bypass via X" tells an attacker exactly what to try on unpatched nodes)? Does the fix add a log line that, if seen in production, identifies an attacker mid-exploit (tripwire) — and is it actually wired to alerting? Could the fix itself be exploited via a different angle (a sanitizer too strict, DoS'ing legitimate traffic)? Are the seed nodes you control on the patched version BEFORE the patch ships publicly (roll-your-own-canary first)? Flag any commit message / PR title that *names* the vulnerability class without obfuscation. Fire this lens on the **public post-mortem PR** too, so unrelated leaked primitives are caught.
8. **Principle-citation completeness** → activates on any heavy-tier change (Matrix 1 Families A-G). Source: `memory/feedback_check_project_principles_before_recommending.md`. Hunt: contract / PR description that proposes touching a safety surface without naming which principles were checked; changes that land on a principle's direct surface (KISS, stacked-defense, verify-before-assert, port-first / activation-after, storage-of-record, right-size methodology, design-review-before-spec) without acknowledging the principle; "reduce complexity" framing without arguing WHY removing the complexity is safe given the principle the complexity served; optimization PRs (latency / memory / disk) that touch safety-adjacent code without an argument for why the optimization preserves the safety invariant. **Output for each missed citation:** name the principle that should have been consulted and one sentence on what its application would have changed in this diff.
9. **Sybil / mining-concentration adversarial** → fires on Matrix 1 Family A rows "DFMP / mining-distribution" or "DNA / attestation". Sources: `memory/sybil_defense_strategy.md`, `memory/dfmp_cooldown_reference.md`, `memory/feedback_no_sybil_advice.md`. Hunt: could a miner with N identities exploit this change to amplify their share beyond their compute? Does the change shorten a cooldown window or relax an attestation check in a way that helps Sybil setups disproportionately? Race conditions between attestation expiry and DFMP cooldown that a coordinated multi-MIK miner could exploit? New "trusted" signals that can be spoofed at the network edge (carrier-NAT /24 collisions, ASN re-assignment, etc.)? Does it weaken the entity-clustering analysis we rely on for monitoring concentration? Flag phrases: "this makes registration easier" / "loosens the attestation requirement" / "speeds up cooldown decay" — all need an adversarial-miner-view check before merge.

## Lens-to-family map

The orchestrator names the Matrix 1 family row in the dispatch prompt. Apply all lenses listed for that family (lenses 1-4 from the existing four-lens set; lenses 5-9 from the additions above):

| Matrix 1 Family | Existing lenses | New lenses (additive) |
|---|---|---|
| **A** — Consensus surface | 1, 2, 3, 4 | 6, 8, 9 (if DFMP/DNA) |
| **B** — Chain plumbing | 1, 2, 3, 4 | **5**, 8 |
| **C** — P2P / network protocol | 1, 2, 3, 4 | 6, 8 |
| **D** — Wallet & Bridge | 1, 2, 3, 4 | 6, 8 |
| **E** — Port-of-upstream | 1, 2, 3, 4 | 8 |
| **F** — Major-rewrite / large-surface-flip | 1, 2, 3, 4 | 5, 6, 8 |
| **G** — Security release (embargo flagged) | 1, 2, 3, 4 | 6, **7**, 8 |
| **H** — RPC / build / ops | 1, 2, 3, 4 (if non-trivial) | — |
| **I** — Agent infra / synced surfaces | 1, 2, 3, 4 | — |
| **J** — Docs | (red-team typically not dispatched) | — |
| **K** — Tests / fuzz / behavioral | 1, 2, 3, **4** (especially) | — |

If the dispatch prompt does not name a family row, **🛑 STOP — the dispatch is malformed.** Write a single finding `BLOCKER: dispatch missing Matrix 1 family row` and exit. Do not fall back to trigger-text matching: that path silently degrades the more-conservative routing source (deterministic family map) to a less-conservative one (text match) and violates principle #25 (production-grade asymmetry — weakening must be explicit, not implicit). Red-team M-6 fold, 2026-05-23.
