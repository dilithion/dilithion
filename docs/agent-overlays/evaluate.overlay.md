# evaluate — Dilithion project overlay

Loaded by the generic evaluate skill when present. Holds Dilithion-specific known-bug patterns and vulnerability classes to hunt during pre-commit review, PLUS Dilithion's own names/questions for the categories that the generic `evaluate/SKILL.md` template genericized (2026-07-12, so the same skill body is reusable in non-blockchain repos). Absent in non-Dilithion repos → generic criteria only.

## Category overrides (use these instead of the generic A/C/E/F/G)

The generic skill's Step 2 categories are written to apply to any codebase. For Dilithion, apply these
domain-specific versions in place of the generic text for the letters listed — same letters, same
weights, same position in the verdict table; only the name/questions differ. Categories B and D are
unchanged from the generic template (already correct for Dilithion) and are not restated here.

### A. Consensus Safety (Weight: CRITICAL) — overrides generic "Core Invariant Safety"
- Can this change cause two nodes to disagree on block validity?
- Is there any non-deterministic behavior (floating point, platform-dependent sizes, undefined behavior)?
- Does it change what blocks are accepted/rejected? If so, is there a height-gated activation?
- Are there new validation rules that could reject previously-valid blocks?
- Could this cause a chain split during upgrade rollout (some nodes on old version, some on new)?

### C. P2P & DoS Resistance (Weight: HIGH) — overrides generic "External Input & DoS Resistance"
- Can a peer trigger expensive computation with cheap messages?
- Are there rate limits on all peer-initiated operations?
- Can this be used to ban legitimate peers (misbehavior score manipulation)?
- Does it handle peer disconnection mid-operation gracefully?

### E. UTXO & State Integrity (Weight: HIGH) — overrides generic "State Integrity & Error Handling"
(Questions unchanged from generic — only the display name differs, kept here for continuity with
Dilithion's bug history below.)
- Does the code assume state/database lookups always succeed?
- Are there any new paths that permanently mark valid input as invalid? (Dangerous - hard to recover)
- Could a temporary state error cause permanent damage?
- Is there proper error propagation vs. silent failure?

### F. Build & Deployment Safety (Weight: MEDIUM) — overrides generic wording with the header-file specifics
- Does this change any struct layouts in header files?
- If headers changed, will a partial/incremental build produce correct binaries?
- Are there any new dependencies or includes that could create circular deps?

### G. Edge Cases & Boundary Conditions (Weight: MEDIUM) — overrides generic wording with blockchain-specific boundaries
- What happens at height 0 (genesis)?
- What happens at activation heights?
- What happens with empty inputs, zero values, max values?
- What happens during IBD vs steady-state?
- What happens during a reorg?

## Per-category known failure patterns

These attach to the categories above (B–G) and are drawn from Dilithion's actual bug history. When evaluating each category, ALSO apply the Dilithion-specific failure pattern and bullets below.

### B. Memory & Resource Safety
Known failure pattern: BUG #275 killed all 4 DilV seed nodes via OOM.
- DilV runs 5x faster than DIL - will this amplify any memory issue?

### C. P2P & DoS Resistance
Known failure pattern: INV flooding caused cascading bans across the entire network.
- Is there any code that calls `AnnounceTransactionToPeers()` in a loop? (ban factory)

### D. Race Conditions & Thread Safety
Known failure pattern: std::cout format state corruption crashed nodes during IBD.
- Is std::cout/std::cerr used with format modifiers (std::fixed, std::setprecision) from threads?

### E. UTXO & State Integrity
Known failure pattern: BUG #276/#277 - UTXO corruption cascaded into false block rejections.
- Does the code assume UTXO lookups always succeed? (They don't after OOM crashes)
- Are there any new paths that mark blocks as BLOCK_FAILED_VALID? (Dangerous - permanent rejection)
- Could a temporary state error cause permanent chain damage?
- Is there proper error propagation vs. silent failure?

### F. Build & Deployment Safety
Known failure pattern: Header changes without `make clean` caused struct layout crashes on all seed nodes.
- Are there new fields in CBlockIndex, ChainParams, NodeContext, or CNode?
- If headers changed, will a partial build (`make -j4` without `make clean`) produce correct binaries?

## Pattern hunt — Dilithion-specific vulnerability patterns

These are patterns from Dilithion's actual bug history. Check EVERY ONE:

1. **Unbounded queue/vector from peer data** - grep for `push_back`, `emplace_back`, `insert` on containers filled by peer messages. Each MUST have a size check.
2. **Missing DilV handling** - grep for `IsTestnet()` / `isTestnet` switches. If there's no `IsDilV()` branch, DilV falls into mainnet path silently.
3. **GMP long truncation on Windows** - any `mpz_mul_si`, `mpz_addmul_ui`, `mpz_submul_ui` with values that could exceed 32 bits.
4. **Coinbase validation before ConnectTip** - fee-based rejection in ProcessNewBlock is unreliable if UTXO state is incomplete.
5. **Cooldown/DFMP bypass** - any path that skips MIK validation or cooldown checks.

## "What I Tested" — Dilithion-specific checklist additions

- [ ] Checked for missing DilV branches

## Modality-coverage repo set (preserves prior behavior)

`modality_coverage_check.sh` now defaults to the current repo only (repo-agnostic). To restore Dilithion's prior cross-repo coverage, set this in `.claude/settings.json` `env`:

```
EVALUATE_COVERAGE_REPOS=".,c:/Users/will/dilithion-private,c:/Users/will/dilithion-strategy,c:/Users/will/dilithion"
```
