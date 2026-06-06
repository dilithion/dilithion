# evaluate — Dilithion project overlay

Loaded by the generic evaluate skill when present. Holds Dilithion-specific known-bug patterns and vulnerability classes to hunt during pre-commit review. Absent in non-Dilithion repos → generic criteria only.

## Per-category known failure patterns

These attach to the generic evaluation categories (B–G) and are drawn from Dilithion's actual bug history. When evaluating each category, ALSO apply the Dilithion-specific failure pattern and bullets below.

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
