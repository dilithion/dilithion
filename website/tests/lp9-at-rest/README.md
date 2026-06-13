# LP-9 browser-wallet at-rest test

Headless Playwright test for the "migrate-then-require" fix (LP-9): the browser wallet must
never persist a plaintext HD seed in IndexedDB. Drives a real Chromium against the served
`wallet.html` and asserts the encryption-mandatory create/restore path, the `encryptExisting`
migration primitive (interruption-safe, zeroizing), the blocking migrate-on-load UI, and that
the SRI-pinned CDN scripts load + execute.

## Run

```bash
# 1. serve the website
cd website && python -m http.server 8799 --bind 127.0.0.1 &

# 2. install playwright-core (browsers from the ms-playwright cache are reused)
cd tests/lp9-at-rest && npm init -y && npm i playwright-core@1.60.0

# 3. run (downloads the two pinned CDN fixtures on first run, then deterministic)
node lp9.test.mjs
```

Exit 0 = all assertions pass. Expected: `45 passed, 0 failed`.

## What it covers
- AC-1: blank/null/short password rejected on create + import; valid create stays `encrypted:true`.
- AC-2/AC-7: `encryptExisting` round-trips + verifies before evicting plaintext, evicts the raw
  seed (deep byte-scan of the stored record), keeps addresses identical, new pw unlocks,
  re-migrate returns false (multi-tab race).
- AC-3: the real `updateLightWalletUI()` chokepoint presents the BLOCKING modal instead of a
  silent unlock; after migration the record is `encrypted:true` and the modal never re-shows.
- AC-4: SRI-pinned js-sha3 `/build/sha3.min.js` loads under the integrity check and address
  derivation works (a wrong hash makes `sha3_256` undefined → first assertion fails).
- M-1 (Cursor): concurrent multi-tab migration race — two tabs read the same plaintext legacy
  wallet and both attempt to migrate with DIFFERENT passwords; the atomic check-and-write in
  `_atomicMigratePut()` lets exactly one commit, the loser aborts as `raced` without
  overwriting, no plaintext is left, and the would-be lockout (loser's password stored) is
  averted. `encryptExisting()` reports already-migrated rather than clobbering.
- L-1 (Cursor): `deleteWallet()` requires password proof regardless of the `encrypted` flag —
  encrypted wallets reject a wrong password (record survives) and delete on the correct one;
  legacy unencrypted records refuse with `WALLET_NEEDS_ENCRYPTION` (no password-free
  destructive bypass) and survive the refused delete.

The two CDN fixtures are git-ignored and fetched from jsDelivr on first run; their bytes match
the sha384 the page pins, so serving them locally still enforces SRI.
