import { chromium } from 'playwright-core';
import { readFileSync, existsSync, writeFileSync } from 'node:fs';

const BASE = 'http://127.0.0.1:8799/wallet.html?mode=light';

// The test serves the EXACT pinned CDN bytes (same sha384 the page's SRI pins) locally so
// the run is deterministic AND still exercises SRI: if the bytes didn't match the pinned
// hash the browser would refuse to run them. The fixtures are NOT committed (git-ignored);
// they are downloaded once from jsDelivr on first run.
const CDN = {
  sha3: { file: new URL('./sha3.build.min.js', import.meta.url), url: 'https://cdn.jsdelivr.net/npm/js-sha3@0.9.3/build/sha3.min.js' },
  ethers: { file: new URL('./ethers.umd.min.js', import.meta.url), url: 'https://cdn.jsdelivr.net/npm/ethers@5.7.2/dist/ethers.umd.min.js' },
};
async function ensureFixture(spec) {
  if (existsSync(spec.file)) return readFileSync(spec.file);
  const buf = Buffer.from(await (await fetch(spec.url)).arrayBuffer());
  writeFileSync(spec.file, buf);
  return buf;
}
const SHA3_BYTES = await ensureFixture(CDN.sha3);
const ETHERS_BYTES = await ensureFixture(CDN.ethers);
let pass = 0, fail = 0;
const results = [];
const log = (...a) => console.log('[t]', ...a);
function check(name, cond, detail = '') {
  if (cond) { pass++; results.push(`PASS  ${name}`); }
  else { fail++; results.push(`FAIL  ${name}${detail ? ' :: ' + detail : ''}`); }
}

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext();
await ctx.route('**/*', (route) => {
  const u = route.request().url();
  // Fulfill the pinned CDN scripts from local copies (deterministic; SRI still enforced).
  if (u.includes('js-sha3@0.9.3/build/sha3.min.js')) {
    return route.fulfill({ status: 200, contentType: 'application/javascript', body: SHA3_BYTES });
  }
  if (u.includes('ethers@5.7.2/dist/ethers.umd.min.js')) {
    return route.fulfill({ status: 200, contentType: 'application/javascript', body: ETHERS_BYTES });
  }
  if (u.startsWith('http://127.0.0.1:8799')) return route.continue();
  return route.abort();
});
const page = await ctx.newPage();
const pageErrs = [];
page.on('console', m => { if (m.type() === 'error') pageErrs.push(m.text()); });
page.on('pageerror', e => pageErrs.push('PAGEERROR: ' + e.message));

log('navigating (single load, no mid-test reloads)...');
await page.goto(BASE, { waitUntil: 'domcontentloaded' });
// NOTE: the page declares `localWallet` as a SCRIPT-SCOPED let (not on window), so the
// test cannot reference it by name. The LocalWallet *class* IS global (window.LocalWallet)
// and all instances share the same IndexedDB, so unit-style scenarios use a self-made
// instance; the UI scenario drives the global functions and asserts on DOM + IndexedDB.
await page.waitForFunction(() => window.LocalWallet && window.DilithiumCrypto && typeof sha3_256 !== 'undefined', null, { timeout: 30000 });
await page.evaluate(async () => { await window.DilithiumCrypto.init(); });
log('loaded.');

// Clear the wallet/address object stores WITHOUT deleteDatabase (clear() does not block).
const clearStores = `async () => {
  const lw = new window.LocalWallet(window.DilithiumCrypto);
  await lw.init();
  await new Promise((resolve, reject) => {
    const tx = lw.db.transaction(['wallets','addresses'], 'readwrite');
    tx.objectStore('wallets').clear();
    tx.objectStore('addresses').clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  lw.db.close();
}`;

// ---- Scenario 1: SRI/crypto sanity + AC-1 blank-password rejection ----
log('scenario 1: SRI + reject');
const sriOk = await page.evaluate(async () => {
  try {
    if (typeof sha3_256 === 'undefined' || typeof sha3_512 === 'undefined') return { ok: false, why: 'sha3 globals missing' };
    const m = await window.DilithiumCrypto.generateMnemonic();
    const seed = await window.DilithiumCrypto.mnemonicToSeed(m);
    const { publicKey } = await window.DilithiumCrypto.deriveChildKey(seed, "m/44'/573'/0'/0'/0'");
    const addr = window.DilithiumCrypto.deriveAddress(publicKey);
    return { ok: typeof addr === 'string' && addr.length > 0, addr };
  } catch (e) { return { ok: false, why: e.message }; }
});
check('SRI-pinned sha3 (/build/) loads & address derivation works', sriOk.ok, JSON.stringify(sriOk));

const reject = await page.evaluate(async () => {
  const out = {}; const lw = new window.LocalWallet(window.DilithiumCrypto); await lw.init();
  try { await lw.createWallet(''); out.empty = 'NO-THROW'; } catch (e) { out.empty = e.message; }
  try { await lw.createWallet(null); out.null = 'NO-THROW'; } catch (e) { out.null = e.message; }
  try { await lw.createWallet('short7!'); out.short = 'NO-THROW'; } catch (e) { out.short = e.message; }
  try { await lw.importWallet(null, ['a','b']); out.import = 'NO-THROW'; } catch (e) { out.import = e.message; }
  return out;
});
check('createWallet("") rejected', /at least 8/.test(reject.empty), reject.empty);
check('createWallet(null) rejected', /at least 8/.test(reject.null), reject.null);
check('createWallet(short) rejected', /at least 8/.test(reject.short), reject.short);
check('importWallet(null,...) rejected', /at least 8/.test(reject.import), reject.import);

// Also verify a VALID create stays encrypted at rest (no plaintext path remains).
const validCreate = await page.evaluate(clearStores).then(() => page.evaluate(async () => {
  const lw = new window.LocalWallet(window.DilithiumCrypto); await lw.init();
  const res = await lw.createWallet('valid-pass-12');
  const rec = await new Promise((resolve) => { const r = indexedDB.open('dilithion_wallet',1); r.onsuccess = () => { const db=r.result; const g=db.transaction('wallets','readonly').objectStore('wallets').getAll(); g.onsuccess=()=>{db.close();resolve(g.result[0]);}; }; });
  return { encrypted: rec.encrypted, hasCipher: !!(rec.encryptedSeed && rec.encryptedSeed.ciphertext), mnemonicLen: res.mnemonic.length };
}));
check('valid createWallet stores encrypted:true (no plaintext path)', validCreate.encrypted === true && validCreate.hasCipher === true, JSON.stringify(validCreate));

// ---- Scenario 2: encryptExisting() AC-2 + AC-7 ----
log('scenario 2: encryptExisting');
await page.evaluate(clearStores);
const enc = await page.evaluate(async () => {
  const out = {}; const crypto = window.DilithiumCrypto;
  const lw = new window.LocalWallet(crypto); await lw.init();
  // Clear any prior wallet on THIS connection, then seed, so getWallet() sees only ours.
  await new Promise((resolve, reject) => { const tx = lw.db.transaction(['wallets','addresses'],'readwrite'); tx.objectStore('wallets').clear(); tx.objectStore('addresses').clear(); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
  // Seed a legacy unencrypted record via raw put on this instance's DB connection.
  const seed = await crypto.mnemonicToSeed(await crypto.generateMnemonic());
  const seedArr = Array.from(seed);
  const keyPath = "m/44'/573'/0'/0'/0'";
  const { publicKey: pk0 } = await crypto.deriveChildKey(seed, keyPath);
  const addr0 = crypto.deriveAddress(pk0);
  await new Promise((resolve, reject) => {
    const tx = lw.db.transaction(['wallets','addresses'],'readwrite');
    tx.objectStore('wallets').put({ id:'legacy-1', version:1, encrypted:false, encryptedSeed:new Uint8Array(seed), createdAt:Date.now(), accounts:[{index:0,name:'Main Account',nextAddressIndex:1}] });
    tx.objectStore('addresses').put({ walletId:'legacy-1', address:addr0, path:keyPath, accountIndex:0, addressIndex:0, label:'Primary', createdAt:Date.now() });
    tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
  });

  out.isEncryptedBefore = await lw.isWalletEncrypted();
  out.unlockThrows = await lw.unlock('whatever').then(() => 'NO-THROW').catch(e => e.message);
  out.badPw = await lw.encryptExisting('short').then(() => 'NO-THROW').catch(e => e.message);

  const before = await new Promise((resolve) => { const r=indexedDB.open('dilithion_wallet',1); r.onsuccess=()=>{const db=r.result; const g=db.transaction('wallets','readonly').objectStore('wallets').getAll(); g.onsuccess=()=>{db.close();resolve(g.result[0]);};}; });
  out.plaintextPresentBefore = before.encrypted === false && before.encryptedSeed && before.encryptedSeed.length > 0;

  out.migrated = await lw.encryptExisting('correct-horse-8');
  out.isEncryptedAfter = await lw.isWalletEncrypted();
  out.unlockedAfter = lw.isWalletUnlocked();

  const after = await new Promise((resolve) => { const r=indexedDB.open('dilithion_wallet',1); r.onsuccess=()=>{const db=r.result; const g=db.transaction('wallets','readonly').objectStore('wallets').getAll(); g.onsuccess=()=>{db.close();resolve(g.result[0]);};}; });
  out.afterEncryptedFlag = after.encrypted === true;
  out.afterHasCiphertextObj = after.encryptedSeed && typeof after.encryptedSeed === 'object' && typeof after.encryptedSeed.ciphertext === 'string' && typeof after.encryptedSeed.salt === 'string' && typeof after.encryptedSeed.iv === 'string';
  let storedRaw = false;
  if (after.encryptedSeed instanceof Uint8Array || Array.isArray(after.encryptedSeed)) storedRaw = Array.from(after.encryptedSeed).join(',') === seedArr.join(',');
  out.seedEvicted = !storedRaw;
  const hay = JSON.stringify(after, (k, v) => (v instanceof Uint8Array ? Array.from(v) : v));
  out.seedBytesAbsentFromRecord = !hay.includes(seedArr.join(','));

  out.decryptedSeedPresent = lw.decryptedSeed != null && lw.decryptedSeed.length > 0;
  if (out.decryptedSeedPresent) {
    const { publicKey: pk2 } = await crypto.deriveChildKey(lw.decryptedSeed, keyPath);
    out.addrUnchanged = crypto.deriveAddress(pk2) === addr0;
  } else { out.addrUnchanged = false; }

  lw.lock();
  out.newPwUnlocks = await lw.unlock('correct-horse-8').then(() => true).catch(() => false);
  out.raceReturnsFalse = await lw.encryptExisting('another-pass-9').then(v => v).catch(e => 'THREW:' + e.message);
  return out;
});
check('legacy wallet reports encrypted:false', enc.isEncryptedBefore === false, JSON.stringify(enc.isEncryptedBefore));
check('unlock() on legacy throws WALLET_NEEDS_ENCRYPTION', enc.unlockThrows === 'WALLET_NEEDS_ENCRYPTION', enc.unlockThrows);
check('encryptExisting rejects short password', /at least 8/.test(enc.badPw), enc.badPw);
check('plaintext seed present before migration (precondition)', enc.plaintextPresentBefore === true);
check('encryptExisting returns true', enc.migrated === true, JSON.stringify(enc.migrated));
check('wallet encrypted:true after migration', enc.isEncryptedAfter === true);
check('wallet unlocked after migration', enc.unlockedAfter === true);
check('stored record flag encrypted:true', enc.afterEncryptedFlag === true);
check('stored seed is now {ciphertext,salt,iv}', enc.afterHasCiphertextObj === true);
check('AC-7 zeroization: raw seed evicted from stored field', enc.seedEvicted === true);
check('AC-7 zeroization: seed bytes absent anywhere in record', enc.seedBytesAbsentFromRecord === true);
check('addresses unchanged after migration', enc.addrUnchanged === true);
check('new password unlocks post-migration', enc.newPwUnlocks === true);
check('AC-7 race: re-migrate returns false (already encrypted)', enc.raceReturnsFalse === false, JSON.stringify(enc.raceReturnsFalse));

// ---- Scenario 3: AC-3 blocking migrate-on-load via real UI ----
// Seed legacy, then call the page's own UI entrypoints directly (no navigation):
// updateLightWalletUI() must present the blocking modal instead of unlock(null).
// Drives the REAL global UI functions (updateLightWalletUI / submitWalletMigration),
// which operate on the page's script-scoped `localWallet`. We seed via a fresh DB
// connection (the UI re-reads the DB) and assert on OBSERVABLE state: the modal DOM
// and the IndexedDB `encrypted` flag — not the unreachable script-scoped instance.
log('scenario 3: migrate-on-load UI');
await page.evaluate(clearStores);
// Helper: read the stored wallet record's encrypted flag.
const readEncryptedFlag = async () => page.evaluate(() => new Promise((resolve) => {
  const r = indexedDB.open('dilithion_wallet', 1);
  r.onsuccess = () => { const db = r.result; const g = db.transaction('wallets','readonly').objectStore('wallets').getAll(); g.onsuccess = () => { db.close(); resolve(g.result[0] ? g.result[0].encrypted : null); }; };
}));

const onload = await page.evaluate(async () => {
  const crypto = window.DilithiumCrypto;
  const seed = await crypto.mnemonicToSeed(await crypto.generateMnemonic());
  const keyPath = "m/44'/573'/0'/0'/0'";
  const { publicKey } = await crypto.deriveChildKey(seed, keyPath);
  const addr0 = crypto.deriveAddress(publicKey);
  // Clear any prior wallet, then seed a legacy unencrypted record (fresh connection).
  await new Promise((resolve, reject) => {
    const req = indexedDB.open('dilithion_wallet', 1);
    req.onsuccess = () => { const db = req.result; const tx = db.transaction(['wallets','addresses'],'readwrite');
      tx.objectStore('wallets').clear();
      tx.objectStore('addresses').clear();
      tx.objectStore('wallets').put({ id:'legacy-2', version:1, encrypted:false, encryptedSeed:new Uint8Array(seed), createdAt:Date.now(), accounts:[{index:0,name:'Main Account',nextAddressIndex:1}] });
      tx.objectStore('addresses').put({ walletId:'legacy-2', address:addr0, path:keyPath, accountIndex:0, addressIndex:0, label:'Primary', createdAt:Date.now() });
      tx.oncomplete = () => { db.close(); resolve(); }; tx.onerror = () => reject(tx.error); };
    req.onerror = () => reject(req.error);
  });
  // Invoke the real load-time UI routine (the chokepoint that used to silently unlock).
  await window.updateLightWalletUI();
  const m = document.getElementById('walletMigrationModal');
  const unlockedSection = document.getElementById('lightWalletUnlocked');
  return {
    modalVisible: m && getComputedStyle(m).display !== 'none',
    unlockedSectionShown: unlockedSection && getComputedStyle(unlockedSection).display !== 'none',
  };
});
check('AC-3 updateLightWalletUI presents blocking modal (no silent unlock)', onload.modalVisible === true, JSON.stringify(onload));
check('AC-3 unlocked wallet UI NOT shown pre-migration', onload.unlockedSectionShown === false, JSON.stringify(onload));
check('AC-3 stored wallet still encrypted:false before migration', (await readEncryptedFlag()) === false);

const afterSubmit = await page.evaluate(async () => {
  document.getElementById('migrationPassword').value = 'brandnew-pass-9';
  document.getElementById('migrationPasswordConfirm').value = 'brandnew-pass-9';
  await window.submitWalletMigration();
  // small settle for any async UI work
  await new Promise(r => setTimeout(r, 300));
  const m = document.getElementById('walletMigrationModal');
  return { modalHidden: !m || getComputedStyle(m).display === 'none' };
});
check('AC-3 modal closes after successful migration', afterSubmit.modalHidden === true, JSON.stringify(afterSubmit));
check('AC-3 stored wallet encrypted:true after UI migration', (await readEncryptedFlag()) === true);

// Re-running updateLightWalletUI on the now-encrypted wallet must NOT re-present the modal.
const afterReuiState = await page.evaluate(async () => {
  await window.updateLightWalletUI();
  const m = document.getElementById('walletMigrationModal');
  return m ? getComputedStyle(m).display !== 'none' : false;
});
check('AC-3 no migration modal once encrypted', afterReuiState === false, 'modalVisible=' + afterReuiState);

// ---- Scenario 4: M-1 concurrent multi-tab migration race ----
// Two tabs migrating the SAME legacy wallet with DIFFERENT passwords must not both
// commit: the atomic check-and-write in _atomicMigratePut() means exactly one write
// survives and the loser aborts cleanly (no overwrite => no lockout, no plaintext left).
log('scenario 4: M-1 multi-tab race');
await page.evaluate(clearStores);
const race = await page.evaluate(async () => {
  const out = {}; const crypto = window.DilithiumCrypto;
  const seed = await crypto.mnemonicToSeed(await crypto.generateMnemonic());
  const seedArr = Array.from(seed);
  const keyPath = "m/44'/573'/0'/0'/0'";
  const { publicKey } = await crypto.deriveChildKey(seed, keyPath);
  const addr0 = crypto.deriveAddress(publicKey);

  // Helper: (re)seed a fresh legacy unencrypted record.
  const seedLegacy = async () => {
    const lw = new window.LocalWallet(crypto); await lw.init();
    await new Promise((res, rej) => { const tx = lw.db.transaction(['wallets','addresses'],'readwrite');
      tx.objectStore('wallets').clear(); tx.objectStore('addresses').clear();
      tx.objectStore('wallets').put({ id:'race-1', version:1, encrypted:false, encryptedSeed:new Uint8Array(seed), createdAt:Date.now(), accounts:[{index:0,name:'Main Account',nextAddressIndex:1}] });
      tx.objectStore('addresses').put({ walletId:'race-1', address:addr0, path:keyPath, accountIndex:0, addressIndex:0, label:'Primary', createdAt:Date.now() });
      tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
    lw.db.close();
  };
  const readRec = () => new Promise((res) => { const r=indexedDB.open('dilithion_wallet',1); r.onsuccess=()=>{const db=r.result; const g=db.transaction('wallets','readonly').objectStore('wallets').getAll(); g.onsuccess=()=>{db.close();res(g.result[0]);};}; });

  // --- 4a: TRUE race window. Both tabs pass the early encrypted-check, then BOTH
  // attempt the atomic put with different passwords. Tab A wins; tab B must see the
  // in-transaction re-check and ABORT (return 'raced'), never overwriting A's ciphertext.
  await seedLegacy();
  const tabA = new window.LocalWallet(crypto); await tabA.init();
  const tabB = new window.LocalWallet(crypto); await tabB.init();
  const wA = await tabA.getWallet();
  const wB = await tabB.getWallet();           // both read plaintext (pre-check passes for both)
  out.bothSawUnencrypted = wA.encrypted === false && wB.encrypted === false;

  const cipherA = await crypto.encrypt(new Uint8Array(wA.encryptedSeed), 'tab-A-password-1');
  const cipherB = await crypto.encrypt(new Uint8Array(wB.encryptedSeed), 'tab-B-password-2');
  const resA = await tabA._atomicMigratePut('race-1', { ...wA, encrypted:true, encryptedSeed:cipherA });
  const resB = await tabB._atomicMigratePut('race-1', { ...wB, encrypted:true, encryptedSeed:cipherB }); // races AFTER A committed
  out.resA = resA; out.resB = resB;

  const afterRace = await readRec();
  out.storedEncrypted = afterRace.encrypted === true;
  // A's ciphertext must be the survivor: decrypts with A's pw, NOT B's.
  out.aPwDecrypts = await crypto.decrypt(afterRace.encryptedSeed, 'tab-A-password-1').then(s => Array.from(s).join(',') === seedArr.join(',')).catch(() => false);
  out.bPwRejected = await crypto.decrypt(afterRace.encryptedSeed, 'tab-B-password-2').then(() => false).catch(() => true);
  // No plaintext seed bytes anywhere in the stored record.
  const hay = JSON.stringify(afterRace, (k, v) => (v instanceof Uint8Array ? Array.from(v) : v));
  out.noPlaintextLeft = !hay.includes(seedArr.join(','));
  tabA.db.close(); tabB.db.close();

  // --- 4b: end-to-end via encryptExisting(): seed legacy, pre-encrypt out-of-band
  // (simulating the other tab having won), then encryptExisting() must NOT clobber and
  // must surface the "another tab" condition rather than unlocking from our plaintext.
  await seedLegacy();
  const winner = new window.LocalWallet(crypto); await winner.init();
  const wRec = await winner.getWallet();
  const winnerCipher = await crypto.encrypt(new Uint8Array(wRec.encryptedSeed), 'winner-pass-9');
  // Out-of-band atomic commit by the "winner" using a separate instance.
  await winner._atomicMigratePut('race-1', { ...wRec, encrypted:true, encryptedSeed:winnerCipher });
  winner.db.close();

  // Now a stale tab tries encryptExisting() — it already read plaintext before the win.
  // Because the stored record is encrypted, the early pre-check OR the atomic re-check
  // must stop it. We force the atomic-path by calling _atomicMigratePut directly with a
  // loser ciphertext, AND verify encryptExisting() itself reports already-migrated.
  const loser = new window.LocalWallet(crypto); await loser.init();
  out.encryptExistingReturnsFalse = await loser.encryptExisting('loser-pass-9').then(v => v).catch(e => 'THREW:' + e.message);
  const loserCipher = await crypto.encrypt(seed, 'loser-pass-9');
  out.directRaced = await loser._atomicMigratePut('race-1', { id:'race-1', encrypted:true, encryptedSeed:loserCipher });
  const finalRec = await readRec();
  out.winnerSurvived = await crypto.decrypt(finalRec.encryptedSeed, 'winner-pass-9').then(() => true).catch(() => false);
  out.loserPwRejected = await crypto.decrypt(finalRec.encryptedSeed, 'loser-pass-9').then(() => false).catch(() => true);
  loser.db.close();
  return out;
});
check('M-1 both tabs read plaintext (true race precondition)', race.bothSawUnencrypted === true, JSON.stringify(race));
check('M-1 first atomic put commits (ok)', race.resA === 'ok', JSON.stringify(race.resA));
check('M-1 second atomic put aborts as raced (no overwrite)', race.resB === 'raced', JSON.stringify(race.resB));
check('M-1 stored record is encrypted after race', race.storedEncrypted === true);
check('M-1 winner (tab A) ciphertext survived', race.aPwDecrypts === true);
check('M-1 loser (tab B) password is NOT what is stored', race.bPwRejected === true);
check('M-1 no plaintext seed left in record after race', race.noPlaintextLeft === true);
check('M-1 encryptExisting reports already-migrated (false)', race.encryptExistingReturnsFalse === false, JSON.stringify(race.encryptExistingReturnsFalse));
check('M-1 direct atomic put on already-encrypted returns raced', race.directRaced === 'raced', JSON.stringify(race.directRaced));
check('M-1 out-of-band winner ciphertext preserved', race.winnerSurvived === true);
check('M-1 loser password rejected (would-be lockout averted)', race.loserPwRejected === true);

// ---- Scenario 5: L-1 delete requires password (no legacy bypass) ----
// Encrypted wallet: wrong password must NOT delete; correct password deletes.
// Legacy unencrypted wallet: delete refuses with WALLET_NEEDS_ENCRYPTION (no
// password-free destructive path) — the record survives.
log('scenario 5: L-1 delete-requires-password');
await page.evaluate(clearStores);
const del = await page.evaluate(async () => {
  const out = {}; const crypto = window.DilithiumCrypto;

  // 5a: encrypted wallet — wrong pw rejected, record survives; right pw deletes.
  const lw = new window.LocalWallet(crypto); await lw.init();
  await new Promise((res, rej) => { const tx = lw.db.transaction(['wallets','addresses'],'readwrite'); tx.objectStore('wallets').clear(); tx.objectStore('addresses').clear(); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
  await lw.createWallet('delete-me-pass-1');
  out.wrongPwThrows = await lw.deleteWallet('totally-wrong-9').then(() => 'NO-THROW').catch(e => e.message);
  out.survivesWrongPw = await lw.getWallet().then(w => !!w);
  out.rightPwDeletes = await lw.deleteWallet('delete-me-pass-1').then(() => true).catch(e => 'THREW:' + e.message);
  out.goneAfterRightPw = await lw.getWallet().then(w => w === null);

  // 5b: legacy unencrypted wallet — delete must refuse (no password-free bypass).
  const seed = await crypto.mnemonicToSeed(await crypto.generateMnemonic());
  await new Promise((res, rej) => { const tx = lw.db.transaction(['wallets','addresses'],'readwrite'); tx.objectStore('wallets').clear(); tx.objectStore('addresses').clear();
    tx.objectStore('wallets').put({ id:'legacy-del', version:1, encrypted:false, encryptedSeed:new Uint8Array(seed), createdAt:Date.now(), accounts:[{index:0,name:'Main Account',nextAddressIndex:1}] });
    tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
  out.legacyNoPwThrows = await lw.deleteWallet().then(() => 'NO-THROW').catch(e => e.message);
  out.legacyAnyPwThrows = await lw.deleteWallet('anything-9').then(() => 'NO-THROW').catch(e => e.message);
  out.legacySurvives = await lw.getWallet().then(w => !!w && w.encrypted === false);
  lw.db.close();
  return out;
});
check('L-1 encrypted delete: wrong password rejected', /Wrong password/.test(del.wrongPwThrows), del.wrongPwThrows);
check('L-1 encrypted wallet survives wrong-password delete', del.survivesWrongPw === true);
check('L-1 encrypted delete: correct password deletes', del.rightPwDeletes === true, JSON.stringify(del.rightPwDeletes));
check('L-1 wallet gone after correct-password delete', del.goneAfterRightPw === true);
check('L-1 legacy delete (no pw) refused (WALLET_NEEDS_ENCRYPTION)', del.legacyNoPwThrows === 'WALLET_NEEDS_ENCRYPTION', del.legacyNoPwThrows);
check('L-1 legacy delete (any pw) refused (no plaintext-flag bypass)', del.legacyAnyPwThrows === 'WALLET_NEEDS_ENCRYPTION', del.legacyAnyPwThrows);
check('L-1 legacy wallet survives refused delete', del.legacySurvives === true);

await browser.close();

const realErrs = pageErrs.filter(e => !/explorer\.dilithion\.org|Failed to fetch|net::ERR|ERR_|getblockchaininfo|seed node|No seed|Connection|favicon/i.test(e));
check('no unexpected console/page errors', realErrs.length === 0, realErrs.slice(0,5).join(' | '));

console.log('\n===== LP-9 TEST RESULTS =====');
for (const r of results) console.log(r);
console.log(`\n${pass} passed, ${fail} failed`);
if (pageErrs.length) console.log('\n[filtered page errors]:', realErrs.length ? realErrs.join(' | ') : '(only benign network noise)');
process.exit(fail === 0 ? 0 : 1);
