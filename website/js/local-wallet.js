/**
 * Local Wallet Storage for Dilithion Light Wallet
 *
 * Provides secure storage for HD wallet data in browser's IndexedDB:
 * - Encrypted seed storage (AES-256-GCM)
 * - Address/account management
 * - Auto-lock functionality
 *
 * Copyright (c) 2025 The Dilithion Core developers
 * Distributed under the MIT software license
 */

// IndexedDB database name and version
const DB_NAME = 'dilithion_wallet';
const DB_VERSION = 1;

// Wallet storage structure
const WALLET_STORE = 'wallets';
const ADDRESS_STORE = 'addresses';
const SETTINGS_STORE = 'settings';

/**
 * Local Wallet Storage class
 */
class LocalWallet {
    constructor(cryptoModule) {
        this.crypto = cryptoModule || window.DilithiumCrypto;
        this.db = null;

        // Current wallet state
        this.walletId = null;
        this.isUnlocked = false;
        this.decryptedSeed = null;
        this.accounts = [];

        // Auto-lock timer
        this.lockTimer = null;
        this.autoLockMinutes = 5;

        // Event listeners
        this.listeners = {
            'lock': [],
            'unlock': [],
            'walletChange': []
        };
    }

    /**
     * Initialize local wallet storage
     * Opens IndexedDB connection
     */
    async init() {
        if (this.db) {
            return;  // Already initialized
        }

        return new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, DB_VERSION);

            request.onerror = () => {
                console.error('[LocalWallet] IndexedDB error:', request.error);
                reject(request.error);
            };

            request.onsuccess = () => {
                this.db = request.result;
                console.log('[LocalWallet] Database opened');
                resolve();
            };

            request.onupgradeneeded = (event) => {
                const db = event.target.result;

                // Wallets store
                if (!db.objectStoreNames.contains(WALLET_STORE)) {
                    const walletStore = db.createObjectStore(WALLET_STORE, { keyPath: 'id' });
                    walletStore.createIndex('createdAt', 'createdAt');
                }

                // Addresses store
                if (!db.objectStoreNames.contains(ADDRESS_STORE)) {
                    const addressStore = db.createObjectStore(ADDRESS_STORE, { keyPath: ['walletId', 'address'] });
                    addressStore.createIndex('walletId', 'walletId');
                    addressStore.createIndex('address', 'address');
                }

                // Settings store
                if (!db.objectStoreNames.contains(SETTINGS_STORE)) {
                    db.createObjectStore(SETTINGS_STORE, { keyPath: 'key' });
                }

                console.log('[LocalWallet] Database schema created');
            };
        });
    }

    /**
     * Check if a wallet exists
     * @returns {Promise<boolean>}
     */
    async hasWallet() {
        await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(WALLET_STORE, 'readonly');
            const store = tx.objectStore(WALLET_STORE);
            const request = store.count();

            request.onsuccess = () => resolve(request.result > 0);
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Create a new wallet
     *
     * A passphrase is MANDATORY (min 8 chars). The unencrypted-at-rest path was
     * removed (LP-9): the raw HD seed is never persisted in plaintext to IndexedDB.
     *
     * @param {string} password - Wallet password (required, min 8 chars)
     * @param {string[]} mnemonic - Optional mnemonic (generates new if not provided)
     * @returns {Promise<Object>} {walletId, mnemonic, addresses}
     */
    async createWallet(password, mnemonic = null) {
        await this.init();

        if (!this.crypto) {
            throw new Error('Crypto module not available');
        }

        // LP-9: passphrase is mandatory — never persist a plaintext seed at rest.
        if (!password || password.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }

        // Generate or validate mnemonic
        if (!mnemonic) {
            mnemonic = await this.crypto.generateMnemonic();
        } else if (!await this.crypto.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic phrase');
        }

        // Convert mnemonic to seed
        const seed = await this.crypto.mnemonicToSeed(mnemonic);

        // Encrypt seed with password (AES-256-GCM via PBKDF2). Plaintext seed is
        // never written to persistent storage.
        const storedSeed = await this.crypto.encrypt(seed, password);

        // Generate wallet ID
        const walletId = this.generateUUID();

        // Derive first address
        const keyPath = "m/44'/573'/0'/0'/0'";
        const { publicKey, chainCode } = await this.crypto.deriveChildKey(seed, keyPath);
        const firstAddress = this.crypto.deriveAddress(publicKey);

        // Create wallet record
        const wallet = {
            id: walletId,
            version: 1,
            encrypted: true,
            encryptedSeed: storedSeed,
            createdAt: Date.now(),
            accounts: [{
                index: 0,
                name: 'Main Account',
                nextAddressIndex: 1
            }]
        };

        // Save wallet
        await this.saveWallet(wallet);

        // Save first address
        await this.saveAddress({
            walletId,
            address: firstAddress,
            path: keyPath,
            accountIndex: 0,
            addressIndex: 0,
            label: 'Primary',
            createdAt: Date.now()
        });

        // Set as current wallet and unlock
        this.walletId = walletId;
        this.decryptedSeed = seed;
        this.isUnlocked = true;
        this.accounts = wallet.accounts;
        this.startLockTimer();

        console.log('[LocalWallet] Wallet created:', walletId, '(encrypted)');

        return {
            walletId,
            mnemonic,
            addresses: [firstAddress]
        };
    }

    /**
     * Import wallet from mnemonic
     * @param {string|null} password - New password (null for unencrypted)
     * @param {string[]} mnemonic - 24-word mnemonic
     * @returns {Promise<Object>} {walletId, addresses}
     */
    async importWallet(password, mnemonic) {
        return await this.createWallet(password, mnemonic);
    }

    /**
     * Scan HD addresses and add any with on-chain balance.
     * Derives sequential addresses and queries the API until GAP_LIMIT
     * consecutive empty addresses are found (BIP44 standard).
     * @param {Object} connectionManager - ConnectionManager instance for API queries
     * @param {Function} onProgress - Optional callback(index, found, address) for UI updates
     * @returns {Promise<Object>} {scanned, found, addresses}
     */
    async scanHDAddresses(connectionManager, onProgress = null) {
        if (!this.isUnlocked) {
            throw new Error('Wallet is locked');
        }

        const GAP_LIMIT = 250;  // Mining wallets can have large gaps between funded addresses
        const accountIndex = 0;
        let consecutiveEmpty = 0;
        let index = 1; // Start at 1 since index 0 was created during import
        let found = 0;
        const foundAddresses = [];

        // Get existing addresses to avoid duplicates
        const existing = await this.getAddresses();
        const existingSet = new Set(existing.map(a => a.address));

        console.log('[LocalWallet] Starting HD address scan (gap limit: ' + GAP_LIMIT + ')...');

        // Scan both external (0') and internal/change (1') chains
        for (const chainIndex of [0, 1]) {
            consecutiveEmpty = 0;
            index = chainIndex === 0 ? 1 : 0;  // External starts at 1 (0 created at import), internal at 0

        while (consecutiveEmpty < GAP_LIMIT) {
            const keyPath = `m/44'/573'/${accountIndex}'/${chainIndex}'/${index}'`;

            try {
                const { publicKey } = await this.crypto.deriveChildKey(this.decryptedSeed, keyPath);
                const address = this.crypto.deriveAddress(publicKey);

                // Query balance from API — check BOTH chains without touching activeChain
                let hasBalance = false;
                const apiPrefixes = ['/api/v1', '/dilv/api/v1'];
                for (const prefix of apiPrefixes) {
                    try {
                        const url = `https://explorer.dilithion.org${prefix}/balance/${address}`;
                        const resp = await fetch(url);
                        if (resp.ok) {
                            const balanceInfo = await resp.json();
                            if ((balanceInfo.confirmed || 0) > 0 || (balanceInfo.unconfirmed || 0) > 0) {
                                hasBalance = true;
                                break;
                            }
                        }
                    } catch (e) {
                        // API error — try next chain
                    }
                }

                // Keep wallet alive during long scans
                this.resetLockTimer();

                if (hasBalance) {
                    consecutiveEmpty = 0;
                    found++;

                    // Save address if not already known
                    if (!existingSet.has(address)) {
                        // Update wallet's nextAddressIndex
                        const wallet = await this.getWallet();
                        const account = wallet.accounts[accountIndex];
                        if (index >= account.nextAddressIndex) {
                            account.nextAddressIndex = index + 1;
                            await this.saveWallet(wallet);
                        }

                        await this.saveAddress({
                            walletId: this.walletId,
                            address,
                            path: keyPath,
                            accountIndex,
                            addressIndex: index,
                            label: '',
                            createdAt: Date.now()
                        });
                        existingSet.add(address);
                        foundAddresses.push(address);
                    }
                } else {
                    consecutiveEmpty++;
                }

                if (onProgress) {
                    onProgress(index, found, address, hasBalance);
                }
            } catch (e) {
                console.warn('[LocalWallet] HD scan error at index ' + index + ':', e.message);
                consecutiveEmpty++;
            }

            index++;
        }
        } // end for chainIndex

        console.log('[LocalWallet] HD scan complete. Scanned: ' + (index - 1) + ', Found: ' + found);
        return { scanned: index - 1, found, addresses: foundAddresses };
    }

    /**
     * Unlock wallet with password
     * @param {string|null} password - Wallet password (null for unencrypted wallets)
     * @returns {Promise<boolean>} True if unlocked successfully
     */
    async unlock(password) {
        await this.init();

        // Get wallet
        const wallet = await this.getWallet();
        if (!wallet) {
            throw new Error('No wallet found');
        }

        if (!wallet.encrypted) {
            // LP-9: legacy unencrypted wallets must be migrated to encrypted-at-rest
            // before they can be unlocked. The UI routes these through
            // encryptExisting() (a blocking "secure your wallet" step) — there is no
            // silent unlock path for a plaintext-at-rest seed.
            throw new Error('WALLET_NEEDS_ENCRYPTION');
        }

        // Decrypt seed
        try {
            this.decryptedSeed = await this.crypto.decrypt(wallet.encryptedSeed, password);
        } catch (e) {
            throw new Error('Wrong password');
        }

        // Update state
        this.walletId = wallet.id;
        this.isUnlocked = true;
        this.accounts = wallet.accounts;

        // Start auto-lock timer
        this.startLockTimer();

        // Emit event
        this.emit('unlock', { walletId: this.walletId });

        console.log('[LocalWallet] Wallet unlocked');
        return true;
    }

    /**
     * Encrypt an already-existing UNENCRYPTED wallet in place (LP-9 migration).
     *
     * Reads the plaintext seed currently stored in IndexedDB, AES-256-GCM-encrypts
     * it with `newPassword` (PBKDF2/100k), and atomically replaces the wallet record
     * with the ciphertext-only version (`encrypted:true`). On success the wallet is
     * left unlocked.
     *
     * Safety properties:
     *  - Interruption-safe: the ciphertext is round-trip VERIFIED (decrypt back to the
     *    exact original seed bytes) BEFORE the plaintext record is replaced. The replace
     *    is a single IndexedDB `put` of the same keyPath, so the store transitions
     *    plaintext -> ciphertext in one atomic write — there is no intermediate
     *    "no seed" state. A crash before the put leaves the original plaintext intact
     *    (next load re-prompts migration); a crash after leaves a fully-encrypted,
     *    verified record.
     *  - Race-tolerant: state is re-read inside the call; if another tab already
     *    encrypted the wallet, this returns without clobbering it.
     *  - Zeroizing: the in-memory plaintext working copies are wiped, and the stored
     *    record no longer carries the raw seed (the old value is overwritten, not kept).
     *
     * @param {string} newPassword - New password (min 8 chars)
     * @returns {Promise<boolean>} True on success (wallet now encrypted + unlocked)
     */
    async encryptExisting(newPassword) {
        await this.init();

        if (!newPassword || newPassword.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }

        // Re-read current state (race-tolerant: another tab may have migrated already)
        const wallet = await this.getWallet();
        if (!wallet) {
            throw new Error('No wallet found');
        }
        if (wallet.encrypted === true) {
            // Already migrated by another tab/process — nothing to do here.
            // Caller should fall back to a normal unlock.
            return false;
        }

        // The plaintext seed is stored directly as bytes for legacy unencrypted wallets.
        // Make a private working copy we control (so we can zeroize it).
        const plaintextSeed = new Uint8Array(wallet.encryptedSeed);

        let encrypted;
        try {
            // Encrypt (AES-256-GCM via PBKDF2).
            encrypted = await this.crypto.encrypt(plaintextSeed, newPassword);

            // VERIFY before we destroy the plaintext: decrypt the ciphertext back and
            // confirm it equals the original seed byte-for-byte. If this fails we throw
            // and leave the original plaintext record untouched (no data loss).
            const roundTrip = await this.crypto.decrypt(encrypted, newPassword);
            if (!this._bytesEqual(roundTrip, plaintextSeed)) {
                roundTrip.fill(0);
                throw new Error('Encryption self-check failed; wallet left unchanged');
            }
            roundTrip.fill(0);
        } catch (e) {
            plaintextSeed.fill(0);
            throw e;
        }

        // Atomic replace: single put of the same keyPath swaps plaintext -> ciphertext.
        const migrated = {
            ...wallet,
            encrypted: true,
            encryptedSeed: encrypted
        };
        try {
            await this.saveWallet(migrated);
        } catch (e) {
            // Write/quota failure: original plaintext record is still intact.
            plaintextSeed.fill(0);
            throw new Error('Could not save encrypted wallet (storage error). Your wallet is unchanged — please try again. ' + (e && e.message ? e.message : ''));
        }

        // Establish unlocked in-memory state from the (now verified) seed.
        this.walletId = wallet.id;
        this.decryptedSeed = new Uint8Array(plaintextSeed);
        this.isUnlocked = true;
        this.accounts = wallet.accounts;
        this.startLockTimer();

        // Wipe the working copy.
        plaintextSeed.fill(0);

        this.emit('unlock', { walletId: this.walletId });
        console.log('[LocalWallet] Wallet migrated to encrypted-at-rest');
        return true;
    }

    /**
     * Constant-ish byte-array equality (length + per-byte).
     * @param {Uint8Array} a
     * @param {Uint8Array} b
     * @returns {boolean}
     */
    _bytesEqual(a, b) {
        if (!a || !b || a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff === 0;
    }

    /**
     * Check if the wallet is encrypted
     * @returns {Promise<boolean|null>} True if encrypted, false if not, null if no wallet
     */
    async isWalletEncrypted() {
        await this.init();
        const wallet = await this.getWallet();
        if (!wallet) return null;
        return wallet.encrypted === true;
    }

    /**
     * Lock wallet (clear decrypted seed from memory)
     */
    lock() {
        if (this.decryptedSeed) {
            // Clear seed from memory
            this.decryptedSeed.fill(0);
        }

        this.decryptedSeed = null;
        this.isUnlocked = false;

        // Cancel lock timer
        if (this.lockTimer) {
            clearTimeout(this.lockTimer);
            this.lockTimer = null;
        }

        // Emit event
        this.emit('lock', {});

        console.log('[LocalWallet] Wallet locked');
    }

    /**
     * Check if wallet is unlocked
     * @returns {boolean}
     */
    isWalletUnlocked() {
        return this.isUnlocked;
    }

    /**
     * Get a new address
     * @param {number} accountIndex - Account index (default 0)
     * @param {string} label - Optional address label
     * @returns {Promise<string>} New address
     */
    async getNewAddress(accountIndex = 0, label = '') {
        if (!this.isUnlocked) {
            throw new Error('Wallet is locked');
        }

        // Get wallet
        const wallet = await this.getWallet();
        if (!wallet) {
            throw new Error('No wallet found');
        }

        // Get account
        const account = wallet.accounts[accountIndex];
        if (!account) {
            throw new Error('Account not found');
        }

        // Derive new address
        const addressIndex = account.nextAddressIndex;
        const keyPath = `m/44'/573'/${accountIndex}'/0'/${addressIndex}'`;
        const { publicKey } = await this.crypto.deriveChildKey(this.decryptedSeed, keyPath);
        const address = this.crypto.deriveAddress(publicKey);

        // Update account
        account.nextAddressIndex = addressIndex + 1;
        await this.saveWallet(wallet);

        // Save address
        await this.saveAddress({
            walletId: this.walletId,
            address,
            path: keyPath,
            accountIndex,
            addressIndex,
            label,
            createdAt: Date.now()
        });

        // Reset lock timer
        this.resetLockTimer();

        console.log('[LocalWallet] New address generated:', address);
        return address;
    }

    /**
     * Get all addresses for wallet
     * @param {number} accountIndex - Optional account filter
     * @returns {Promise<Object[]>} Array of address records
     */
    async getAddresses(accountIndex = null) {
        await this.init();

        if (!this.walletId) {
            const wallet = await this.getWallet();
            if (!wallet) {
                return [];
            }
            this.walletId = wallet.id;
        }

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(ADDRESS_STORE, 'readonly');
            const store = tx.objectStore(ADDRESS_STORE);
            const index = store.index('walletId');
            const request = index.getAll(this.walletId);

            request.onsuccess = () => {
                let addresses = request.result;
                if (accountIndex !== null) {
                    addresses = addresses.filter(a => a.accountIndex === accountIndex);
                }
                resolve(addresses);
            };
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Get private key for address (for signing)
     * @param {string} address - Address to get key for
     * @returns {Promise<Uint8Array>} Private key
     */
    async getPrivateKey(address) {
        if (!this.isUnlocked) {
            throw new Error('Wallet is locked');
        }

        // Find address record
        const addresses = await this.getAddresses();
        const addrRecord = addresses.find(a => a.address === address);

        if (!addrRecord) {
            throw new Error('Address not found in wallet');
        }

        // Derive private key
        const { privateKey } = await this.crypto.deriveChildKey(
            this.decryptedSeed,
            addrRecord.path
        );

        // Reset lock timer
        this.resetLockTimer();

        return privateKey;
    }

    /**
     * Update address label
     * @param {string} address - Address to update
     * @param {string} label - New label
     */
    async setAddressLabel(address, label) {
        await this.init();

        const tx = this.db.transaction(ADDRESS_STORE, 'readwrite');
        const store = tx.objectStore(ADDRESS_STORE);
        const index = store.index('address');
        const request = index.get(address);

        return new Promise((resolve, reject) => {
            request.onsuccess = () => {
                const record = request.result;
                if (!record) {
                    reject(new Error('Address not found'));
                    return;
                }

                record.label = label;
                const updateRequest = store.put(record);
                updateRequest.onsuccess = () => resolve();
                updateRequest.onerror = () => reject(updateRequest.error);
            };
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Export mnemonic (requires unlocked wallet)
     * @param {string} password - Password to verify
     * @returns {Promise<string[]>} Mnemonic words
     */
    async exportMnemonic(password) {
        if (!this.isUnlocked) {
            throw new Error('Wallet is locked');
        }

        // Verify password by attempting to decrypt
        const wallet = await this.getWallet();
        try {
            await this.crypto.decrypt(wallet.encryptedSeed, password);
        } catch (e) {
            throw new Error('Wrong password');
        }

        // Mnemonic is not stored in the browser for security reasons
        throw new Error('Your recovery phrase was shown when you created your wallet. For security, it is not stored in the browser. Make sure to keep a backup of your wallet.dat file.');
    }

    /**
     * Change wallet password
     * @param {string} oldPassword - Current password
     * @param {string} newPassword - New password
     */
    async changePassword(oldPassword, newPassword) {
        if (!this.isUnlocked) {
            throw new Error('Wallet is locked');
        }

        // Validate new password
        if (!newPassword || newPassword.length < 8) {
            throw new Error('New password must be at least 8 characters');
        }

        // Verify old password
        const wallet = await this.getWallet();
        try {
            await this.crypto.decrypt(wallet.encryptedSeed, oldPassword);
        } catch (e) {
            throw new Error('Wrong password');
        }

        // Re-encrypt seed with new password
        wallet.encryptedSeed = await this.crypto.encrypt(this.decryptedSeed, newPassword);
        await this.saveWallet(wallet);

        console.log('[LocalWallet] Password changed');
    }

    /**
     * Delete wallet (irreversible!)
     * @param {string} password - Password to confirm (ignored for unencrypted wallets)
     */
    async deleteWallet(password) {
        // Verify password for encrypted wallets
        const wallet = await this.getWallet();
        if (wallet && wallet.encrypted) {
            try {
                await this.crypto.decrypt(wallet.encryptedSeed, password);
            } catch (e) {
                throw new Error('Wrong password');
            }
        }

        // Lock wallet
        this.lock();

        // Delete all data
        await new Promise((resolve, reject) => {
            const tx = this.db.transaction([WALLET_STORE, ADDRESS_STORE], 'readwrite');
            tx.objectStore(WALLET_STORE).clear();
            tx.objectStore(ADDRESS_STORE).clear();
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });

        console.log('[LocalWallet] Wallet deleted');
    }

    // ========================================================================
    // Settings
    // ========================================================================

    /**
     * Set auto-lock timeout
     * @param {number} minutes - Minutes before auto-lock (0 = disabled)
     */
    setAutoLockMinutes(minutes) {
        this.autoLockMinutes = minutes;
        this.saveSetting('autoLockMinutes', minutes);
        this.resetLockTimer();
    }

    /**
     * Get auto-lock timeout
     * @returns {number} Minutes
     */
    getAutoLockMinutes() {
        return this.autoLockMinutes;
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /**
     * Get wallet from database
     * @returns {Promise<Object|null>}
     */
    async getWallet() {
        await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(WALLET_STORE, 'readonly');
            const store = tx.objectStore(WALLET_STORE);
            const request = store.getAll();

            request.onsuccess = () => {
                const wallets = request.result;
                resolve(wallets.length > 0 ? wallets[0] : null);
            };
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Save wallet to database
     * @param {Object} wallet
     */
    async saveWallet(wallet) {
        await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(WALLET_STORE, 'readwrite');
            const store = tx.objectStore(WALLET_STORE);
            const request = store.put(wallet);

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Save address to database
     * @param {Object} address
     */
    async saveAddress(address) {
        await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(ADDRESS_STORE, 'readwrite');
            const store = tx.objectStore(ADDRESS_STORE);
            const request = store.put(address);

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Save setting
     * @param {string} key
     * @param {any} value
     */
    async saveSetting(key, value) {
        await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(SETTINGS_STORE, 'readwrite');
            const store = tx.objectStore(SETTINGS_STORE);
            const request = store.put({ key, value });

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Load setting
     * @param {string} key
     * @param {any} defaultValue
     * @returns {Promise<any>}
     */
    async loadSetting(key, defaultValue = null) {
        await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(SETTINGS_STORE, 'readonly');
            const store = tx.objectStore(SETTINGS_STORE);
            const request = store.get(key);

            request.onsuccess = () => {
                resolve(request.result ? request.result.value : defaultValue);
            };
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Start auto-lock timer
     */
    startLockTimer() {
        if (this.autoLockMinutes <= 0) {
            return;  // Auto-lock disabled
        }

        this.lockTimer = setTimeout(() => {
            console.log('[LocalWallet] Auto-lock triggered');
            this.lock();
        }, this.autoLockMinutes * 60 * 1000);
    }

    /**
     * Reset auto-lock timer (called on user activity)
     */
    resetLockTimer() {
        if (this.lockTimer) {
            clearTimeout(this.lockTimer);
        }
        if (this.isUnlocked) {
            this.startLockTimer();
        }
    }

    /**
     * Generate UUID v4
     * @returns {string}
     */
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    // ========================================================================
    // Event handling
    // ========================================================================

    /**
     * Add event listener
     * @param {string} event - Event name
     * @param {Function} callback
     */
    on(event, callback) {
        if (this.listeners[event]) {
            this.listeners[event].push(callback);
        }
    }

    /**
     * Remove event listener
     * @param {string} event - Event name
     * @param {Function} callback
     */
    off(event, callback) {
        if (this.listeners[event]) {
            this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
        }
    }

    /**
     * Emit event
     * @param {string} event - Event name
     * @param {any} data
     */
    emit(event, data) {
        if (this.listeners[event]) {
            for (const callback of this.listeners[event]) {
                try {
                    callback(data);
                } catch (e) {
                    console.error('[LocalWallet] Event handler error:', e);
                }
            }
        }
    }
}

// Export for both module and browser use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LocalWallet;
} else if (typeof window !== 'undefined') {
    window.LocalWallet = LocalWallet;
}
