// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <attestation/seed_attestation.h>
#include <crypto/sha3.h>
#include <util/strencodings.h>
#include <wallet/crypter.h>  // For memory_cleanse() + CCrypter/DeriveKey (LP-13 encrypt-at-rest)

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>  // LP-13 (extreview HIGH): presence test, not readability
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>   // LP-13 H-2: MoveFileExW for atomic key-file replace
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/stat.h>   // LP-13: chmod/fchmod for 0600 key file perms
#include <fcntl.h>
#endif

// Dilithium3 reference implementation
extern "C" {
    int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
    int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *sk);
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

namespace Attestation {

// File format magic and version
static constexpr uint32_t KEY_FILE_MAGIC = 0x444C4154;  // "DLAT" (Dilithion Attestation)
// v1: plaintext private key (legacy — still readable for backward-compat migration)
// v2 (LP-13): private key encrypted at rest (AES-256-CBC, PBKDF2-SHA3, encrypt-then-MAC)
static constexpr uint8_t KEY_FILE_VERSION_V1 = 1;
static constexpr uint8_t KEY_FILE_VERSION_V2 = 2;

// LP-13 v2 on-disk sizes (bytes)
static constexpr size_t SEED_KEY_SALT_SIZE = 16;  // PBKDF2 salt (== WALLET_CRYPTO_SALT_SIZE)
static constexpr size_t SEED_KEY_IV_SIZE   = 16;  // AES-CBC IV     (== WALLET_CRYPTO_IV_SIZE)
static constexpr size_t SEED_KEY_MAC_SIZE  = 64;  // HMAC-SHA3-512  (encrypt-then-MAC)

// LP-13: PBKDF2 rounds for the seed-key passphrase. Reuse the wallet constant
// for a single hardened KDF cost across the codebase.
static constexpr unsigned int SEED_KEY_PBKDF2_ROUNDS = WALLET_CRYPTO_PBKDF2_ROUNDS;

// ============================================================================
// LP-13 helpers
// ============================================================================

// Read the operator passphrase from the environment. Empty => not configured
// (Save falls back to legacy v1 plaintext; Load cannot decrypt a v2 file).
static std::string GetSeedKeyPassphrase() {
    const char* env = std::getenv(Attestation::SEED_KEY_PASSPHRASE_ENV);
    if (env == nullptr) return std::string();
    return std::string(env);
}

// Restrict a key file to owner read/write only. POSIX: chmod 0600. Windows:
// best-effort no-op (NTFS confines the per-user profile data dir; documented).
// Returns true if perms are owner-only after the call (Windows: always true).
static bool RestrictKeyFilePerms(const std::string& path) {
#ifndef _WIN32
    // 0600 = owner rw, no group/other. Failure is logged; the caller decides
    // whether it is fatal (Save M-4 fail-closed) or merely a warning.
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        std::cerr << "[Attestation] WARNING: could not chmod 0600 key file: " << path << std::endl;
        return false;
    }
    return true;
#else
    (void)path;  // Windows: relies on NTFS ACL of the user profile data dir.
    return true;
#endif
}

// LP-13 M-3: on Load, report whether a pre-existing file is group/other-readable
// (a legacy v1 file may have been written 0644 before this hardening landed).
// POSIX only; Windows relies on the NTFS ACL of the profile dir.
#ifndef _WIN32
static bool KeyFileIsPermissive(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;  // can't tell; don't warn
    return (st.st_mode & (S_IRWXG | S_IRWXO)) != 0;   // any group/other bit set
}
#endif

// LP-13 (extreview HIGH): presence test (stat), not readability. See header.
bool SeedKeyFilePresent(const std::string& dataDir) {
    std::error_code ec;
    bool present = std::filesystem::exists(dataDir + "/" + SEED_KEY_FILENAME, ec);
    // A stat error (ec set) means we cannot prove ABSENCE; fail closed (report
    // present) so an unstattable-but-genuine key still drives fail-loud startup.
    if (ec) return true;
    return present;
}

// LP-13 H-2 atomic-save test seam (see header). nullptr in production.
bool (*g_seedKeySaveFailpoint)() = nullptr;
// LP-13 B-1 fsync-failure test seam (see header). nullptr in production.
bool (*g_seedKeyFsyncFailpoint)() = nullptr;

// ============================================================================
// CSeedAttestationKey
// ============================================================================

CSeedAttestationKey::~CSeedAttestationKey() {
    Clear();
}

void CSeedAttestationKey::Clear() {
    if (!m_privkey.empty()) {
        memory_cleanse(m_privkey.data(), m_privkey.size());
    }
    m_privkey.clear();
    m_pubkey.clear();
    m_loadedV1Plaintext = false;
}

bool CSeedAttestationKey::Generate() {
    m_pubkey.resize(DFMP::MIK_PUBKEY_SIZE);
    m_privkey.resize(DFMP::MIK_PRIVKEY_SIZE);

    int result = pqcrystals_dilithium3_ref_keypair(m_pubkey.data(), m_privkey.data());
    if (result != 0) {
        Clear();
        return false;
    }
    return true;
}

// LP-13 (round-2 fold): internal Load that ALSO classifies the failure reason
// (MISSING vs CORRUPT vs TRANSIENT) so the node can pick FATAL vs warn-continue.
// The public Load() forwards to this and discards the status (behavior unchanged).
SeedKeyLoadStatus CSeedAttestationKey::LoadClassified(const std::string& dataDir) {
    std::string path = dataDir + "/" + SEED_KEY_FILENAME;
    m_loadedV1Plaintext = false;

    // LP-13 M-3: repair perms on a pre-existing key file BEFORE reading its
    // secret bytes. A legacy v1 file may have been written world/group-readable
    // (0644) prior to this hardening; chmod it back to 0600 and warn loudly so
    // the operator knows the key was exposed at rest.
#ifndef _WIN32
    if (KeyFileIsPermissive(path)) {
        std::cerr << "[Attestation] WARNING: key file " << path
                  << " was group/other-readable; repairing to 0600. The consensus"
                     " signing key may have been exposed — consider rotating it."
                  << std::endl;
        RestrictKeyFilePerms(path);
    }
#endif

    // LP-13 (round-2 fold, transient-vs-permanent): classify open failures.
    // ENOENT (file genuinely absent) => MISSING (permanent, the SM-5 loud-fatal
    // case on an actual seed). Any OTHER open errno on a file that statted as
    // PRESENT (EACCES/EBUSY/EIO/EMFILE/…) => TRANSIENT: a momentary fault that a
    // retry/reboot may clear, so the node warns-and-continues rather than entering
    // a crash-loop. We use the SAME presence oracle (SeedKeyFilePresent / stat)
    // the node already trusts, then read errno from the actual open() attempt.
    // Read the whole file up front so v2 length/format checks are robust against
    // truncation, and so we never leave a half-read secret in memory on error.
    errno = 0;
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        int openErrno = errno;
        // SeedKeyFilePresent fails CLOSED (reports present on an indeterminate
        // stat), so "not present" here means a clean ENOENT-class absence.
        bool present = SeedKeyFilePresent(dataDir);
        if (!present || openErrno == ENOENT) {
            return SeedKeyLoadStatus::MISSING;
        }
        // Present but unopenable for a non-ENOENT reason => transient/permission.
        std::cerr << "[Attestation] WARNING: seed key file present at " << path
                  << " but could not be opened (errno " << openErrno
                  << "); treating as a TRANSIENT read error." << std::endl;
        return SeedKeyLoadStatus::TRANSIENT;
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
    file.close();

    // magic(4) + version(1) header. Past this point the file is PRESENT and
    // OPENED — any failure is a PERMANENT content/format/passphrase problem
    // (CORRUPT), not a transient one: re-running yields the identical failure.
    if (buf.size() < 5) {
        std::cerr << "[Attestation] Key file too short" << std::endl;
        return SeedKeyLoadStatus::CORRUPT;
    }

    uint32_t magic = 0;
    std::memcpy(&magic, buf.data(), 4);
    if (magic != KEY_FILE_MAGIC) {
        std::cerr << "[Attestation] Invalid key file magic" << std::endl;
        return SeedKeyLoadStatus::CORRUPT;
    }

    uint8_t version = buf[4];
    size_t off = 5;

    if (version == KEY_FILE_VERSION_V1) {
        // Legacy plaintext format (backward compat for un-migrated seeds):
        //   magic(4) version(1) pubkey(1952) privkey(4032)
        if (buf.size() < off + DFMP::MIK_PUBKEY_SIZE + DFMP::MIK_PRIVKEY_SIZE) {
            std::cerr << "[Attestation] v1 key file truncated" << std::endl;
            return SeedKeyLoadStatus::CORRUPT;
        }
        m_pubkey.assign(buf.begin() + off, buf.begin() + off + DFMP::MIK_PUBKEY_SIZE);
        off += DFMP::MIK_PUBKEY_SIZE;
        m_privkey.assign(buf.begin() + off, buf.begin() + off + DFMP::MIK_PRIVKEY_SIZE);
        // Wipe the plaintext private key out of the read buffer.
        memory_cleanse(buf.data() + off, DFMP::MIK_PRIVKEY_SIZE);
        m_loadedV1Plaintext = true;  // LP-13 H-1: provenance for require-encryption gate
        std::cout << "[Attestation] Loaded seed attestation key (v1 plaintext): "
                  << GetPubKeyHex().substr(0, 16) << "..." << std::endl;
        std::cerr << "[Attestation] NOTE: key file is unencrypted (v1). Set "
                  << SEED_KEY_PASSPHRASE_ENV << " to re-save it encrypted (v2)." << std::endl;
        return SeedKeyLoadStatus::OK;
    }

    if (version == KEY_FILE_VERSION_V2) {
        // LP-13 encrypted format:
        //   magic(4) version(1) pubkey(1952) salt(16) iv(16) mac(64)
        //   ctlen(4 LE) ciphertext(ctlen)
        size_t headerEnd = off + DFMP::MIK_PUBKEY_SIZE + SEED_KEY_SALT_SIZE +
                           SEED_KEY_IV_SIZE + SEED_KEY_MAC_SIZE + 4;
        if (buf.size() < headerEnd) {
            std::cerr << "[Attestation] v2 key file truncated (header)" << std::endl;
            return SeedKeyLoadStatus::CORRUPT;
        }

        m_pubkey.assign(buf.begin() + off, buf.begin() + off + DFMP::MIK_PUBKEY_SIZE);
        off += DFMP::MIK_PUBKEY_SIZE;

        std::vector<uint8_t> salt(buf.begin() + off, buf.begin() + off + SEED_KEY_SALT_SIZE);
        off += SEED_KEY_SALT_SIZE;
        std::vector<uint8_t> iv(buf.begin() + off, buf.begin() + off + SEED_KEY_IV_SIZE);
        off += SEED_KEY_IV_SIZE;
        std::vector<uint8_t> mac(buf.begin() + off, buf.begin() + off + SEED_KEY_MAC_SIZE);
        off += SEED_KEY_MAC_SIZE;

        uint32_t ctlen = static_cast<uint32_t>(buf[off]) |
                         (static_cast<uint32_t>(buf[off + 1]) << 8) |
                         (static_cast<uint32_t>(buf[off + 2]) << 16) |
                         (static_cast<uint32_t>(buf[off + 3]) << 24);
        off += 4;

        if (buf.size() != off + ctlen || ctlen == 0 || (ctlen % 16) != 0) {
            std::cerr << "[Attestation] v2 key file truncated or malformed ciphertext" << std::endl;
            return SeedKeyLoadStatus::CORRUPT;
        }
        std::vector<uint8_t> ciphertext(buf.begin() + off, buf.begin() + off + ctlen);

        std::string passphrase = GetSeedKeyPassphrase();
        if (passphrase.empty()) {
            std::cerr << "[Attestation] ERROR: key file is encrypted (v2) but "
                      << SEED_KEY_PASSPHRASE_ENV << " is not set. Cannot decrypt." << std::endl;
            Clear();
            return SeedKeyLoadStatus::CORRUPT;
        }

        // LP-13 M-3 (Cursor): RAII exception-safe wipe of the v2 decrypt secrets —
        // mirrors Save()'s SecretScopeWipe (Cursor flagged the asymmetry). passphrase
        // / aesKey / plain are cleansed on EVERY exit from here including a thrown
        // std::bad_alloc, not just the explicit returns below (which keep their
        // earlier inline cleanses for minimal live-window hygiene; double-cleansing
        // already-zeroed bytes is harmless).
        std::vector<uint8_t> aesKey, plain;
        struct LoadSecretWipe {
            std::string& p; std::vector<uint8_t>& k; std::vector<uint8_t>& pl;
            ~LoadSecretWipe() {
                if (!p.empty()) memory_cleanse(&p[0], p.size());
                if (!k.empty()) memory_cleanse(k.data(), k.size());
                if (!pl.empty()) memory_cleanse(pl.data(), pl.size());
            }
        } loadSecretWipe{passphrase, aesKey, plain};

        // Derive AES key from passphrase + salt, then encrypt-then-MAC verify.
        if (!DeriveKey(passphrase, salt, SEED_KEY_PBKDF2_ROUNDS, aesKey)) {
            std::cerr << "[Attestation] ERROR: key derivation failed" << std::endl;
            memory_cleanse(&passphrase[0], passphrase.size());
            Clear();
            return SeedKeyLoadStatus::CORRUPT;
        }
        memory_cleanse(&passphrase[0], passphrase.size());

        CCrypter crypter;
        if (!crypter.SetKey(aesKey, iv)) {
            std::cerr << "[Attestation] ERROR: failed to set decryption key" << std::endl;
            memory_cleanse(aesKey.data(), aesKey.size());
            Clear();
            return SeedKeyLoadStatus::CORRUPT;
        }
        memory_cleanse(aesKey.data(), aesKey.size());

        // Verify MAC BEFORE decrypt (prevents padding-oracle / tamper). A wrong
        // passphrase yields a different derived key => MAC mismatch => reject.
        if (!crypter.VerifyMAC(ciphertext, mac)) {
            std::cerr << "[Attestation] ERROR: key file MAC verification failed "
                      << "(wrong passphrase or tampered/corrupt file)." << std::endl;
            Clear();
            return SeedKeyLoadStatus::CORRUPT;
        }

        if (!crypter.Decrypt(ciphertext, plain) || plain.size() != DFMP::MIK_PRIVKEY_SIZE) {
            std::cerr << "[Attestation] ERROR: key file decryption failed" << std::endl;
            if (!plain.empty()) memory_cleanse(plain.data(), plain.size());
            Clear();
            return SeedKeyLoadStatus::CORRUPT;
        }
        m_privkey.assign(plain.begin(), plain.end());
        memory_cleanse(plain.data(), plain.size());

        std::cout << "[Attestation] Loaded seed attestation key (v2 encrypted): "
                  << GetPubKeyHex().substr(0, 16) << "..." << std::endl;
        return SeedKeyLoadStatus::OK;
    }

    std::cerr << "[Attestation] Unsupported key file version: " << (int)version << std::endl;
    return SeedKeyLoadStatus::CORRUPT;
}

// LP-13: public Load() preserves the original bool contract (true == OK), now a
// thin wrapper over the classifying LoadClassified(). All existing callers and
// tests are unaffected.
bool CSeedAttestationKey::Load(const std::string& dataDir) {
    return LoadClassified(dataDir) == SeedKeyLoadStatus::OK;
}

// LP-13 MEDIUM-1: zero a transient buffer that may hold the plaintext private
// key on the v1 Save path. Exposed (declared in the header) so the test suite
// can assert the wipe actually happens — deleting the memory_cleanse below is
// the mutation the cleanse test is designed to catch.
void CleanseSeedKeyBuffer(std::vector<uint8_t>& buf) {
    if (!buf.empty()) memory_cleanse(buf.data(), buf.size());
}

bool CSeedAttestationKey::Save(const std::string& dataDir, bool allowPlaintext) const {
    if (!IsValid()) return false;

    std::string path = dataDir + "/" + SEED_KEY_FILENAME;

    // LP-13 CL-1 (DEFAULT-ON ENCRYPTION — inverted from the prior default): the
    // seed consensus signing key is encrypted at rest by default. We refuse to
    // write a plaintext (v1) key unless the operator EXPLICITLY opts out via
    // allowPlaintext (--allow-plaintext-seed-key). Without the passphrase we
    // cannot encrypt, so on the default path (allowPlaintext=false + no
    // passphrase) we FAIL LOUD rather than silently persist an unencrypted
    // consensus key. The passphrase is provisioned at deploy via
    // DILITHION_SEED_KEY_PASSPHRASE.
    if (GetSeedKeyPassphrase().empty() && !allowPlaintext) {
        std::cerr << "[Attestation] FATAL: " << SEED_KEY_PASSPHRASE_ENV
                  << " is unset and seed-key encryption is mandatory by default."
                     " Refusing to write an UNENCRYPTED (v1) seed consensus signing"
                     " key. Provision the passphrase (recommended), or pass"
                     " --allow-plaintext-seed-key to explicitly opt out of"
                     " encryption-at-rest." << std::endl;
        return false;
    }

    // LP-13: assemble the full serialized blob in memory first, then write it
    // in one shot. This lets us harden file permissions BEFORE any secret bytes
    // hit the disk (POSIX: create with 0600), avoiding a world-readable window.
    std::vector<uint8_t> out;
    auto putU32 = [&out](uint32_t v) {
        out.push_back(static_cast<uint8_t>(v & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    };

    // magic(4, native order to match Load's memcpy) + version(1)
    uint32_t magic = KEY_FILE_MAGIC;
    const uint8_t* magicBytes = reinterpret_cast<const uint8_t*>(&magic);
    out.insert(out.end(), magicBytes, magicBytes + 4);

    std::string passphrase = GetSeedKeyPassphrase();
    bool encrypt = !passphrase.empty();

    // LP-13 (exception-safety fold, convergent across red-team + extreview grok/
    // qwen3/nemotron): the finish() lambda below + the inline memory_cleanse calls
    // only run on EXPLICIT returns. A std::bad_alloc thrown mid-assembly (e.g. an
    // out.insert / DeriveKey allocation) would unwind PAST them, leaving the
    // plaintext private key (v1 `out`) or the passphrase in freed heap. This RAII
    // guard makes the wipe exception-safe: it cleanses both on EVERY scope exit,
    // including a throw. (Double-cleansing already-zeroed bytes on the normal path
    // is harmless.)
    struct SecretScopeWipe {
        std::vector<uint8_t>& buf;
        std::string& pass;
        ~SecretScopeWipe() {
            CleanseSeedKeyBuffer(buf);
            if (!pass.empty()) memory_cleanse(&pass[0], pass.size());
        }
    } secretScopeWipe{out, passphrase};

    // LP-13 MEDIUM-1: on the v1 (default, un-passphrased) path `out` holds the
    // plaintext Dilithium3 private key; on the v2 path it holds only ciphertext.
    // Cleanse `out` UNCONDITIONALLY before every return so the plaintext key is
    // never left in freed heap (cleansing the non-secret v2 buffer is harmless).
    // The actual wipe lives in CleanseSeedKeyBuffer (a test seam — see
    // seed_attestation_key_tests.cpp); this lambda is the single exit gate for
    // all returns past this point.
    auto finish = [&out](bool ok) -> bool {
        CleanseSeedKeyBuffer(out);
        return ok;
    };

    if (!encrypt) {
        // ---- Legacy v1 plaintext (no passphrase configured) ----
        out.push_back(KEY_FILE_VERSION_V1);
        out.insert(out.end(), m_pubkey.begin(), m_pubkey.end());
        out.insert(out.end(), m_privkey.begin(), m_privkey.end());
        std::cerr << "[Attestation] WARNING: " << SEED_KEY_PASSPHRASE_ENV
                  << " not set — writing UNENCRYPTED (v1) key file. Set it to "
                     "encrypt the consensus signing key at rest." << std::endl;
    } else {
        // ---- LP-13 v2 encrypted: AES-256-CBC, PBKDF2-SHA3, encrypt-then-MAC ----
        std::vector<uint8_t> salt, iv;
        if (!GenerateSalt(salt) || !GenerateIV(iv)) {
            std::cerr << "[Attestation] ERROR: failed to generate salt/IV" << std::endl;
            memory_cleanse(&passphrase[0], passphrase.size());
            return finish(false);
        }

        std::vector<uint8_t> aesKey;
        if (!DeriveKey(passphrase, salt, SEED_KEY_PBKDF2_ROUNDS, aesKey)) {
            std::cerr << "[Attestation] ERROR: key derivation failed" << std::endl;
            memory_cleanse(&passphrase[0], passphrase.size());
            return finish(false);
        }
        memory_cleanse(&passphrase[0], passphrase.size());

        CCrypter crypter;
        if (!crypter.SetKey(aesKey, iv)) {
            std::cerr << "[Attestation] ERROR: failed to set encryption key" << std::endl;
            memory_cleanse(aesKey.data(), aesKey.size());
            return finish(false);
        }
        memory_cleanse(aesKey.data(), aesKey.size());

        // LP-13 LOW-1: ComputeMAC keys the HMAC with the SAME 32-byte AES key
        // (no separate k_mac). This is a DELIBERATE reuse of the audited wallet
        // CCrypter construction (encrypt-then-MAC, MAC verified BEFORE decrypt at
        // Load → no padding-oracle surface), not an oversight. AES-256-CBC and
        // HMAC-SHA3-512 are independent constructions with no known cross-protocol
        // interaction under shared keying, so this is no weaker than the wallet's
        // at-rest format. Documented here so it is not re-litigated in review.
        std::vector<uint8_t> ciphertext, mac;
        if (!crypter.Encrypt(m_privkey, ciphertext) ||
            !crypter.ComputeMAC(ciphertext, mac)) {
            std::cerr << "[Attestation] ERROR: encryption/MAC failed" << std::endl;
            return finish(false);
        }

        // magic(4) version(1) pubkey(1952) salt(16) iv(16) mac(64) ctlen(4) ct
        out.push_back(KEY_FILE_VERSION_V2);
        out.insert(out.end(), m_pubkey.begin(), m_pubkey.end());
        out.insert(out.end(), salt.begin(), salt.end());
        out.insert(out.end(), iv.begin(), iv.end());
        out.insert(out.end(), mac.begin(), mac.end());
        putU32(static_cast<uint32_t>(ciphertext.size()));
        out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    }

    // LP-13 H-2 / B-1: ATOMIC, FAIL-CLOSED-DURABLE SAVE. Mirror the wallet's
    // proven temp+fsync+rename pattern (CWallet::SaveUnlocked), but make the
    // durability fatal: the consensus signing key is irreplaceable (not derivable
    // from chainparams), so a failed/partial write hits "<file>.tmp" only — the
    // live "<file>" is left byte-intact and replaced ONLY by an atomic rename of
    // a fully-written, fsync'd temp; if the fsync (POSIX) / FlushFileBuffers
    // (Windows) cannot be confirmed, Save deletes the temp and returns WITHOUT
    // renaming. LP-13 CL-2: there is NO plaintext "<file>.bak" staging copy — the
    // atomic rename alone gives the no-key-loss guarantee (the live "<file>" is
    // untouched until the single rename publishes the fully-flushed temp), so a
    // second (possibly plaintext) copy of the key on disk was both unnecessary and
    // a custody hazard. The guarantee that a crash / partial write / power loss
    // cannot destroy the only copy rests on fsync-before-rename being fatal + the
    // atomic rename + the post-rename dir-fsync below.
    std::string tmpPath = path + ".tmp";
    std::string bakPath = path + ".bak";

#ifndef _WIN32
    // Create the temp with 0600 from the outset (no world-readable window).
    // LP-13 (PARTIAL symlink-hardening, nemotron extreview finding): O_NOFOLLOW
    // refuses to open the temp if its final path component is ALREADY a symlink at
    // open() time — closing the pre-open half of the symlink-swap vector (an
    // attacker pre-planting "<file>.tmp" as a symlink to redirect the key write).
    // We do NOT add O_EXCL: a stale ".tmp" from a prior crashed save is
    // legitimately re-truncated; O_EXCL would wedge the save.
    //
    // SCOPE / KNOWN RESIDUAL (Cursor C-1, accepted out-of-scope): O_NOFOLLOW does
    // NOT close the close()->rename() TOCTOU — between this fd being closed and the
    // ::rename below, a writer in the data dir could swap "<file>.tmp" for a symlink
    // and have rename publish that symlink over the canonical key. Closing that
    // fully needs an O_TMPFILE+linkat (POSIX) / reparse-point (Windows) restructure.
    // It is deliberately NOT done here: it defends only against an attacker who
    // already has WRITE access to the seed's root-owned 0600/0700 data dir (i.e. is
    // already root-equivalent and can destroy the key directly), and this atomic
    // temp+rename mirrors the audited CWallet::SaveUnlocked, which carries the same
    // accepted residual under the same operator-owned-datadir threat model. Accepted
    // as a deferred follow-up (not a #113 blocker); the deferred items are tracked
    // out-of-tree in the project's security record rather than enumerated here, to
    // avoid expanding public detail on un-deployed fixes during the disclosure window.
    int fd = ::open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        std::cerr << "[Attestation] Failed to open temp key file for writing: " << tmpPath
                  << " (errno " << errno << "; O_NOFOLLOW rejects a symlinked temp)" << std::endl;
        return finish(false);
    }
    // LP-13 M-4: re-assert 0600 on the open fd. O_TRUNC does NOT reset the mode
    // of a pre-existing temp. Track whether owner-only perms were established;
    // if BOTH this and the post-write chmod fail we fail-closed below.
    bool permOk = (::fchmod(fd, S_IRUSR | S_IWUSR) == 0);
    if (!permOk) {
        std::cerr << "[Attestation] WARNING: fchmod 0600 on temp key file failed (errno "
                  << errno << "); will re-assert after write." << std::endl;
    }
    size_t written = 0;
    bool writeOk = true;
    while (written < out.size()) {
        ssize_t n = ::write(fd, out.data() + written, out.size() - written);
        if (n <= 0) { writeOk = false; break; }
        written += static_cast<size_t>(n);
    }
    // fsync the data to physical disk BEFORE the rename, so a power loss after
    // rename cannot expose a zero-length/partial file as the live key.
    // LP-13 B-1 (fail-closed durability): a failed fsync means the temp's bytes
    // are NOT guaranteed on stable storage. The consensus signing key is NOT
    // recoverable if lost (not derivable from chainparams), so — unlike
    // wallet.cpp's warn-and-continue (the wallet is seed-recoverable) — we treat
    // fsync failure as FATAL: close, remove the temp, and return WITHOUT
    // renaming. The canonical "<file>" is left byte-intact rather than risk
    // publishing un-flushed (possibly zero-length/partial) data as the live key.
    bool fsyncOk = writeOk && (::fsync(fd) == 0);
    if (writeOk && !fsyncOk) {
        std::cerr << "[Attestation] FATAL: fsync of temp key file failed (errno "
                  << errno << "); refusing to publish un-flushed consensus key. "
                     "Canonical key at " << path << " left untouched." << std::endl;
    }
    // LP-13 B-1 TEST SEAM: let a test force the "fsync failed" branch without a
    // real disk fault (checked here, mirroring g_seedKeySaveFailpoint). nullptr
    // in production (no overhead, no behavior change).
    if (writeOk && fsyncOk && g_seedKeyFsyncFailpoint && g_seedKeyFsyncFailpoint()) {
        std::cerr << "[Attestation] (test) fsync failpoint fired — treating as FATAL fsync failure" << std::endl;
        fsyncOk = false;
    }
    ::close(fd);
    if (writeOk && !fsyncOk) {
        ::unlink(tmpPath.c_str());
        return finish(false);
    }

    // Belt-and-braces: re-assert 0600 on the path in case fchmod was unsupported.
    bool permOk2 = RestrictKeyFilePerms(tmpPath);

    if (!writeOk) {
        std::cerr << "[Attestation] Key file write error (temp)" << std::endl;
        ::unlink(tmpPath.c_str());
        return finish(false);
    }
    // LP-13 M-4 fail-closed: if owner-only perms could NOT be set by either
    // mechanism, refuse to publish a possibly group/other-readable consensus key.
    if (!permOk && !permOk2) {
        std::cerr << "[Attestation] FATAL: could not set 0600 perms on key file; "
                     "refusing to publish a possibly readable consensus key." << std::endl;
        ::unlink(tmpPath.c_str());
        return finish(false);
    }

    // H-2 test seam: simulate a crash between temp-write and rename.
    if (g_seedKeySaveFailpoint && g_seedKeySaveFailpoint()) {
        std::cerr << "[Attestation] (test) save failpoint fired before rename" << std::endl;
        ::unlink(tmpPath.c_str());
        return finish(false);
    }

    // LP-13 CL-2: NO plaintext .bak. The prior key staging copy was a second
    // copy of the OLD key at rest — and for a v1 (or legacy plaintext) key that
    // was a SECOND PLAINTEXT copy of the consensus signing key lingering on disk
    // inside a crash window. The atomic temp+rename below already gives the
    // no-key-loss guarantee (a failed/partial write touches only "<file>.tmp";
    // the live "<file>" is byte-intact until the single atomic rename publishes a
    // fully-written, fsync'd temp), so the .bak fallback was never load-bearing.
    // We drop it entirely so no extra (possibly plaintext) seed key ever survives
    // on disk. Defensive: remove any stale .bak a PRIOR (pre-CL-2) build left.
    ::unlink(bakPath.c_str());

    // Atomic publish: rename(2) over the target is atomic on POSIX.
    if (::rename(tmpPath.c_str(), path.c_str()) != 0) {
        std::cerr << "[Attestation] Key file atomic rename failed (errno " << errno
                  << "); original key left intact at " << path << std::endl;
        ::unlink(tmpPath.c_str());
        return finish(false);
    }
    // perms ride with rename, but re-assert defensively. LP-13 (round-2 LOW): if
    // the post-rename re-assert fails the key was still PUBLISHED (the rename
    // succeeded — we do NOT fail the save and lose the key over a perms blip), but
    // the on-disk file may carry wrong/looser perms than 0600. Warn so the operator
    // can repair it rather than the failure passing silently.
    if (!RestrictKeyFilePerms(path)) {
        std::cerr << "[Attestation] WARNING: could not re-assert 0600 on the published key"
                     " file " << path << " after the atomic rename; the key was SAVED but may"
                     " carry incorrect permissions. Repair manually (chmod 0600)." << std::endl;
    }

    // fsync the directory so the rename metadata is durable across power loss.
    {
        size_t lastSlash = path.find_last_of("/\\");
        std::string parentDir = (lastSlash == std::string::npos) ? "." : path.substr(0, lastSlash);
        if (parentDir.empty()) parentDir = ".";
        int dirfd = ::open(parentDir.c_str(), O_RDONLY);
        if (dirfd >= 0) { ::fsync(dirfd); ::close(dirfd); }
    }
#endif
#ifdef _WIN32
    // Windows: write temp with a durable flush, then MoveFileEx atomic replace.
    // LP-13 CL-2: NO plaintext .bak staging (see the POSIX rationale above).
    //
    // LP-13 B-1 (fail-closed durability, Windows): ofstream::flush()/close() only
    // pushes bytes into the OS cache — NOT to stable storage. We must
    // FlushFileBuffers() the temp BEFORE the MoveFileEx, matching the POSIX
    // fsync-before-rename guarantee. If the durable flush cannot be confirmed we
    // fail-closed (delete temp, leave canonical key untouched) rather than
    // MoveFileEx un-flushed data over the irreplaceable consensus key.
    {
        std::wstring wTmpW(tmpPath.begin(), tmpPath.end());
        HANDLE hTmp = CreateFileW(wTmpW.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hTmp == INVALID_HANDLE_VALUE) {
            std::cerr << "[Attestation] Failed to open temp key file for writing: " << tmpPath
                      << " (GetLastError " << GetLastError() << ")" << std::endl;
            return finish(false);
        }
        bool writeOk = true;
        size_t written = 0;
        while (written < out.size()) {
            DWORD toWrite = static_cast<DWORD>(
                std::min<size_t>(out.size() - written, 1u << 20));
            DWORD wrote = 0;
            if (!WriteFile(hTmp, out.data() + written, toWrite, &wrote, nullptr) || wrote == 0) {
                writeOk = false;
                break;
            }
            written += wrote;
        }
        // Durable flush to stable storage before the atomic replace.
        bool flushOk = writeOk && (FlushFileBuffers(hTmp) != 0);
        if (writeOk && !flushOk) {
            std::cerr << "[Attestation] FATAL: FlushFileBuffers of temp key file failed "
                         "(GetLastError " << GetLastError() << "); refusing to publish "
                         "un-flushed consensus key. Canonical key at " << path
                      << " left untouched." << std::endl;
        }
        // LP-13 B-1 TEST SEAM (Windows): force the "flush failed" branch.
        if (writeOk && flushOk && g_seedKeyFsyncFailpoint && g_seedKeyFsyncFailpoint()) {
            std::cerr << "[Attestation] (test) fsync failpoint fired — treating as FATAL flush failure" << std::endl;
            flushOk = false;
        }
        CloseHandle(hTmp);
        if (!writeOk) {
            std::cerr << "[Attestation] Key file write error (temp)" << std::endl;
            std::remove(tmpPath.c_str());
            return finish(false);
        }
        if (!flushOk) {
            std::remove(tmpPath.c_str());
            return finish(false);
        }
    }

    // H-2 test seam: simulate a crash between temp-write and rename.
    if (g_seedKeySaveFailpoint && g_seedKeySaveFailpoint()) {
        std::cerr << "[Attestation] (test) save failpoint fired before rename" << std::endl;
        std::remove(tmpPath.c_str());
        return finish(false);
    }

    // LP-13 CL-2: NO plaintext .bak. See the POSIX path for the rationale —
    // MoveFileExW's atomic replace already guarantees no-key-loss without a
    // second (possibly plaintext) copy on disk. Defensive: remove any stale .bak
    // a PRIOR (pre-CL-2) build may have left behind.
    std::remove(bakPath.c_str());

    // Atomic publish via MoveFileExW (REPLACE_EXISTING | WRITE_THROUGH): either
    // fully succeeds or fully fails — never a partial/corrupt live key file.
    std::wstring wTmp(tmpPath.begin(), tmpPath.end());
    std::wstring wDst(path.begin(), path.end());
    if (!MoveFileExW(wTmp.c_str(), wDst.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::cerr << "[Attestation] Key file atomic move failed; original key left intact at "
                  << path << std::endl;
        std::remove(tmpPath.c_str());
        return finish(false);
    }
    // best-effort no-op on Windows (NTFS ACL governs); symmetric with POSIX warn.
    if (!RestrictKeyFilePerms(path)) {
        std::cerr << "[Attestation] WARNING: could not re-assert owner-only perms on the"
                     " published key file " << path << " after the atomic move; the key was"
                     " SAVED but may carry incorrect permissions." << std::endl;
    }
#endif

    std::cout << "[Attestation] Saved seed attestation key to: " << path
              << (encrypt ? " (v2 encrypted)" : " (v1 plaintext)") << std::endl;
    return finish(true);
}

bool CSeedAttestationKey::LoadOrGenerate(const std::string& dataDir, bool allowGenerate,
                                         bool allowPlaintext) {
    SeedKeyLoadStatus ignored = SeedKeyLoadStatus::OK;
    return LoadOrGenerate(dataDir, allowGenerate, allowPlaintext, &ignored);
}

bool CSeedAttestationKey::LoadOrGenerate(const std::string& dataDir, bool allowGenerate,
                                         bool allowPlaintext, SeedKeyLoadStatus* status) {
    SeedKeyLoadStatus localStatus = SeedKeyLoadStatus::OK;
    if (!status) status = &localStatus;
    *status = SeedKeyLoadStatus::OK;

    SeedKeyLoadStatus loadStatus = LoadClassified(dataDir);

    if (loadStatus == SeedKeyLoadStatus::OK) {
        // LP-13 CL-1 (MIGRATION, default-on encryption): an existing v1 plaintext
        // key still LOADS so a rolling upgrade never bricks a live seed. But the
        // default is now mandatory encryption-at-rest, so we MIGRATE it in place:
        // if a passphrase is available we re-save the already-loaded key as v2
        // encrypted. The re-save is the audited atomic temp+rename — the original
        // v1 file stays byte-intact until the encrypted write is confirmed (no
        // window in which the only copy is lost). The in-memory private key is
        // unchanged, so a failed migration re-save is non-fatal: we keep running
        // on the loaded key and warn (the operator can retry). Only when plaintext
        // is NOT explicitly allowed AND we cannot encrypt (no passphrase) do we
        // refuse, because that operator demanded encryption-by-default but gave us
        // no way to provide it.
        if (LoadedPlaintext()) {
            std::string passphrase = GetSeedKeyPassphrase();
            if (!passphrase.empty()) {
                memory_cleanse(&passphrase[0], passphrase.size());
                std::cout << "[Attestation] Migrating plaintext (v1) seed key to encrypted"
                             " (v2) at rest..." << std::endl;
                if (Save(dataDir, /*allowPlaintext=*/false)) {
                    m_loadedV1Plaintext = false;  // now persisted as v2
                    std::cout << "[Attestation] Seed key migrated to v2 encrypted." << std::endl;
                } else {
                    // Save left the original v1 file byte-intact (atomic). The
                    // in-memory key is still valid; keep running and let the
                    // operator retry the migration. NOT fatal — failing here would
                    // brick a live seed over a transient disk error.
                    std::cerr << "[Attestation] WARNING: could not re-save the seed key"
                                 " encrypted (v2); continuing on the loaded key. The"
                                 " on-disk key remains UNENCRYPTED (v1) — investigate"
                                 " (data dir perms / disk) and re-provision to encrypt"
                                 " it at rest." << std::endl;
                }
                // *status stays OK either way: the node is running on a usable,
                // loaded key. A failed migration is non-fatal by design (MEDIUM-1).
            } else if (!allowPlaintext) {
                // Default-on encryption, but no passphrase to encrypt with and no
                // explicit opt-out: refuse rather than run on a plaintext key the
                // operator's policy says must be encrypted. This is a PERMANENT
                // config-policy state (re-running fails identically) => CORRUPT so
                // an actual seed treats it as fatal.
                std::cerr << "[Attestation] FATAL: on-disk seed key is UNENCRYPTED (v1) and "
                          << SEED_KEY_PASSPHRASE_ENV << " is unset, but encryption-at-rest is"
                             " mandatory by default. Provision the passphrase to migrate it to"
                             " v2 (recommended), or pass --allow-plaintext-seed-key to run on"
                             " the plaintext key." << std::endl;
                Clear();
                *status = SeedKeyLoadStatus::CORRUPT;
                return false;
            }
            // else: allowPlaintext && no passphrase => explicit legacy opt-out;
            // run on the v1 key unchanged.
        }
        return true;
    }

    // LP-13 (round-2 fold, transient-vs-permanent): a TRANSIENT read error (the
    // file is PRESENT but momentarily unreadable — EACCES/EBUSY/EIO/…) must NOT
    // trigger a mint and must NOT be reclassified as a permanent failure. Surface
    // it as TRANSIENT so the node warns-and-continues (non-attesting) instead of
    // crash-looping over a disk blip. We do NOT auto-mint over a present-but-
    // unreadable key (that would risk minting a SECOND key alongside a real one).
    if (loadStatus == SeedKeyLoadStatus::TRANSIENT) {
        std::cerr << "[Attestation] WARNING: seed attestation key present but could not be"
                     " read (transient error) at " << dataDir << "/" << SEED_KEY_FILENAME
                  << ". NOT minting a replacement; the node will continue NON-ATTESTING."
                     " Investigate disk/permissions and restart to attest again." << std::endl;
        *status = SeedKeyLoadStatus::TRANSIENT;
        return false;
    }

    // From here loadStatus is MISSING or CORRUPT (a permanent failure). A
    // missing/corrupt key file must NOT silently mint a fresh consensus signing
    // key on a production seed. Auto-mint is gated behind the explicit
    // --generate-seed-key operator flag (allowGenerate), and is only meaningful
    // for a genuinely MISSING key — a CORRUPT/present file is never overwritten
    // by an auto-mint (that would destroy a possibly-recoverable key).
    if (!allowGenerate || loadStatus == SeedKeyLoadStatus::CORRUPT) {
        std::cerr << "[Attestation] FATAL: no usable seed attestation key at "
                  << dataDir << "/" << SEED_KEY_FILENAME
                  << (loadStatus == SeedKeyLoadStatus::CORRUPT
                         ? " (file PRESENT but unreadable/corrupt/wrong-passphrase; NOT"
                           " auto-minting over a present key)."
                         : " and --generate-seed-key was NOT given.")
                  << " Refusing to mint a new consensus signing key. If this is a"
                     " first-time provision, restart with --generate-seed-key; if the"
                     " key was expected to exist, investigate (wrong data dir,"
                     " missing/encrypted file, or unset "
                  << SEED_KEY_PASSPHRASE_ENV << ")." << std::endl;
        *status = loadStatus;  // MISSING or CORRUPT
        return false;
    }

    std::cout << "[Attestation] No existing attestation key found, generating new keypair (--generate-seed-key)..." << std::endl;
    if (!Generate()) {
        std::cerr << "[Attestation] Failed to generate attestation keypair" << std::endl;
        *status = SeedKeyLoadStatus::CORRUPT;
        return false;
    }

    // LP-13 M-2: a freshly minted key that cannot be PERSISTED is worthless — on
    // the next restart the node would have a different (or no) key that does not
    // match chainparams. Do NOT run on a non-persisted ephemeral key: fail loud.
    // CL-1: a freshly minted key is saved under the default-on encryption policy
    // (Save refuses plaintext unless allowPlaintext was explicitly passed).
    if (!Save(dataDir, allowPlaintext)) {
        std::cerr << "[Attestation] FATAL: generated a new seed key but failed to save it"
                     " to disk. Refusing to run on a non-persisted (ephemeral) consensus"
                     " signing key — fix the data dir / perms / passphrase and retry."
                  << std::endl;
        Clear();
        *status = SeedKeyLoadStatus::CORRUPT;
        return false;
    }

    std::cout << "[Attestation] Generated new seed attestation key: " << GetPubKeyHex().substr(0, 16) << "..." << std::endl;
    return true;
}

bool CSeedAttestationKey::Sign(const std::vector<uint8_t>& message,
                                std::vector<uint8_t>& signature) const {
    if (!IsValid() || m_privkey.empty()) return false;

    signature.resize(DFMP::MIK_SIGNATURE_SIZE);
    size_t siglen = 0;

    int result = pqcrystals_dilithium3_ref_signature(
        signature.data(), &siglen,
        message.data(), message.size(),
        nullptr, 0,
        m_privkey.data()
    );

    if (result != 0 || siglen != DFMP::MIK_SIGNATURE_SIZE) {
        signature.clear();
        return false;
    }
    return true;
}

bool CSeedAttestationKey::IsValid() const {
    return m_pubkey.size() == DFMP::MIK_PUBKEY_SIZE;
}

std::string CSeedAttestationKey::GetPubKeyHex() const {
    return HexStr(m_pubkey);
}

// ============================================================================
// MESSAGE BUILDING
// ============================================================================

std::vector<uint8_t> BuildAttestationMessage(
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    uint32_t timestamp,
    uint8_t seedId)
{
    // Build: "DILV_ATTEST" || mikPubkey || dnaHash || timestamp_le32 || seedId
    std::vector<uint8_t> preimage;
    preimage.reserve(ATTESTATION_DOMAIN_LEN + mikPubkey.size() + 32 + 4 + 1);

    // Domain separator
    preimage.insert(preimage.end(),
        reinterpret_cast<const uint8_t*>(ATTESTATION_DOMAIN),
        reinterpret_cast<const uint8_t*>(ATTESTATION_DOMAIN) + ATTESTATION_DOMAIN_LEN);

    // MIK pubkey
    preimage.insert(preimage.end(), mikPubkey.begin(), mikPubkey.end());

    // DNA hash
    preimage.insert(preimage.end(), dnaHash.begin(), dnaHash.end());

    // Timestamp (little-endian)
    preimage.push_back(static_cast<uint8_t>(timestamp & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 8) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 16) & 0xFF));
    preimage.push_back(static_cast<uint8_t>((timestamp >> 24) & 0xFF));

    // Seed ID
    preimage.push_back(seedId);

    // Hash to 32 bytes
    std::vector<uint8_t> hash(32);
    SHA3_256(preimage.data(), preimage.size(), hash.data());
    return hash;
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

bool VerifyAttestation(
    const CAttestation& attestation,
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    const std::vector<uint8_t>& seedPubkey)
{
    if (!attestation.IsValid()) return false;
    if (seedPubkey.size() != DFMP::MIK_PUBKEY_SIZE) return false;

    // Reconstruct the signed message
    std::vector<uint8_t> message = BuildAttestationMessage(
        mikPubkey, dnaHash, attestation.timestamp, attestation.seedId);

    // Verify Dilithium3 signature
    int result = pqcrystals_dilithium3_ref_verify(
        attestation.signature.data(), attestation.signature.size(),
        message.data(), message.size(),
        nullptr, 0,
        seedPubkey.data()
    );

    return (result == 0);
}

bool VerifyAttestationSet(
    const CAttestationSet& attestations,
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    const std::vector<std::vector<uint8_t>>& seedPubkeys,
    int64_t blockTimestamp,
    std::string& error)
{
    if (seedPubkeys.size() != NUM_SEEDS) {
        error = "Invalid seed pubkey count";
        return false;
    }

    int validCount = 0;
    bool usedSeed[NUM_SEEDS] = {};  // Track which seeds have been used (no duplicates)

    for (size_t idx = 0; idx < attestations.attestations.size(); idx++) {
        const auto& att = attestations.attestations[idx];
        if (att.seedId >= NUM_SEEDS) {
            std::cerr << "  [Attest] #" << idx << ": seedId=" << (int)att.seedId << " SKIP (invalid id)" << std::endl;
            continue;
        }

        if (usedSeed[att.seedId]) {
            std::cerr << "  [Attest] #" << idx << ": seedId=" << (int)att.seedId << " SKIP (duplicate)" << std::endl;
            continue;
        }

        // Check freshness: attestation timestamp within validity window of block timestamp
        int64_t timeDiff = blockTimestamp - static_cast<int64_t>(att.timestamp);
        if (timeDiff < 0 || timeDiff > ATTESTATION_VALIDITY_WINDOW) {
            std::cerr << "  [Attest] #" << idx << ": seedId=" << (int)att.seedId
                      << " SKIP (stale: diff=" << timeDiff << "s, window=" << ATTESTATION_VALIDITY_WINDOW << ")" << std::endl;
            continue;
        }

        // Verify signature
        bool sigOk = VerifyAttestation(att, mikPubkey, dnaHash, seedPubkeys[att.seedId]);
        if (sigOk) {
            usedSeed[att.seedId] = true;
            validCount++;
        } else {
            std::cerr << "  [Attest] #" << idx << ": seedId=" << (int)att.seedId
                      << " FAILED signature (sigSize=" << att.signature.size()
                      << ", keySize=" << seedPubkeys[att.seedId].size() << ")" << std::endl;
        }
    }

    if (validCount < MIN_ATTESTATIONS) {
        error = "Insufficient valid attestations: " + std::to_string(validCount) +
                " of " + std::to_string(MIN_ATTESTATIONS) + " required"
                + " (checked " + std::to_string(attestations.attestations.size()) + " entries)";
        return false;
    }

    return true;
}

// ============================================================================
// SERIALIZATION
// ============================================================================

bool BuildAttestationScriptData(
    const CAttestationSet& attestations,
    std::vector<uint8_t>& data)
{
    if (attestations.attestations.empty()) return false;
    if (attestations.attestations.size() > 255) return false;  // Count fits in 1 byte

    // Marker
    data.push_back(ATTESTATION_MARKER);

    // Count
    data.push_back(static_cast<uint8_t>(attestations.attestations.size()));

    // Each attestation entry
    for (const auto& att : attestations.attestations) {
        if (!att.IsValid()) return false;

        // Seed ID
        data.push_back(att.seedId);

        // Timestamp (little-endian)
        data.push_back(static_cast<uint8_t>(att.timestamp & 0xFF));
        data.push_back(static_cast<uint8_t>((att.timestamp >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>((att.timestamp >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((att.timestamp >> 24) & 0xFF));

        // Signature
        data.insert(data.end(), att.signature.begin(), att.signature.end());
    }

    return true;
}

bool ParseAttestationScriptData(
    const uint8_t* data,
    size_t dataLen,
    CAttestationSet& attestations,
    size_t& consumed)
{
    consumed = 0;
    attestations.attestations.clear();

    if (dataLen < 2) return false;  // Need at least marker + count

    // Verify marker
    if (data[0] != ATTESTATION_MARKER) return false;

    uint8_t count = data[1];
    size_t expectedSize = 2 + (count * ATTESTATION_ENTRY_SIZE);
    if (dataLen < expectedSize) return false;

    size_t offset = 2;
    for (uint8_t i = 0; i < count; i++) {
        CAttestation att;

        // Seed ID
        att.seedId = data[offset++];

        // Timestamp (little-endian)
        att.timestamp = static_cast<uint32_t>(data[offset]) |
                       (static_cast<uint32_t>(data[offset + 1]) << 8) |
                       (static_cast<uint32_t>(data[offset + 2]) << 16) |
                       (static_cast<uint32_t>(data[offset + 3]) << 24);
        offset += 4;

        // Signature
        att.signature.assign(data + offset, data + offset + DFMP::MIK_SIGNATURE_SIZE);
        offset += DFMP::MIK_SIGNATURE_SIZE;

        attestations.attestations.push_back(std::move(att));
    }

    consumed = offset;
    return true;
}

// ============================================================================
// RPC HELPERS — Request attestation from seed nodes
// ============================================================================

// Simple synchronous HTTP POST for JSON-RPC (no external dependencies)
static bool HttpJsonRpcCall(
    const std::string& host,
    uint16_t port,
    const std::string& jsonBody,
    std::string& response,
    std::string& error,
    int timeoutSec = 10)
{
    // Create socket
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        error = "Failed to create socket";
        return false;
    }
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        error = "Failed to create socket";
        return false;
    }
#endif

    // Set timeout
#ifdef _WIN32
    // Windows SO_RCVTIMEO/SO_SNDTIMEO expects DWORD in milliseconds, not struct timeval
    DWORD timeout_ms = timeoutSec * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = timeoutSec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif

    // Resolve and connect
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        error = "Invalid IP address: " + host;
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        error = "Connection failed to " + host + ":" + std::to_string(port);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    // Build HTTP request with auth header (rpc:rpc)
    std::string httpRequest =
        "POST / HTTP/1.1\r\n"
        "Host: " + host + ":" + std::to_string(port) + "\r\n"
        "Content-Type: application/json\r\n"
        "X-Dilithion-RPC: 1\r\n"
        "Authorization: Basic cnBjOnJwYw==\r\n"  // base64("rpc:rpc")
        "Content-Length: " + std::to_string(jsonBody.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" + jsonBody;

    // Send
    int sent = send(sock, httpRequest.c_str(), static_cast<int>(httpRequest.size()), 0);
    if (sent <= 0) {
        error = "Failed to send request";
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    // Receive response
    response.clear();
    char buf[4096];
    int received;
    while ((received = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[received] = '\0';
        response += buf;
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    if (response.empty()) {
        error = "Empty response from " + host;
        return false;
    }

    // Strip HTTP headers — find the JSON body after \r\n\r\n
    size_t bodyStart = response.find("\r\n\r\n");
    if (bodyStart != std::string::npos) {
        response = response.substr(bodyStart + 4);
    }

    return true;
}

// Simple JSON string value extractor (avoid external JSON library dependency)
static std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    pos += searchKey.size();
    size_t endPos = json.find("\"", pos);
    if (endPos == std::string::npos) return "";
    return json.substr(pos, endPos - pos);
}

static std::string ExtractJsonNumber(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    pos += searchKey.size();
    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    size_t endPos = pos;
    while (endPos < json.size() && (json[endPos] >= '0' && json[endPos] <= '9')) endPos++;
    if (endPos == pos) return "";
    return json.substr(pos, endPos - pos);
}

bool RequestAttestation(
    const std::string& seedIP,
    uint16_t rpcPort,
    const std::string& mikPubkeyHex,
    const std::string& dnaHashHex,
    CAttestation& attestation,
    std::string& error)
{
    // Build JSON-RPC request
    std::string jsonBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getmikattestation\","
                           "\"params\":{\"mik_pubkey\":\"" + mikPubkeyHex + "\","
                           "\"dna_hash\":\"" + dnaHashHex + "\"}}";

    std::string response;
    if (!HttpJsonRpcCall(seedIP, rpcPort, jsonBody, response, error)) {
        return false;
    }

    // Check for error in response
    if (response.find("\"error\"") != std::string::npos &&
        response.find("\"error\":null") == std::string::npos) {
        // Extract error message
        std::string errMsg = ExtractJsonString(response, "message");
        if (!errMsg.empty()) {
            error = "Seed " + seedIP + ": " + errMsg;
        } else {
            error = "Seed " + seedIP + " returned error: " + response.substr(0, 200);
        }
        return false;
    }

    // Extract result fields
    std::string seedIdStr = ExtractJsonNumber(response, "seed_id");
    std::string timestampStr = ExtractJsonNumber(response, "timestamp");
    std::string signatureHex = ExtractJsonString(response, "signature");

    if (seedIdStr.empty() || timestampStr.empty() || signatureHex.empty()) {
        error = "Missing fields in attestation response from " + seedIP;
        return false;
    }

    attestation.seedId = static_cast<uint8_t>(std::stoi(seedIdStr));
    attestation.timestamp = static_cast<uint32_t>(std::stoul(timestampStr));
    attestation.signature = ParseHex(signatureHex);

    if (attestation.signature.size() != DFMP::MIK_SIGNATURE_SIZE) {
        error = "Invalid signature size from " + seedIP + ": " +
                std::to_string(attestation.signature.size());
        attestation.signature.clear();
        return false;
    }

    return true;
}

bool CollectAttestations(
    const std::vector<std::string>& seedIPs,
    uint16_t rpcPort,
    const std::string& mikPubkeyHex,
    const std::string& dnaHashHex,
    CAttestationSet& attestations,
    std::string& error)
{
    attestations.attestations.clear();
    int failures = 0;

    for (size_t i = 0; i < seedIPs.size(); i++) {
        std::cout << "  [Attestation] Requesting from seed " << i << " (" << seedIPs[i] << ")..." << std::flush;

        CAttestation att;
        std::string seedError;
        if (RequestAttestation(seedIPs[i], rpcPort, mikPubkeyHex, dnaHashHex, att, seedError)) {
            std::cout << " OK" << std::endl;
            attestations.attestations.push_back(std::move(att));

            if (attestations.HasMinimum()) {
                std::cout << "  [Attestation] Collected " << attestations.Count()
                          << " attestations (minimum " << MIN_ATTESTATIONS << " met)" << std::endl;
                return true;
            }
        } else {
            std::cout << " FAILED: " << seedError << std::endl;
            failures++;
        }
    }

    if (!attestations.HasMinimum()) {
        error = "Only " + std::to_string(attestations.Count()) + " of " +
                std::to_string(MIN_ATTESTATIONS) + " required attestations collected (" +
                std::to_string(failures) + " seeds failed)";
        return false;
    }

    return true;
}

} // namespace Attestation
