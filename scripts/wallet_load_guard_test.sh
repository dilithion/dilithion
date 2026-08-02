#!/bin/bash
# ============================================================================
# Regression: an UNREADABLE wallet.dat must never be overwritten.
#
# Before the guard this test pins, a failed CWallet::Load() only warned
# ("Failed to load wallet, creating new one") and fell through to the ordinary
# creation path. Creation ends in Save(wallet_path), whose SaveUnlocked does
# temp-write + fsync + atomic rename OVER the user's wallet.dat, keeping no
# copy — so the encrypted key material was destroyed and only a BIP39 phrase
# could recover the funds.
#
# That path was reachable in production: v4.5.0 shipped LP-7's rule that a v7
# record with an empty MAC invalidates the whole wallet, but NOT the fix
# (b34eb373) for the three store sites that wrote exactly such records. An
# encrypted HD wallet on v4.5.0 bricks as soon as it mints a receive or change
# address, and the affected user was then invited to overwrite it.
#
# This asserts the three properties that matter, against the real binary:
#   1. the node refuses to start (non-zero exit)
#   2. wallet.dat is byte-identical afterwards
#   3. a .unreadable-<timestamp> copy is written, matching the original bytes
#
# Usage: bash scripts/wallet_load_guard_test.sh [path-to-dilithion-node]
# ============================================================================
set -u

NODE="${1:-./dilithion-node.exe}"
[ -x "$NODE" ] || NODE="./dilithion-node"
if [ ! -x "$NODE" ]; then
    echo "FAIL: node binary not found or not executable: $NODE" >&2
    exit 1
fi

D="$(mktemp -d 2>/dev/null || echo /tmp/wallet_guard_$$)"
mkdir -p "$D"
cleanup() { rm -rf "$D"; }
trap cleanup EXIT

# A wallet.dat that exists but cannot be parsed — stands in for the v4.5.0
# empty-MAC v7 record that makes Load() reject an otherwise healthy wallet.
printf 'NOT A VALID WALLET FILE - corrupt on purpose\x00\x01\x02\x03' > "$D/wallet.dat"

BEFORE_SUM=$(sha256sum "$D/wallet.dat" | awk '{print $1}')

# stdin from /dev/null: never block on the interactive create/restore prompt.
timeout 180 "$NODE" --datadir="$D" < /dev/null > "$D/node.log" 2>&1
RC=$?

AFTER_SUM=$(sha256sum "$D/wallet.dat" 2>/dev/null | awk '{print $1}')

FAILED=0
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }

if [ "$RC" -ne 0 ]; then
    pass "node refused to start (exit $RC)"
else
    fail "node started despite an unreadable wallet (exit 0)"
fi

if [ -n "$AFTER_SUM" ] && [ "$BEFORE_SUM" = "$AFTER_SUM" ]; then
    pass "wallet.dat is byte-identical (not overwritten)"
else
    fail "wallet.dat was modified or removed (before=$BEFORE_SUM after=${AFTER_SUM:-MISSING})"
fi

BACKUP=$(ls "$D"/wallet.dat.unreadable-* 2>/dev/null | head -1)
if [ -n "$BACKUP" ]; then
    pass "preserved copy written: $(basename "$BACKUP")"
    if [ "$(sha256sum "$BACKUP" | awk '{print $1}')" = "$BEFORE_SUM" ]; then
        pass "preserved copy matches the original bytes"
    else
        fail "preserved copy does not match the original bytes"
    fi
else
    fail "no .unreadable-<timestamp> copy was written"
fi

if [ "$FAILED" -ne 0 ]; then
    echo "--- node log ---" >&2
    tail -30 "$D/node.log" >&2
    exit 1
fi
exit 0
