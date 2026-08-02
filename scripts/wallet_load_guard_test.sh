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
# Both node binaries own a wallet and BOTH had the unguarded path — the DilV
# copy was missed on the first pass and caught by the evaluate overlay's
# "missing DilV branch" pattern hunt. Defaults to checking both.
#
# Usage: bash scripts/wallet_load_guard_test.sh [node-binary ...]
# ============================================================================
set -u

# Always hand back an explicitly-rooted path. A bare name passes bash's -x on
# MSYS (which resolves the .exe) but is then exec'd verbatim and fails with 127,
# which used to be scored as a PASS for "refused to start".
resolve_node() {
    case "$1" in
        /*|./*|../*) prefix="" ;;
        *)           prefix="./" ;;
    esac
    for cand in "${prefix}$1.exe" "${prefix}$1"; do
        if [ -x "$cand" ] && [ -f "$cand" ]; then echo "$cand"; return 0; fi
    done
    return 1
}

if [ "$#" -gt 0 ]; then
    REQUESTED=("$@")
else
    REQUESTED=(dilithion-node dilv-node)
fi

NODES=()
for want in "${REQUESTED[@]}"; do
    if resolved=$(resolve_node "$want"); then
        NODES+=("$resolved")
    else
        echo "FAIL: node binary not found or not executable: $want" >&2
        exit 1
    fi
done

FAILED=0
pass() { echo "    [PASS] $1"; }
fail() { echo "    [FAIL] $1"; FAILED=1; }

WORK="$(mktemp -d 2>/dev/null || echo /tmp/wallet_guard_$$)"
mkdir -p "$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

for NODE in "${NODES[@]}"; do
    echo "  --- $(basename "$NODE") ---"
    D="$WORK/$(basename "$NODE").datadir"
    mkdir -p "$D"

    # A wallet.dat that exists but cannot be parsed — stands in for the v4.5.0
    # empty-MAC v7 record that makes Load() reject an otherwise healthy wallet.
    printf 'NOT A VALID WALLET FILE - corrupt on purpose\x00\x01\x02\x03' > "$D/wallet.dat"

    BEFORE_SUM=$(sha256sum "$D/wallet.dat" | awk '{print $1}')

    # --connect to a dead local address: never peer with production seeds from
    # a CI runner. -k so a node ignoring SIGTERM cannot wedge the job forever.
    NOPEER="--connect=127.0.0.1:1"

    # stdin from /dev/null: never block on the interactive create/restore prompt.
    timeout -k 15 180 "$NODE" --datadir="$D" $NOPEER < /dev/null > "$D/node.log" 2>&1
    RC=$?

    AFTER_SUM=$(sha256sum "$D/wallet.dat" 2>/dev/null | awk '{print $1}')

    # 126/127 mean the binary could not be executed at all, and 124 is the
    # timeout firing. None of those are the node deciding to refuse, and
    # scoring them as a pass would make this whole test vacuous.
    if [ "$RC" -eq 0 ]; then
        fail "node started despite an unreadable wallet (exit 0)"
    elif [ "$RC" -eq 126 ] || [ "$RC" -eq 127 ]; then
        fail "binary could not be executed (exit $RC) — test did not exercise the guard"
    elif [ "$RC" -eq 124 ]; then
        fail "node hung until the timeout (exit 124) — it neither started nor refused"
    else
        pass "node refused to start (exit $RC)"
    fi

    if [ -n "$AFTER_SUM" ] && [ "$BEFORE_SUM" = "$AFTER_SUM" ]; then
        pass "wallet.dat is byte-identical (not overwritten)"
    else
        fail "wallet.dat was modified or removed (before=$BEFORE_SUM after=${AFTER_SUM:-MISSING})"
    fi

    # DISCRIMINATOR. Without this, deleting the entire refusal block while
    # keeping the PreserveUnreadableWallet() call still passes every other
    # assertion: with stdin not a TTY the PRE-EXISTING non-TTY guard already
    # exits non-zero and already leaves wallet.dat intact, so those arms say
    # nothing about whether our guard exists. Pin the refusal itself.
    if grep -q "Refusing to start" "$D/node.log"; then
        pass "node refused explicitly (guard fired, not the non-TTY fallback)"
    else
        fail "no refusal message — the guard did not fire; a non-TTY exit is not the same thing"
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

    # --- relay-only arm: must NOT abort (seed nodes run this way) but must
    # --- still leave the file untouched and preserve a copy.
    R="$WORK/$(basename "$NODE").relay"
    mkdir -p "$R"
    printf 'NOT A VALID WALLET FILE - corrupt on purpose\x00\x01\x02\x03' > "$R/wallet.dat"
    R_BEFORE=$(sha256sum "$R/wallet.dat" | awk '{print $1}')
    timeout 60 "$NODE" --datadir="$R" --relay-only < /dev/null > "$R/node.log" 2>&1
    R_RC=$?
    R_AFTER=$(sha256sum "$R/wallet.dat" 2>/dev/null | awk '{print $1}')
    if [ "$R_BEFORE" = "$R_AFTER" ]; then
        pass "relay-only: wallet.dat is byte-identical"
    else
        fail "relay-only: wallet.dat was modified (rc=$R_RC)"
    fi
    if ls "$R"/wallet.dat.unreadable-* >/dev/null 2>&1; then
        pass "relay-only: preserved copy written"
    else
        fail "relay-only: no preserved copy written"
    fi

    # --- restore arm: the guard PRINTS --restore-mnemonic as the remedy, so
    # --- that remedy must actually get past the guard. A wrong phrase is fine:
    # --- what is under test is that we reach mnemonic handling at all rather
    # --- than being refused by the guard before the restore branch is seen.
    M="$WORK/$(basename "$NODE").restore"
    mkdir -p "$M"
    printf 'NOT A VALID WALLET FILE - corrupt on purpose\x00\x01\x02\x03' > "$M/wallet.dat"
    timeout 90 "$NODE" --datadir="$M" \
        --restore-mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" \
        < /dev/null > "$M/node.log" 2>&1
    if grep -qi "could not be loaded" "$M/node.log" && \
       grep -qiE "recovery phrase|restor" "$M/node.log" && \
       ! grep -qi "Refusing to start" "$M/node.log"; then
        pass "restore: --restore-mnemonic gets past the guard (advertised remedy works)"
    else
        fail "restore: guard blocked --restore-mnemonic, its own printed remedy"
    fi
    if ls "$M"/wallet.dat.unreadable-* >/dev/null 2>&1; then
        pass "restore: unreadable wallet preserved before restore proceeds"
    else
        fail "restore: proceeded without preserving the unreadable wallet"
    fi

    # --- PTY arm: the ONLY arm that reaches the actually-destructive path.
    # --- Every other arm runs without a TTY, where the pre-existing non-TTY
    # --- guard stops the node before wallet creation, so none of them can
    # --- observe the overwrite this whole change exists to prevent. Under a
    # --- real pty the node reaches the CREATE/RESTORE prompt; answering "1"
    # --- on an UNGUARDED binary creates a wallet and Save()s it over
    # --- wallet.dat. Skipped where no pty helper exists (e.g. plain Windows).
    if command -v script >/dev/null 2>&1 && [ "$(uname -s 2>/dev/null)" != "" ] \
       && ! uname -s 2>/dev/null | grep -qiE "mingw|msys|cygwin"; then
        P="$WORK/$(basename "$NODE").pty"
        mkdir -p "$P"
        printf 'NOT A VALID WALLET FILE - corrupt on purpose\x00\x01\x02\x03' > "$P/wallet.dat"
        P_BEFORE=$(sha256sum "$P/wallet.dat" | awk '{print $1}')
        printf '1\n' > "$P/answers"
        # -q quiet, -c command, output discarded; feed "1" = CREATE new wallet.
        timeout -k 15 120 script -q -c \
            "'$NODE' --datadir='$P' $NOPEER < '$P/answers'" /dev/null \
            > "$P/node.log" 2>&1 || true
        P_AFTER=$(sha256sum "$P/wallet.dat" 2>/dev/null | awk '{print $1}')
        if [ "$P_BEFORE" = "$P_AFTER" ]; then
            pass "pty: wallet.dat survived an interactive CREATE (destructive path blocked)"
        else
            fail "pty: wallet.dat was OVERWRITTEN via the interactive create path"
        fi
    else
        echo "    [SKIP] pty arm (no usable pty helper on this platform) — the" >&2
        echo "           destructive path is NOT covered here; it is covered on Linux CI." >&2
    fi

    if [ "$FAILED" -ne 0 ]; then
        echo "--- $(basename "$NODE") interactive log ---" >&2
        tail -20 "$D/node.log" >&2
        echo "--- $(basename "$NODE") restore log ---" >&2
        tail -20 "$M/node.log" >&2
    fi
done

exit "$FAILED"
