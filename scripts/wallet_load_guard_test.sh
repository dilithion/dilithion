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
#   1. the node refuses to start, with EXACTLY the contracted exit code (1) —
#      not merely "non-zero", which also matches an abort
#   2. wallet.dat is byte-identical afterwards
#   3. a .unreadable-<timestamp> copy is written, matching the original bytes
#
# Both node binaries own a wallet and BOTH had the unguarded path — the DilV
# copy was missed on the first pass and caught by the evaluate overlay's
# "missing DilV branch" pattern hunt. Defaults to checking both.
#
# REQUIRES A PTY. The pty arm is the only arm that reaches the destructive path;
# without it every remaining assertion is satisfied by the pre-existing non-TTY
# guard alone, and the suite passes against a guard that has been deleted
# (demonstrated by mutation, see the pty block below). A platform with no pty
# helper is therefore a FAILURE, not a skip. Run it on Linux or in CI.
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

# The exit code the interactive refusal is CONTRACTED to produce. `return 1` from
# main(). Asserted exactly — see the arm below for why "any non-zero" was not enough.
EXPECTED_REFUSAL_RC=1

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

    # EXACT code, not "any non-zero". The previous "non-zero except 124/126/127"
    # rule scored an ABORT as a refusal: dilithion-node was terminating at static
    # destruction on a still-joinable RandomX init thread, so this arm exited 3
    # (MSVC runtime abort) / 134 (Linux SIGABRT) while printing the guard's "this
    # is a deliberate stop, not a crash" text. The suite said PASS for months.
    # Anything keying on exit 1 — this test, CI, a wrapper script, a user — was
    # reading a crash as a deliberate refusal. Pin the contract: exit 1.
    if [ "$RC" -eq 0 ]; then
        fail "node started despite an unreadable wallet (exit 0)"
    elif [ "$RC" -eq 126 ] || [ "$RC" -eq 127 ]; then
        fail "binary could not be executed (exit $RC) — test did not exercise the guard"
    elif [ "$RC" -eq 124 ]; then
        fail "node hung until the timeout (exit 124) — it neither started nor refused"
    elif [ "$RC" -eq "$EXPECTED_REFUSAL_RC" ]; then
        pass "node refused to start with the intended exit code ($RC)"
    else
        fail "node exited $RC, expected exactly $EXPECTED_REFUSAL_RC — non-zero is not enough; 3/134 mean the process ABORTED (std::terminate) rather than returning the refusal code"
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
    # $NOPEER here too — this arm leaves a node RUNNING, so without it the test
    # dials the production seed list from a CI runner. -k for the same reason.
    timeout -k 15 60 "$NODE" --datadir="$R" --relay-only $NOPEER < /dev/null > "$R/node.log" 2>&1
    R_RC=$?
    R_AFTER=$(sha256sum "$R/wallet.dat" 2>/dev/null | awk '{print $1}')
    if [ "$R_BEFORE" = "$R_AFTER" ]; then
        pass "relay-only: wallet.dat is byte-identical"
    else
        fail "relay-only: wallet.dat was modified (rc=$R_RC)"
    fi
    # Relay-only must CONTINUE past an unreadable wallet rather than aborting
    # on it — seed nodes run this way and must not fail fleet-wide on a rolling
    # deploy. Assert that it got past wallet init, NOT that the process
    # survived: a node can legitimately abort later for reasons that have
    # nothing to do with us (e.g. the seed attestation key being plaintext
    # without DILITHION_SEED_KEY_PASSPHRASE aborts startup, and does so
    # identically with no wallet.dat present at all — verified). Keying on the
    # exit code made this arm fail on any host in that state, which is a test
    # bug, not a guard bug.
    if grep -qE "P2P networking started|chain notification callbacks registered" "$R/node.log"; then
        pass "relay-only: continued past wallet init (did not abort on the wallet)"
    else
        fail "relay-only: never got past wallet init (rc=$R_RC) — it aborted on the wallet"
    fi
    if grep -q "Refusing to start" "$R/node.log"; then
        fail "relay-only: node printed the interactive refusal — wrong branch taken"
    else
        pass "relay-only: took the continue-with-warning branch, not the refusal"
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
    M_BEFORE=$(sha256sum "$M/wallet.dat" | awk '{print $1}')
    timeout -k 15 90 "$NODE" --datadir="$M" $NOPEER \
        --restore-mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" \
        < /dev/null > "$M/node.log" 2>&1
    if grep -qi "could not be loaded" "$M/node.log" && \
       grep -qiE "recovery phrase|restor" "$M/node.log" && \
       ! grep -qi "Refusing to start" "$M/node.log"; then
        pass "restore: --restore-mnemonic gets past the guard (advertised remedy works)"
    else
        fail "restore: guard blocked --restore-mnemonic, its own printed remedy"
    fi
    # This is the ONE arm where wallet.dat may legitimately be replaced, so the
    # preserved copy is the only remaining record. Checking that a file merely
    # EXISTS is not enough — verify its bytes are the original wallet.
    M_BACKUP=$(ls "$M"/wallet.dat.unreadable-* 2>/dev/null | head -1)
    if [ -n "$M_BACKUP" ]; then
        pass "restore: unreadable wallet preserved before restore proceeds"
        if [ "$(sha256sum "$M_BACKUP" | awk '{print $1}')" = "$M_BEFORE" ]; then
            pass "restore: preserved copy holds the ORIGINAL wallet bytes"
        else
            fail "restore: preserved copy does not match the original wallet bytes"
        fi
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
        # Answers go on SCRIPT's stdin, never inside -c. A redirect inside the
        # -c string makes the child's fd 0 a regular file, isatty(0) is false,
        # and the PRE-EXISTING non-TTY guard fires instead of the create path —
        # which made the previous version of this arm pass with the guard
        # deleted. Several lines, because the create flow prompts more than
        # once and dilithion-node.cpp's confirm loop has no EOF guard: running
        # out of input there spins rather than exiting.
        # DELIBERATELY TWO RUNS. One run cannot prove both things. On a GUARDED
        # binary the refusal happens BEFORE the wallet menu prints, so demanding
        # "we reached the menu" as proof the pty was live condemns the CORRECT
        # binary — CI goes red on good code. On an UNGUARDED binary the UPnP
        # [Y/n] prompt (~250 lines earlier) swallows the first answer, the menu
        # rejects the rest, the run blocks to the timeout without reaching
        # Save(), and the byte check then reports "destructive path blocked" on
        # a binary with no guard at all. Inverted in both directions.
        # So: prove the pty works where the menu is legitimately reachable,
        # then check the guard where the menu must NOT be reached.
        # Answers start with 'n' for the UPnP prompt; without it every
        # subsequent answer is off by one.

        # (i) LIVENESS CONTROL — clean datadir, no wallet. The menu SHOULD
        #     appear. If it does not, the pty machinery is broken and part (ii)
        #     proves nothing, so fail loudly instead of letting (ii) pass for
        #     the wrong reason.
        L="$WORK/$(basename "$NODE").ptylive"
        mkdir -p "$L"
        printf 'n\n' > "$L/answers"
        timeout -k 15 90 script -q -c "'$NODE' --datadir='$L' $NOPEER" /dev/null \
            < "$L/answers" > "$L/node.log" 2>&1 || true
        # Match the menu text ONLY, case-sensitively: matching "wallet setup"
        # case-insensitively also matches the non-TTY guard's own refusal
        # ("Wallet setup requires an interactive terminal"), which would score
        # a DEAD pty as live.
        if grep -q "CREATE a new wallet" "$L/node.log"; then
            pass "pty: menu reached on a clean datadir (pty is real, isatty passed)"
            PTY_LIVE=1
        else
            fail "pty: menu never appeared even with NO wallet — pty setup broken, guard arm below would prove nothing"
            PTY_LIVE=0
        fi

        # (ii) GUARD CHECK — same pty, corrupt wallet. The guard must refuse
        #      BEFORE the menu; an unguarded binary reaches the menu here.
        if [ "$PTY_LIVE" -eq 1 ]; then
            P_BEFORE=$(sha256sum "$P/wallet.dat" | awk '{print $1}')
            printf 'n\n1\n' > "$P/answers"
            timeout -k 15 120 script -q -c "'$NODE' --datadir='$P' $NOPEER" /dev/null \
                < "$P/answers" > "$P/node.log" 2>&1 || true
            P_AFTER=$(sha256sum "$P/wallet.dat" 2>/dev/null | awk '{print $1}')
            if grep -q "CREATE a new wallet" "$P/node.log"; then
                fail "pty: reached the create menu with an unreadable wallet — guard did not fire under a real tty"
            else
                pass "pty: guard fired before the create menu under a real tty"
            fi
            if [ "$P_BEFORE" = "$P_AFTER" ]; then
                pass "pty: wallet.dat is byte-identical after an interactive run"
            else
                fail "pty: wallet.dat was OVERWRITTEN via the interactive create path"
            fi
        fi
    else
        # NOT a skip. A skip here is indistinguishable from a pass, and that is
        # not a theory: mutation testing on MSYS deleted the guard's `return 1`
        # while keeping its message, and this suite reported 12/12 PASS, exit 0.
        # Every other arm runs without a TTY, where the PRE-EXISTING non-TTY guard
        # exits non-zero and leaves wallet.dat alone all by itself — so with the
        # pty arm gone, not one assertion in this file is sensitive to whether our
        # guard exists. `make wallet_load_guard_test` was reporting success against
        # a gutted guard on this project's primary dev platform.
        #
        # So: no pty, no verdict. Fail loudly and say what is missing. Run the
        # suite on Linux (or in the Linux CI job) to get a real answer; there is
        # deliberately no environment-variable escape hatch, because an escape
        # hatch is how a green-but-vacuous run comes back.
        fail "pty arm unavailable on this platform ($(uname -s 2>/dev/null || echo unknown)) — the destructive create-over-wallet.dat path is the ONLY thing this suite tests that a non-TTY run cannot fake, so a run without it proves nothing about the guard. Run on Linux/CI."
    fi

    # ========================================================================
    # INVERSE-FAILURE ARMS (F2)
    # ========================================================================
    # The arms above pin "an unreadable wallet is never overwritten". These pin
    # the opposite defect: the guard must not brick a node over a file that
    # provably holds no keys, or over a file it merely failed to OPEN.
    #
    # CWallet::Load() returns the same `false` for a 0-byte file, a file held by
    # an antivirus scanner, and a corrupt wallet. Treating all three as
    # corruption made the node exit 1 on EVERY start, forever, while telling the
    # user not to delete the blocking file — a permanent brick from a transient
    # cause, for users who never had a wallet at all.
    #
    # These arms key on LOG TEXT and FILE BYTES, not on exit codes. The exact
    # refusal exit code is a separate contract, asserted by the first arm above;
    # duplicating it here would couple these arms to the RandomX shutdown fix
    # (PR #154) that makes the code reliably 1 rather than an abort.
    # Distinct ports for every arm below. The arms above all use the default
    # 8332/8444, and the relay-only arm deliberately leaves a node RUNNING for
    # up to 60s — so a later arm that binds the same ports can exit 1 before it
    # ever reaches wallet init, which looks exactly like a guard verdict. (Seen
    # once on Windows: the first arm exited 1 with no wallet output at all.)
    # Nothing here shares a port with anything else.
    PORTS_E="--rpcport=18901 --port=18911"
    PORTS_S="--rpcport=18902 --port=18912"
    PORTS_T="--rpcport=18903 --port=18913"
    PORTS_F="--rpcport=18904 --port=18914"
    PORTS_K="--rpcport=18905 --port=18915"
    PORTS_EP="--rpcport=18906 --port=18916"
    PORTS_FP="--rpcport=18907 --port=18917"

    E="$WORK/$(basename "$NODE").empty"
    mkdir -p "$E"
    : > "$E/wallet.dat"        # exactly 0 bytes
    timeout -k 15 120 "$NODE" --datadir="$E" $NOPEER $PORTS_E < /dev/null > "$E/node.log" 2>&1
    if grep -qE "Refusing to start|could not be loaded|could not be OPENED" "$E/node.log"; then
        fail "empty: a 0-byte wallet.dat was treated as unreadable — node is bricked on every start"
    else
        pass "empty: 0-byte wallet.dat not treated as an unreadable wallet"
    fi
    # Positive proof it got all the way to wallet creation rather than stopping
    # somewhere earlier for an unrelated reason. Two accepted endings, because
    # both mean "the empty file is now equivalent to no file", which is the
    # property under test: on a real non-TTY stdin the creation path ends at the
    # interactive-terminal guard, while on MSYS `< /dev/null` still satisfies
    # isatty() so the run reaches the create MENU and stops one step later at
    # "stdin closed during wallet setup". Accepting only the first string would
    # make this arm fail on Windows against a correct binary.
    if grep -qE "Wallet setup requires an interactive terminal|CREATE a new wallet" "$E/node.log"; then
        pass "empty: reached wallet setup (0-byte file behaves like no wallet)"
    else
        fail "empty: never reached wallet setup — the empty file still blocked startup"
    fi
    if ls "$E"/wallet.dat.unreadable-* >/dev/null 2>&1; then
        fail "empty: preserved a copy of a 0-byte file — it holds nothing to preserve"
    else
        pass "empty: no pointless .unreadable- copy written for an empty file"
    fi

    # Sub-magic file: 4 bytes cannot hold the 8-byte magic, so no wallet format
    # this project ever wrote can be in there. Same treatment as 0 bytes.
    S="$WORK/$(basename "$NODE").short"
    mkdir -p "$S"
    printf 'DILW' > "$S/wallet.dat"
    timeout -k 15 120 "$NODE" --datadir="$S" $NOPEER $PORTS_S < /dev/null > "$S/node.log" 2>&1
    if grep -qE "Refusing to start|could not be loaded|could not be OPENED" "$S/node.log"; then
        fail "short: a 4-byte wallet.dat (below the magic) was treated as unreadable"
    else
        pass "short: sub-magic wallet.dat treated as no wallet present"
    fi

    # BOUND CHECK, the other direction. 12 bytes: enough for the magic, and the
    # magic is VALID, so this IS a wallet — a truncated one. It must still
    # refuse. This is what stops the empty-file relaxation above from being
    # widened into "anything short is fair game to overwrite".
    T="$WORK/$(basename "$NODE").trunc"
    mkdir -p "$T"
    printf 'DILWLT07\x01\x00\x00' > "$T/wallet.dat"
    T_BEFORE=$(sha256sum "$T/wallet.dat" | awk '{print $1}')
    timeout -k 15 120 "$NODE" --datadir="$T" $NOPEER $PORTS_T < /dev/null > "$T/node.log" 2>&1
    if grep -q "Refusing to start" "$T/node.log"; then
        pass "truncated: a short-but-valid-magic wallet still refuses"
    else
        fail "truncated: a truncated REAL wallet was not refused — the empty-file relaxation is too wide"
    fi
    if [ "$T_BEFORE" = "$(sha256sum "$T/wallet.dat" 2>/dev/null | awk '{print $1}')" ]; then
        pass "truncated: wallet.dat is byte-identical"
    else
        fail "truncated: wallet.dat was modified"
    fi

    # --- --force-new-wallet: the escape hatch the refusal advertises. It must
    # --- get past the guard AND preserve the original bytes, never overwrite
    # --- them silently.
    F="$WORK/$(basename "$NODE").force"
    mkdir -p "$F"
    printf 'NOT A VALID WALLET FILE - corrupt on purpose\x00\x01\x02\x03' > "$F/wallet.dat"
    F_BEFORE=$(sha256sum "$F/wallet.dat" | awk '{print $1}')
    timeout -k 15 120 "$NODE" --datadir="$F" $NOPEER $PORTS_F --force-new-wallet \
        < /dev/null > "$F/node.log" 2>&1
    if grep -q "force-new-wallet was given" "$F/node.log" && \
       ! grep -q "Refusing to start" "$F/node.log"; then
        pass "force: --force-new-wallet gets past the guard (advertised remedy works)"
    else
        fail "force: guard blocked --force-new-wallet, its own printed remedy"
    fi
    # Same positive-reach proof as the empty arm: getting past the guard is only
    # useful if it lands in wallet creation. See that arm for the two endings.
    if grep -qE "Wallet setup requires an interactive terminal|CREATE a new wallet" "$F/node.log"; then
        pass "force: reached wallet setup after the guard let it through"
    else
        fail "force: got past the guard but never reached wallet setup"
    fi
    F_BACKUP=$(ls "$F"/wallet.dat.unreadable-* 2>/dev/null | head -1)
    if [ -n "$F_BACKUP" ]; then
        pass "force: unreadable wallet preserved before proceeding"
        if [ "$(sha256sum "$F_BACKUP" | awk '{print $1}')" = "$F_BEFORE" ]; then
            pass "force: preserved copy holds the ORIGINAL wallet bytes"
        else
            fail "force: preserved copy does not match the original wallet bytes"
        fi
    else
        fail "force: proceeded without preserving the unreadable wallet"
    fi
    # The refusal must NAME the escape hatch. A route out that is not printed is
    # not a route out — the whole defect is a user reading "do not delete
    # wallet.dat" with nothing else to try.
    if grep -q -- "--force-new-wallet" "$D/node.log"; then
        pass "force: the refusal message names --force-new-wallet"
    else
        fail "force: the refusal never tells the user about --force-new-wallet"
    fi

    # --- transient OPEN failure: must be reported as a lock, not as corruption,
    # --- and must not claim the wallet is damaged.
    # chmod is meaningless for root (and for MSYS), so probe whether the mode
    # actually denied a read before asserting anything on it.
    K="$WORK/$(basename "$NODE").locked"
    mkdir -p "$K"
    printf 'NOT A VALID WALLET FILE - corrupt on purpose\x00\x01\x02\x03' > "$K/wallet.dat"
    chmod 000 "$K/wallet.dat" 2>/dev/null || true
    if head -c 1 "$K/wallet.dat" >/dev/null 2>&1; then
        echo "    [SKIP] lock arm — chmod 000 did not deny reads here (root, or a" >&2
        echo "           filesystem without POSIX modes). Not a verdict on the guard." >&2
    else
        timeout -k 15 120 "$NODE" --datadir="$K" $NOPEER $PORTS_K < /dev/null > "$K/node.log" 2>&1
        if grep -q "could not be OPENED" "$K/node.log"; then
            pass "locked: reported as an open failure, not as an unreadable wallet"
        else
            fail "locked: an unopenable wallet was not reported as a lock/permissions problem"
        fi
        if grep -q "destroy the keys in it" "$K/node.log"; then
            fail "locked: told the user their wallet may be corrupt when it was merely locked"
        else
            pass "locked: did not describe a locked file as corruption"
        fi
    fi
    chmod 644 "$K/wallet.dat" 2>/dev/null || true

    # --- pty coverage for the two non-refusing paths. Non-TTY runs can only
    # --- prove the node reached wallet setup; only a real tty proves it can
    # --- actually get to the create menu, which is what "not bricked" means to
    # --- a user. Detection duplicated from the arm above deliberately: sharing
    # --- a variable would mean editing that block, which PR #154 also edits.
    if command -v script >/dev/null 2>&1 \
       && ! uname -s 2>/dev/null | grep -qiE "mingw|msys|cygwin"; then
        EP="$WORK/$(basename "$NODE").emptypty"
        mkdir -p "$EP"
        : > "$EP/wallet.dat"
        printf 'n\n' > "$EP/answers"
        timeout -k 15 90 script -q -c "'$NODE' --datadir='$EP' $NOPEER $PORTS_EP" /dev/null \
            < "$EP/answers" > "$EP/node.log" 2>&1 || true
        if grep -q "CREATE a new wallet" "$EP/node.log"; then
            pass "pty/empty: create menu reached with a 0-byte wallet.dat (not bricked)"
        else
            fail "pty/empty: a 0-byte wallet.dat still blocked the create menu under a real tty"
        fi

        FP="$WORK/$(basename "$NODE").forcepty"
        mkdir -p "$FP"
        printf 'NOT A VALID WALLET FILE - corrupt on purpose\x00\x01\x02\x03' > "$FP/wallet.dat"
        FP_BEFORE=$(sha256sum "$FP/wallet.dat" | awk '{print $1}')
        printf 'n\n' > "$FP/answers"
        timeout -k 15 90 script -q -c "'$NODE' --datadir='$FP' $NOPEER $PORTS_FP --force-new-wallet" /dev/null \
            < "$FP/answers" > "$FP/node.log" 2>&1 || true
        if grep -q "CREATE a new wallet" "$FP/node.log"; then
            pass "pty/force: create menu reached with --force-new-wallet"
        else
            fail "pty/force: --force-new-wallet did not reach the create menu under a real tty"
        fi
        FP_BACKUP=$(ls "$FP"/wallet.dat.unreadable-* 2>/dev/null | head -1)
        if [ -n "$FP_BACKUP" ] && \
           [ "$(sha256sum "$FP_BACKUP" | awk '{print $1}')" = "$FP_BEFORE" ]; then
            pass "pty/force: original bytes preserved before the create menu was offered"
        else
            fail "pty/force: reached the create menu without a matching preserved copy"
        fi
    fi

    if [ "$FAILED" -ne 0 ]; then
        echo "--- $(basename "$NODE") interactive log ---" >&2
        tail -20 "$D/node.log" >&2
        echo "--- $(basename "$NODE") restore log ---" >&2
        tail -20 "$M/node.log" >&2
    fi
done

exit "$FAILED"
