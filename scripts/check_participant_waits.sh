#!/usr/bin/env bash
# ==============================================================================
# check_participant_waits.sh — an epoch participant must not BLOCK while ONLINE.
# ==============================================================================
#
# ⚠️ THIS GUARD EXISTS BECAUSE THE SAME DEFECT WAS FOUND FOUR TIMES BY HAND.
# An epoch scheme's entire bound is "every participating thread passes its
# checkpoint promptly". A thread that publishes an epoch and then BLOCKS freezes
# DrainGraveyard's minimum for the whole block: nothing unlinked meanwhile can be
# freed, and the node grows while behaving perfectly.
#
#   round 1  RPC server parked in accept()     47.60 MB / 15 s, 0 freed  (measured)
#   round 4  two paused validation threads     10 ms at a time, unbounded
#   round 7  idle headers processor      (F45) the state an idle node IS in
#   round 8  VDF miner in cooldown       (F46) TWO MINUTES, repeatedly, on miners
#
# Four rounds, four files, four humans noticing. The fifth should be a machine.
#
# ⚠️ AND WHAT HID F45/F46 WAS A COMMENT STATING A BOUND -- "Pin bound: one VDF
# round", written directly above eight waits totalling up to two minutes. A prose
# bound is not checkable and it actively stops the next reader looking. This is.
#
# ⚠️ POINTER-FREE IS NOT PIN-FREE: all four looked safe because the thread held
# nothing at the wait. A thread pins by its PUBLISHED EPOCH. That is precisely the
# reasoning error a reviewer makes and a checker does not.
#
# SCOPE: every file under src/ (excluding src/test/) that contains
# `EpochCheckpoint(` -- i.e. every file with a registered participant. In those
# files every blocking call must sit inside an EpochOfflineScope / EpochOnlineWindow,
# or carry, on one of the three lines above it:
#
#     // EPOCH-WAIT-EXEMPT: <why this thread cannot pin here>
#
# The reason is mandatory. The exemption is not an escape hatch; it is a demand
# that the argument be written down where the next reader will find it.
#
# Self-test:  scripts/check_participant_waits.sh --self-test

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AWK_PROG="$SCRIPT_DIR/check_participant_waits.awk"

if [ ! -f "$AWK_PROG" ]; then
    echo "===== participant-wait guard: FAIL (parser $AWK_PROG is MISSING) ====="
    exit 2
fi
if ! command -v awk >/dev/null 2>&1; then
    echo "===== participant-wait guard: FAIL (no awk on PATH) ====="
    exit 2
fi

scan() {   # $1 = dir
    local f rc=0 seen=0 list
    if ! list="$(find "$1" \( -name '*.cpp' -o -name '*.h' \) -type f 2>/dev/null | sort)"; then
        echo "PARSE $1 0 find failed"; return 2
    fi
    if [ -z "$list" ]; then echo "PARSE $1 0 find matched no sources"; return 2; fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        case "$f" in */test/*) continue ;; esac
        seen=$((seen + 1))
        if ! awk -f "$AWK_PROG" "$f"; then
            echo "PARSE $f 0 awk exited non-zero"; rc=2
        fi
    done <<EOF
$list
EOF
    [ "$seen" -eq 0 ] && { echo "PARSE $1 0 no sources scanned"; return 2; }
    return $rc
}

if [ "${1:-}" = "--self-test" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT INT TERM
    mkdir -p "$tmp/src"

    # BAD: a participant blocking with no scope — the F45/F46 shape
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  cv.wait_for(lk, t, p);\n}\n' > "$tmp/src/b1.cpp"
    # BAD: the scope CLOSED before the call — the exact case a line-window
    # heuristic accepts and brace tracking rejects
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  { EpochOfflineScope o(&g_chainstate); }\n  cv.wait(lk);\n}\n' > "$tmp/src/b2.cpp"
    # BAD: an EXEMPT marker with no reason is not an exemption
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  // EPOCH-WAIT-EXEMPT:\n  cv.wait(lk);\n}\n' > "$tmp/src/b3.cpp"
    # OK: properly scoped
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  { EpochOfflineScope o(&g_chainstate);\n    cv.wait(lk); }\n}\n' > "$tmp/src/g1.cpp"
    # OK: exempt WITH a reason
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  // EPOCH-WAIT-EXEMPT: shutdown only, no epoch published\n  cv.wait(lk);\n}\n' > "$tmp/src/g2.cpp"
    # OK: NOT a participant — no checkpoint, so not in scope at all
    printf 'void f(){ cv.wait(lk); }\n' > "$tmp/src/g3.cpp"

    # ── round-8 F49: six ways to satisfy the guard WITHOUT the property ──────
    # (a) a marker three lines up exempts a call added into the window later
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  // EPOCH-WAIT-EXEMPT: an older reason, about a different call\n  int filler = 0; (void)filler;\n  cv.wait(lk);\n}\n' > "$tmp/src/b4.cpp"
    # (b) braceless: the scope dies at the semicolon, the next call is NOT covered
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  if (x) EpochOfflineScope o(&cs);\n  cv.wait(lk);\n}\n' > "$tmp/src/b5.cpp"
    # (c) an ONLINE WINDOW is not an offline scope -- its body is ONLINE
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  { EpochOnlineWindow w(&cs);\n    cv.wait(lk); }\n}\n' > "$tmp/src/b6.cpp"
    # (d) an online window NESTED in an offline scope masks it
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  { EpochOfflineScope o(&cs);\n    { EpochOnlineWindow w(&cs);\n      cv.wait(lk); } }\n}\n' > "$tmp/src/b7.cpp"
    # (e) only the FIRST call on a line was checked; the second hid
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  { EpochOfflineScope o(&cs); cv.wait(lk); } cv.wait(lk2);\n}\n' > "$tmp/src/b8.cpp"
    # (f) taxonomy: join() on the node main is a blocking call too
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  t.join();\n}\n' > "$tmp/src/b9.cpp"
    # (f) taxonomy: arrow-form wait
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  p->wait(lk);\n}\n' > "$tmp/src/b10.cpp"

    # OK: the marker on the IMMEDIATELY preceding line still works
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  // EPOCH-WAIT-EXEMPT: shutdown only\n  cv.wait(lk);\n}\n' > "$tmp/src/g4.cpp"
    # OK: a marker further up that NAMES the call it excuses
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  // EPOCH-WAIT-EXEMPT: the join below is shutdown-only\n  int filler = 0; (void)filler;\n  t.join();\n}\n' > "$tmp/src/g5.cpp"
    # OK: an offline scope OUTSIDE an online window covers a call after it
    printf 'void f(){ g_chainstate.EpochCheckpoint("x");\n  { EpochOfflineScope o(&cs);\n    { EpochOnlineWindow w(&cs); }\n    cv.wait(lk); }\n}\n' > "$tmp/src/g6.cpp"

    fails=0
    for f in b1 b2 b3 b4 b5 b6 b7 b8 b9 b10; do
        if awk -f "$AWK_PROG" "$tmp/src/$f.cpp" 2>&1 | grep -q '^BAD'; then
            echo "  PASS  reject $f"
        else
            echo "  FAIL  reject $f: an ONLINE blocking call was not flagged"; fails=$((fails+1))
        fi
    done
    for f in g1 g2 g4 g5 g6; do
        if awk -f "$AWK_PROG" "$tmp/src/$f.cpp" 2>&1 | grep -qE '^(OK|EXEMPT)'; then
            echo "  PASS  accept $f"
        else
            echo "  FAIL  accept $f: a correctly handled call was flagged"; fails=$((fails+1))
        fi
    done
    if [ -z "$(awk -f "$AWK_PROG" "$tmp/src/g3.cpp" 2>&1)" ]; then
        echo "  PASS  accept g3 (a non-participant file is out of scope)"
    else
        echo "  FAIL  accept g3: a non-participant file was scanned"; fails=$((fails+1))
    fi

    echo
    if [ "$fails" -ne 0 ]; then
        echo "===== participant-wait guard SELF-TEST: FAIL ($fails) ====="; exit 1
    fi
    echo "===== participant-wait guard SELF-TEST: PASS (10 rejected, 6 accepted) ====="
    exit 0
fi

cd "$ROOT" || exit 2

verdicts="$(scan src)"; tool_rc=$?

bad=$(printf    '%s\n' "$verdicts" | grep -c '^BAD '    || true)
ok=$(printf     '%s\n' "$verdicts" | grep -c '^OK '     || true)
exempt=$(printf '%s\n' "$verdicts" | grep -c '^EXEMPT ' || true)
parse=$(printf  '%s\n' "$verdicts" | grep -c '^PARSE '  || true)

printf '%s\n' "$verdicts" | grep '^PARSE ' | while IFS= read -r l; do
    set -- $l
    echo "PARSE-FAIL  $2:$3  ${l#PARSE $2 $3 }"
done
printf '%s\n' "$verdicts" | grep '^BAD ' | while IFS= read -r l; do
    set -- $l
    echo "FAIL  $2:$3"
    echo "        \`$4\` blocks with this thread ONLINE."
    echo "        This file registers an epoch participant, so the thread has an"
    echo "        epoch published, and DrainGraveyard's minimum is frozen at it for"
    echo "        the whole of this call. Wrap the call (only the call) in an"
    echo "        EpochOfflineScope, or add above it:"
    echo "            // EPOCH-WAIT-EXEMPT: <why this thread cannot pin here>"
done

echo
echo "participant blocking calls: $ok scoped, $exempt exempt, $bad ONLINE, $parse unparsable"

# ⚠️ The population is PRINTED, not just counted. A guard whose scan silently
# narrows reports a smaller clean number and looks better while checking less.
# ⚠️ THE INPUT SET IS PRINTED, AND SO IS WHAT IS NOT IN IT (round-8 F51). The send
# accounting did not reconcile across three artifacts -- "18 sends" in one comment,
# "4 markers" in another, "five sites by hand" in a commit message -- because each
# counted a different population and none said which. The guard now states its own:
echo "input set: src/**/*.{cpp,h}, EXCLUDING src/test/; within that, only files"
echo "           containing EpochCheckpoint( ; within those, only the checkpointing"
echo "           function and ONE HOP of its callees."
echo "⚠️ NOT in the input set, and therefore NOT certified by this PASS:"
echo "           * blocking calls two or more frames below a checkpointing function"
echo "           * blocking calls in another translation unit"
echo "           * src/test/ (tests are not a node)"
echo "           * any participant file the parser could not read (reported as PARSE"
echo "             above; there are $parse of those)"
echo "participant files scanned:"
printf '%s\n' "$verdicts" | awk '{print "        " $2}' | sort -u

if [ "$tool_rc" -ne 0 ]; then
    echo "===== participant-wait guard: FAIL (a tool failed; status $tool_rc) ====="; exit 2
fi
if [ "$parse" -ne 0 ] || [ "$bad" -ne 0 ]; then
    echo "===== participant-wait guard: FAIL ($bad online, $parse unparsable) ====="; exit 1
fi
echo "===== participant-wait guard: PASS ($ok scoped, $exempt exempt) ====="
exit 0
