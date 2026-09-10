#!/usr/bin/env bash
# ==============================================================================
# check_thread_local_guard.sh — every `thread_local` in production code must be
# TRIVIALLY DESTRUCTIBLE, and must say so with a static_assert on ITS OWN TYPE
# that a compiler checks.
# ==============================================================================
#
# ⚠️ WHY THIS EXISTS. On the toolchain this project ships on (MSYS2 g++ /
# libwinpthread / libstdc++), `thread_local` is emutls: one malloc block per
# variable per thread, freed by the emutls pthread key -- whose destructor runs
# BEFORE the key libstdc++ uses to run C++ destructors. So EVERY thread_local
# destructor in the process runs on memory that has already been free()d.
# Measured with `--wrap=free`: 300/300 and 600/600, deterministic.
#
# Usually the freed block still holds the old bytes, which is why this cost days:
# the failure appears only when the block is re-issued in the microsecond window
# between the free and the destructor -- which happens when ANOTHER THREAD STARTS,
# because its first `__cxa_thread_atexit` allocates a 32-byte block in the same
# size class. On this codebase that produced (a) an accusation that was never
# withdrawn, so the startup gate refused a healthy node at ~5% of runs, and (b) an
# epoch slot pointer read as garbage, so `slot->store(~0)` wrote eight 0xFF bytes
# through a wild pointer into a live heap block.
#
# A comment cannot hold that line -- comments have no decay function. A
# static_assert does, and it fails at COMPILE time, in the file, on the line.
#
# THE RULE: state that needs to act at thread exit does NOT go in a thread_local.
# It goes in a heap record owned by a pthread key, whose destructor is HANDED the
# record as its argument (pthread key values live in the pthread TLS array, not in
# emutls). See EpochThreadRecord in src/consensus/chain.cpp for the worked example.
#
# There is NO allowlist. A thread_local that cannot satisfy the assert is a
# thread_local that must not exist.
#
# ⚠️ ROUND 6 FOUND THIS GUARD BYPASSABLE FIVE WAYS, AND THAT IS WHY THE PARSING
# LIVES IN AWK NOW. The first version matched lines with regexes:
#   * `(static|extern)? thread_local` missed `inline thread_local`,
#     `constexpr thread_local`, `static inline thread_local` and macro-wrapped
#     declarations -- NEVER COUNTED, so never required to assert anything;
#   * a declaration split across two lines was invisible for the same reason;
#   * the six-line window grepped the BARE STRING `is_trivially_destructible`,
#     so a COMMENT in the window satisfied the guard;
#   * as did a static_assert on a COMPLETELY DIFFERENT type.
# Each of those is now a NEGATIVE FIXTURE below that the guard must reject. A
# guard is only worth its exit code if you have watched it fail.
#
# Self-test:  scripts/check_thread_local_guard.sh --self-test

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AWK_PROG="$SCRIPT_DIR/check_thread_local_guard.awk"

# ⚠️ FAIL CLOSED ON A MISSING INSTRUMENT. A guard whose parser is absent must not
# report CLEAN -- that is how a check silently stops existing.
if [ ! -f "$AWK_PROG" ]; then
    echo "===== thread_local guard: FAIL (parser $AWK_PROG is MISSING) ====="
    exit 2
fi
if ! command -v awk >/dev/null 2>&1; then
    echo "===== thread_local guard: FAIL (no awk on PATH) ====="
    exit 2
fi

# The floor exists so a guard that suddenly sees nothing FAILS. Raise it when the
# tree legitimately gains declarations; never lower it to make a run pass.
MIN_CHECKED="${DIL_TLGUARD_MIN_CHECKED:-6}"

run_over() {   # $1 = directory to scan; prints the awk verdict lines
    local dir="$1" f
    while IFS= read -r f; do
        case "$f" in
            */test/*) continue ;;   # tests may declare their own; they are not a node
        esac
        awk -f "$AWK_PROG" "$f"
    done < <(find "$dir" \( -name '*.cpp' -o -name '*.h' \) -type f | sort)
}

# ---------------------------------------------------------------------------
# --self-test: the negative fixtures. Each is a form that BYPASSED the previous
# guard; each must now be REJECTED. Run in a temp dir, never in the tree.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT INT TERM
    mkdir -p "$tmp/src"

    # (1) inline specifier — previously not counted at all
    printf '#include <string>\ninline thread_local std::string a;\n' > "$tmp/src/f1.cpp"
    # (2) constexpr-adjacent / static inline combination
    printf '#include <string>\nstatic inline thread_local std::string b;\n' > "$tmp/src/f2.cpp"
    # (3) split across lines
    printf '#include <string>\nthread_local\n    std::string c;\n' > "$tmp/src/f3.cpp"
    # (4) a COMMENT in the window satisfied the old bare-string grep
    printf '#include <string>\nthread_local std::string d;\n// is_trivially_destructible: honest, promise\n' > "$tmp/src/f4.cpp"
    # (5) an assert on the WRONG type satisfied the old grep
    printf '#include <string>\n#include <type_traits>\nthread_local std::string e;\nstatic_assert(std::is_trivially_destructible<int>::value, "");\n' > "$tmp/src/f5.cpp"
    # (P) the POSITIVE fixture: a correct declaration must be accepted, or the
    #     guard is merely rejecting everything and proving nothing.
    printf '#include <type_traits>\nthread_local int* p = 0;\nstatic_assert(std::is_trivially_destructible<int*>::value, "");\n' > "$tmp/src/p1.cpp"

    fails=0
    for f in f1 f2 f3 f4 f5; do
        out="$(awk -f "$AWK_PROG" "$tmp/src/$f.cpp")"
        if echo "$out" | grep -qE '^(BAD|PARSE)'; then
            echo "  PASS  self-test $f: rejected as it must be"
        else
            echo "  FAIL  self-test $f: NOT REJECTED -- the bypass is still open"
            echo "        awk said: ${out:-<nothing>}"
            fails=$((fails + 1))
        fi
    done
    out="$(awk -f "$AWK_PROG" "$tmp/src/p1.cpp")"
    if echo "$out" | grep -q '^OK'; then
        echo "  PASS  self-test p1: a correct declaration is accepted"
    else
        echo "  FAIL  self-test p1: a CORRECT declaration was rejected -- the guard"
        echo "        rejects everything, which proves nothing. awk said: ${out:-<nothing>}"
        fails=$((fails + 1))
    fi

    echo
    if [ "$fails" -ne 0 ]; then
        echo "===== thread_local guard SELF-TEST: FAIL ($fails) ====="
        exit 1
    fi
    echo "===== thread_local guard SELF-TEST: PASS (5 bypasses rejected, 1 correct accepted) ====="
    exit 0
fi

cd "$ROOT" || exit 2

verdicts="$(run_over src)"

parse=$(printf '%s\n' "$verdicts" | grep -c '^PARSE ' || true)
bad=$(printf   '%s\n' "$verdicts" | grep -c '^BAD '   || true)
ok=$(printf    '%s\n' "$verdicts" | grep -c '^OK '    || true)
checked=$((ok + bad + parse))

printf '%s\n' "$verdicts" | grep '^PARSE ' | while IFS= read -r l; do
    set -- $l
    echo "PARSE-FAIL  $2:$3"
    echo "        ${l#PARSE $2 $3 }"
    echo "        The guard could not parse this declaration, so it cannot certify"
    echo "        it. Simplify the declaration or extend the parser -- a guard that"
    echo "        cannot read its input must never report CLEAN."
done

printf '%s\n' "$verdicts" | grep '^BAD ' | while IFS= read -r l; do
    set -- $l
    echo "FAIL  $2:$3"
    echo "        declared type: $4"
    echo "        No static_assert(std::is_trivially_destructible<$4>::value) in"
    echo "        CODE within 6 lines. On this toolchain a thread_local destructor"
    echo "        runs on FREED storage. If this type needs to act at thread exit,"
    echo "        move its state into a pthread-key record (see EpochThreadRecord in"
    echo "        src/consensus/chain.cpp). If it does not, add the assert -- naming"
    echo "        THIS type, in code, not in a comment."
done

echo
echo "checked $checked thread_local declaration(s) in src (excluding tests): $ok ok, $bad unguarded, $parse unparsable"

# ⚠️ A FLOOR, NOT JUST A ZERO CHECK. "Zero declarations" was already caught; the
# subtler failure is the parser matching FEWER than it used to after an edit, so
# a declaration silently drops out of the population. The floor makes that a
# failure instead of a quieter pass.
if [ "$checked" -lt "$MIN_CHECKED" ]; then
    echo "===== thread_local guard: FAIL (found $checked declarations, floor is"
    echo "      $MIN_CHECKED -- the instrument is under-counting, not the tree"
    echo "      shrinking; raise DIL_TLGUARD_MIN_CHECKED deliberately if the tree"
    echo "      really did lose declarations) ====="
    exit 2
fi

if [ "$parse" -ne 0 ] || [ "$bad" -ne 0 ]; then
    echo "===== thread_local guard: FAIL ($bad unguarded, $parse unparsable) ====="
    exit 1
fi

echo "===== thread_local guard: PASS (0 unguarded, 0 unparsable) ====="
exit 0
