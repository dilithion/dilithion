#!/usr/bin/env bash
# ==============================================================================
# check_thread_local_guard.sh — every `thread_local` in production code must be
# TRIVIALLY DESTRUCTIBLE, and must say so with a static_assert a compiler checks.
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

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT" || exit 2

# Production code only. Tests may declare their own thread_locals; they do not run
# in a node, and the defect's payload is a node that refuses to start or corrupts
# its heap.
SEARCH_DIRS="src"
EXCLUDE_RE='^src/test/'

fail=0
checked=0

# A declaration, not a mention: `thread_local` followed by a type and a name, at
# the start of a statement. Comments and string literals are excluded by requiring
# the line to be a declaration and not to begin with a comment marker.
while IFS= read -r line; do
    file="${line%%:*}"
    rest="${line#*:}"
    lineno="${rest%%:*}"
    text="${rest#*:}"

    case "$file" in
        *) if echo "$file" | grep -qE "$EXCLUDE_RE"; then continue; fi ;;
    esac

    # Skip comment lines and anything that is plainly prose about thread_local.
    trimmed="$(echo "$text" | sed -e 's/^[[:space:]]*//')"
    case "$trimmed" in
        '//'*|'*'*|'/*'*) continue ;;
    esac
    # A declaration has `thread_local` as a leading storage specifier, optionally
    # after `static` or `extern`.
    if ! echo "$trimmed" | grep -qE '^(static[[:space:]]+|extern[[:space:]]+)?thread_local[[:space:]]'; then
        continue
    fi

    checked=$((checked + 1))

    # The guard must appear within the 6 lines following the declaration. That is
    # deliberately tight: a static_assert twenty lines away is a static_assert
    # nobody will move when they move the declaration.
    window="$(sed -n "${lineno},$((lineno + 6))p" "$file")"
    if echo "$window" | grep -q 'is_trivially_destructible'; then
        continue
    fi

    echo "FAIL  $file:$lineno"
    echo "        $trimmed"
    echo "        No is_trivially_destructible static_assert within 6 lines."
    echo "        On this toolchain a thread_local destructor runs on FREED"
    echo "        storage. If this type needs to act at thread exit, move its"
    echo "        state into a pthread-key record (see EpochThreadRecord in"
    echo "        src/consensus/chain.cpp). If it does not, add:"
    echo "            static_assert(std::is_trivially_destructible<T>::value, \"\");"
    fail=$((fail + 1))
done < <(grep -rn 'thread_local' --include=*.cpp --include=*.h $SEARCH_DIRS 2>/dev/null)

echo
echo "checked $checked thread_local declaration(s) in $SEARCH_DIRS (excluding tests)"

# ⚠️ FAIL CLOSED ON A BROKEN INSTRUMENT. Zero declarations means the grep found
# nothing, which is far more likely to be a moved directory or a changed pattern
# than a codebase that genuinely has none -- and a check that passes when it
# cannot see anything is worse than no check. This project has been bitten by a
# vacuous verification before.
if [ "$checked" -eq 0 ]; then
    echo "===== thread_local guard: FAIL (found NO declarations to check --"
    echo "      the instrument is broken, not the tree) ====="
    exit 2
fi

if [ "$fail" -ne 0 ]; then
    echo "===== thread_local guard: FAIL ($fail unguarded) ====="
    exit 1
fi

echo "===== thread_local guard: PASS (0 unguarded) ====="
exit 0
