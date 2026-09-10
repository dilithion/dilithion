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

# ⚠️ AN EXPLICIT INVENTORY, NOT A FLOOR (round-7 F37e). The floor was a number
# with an ENV OVERRIDE, which means the check could be silenced from outside the
# file by the same command line that runs it -- and "at least N" says nothing
# about WHICH N. An inventory says exactly which declarations are expected to
# exist, so both directions are failures a human has to look at:
#   * a declaration DISAPPEARS  -> something removed it; say so and update this list
#   * a declaration APPEARS     -> it is new, and must be added here deliberately
# There is no override. Editing the list is the acknowledgement.
#
# Format: <file>:<type>, one per line, sorted. Regenerate the candidate list with
#   awk -f scripts/check_thread_local_guard.awk <file> ...
# and then READ it before pasting -- the point is the deliberate step.
INVENTORY="$(cat <<'EOF'
src/consensus/chain.cpp:EpochThreadRecord*
src/consensus/chain.cpp:std::atomic<uint64_t>*
src/consensus/chain.cpp:const char*
src/consensus/chain.cpp:bool
src/digital_dna/verification_manager.cpp:std::mt19937_64
EOF
)"

# ⚠️ THE SCANNED SET, STATED (round-7 F37d). This scans `src/**/*.cpp` and
# `src/**/*.h`, EXCLUDING `src/test/`. Production code outside that set would not
# be checked, so: at the time of writing there is none -- the node binaries, the
# consensus, net, rpc, api, node, wallet, crypto and digital_dna sources are all
# under `src/`, and `depends/` is third-party. A new top-level source directory
# must be added here.
SCAN_DIRS="src"
SCAN_EXCLUDE_RE='(^|/)test/'

run_over() {   # prints awk verdict lines; returns non-zero if any tool failed
    local dir="$1" f rc=0 found=0
    local list
    # ⚠️ find's exit status is CHECKED (F37d). A failed find previously produced
    # an empty stream that read as "no declarations", i.e. a broken instrument
    # reporting a clean tree.
    if ! list="$(find "$dir" \( -name '*.cpp' -o -name '*.h' \) -type f 2>/dev/null | sort)"; then
        echo "PARSE $dir 0 find failed over $dir" 
        return 2
    fi
    if [ -z "$list" ]; then
        echo "PARSE $dir 0 find matched NO source files under $dir"
        return 2
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if echo "$f" | grep -qE "$SCAN_EXCLUDE_RE"; then continue; fi
        found=$((found + 1))
        # ⚠️ awk's exit status is CHECKED too, per file.
        if ! awk -f "$AWK_PROG" "$f"; then
            echo "PARSE $f 0 awk exited non-zero while parsing this file"
            rc=2
        fi
    done <<EOF
$list
EOF
    if [ "$found" -eq 0 ]; then
        echo "PARSE $dir 0 no non-test source files were scanned"
        return 2
    fi
    return $rc
}

# ---------------------------------------------------------------------------
# --self-test: the negative fixtures. Each is a form that BYPASSED the previous
# guard; each must now be REJECTED. Run in a temp dir, never in the tree.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT INT TERM
    mkdir -p "$tmp/src"

    # ── MUST BE REJECTED ─────────────────────────────────────────────────────
    # Round 6's five bypasses:
    printf '#include <string>\ninline thread_local std::string a;\n' > "$tmp/src/f1.cpp"
    printf '#include <string>\nstatic inline thread_local std::string b;\n' > "$tmp/src/f2.cpp"
    printf '#include <string>\nthread_local\n    std::string c;\n' > "$tmp/src/f3.cpp"
    printf '#include <string>\nthread_local std::string d;\n// is_trivially_destructible: honest, promise\n' > "$tmp/src/f4.cpp"
    printf '#include <string>\n#include <type_traits>\nthread_local std::string e;\nstatic_assert(std::is_trivially_destructible<int>::value, "");\n' > "$tmp/src/f5.cpp"

    # Round 7 F37a — the window keyed on a bare TOKEN, so none of these was an
    # assert at all, and one of them asserts the OPPOSITE:
    printf '#include <string>\n#include <type_traits>\nthread_local std::string g;\nusing Check = std::is_trivially_destructible<std::string>;\n' > "$tmp/src/f6.cpp"
    printf '#include <string>\n#include <type_traits>\nthread_local std::string h;\nstatic_assert(!std::is_trivially_destructible<std::string>::value, "");\n' > "$tmp/src/f7.cpp"
    printf '#include <string>\n#include <type_traits>\nvoid f() {\nthread_local std::string i;\nif constexpr (std::is_trivially_destructible<std::string>::value) { }\n}\n' > "$tmp/src/f8.cpp"

    # F37b — multiple declarators: one assert cannot describe two types.
    printf '#include <string>\n#include <type_traits>\nthread_local std::string *p2 = nullptr, s2;\nstatic_assert(std::is_trivially_destructible<std::string*>::value, "");\n' > "$tmp/src/f9.cpp"

    # F37c — a token the parser cannot account for must be PARSE, never skipped.
    printf '#include <string>\n#define MY_TLS thread_local std::string\nMY_TLS z;\n' > "$tmp/src/f10.cpp"
    printf '#include <string>\nconstexpr thread_local int k = 0;\n' > "$tmp/src/f11.cpp"

    # F43 — u8 char literals were misparsed as digit separators, which swallowed
    # the rest of the file: the declaration below then went UNSEEN entirely.
    printf "#include <string>\nchar c8 = u8'A';\nthread_local std::string w;\n" > "$tmp/src/f12.cpp"

    # ── MUST BE ACCEPTED ─────────────────────────────────────────────────────
    # Five rejections are equally satisfied by a guard that rejects everything.
    printf '#include <type_traits>\nthread_local int* p = 0;\nstatic_assert(std::is_trivially_destructible<int*>::value, "");\n' > "$tmp/src/p1.cpp"
    # raw strings must be PARSED, not refused (src/api/*_html.h contain them)
    printf '#include <string>\n#include <type_traits>\nconst char* html = R"H(<a href="x">//not a comment</a> it'"'"'s fine)H";\nthread_local int* q = 0;\nstatic_assert(std::is_trivially_destructible<int*>::value, "");\n' > "$tmp/src/p2.cpp"
    # digit separators must still work after the F43 fix
    printf '#include <type_traits>\nlong v = 200000;\nlong w2 = 0x1F;\nthread_local int* r = 0;\nstatic_assert(std::is_trivially_destructible<int*>::value, "");\n' > "$tmp/src/p3.cpp"
    # the trait may be spelled with the _v alias and still be a positive assert
    printf '#include <type_traits>\nthread_local int* t2 = 0;\nstatic_assert(std::is_trivially_destructible<int*>::value, "ok");\n' > "$tmp/src/p4.cpp"

    fails=0
    for f in f1 f2 f3 f4 f5 f6 f7 f8 f9 f10 f11 f12; do
        out="$(awk -f "$AWK_PROG" "$tmp/src/$f.cpp" 2>&1)"
        if echo "$out" | grep -qE '^(BAD|PARSE)'; then
            echo "  PASS  reject $f: $(echo "$out" | head -1 | cut -c1-72)"
        else
            echo "  FAIL  reject $f: NOT REJECTED -- the bypass is still open"
            echo "        awk said: ${out:-<nothing at all, which is the worst case>}"
            fails=$((fails + 1))
        fi
    done
    for f in p1 p2 p3 p4; do
        out="$(awk -f "$AWK_PROG" "$tmp/src/$f.cpp" 2>&1)"
        if echo "$out" | grep -q '^OK'; then
            echo "  PASS  accept $f: a correct declaration is accepted"
        else
            echo "  FAIL  accept $f: a CORRECT declaration was rejected -- a guard that"
            echo "        rejects everything proves nothing. awk said: ${out:-<nothing>}"
            fails=$((fails + 1))
        fi
    done

    echo
    if [ "$fails" -ne 0 ]; then
        echo "===== thread_local guard SELF-TEST: FAIL ($fails) ====="
        exit 1
    fi
    echo "===== thread_local guard SELF-TEST: PASS (12 rejected, 4 accepted) ====="
    exit 0
fi

cd "$ROOT" || exit 2

# ⚠️ THE TOOL'S EXIT STATUS IS CAPTURED, NOT DISCARDED (round-7 F37d). Writing
# `verdicts="$(run_over src)"` on its own throws away run_over's status, so a
# failed find or a crashed awk became an empty verdict list -- which the report
# below would have described as a clean tree. `set -u` does not catch that; only
# looking at the status does.
verdicts="$(run_over "$SCAN_DIRS")"
tool_rc=$?

parse=$(printf '%s\n' "$verdicts" | grep -c '^PARSE ' || true)
bad=$(printf   '%s\n' "$verdicts" | grep -c '^BAD '   || true)
ok=$(printf    '%s\n' "$verdicts" | grep -c '^OK '    || true)
checked=$((ok + bad + parse))

printf '%s\n' "$verdicts" | grep '^PARSE ' | while IFS= read -r l; do
    set -- $l
    echo "PARSE-FAIL  $2:$3"
    echo "        ${l#PARSE $2 $3 }"
    echo "        The guard could not account for this \`thread_local\` token, so it"
    echo "        cannot certify it -- and it will NOT skip it. Simplify the"
    echo "        declaration or extend the parser. A guard that cannot read its"
    echo "        input must never report CLEAN."
done

printf '%s\n' "$verdicts" | grep '^BAD ' | while IFS= read -r l; do
    set -- $l
    echo "FAIL  $2:$3"
    echo "        declared type: $4"
    echo "        No POSITIVE static_assert(std::is_trivially_destructible<$4>::value)"
    echo "        in CODE within 6 lines. Note all three words: it must be a real"
    echo "        static_assert (not a using-alias or an if constexpr), it must not"
    echo "        be negated, and it must name THIS type. On this toolchain a"
    echo "        thread_local destructor runs on FREED storage; if this type needs"
    echo "        to act at thread exit, move its state into a pthread-key record"
    echo "        (see EpochThreadRecord in src/consensus/chain.cpp)."
done

echo
echo "checked $checked \`thread_local\` token(s) under $SCAN_DIRS (excluding tests): $ok ok, $bad unguarded, $parse unaccounted"

# ── THE INVENTORY (F37e) ─────────────────────────────────────────────────────
# Both directions are failures a human must look at. No env override exists.
actual="$(printf '%s\n' "$verdicts" | grep '^OK ' | awk '{ t = $4; for (i = 5; i <= NF; i++) t = t " " $i; print $2 ":" t }' | sort)"
expected="$(printf '%s\n' "$INVENTORY" | grep -v '^[[:space:]]*$' | sort)"

missing="$(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") || true)"
extra="$(  comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") || true)"

inv_fail=0
if [ -n "$missing" ]; then
    echo
    echo "INVENTORY: these declarations are EXPECTED but were not found —"
    printf '%s\n' "$missing" | sed 's/^/        /'
    echo "        Either something removed them (say so, and LOWER the inventory"
    echo "        deliberately by deleting these lines), or the parser stopped"
    echo "        seeing them, which is the instrument failing and is far worse."
    inv_fail=1
fi
if [ -n "$extra" ]; then
    echo
    echo "INVENTORY: these declarations were found but are NOT expected —"
    printf '%s\n' "$extra" | sed 's/^/        /'
    echo "        A new thread_local. It passed the assert check, but adding it to"
    echo "        the inventory is a deliberate step: confirm it really must be"
    echo "        thread-local at all, then add the line."
    inv_fail=1
fi

if [ "$tool_rc" -ne 0 ]; then
    echo "===== thread_local guard: FAIL (a tool in the scan failed; status $tool_rc) ====="
    exit 2
fi
if [ "$parse" -ne 0 ] || [ "$bad" -ne 0 ]; then
    echo "===== thread_local guard: FAIL ($bad unguarded, $parse unaccounted) ====="
    exit 1
fi
if [ "$inv_fail" -ne 0 ]; then
    echo "===== thread_local guard: FAIL (inventory mismatch — see above) ====="
    exit 1
fi

echo "===== thread_local guard: PASS ($ok guarded, inventory matches exactly) ====="
exit 0
