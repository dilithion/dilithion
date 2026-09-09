#!/bin/bash
# seed_wrapper_exit_code_check.sh — behavioural check + mutation control for the
# exit-code branch in the two relay-only seed wrappers.
#
# WHY THIS EXISTS. PR #127 makes the node exit 1 (no auto_rebuild marker) when
# its startup integrity check hits a persistent storage fault that is NOT
# corruption. The wrappers used to `while true` on every exit code, so that
# "stop for an operator" exit became a ~65-second crash loop against a suspect
# disk (fresh pass 2026-09-07, MEDIUM-3). The fold makes exit 1 stop the loop.
#
# WHAT IT PROVES, PER WRAPPER, with a fake binary that counts its own starts:
#   arm 1  exit 1  -> wrapper terminates itself (rc 1), binary ran ONCE,
#                     "RECOVERY REQUIRED" printed
#   arm 2  exit 2  -> wrapper keeps restarting (killed by timeout, rc 124),
#                     binary ran >= 2 times            (existing behaviour kept)
#   arm 0  exit 0  -> same as arm 2                     (existing behaviour kept)
#   MUTANT: invert the branch (-eq 1 -> -ne 1); arm 1 must now FAIL (the
#           counter keeps climbing).  If the mutant passes, this check is not
#           discriminating and the whole run is a FAIL.
#   CONTROL: comment-only edit; all arms must still pass.
#
# Exit code: 0 = every arm as expected AND mutant killed AND control green.
# Anything else = FAIL, with the first failing assertion printed.
#
# Needs: bash, coreutils timeout, mktemp. Runs anywhere (MSYS2 included); the
# wrapper's `hostname -I` and `ulimit` may complain on non-Linux — harmless.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TIMEOUT_S=6
FAILS=0

fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
pass() { echo "  ok:   $*"; }

# run_arm <wrapper-file> <binary-name> <fake-exit-code> <label>
# Sets: ARM_RC ARM_COUNT ARM_OUT
run_arm() {
    local wrapper="$1" binary="$2" fake_exit="$3" label="$4"
    local tmp; tmp="$(mktemp -d)"
    cp "$wrapper" "$tmp/wrapper.sh"
    mkdir -p "$tmp/home"
    cat > "$tmp/$binary" <<EOF
#!/bin/bash
echo run >> "$tmp/count"
exit $fake_exit
EOF
    chmod +x "$tmp/$binary" "$tmp/wrapper.sh"
    : > "$tmp/count"
    HOME="$tmp/home" \
    DILITHION_NODE_LOG="$tmp/node.log" \
    DILITHION_WRAPPER_RESTART_DELAY=1 \
        timeout "$TIMEOUT_S" bash "$tmp/wrapper.sh" > "$tmp/out" 2>&1
    ARM_RC=$?
    ARM_COUNT=$(wc -l < "$tmp/count" | tr -d ' ')
    ARM_OUT="$tmp/out"
    echo "[$label] rc=$ARM_RC starts=$ARM_COUNT"
}

# expect_stop <label>: wrapper exited by itself with 1 after exactly one start
expect_stop() {
    [ "$ARM_RC" -eq 1 ]       && pass "$1: wrapper exited 1 by itself" || fail "$1: expected wrapper rc 1, got $ARM_RC (124 = still looping)"
    [ "$ARM_COUNT" -eq 1 ]    && pass "$1: binary started exactly once" || fail "$1: expected 1 start, got $ARM_COUNT"
    grep -q 'RECOVERY REQUIRED' "$ARM_OUT" && pass "$1: RECOVERY REQUIRED printed" || fail "$1: RECOVERY REQUIRED banner missing"
}

# expect_loop <label>: wrapper kept restarting until timeout killed it
expect_loop() {
    [ "$ARM_RC" -eq 124 ]     && pass "$1: wrapper still looping at timeout" || fail "$1: expected rc 124 (timeout), got $ARM_RC"
    [ "$ARM_COUNT" -ge 2 ]    && pass "$1: binary restarted (starts=$ARM_COUNT)" || fail "$1: expected >=2 starts, got $ARM_COUNT"
}

# mutant_is_killed <wrapper-file> <binary>: on the inverted branch, arm 1 must
# stop being a stop. Returns 0 if the mutant is detected (good).
mutant_check() {
    local wrapper="$1" binary="$2" tmp; tmp="$(mktemp -d)"
    sed 's/\[ "\$EXIT_CODE" -eq 1 \]; then/[ "$EXIT_CODE" -ne 1 ]; then/' "$wrapper" > "$tmp/mutant.sh"
    if cmp -s "$wrapper" "$tmp/mutant.sh"; then
        fail "mutant: sed did not change the file — the branch text moved; update this check"
        return
    fi
    run_arm "$tmp/mutant.sh" "$binary" 1 "MUTANT exit1"
    if [ "$ARM_RC" -eq 124 ] && [ "$ARM_COUNT" -ge 2 ]; then
        pass "mutant (inverted branch) is KILLED: exit-1 arm looped instead of stopping"
    else
        fail "mutant NOT killed: inverted branch still satisfied the exit-1 arm (rc=$ARM_RC starts=$ARM_COUNT) — check is not discriminating"
    fi
}

control_check() {
    local wrapper="$1" binary="$2" tmp; tmp="$(mktemp -d)"
    sed '1a # control mutant: comment-only edit' "$wrapper" > "$tmp/control.sh"
    run_arm "$tmp/control.sh" "$binary" 1 "CONTROL exit1"
    expect_stop "control"
}

for pair in "run-dil-seed-relayonly.sh:dilithion-node" "run-dilv-seed-relayonly.sh:dilv-node"; do
    wrapper="$REPO_ROOT/${pair%%:*}"
    binary="${pair##*:}"
    echo "=== $(basename "$wrapper") (fake $binary)"
    run_arm "$wrapper" "$binary" 1 "exit1"; expect_stop "exit1"
    run_arm "$wrapper" "$binary" 2 "exit2"; expect_loop "exit2"
    run_arm "$wrapper" "$binary" 0 "exit0"; expect_loop "exit0"
    mutant_check "$wrapper" "$binary"
    control_check "$wrapper" "$binary"
done

echo
if [ "$FAILS" -eq 0 ]; then
    echo "seed_wrapper_exit_code_check: PASS (all arms as expected, mutant killed, control green)"
    exit 0
fi
echo "seed_wrapper_exit_code_check: FAIL ($FAILS assertion(s))"
exit 1
