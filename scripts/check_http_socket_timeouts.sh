#!/usr/bin/env bash
# ==============================================================================
# check_http_socket_timeouts.sh — AcceptThread must APPLY the socket timeouts and
# must REJECT a socket that will not take them.
# ==============================================================================
#
# ⚠️ WHY A STRUCTURAL GUARD AND NOT A UNIT TEST. `http_socket_timeout_tests` calls
# `CHttpServer::ApplyClientSocketTimeouts` directly, so it proves the HELPER works
# and stays green if `AcceptThread` stops calling it. That is the exact failure this
# branch has already shipped twice — nothing called `DrainGraveyard()`, nothing
# created the pinning slot — and the lesson from both is the same: a test that calls
# the mechanism proves the mechanism, not that anything invokes it.
#
# Reaching AcceptThread from a unit test needs a live server, a real client and a
# wall clock. So the CALLER is pinned textually instead, the same way
# check-tip-notify-drain pins its invariant.
#
# ⚠️ AND A MUTATION ARM WAS TRIED FIRST AND DISCARDED. Mutating AcceptThread and
# expecting `red_arms_pr198_r1_folds.sh` to die would have SURVIVED: that harness
# runs `deferred_reclamation_tests`, which never touches CHttpServer. A mutant that
# survives because the harness cannot observe it is not evidence — it is a green row
# for a check that does not exist.
#
# WHAT IS PINNED, and why each half matters:
#   1. AcceptThread CALLS ApplyClientSocketTimeouts.      Without it, no bound.
#   2. It REJECTS the socket when that call FAILS.        Without it, a failed
#      setsockopt silently restores the unbounded pin on a socket whose send sites
#      carry markers reading "BOUNDED AT 10 s" — the value exists, is correct, and
#      is not enforced. (Round-9 F56; this is the fifth form of the
#      adjective-versus-value defect on this branch.)
#
# Self-test: scripts/check_http_socket_timeouts.sh --self-test

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

check_file() {   # $1 = path to an http_server.cpp to check; echoes failures
    local f="$1" body fails=0

    if [ ! -f "$f" ]; then
        echo "  MISSING $f"
        return 2
    fi

    # ⚠️ COMMENTS ARE STRIPPED FIRST. Every comment in that file MENTIONS
    # ApplyClientSocketTimeouts — this guard's own rationale is written there — so a
    # raw grep would pass on a file whose only surviving mention is prose. Fixture
    # b3 is exactly that case.
    #
    # A line-comment strip is sufficient here and its limits are stated: the two
    # tokens below never appear inside a string literal in this file, and if
    # AcceptThread cannot be located at all the guard FAILS rather than skips.
    if ! body="$(sed -e 's://.*::' "$f")"; then
        echo "  could not read $f"
        return 2
    fi

    local accept_body
    accept_body="$(printf '%s\n' "$body" | awk '/void CHttpServer::AcceptThread/{f=1} f{print} f&&/^}/{exit}')"
    if [ -z "$accept_body" ]; then
        echo "  FAIL: could not locate CHttpServer::AcceptThread — the guard cannot"
        echo "        certify a function it cannot find, so this is a failure, not a skip"
        return 1
    fi

    if ! printf '%s\n' "$accept_body" | grep -q 'ApplyClientSocketTimeouts[ \t]*('; then
        echo "  FAIL: AcceptThread does not call ApplyClientSocketTimeouts."
        echo "        Accepted sockets then carry NO SO_SNDTIMEO/SO_RCVTIMEO, and a"
        echo "        client that stops reading pins a checkpointing worker for as"
        echo "        long as it likes — while the send-site exemption markers in"
        echo "        this file claim the pin is BOUNDED AT 10 s."
        fails=1
    fi

    # ⚠️ RECOGNITION IS NOT REJECTION (round-10 F62). Checking only that
    # `if (!Apply...)` appears passes an EMPTY branch and a LOG-ONLY branch --
    # both recognise the failure and then admit the socket anyway, which is
    # exactly the defect F56 fixed. Pin what the branch DOES.
    if ! printf '%s\n' "$accept_body" | grep -qE 'if[ \t]*\([ \t]*![ \t]*ApplyClientSocketTimeouts'; then
        echo "  FAIL: AcceptThread does not test the result of"
        echo "        ApplyClientSocketTimeouts. Discarding it silently restores the"
        echo "        unbounded pin: the value exists, is correct, is not enforced."
        fails=1
    else
        # ⚠️ BRACE DEPTH, NOT "the next line that looks like a closing brace".
        # The real branch contains a nested `if (!s_warned.exchange(true)) { ... }`
        # for the once-per-process log, and a pattern-based extractor stopped at
        # THAT brace -- truncating the branch before the close/continue and
        # reporting a CORRECT tree as broken. The guard being naive about the very
        # construct it checks is F62 one level down.
        branch="$(printf '%s\n' "$accept_body" | awk '
            /if[ \t]*\([ \t]*![ \t]*ApplyClientSocketTimeouts/ { f = 1 }
            f {
                print
                n = gsub(/\{/, "{"); m = gsub(/\}/, "}")
                d += n - m
                if (started && d <= 0) exit
                if (n > 0) started = 1
            }')"
        if ! printf '%s\n' "$branch" | grep -qE '(^|[^A-Za-z0-9_])close[ \t]*\('; then
            echo "  FAIL: the failure branch does not CLOSE the socket. Recognising the"
            echo "        failure and admitting the connection anyway is the same"
            echo "        unbounded pin with a log line in front of it."
            fails=1
        fi
        if ! printf '%s\n' "$branch" | grep -qE '(^|[^A-Za-z0-9_])(continue|return)[ \t]*;'; then
            echo "  FAIL: the failure branch does not stop processing this socket, so"
            echo "        control falls through to the enqueue -- the socket is closed"
            echo "        AND handed to a worker."
            fails=1
        fi
    fi

    return $fails
}

if [ "${1:-}" = "--self-test" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT INT TERM
    fails=0

    # NEGATIVE: the caller removed entirely
    printf 'void CHttpServer::AcceptThread() {\n  while (1) {\n    SOCKET s = accept(a,b,c);\n    queue(s);\n  }\n}\n' > "$tmp/b1.cpp"
    # NEGATIVE: called, but the result discarded — the F56 shape exactly
    printf 'void CHttpServer::AcceptThread() {\n  while (1) {\n    SOCKET s = accept(a,b,c);\n    (void)ApplyClientSocketTimeouts(s);\n    queue(s);\n  }\n}\n' > "$tmp/b2.cpp"
    # NEGATIVE: only a COMMENT mentions it — the reason comments are stripped
    printf 'void CHttpServer::AcceptThread() {\n  while (1) {\n    SOCKET s = accept(a,b,c);\n    // ApplyClientSocketTimeouts(s); if (!ApplyClientSocketTimeouts(s)) {}\n    queue(s);\n  }\n}\n' > "$tmp/b3.cpp"
    # NEGATIVE (F62): recognised, then admitted anyway -- an EMPTY branch
    printf 'void CHttpServer::AcceptThread() {\n  while (1) {\n    SOCKET s = accept(a,b,c);\n    if (!ApplyClientSocketTimeouts(s)) {\n    }\n    queue(s);\n  }\n}\n' > "$tmp/b4.cpp"
    # NEGATIVE (F62): recognised and LOGGED, then admitted anyway
    printf 'void CHttpServer::AcceptThread() {\n  while (1) {\n    SOCKET s = accept(a,b,c);\n    if (!ApplyClientSocketTimeouts(s)) {\n      std::cerr << "oh dear" << std::endl;\n    }\n    queue(s);\n  }\n}\n' > "$tmp/b5.cpp"
    # NEGATIVE (F62): closed, but control FALLS THROUGH to the enqueue
    printf 'void CHttpServer::AcceptThread() {\n  while (1) {\n    SOCKET s = accept(a,b,c);\n    if (!ApplyClientSocketTimeouts(s)) {\n      close(s);\n    }\n    queue(s);\n  }\n}\n' > "$tmp/b6.cpp"

    # POSITIVE: the real shape
    printf 'void CHttpServer::AcceptThread() {\n  while (1) {\n    SOCKET s = accept(a,b,c);\n    if (!ApplyClientSocketTimeouts(s)) {\n      close(s);\n      continue;\n    }\n    queue(s);\n  }\n}\n' > "$tmp/g1.cpp"

    for f in b1 b2 b3 b4 b5 b6; do
        if check_file "$tmp/$f.cpp" >/dev/null 2>&1; then
            echo "  FAIL  reject $f: an unwired/unenforced AcceptThread was accepted"
            fails=$((fails+1))
        else
            echo "  PASS  reject $f"
        fi
    done
    if check_file "$tmp/g1.cpp" >/dev/null 2>&1; then
        echo "  PASS  accept g1 (the real shape is accepted)"
    else
        echo "  FAIL  accept g1: the correct shape was rejected — this guard would"
        echo "        reject everything, which proves nothing"
        fails=$((fails+1))
    fi

    echo
    if [ "$fails" -ne 0 ]; then
        echo "===== http socket-timeout wiring SELF-TEST: FAIL ($fails) ====="; exit 1
    fi
    echo "===== http socket-timeout wiring SELF-TEST: PASS (6 rejected, 1 accepted) ====="
    exit 0
fi

cd "$ROOT" || exit 2
out="$(check_file src/api/http_server.cpp)"; rc=$?
[ -n "$out" ] && printf '%s\n' "$out"
if [ "$rc" -ne 0 ]; then
    echo "===== http socket-timeout wiring: FAIL ====="
    exit "$rc"
fi
echo "  - AcceptThread applies the socket timeouts"
echo "  - and REJECTS a socket that will not take them (fail closed)"
echo "===== http socket-timeout wiring: PASS ====="
exit 0
