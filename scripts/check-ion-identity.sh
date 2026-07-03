#!/usr/bin/env bash
#
# check-ion-identity.sh — merge-gate hygiene check (Fable5 review of PR #142).
#
# ion-node.cpp was cloned from dilv-node.cpp and originally shipped with DilV's
# hardcoded identity (wire magic, production seed IP, config/datadir selector,
# REST API port, .dilv paths) even though its ChainParams say ION. That class of
# bug — "the ION binary secretly says DilV" — is easy for a human reviewer to
# miss. This script makes it a machine gate: it fails the build if any DilV-
# identity token reappears in ion-node.cpp OUTSIDE a full-line comment.
#
# FAIL-CLOSED comment handling (convergence re-review MED-1). A naive
# `sed 's://.*$::'` strips everything after the FIRST `//` on a line — including
# a `//` that lives INSIDE a string literal (e.g. a URL "http://seed:9444"), so a
# DilV token hidden in live code would silently ESCAPE the gate. That is
# fail-OPEN and defeats the purpose of a merge gate.
#
# This version only exempts a line when the ENTIRE line is a comment — after
# leading whitespace it begins with `//` (line comment), `/*` (block-comment
# open), or `*` (block-comment continuation/close, incl. `*/`). Standard
# multi-line /* ... */ blocks are therefore stripped line-by-line. EVERY other
# line is treated as code and grepped WHOLE, un-stripped, so a DilV token in a
# string literal or in a trailing position IS caught. The trade-off is
# intentionally fail-CLOSED: a raw DilV-identity token in a *trailing* `// ...`
# comment on a code line will (correctly) fail the gate. Convention: do not put
# raw DilV-identity tokens even in trailing comments — reword them (see the
# `api_port` line in ion-node.cpp for the pattern: "distinct from dilv-node's
# REST port", not "...9334").
#
# Usage: scripts/check-ion-identity.sh   (run from repo root; exit 1 on failure)

set -euo pipefail

TARGET="src/node/ion-node.cpp"

# ---------------------------------------------------------------------------
# DilV-identity tokens that must never appear in ion-node's live code.
# Keep this list maintainable — one token (or `|`-alternative) per concern.
# Only add tokens that CANNOT legitimately appear in correct ION code.
# ---------------------------------------------------------------------------
#   DILV_MAGIC                 — DilV wire magic (ION must use ION_MAGIC)
#   138.197.68.128             — DilV NYC production seed IP (ION has no seeds)
#   GetDataDir(Dilithion::DILV — would open DilV's datadir / LevelDB
#   .dilv                      — DilV data-directory path fragment
#   seed-dilv                  — DilV DNS seeds (seed-dilv{,1,2}.dilithion.org);
#                                does NOT match DIL/neutral seed.dilithion.org
#   9444                       — DilV P2P port (ION uses its own)
#   9332                       — DilV RPC port  (ION uses 10332)
#   9334                       — dilv-node REST API port (ION uses 10334)
#   RegisterX402Facilitator    — x402 settlement is DilV-only (NETWORK_ID_DILV);
#                                it must stay UNregistered on ion-node (Fable5
#                                H-1). Note: bare "x402" is intentionally NOT a
#                                token — ion-node legitimately logs an
#                                "x402 facilitator disabled on ION" message.
PATTERN='DILV_MAGIC|138\.197\.68\.128|GetDataDir\(Dilithion::DILV|\.dilv|seed-dilv|9444|9332|9334|RegisterX402Facilitator'

if [ ! -f "$TARGET" ]; then
    echo "check-ion-identity: ERROR: $TARGET not found (run from repo root)" >&2
    exit 2
fi

# Blank full-line comments (keep the line so grep -n stays aligned with the
# source), leave every code-bearing line fully intact, then match. A line is a
# full-line comment iff, after optional leading whitespace, it starts with
# `//`, `/*`, or `*`. Everything else is grepped WHOLE — fail-CLOSED.
violations="$(sed -E 's,^[[:space:]]*(//|/\*|\*).*$,,' "$TARGET" | grep -nE "$PATTERN" || true)"

if [ -n "$violations" ]; then
    echo "check-ion-identity: FAIL — DilV-identity token(s) in live code of $TARGET:" >&2
    echo "$violations" >&2
    echo "" >&2
    echo "ion-node must drive its identity from ION, not DilV. If a match is" >&2
    echo "legitimate rationale, move it into a FULL-LINE // comment (a trailing" >&2
    echo "comment on a code line is NOT exempt — this gate is fail-closed);" >&2
    echo "otherwise fix the code." >&2
    exit 1
fi

echo "check-ion-identity: OK — no DilV-identity tokens in live code of $TARGET"
