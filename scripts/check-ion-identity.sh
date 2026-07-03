#!/usr/bin/env bash
#
# check-ion-identity.sh — merge-gate hygiene check (Fable5 review of PR #142).
#
# ion-node.cpp was cloned from dilv-node.cpp and originally shipped with DilV's
# hardcoded identity (wire magic, production seed IP, config/datadir selector,
# REST API port, .dilv paths) even though its ChainParams say ION. That class of
# bug — "the ION binary secretly says DilV" — is easy for a human reviewer to
# miss. This script makes it a machine gate: it fails the build if any DilV-
# identity token reappears in ion-node.cpp OUTSIDE a // comment.
#
# Comments are allowed (rationale like "distinct from dilv-node's 9334 port" is
# legitimate); only live code / string-literal occurrences fail the gate.
#
# Usage: scripts/check-ion-identity.sh   (run from repo root; exit 1 on failure)

set -euo pipefail

TARGET="src/node/ion-node.cpp"

# DilV-identity tokens that must never appear in ion-node's live code:
#   DILV_MAGIC                 — DilV wire magic (must use ION_MAGIC)
#   138.197.68.128:9444        — DilV NYC production seed (ION has no seeds yet)
#   GetDataDir(Dilithion::DILV — would open DilV's datadir / LevelDB
#   9334                       — dilv-node REST API port (ION uses 10334)
#   .dilv                      — DilV data directory path fragment
PATTERN='DILV_MAGIC|138\.197\.68\.128:9444|GetDataDir\(Dilithion::DILV|9334|\.dilv'

if [ ! -f "$TARGET" ]; then
    echo "check-ion-identity: ERROR: $TARGET not found (run from repo root)" >&2
    exit 2
fi

# Strip // line-comments (sed does NOT delete the lines, so grep -n line numbers
# stay aligned with the source) before matching, so commented rationale is
# exempt and only live-code / string-literal matches survive.
violations="$(sed 's://.*$::' "$TARGET" | grep -nE "$PATTERN" || true)"

if [ -n "$violations" ]; then
    echo "check-ion-identity: FAIL — DilV-identity token(s) in live code of $TARGET:" >&2
    echo "$violations" >&2
    echo "" >&2
    echo "ion-node must drive its identity from ION, not DilV. If a match is" >&2
    echo "legitimate rationale, move it into a // comment; otherwise fix it." >&2
    exit 1
fi

echo "check-ion-identity: OK — no DilV-identity tokens in live code of $TARGET"
