#!/usr/bin/env bash
# Repo hygiene checker for dilithion/dilithion.
#
# Run manually:    ./scripts/check-repo-hygiene.sh
# Run as a gate:   set -e ./scripts/check-repo-hygiene.sh
# In CI:           .github/workflows/repo-hygiene.yml invokes this on every PR.
#
# Prints each finding as one line. Exits 0 if clean, 1 if any blocking
# violation is found. Warnings don't fail the build; blockers do.

set -u

FAIL=0
WARN=0

note()   { echo "::notice::$*"; }
warn()   { echo "::warning::$*"; WARN=$((WARN+1)); }
block()  { echo "::error::$*";   FAIL=$((FAIL+1)); }

# ─────────────────────────────────────────────────────────────
# Allowed files at repo root.
# Keep this sorted. Before adding an entry, ask: does this truly
# belong at the top level, or could it live in a subdirectory?
# See repo_structure_policy.md for the rationale.
# ─────────────────────────────────────────────────────────────
ALLOWED_ROOT_FILES=(
  # Standard OSS
  AUTHORS
  CHANGELOG.md
  CODE_OF_CONDUCT.md
  CONTRIBUTING.md
  LICENSE
  README.md
  SECURITY.md
  TEAM.md

  # Config / lint / build
  .clang-format
  .clang-tidy
  .cppcheck-suppressions.txt
  .editorconfig
  .gitattributes
  .gitignore
  .gitmodules
  Doxyfile
  Makefile
  Dockerfile
  Dockerfile.fuzzer
  codecov.yml
  dilithion.conf.example
  rpc_permissions.json.example

  # Release packaging scripts
  build-release.sh
  convert-whitepaper.sh
  create-github-release.sh
  create-linux-installer-secure.sh
  create-linux-installer.sh
  create-macos-installer-secure.sh
  create-macos-installer.sh
  create-windows-sfx.bat
  package-bootstrap.sh
  package-dilv-linux-release.sh
  package-dilv-macos-release.sh
  package-dilv-windows-release-github.sh
  package-linux-release.sh
  package-macos-release.sh
  package-windows-release-github.sh
  package-windows-release.bat

  # Release-package contents (shipped in tarballs)
  README-DILV-LINUX.txt
  README-DILV-MAC.txt
  README-DILV-WINDOWS.txt
  README-LINUX.txt
  README-MAC.txt
  README-WINDOWS.txt
  SETUP-AND-START.bat
  SETUP-DILV.bat
  START-DILV-MINER-GUI.bat
  START-DILV-MINING.bat
  START-MINER-GUI.bat
  START-MINING.bat
  build-randomx.bat
  dilithion-wallet
  dilithion-wallet.bat
  dilv-wallet.bat
  setup-and-start.sh
  setup-dilv.sh
  start-dilv-miner-gui.sh
  start-dilv-mining.sh
  start-miner-gui.sh
  start-mining.sh

  # Seed-node ops (relay-only variants — LDN/SGP/SYD. NYC uses its own
  # top-level /root/run-*-seed.sh which omits --relay-only for bridge)
  restart-seed-node.sh
  run-dil-seed-relayonly.sh
  run-dilv-seed-relayonly.sh

  # Runtime data (read by node code)
  datacenter-asns.txt

  # Historical references (kept for now)
  BITCOIN-ANALYSIS-README.txt
  MANIFEST.txt

  # Whitepaper (canonical)
  Dilithion-Whitepaper-v1.0.pdf
)

# ─────────────────────────────────────────────────────────────
# Legacy allow-list.
#
# Files known to be at root as of the April 2026 hygiene pass,
# that we know are cruft but haven't scheduled for removal yet.
# New PRs should not add anything to this list — it only exists
# so the hygiene CI can activate today without blocking every PR.
#
# Remove entries from here as you clean them up in dedicated PRs.
# When this list is empty, delete it entirely.
# ─────────────────────────────────────────────────────────────
LEGACY_ALLOWED=(
  # Stray images / screenshots (removal proposed in PR-E #16)
  "4.png"
  "amber.png"
  "Screenshot 2025-10-31 194715.png"
  "Screenshot 2025-10-31 194832.png"
  "Screenshot 2025-10-31 194848.png"
  "Screenshot 2025-10-31 194903.png"

  # HTML at root (removal proposed in PR-E #16)
  "DILITHION-COMPREHENSIVE-TECHNICAL-DOCUMENTATION.html"
  "WHITEPAPER.html"
  "wallet_test.html"

  # PDF documentation duplicates (authoritative copy lives in website/)
  "Dilithion - Comprehensive Technical Documentation.pdf"

  # One-off scripts awaiting future cleanup
  "build.sh"
  "check-wallet-balance.cpp"
  "convert-to-pdf.py"
  "create_favicon.py"
  "demo_wallet_interface.py"
  "demo_wallet_simple.py"
  "final_stress_test.sh"
  "git-push-safe.sh"
  "monitor-wallets.sh"
  "monitor_test.sh"
  "quick_snapshot.py"
  "run_all_tests.sh"
  "run_smoke_tests.sh"
  "run_stress_test.sh"
  "stress_test_3nodes.sh"
  "test-security-fixes.sh"
  "test-wallet-balance.sh"
  "test-wallet-security.sh"
  "test_htlc.py"
  "test_passphrase_validator.cpp"
  "test_runner.sh"
  "testnet_live_monitoring.sh"

  # Monitoring configs that belong in monitoring/
  "grafana-alerts.json"
  "grafana-dashboard.json"

  # Mystery paths to investigate
  "Dilithion"
  "cmd_line"
)

# Check whether a path is in the main allow-list.
is_allowed() {
  local needle=$1
  for allowed in "${ALLOWED_ROOT_FILES[@]}"; do
    [[ "$needle" == "$allowed" ]] && return 0
  done
  return 1
}

# Check whether a path is on the legacy grandfathered list.
is_legacy() {
  local needle=$1
  for allowed in "${LEGACY_ALLOWED[@]}"; do
    [[ "$needle" == "$allowed" ]] && return 0
  done
  return 1
}

# ─────────────────────────────────────────────────────────────
# Check 1 — root-level whitelist
# ─────────────────────────────────────────────────────────────
echo ""
echo "[1/8] Checking root-level whitelist …"

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  if is_allowed "$path"; then
    continue
  fi
  if is_legacy "$path"; then
    warn "Root-level file on legacy cruft list (schedule for removal): $path"
    continue
  fi
  block "Root-level file not in whitelist: $path"
  echo "      → if this file is legitimate, add it to ALLOWED_ROOT_FILES in scripts/check-repo-hygiene.sh"
  echo "      → otherwise, move it to a subdirectory (see docs/BUILDING.md / repo_structure_policy.md)"
done < <(git ls-tree HEAD | awk -F'\t' '{ split($1, cols, " "); if (cols[2]=="blob") print $2 }')

# ─────────────────────────────────────────────────────────────
# Check 2 — binary/build outputs at root
# ─────────────────────────────────────────────────────────────
echo ""
echo "[2/8] Checking for binary/build outputs at root …"

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  case "$path" in
    *.dll|*.so|*.dylib|*.a|*.o|*.exe|*.app|*.dmg|*.iso|*.msi|*.pdb)
      block "Build artifact at repo root: $path" ;;
    *.tar.gz|*.tar.bz2|*.tar.xz|*.tgz|*.zip|*.7z|*.rar|*.run|*.sha256)
      block "Release artifact at repo root (ship via GitHub Releases): $path" ;;
  esac
done < <(git ls-tree HEAD | awk -F'\t' '{ split($1, cols, " "); if (cols[2]=="blob") print $2 }')

# ─────────────────────────────────────────────────────────────
# Check 3 — coverage output at root
# ─────────────────────────────────────────────────────────────
echo ""
echo "[3/8] Checking for LCOV coverage reports at root …"

# LCOV often creates directories at root named after src/ subdirs.
# Any of these at root with .html inside = coverage, not source.
for fake in consensus core crypto primitives util; do
  if git ls-tree HEAD | awk -F'\t' -v d="$fake" '{ split($1, c, " "); if (c[2]=="tree" && $2==d) print }' | grep -q .; then
    block "Directory /$fake/ at repo root looks like LCOV coverage output"
    echo "      → real source code lives in src/$fake/, not /$fake/"
  fi
done

# Known LCOV files
for badfile in index.html index-sort-f.html index-sort-l.html index-detail.html index-detail-sort-f.html index-detail-sort-l.html coverage.info coverage_filtered.info; do
  if git ls-tree HEAD | awk -F'\t' -v f="$badfile" '{ split($1, c, " "); if (c[2]=="blob" && $2==f) print }' | grep -q .; then
    block "LCOV coverage file at root: $badfile"
  fi
done

# ─────────────────────────────────────────────────────────────
# Check 4 — dated / session-artifact filenames
# ─────────────────────────────────────────────────────────────
echo ""
echo "[4/8] Checking for dated session-artifact filenames …"

# Pattern: filename contains YYYY-MM-DD somewhere
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  # Skip the legacy pre-v3 changelog archive — expected to have a date
  [[ "$path" == "docs/CHANGELOG-LEGACY.md" ]] && continue
  # Skip intentionally dated configs inside docs/archive or docs/archive-like areas (none on main)
  if [[ "$path" =~ [0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
    warn "File name contains a date (likely session artifact): $path"
  fi
done < <(git ls-tree -r HEAD | awk '$2=="blob" {print $4}')

# Session-artifact keywords at root only
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  case "$path" in
    *SESSION*|*HANDOFF*|*-COMPLETE*|*-FINAL*|*STATUS.md|*PROGRESS.md|*READINESS*|*CHECKLIST*)
      block "Session-artifact filename at root: $path" ;;
  esac
done < <(git ls-tree HEAD | awk -F'\t' '{ split($1, cols, " "); if (cols[2]=="blob") print $2 }')

# ─────────────────────────────────────────────────────────────
# Check 5 — Windows path-escape / unicode bugs
# ─────────────────────────────────────────────────────────────
echo ""
echo "[5/8] Checking for Windows path-escape / unicode-garbage paths …"

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  if [[ "$path" == "nul" ]] || \
     [[ "$path" =~ ^Userswill ]] || \
     [[ "$path" =~ ^C.Users ]] || \
     [[ "$path" =~ [^[:print:]/] ]]; then
    block "Windows path-escape / non-printable filename: $(printf %q "$path")"
  fi
done < <(git ls-files)

# ─────────────────────────────────────────────────────────────
# Check 6 — private content
# ─────────────────────────────────────────────────────────────
echo ""
echo "[6/8] Checking for private / AI-assistant content …"

if git ls-tree -r HEAD -- .claude 2>/dev/null | grep -q .; then
  block "Private .claude/ directory is tracked — remove with 'git rm --cached -r .claude/'"
fi
if git ls-tree HEAD -- CLAUDE.md 2>/dev/null | grep -q .; then
  block "CLAUDE.md is tracked — this file contains private dev instructions"
fi
if git ls-tree HEAD -- PLAN.md 2>/dev/null | grep -q .; then
  warn "PLAN.md at root — usually a session artifact, consider moving to docs/planning/"
fi

# ─────────────────────────────────────────────────────────────
# Check 7 — line endings: index must match .gitattributes
# ─────────────────────────────────────────────────────────────
echo ""
echo "[7/8] Checking index line endings against .gitattributes …"

# `git ls-files --eol` prints:  i/<eol>  w/<eol>  attr/text [eol=...]  <path>
# A blocking violation is when the INDEX has CRLF for a file that
# .gitattributes mandates as LF. The working-tree column is irrelevant
# to CI — git normalizes at commit time, so a Windows dev with CRLF on
# disk is fine as long as their commits land as LF in the index.
#
# Fix locally with:  git add --renormalize <path> && git commit
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  block "Index has CRLF but .gitattributes mandates LF: $path"
done < <(git ls-files --eol | grep '^i/crlf' | grep -F 'eol=lf' | sed 's/.*\t//')

# ─────────────────────────────────────────────────────────────
# Check 8 — merge-conflict / editor leftover files (*.orig, *.rej)
# ─────────────────────────────────────────────────────────────
echo ""
echo "[8/8] Checking for merge-conflict / editor leftover files …"

# *.orig and *.rej are produced by git merge/rebase conflicts and by
# patch(1). They are never source — a tracked one is always a leftover.
# (Caught early by the *.orig / *.rej .gitignore patterns; this is the
#  CI backstop for anything force-added or committed before that landed.)
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  block "Merge-conflict / editor leftover tracked in repo: $path (delete it — it's a git/patch artifact, not source)"
done < <(git ls-files '*.orig' '*.rej')

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════"
echo "  Repo hygiene check complete"
echo "═══════════════════════════════════════"
echo "  Blocking violations: $FAIL"
echo "  Warnings:           $WARN"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
  echo "❌ Fix blocking violations before merging."
  echo ""
  echo "   If you believe a violation is a false positive, either:"
  echo "   (a) add the file to ALLOWED_ROOT_FILES in this script and explain why"
  echo "       in the PR description, or"
  echo "   (b) move the file to a subdirectory."
  exit 1
fi

if [[ "$WARN" -gt 0 ]]; then
  echo "⚠️  Warnings only — PR can merge, but please consider."
fi

echo "✅ Repo hygiene passed."
exit 0
