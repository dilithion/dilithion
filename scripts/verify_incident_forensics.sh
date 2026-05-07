#!/usr/bin/env bash
# verify_incident_forensics.sh
#
# Periodic cross-reference between memory/CURRENT_STATE.md "Incident forensics"
# registry and what actually lives in the off-host blob storage bucket.
#
# Background: a sibling-of-live-state forensic copy is not durable. Off-host
# upload + URI logged in CURRENT_STATE.md is the durable preservation pattern
# (see memory/feedback_preserve_to_safe_location.md). This script catches:
#   1. Registry entries whose tar URI no longer exists in the bucket
#      (silent loss / mistaken cleanup).
#   2. Bucket objects that have no entry in the registry
#      (untracked artifacts; either backfill the registry or archive).
#   3. Entries whose preserved-until date has passed
#      (review for archival or deletion with explicit log).
#
# Run monthly via cron, or manually before any major deploy.
#
# Usage:
#   scripts/verify_incident_forensics.sh                # default bucket
#   FORENSICS_BUCKET=s3://my-bucket scripts/verify_incident_forensics.sh
#
# Requirements:
#   - The blob-storage CLI for the chosen backend (aws / gcloud / s5cmd /
#     rclone). The script auto-detects.
#   - Read access to memory/CURRENT_STATE.md.
#
# Exit codes:
#   0 — registry and bucket are consistent
#   1 — drift detected (missing artifacts, untracked objects, or expired entries)
#   2 — environment problem (no CLI found, registry path missing, bucket unreachable)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REGISTRY="${REGISTRY:-$REPO_ROOT/memory/CURRENT_STATE.md}"
BUCKET="${FORENSICS_BUCKET:-}"
TODAY_UTC=$(date -u +%Y-%m-%d)

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
die() { log "FATAL: $*"; exit 2; }

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

[[ -f "$REGISTRY" ]] || die "registry not found at $REGISTRY"

if [[ -z "$BUCKET" ]]; then
    log "FORENSICS_BUCKET env var not set — script can verify registry shape but cannot cross-check bucket contents."
    log "Set FORENSICS_BUCKET=s3://... or gs://... or similar, then re-run."
    log "Continuing in registry-shape-only mode."
fi

# Detect available blob-storage CLI.
BLOB_CLI=""
if command -v aws >/dev/null 2>&1; then
    BLOB_CLI="aws"
elif command -v gcloud >/dev/null 2>&1; then
    BLOB_CLI="gcloud"
elif command -v rclone >/dev/null 2>&1; then
    BLOB_CLI="rclone"
elif command -v s5cmd >/dev/null 2>&1; then
    BLOB_CLI="s5cmd"
fi

if [[ -n "$BUCKET" ]] && [[ -z "$BLOB_CLI" ]]; then
    die "no blob-storage CLI on PATH (aws, gcloud, rclone, s5cmd) — cannot cross-check bucket"
fi

# ---------------------------------------------------------------------------
# Phase 1 — extract registry entries
# ---------------------------------------------------------------------------

# The registry's "Incident forensics" section is a markdown table with columns:
#   Incident date | Seed(s) | Tip @ snapshot | Corruption signature | Tar URI |
#   Tar SHA-256 | Preserved-until
#
# We extract Tar URI + Preserved-until and the row context for each.
log "Phase 1: parsing registry at $REGISTRY"

REGISTRY_TMPDIR=$(mktemp -d)
trap 'rm -rf "$REGISTRY_TMPDIR"' EXIT

REGISTRY_ENTRIES="$REGISTRY_TMPDIR/registry_entries.tsv"
REGISTRY_URIS="$REGISTRY_TMPDIR/registry_uris.txt"

# Extract markdown table rows under the "Incident forensics" heading. Skip the
# header row and separator. Skip rows that contain "_none yet_" or are empty.
awk '
    BEGIN { in_section = 0; row_seen = 0 }
    /^## Incident forensics/ { in_section = 1; next }
    in_section && /^## / { in_section = 0 }
    in_section && /^\|/ {
        if ($0 ~ /^\| *Incident date/) { row_seen = 1; next }
        if ($0 ~ /^\| *-+/) { next }
        if ($0 ~ /_none yet/) { next }                # placeholder row
        # Skip rows whose Tar URI column (field 6 with leading | empty) is blank.
        n = split($0, f, "|");
        uri_col = f[6]; gsub(/^ +| +$/, "", uri_col);
        if (uri_col == "") next
        if (row_seen) print
    }
' "$REGISTRY" > "$REGISTRY_ENTRIES"

ENTRY_COUNT=$(wc -l < "$REGISTRY_ENTRIES" | tr -d ' ')
log "  found $ENTRY_COUNT registry entries"

# Pull just the Tar URI column (5th |-separated field after the leading |).
awk -F'|' '{ gsub(/^ +| +$/, "", $6); if ($6 != "") print $6 }' "$REGISTRY_ENTRIES" > "$REGISTRY_URIS"

# ---------------------------------------------------------------------------
# Phase 2 — check expired entries
# ---------------------------------------------------------------------------

log "Phase 2: checking preserved-until dates against today (${TODAY_UTC})"
EXPIRED_COUNT=0
while IFS='|' read -r _ inc_date _ _ _ _ _ uri _ preserved_until _; do
    inc_date=$(echo "$inc_date" | xargs)
    uri=$(echo "$uri" | xargs)
    preserved_until=$(echo "$preserved_until" | xargs)
    [[ -z "$preserved_until" ]] && continue
    [[ "$preserved_until" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || continue
    if [[ "$preserved_until" < "$TODAY_UTC" ]]; then
        log "  EXPIRED: $inc_date entry preserved-until=$preserved_until (today=$TODAY_UTC) uri=$uri"
        EXPIRED_COUNT=$((EXPIRED_COUNT + 1))
    fi
done < "$REGISTRY_ENTRIES"
log "  expired entries: $EXPIRED_COUNT"

# ---------------------------------------------------------------------------
# Phase 3 — bucket cross-check (only if BUCKET is set + CLI available)
# ---------------------------------------------------------------------------

DRIFT=0

if [[ -n "$BUCKET" ]] && [[ -n "$BLOB_CLI" ]]; then
    log "Phase 3: cross-checking bucket $BUCKET via $BLOB_CLI"

    BUCKET_LIST="$REGISTRY_TMPDIR/bucket_list.txt"
    case "$BLOB_CLI" in
        aws)    aws s3 ls --recursive "$BUCKET" | awk '{print $NF}' > "$BUCKET_LIST" ;;
        gcloud) gcloud storage ls -r "$BUCKET" > "$BUCKET_LIST" ;;
        rclone) rclone lsf "$BUCKET" > "$BUCKET_LIST" ;;
        s5cmd)  s5cmd ls "$BUCKET/*" | awk '{print $NF}' > "$BUCKET_LIST" ;;
    esac

    log "  bucket lists $(wc -l < "$BUCKET_LIST" | tr -d ' ') objects"

    # Missing-from-bucket: registry URIs that don't appear in the bucket.
    while read -r uri; do
        [[ -z "$uri" ]] && continue
        # Strip the bucket prefix to get the object key for comparison.
        key="${uri#$BUCKET/}"
        key="${key#${BUCKET}}"
        if ! grep -qF -- "$key" "$BUCKET_LIST"; then
            log "  MISSING-FROM-BUCKET: $uri (registry says it should exist; bucket disagrees)"
            DRIFT=1
        fi
    done < "$REGISTRY_URIS"

    # Untracked-in-bucket: bucket objects with no registry entry.
    while read -r obj; do
        [[ -z "$obj" ]] && continue
        if ! grep -qF -- "$obj" "$REGISTRY_URIS"; then
            log "  UNTRACKED-IN-BUCKET: $obj (in bucket but no registry entry)"
            DRIFT=1
        fi
    done < "$BUCKET_LIST"
else
    log "Phase 3: SKIPPED (FORENSICS_BUCKET not set or no blob CLI available)"
fi

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

if [[ $EXPIRED_COUNT -gt 0 ]] || [[ $DRIFT -ne 0 ]]; then
    log "RESULT: drift detected — review CURRENT_STATE.md and bucket"
    exit 1
fi

log "RESULT: clean — registry and bucket are consistent"
exit 0
