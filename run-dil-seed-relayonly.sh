#!/bin/bash
# Raise fd limit from the default 1024 so the node can absorb connection
# surges without hitting EMFILE. A 2026-04-21 SYN flood on port 8444 hit
# the 1024 limit on NYC and stalled a user tx for 37 min because miners
# couldn't connect to fetch it. 65536 matches the hard ulimit on the
# droplets and the LimitNOFILE in the (currently unused) systemd units.
ulimit -n 65536

# Auto-restart wrapper for DIL relay-only seed nodes (LDN/SGP/SYD).
#
# NYC is different: NYC's DIL node loads the bridge wallet and runs WITHOUT
# --relay-only. Do NOT use this wrapper on NYC — NYC uses a separate
# top-level script at /root/run-dil-seed.sh that omits --relay-only.
# See .claude/skills/deploy/SKILL.md for the per-host wrapper matrix.
#
# Usage: nohup ./run-dil-seed-relayonly.sh > /root/dil-seed.log 2>&1 &

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/dilithion-node"
# Overridable ONLY so scripts/seed_wrapper_exit_code_check.sh can drive this
# loop with a fake binary. Production never sets either variable.
LOG="${DILITHION_NODE_LOG:-/root/node.log}"
RESTART_DELAY="${DILITHION_WRAPPER_RESTART_DELAY:-5}"

# Auto-detect external IP. Required for seed_id resolution (the node matches
# --externalip to its chainparams seed slot). As of v4.5.0 a missing/mismatched
# --externalip makes the node SKIP_NOT_A_SEED (does not attest) — no silent seed_id=0.
EXTERNAL_IP=$(hostname -I | awk '{print $1}')
# --rpcallowhost=${EXTERNAL_IP}: v4.5.0 added an anti-DNS-rebinding Host-allowlist; a
#   --public-api node WITHOUT it 403s every non-loopback Host, breaking remote miner
#   MIK-attestation (Host: <seed-ip>) + monitor + bridge cross-seed RPC. (Incident 2026-06-19.)
# --allow-plaintext-seed-key: seeds hold v1-plaintext attestation keys; v4.5.0 default-on
#   encryption would FATAL on them without this opt-out (removed at the seed-key cutover).
FLAGS="--relay-only --public-api --externalip=${EXTERNAL_IP} --rpcallowhost=${EXTERNAL_IP} --allow-plaintext-seed-key"

cd "$SCRIPT_DIR" || exit 1

echo "$(date): DIL seed node wrapper starting (dir=$SCRIPT_DIR, externalip=${EXTERNAL_IP})"

while true; do
    echo "$(date): Starting $BINARY $FLAGS"
    $BINARY $FLAGS >> "$LOG" 2>&1
    EXIT_CODE=$?

    echo "$(date): Node exited with code $EXIT_CODE"

    # PR #127 (startup integrity, fresh-pass MEDIUM-3 2026-09-07): the node
    # exits 1 WITHOUT writing the auto_rebuild marker when its startup
    # integrity check hits a persistent storage fault that is NOT corruption
    # (failing disk, fsync lag, a file lock). That exit means STOP FOR AN
    # OPERATOR. Restarting cannot fix it and used to re-run a 60-second retry
    # loop against the suspect disk every cycle, forever, with no signal but
    # this log. Exit 1 is also every other fatal init error (bad flag, port in
    # use, unreadable datadir), none of which a 5-second restart repairs.
    # So exit 1 STOPS this loop, loudly. Exit 2 (marker written; the node
    # wipes and resyncs itself on its next start) and every other code keep
    # the existing restart behaviour. Verified by
    # scripts/seed_wrapper_exit_code_check.sh, including the inverted-branch
    # mutant.
    if [ "$EXIT_CODE" -eq 1 ]; then
        echo "=========================================================="
        echo "$(date): RECOVERY REQUIRED — node exited 1 (fatal startup or integrity error, NOT corruption)."
        echo "  NOT restarting: a restart cannot fix this and would loop forever."
        echo "  auto_rebuild marker path (absent by design on this exit): $HOME/.dilithion/auto_rebuild"
        echo "  Read the tail of $LOG, fix the cause (disk / lock / config), then start this wrapper again."
        echo "=========================================================="
        exit 1
    fi

    if [ -f "$HOME/.dilithion/auto_rebuild" ]; then
        echo "$(date): Auto-rebuild marker detected — node will clean up on restart"
    fi

    echo "$(date): Restarting in ${RESTART_DELAY} seconds..."
    sleep "$RESTART_DELAY"
done
