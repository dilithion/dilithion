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
LOG="/root/node.log"

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

    if [ -f "$HOME/.dilithion/auto_rebuild" ]; then
        echo "$(date): Auto-rebuild marker detected — node will clean up on restart"
    fi

    echo "$(date): Restarting in 5 seconds..."
    sleep 5
done
