#!/usr/bin/env bash
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Periodically call getblocktemplate so that GetBlockBuilder operations
# are captured in a TxGraph trace recording.
#
# Usage:
#   ./periodic_gbt.sh [bitcoin-cli-args...]
#
# Examples:
#   ./periodic_gbt.sh                          # default bitcoin-cli
#   ./periodic_gbt.sh -signet                  # signet
#   ./periodic_gbt.sh -datadir=/path/to/data   # custom datadir

CLI="bitcoin-cli"
CLI_ARGS=("$@")
COUNT=0

echo "Waiting for new blocks and calling getblocktemplate after each one."
echo "Press Ctrl+C to stop."
echo "bitcoin-cli args: ${CLI_ARGS[*]:-<none>}"
echo ""

while true; do
    # Wait for a new block (blocks indefinitely until tip changes)
    RESULT=$($CLI "${CLI_ARGS[@]}" waitfornewblock 0 2>&1)
    if [ $? -ne 0 ]; then
        echo "[$(date '+%H:%M:%S')] waitfornewblock failed: $RESULT"
        echo "Retrying in 30s..."
        sleep 30
        continue
    fi

    HASH=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['hash'])" 2>/dev/null)
    HEIGHT=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['height'])" 2>/dev/null)

    COUNT=$((COUNT + 1))
    echo "[$(date '+%H:%M:%S')] Block #${HEIGHT} ${HASH:0:16}... — calling getblocktemplate (#${COUNT})"

    # Call getblocktemplate (output discarded, we only care about the TxGraph work)
    GBT_START=$(date +%s%N)
    $CLI "${CLI_ARGS[@]}" getblocktemplate '{"rules":["segwit"]}' > /dev/null 2>&1
    GBT_END=$(date +%s%N)
    GBT_MS=$(( (GBT_END - GBT_START) / 1000000 ))

    echo "[$(date '+%H:%M:%S')] getblocktemplate completed in ${GBT_MS}ms"
done
