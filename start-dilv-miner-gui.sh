#!/bin/bash
#########################################################
#  DILV MINER GUI - ONE-CLICK LAUNCH
#########################################################
#  Starts the dilv-node with VDF mining enabled and opens
#  the miner dashboard in your default web browser.
#########################################################

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "  ================================================"
echo "    DILV MINER GUI"
echo "  ================================================"
echo -e "${NC}"

# Check if dilv-node exists
if [ ! -f "dilv-node" ]; then
    echo -e "${YELLOW}ERROR: dilv-node binary not found!${NC}"
    echo "Make sure you extracted the complete release package."
    exit 1
fi

chmod +x dilv-node 2>/dev/null

# Detect RPC port (DilV mainnet default)
RPC_PORT=9332

# Function to open browser cross-platform
open_browser() {
    local url=$1
    if command -v xdg-open &> /dev/null; then
        xdg-open "$url" &> /dev/null &
    elif command -v open &> /dev/null; then
        open "$url"
    elif command -v sensible-browser &> /dev/null; then
        sensible-browser "$url" &> /dev/null &
    else
        echo -e "${YELLOW}Could not detect browser. Please open manually:${NC}"
        echo "  $url"
    fi
}

# Check if node is already running (DilV uses the same X-Dilithion-RPC header)
if curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
    --data-binary '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
    http://127.0.0.1:${RPC_PORT}/ > /dev/null 2>&1; then
    echo -e "${BLUE}Node is already running! Opening miner dashboard...${NC}"
    open_browser "http://127.0.0.1:${RPC_PORT}/miner"
    echo ""
    echo -e "${GREEN}Dashboard opened in your browser.${NC}"
    echo "URL: http://127.0.0.1:${RPC_PORT}/miner"
    exit 0
fi

# Start node in background
echo -e "${BLUE}Starting dilv-node with VDF mining enabled...${NC}"
./dilv-node --mine &
NODE_PID=$!

# Wait for RPC to become available
echo -e "${BLUE}Waiting for node to initialize...${NC}"
for i in $(seq 1 30); do
    sleep 2
    if curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
        --data-binary '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
        http://127.0.0.1:${RPC_PORT}/ > /dev/null 2>&1; then
        break
    fi
    echo "  Still waiting... ($i/30)"
done

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  Node is running! Opening miner dashboard...${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "URL: http://127.0.0.1:${RPC_PORT}/miner"
echo ""

# Open browser
open_browser "http://127.0.0.1:${RPC_PORT}/miner"

echo "Press Ctrl+C to stop the node, or use the"
echo "\"Shutdown Node\" button in the dashboard."
echo ""

# Handle Ctrl+C gracefully
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down node...${NC}"
    curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
        --data-binary '{"jsonrpc":"2.0","id":1,"method":"stop","params":[]}' \
        http://127.0.0.1:${RPC_PORT}/ > /dev/null 2>&1
    wait $NODE_PID 2>/dev/null
    echo "Done."
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait for node process to exit
wait $NODE_PID
echo ""
echo -e "${YELLOW}Node has stopped.${NC}"
