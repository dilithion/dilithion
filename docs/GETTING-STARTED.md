# Dilithion — Getting Started

**Applies to:** DIL mainnet and DilV mainnet (also covers DIL testnet — `--testnet`).
**Renamed from `TESTNET-GUIDE.md` in v4.4.1.** Procedures below apply to both
chains; where commands differ by chain, both forms are shown. The portions of
this guide that still read as testnet-specific are scheduled for refresh in a
follow-up docs PR — file an issue if a section is unclear in the meantime.

## Overview

This guide walks you through setting up Dilithion nodes — DIL (RandomX PoW) and
DilV (VDF) — on mainnet or testnet. The Dilithion testnet uses easier difficulty
(256x) and separate network infrastructure from mainnet; the mainnet sections
apply by default unless `--testnet` is shown.

## Current Implementation Status

### ✅ What's Ready
- Testnet genesis block (mined and verified)
- ChainParams system (mainnet and testnet configurations)
- Basic node infrastructure (blockchain, mempool, wallet, RPC)
- Mining controller
- Genesis block verification

### ⏳ What Needs Implementation
- `--testnet` command-line flag in dilithion-node
- P2P network activation (currently initialized but not started)
- Genesis block loading on node startup
- Peer connection management (`--connect`, `--addnode` flags)
- Network message handling for testnet magic bytes

## Quick Start: Current Testing Capabilities

While full P2P networking is being implemented, you can test individual components:

### 1. Single Node Testing (Available Now)

```bash
# Test mainnet node
./dilithion-node --datadir=.dilithion-node1 --rpcport=8332

# Test RPC commands
curl -X POST http://localhost:8332 -d '{"method":"help"}'
curl -X POST http://localhost:8332 -d '{"method":"getnewaddress"}'
curl -X POST http://localhost:8332 -d '{"method":"getbalance"}'
```

### 2. Genesis Block Verification (Available Now)

```bash
# Verify testnet genesis
./genesis_gen --testnet

# Expected output:
# Nonce: 82393330
# Hash: 00000005a5311314b1b466839c495e841d5e0db02972216d3a8a6fdddaebf56f
# ✓ Genesis block verification passed
```

### 3. Wallet Testing (Available Now)

```bash
# Start node with wallet
./dilithion-node --datadir=.dilithion-test-wallet --rpcport=8332

# In another terminal, test wallet operations
curl -X POST http://localhost:8332 -d '{"method":"getnewaddress"}'
curl -X POST http://localhost:8332 -d '{"method":"getaddresses"}'
curl -X POST http://localhost:8332 -d '{"method":"getbalance"}'
```

### 4. Mining Testing (Available Now)

```bash
# Start node with mining enabled
./dilithion-node --datadir=.dilithion-test-mining --rpcport=8332 --mine --threads=2

# Watch mining output
# Expected: Hash rate reporting every 10 seconds
```

## Full Multi-Node Setup (Requires Implementation)

To enable full multi-node testing, the following features need to be added to `src/node/dilithion-node.cpp`:

### Required Features

#### 1. Testnet Support

Add `--testnet` flag to load testnet chain parameters:

```cpp
struct NodeConfig {
    bool testnet = false;
    // ... existing fields

    bool ParseArgs(int argc, char* argv[]) {
        // ... existing parsing
        else if (arg == "--testnet") {
            testnet = true;
        }
    }
};

// In main():
// Initialize chain parameters based on network
if (config.testnet) {
    Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Testnet());
    std::cout << "Network: TESTNET" << std::endl;
} else {
    Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Mainnet());
    std::cout << "Network: MAINNET" << std::endl;
}
```

#### 2. P2P Port Configuration

Add `--port` flag for P2P networking:

```cpp
struct NodeConfig {
    uint16_t p2p_port = 0;  // 0 = use default from chain params
    // ... existing fields

    bool ParseArgs(int argc, char* argv[]) {
        // ... existing parsing
        else if (arg.find("--port=") == 0) {
            p2p_port = std::stoi(arg.substr(7));
        }
    }
};
```

#### 3. Peer Connection

Add `--connect` and `--addnode` flags:

```cpp
struct NodeConfig {
    std::vector<std::string> connect_nodes;
    std::vector<std::string> add_nodes;

    bool ParseArgs(int argc, char* argv[]) {
        // ... existing parsing
        else if (arg.find("--connect=") == 0) {
            connect_nodes.push_back(arg.substr(10));
        }
        else if (arg.find("--addnode=") == 0) {
            add_nodes.push_back(arg.substr(10));
        }
    }
};
```

#### 4. Genesis Block Loading

Add genesis block verification on startup:

```cpp
// In main(), after blockchain initialization:
std::cout << "Loading genesis block..." << std::endl;
CBlock genesis = Genesis::CreateGenesisBlock();

if (!Genesis::IsGenesisBlock(genesis)) {
    std::cerr << "Genesis block verification failed!" << std::endl;
    return 1;
}

std::cout << "  ✓ Genesis block: " << genesis.GetHash().GetHex() << std::endl;
```

#### 5. P2P Network Activation

Actually start the P2P networking:

```cpp
// In main(), after P2P component initialization:
std::cout << "Starting P2P network..." << std::endl;

uint16_t p2p_port = config.p2p_port > 0 ?
                    config.p2p_port :
                    Dilithion::g_chainParams->p2pPort;

if (!connection_manager.Start(p2p_port)) {
    std::cerr << "Failed to start P2P network on port " << p2p_port << std::endl;
    return 1;
}

std::cout << "  ✓ P2P network listening on port " << p2p_port << std::endl;

// Connect to specified nodes
for (const auto& node : config.connect_nodes) {
    connection_manager.ConnectToNode(node);
}
```

## Multi-Node Testing Procedure (Once Implemented)

### Setup 3 Local Nodes

**Node 1** (Miner):
```bash
./dilithion-node \
  --testnet \
  --datadir=.dilithion-testnet-node1 \
  --port=18444 \
  --rpcport=18332 \
  --mine \
  --threads=2
```

**Node 2** (Relay):
```bash
./dilithion-node \
  --testnet \
  --datadir=.dilithion-testnet-node2 \
  --port=18445 \
  --rpcport=18333 \
  --connect=127.0.0.1:18444
```

**Node 3** (Observer):
```bash
./dilithion-node \
  --testnet \
  --datadir=.dilithion-testnet-node3 \
  --port=18446 \
  --rpcport=18334 \
  --connect=127.0.0.1:18445
```

### Testing Scenarios

#### Test 1: Genesis Block Sync
**Goal**: Verify all nodes have the same genesis block

```bash
# On each node
curl -X POST http://localhost:18332 -d '{"method":"getbestblockhash"}'
curl -X POST http://localhost:18333 -d '{"method":"getbestblockhash"}'
curl -X POST http://localhost:18334 -d '{"method":"getbestblockhash"}'

# All should return: 00000005a5311314b1b466839c495e841d5e0db02972216d3a8a6fdddaebf56f
```

#### Test 2: Block Propagation
**Goal**: Blocks mined on Node 1 appear on all nodes

```bash
# Start mining on Node 1
curl -X POST http://localhost:18332 -d '{"method":"startmining"}'

# Wait 4-5 minutes (testnet block time = 4 minutes)

# Check block count on all nodes
curl -X POST http://localhost:18332 -d '{"method":"getblockcount"}'
curl -X POST http://localhost:18333 -d '{"method":"getblockcount"}'
curl -X POST http://localhost:18334 -d '{"method":"getblockcount"}'

# All should show same block height
```

#### Test 3: Transaction Broadcasting
**Goal**: Transactions created on one node appear in mempools of all nodes

```bash
# On Node 2, create transaction
curl -X POST http://localhost:18333 -d '{
  "method":"sendtoaddress",
  "params":["<address>", 10.0]
}'

# Check mempool on all nodes
curl -X POST http://localhost:18332 -d '{"method":"getmempoolinfo"}'
curl -X POST http://localhost:18333 -d '{"method":"getmempoolinfo"}'
curl -X POST http://localhost:18334 -d '{"method":"getmempoolinfo"}'

# All should show same transaction count
```

#### Test 4: Peer Discovery
**Goal**: Nodes discover and connect to each other

```bash
# Check peer connections on each node
curl -X POST http://localhost:18332 -d '{"method":"getpeerinfo"}'
curl -X POST http://localhost:18333 -d '{"method":"getpeerinfo"}'
curl -X POST http://localhost:18334 -d '{"method":"getpeerinfo"}'

# Expected: Node 1 sees Node 2, Node 2 sees Nodes 1&3, Node 3 sees Node 2
```

#### Test 5: Wallet Post-Quantum Signatures
**Goal**: Verify Dilithium signature creation and validation

```bash
# Generate new address with post-quantum key pair
curl -X POST http://localhost:18332 -d '{"method":"getnewaddress"}'

# Create signed transaction (triggers Dilithium signature generation)
curl -X POST http://localhost:18332 -d '{
  "method":"sendtoaddress",
  "params":["<address>", 1.0]
}'

# Verify signature size (should be ~2420 bytes for Dilithium3)
# Check transaction in mempool
curl -X POST http://localhost:18332 -d '{"method":"getrawmempool","params":[true]}'
```

#### Test 6: Difficulty Adjustment
**Goal**: Mine 2016+ blocks to test difficulty adjustment

```bash
# Start mining on Node 1
curl -X POST http://localhost:18332 -d '{"method":"startmining"}'

# This will take ~5.6 days at 4-minute blocks
# Monitor progress:
watch -n 60 'curl -X POST http://localhost:18332 -d "{\"method\":\"getmininginfo\"}"'

# After 2016 blocks, check difficulty changed:
curl -X POST http://localhost:18332 -d '{"method":"getdifficulty"}'
```

## Network Configuration Reference

### Testnet Parameters

| Parameter | Value | Usage |
|-----------|-------|-------|
| Network Magic | `0xDAB5BFFA` | P2P message identifier |
| P2P Port | `18444` | Default listening port |
| RPC Port | `18332` | Default RPC port |
| Data Directory | `.dilithion-testnet` | Blockchain storage |
| Genesis Hash | `00000005...aebf56f` | First block |
| Genesis Nonce | `82393330` | Mined value |
| Block Time | `240 seconds` | 4 minutes |
| Difficulty | `0x1e00ffff` | 256x easier than mainnet |

### Port Allocation for Local Testing

| Node | P2P Port | RPC Port | Data Directory |
|------|----------|----------|----------------|
| Node 1 (Miner) | 18444 | 18332 | `.dilithion-testnet-node1` |
| Node 2 (Relay) | 18445 | 18333 | `.dilithion-testnet-node2` |
| Node 3 (Observer) | 18446 | 18334 | `.dilithion-testnet-node3` |

## Troubleshooting

### Issue: Port Already in Use

```bash
# Error: Failed to start RPC server on port 18332
# Solution: Use different port
./dilithion-node --testnet --rpcport=18335
```

### Issue: Nodes Not Connecting

```bash
# Check if node is listening
netstat -an | grep 18444

# Check firewall allows localhost connections
# On Windows: Check Windows Defender Firewall
# On Linux: sudo iptables -L
```

### Issue: Genesis Hash Mismatch

```bash
# Verify genesis block
./genesis_gen --testnet

# Expected: 00000005a5311314b1b466839c495e841d5e0db02972216d3a8a6fdddaebf56f
# If different: chainparams.cpp has wrong values
```

### Issue: Mining Too Slow

```bash
# Testnet mining should be fast (~20 minutes for genesis)
# Check CPU usage:
top

# Increase threads:
./dilithion-node --testnet --mine --threads=4
```

## Success Criteria Checklist

After implementing multi-node support, verify:

- [ ] All 3 nodes start without errors
- [ ] All nodes show same genesis hash
- [ ] Nodes connect to each other
- [ ] Blocks mined on Node 1 appear on Nodes 2&3 within 10 seconds
- [ ] Transactions broadcast from any node appear in all mempools
- [ ] Wallet creates valid Dilithium signatures (~2420 bytes)
- [ ] No crashes during 1+ hour operation
- [ ] RPC commands work on all nodes
- [ ] Mining statistics update correctly
- [ ] Mempool synchronizes across nodes

## Next Steps

### Immediate (1-2 hours)
1. Add `--testnet` flag support to dilithion-node.cpp
2. Add `--port` flag for P2P port configuration
3. Initialize ChainParams at node startup
4. Load and verify genesis block on startup

### Short-term (4-8 hours)
5. Implement `--connect` and `--addnode` flags
6. Activate P2P networking (currently disabled)
7. Implement peer connection manager
8. Test basic peer discovery

### Medium-term (1-2 days)
9. Implement block propagation
10. Implement transaction broadcasting
11. Implement mempool synchronization
12. Test multi-node scenarios

### Testing (3-5 days)
13. Run all test scenarios
14. Long-running stability tests (24+ hours)
15. Stress tests (high transaction volume)
16. Edge case testing (network partitions, etc.)

## File Locations

### Configuration Files
- **Chain Parameters**: `src/core/chainparams.cpp`
- **Genesis Code**: `src/node/genesis.cpp`
- **Node Main**: `src/node/dilithion-node.cpp`

### Network Code
- **P2P Protocol**: `src/net/protocol.h`
- **Network Manager**: `src/net/net.cpp`
- **Peer Manager**: `src/net/peers.cpp`
- **Connection Manager**: `src/net/socket.cpp`

### Testing Tools
- **Genesis Generator**: `src/test/genesis_test.cpp` (binary: `genesis_gen`)
- **Node Binary**: `dilithion-node`

## References

- **Implementation Plan**: `TESTNET-IMPLEMENTATION-PLAN.md`
- **Current Status**: `TESTNET-STATUS.md`
- **Testnet Genesis**: Use `./genesis_gen --testnet` to display
- **Mainnet Parameters**: `src/core/chainparams.cpp` line 8-40

---

**Last Updated**: October 26, 2025
**Network Status**: Testnet genesis ready, P2P implementation in progress
**Next Milestone**: Add `--testnet` flag and activate P2P networking
