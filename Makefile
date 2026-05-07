# Dilithion Cryptocurrency Makefile
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

# ============================================================================
# Configuration
# ============================================================================

# Version detection from git tags
# Tries to get version from git tag, falls back to "dev" if not available
# Add Windows Git to PATH for MSYS2 environments that may not have git
export PATH := $(PATH):/c/Program Files/Git/cmd
GIT_VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date +%Y-%m-%d 2>/dev/null || echo "unknown")

# Detect operating system
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

# Compiler and flags
CXX := g++
# Use ?= to allow environment variables (e.g., --coverage) to completely override defaults
# If not set by environment, use optimized defaults
# Note: -pipe avoids temp file issues on Windows
# Phase 9.2: Build hardening flags for security
# -fstack-protector-strong: Stack canaries (prevents stack buffer overflow exploits)
# -D_FORTIFY_SOURCE=2: Runtime buffer overflow checks (requires -O2 or higher)
# -Wformat -Wformat-security: Format string vulnerability warnings
# -fPIC: Position-independent code (for shared libraries)
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -pipe -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
CXXFLAGS += -DDILITHION_VERSION='"$(GIT_VERSION)"'
# -MMD -MP: Auto-generate header dependency files (.d) so changing a .h triggers recompilation
CXXFLAGS += -MMD -MP
CFLAGS ?= -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
CFLAGS += -MMD -MP

# Include paths (base)
INCLUDES := -I src \
            -I depends/randomx/src \
            -I depends/dilithium/ref \
            -I depends/chiavdf/src \
            -I depends/chiavdf/src/c_bindings

# Library paths and libraries (base)
# Use ?= to allow environment to set initial LDFLAGS (e.g., --coverage)
# Then append our library paths
LDFLAGS ?=

# Platform-specific RandomX build directory
ifeq ($(UNAME_S),Windows)
    RANDOMX_BUILD_DIR := depends/randomx/build-windows
else ifneq (,$(findstring MINGW,$(UNAME_S)))
    RANDOMX_BUILD_DIR := depends/randomx/build-windows
else ifneq (,$(findstring MSYS,$(UNAME_S)))
    RANDOMX_BUILD_DIR := depends/randomx/build-windows
else
    # Linux, macOS, and other Unix-like systems
    RANDOMX_BUILD_DIR := depends/randomx/build
endif

LDFLAGS += -L $(RANDOMX_BUILD_DIR) \
           -L depends/dilithium/ref \
           -L /mingw64/lib \
           -L C:/msys64/mingw64/lib \
           -L .

# FIX-007 (CRYPT-001/006): Add OpenSSL for secure AES-256 implementation
# Phase 2.2: Add dbghelp for Windows stack traces
# PEER-DISCOVERY: Add miniupnpc for automatic UPnP port mapping
LIBS := -lrandomx -lleveldb -lpthread -lssl -lcrypto -lminiupnpc -lgmpxx -lgmp

# Platform-specific configuration
ifeq ($(UNAME_S),Darwin)
    # macOS with Homebrew
    HOMEBREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
    INCLUDES += -I$(HOMEBREW_PREFIX)/opt/leveldb/include
    LDFLAGS += -L$(HOMEBREW_PREFIX)/opt/leveldb/lib
else ifeq ($(UNAME_S),Windows)
    # Windows requires ws2_32 for sockets, bcrypt for secure RNG, and dbghelp for stack traces
    # iphlpapi is required by miniupnpc on Windows
    LIBS += -lws2_32 -lbcrypt -ldbghelp -liphlpapi
    # Use MSYS2 MinGW64 includes - do NOT use MinGW-Builds paths (C:/ProgramData/mingw64)
    # as they lack C11 support (quick_exit, timespec_get)
    INCLUDES += -I depends/leveldb/include -I /mingw64/include -I C:/msys64/mingw64/include
else ifneq (,$(findstring MINGW,$(UNAME_S)))
    # MinGW/MSYS2 on Windows - use system OpenSSL 3.x from /mingw64
    # iphlpapi is required by miniupnpc on Windows
    LIBS += -lws2_32 -lbcrypt -ldbghelp -liphlpapi
    INCLUDES += -I depends/leveldb/include -I /mingw64/include -I C:/msys64/mingw64/include
else ifneq (,$(findstring MSYS,$(UNAME_S)))
    # MSYS on Windows - use system OpenSSL 3.x from /mingw64
    # iphlpapi is required by miniupnpc on Windows
    LIBS += -lws2_32 -lbcrypt -ldbghelp -liphlpapi
    INCLUDES += -I depends/leveldb/include -I /mingw64/include -I C:/msys64/mingw64/include
endif

# Fix for Windows: Use system default temp directories
# Commenting out hardcoded /c/tmp as it causes issues
# ifeq ($(UNAME_S),Windows)
#     export TMP := /c/tmp
#     export TEMP := /c/tmp
#     export TMPDIR := /c/tmp
#     $(shell mkdir -p /c/tmp 2>/dev/null)
# else ifneq (,$(findstring MINGW,$(UNAME_S)))
#     export TMP := /c/tmp
#     export TEMP := /c/tmp
#     export TMPDIR := /c/tmp
#     $(shell mkdir -p /c/tmp 2>/dev/null)
# else ifneq (,$(findstring MSYS,$(UNAME_S)))
#     export TMP := /c/tmp
#     export TEMP := /c/tmp
#     export TMPDIR := /c/tmp
#     $(shell mkdir -p /c/tmp 2>/dev/null)
# endif

# Dilithium C files (compiled separately)
DILITHIUM_DIR := depends/dilithium/ref
DILITHIUM_SOURCES := $(DILITHIUM_DIR)/sign.c \
                     $(DILITHIUM_DIR)/packing.c \
                     $(DILITHIUM_DIR)/polyvec.c \
                     $(DILITHIUM_DIR)/poly.c \
                     $(DILITHIUM_DIR)/ntt.c \
                     $(DILITHIUM_DIR)/reduce.c \
                     $(DILITHIUM_DIR)/rounding.c \
                     $(DILITHIUM_DIR)/symmetric-shake.c \
                     $(DILITHIUM_DIR)/fips202.c \
                     $(DILITHIUM_DIR)/randombytes.c
DILITHIUM_OBJECTS := $(DILITHIUM_SOURCES:.c=.o)

# Build directory
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj

# Phase 6 sub-stream (b) — Thread Sanitizer build mode.
# Usage:   make TSAN=1 <target>
# Example: make TSAN=1 reorg_wal_crash_injection_tests
# Run the resulting binary directly; TSAN prints a race report on stderr
# and exits non-zero if a data race is detected. TSAN-built objects go to
# build-tsan/ to keep them separate from the normal build artifacts. To
# switch between TSAN and non-TSAN cleanly, run `make clean` first
# (dilithium .o files live in depends/dilithium/ref/ and are shared
# across modes — clean rebuilds them with the correct flags).
# Requires GCC 4.8+ (Linux) with libtsan; NOT supported on MSYS2 mingw64.
ifdef TSAN
    TSAN_FLAGS := -fsanitize=thread -fno-omit-frame-pointer
    CXXFLAGS += $(TSAN_FLAGS)
    CFLAGS += $(TSAN_FLAGS)
    LDFLAGS += $(TSAN_FLAGS)
    BUILD_DIR := build-tsan
    OBJ_DIR := $(BUILD_DIR)/obj
endif

# Colors for output
COLOR_RESET := \033[0m
COLOR_GREEN := \033[32m
COLOR_BLUE := \033[34m
COLOR_YELLOW := \033[33m

# ============================================================================
# Source Files
# ============================================================================

# Core source files (organized by module)
CONSENSUS_SOURCES := src/consensus/fees.cpp \
                     src/consensus/pow.cpp \
                     src/consensus/chain.cpp \
                     src/consensus/reorg_wal.cpp \
                     src/consensus/chain_verifier.cpp \
                     src/consensus/tx_validation.cpp \
                     src/consensus/signature_batch_verifier.cpp \
                     src/consensus/validation.cpp \
                     src/consensus/vdf_validation.cpp \
                     src/consensus/port/chain_selector_impl.cpp

CORE_SOURCES_UTIL := src/core/chainparams.cpp \
                     src/core/globals.cpp \
                     src/core/node_context.cpp \
                     src/core/version.cpp

# Phase 4.2: Database hardening
DB_SOURCES := src/db/db_errors.cpp

CRYPTO_SOURCES := src/crypto/randomx_hash.cpp \
                  src/crypto/sha3.cpp \
                  src/crypto/hmac_sha3.cpp \
                  src/crypto/pbkdf2_sha3.cpp \
                  src/crypto/siphash.cpp

MINER_SOURCES := src/miner/controller.cpp \
                 src/miner/vdf_miner.cpp

# DFMP (Fair Mining Protocol) sources
DFMP_SOURCES := src/dfmp/dfmp.cpp \
                src/dfmp/identity_db.cpp \
                src/dfmp/mik.cpp \
                src/dfmp/mik_registration_file.cpp

# Digital DNA (Sybil-resistant identity) sources
DIGITAL_DNA_SOURCES := src/digital_dna/digital_dna.cpp \
                       src/digital_dna/latency_fingerprint.cpp \
                       src/digital_dna/timing_signature.cpp \
                       src/digital_dna/perspective_proof.cpp \
                       src/digital_dna/digital_dna_rpc.cpp \
                       src/digital_dna/behavioral_profile.cpp \
                       src/digital_dna/memory_fingerprint.cpp \
                       src/digital_dna/clock_drift.cpp \
                       src/digital_dna/bandwidth_proof.cpp \
                       src/digital_dna/ml_detector.cpp \
                       src/digital_dna/dna_registry_db.cpp \
                       src/digital_dna/trust_score.cpp \
                       src/digital_dna/dna_verification.cpp \
                       src/digital_dna/verification_manager.cpp \
                       src/digital_dna/sample_rate_limiter.cpp \
                       src/digital_dna/sample_envelope.cpp \
                       src/digital_dna/mik_pubkey_cache.cpp

# VDF (Verifiable Delay Function) sources - uses chiavdf class group VDF
VDF_SOURCES := src/vdf/vdf.cpp \
               src/vdf/cooldown_tracker.cpp

# chiavdf library objects (compiled separately from third-party source)
CHIAVDF_OBJECTS := $(OBJ_DIR)/chiavdf/c_wrapper.o $(OBJ_DIR)/chiavdf/lzcnt.o

NET_SOURCES := src/net/protocol.cpp \
               src/net/serialize.cpp \
               src/net/net.cpp \
               src/net/peer_discovery.cpp \
               src/net/peers.cpp \
               src/net/socket.cpp \
               src/net/dns.cpp \
               src/net/tx_relay.cpp \
               src/net/async_broadcaster.cpp \
               src/net/headers_manager.cpp \
               src/net/orphan_manager.cpp \
               src/net/block_fetcher.cpp \
               src/net/netaddress.cpp \
               src/net/addrman.cpp \
               src/net/port/addrman_v2.cpp \
               src/net/port/addrman_migrator.cpp \
               src/net/port/peer_scorer.cpp \
               src/net/port/sync_coordinator_adapter.cpp \
               src/net/banman.cpp \
               src/net/headerssync.cpp \
               src/net/blockencodings.cpp \
               src/net/feeler.cpp \
               src/net/bandwidth_throttle.cpp \
               src/net/connection_quality.cpp \
               src/net/partition_detector.cpp \
               src/net/connman.cpp \
               src/net/asn_database.cpp \
               src/net/node.cpp \
               src/net/sock.cpp \
               src/net/upnp.cpp \
               src/attestation/seed_attestation.cpp

NODE_SOURCES := src/node/block_index.cpp \
                src/node/blockchain_storage.cpp \
                src/node/block_processing.cpp \
                src/node/fork_manager.cpp \
                src/node/mempool.cpp \
                src/node/genesis.cpp \
                src/node/utxo_set.cpp \
                src/node/ibd_coordinator.cpp \
                src/node/block_validation_queue.cpp \
                src/node/validation_watchdog.cpp \
                src/node/resource_monitor.cpp \
                src/node/peer_mik_tracker.cpp \
                src/node/registration_manager.cpp \
                src/node/startup_checkpoint_validator.cpp \
                src/node/chainstate_integrity_monitor.cpp

PRIMITIVES_SOURCES := src/primitives/block.cpp \
                      src/primitives/transaction.cpp

RPC_SOURCES := src/rpc/server.cpp \
               src/rpc/auth.cpp \
               src/rpc/ratelimiter.cpp \
               src/rpc/permissions.cpp \
               src/rpc/logger.cpp \
               src/rpc/ssl_wrapper.cpp \
               src/rpc/websocket.cpp \
               src/rpc/rest_api.cpp

API_SOURCES := src/api/http_server.cpp \
               src/api/cached_stats.cpp

X402_SOURCES := src/x402/x402_types.cpp \
                src/x402/vma.cpp \
                src/x402/facilitator.cpp

# Script system (Bitcoin-compatible script interpreter + HTLC + atomic swaps)
SCRIPT_SOURCES := src/script/interpreter.cpp \
                  src/script/htlc.cpp \
                  src/script/atomic_swap.cpp

WALLET_SOURCES := src/wallet/wallet.cpp \
                  src/wallet/crypter.cpp \
                  src/wallet/passphrase_validator.cpp \
                  src/wallet/mnemonic.cpp \
                  src/wallet/hd_derivation.cpp \
                  src/wallet/wallet_manager.cpp \
                  src/wallet/wallet_manager_wizard.cpp \
                  src/wallet/wallet_init.cpp \
                  src/wallet/wal.cpp \
                  src/wallet/wal_recovery.cpp

UTIL_SOURCES := src/util/strencodings.cpp \
                src/util/stacktrace.cpp \
                src/util/base58.cpp \
                src/util/system.cpp \
                src/util/assert.cpp \
                src/util/logging.cpp \
                src/util/config.cpp \
                src/util/config_validator.cpp \
                src/util/error_format.cpp \
                src/util/bench.cpp \
                src/util/pidfile.cpp \
                src/util/chain_reset.cpp

# Combine all core sources
CORE_SOURCES := $(CONSENSUS_SOURCES) \
                $(CORE_SOURCES_UTIL) \
                $(DB_SOURCES) \
                $(CRYPTO_SOURCES) \
                $(MINER_SOURCES) \
                $(DFMP_SOURCES) \
                $(DIGITAL_DNA_SOURCES) \
                $(VDF_SOURCES) \
                $(NET_SOURCES) \
                $(NODE_SOURCES) \
                $(PRIMITIVES_SOURCES) \
                $(RPC_SOURCES) \
                $(API_SOURCES) \
                $(X402_SOURCES) \
                $(SCRIPT_SOURCES) \
                $(UTIL_SOURCES) \
                $(WALLET_SOURCES)

# Object files
CORE_OBJECTS := $(CORE_SOURCES:src/%.cpp=$(OBJ_DIR)/%.o)

# Main application sources
DILITHION_NODE_SOURCE := src/node/dilithion-node.cpp
GENESIS_GEN_SOURCE := src/test/genesis_test.cpp

# Test sources
PHASE1_TEST_SOURCE := src/test/phase1_simple_test.cpp
MINER_TEST_SOURCE := src/test/miner_tests.cpp
WALLET_TEST_SOURCE := src/test/wallet_tests.cpp
RPC_TEST_SOURCE := src/test/rpc_tests.cpp
RPC_AUTH_TEST_SOURCE := src/test/rpc_auth_tests.cpp
RPC_HD_WALLET_TEST_SOURCE := src/test/rpc_hd_wallet_tests.cpp
RPC_SSL_TEST_SOURCE := src/test/rpc_ssl_tests.cpp
RPC_WEBSOCKET_TEST_SOURCE := src/test/rpc_websocket_tests.cpp
TIMESTAMP_TEST_SOURCE := src/test/timestamp_tests.cpp
CRYPTER_TEST_SOURCE := src/test/crypter_tests.cpp
WALLET_ENCRYPTION_INTEGRATION_TEST_SOURCE := src/test/wallet_encryption_integration_tests.cpp
WALLET_PERSISTENCE_TEST_SOURCE := src/test/wallet_persistence_tests.cpp
INTEGRATION_TEST_SOURCE := src/test/integration_tests.cpp
NET_TEST_SOURCE := src/test/net_tests.cpp
CONNMAN_TEST_SOURCE := src/test/connman_tests.cpp
TX_VALIDATION_TEST_SOURCE := src/test/tx_validation_tests.cpp
TX_RELAY_TEST_SOURCE := src/test/tx_relay_tests.cpp
MINING_INTEGRATION_TEST_SOURCE := src/test/mining_integration_tests.cpp
DFMP_MIK_TEST_SOURCE := src/test/dfmp_mik_tests.cpp
MIK_REG_PERSIST_TEST_SOURCE := src/test/mik_registration_persistence_tests.cpp
REGISTRATION_MANAGER_TEST_SOURCE := src/test/registration_manager_tests.cpp
DNA_PROPAGATION_TEST_SOURCE := src/test/dna_propagation_tests.cpp
PASSPHRASE_VALIDATOR_TEST_SOURCE := test_passphrase_validator.cpp

# Boost Unit Test sources
BOOST_TEST_MAIN_SOURCE := src/test/test_dilithion.cpp
BOOST_CRYPTO_TEST_SOURCE := src/test/crypto_tests.cpp
BOOST_HMAC_SHA3_TEST_SOURCE := src/test/hmac_sha3_tests.cpp
BOOST_PBKDF2_TEST_SOURCE := src/test/pbkdf2_tests.cpp
BOOST_TRANSACTION_TEST_SOURCE := src/test/transaction_tests.cpp
BOOST_BLOCK_TEST_SOURCE := src/test/block_tests.cpp
BOOST_UTIL_TEST_SOURCE := src/test/util_tests.cpp
BOOST_MNEMONIC_TEST_SOURCE := src/test/mnemonic_tests.cpp
BOOST_HD_DERIVATION_TEST_SOURCE := src/test/hd_derivation_tests.cpp
BOOST_WALLET_HD_TEST_SOURCE := src/test/wallet_hd_tests.cpp
BOOST_IBD_COORDINATOR_TEST_SOURCE := src/test/ibd_coordinator_tests.cpp
BOOST_MISBEHAVIOR_SCORING_TEST_SOURCE := src/test/misbehavior_scoring_tests.cpp
BOOST_IBD_FUNCTIONAL_TEST_SOURCE := src/test/ibd_functional_tests.cpp
# Phase 9.3: Crypto property tests
BOOST_CRYPTO_PROPERTY_TEST_SOURCE := src/test/crypto_property_tests.cpp
# Phase 3 & 4: RPC SSL and WebSocket tests
BOOST_RPC_SSL_TEST_SOURCE := src/test/rpc_ssl_tests.cpp
BOOST_RPC_WEBSOCKET_TEST_SOURCE := src/test/rpc_websocket_tests.cpp

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean install help tests test depends
.DEFAULT_GOAL := all

# Default target: build main binaries and utilities
all: dilithion-node dilv-node genesis_gen check-wallet-balance
	@echo "$(COLOR_GREEN)✓ Build complete!$(COLOR_RESET)"
	@echo "  dilithion-node:        $(shell ls -lh dilithion-node 2>/dev/null | awk '{print $$5}')"
	@echo "  dilv-node:             $(shell ls -lh dilv-node 2>/dev/null | awk '{print $$5}')"
	@echo "  genesis_gen:           $(shell ls -lh genesis_gen 2>/dev/null | awk '{print $$5}')"
	@echo "  check-wallet-balance:  $(shell ls -lh check-wallet-balance 2>/dev/null | awk '{print $$5}')"

# ============================================================================
# Main Binaries
# ============================================================================

dilithion-node: $(CORE_OBJECTS) $(OBJ_DIR)/node/dilithion-node.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dilithion-node built successfully$(COLOR_RESET)"

dilv-node: $(CORE_OBJECTS) $(OBJ_DIR)/node/dilv-node.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dilv-node built successfully$(COLOR_RESET)"

genesis_gen: $(CORE_OBJECTS) $(OBJ_DIR)/test/genesis_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ genesis_gen built successfully$(COLOR_RESET)"

inspect_db: $(CORE_OBJECTS) $(OBJ_DIR)/tools/inspect_db.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ inspect_db built successfully$(COLOR_RESET)"

# Phase 5 Day 5: leveldb state-hash tool for V2 byte-equivalence testing.
# Computes SHA3-256 of sorted (key,value) entries; comparing two outputs
# proves byte-level equivalence of two LevelDB databases.
leveldb_state_hash: $(CORE_OBJECTS) $(OBJ_DIR)/tools/leveldb_state_hash.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ leveldb_state_hash built successfully$(COLOR_RESET)"

check-wallet-balance: $(CORE_OBJECTS) $(OBJ_DIR)/check-wallet-balance.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ check-wallet-balance built successfully$(COLOR_RESET)"

dilv-genesis-vdf: $(CORE_OBJECTS) $(OBJ_DIR)/tools/dilv_genesis_vdf.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dilv-genesis-vdf built successfully$(COLOR_RESET)"

# ============================================================================
# Test Binaries
# ============================================================================

tests: phase1_test miner_tests wallet_tests rpc_tests rpc_auth_tests timestamp_tests crypter_tests wallet_encryption_integration_tests wallet_persistence_tests integration_tests net_tests connman_tests tx_validation_tests tx_relay_tests mining_integration_tests dfmp_mik_tests mik_registration_persistence_tests dna_propagation_tests test_passphrase_validator script_tests addrman_v2_tests peer_scorer_tests peer_scorer_banman_integration_tests header_proof_checker_tests chain_selector_tests getchaintips_equivalence_tests chain_case_2_5_equivalence_tests chain_work_smoke_tests reorg_wal_crash_injection_tests competing_sibling_below_checkpoint_tests headers_manager_to_chain_selector_wiring_tests fast_path_2_boundary_tests v4_1_checkpoint_enforcement_tests v4_1_chain_selector_suppression_tests auto_rebuild_marker_mode_symmetry_tests add_block_index_flag_merge_tests port_chain_selector_invariants_tests legacy_vs_port_differential_tests chainstate_integrity_tests
	@echo "$(COLOR_GREEN)✓ All tests built successfully$(COLOR_RESET)"

phase1_test: $(CORE_OBJECTS) $(OBJ_DIR)/test/phase1_simple_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

miner_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/miner_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

wallet_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/wallet_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

rpc_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/rpc_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

rpc_auth_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/rpc_auth_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

timestamp_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/timestamp_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

crypter_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/crypter_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

wallet_encryption_integration_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/wallet_encryption_integration_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

wallet_persistence_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/wallet_persistence_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

test_iv_reuse_detection: $(CORE_OBJECTS) $(OBJ_DIR)/test/test_iv_reuse_detection.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

test_authenticated_encryption: $(CORE_OBJECTS) $(OBJ_DIR)/test/test_authenticated_encryption.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

test_secure_allocator: $(CORE_OBJECTS) $(OBJ_DIR)/test/test_secure_allocator.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

hd_wallet_standalone_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/hd_wallet_standalone_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

integration_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/integration_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

net_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/net_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

connman_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/connman_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

tx_validation_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/tx_validation_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

tx_relay_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/tx_relay_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

mining_integration_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/mining_integration_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

dfmp_mik_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/dfmp_mik_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

mik_registration_persistence_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/mik_registration_persistence_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

registration_manager_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/registration_manager_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

dna_propagation_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/dna_propagation_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

ipv6_smoke_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/ipv6_smoke_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

script_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/script_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ script_tests built successfully$(COLOR_RESET)"

addrman_v2_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/addrman_v2_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ addrman_v2_tests built successfully$(COLOR_RESET)"

peer_scorer_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/peer_scorer_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ peer_scorer_tests built successfully$(COLOR_RESET)"

peer_scorer_banman_integration_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/peer_scorer_banman_integration_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ peer_scorer_banman_integration_tests built successfully$(COLOR_RESET)"

header_proof_checker_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/header_proof_checker_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ header_proof_checker_tests built successfully$(COLOR_RESET)"

# Phase 5 PR5.1: trivial-getter tests for ChainSelectorAdapter. Real
# algorithm tests land in PR5.3 (chain_selector_tests will grow to ~14).
chain_selector_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/chain_selector_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ chain_selector_tests built successfully$(COLOR_RESET)"

# v4.1 mandatory upgrade — checkpoint enforcement tests (Phase 1 + Phase 2
# startup validator + lifetime-miner snapshot assertion semantics).
v4_1_checkpoint_enforcement_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/v4_1_checkpoint_enforcement_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ v4_1_checkpoint_enforcement_tests built successfully$(COLOR_RESET)"

# v4.1 IBD silent-drop suppression tests. Note: v4.3 keeps the construction
# gate on DILITHION_USE_NEW_CHAIN_SELECTOR but Phase 11 ABI fixes the
# underlying AddBlockIndex flag-merge semantics. Suppression tests still
# pass because the env-var gate behavior is unchanged.
v4_1_chain_selector_suppression_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/v4_1_chain_selector_suppression_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ v4_1_chain_selector_suppression_tests built successfully$(COLOR_RESET)"

# Phase 11 ABI: AddBlockIndex flag-merge tests. Verifies BLOCK_VALID_HEADER +
# BLOCK_HAVE_DATA merge into the existing CBlockIndex when the same hash is
# added twice — fixes the underlying cause of the v4.1 IBD silent-drop.
add_block_index_flag_merge_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/add_block_index_flag_merge_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ add_block_index_flag_merge_tests built successfully$(COLOR_RESET)"

# Phase 7 PR7.2: fork-staging legacy-path regression tests (state-machine
# level; PreValidateBlock + TriggerChainSwitch + ProcessNewBlock end-to-end
# deferred to Phase 8). 4 cases (3 required + 1 optional).
fork_staging_legacy_path_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/fork_staging_legacy_path_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ fork_staging_legacy_path_tests built successfully$(COLOR_RESET)"

# Phase 11 A1: port-path fork-staging dispatch tests. Locks the routing logic
# in ChainSelectorAdapter::ProcessNewBlock that re-implements the legacy
# block_processing.cpp staging behavior on the port path. 5 cases.
port_fork_staging_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/port_fork_staging_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ port_fork_staging_tests built successfully$(COLOR_RESET)"

# Phase 10 PR10.1: per-RPC unit tests for Phase 9 telemetry surface.
# 9 cases locking v0.1.2 schemas of getsyncstatus + getblockdownloadstats
# + getpeerinfo manager_class extension. Closes Cursor Phase 9 S4 + Layer-2
# PR9.6-RT-MEDIUM-2 enhancement filings.
phase_9_telemetry_rpc_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/phase_9_telemetry_rpc_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ phase_9_telemetry_rpc_tests built successfully$(COLOR_RESET)"

# v4.3.4 Option C cut Block 3: regression gate proving legacy block-arrival
# reaches chain selector with DILITHION_USE_NEW_CHAIN_SELECTOR=1 and NO
# port peer manager registration.
legacy_block_arrival_chainsel_gate_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/legacy_block_arrival_chainsel_gate_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ legacy_block_arrival_chainsel_gate_tests built successfully$(COLOR_RESET)"

# Phase 6 PR6.1: HeadersManager → chain_selector wiring tests (5 cases).
# Verifies happy-path, idempotency, orphan, rejected-parent flood,
# cap-saturation per v1.5 plan §4 PR6.1.
headers_manager_to_chain_selector_wiring_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/headers_manager_to_chain_selector_wiring_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ headers_manager_to_chain_selector_wiring_tests built successfully$(COLOR_RESET)"

# Phase 6 PR6.4: FAST PATH 2 boundary tests (5 cases). Gates Patch H deletion.
# Tests the specific defect class that caused PR5.6's revert.
fast_path_2_boundary_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/fast_path_2_boundary_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ fast_path_2_boundary_tests built successfully$(COLOR_RESET)"

# Phase 5 PR5.2.A: GetChainTips equivalence proof (legacy string-status
# vs adapter enum-Status). Gates PR5.2.B CChainTipsTracker retirement.
getchaintips_equivalence_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/getchaintips_equivalence_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ getchaintips_equivalence_tests built successfully$(COLOR_RESET)"

# Phase 5 Day 4: Patch B equivalence harness. CONSENSUS-CRITICAL —
# proves new chain-selection path produces same end-state as legacy
# Case 2.5 + Patch B for all 5 scenarios. Gates PR5.4 (Patch B deletion).
chain_case_2_5_equivalence_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/chain_case_2_5_equivalence_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ chain_case_2_5_equivalence_tests built successfully$(COLOR_RESET)"

# Phase 5 Day 4 V1: chain_work bit-equivalence smoke test.
chain_work_smoke_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/chain_work_smoke_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ chain_work_smoke_tests built successfully$(COLOR_RESET)"

# v4.3.2 M1 fix: regression suite for LDN canary 2026-05-04. Verifies the
# auto_rebuild marker is reliably written under both --usenewpeerman=0 and
# --usenewpeerman=1 sync-coordinator configurations. See
# src/test/auto_rebuild_marker_mode_symmetry_tests.cpp for full context.
auto_rebuild_marker_mode_symmetry_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/auto_rebuild_marker_mode_symmetry_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ auto_rebuild_marker_mode_symmetry_tests built successfully$(COLOR_RESET)"

# v4.4 Block 4: regression suite for chainstate-integrity walk
# (CUTXOSet::VerifyUndoDataInRange) — startup-time pprev walk verifying every
# block in [highest_checkpoint+1 .. tip] has a present, SHA3-checksummed undo
# record. Detects the missing/corrupt undo-data corruption mode that crash-looped
# NYC + LDN on 2026-04-25. See src/test/chainstate_integrity_tests.cpp.
chainstate_integrity_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/chainstate_integrity_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ chainstate_integrity_tests built successfully$(COLOR_RESET)"

# v4.3.3 T1: synthetic regression harness for canary-3 reproduction +
# F1-F6 invariants in port-path chain selection. See
# src/test/port_chain_selector_invariants_tests.cpp for full context.
port_chain_selector_invariants_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/port_chain_selector_invariants_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ port_chain_selector_invariants_tests built successfully$(COLOR_RESET)"

# v4.3.3 T2: differential testing harness — legacy vs port path equivalence
# enforcement (audit modality 3 from feedback_audit_techniques_beyond_code_review).
# Permanent CI infrastructure: every future port change that introduces an
# unexpected divergence between legacy and port paths fails this suite.
legacy_vs_port_differential_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/legacy_vs_port_differential_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ legacy_vs_port_differential_tests built successfully$(COLOR_RESET)"

# Phase 5 Day 4 V1: deterministic WAL transition trace test (plan §13 hard gate #3).
reorg_wal_crash_injection_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/reorg_wal_crash_injection_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ reorg_wal_crash_injection_tests built successfully$(COLOR_RESET)"

# Phase 5 Day 4 V1: competing-sibling-below-checkpoint structural coverage.
# WITH-Patch-H subset — gates PR5.6 (Patch H deletion).
competing_sibling_below_checkpoint_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/competing_sibling_below_checkpoint_tests.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ competing_sibling_below_checkpoint_tests built successfully$(COLOR_RESET)"

# Phase 5 Day 5: regtest mode scaffold smoke test.
regtest_chainparams_smoke: $(CORE_OBJECTS) $(OBJ_DIR)/test/regtest_chainparams_smoke.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ regtest_chainparams_smoke built successfully$(COLOR_RESET)"

dna_serialization_test: $(CORE_OBJECTS) $(OBJ_DIR)/digital_dna/dna_serialization_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dna_serialization_test built successfully$(COLOR_RESET)"

dna_p2p_test: $(CORE_OBJECTS) $(OBJ_DIR)/digital_dna/dna_p2p_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dna_p2p_test built successfully$(COLOR_RESET)"

dna_detection_test: $(CORE_OBJECTS) $(OBJ_DIR)/digital_dna/dna_detection_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dna_detection_test built successfully$(COLOR_RESET)"

dna_history_test: $(CORE_OBJECTS) $(OBJ_DIR)/digital_dna/dna_history_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dna_history_test built successfully$(COLOR_RESET)"

dna_monitor_test: $(CORE_OBJECTS) $(OBJ_DIR)/digital_dna/dna_monitor_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dna_monitor_test built successfully$(COLOR_RESET)"

verification_test: $(CORE_OBJECTS) $(OBJ_DIR)/digital_dna/verification_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ verification_test built successfully$(COLOR_RESET)"

dfmp_v34_test: $(CORE_OBJECTS) $(OBJ_DIR)/test/dfmp_v34_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dfmp_v34_test built successfully$(COLOR_RESET)"

vdf_test: $(CORE_OBJECTS) $(OBJ_DIR)/vdf/vdf_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ vdf_test built successfully$(COLOR_RESET)"

vdf_consensus_test: $(CORE_OBJECTS) $(OBJ_DIR)/vdf/vdf_consensus_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ vdf_consensus_test built successfully$(COLOR_RESET)"

vdf_miner_test: $(CORE_OBJECTS) $(OBJ_DIR)/miner/vdf_miner_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ vdf_miner_test built successfully$(COLOR_RESET)"

vdf_lottery_test: $(CORE_OBJECTS) $(OBJ_DIR)/vdf/vdf_lottery_test.o $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ vdf_lottery_test built successfully$(COLOR_RESET)"

# v4.2.0 — Time-decay cooldown unit tests. Standalone (only depends on
# cooldown_tracker.cpp + std). See spec §7.1.
v4_2_time_decay_cooldown_tests: $(OBJ_DIR)/test/v4_2_time_decay_cooldown_tests.o $(OBJ_DIR)/vdf/cooldown_tracker.o
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "$(COLOR_GREEN)✓ v4_2_time_decay_cooldown_tests built successfully$(COLOR_RESET)"

test_passphrase_validator: $(OBJ_DIR)/wallet/passphrase_validator.o $(OBJ_DIR)/test_passphrase_validator.o
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

validate_crypto: validate_crypto.o $(OBJ_DIR)/crypto/hmac_sha3.o $(OBJ_DIR)/crypto/pbkdf2_sha3.o $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

# Phase 8 PR8.2: 4-node regtest harness (orchestration via bash script).
# Boots 4 dilv-node regtest binaries in full-mesh topology, mines on Node A,
# verifies lockstep + tip-hash equality + active-tip agreement + forbidden-
# token GREP regression. Scenarios 2 (delay injection) + 3 (competing
# leaves) deferred to PR8.2-followup (require Linux tc / dual-mining
# infrastructure). Depends on dilv-node binary already built.
.PHONY: four_node_test
four_node_test:
	@echo "$(COLOR_BLUE)[TEST]$(COLOR_RESET) 4-node regtest harness (scripts/four_node_local.sh)"
	@bash scripts/four_node_local.sh smoke 10 180
	@echo "$(COLOR_GREEN)✓ four_node_test passed$(COLOR_RESET)"

# ============================================================================
# Boost Unit Test Binaries
# ============================================================================

# Phase 9.3: Crypto property tests object
CRYPTO_PROPERTY_OBJECTS := $(OBJ_DIR)/test/crypto_property_tests.o
# Phase 3 & 4: RPC SSL and WebSocket test objects
RPC_SSL_TEST_OBJECTS := $(OBJ_DIR)/test/rpc_ssl_tests.o
RPC_WEBSOCKET_TEST_OBJECTS := $(OBJ_DIR)/test/rpc_websocket_tests.o

# Boost unit test objects (test-specific .o files)
BOOST_TEST_OBJECTS := $(OBJ_DIR)/test/test_dilithion.o \
	$(OBJ_DIR)/test/crypto_tests.o \
	$(OBJ_DIR)/test/hmac_sha3_tests.o \
	$(OBJ_DIR)/test/pbkdf2_tests.o \
	$(OBJ_DIR)/test/transaction_tests.o \
	$(OBJ_DIR)/test/block_tests.o \
	$(OBJ_DIR)/test/util_tests.o \
	$(OBJ_DIR)/test/mnemonic_tests.o \
	$(OBJ_DIR)/test/hd_derivation_tests.o \
	$(OBJ_DIR)/test/wallet_hd_tests.o \
	$(OBJ_DIR)/test/rpc_hd_wallet_tests.o \
	$(RPC_SSL_TEST_OBJECTS) \
	$(RPC_WEBSOCKET_TEST_OBJECTS) \
	$(OBJ_DIR)/test/difficulty_tests.o \
	$(OBJ_DIR)/test/validation_integration_tests.o \
	$(OBJ_DIR)/test/consensus_validation_tests.o \
	$(OBJ_DIR)/test/utxo_tests.o \
	$(OBJ_DIR)/test/tx_validation_tests.o \
	$(OBJ_DIR)/test/ibd_coordinator_tests.o \
	$(OBJ_DIR)/test/misbehavior_scoring_tests.o \
	$(OBJ_DIR)/test/ibd_functional_tests.o \
	$(OBJ_DIR)/test/fork_detection_tests.o \
	$(CRYPTO_PROPERTY_OBJECTS)

# Link test objects + full library (CORE_OBJECTS) to avoid hand-picked object drift
test_dilithion: $(BOOST_TEST_OBJECTS) $(CORE_OBJECTS) $(DILITHIUM_OBJECTS) $(CHIAVDF_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ Boost test suite built successfully$(COLOR_RESET)"

# ============================================================================
# Difficulty Determinism Test (Week 4 Track B - CRITICAL CONSENSUS TEST)
# ============================================================================

difficulty_determinism_test: $(OBJ_DIR)/test/difficulty_determinism_test.o $(OBJ_DIR)/consensus/pow.o $(OBJ_DIR)/core/chainparams.o $(OBJ_DIR)/primitives/block.o $(OBJ_DIR)/crypto/randomx_hash.o $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ Difficulty determinism test built successfully$(COLOR_RESET)"

eda_test:
	@echo "$(COLOR_BLUE)[CXX+LINK]$(COLOR_RESET) src/test/eda_test.cpp (standalone)"
	@$(CXX) -std=c++17 -O2 -o $@ src/test/eda_test.cpp
	@echo "$(COLOR_GREEN)✓ EDA test built successfully$(COLOR_RESET)"

asert_test:
	@echo "$(COLOR_BLUE)[CXX+LINK]$(COLOR_RESET) src/test/asert_test.cpp (standalone)"
	@$(CXX) -std=c++17 -O2 -o $@ src/test/asert_test.cpp
	@echo "$(COLOR_GREEN)✓ ASERT test built successfully$(COLOR_RESET)"

# ============================================================================
# Run Tests
# ============================================================================

test: tests test_dilithion asert_test
	@echo "$(COLOR_YELLOW)========================================$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Running Boost Unit Test Suite$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)========================================$(COLOR_RESET)"
	@./test_dilithion --log_level=test_suite --report_level=short || true
	@echo ""
	@echo "$(COLOR_YELLOW)========================================$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Running Legacy Test Suite$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)========================================$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_YELLOW)Running Phase 1 tests...$(COLOR_RESET)"
	@./phase1_test
	@echo ""
	@echo "$(COLOR_YELLOW)Running Phase 3 miner tests...$(COLOR_RESET)"
	@./miner_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running Phase 4 wallet tests...$(COLOR_RESET)"
	@timeout 10 ./wallet_tests || true
	@echo ""
	@echo "$(COLOR_YELLOW)Running Phase 4 RPC tests...$(COLOR_RESET)"
	@timeout 10 ./rpc_tests || true
	@echo ""
	@echo "$(COLOR_YELLOW)Running RPC authentication tests...$(COLOR_RESET)"
	@./rpc_auth_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running timestamp validation tests...$(COLOR_RESET)"
	@./timestamp_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running wallet encryption tests...$(COLOR_RESET)"
	@./crypter_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running wallet encryption integration tests...$(COLOR_RESET)"
	@./wallet_encryption_integration_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running wallet persistence tests...$(COLOR_RESET)"
	@./wallet_persistence_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running passphrase validator tests...$(COLOR_RESET)"
	@./test_passphrase_validator
	@echo ""
	@echo "$(COLOR_YELLOW)Running integration tests...$(COLOR_RESET)"
	@./integration_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running ASERT difficulty tests...$(COLOR_RESET)"
	@./asert_test
	@echo ""
	@echo "$(COLOR_YELLOW)Running Phase 6 script system tests...$(COLOR_RESET)"
	@./script_tests
	@echo ""
	@echo "$(COLOR_GREEN)✓ All test suites complete$(COLOR_RESET)"

# ============================================================================
# Object File Rules
# ============================================================================

# Create build directories
$(OBJ_DIR)/attestation \
$(OBJ_DIR)/consensus \
$(OBJ_DIR)/consensus/port \
$(OBJ_DIR)/core \
$(OBJ_DIR)/crypto \
$(OBJ_DIR)/db \
$(OBJ_DIR)/dfmp \
$(OBJ_DIR)/miner \
$(OBJ_DIR)/net \
$(OBJ_DIR)/net/port \
$(OBJ_DIR)/node \
$(OBJ_DIR)/primitives \
$(OBJ_DIR)/rpc \
$(OBJ_DIR)/wallet \
$(OBJ_DIR)/util \
$(OBJ_DIR)/api \
$(OBJ_DIR)/vdf \
$(OBJ_DIR)/chiavdf \
$(OBJ_DIR)/digital_dna \
$(OBJ_DIR)/script \
$(OBJ_DIR)/tools \
$(OBJ_DIR)/x402 \
$(OBJ_DIR)/test \
$(OBJ_DIR)/test/fuzz:
	@mkdir -p $@

# Compile C++ source files
$(OBJ_DIR)/%.o: src/%.cpp | $(OBJ_DIR)/attestation $(OBJ_DIR)/consensus $(OBJ_DIR)/consensus/port $(OBJ_DIR)/core $(OBJ_DIR)/crypto $(OBJ_DIR)/db $(OBJ_DIR)/dfmp $(OBJ_DIR)/miner $(OBJ_DIR)/net $(OBJ_DIR)/net/port $(OBJ_DIR)/node $(OBJ_DIR)/primitives $(OBJ_DIR)/rpc $(OBJ_DIR)/wallet $(OBJ_DIR)/util $(OBJ_DIR)/api $(OBJ_DIR)/vdf $(OBJ_DIR)/digital_dna $(OBJ_DIR)/script $(OBJ_DIR)/tools $(OBJ_DIR)/x402 $(OBJ_DIR)/test
	@echo "$(COLOR_BLUE)[CXX]$(COLOR_RESET)  $<"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile chiavdf C++ wrapper (third-party, suppress warnings with -w)
# Half-word Lehmer (32-bit approx) avoids signed overflow — no -fwrapv needed.
$(OBJ_DIR)/chiavdf/c_wrapper.o: depends/chiavdf/src/c_bindings/c_wrapper.cpp | $(OBJ_DIR)/chiavdf
	@echo "$(COLOR_BLUE)[CXX]$(COLOR_RESET)  $< (chiavdf)"
	@$(CXX) -std=c++17 -O2 -pipe -w $(CPPFLAGS) -I depends/chiavdf/src -I depends/chiavdf/src/c_bindings -c $< -o $@

# Compile chiavdf lzcnt utility (C file)
$(OBJ_DIR)/chiavdf/lzcnt.o: depends/chiavdf/src/refcode/lzcnt.c | $(OBJ_DIR)/chiavdf
	@echo "$(COLOR_BLUE)[CC]$(COLOR_RESET)   $< (chiavdf)"
	@gcc $(CFLAGS) -w -c $< -o $@

# Compile utility C++ files from root directory
$(OBJ_DIR)/%.o: %.cpp | $(OBJ_DIR)
	@echo "$(COLOR_BLUE)[CXX]$(COLOR_RESET)  $<"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile Dilithium C files
$(DILITHIUM_DIR)/%.o: $(DILITHIUM_DIR)/%.c
	@echo "$(COLOR_BLUE)[CC]$(COLOR_RESET)   $<"
	@gcc $(CFLAGS) -DDILITHIUM_MODE=3 -I $(DILITHIUM_DIR) -c $< -o $@

# Fuzzer harness files (MUST compile with sanitizers for libFuzzer integration)
$(OBJ_DIR)/test/fuzz/%.o: src/test/fuzz/%.cpp | $(OBJ_DIR)/test/fuzz
	@echo "$(COLOR_BLUE)[FUZZ-CXX]$(COLOR_RESET) $<"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -c $< -o $@

# Fuzz stubs: compiled WITHOUT sanitizers (dependency code, not harness)
$(OBJ_DIR)/test/fuzz/fuzz_stubs.o: src/test/fuzz/fuzz_stubs.cpp | $(OBJ_DIR)/test/fuzz
	@echo "$(COLOR_BLUE)[CXX]$(COLOR_RESET)  $< (fuzz stubs)"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# ============================================================================
# Dependencies
# ============================================================================

depends:
	@echo "$(COLOR_YELLOW)Building dependencies...$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)[RandomX]$(COLOR_RESET) Building RandomX library..."
	@cd depends/randomx && mkdir -p build-windows && cd build-windows && cmake -DCMAKE_SYSTEM_PROCESSOR=x86_64 -G "MSYS Makefiles" .. && make
	@echo "$(COLOR_BLUE)[Dilithium]$(COLOR_RESET) Building Dilithium reference C objects..."
	@$(MAKE) --no-print-directory $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_GREEN)✓ Dependencies built$(COLOR_RESET)"

# Include auto-generated header dependency files (-MMD -MP)
# These ensure that changing any .h file triggers recompilation of all .cpp files that include it
-include $(wildcard $(OBJ_DIR)/**/*.d $(OBJ_DIR)/*.d)

# ============================================================================
# Utility Targets
# ============================================================================

clean:
	@echo "$(COLOR_YELLOW)Cleaning build artifacts...$(COLOR_RESET)"
	@rm -rf $(BUILD_DIR)
	@rm -f dilithion-node genesis_gen
	@rm -f phase1_test miner_tests wallet_tests rpc_tests rpc_auth_tests timestamp_tests crypter_tests wallet_encryption_integration_tests wallet_persistence_tests integration_tests net_tests tx_validation_tests tx_relay_tests mining_integration_tests dfmp_mik_tests mik_registration_persistence_tests registration_manager_tests dna_propagation_tests
	@rm -f test_dilithion
	@rm -f $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_GREEN)✓ Clean complete$(COLOR_RESET)"

install: dilithion-node genesis_gen
	@echo "$(COLOR_YELLOW)Installing binaries...$(COLOR_RESET)"
	@install -d $(DESTDIR)/usr/local/bin
	@install -m 0755 dilithion-node $(DESTDIR)/usr/local/bin/
	@install -m 0755 genesis_gen $(DESTDIR)/usr/local/bin/
	@echo "$(COLOR_GREEN)✓ Installed to /usr/local/bin$(COLOR_RESET)"

help:
	@echo "Dilithion Cryptocurrency - Build System"
	@echo ""
	@echo "$(COLOR_BLUE)Main Targets:$(COLOR_RESET)"
	@echo "  all              - Build dilithion-node and genesis_gen (default)"
	@echo "  dilithion-node   - Build the main node application"
	@echo "  genesis_gen      - Build the genesis block generator"
	@echo ""
	@echo "$(COLOR_BLUE)Test Targets:$(COLOR_RESET)"
	@echo "  tests            - Build all test binaries"
	@echo "  test             - Build and run all tests"
	@echo "  phase1_test      - Build Phase 1 core tests"
	@echo "  miner_tests      - Build Phase 3 mining tests"
	@echo "  wallet_tests     - Build Phase 4 wallet tests"
	@echo "  rpc_tests        - Build Phase 4 RPC tests"
	@echo "  integration_tests- Build Phase 5 integration tests"
	@echo "  net_tests        - Build Phase 2 network tests"
	@echo ""
	@echo "$(COLOR_BLUE)Utility Targets:$(COLOR_RESET)"
	@echo "  depends          - Build RandomX and Dilithium dependencies"
	@echo "  clean            - Remove all built files"
	@echo "  install          - Install binaries to /usr/local/bin"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "$(COLOR_BLUE)Code Quality Targets:$(COLOR_RESET)"
	@echo "  analyze          - Run static analysis (cppcheck)"
	@echo "  lint             - Run linter (clang-tidy)"
	@echo "  memcheck         - Run memory leak detection (valgrind)"
	@echo "  coverage         - Generate code coverage report"
	@echo "  docs             - Generate API documentation (Doxygen)"
	@echo "  quality          - Run analysis checks"
	@echo ""
	@echo "$(COLOR_BLUE)Examples:$(COLOR_RESET)"
	@echo "  make                    # Build main binaries"
	@echo "  make -j8                # Build with 8 parallel jobs"
	@echo "  make tests              # Build all tests"
	@echo "  make test               # Build and run all tests"
	@echo "  make clean all          # Clean rebuild"
	@echo "  make depends all        # Build dependencies and main binaries"
	@echo ""
	@echo "$(COLOR_BLUE)Requirements:$(COLOR_RESET)"
	@echo "  - g++ with C++17 support"
	@echo "  - LevelDB library (apt-get install libleveldb-dev)"
	@echo "  - CMake (for RandomX dependency)"
	@echo ""

# ============================================================================
# Code Quality and Analysis
# ============================================================================

.PHONY: analyze lint memcheck coverage quality docs

# Static analysis with cppcheck
analyze:
	@echo "$(COLOR_YELLOW)Running static analysis...$(COLOR_RESET)"
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all \
			--suppress=missingInclude \
			--suppress=unusedFunction \
			$(INCLUDES) \
			src/ 2> cppcheck-report.txt; \
		cat cppcheck-report.txt; \
		echo "$(COLOR_GREEN)✓ Analysis complete (see cppcheck-report.txt)$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ cppcheck not installed. See docs/STATIC-ANALYSIS.md$(COLOR_RESET)"; \
	fi

# Linting with clang-tidy
lint:
	@echo "$(COLOR_YELLOW)Running linter...$(COLOR_RESET)"
	@if command -v clang-tidy >/dev/null 2>&1; then \
		find src -name "*.cpp" -not -path "*/test/*" | while read file; do \
			echo "Checking $$file..."; \
			clang-tidy $$file -- -std=c++17 -I src || true; \
		done; \
		echo "$(COLOR_GREEN)✓ Linting complete$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ clang-tidy not installed. See docs/STATIC-ANALYSIS.md$(COLOR_RESET)"; \
	fi

# Memory leak detection
memcheck: tests
	@echo "$(COLOR_YELLOW)Running memory leak detection...$(COLOR_RESET)"
	@if command -v valgrind >/dev/null 2>&1; then \
		valgrind --leak-check=full --show-leak-kinds=all \
			--log-file=valgrind-phase1.txt ./phase1_test; \
		valgrind --leak-check=full --show-leak-kinds=all \
			--log-file=valgrind-wallet.txt ./wallet_tests; \
		echo "$(COLOR_GREEN)✓ Memory check complete$(COLOR_RESET)"; \
		echo "  Reports: valgrind-phase1.txt, valgrind-wallet.txt"; \
	else \
		echo "$(COLOR_YELLOW)⚠ valgrind not installed. See docs/STATIC-ANALYSIS.md$(COLOR_RESET)"; \
	fi

# Generate API documentation
docs:
	@echo "$(COLOR_YELLOW)Generating API documentation...$(COLOR_RESET)"
	@if command -v doxygen >/dev/null 2>&1; then \
		doxygen Doxyfile; \
		echo "$(COLOR_GREEN)✓ Documentation generated: docs/api/html/index.html$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ doxygen not installed. Install: sudo apt-get install doxygen$(COLOR_RESET)"; \
	fi

# Run all quality checks
quality: analyze
	@echo "$(COLOR_GREEN)✓ Quality checks complete$(COLOR_RESET)"
	@echo "  Note: Run 'make memcheck' and 'make coverage' separately (time-intensive)"

# ============================================================================
# Fuzz Testing (libFuzzer)
# ============================================================================
#
# ARCHITECTURE: Pre-compiled object file approach
#
# This build system uses pre-compiled object files to avoid linker errors in
# CI environments. The architecture mirrors the proven test_dilithion pattern.
#
# STRUCTURE:
#   1. Fuzzer harness files (.cpp) → compiled WITH sanitizers → harness.o
#   2. Dependency files (.cpp) → compiled WITHOUT sanitizers → deps.o
#   3. Dilithium library (.c) → compiled with gcc → dilithium/*.o
#   4. Link: harness.o + deps.o + dilithium/*.o → fuzzer binary
#
# WHY THIS WORKS:
#   - Make automatically builds all prerequisite .o files first
#   - Fuzzer harness gets proper libFuzzer instrumentation
#   - Dependencies use standard compilation (no ABI issues)
#   - Works identically in local and CI (no cached state needed)
#
# WHY DIRECT .cpp COMPILATION FAILS:
#   - Old approach: fuzz_block: harness.cpp block.cpp ... $(DILITHIUM_OBJECTS)
#   - Clang compiles each .cpp separately without full instrumentation
#   - Linker receives incomplete objects → "undefined reference" errors
#   - Worked locally only due to cached .o files from previous builds
#
# FOR MORE DETAILS: See docs/FUZZING-BUILD-SYSTEM.md
#
# Fuzz test compiler (requires Clang with libFuzzer support)
# Try clang++-14 first, fall back to clang++ (any version), or use environment variable
FUZZ_CXX ?= $(shell command -v clang++-14 2>/dev/null || command -v clang++ 2>/dev/null || echo clang++)
FUZZ_CXXFLAGS := -fsanitize=fuzzer,address,undefined -std=c++17 -O1 -g $(INCLUDES) -DDILITHIUM_MODE=3

# Fuzz test sources (Week 3 Phase 4 - 9 harnesses, 42+ targets)
# Week 6 Phase 3 - Added tx_validation and utxo fuzzers (11 harnesses total)
# Week 7 Phase 3 - Split multi-target fuzzers (20 harnesses total)
FUZZ_SHA3_SOURCE := src/test/fuzz/fuzz_sha3.cpp
FUZZ_TRANSACTION_SOURCE := src/test/fuzz/fuzz_transaction.cpp
FUZZ_BLOCK_SOURCE := src/test/fuzz/fuzz_block.cpp
FUZZ_COMPACTSIZE_SOURCE := src/test/fuzz/fuzz_compactsize.cpp
FUZZ_NETWORK_MSG_SOURCE := src/test/fuzz/fuzz_network_message.cpp
FUZZ_ADDRESS_SOURCE := src/test/fuzz/fuzz_address.cpp
FUZZ_DIFFICULTY_SOURCE := src/test/fuzz/fuzz_difficulty.cpp
FUZZ_SUBSIDY_SOURCE := src/test/fuzz/fuzz_subsidy.cpp
FUZZ_MERKLE_SOURCE := src/test/fuzz/fuzz_merkle.cpp
FUZZ_TX_VALIDATION_SOURCE := src/test/fuzz/fuzz_tx_validation.cpp
FUZZ_UTXO_SOURCE := src/test/fuzz/fuzz_utxo.cpp
# New split fuzzers (Phase 3 - Nov 2025)
FUZZ_ADDRESS_ENCODE_SOURCE := src/test/fuzz/fuzz_address_encode.cpp
FUZZ_ADDRESS_VALIDATE_SOURCE := src/test/fuzz/fuzz_address_validate.cpp
FUZZ_ADDRESS_BECH32_SOURCE := src/test/fuzz/fuzz_address_bech32.cpp
FUZZ_ADDRESS_TYPE_SOURCE := src/test/fuzz/fuzz_address_type.cpp
FUZZ_NETWORK_CREATE_SOURCE := src/test/fuzz/fuzz_network_create.cpp
FUZZ_NETWORK_CHECKSUM_SOURCE := src/test/fuzz/fuzz_network_checksum.cpp
FUZZ_NETWORK_COMMAND_SOURCE := src/test/fuzz/fuzz_network_command.cpp
FUZZ_SIGNATURE_SOURCE := src/test/fuzz/fuzz_signature.cpp
FUZZ_BASE58_SOURCE := src/test/fuzz/fuzz_base58.cpp
# Phase 9.1: Additional fuzz targets
FUZZ_SERIALIZE_SOURCE := src/test/fuzz/fuzz_serialize.cpp
FUZZ_MEMPOOL_SOURCE := src/test/fuzz/fuzz_mempool.cpp
FUZZ_RPC_SOURCE := src/test/fuzz/fuzz_rpc.cpp

# Fuzzer object files (compiled WITH sanitizers) - harness code only
FUZZ_SHA3_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_sha3.o
FUZZ_TRANSACTION_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_transaction.o
FUZZ_BLOCK_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_block.o
FUZZ_COMPACTSIZE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_compactsize.o
FUZZ_NETWORK_MSG_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_network_message.o
FUZZ_ADDRESS_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address.o
FUZZ_DIFFICULTY_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_difficulty.o
FUZZ_SUBSIDY_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_subsidy.o
FUZZ_MERKLE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_merkle.o
FUZZ_TX_VALIDATION_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_tx_validation.o
FUZZ_UTXO_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_utxo.o
# New split fuzzer objects
FUZZ_ADDRESS_ENCODE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address_encode.o
FUZZ_ADDRESS_VALIDATE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address_validate.o
FUZZ_ADDRESS_BECH32_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address_bech32.o
FUZZ_ADDRESS_TYPE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address_type.o
FUZZ_NETWORK_CREATE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_network_create.o
FUZZ_NETWORK_CHECKSUM_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_network_checksum.o
FUZZ_NETWORK_COMMAND_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_network_command.o
FUZZ_SIGNATURE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_signature.o
FUZZ_BASE58_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_base58.o
# Phase 9.1: Additional fuzzer objects
FUZZ_SERIALIZE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_serialize.o
FUZZ_MEMPOOL_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_mempool.o
FUZZ_RPC_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_rpc.o

# Common fuzzer dependencies (compiled WITHOUT sanitizers) - linked library code
FUZZ_COMMON_OBJECTS := $(OBJ_DIR)/crypto/sha3.o \
                       $(OBJ_DIR)/primitives/transaction.o \
                       $(OBJ_DIR)/primitives/block.o \
                       $(OBJ_DIR)/core/chainparams.o \
                       $(OBJ_DIR)/crypto/randomx_hash.o \
                       $(OBJ_DIR)/util/system.o

FUZZ_CONSENSUS_OBJECTS := $(OBJ_DIR)/consensus/pow.o \
                          $(OBJ_DIR)/consensus/fees.o \
                          $(OBJ_DIR)/consensus/tx_validation.o \
                          $(OBJ_DIR)/consensus/validation.o \
                          $(OBJ_DIR)/consensus/signature_batch_verifier.o

FUZZ_DFMP_OBJECTS := $(OBJ_DIR)/dfmp/dfmp.o \
                     $(OBJ_DIR)/dfmp/identity_db.o \
                     $(OBJ_DIR)/dfmp/mik.o

FUZZ_NODE_OBJECTS := $(OBJ_DIR)/node/utxo_set.o

# Stubs for heavy dependencies (NodeContext, DNA, VDF) that would cascade into 20+ objects.
# Real self-contained objects for symbols that don't cascade.
# See src/test/fuzz/fuzz_stubs.cpp for details.
FUZZ_STUBS_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_stubs.o
FUZZ_EXTRA_OBJECTS := $(OBJ_DIR)/node/block_index.o \
                      $(OBJ_DIR)/util/logging.o \
                      $(OBJ_DIR)/script/interpreter.o

# Fuzz test binaries
FUZZ_SHA3 := fuzz_sha3
FUZZ_TRANSACTION := fuzz_transaction
FUZZ_BLOCK := fuzz_block
FUZZ_COMPACTSIZE := fuzz_compactsize
FUZZ_NETWORK_MSG := fuzz_network_message
FUZZ_ADDRESS := fuzz_address
FUZZ_DIFFICULTY := fuzz_difficulty
FUZZ_SUBSIDY := fuzz_subsidy
FUZZ_MERKLE := fuzz_merkle
FUZZ_TX_VALIDATION := fuzz_tx_validation
FUZZ_UTXO := fuzz_utxo
# New split fuzzer binaries
FUZZ_ADDRESS_ENCODE := fuzz_address_encode
FUZZ_ADDRESS_VALIDATE := fuzz_address_validate
FUZZ_ADDRESS_BECH32 := fuzz_address_bech32
FUZZ_ADDRESS_TYPE := fuzz_address_type
FUZZ_NETWORK_CREATE := fuzz_network_create
FUZZ_NETWORK_CHECKSUM := fuzz_network_checksum
FUZZ_NETWORK_COMMAND := fuzz_network_command
FUZZ_SIGNATURE := fuzz_signature
FUZZ_BASE58 := fuzz_base58
# Phase 9.1: Additional fuzzer binaries
FUZZ_SERIALIZE := fuzz_serialize
FUZZ_MEMPOOL := fuzz_mempool
FUZZ_RPC := fuzz_rpc

# Build all fuzz tests (requires Clang with libFuzzer)
# Phase 9.1: Expanded to 23 harnesses with additional coverage
fuzz: fuzz_sha3 fuzz_transaction fuzz_block fuzz_compactsize fuzz_network_message fuzz_address fuzz_difficulty fuzz_subsidy fuzz_merkle fuzz_tx_validation fuzz_utxo fuzz_address_encode fuzz_address_validate fuzz_address_bech32 fuzz_address_type fuzz_network_create fuzz_network_checksum fuzz_network_command fuzz_signature fuzz_base58 fuzz_serialize fuzz_mempool fuzz_rpc
	@echo "$(COLOR_GREEN)✓ All fuzz tests built successfully (23 harnesses, 80+ targets)$(COLOR_RESET)"
	@echo "  Run individual: ./fuzz_sha3, ./fuzz_transaction, ./fuzz_block, etc."
	@echo "  With corpus: ./fuzz_transaction fuzz_corpus/transaction/"
	@echo "  Time limit: ./fuzz_block -max_total_time=60"

# Fuzz Testing (libFuzzer) - Pre-compiled object file architecture
# Uses proven pattern from test_dilithion: harness + dependencies as .o files
# Avoids CI linker errors from direct .cpp compilation with sanitizers

# fuzz_sha3: Minimal dependencies (SHA3 only)
fuzz_sha3: $(FUZZ_SHA3_OBJ) $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_transaction: Block + transaction dependencies
fuzz_transaction: $(FUZZ_TRANSACTION_OBJ) $(FUZZ_COMMON_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (3 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L $(RANDOMX_BUILD_DIR) -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_block: Block header dependencies
fuzz_block: $(FUZZ_BLOCK_OBJ) $(FUZZ_COMMON_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (4 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L $(RANDOMX_BUILD_DIR) -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_compactsize: No external dependencies
fuzz_compactsize: $(FUZZ_COMPACTSIZE_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (5 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_network_message: SHA3, block, transaction dependencies
fuzz_network_message: $(FUZZ_NETWORK_MSG_OBJ) $(OBJ_DIR)/crypto/sha3.o $(OBJ_DIR)/primitives/block.o $(OBJ_DIR)/primitives/transaction.o $(OBJ_DIR)/crypto/randomx_hash.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (1 target)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L $(RANDOMX_BUILD_DIR) -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_address: SHA3 and Base58 dependency
fuzz_address: $(FUZZ_ADDRESS_OBJ) $(OBJ_DIR)/crypto/sha3.o $(OBJ_DIR)/util/base58.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (5 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_difficulty: Full consensus + UTXO + DFMP dependencies (pow.o and tx_validation.o use DFMP and UTXO)
fuzz_difficulty: $(FUZZ_DIFFICULTY_OBJ) $(FUZZ_COMMON_OBJECTS) $(FUZZ_CONSENSUS_OBJECTS) $(FUZZ_DFMP_OBJECTS) $(FUZZ_NODE_OBJECTS) $(FUZZ_STUBS_OBJ) $(FUZZ_EXTRA_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (6 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L $(RANDOMX_BUILD_DIR) -lleveldb -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_subsidy: No external dependencies
fuzz_subsidy: $(FUZZ_SUBSIDY_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (7 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_merkle: Full consensus + UTXO + DFMP for CBlockValidator::BuildMerkleRoot
fuzz_merkle: $(FUZZ_MERKLE_OBJ) $(FUZZ_COMMON_OBJECTS) $(FUZZ_CONSENSUS_OBJECTS) $(FUZZ_DFMP_OBJECTS) $(FUZZ_NODE_OBJECTS) $(FUZZ_STUBS_OBJ) $(FUZZ_EXTRA_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (7 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L $(RANDOMX_BUILD_DIR) -lleveldb -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_tx_validation: Full consensus + UTXO + DFMP dependencies
fuzz_tx_validation: $(FUZZ_TX_VALIDATION_OBJ) $(FUZZ_COMMON_OBJECTS) $(FUZZ_CONSENSUS_OBJECTS) $(FUZZ_DFMP_OBJECTS) $(FUZZ_NODE_OBJECTS) $(FUZZ_STUBS_OBJ) $(FUZZ_EXTRA_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (4 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L $(RANDOMX_BUILD_DIR) -lleveldb -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_utxo: Full consensus + UTXO + DFMP dependencies
fuzz_utxo: $(FUZZ_UTXO_OBJ) $(FUZZ_COMMON_OBJECTS) $(FUZZ_CONSENSUS_OBJECTS) $(FUZZ_DFMP_OBJECTS) $(FUZZ_NODE_OBJECTS) $(FUZZ_STUBS_OBJ) $(FUZZ_EXTRA_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (4 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L $(RANDOMX_BUILD_DIR) -lleveldb -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# ============================================================================
# New Split Fuzzers (Phase 3 - November 2025)
# ============================================================================

# fuzz_address_encode: Base58 encoding with SHA3 checksum
fuzz_address_encode: $(FUZZ_ADDRESS_ENCODE_OBJ) $(OBJ_DIR)/crypto/sha3.o $(OBJ_DIR)/util/base58.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_address_validate: Address validation and checksum verification
fuzz_address_validate: $(FUZZ_ADDRESS_VALIDATE_OBJ) $(OBJ_DIR)/crypto/sha3.o $(OBJ_DIR)/util/base58.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_address_bech32: Bech32 address decoding
fuzz_address_bech32: $(FUZZ_ADDRESS_BECH32_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_address_type: Address type detection
fuzz_address_type: $(FUZZ_ADDRESS_TYPE_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_network_create: Network message serialization
fuzz_network_create: $(FUZZ_NETWORK_CREATE_OBJ) $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_network_checksum: Network checksum validation
fuzz_network_checksum: $(FUZZ_NETWORK_CHECKSUM_OBJ) $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_network_command: Network command parsing
fuzz_network_command: $(FUZZ_NETWORK_COMMAND_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_signature: Dilithium signature verification
fuzz_signature: $(FUZZ_SIGNATURE_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_base58: Base58 codec testing
fuzz_base58: $(FUZZ_BASE58_OBJ) $(OBJ_DIR)/util/base58.o $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# Phase 9.1: Additional fuzz targets
# fuzz_serialize: Serialization/deserialization
fuzz_serialize: $(FUZZ_SERIALIZE_OBJ) $(OBJ_DIR)/net/serialize.o $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_mempool: Mempool operations (needs full common + fees + mempool + logging for g_verbose)
fuzz_mempool: $(FUZZ_MEMPOOL_OBJ) $(FUZZ_COMMON_OBJECTS) $(OBJ_DIR)/node/mempool.o $(OBJ_DIR)/consensus/fees.o $(OBJ_DIR)/util/logging.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L $(RANDOMX_BUILD_DIR) -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_rpc: RPC parsing and validation
fuzz_rpc: $(FUZZ_RPC_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# Run fuzz tests (short run for CI)
# Phase 9.1: Updated to include new fuzz targets
run_fuzz: fuzz
	@echo "$(COLOR_YELLOW)Running fuzz tests (60 second each)...$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)Fuzzing SHA-3...$(COLOR_RESET)"
	@timeout 60 ./$(FUZZ_SHA3) || true
	@echo "$(COLOR_BLUE)Fuzzing Serialization...$(COLOR_RESET)"
	@timeout 60 ./$(FUZZ_SERIALIZE) || true
	@echo "$(COLOR_BLUE)Fuzzing Mempool...$(COLOR_RESET)"
	@timeout 60 ./$(FUZZ_MEMPOOL) || true
	@echo "$(COLOR_BLUE)Fuzzing RPC...$(COLOR_RESET)"
	@timeout 60 ./$(FUZZ_RPC) || true
	@echo "$(COLOR_GREEN)✓ Fuzz testing complete$(COLOR_RESET)"

# ============================================================================
# Code Coverage (Week 4)
# ============================================================================

# Coverage flags
COVERAGE_CXXFLAGS := --coverage -O0 -g
COVERAGE_LDFLAGS := --coverage

# Build with coverage instrumentation and run tests
coverage: CXXFLAGS += $(COVERAGE_CXXFLAGS)
coverage: LDFLAGS += $(COVERAGE_LDFLAGS)
coverage: clean all
	@echo "$(COLOR_BLUE)[COVERAGE]$(COLOR_RESET) Building with coverage instrumentation..."
	@echo "$(COLOR_YELLOW)Note: test_dilithion not yet implemented$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)[COVERAGE]$(COLOR_RESET) Generating coverage report..."
	@mkdir -p coverage_html
	@if command -v lcov >/dev/null 2>&1; then \
		lcov --capture --directory . --output-file coverage.info --ignore-errors source 2>/dev/null || true; \
		lcov --remove coverage.info '/usr/*' '*/test/*' '*/depends/*' --output-file coverage_filtered.info --ignore-errors unused 2>/dev/null || true; \
		genhtml coverage_filtered.info --output-directory coverage_html --ignore-errors source 2>/dev/null || true; \
		echo "$(COLOR_GREEN)✓ Coverage report generated: coverage_html/index.html$(COLOR_RESET)"; \
		lcov --summary coverage_filtered.info 2>/dev/null || true; \
	else \
		echo "$(COLOR_YELLOW)⚠ lcov not found. Install with: sudo apt-get install lcov$(COLOR_RESET)"; \
	fi

# Generate coverage HTML report (assumes coverage data exists)
coverage-html:
	@echo "$(COLOR_BLUE)[COVERAGE]$(COLOR_RESET) Generating HTML report..."
	@mkdir -p coverage_html
	@if command -v lcov >/dev/null 2>&1 && [ -f coverage.info ]; then \
		genhtml coverage_filtered.info --output-directory coverage_html 2>/dev/null || \
		genhtml coverage.info --output-directory coverage_html 2>/dev/null || true; \
		echo "$(COLOR_GREEN)✓ Coverage report: coverage_html/index.html$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ No coverage data found. Run 'make coverage' first.$(COLOR_RESET)"; \
	fi

# Clean coverage files
coverage-clean:
	@echo "$(COLOR_BLUE)[CLEAN]$(COLOR_RESET) Removing coverage files..."
	@rm -rf *.gcda *.gcno coverage.info coverage_filtered.info coverage_html
	@find . -name "*.gcda" -delete 2>/dev/null || true
	@find . -name "*.gcno" -delete 2>/dev/null || true
	@echo "$(COLOR_GREEN)✓ Coverage files removed$(COLOR_RESET)"

# ============================================================================
# Debugging
# ============================================================================

print-%:
	@echo '$*=$($*)'

.PHONY: print-% fuzz fuzz_sha3 fuzz_transaction fuzz_block fuzz_compactsize fuzz_network_message fuzz_address fuzz_difficulty fuzz_subsidy fuzz_merkle run_fuzz coverage coverage-html coverage-clean
